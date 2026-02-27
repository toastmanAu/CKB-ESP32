/*
 * TransferCKB.ino — Build, sign, and broadcast a CKB transfer
 *
 * Two patterns shown:
 *   A) Manual:   buildTransfer() + signTx() + broadcast() — full visibility
 *   B) One-shot: sendTransaction()               — minimal code
 *
 * !! NEVER hard-code a real private key in firmware you share or commit !!
 *    Use Preferences/NVS. See the Key Security section in the README.
 */

#define CKB_PROFILE_SIGNER
#include <WiFi.h>
#include "CKB.h"
#include "CKBSigner.h"

// ── Config ────────────────────────────────────────────────────────────────────
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
const char* CKB_NODE  = "http://192.168.1.100:8114";

// Load from NVS in production — see README Key Security section
const char* PRIVKEY_HEX = "your-64-char-private-key-hex";
const char* TO_ADDR     = "ckb1q...recipient";
const float SEND_CKB    = 100.0f;

CKBClient ckb(CKB_NODE);

// Run in 32KB FreeRTOS task — buildTransfer + crypto exceed default 8KB stack
void transferTask(void*) {
    // ── WiFi ──────────────────────────────────────────────────────────────────
    Serial.printf("Connecting to %s", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis()-t0 < 15000)
        { delay(300); Serial.print("."); }
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\nWiFi failed"); vTaskDelete(nullptr); return;
    }
    Serial.printf("\nConnected: %s\n\n", WiFi.localIP().toString().c_str());

    // ── Load key ──────────────────────────────────────────────────────────────
    CKBKey key;
    if (!key.loadPrivateKeyHex(PRIVKEY_HEX)) {
        Serial.println("ERROR: invalid private key"); vTaskDelete(nullptr); return;
    }

    // Derive from address from the key — no need to hardcode it
    char fromAddr[120];
    key.getAddress(fromAddr, sizeof(fromAddr), true);   // true = mainnet
    Serial.printf("From:    %s\n", fromAddr);
    Serial.printf("To:      %s\n", TO_ADDR);
    Serial.printf("Amount:  %.2f CKB\n\n", SEND_CKB);

    // ── Check balance ─────────────────────────────────────────────────────────
    CKBBalance bal = ckb.getBalance(fromAddr);
    if (bal.error != CKB_OK || bal.shannon == 0) {
        Serial.printf("Balance error or zero: %s\n", ckb.lastErrorStr());
        vTaskDelete(nullptr); return;
    }
    Serial.printf("Balance: %s (%u cells)\n\n",
        CKBClient::formatCKB(bal.shannon).c_str(), bal.cellCount);

    // ══════════════════════════════════════════════════════════════════════════
    // Pattern A — Manual: full visibility over each step
    // ══════════════════════════════════════════════════════════════════════════
    Serial.println("── Pattern A: buildTransfer + signTx + broadcast ──");

    CKBBuiltTx tx = ckb.buildTransfer(fromAddr, TO_ADDR, CKBClient::ckbToShannon(SEND_CKB));
    if (!tx.valid) {
        Serial.printf("Build failed: %s\n", ckb.lastErrorStr());
        vTaskDelete(nullptr); return;
    }

    Serial.printf("TX hash:   %s\n", tx.txHashHex);
    Serial.printf("Inputs:    %d cells, total %s\n",
        tx.inputCount, CKBClient::formatCKB(tx.totalInputCapacity()).c_str());
    Serial.printf("Send:      %s\n", CKBClient::formatCKB(tx.outputs[0].capacity).c_str());
    if (tx.outputCount > 1)
        Serial.printf("Change:    %s\n", CKBClient::formatCKB(tx.outputs[1].capacity).c_str());
    Serial.printf("Fee:       %llu shannon\n\n", (unsigned long long)tx.fee());

    if (ckb.signTx(tx, key) != CKB_OK || !tx.signed_) {
        Serial.println("Sign failed"); vTaskDelete(nullptr); return;
    }
    Serial.println("Signed ✓");

    char txHashA[67] = {0};
    CKBError errA = CKBClient::broadcast(tx, CKB_NODE, txHashA);
    if (errA == CKB_OK)
        Serial.printf("Broadcast OK: %s\n\n", txHashA[0] ? txHashA : "(already in pool)");
    else
        Serial.printf("Broadcast failed (%d): %s\n\n", (int)errA, ckb.lastErrorStr());

    // ══════════════════════════════════════════════════════════════════════════
    // Pattern B — One-shot: minimal code, same result
    // (Comment out Pattern A above before using this — needs a fresh funded cell)
    // ══════════════════════════════════════════════════════════════════════════
    // char txHashB[67] = {0};
    // CKBError errB = ckb.sendTransaction(TO_ADDR, SEND_CKB, key, txHashB);
    // if (errB == CKB_OK)
    //     Serial.printf("Sent! TX: %s\n", txHashB[0] ? txHashB : "(already in pool)");
    // else
    //     Serial.printf("sendTransaction failed (%d): %s\n", (int)errB, ckb.lastErrorStr());

    // ── Wipe key material ─────────────────────────────────────────────────────
    key.clear();
    vTaskDelete(nullptr);
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    xTaskCreatePinnedToCore(transferTask, "ckb", 32768, nullptr, 1, nullptr, 1);
}
void loop() { delay(10000); }
