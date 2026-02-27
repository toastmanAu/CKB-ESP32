/*
 * CKBSigningExample.ino
 *
 * Demonstrates on-device secp256k1 signing for a CKB transaction.
 * Shows key loading, address derivation, signing, and witness construction.
 *
 * Flow:
 *   1. Load private key
 *   2. Derive address — confirm it matches your expected CKB address
 *   3. Build a transfer (UTXO collection + Molecule encoding)
 *   4. Sign on-device (secp256k1, RFC6979 — no cloud, no external chip)
 *   5. Print 65-byte witness signature as hex
 *
 * For a full build+sign+broadcast in one call, see sendTransaction() in TransferCKB.
 *
 * !! NEVER hard-code a real private key in firmware you'll share !!
 *    Use Preferences/NVS or derive from a hardware seed.
 *    See the Key Security section in the README.
 */

#define CKB_PROFILE_SIGNER
#include <Arduino.h>
#include <WiFi.h>
#include "CKB.h"
#include "CKBSigner.h"

// ── Config ────────────────────────────────────────────────────────────────────
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
const char* CKB_NODE  = "http://192.168.1.100:8114";

// Test key — DO NOT use a funded key here in firmware you'll flash and forget
// Load from NVS in production: see README Key Security section
const char* TEST_PRIVKEY_HEX =
    "0000000000000000000000000000000000000000000000000000000000000001";

// Destination address for the example transfer
const char* TO_ADDR = "ckb1q...your-recipient-address";
const float SEND_CKB = 10.0f;

// Run in 32KB task — crypto + Molecule need more than default 8KB stack
void signingTask(void*) {
    Serial.println("\n=== CKB On-Device Signing Demo ===\n");

    // ── 1. Load key ────────────────────────────────────────────────────────
    CKBKey key;
    if (!key.loadPrivateKeyHex(TEST_PRIVKEY_HEX)) {
        Serial.println("ERROR: invalid private key");
        vTaskDelete(nullptr); return;
    }
    Serial.println("✓ Private key loaded");

    // ── 2. Derive address (no need to hardcode it) ─────────────────────────
    char addr[120];
    if (key.getAddress(addr, sizeof(addr), true)) {   // true = mainnet
        Serial.print("  Address (mainnet): "); Serial.println(addr);
    }

    char lockArgsHex[43];
    if (key.getLockArgsHex(lockArgsHex, sizeof(lockArgsHex))) {
        Serial.print("  Lock args:         "); Serial.println(lockArgsHex);
    }

    uint8_t pubKey[33];
    if (key.getPublicKey(pubKey)) {
        char pubHex[67];
        CKBSigner::bytesToHex(pubKey, 33, pubHex);
        Serial.print("  Compressed pubkey: 0x"); Serial.println(pubHex);
    }

    // ── 3. Connect WiFi and build transaction ──────────────────────────────
    Serial.printf("\nConnecting to %s...", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis()-t0 < 15000)
        { delay(300); Serial.print("."); }
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\nWiFi failed"); vTaskDelete(nullptr); return;
    }
    Serial.printf("\nConnected: %s\n\n", WiFi.localIP().toString().c_str());

    CKBClient ckb(CKB_NODE);
    CKBBuiltTx tx = ckb.buildTransfer(addr, TO_ADDR, CKBClient::ckbToShannon(SEND_CKB));
    if (!tx.valid) {
        Serial.printf("Build failed: %s\n", ckb.lastErrorStr());
        vTaskDelete(nullptr); return;
    }
    Serial.printf("TX hash:     %s\n", tx.txHashHex);
    char sigHashHex[65];
    CKBSigner::bytesToHex(tx.signingHash, 32, sigHashHex);
    Serial.printf("Sign this:   0x%s\n\n", sigHashHex);

    // ── 4. Sign ────────────────────────────────────────────────────────────
    // The signing hash (tx.signingHash) is what the secp256k1 lock script verifies.
    // It's Blake2b(tx_hash || u64le(witness_len) || witness_with_zeroed_lock).
    unsigned long ts = millis();
    CKBError signErr = ckb.signTx(tx, key);
    unsigned long elapsed = millis() - ts;

    if (signErr != CKB_OK || !tx.signed_) {
        Serial.printf("Sign failed: %d\n", (int)signErr);
        vTaskDelete(nullptr); return;
    }

    // Signature format: [r(32) | s(32) | recid(1)]
    char sigHex[131];
    CKBSigner::bytesToHex(tx.signature, 65, sigHex);
    Serial.printf("✓ Signed in %lu ms\n", elapsed);
    Serial.printf("  r:     0x%.64s\n", sigHex);
    Serial.printf("  s:     0x%.64s\n", sigHex + 64);
    Serial.printf("  recid: %u\n", tx.signature[64]);
    Serial.printf("  full:  0x%s\n\n", sigHex);

    // ── 5. WitnessArgs molecule (85 bytes) ────────────────────────────────
    // This is what goes in the witnesses[] array of the send_transaction RPC call.
    uint8_t witnessBytes[CKB_WITNESS_ARGS_LEN];
    CKBSigner::buildWitnessWithSig(tx.signature, witnessBytes);
    char witnessHex[CKB_WITNESS_ARGS_LEN * 2 + 3];
    witnessHex[0] = '0'; witnessHex[1] = 'x';
    CKBSigner::bytesToHex(witnessBytes, CKB_WITNESS_ARGS_LEN, witnessHex + 2);
    Serial.printf("WitnessArgs (85 bytes):\n  %s\n\n", witnessHex);

    // ── 6. Broadcast ───────────────────────────────────────────────────────
    char txHash[67] = {0};
    CKBError err = CKBClient::broadcast(tx, CKB_NODE, txHash);
    if (err == CKB_OK)
        Serial.printf("✓ Broadcast OK: %s\n", txHash[0] ? txHash : "(already in pool)");
    else
        Serial.printf("✗ Broadcast failed (%d) — %s\n", (int)err, ckb.lastErrorStr());

    // Wipe key material from RAM when done
    key.clear();
    vTaskDelete(nullptr);
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    xTaskCreatePinnedToCore(signingTask, "sign", 32768, nullptr, 1, nullptr, 1);
}
void loop() { delay(10000); }
