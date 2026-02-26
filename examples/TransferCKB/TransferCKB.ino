/**
 * TransferCKB.ino — Build, sign, and broadcast a CKB transfer
 *
 * The transaction object is independent of where it's built or sent.
 * Build from one node, broadcast to any other.
 *
 * Node type selection (pick one, or omit for default = full):
 */
// #define CKB_NODE_LIGHT       // Light client
// #define CKB_NODE_INDEXER     // Separate indexer process
// #define CKB_NODE_RICH        // Rich indexer (Mercury)

#include <WiFi.h>
#include "CKB.h"

const char* WIFI_SSID  = "your-wifi";
const char* WIFI_PASS  = "your-password";

// Node used for building the tx (cell collection, indexer queries)
// For CKB_NODE_FULL / CKB_NODE_LIGHT: just one URL
CKBClient ckb("http://192.168.68.87:8114");

// For separate indexer:
// CKBClient ckb("http://192.168.68.87:8114", "http://192.168.68.87:8116");

// Broadcast target — can be any CKB node, does not need to match above
const char* BROADCAST_NODE = "http://192.168.68.87:8114";

const char*    FROM_ADDR = "ckb1qyqyouraddresshere";
const char*    TO_ADDR   = "ckb1qyqrecipientaddresshere";
const uint64_t AMOUNT    = 100ULL * 100000000ULL;  // 100 CKB
const uint64_t FEE       = 1000ULL;                // 1000 shannon

void setup() {
    Serial.begin(115200);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println("\nWiFi connected — node type: " + String(CKBClient::nodeTypeStr()));

    // ── 1. Check balance ──────────────────────────────────────────────────────
    CKBBalance bal = ckb.getBalance(FROM_ADDR);
    if (bal.valid) {
        Serial.printf("Balance: %s\n", CKBClient::formatCKB(bal.totalCapacity).c_str());
    }

    // ── 2. Build the transaction ──────────────────────────────────────────────
    Serial.println("Building transfer...");
    CKBBuiltTx tx = ckb.buildTransfer(FROM_ADDR, TO_ADDR, AMOUNT, FEE);

    if (!tx.valid) {
        Serial.printf("Build failed: %s\n", CKBClient::lastErrorStr());
        return;
    }

    // Inspect the transaction object
    Serial.printf("TX hash:    %s\n",   tx.txHashHex);
    Serial.printf("Inputs:     %d cells, total %s\n",
        tx.inputCount,
        CKBClient::formatCKB(tx.totalInputCapacity()).c_str());
    Serial.printf("Send:       %s\n", CKBClient::formatCKB(tx.outputs[0].capacity).c_str());
    if (tx.outputCount > 1)
        Serial.printf("Change:     %s\n", CKBClient::formatCKB(tx.outputs[1].capacity).c_str());
    Serial.printf("Fee:        %llu shannon\n", tx.fee());

    // The signing hash — pass this to your signing function
    Serial.print("Sign this:  ");
    for (int i = 0; i < 32; i++) Serial.printf("%02x", tx.signingHash[i]);
    Serial.println();

    // ── 3. Sign ───────────────────────────────────────────────────────────────
    // Sign tx.signingHash[32] with your secp256k1 private key.
    // Implementations:
    //   - Hardware wallet (ESP32-P4 + SPHINCS+): send over UART/SPI, get sig back
    //   - mbedTLS on-device secp256k1: see mbedtls/ecp.h + mbedtls/ecdsa.h
    //   - External signer: QR code → phone → scan back
    //
    // For testing (don't use for real funds):
    uint8_t mySig[65] = {0};  // replace with real signature

    tx.setSignature(mySig);

    // ── 4. Broadcast ──────────────────────────────────────────────────────────
    // Broadcast to ANY node — independent of which node built the tx
    char submittedHash[67] = {0};
    CKBError err = CKBClient::broadcast(tx, BROADCAST_NODE, submittedHash);

    if (err == CKB_OK) {
        Serial.printf("Broadcast OK: %s\n", submittedHash);
    } else {
        Serial.printf("Broadcast failed: %d\n", err);
    }

    // ── Advanced: broadcast with custom witness (e.g. SPHINCS+) ──────────────
    // const char* sphincsWitness = "0x<hex-encoded WitnessArgs with SPHINCS+ sig>";
    // CKBClient::broadcastWithWitness(tx, BROADCAST_NODE, sphincsWitness, submittedHash);
}

void loop() {}
