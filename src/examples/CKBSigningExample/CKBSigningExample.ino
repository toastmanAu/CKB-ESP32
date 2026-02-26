/*
 * CKBSigningExample.ino
 *
 * Demonstrates on-device secp256k1 signing for a CKB transfer.
 *
 * Flow:
 *   1. Load private key
 *   2. Derive address — confirm it matches your expected CKB address
 *   3. Obtain tx_hash from node (after building tx via RPC or dry-run)
 *   4. Compute signing hash
 *   5. Sign
 *   6. Print 65-byte witness signature as hex
 *   7. (Optional) broadcast via send_transaction RPC
 *
 * !! NEVER hard-code a real private key in firmware you'll share !!
 *    Use Preferences/NVS or derive from a hardware seed.
 */

#include <Arduino.h>
#include <WiFi.h>
#include "CKB.h"
#include "CKBSigner.h"

// ── Config ────────────────────────────────────────────────────────────────────
const char* WIFI_SSID = "YourSSID";
const char* WIFI_PASS = "YourPassword";
const char* CKB_NODE  = "http://192.168.68.87:8114";

// Test private key (DO NOT use a funded key here!)
// This is the well-known test key: privkey = 0x0001...0001
const char* TEST_PRIVKEY_HEX =
    "0000000000000000000000000000000000000000000000000000000000000001";

// Example tx hash to sign (replace with a real one from your node)
const char* TEST_TX_HASH =
    "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c";

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n=== CKB On-Device Signing Demo ===\n");

    // ── 1. Load key ────────────────────────────────────────────────────────
    CKBKey key;
    if (!key.loadPrivateKeyHex(TEST_PRIVKEY_HEX)) {
        Serial.println("ERROR: invalid private key");
        return;
    }
    Serial.println("✓ Private key loaded");

    // ── 2. Derive address ──────────────────────────────────────────────────
    char addr[100];
    if (key.getAddress(addr, sizeof(addr), true)) {
        Serial.print("  Address (mainnet): ");
        Serial.println(addr);
    }

    char lockArgsHex[43];
    if (key.getLockArgsHex(lockArgsHex, sizeof(lockArgsHex))) {
        Serial.print("  Lock args:         ");
        Serial.println(lockArgsHex);
    }

    uint8_t pubKey[33];
    if (key.getPublicKey(pubKey)) {
        char pubHex[67];
        CKBSigner::bytesToHex(pubKey, 33, pubHex);
        Serial.print("  Compressed pubkey: ");
        Serial.println(pubHex);
    }

    // ── 3. Compute signing hash ────────────────────────────────────────────
    Serial.println();
    Serial.print("Tx hash: ");
    Serial.println(TEST_TX_HASH);

    uint8_t signingHash[32];
    if (!CKBSigner::computeSigningHash(TEST_TX_HASH, signingHash)) {
        Serial.println("ERROR: failed to compute signing hash");
        return;
    }
    char hashHex[65];
    CKBSigner::bytesToHex(signingHash, 32, hashHex);
    Serial.print("Signing hash: 0x");
    Serial.println(hashHex);

    // ── 4. Sign ────────────────────────────────────────────────────────────
    uint8_t sig[65];
    unsigned long t0 = millis();
    if (!CKBSigner::sign(signingHash, key, sig)) {
        Serial.println("ERROR: signing failed");
        return;
    }
    unsigned long elapsed = millis() - t0;

    char sigHex[131];
    CKBSigner::bytesToHex(sig, 65, sigHex);

    Serial.println();
    Serial.printf("✓ Signed in %lu ms\n", elapsed);
    Serial.print("  recid: ");
    Serial.println(sig[0]);
    Serial.print("  sig:   0x");
    Serial.println(sigHex);

    // ── 5. Build WitnessArgs molecule with real signature ──────────────────
    uint8_t witnessBytes[CKB_WITNESS_ARGS_LEN];
    CKBSigner::buildWitnessWithSig(sig, witnessBytes);

    char witnessHex[CKB_WITNESS_ARGS_LEN * 2 + 3];
    witnessHex[0] = '0'; witnessHex[1] = 'x';
    CKBSigner::bytesToHex(witnessBytes, CKB_WITNESS_ARGS_LEN, witnessHex + 2);

    Serial.println();
    Serial.print("WitnessArgs (85 bytes): ");
    Serial.println(witnessHex);

    // ── 6. (Optional) broadcast ────────────────────────────────────────────
    // To broadcast, connect WiFi, call CKBClient::broadcast(tx, nodeUrl)
    // Full broadcast flow: see CKBBroadcastExample
    Serial.println();
    Serial.println("=== Done — paste witness into your tx and broadcast ===");
}

void loop() {}
