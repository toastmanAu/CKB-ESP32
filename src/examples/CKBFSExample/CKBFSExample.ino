/*
 * CKBFSExample.ino — Store and retrieve data on CKB chain
 *
 * Demonstrates ckbfs_publish() and ckbfs_read() using CKB-ESP32.
 *
 * USE CASE: An embedded device stores its firmware manifest or
 * configuration permanently on-chain. Any other device can read it
 * with just the tx hash — no central server required.
 *
 * Hardware: Any ESP32 with WiFi (or W5500 Ethernet)
 * Requires: CKB full node + funded wallet (min ~62 CKB)
 */
#include <Arduino.h>
#include <WiFi.h>
#include "CKB.h"
#include "CKBSigner.h"
#include "ckbfs.h"

// ── Config ───────────────────────────────────────────────────────────────────
#define WIFI_SSID   "your_ssid"
#define WIFI_PASS   "your_password"
#define CKB_NODE    "http://192.168.68.87:8114"

// Private key (hex, 64 chars) — fund this address before running publish
#define PRIVKEY_HEX "0000000000000000000000000000000000000000000000000000000000000001"

// To read back after publish — fill in after first run
#define READ_TX_HASH  ""  // "0x..." from publish output
#define READ_WIT_IDX  1
#define READ_CHECKSUM 0   // 0 = skip checksum verify

// ── What to store ─────────────────────────────────────────────────────────────
const char *CONTENT = R"({
  "device": "WT9932P4-TINY",
  "firmware": "ckb-light-esp",
  "version": "0.1.0",
  "pubkey": "02...",
  "built": "2026-02-28"
})";

void setup() {
    Serial.begin(115200);
    delay(1000);

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("Connecting WiFi");
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(" OK  IP: " + WiFi.localIP().toString());

    // ── Load key ────────────────────────────────────────────────────────────
    CKBKey key;
    if (!key.loadPrivateKeyHex(PRIVKEY_HEX)) {
        Serial.println("Bad privkey!"); return;
    }
    char addr[110];
    key.getAddress(addr, sizeof(addr), true);
    Serial.println("Address: " + String(addr));

    // ── Publish ─────────────────────────────────────────────────────────────
    if (strlen(READ_TX_HASH) == 0) {
        Serial.println("\n=== PUBLISH ===");
        Serial.printf("Content: %zu bytes\n", strlen(CONTENT));

        char tx_hash[67] = {};
        ckbfs_err_t e = ckbfs_publish_string(
            CKB_NODE, key,
            CONTENT,
            "device-manifest.json",
            62,  // CKB to lock (permanent)
            tx_hash
        );

        if (e == CKBFS_OK) {
            Serial.println("Published! TX: " + String(tx_hash));
            Serial.println("Set READ_TX_HASH to this value and reflash to read back.");
        } else {
            Serial.printf("Publish failed: %d\n", e);
        }
    }

    // ── Read ────────────────────────────────────────────────────────────────
    else {
        Serial.println("\n=== READ ===");
        Serial.println("TX: " READ_TX_HASH);

        uint8_t buf[4096];
        size_t len = 0;
        ckbfs_err_t e = ckbfs_read(
            CKB_NODE, READ_TX_HASH, READ_WIT_IDX, READ_CHECKSUM,
            buf, sizeof(buf), &len
        );

        if (e == CKBFS_OK) {
            buf[len] = '\0';
            Serial.printf("Read %zu bytes:\n%s\n", len, (char*)buf);
        } else {
            Serial.printf("Read failed: %d\n", e);
        }
    }
}

void loop() {}
