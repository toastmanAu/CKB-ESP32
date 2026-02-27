/*
 * WatchAddress.ino
 * CKB-ESP32 example — watch a CKB address for incoming payments.
 *
 * Polls the indexer every 10 seconds. Prints an alert on Serial
 * when any new transaction is detected and shows the received amount.
 *
 * Use case: POS payment monitor, whale alert, personal wallet watcher.
 *
 * Requires: CKB full node with built-in indexer (CKB >= v0.100)
 */

#define CKB_PROFILE_DISPLAY
#include <WiFi.h>
#include "CKB.h"

const char* SSID     = "YOUR_WIFI_SSID";
const char* PASSWORD = "YOUR_WIFI_PASSWORD";
const char* CKB_NODE = "http://192.168.1.100:8114";

// Address to watch — replace with any CKB mainnet address
const char* WATCH_ADDR = "ckb1q...your-address-here";

const uint32_t POLL_INTERVAL_MS = 10000;   // ~6s blocks, no need to poll faster

CKBClient ckb(CKB_NODE);
uint64_t  lastSeenBlock = 0;
CKBScript watchLock;

void onPaymentDetected(const CKBIndexerTx& tx) {
    Serial.println("\n┌─────────────────────────────────────────┐");
    Serial.println("│         💰 PAYMENT DETECTED              │");
    Serial.println("└─────────────────────────────────────────┘");
    Serial.printf("  Tx:    %s\n", tx.txHash);
    Serial.printf("  Block: %llu\n", (unsigned long long)tx.blockNumber);
    Serial.printf("  Type:  %s\n", tx.ioType == 1 ? "received (output)" : "sent (input)");

    // Fetch full transaction to calculate received amount
    CKBTransaction fullTx = ckb.getTransaction(tx.txHash);
    if (fullTx.valid) {
        uint64_t received = 0;
        for (uint8_t i = 0; i < fullTx.outputCount; i++) {
            if (strcmp(fullTx.outputs[i].lock.args, watchLock.args) == 0 &&
                strcmp(fullTx.outputs[i].lock.codeHash, watchLock.codeHash) == 0) {
                received += fullTx.outputs[i].capacity;
            }
        }
        if (received > 0)
            Serial.printf("  Amount: %s\n", CKBClient::formatCKB(received).c_str());
    }

    // Show updated balance
    CKBBalance bal = ckb.getCellsCapacity(watchLock);
    if (bal.error == CKB_OK)
        Serial.printf("  Balance now: %s (%u cells)\n\n",
            CKBClient::formatCKB(bal.shannon).c_str(), bal.cellCount);
}

void setup() {
    Serial.begin(115200);
    delay(500);

    WiFi.begin(SSID, PASSWORD);
    Serial.print("Connecting WiFi");
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println(" OK");

    // Decode address to lock script once
    watchLock = CKBClient::decodeAddress(WATCH_ADDR);
    if (!watchLock.valid) {
        Serial.printf("Invalid address: %s\n", WATCH_ADDR);
        while (true) delay(1000);
    }
    Serial.printf("\nWatching: %s\n", WATCH_ADDR);
    Serial.printf("Lock args: %s\n\n", watchLock.args);

    // Show current balance
    CKBBalance bal = ckb.getCellsCapacity(watchLock);
    if (bal.error == CKB_OK)
        Serial.printf("Current balance: %s (%u cells)\n\n",
            CKBClient::formatCKB(bal.shannon).c_str(), bal.cellCount);

    // Set baseline (don't alert on existing transactions)
    CKBIndexerTip tip = ckb.getIndexerTip();
    if (tip.valid) {
        lastSeenBlock = tip.blockNumber;
        Serial.printf("Watching from block %llu...\n", (unsigned long long)lastSeenBlock);
    }
}

void loop() {
    delay(POLL_INTERVAL_MS);

    if (ckb.hasNewActivity(watchLock, lastSeenBlock)) {
        // Fetch recent transactions and surface any in the new blocks
        CKBTxsResult txs = ckb.getTransactions(watchLock, "lock", "both", 5);
        for (uint8_t i = 0; i < txs.count; i++) {
            if (txs.txs[i].blockNumber >= lastSeenBlock - 2)
                onPaymentDetected(txs.txs[i]);
        }
    } else {
        Serial.print(".");   // heartbeat dot — no new activity
    }
}
