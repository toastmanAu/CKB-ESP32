/*
 * WatchAddress.ino
 * CKB-ESP32 example — watch a CKB address for incoming payments.
 * Prints an alert on Serial when any new transaction is detected.
 *
 * Use case: BlackBox POS payment monitor, whale alert, personal wallet watcher.
 *
 * Requires: CKB node with built-in indexer (CKB >= v0.100)
 */

#include <WiFi.h>
#include "CKB.h"

const char* SSID     = "YOUR_WIFI_SSID";
const char* PASSWORD = "YOUR_WIFI_PASSWORD";
const char* CKB_NODE = "http://192.168.1.100:8114";

// Address to watch — replace with any CKB mainnet address
const char* WATCH_ADDR = "ckb1qyqwueud5e9j3lp3chv8qq820s7lxyggd9usvlg";

// Poll interval (ms) — CKB blocks ~6s, no need to poll faster than this
const uint32_t POLL_INTERVAL_MS = 10000;

CKBClient ckb(CKB_NODE);

uint64_t lastSeenBlock = 0;
CKBScript watchLock;

void onPaymentDetected(const CKBIndexerTx& tx) {
    Serial.println("\n┌─────────────────────────────────────────┐");
    Serial.println("│         💰 PAYMENT DETECTED              │");
    Serial.println("└─────────────────────────────────────────┘");
    Serial.printf("  Tx:    %s\n", tx.txHash);
    Serial.printf("  Block: %llu\n", (unsigned long long)tx.blockNumber);
    Serial.printf("  Type:  %s\n", tx.ioType == 1 ? "received (output)" : "sent (input)");

    // Get full transaction to see the amount
    CKBTransaction fullTx = ckb.getTransaction(tx.txHash);
    if (fullTx.valid) {
        // Sum outputs going to our address
        uint64_t received = 0;
        for (uint8_t i = 0; i < fullTx.outputCount; i++) {
            // Check if this output's lock matches our watch address
            if (strcmp(fullTx.outputs[i].lock.args, watchLock.args) == 0 &&
                strcmp(fullTx.outputs[i].lock.codeHash, watchLock.codeHash) == 0) {
                received += fullTx.outputs[i].capacity;
            }
        }
        if (received > 0) {
            Serial.printf("  Amount: %s\n",
                CKBClient::formatCKB(received).c_str());
        }
    }

    // Get current balance
    CKBBalance bal = ckb.getCellsCapacity(watchLock, "lock");
    if (bal.error == CKB_OK) {
        Serial.printf("  Balance now: %s (%u cells)\n",
            CKBClient::formatCKB(bal.shannon).c_str(),
            bal.cellCount);
    }
    Serial.println();
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

    // Get initial balance
    CKBBalance bal = ckb.getCellsCapacity(watchLock, "lock");
    if (bal.error == CKB_OK) {
        Serial.printf("Current balance: %s (%u cells)\n\n",
            CKBClient::formatCKB(bal.shannon).c_str(), bal.cellCount);
    }

    // Set baseline block
    CKBIndexerTip tip = ckb.getIndexerTip();
    if (tip.valid) {
        lastSeenBlock = tip.blockNumber;
        Serial.printf("Watching from block %llu...\n", (unsigned long long)lastSeenBlock);
    }
}

void loop() {
    delay(POLL_INTERVAL_MS);

    // Check for new activity
    if (ckb.hasNewActivity(watchLock, lastSeenBlock)) {
        // Get recent transactions to find what changed
        CKBTxsResult txs = ckb.getTransactions(watchLock, "lock", "both", 5);
        for (uint8_t i = 0; i < txs.count; i++) {
            if (txs.txs[i].blockNumber >= lastSeenBlock - 2) {
                onPaymentDetected(txs.txs[i]);
            }
        }
    } else {
        // Just print a heartbeat dot every poll
        Serial.print(".");
    }
}
