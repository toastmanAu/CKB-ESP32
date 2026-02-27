/*
 * BasicNodeInfo.ino
 * CKB-ESP32 example — connect to a CKB node, display tip block, peers, epoch.
 *
 * Hardware: any ESP32 board with WiFi
 * Libraries: CKB-ESP32, ArduinoJson
 * Profile: DISPLAY (no signing, no send)
 */

#define CKB_PROFILE_DISPLAY
#include <WiFi.h>
#include "CKB.h"

const char* SSID      = "YOUR_WIFI_SSID";
const char* PASSWORD  = "YOUR_WIFI_PASSWORD";
const char* CKB_NODE  = "http://192.168.1.100:8114";

CKBClient ckb(CKB_NODE);

void setup() {
    Serial.begin(115200);
    delay(500);

    Serial.printf("Connecting to %s...\n", SSID);
    WiFi.begin(SSID, PASSWORD);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.printf("\nConnected! IP: %s\n\n", WiFi.localIP().toString().c_str());

    // ── Tip block number ──────────────────────────────────────────────────────
    uint64_t tip = ckb.getTipBlockNumber();
    if (tip == UINT64_MAX) {
        Serial.printf("Error getting tip: %s\n", ckb.lastErrorStr());
    } else {
        Serial.printf("Tip block:  %llu\n", (unsigned long long)tip);
    }

    // ── Chain info ────────────────────────────────────────────────────────────
    CKBChainInfo chain = ckb.getBlockchainInfo();
    if (chain.valid) {
        Serial.printf("Network:    %s (%s)\n",
            chain.networkId, chain.isMainnet ? "mainnet" : "testnet");
        Serial.printf("Epoch:      %llu\n", (unsigned long long)chain.epoch);
    }

    // ── Current epoch ─────────────────────────────────────────────────────────
    CKBEpoch epoch = ckb.getCurrentEpoch();
    if (epoch.valid) {
        Serial.printf("Epoch #%llu:  starts at block %llu, length %llu\n",
            (unsigned long long)epoch.number,
            (unsigned long long)epoch.startNumber,
            (unsigned long long)epoch.length);
        if (tip != UINT64_MAX && tip >= epoch.startNumber) {
            uint64_t progress = tip - epoch.startNumber;
            if (progress > epoch.length) progress = epoch.length;  // clamp at 100%
            Serial.printf("Progress:   block %llu / %llu (%.1f%%)\n",
                (unsigned long long)progress,
                (unsigned long long)epoch.length,
                100.0 * progress / epoch.length);
        }
    }

    // ── Tx pool ───────────────────────────────────────────────────────────────
    CKBTxPoolInfo pool = ckb.getTxPoolInfo();
    if (pool.valid) {
        Serial.printf("Tx pool:    %llu pending, %llu proposed\n",
            (unsigned long long)pool.pending,
            (unsigned long long)pool.proposed);
    }

    // ── Peers ─────────────────────────────────────────────────────────────────
    CKBPeer peers[8];
    uint8_t peerCount = ckb.getPeers(peers, 8);
    Serial.printf("Peers:      %u connected\n", peerCount);
    for (uint8_t i = 0; i < peerCount && i < 3; i++) {
        Serial.printf("  [%u] %s (%s)\n", i,
            peers[i].nodeId,
            peers[i].direction ? "out" : "in");
    }

    // ── Latest block ──────────────────────────────────────────────────────────
    if (tip != UINT64_MAX) {
        CKBBlock block = ckb.getBlockByNumber(tip);
        if (block.valid) {
            time_t t = CKBClient::msToTime(block.header.timestamp);
            struct tm* tm_info = gmtime(&t);
            char timeBuf[32];
            strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S UTC", tm_info);
            Serial.printf("\nLatest block %llu:\n", (unsigned long long)tip);
            Serial.printf("  Time:   %s\n", timeBuf);
            Serial.printf("  Txs:    %u\n", block.txCount);
            Serial.printf("  Miner:  0x%s\n", block.minerLockArgs);
            Serial.printf("  Hash:   %s\n", block.header.hash);
        }
    }

    // ── Indexer tip ───────────────────────────────────────────────────────────
    CKBIndexerTip idxTip = ckb.getIndexerTip();
    if (idxTip.valid) {
        Serial.printf("\nIndexer at: block %llu\n",
            (unsigned long long)idxTip.blockNumber);
        if (tip != UINT64_MAX) {
            int64_t lag = (int64_t)tip - (int64_t)idxTip.blockNumber;
            if (lag > 0) Serial.printf("Indexer lag: %lld blocks behind\n", (long long)lag);
            else         Serial.println("Indexer: fully synced");
        }
    }
}

void loop() {
    delay(10000);
    uint64_t tip = ckb.getTipBlockNumber();
    if (tip != UINT64_MAX)
        Serial.printf("[%lu] Tip: %llu\n", millis()/1000, (unsigned long long)tip);
}
