/*
 * IndexerCells.ino
 * CKB-ESP32 example — query all live cells for an address using the Indexer.
 * Shows pagination, cell data inspection, and type script detection.
 *
 * Useful for: NFT/token detection, DAO deposit tracking, custom cell monitoring.
 */

#include <WiFi.h>
#include "CKB.h"

const char* SSID      = "YOUR_WIFI_SSID";
const char* PASSWORD  = "YOUR_WIFI_PASSWORD";
const char* CKB_NODE  = "http://192.168.1.100:8114";

const char* TARGET_ADDR = "ckb1qyqwueud5e9j3lp3chv8qq820s7lxyggd9usvlg";

// Known type script code hashes for identification
const char* DAO_CODE_HASH  = "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76978698d00d1d8f6aa5cb7a81";
const char* SUDT_CODE_HASH = "0x5e7a36a77e68eecc013dfa2fe6a23f3b6c344b04005808694ae6dd45eea4cfd5";
const char* XUDT_CODE_HASH = "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb";

CKBClient ckb(CKB_NODE);

const char* identifyTypeScript(const CKBScript& type) {
    if (!type.valid) return "none";
    if (strncmp(type.codeHash, DAO_CODE_HASH, 10) == 0)  return "Nervos DAO";
    if (strncmp(type.codeHash, SUDT_CODE_HASH, 10) == 0) return "SUDT token";
    if (strncmp(type.codeHash, XUDT_CODE_HASH, 10) == 0) return "xUDT token";
    return "unknown type";
}

void setup() {
    Serial.begin(115200);
    delay(500);

    WiFi.begin(SSID, PASSWORD);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println("\nConnected");

    CKBScript lock = CKBClient::decodeAddress(TARGET_ADDR);
    if (!lock.valid) { Serial.println("Invalid address"); return; }

    Serial.printf("Querying cells for: %s\n\n", TARGET_ADDR);

    // ── Paginated cell query ──────────────────────────────────────────────────
    uint64_t totalCapacity = 0;
    uint32_t totalCells    = 0;
    uint32_t daoCells      = 0;
    uint32_t tokenCells    = 0;
    char cursor[67]        = "";
    uint8_t page           = 0;

    do {
        CKBCellsResult result = ckb.getCells(lock, "lock", 32,
            strlen(cursor) > 0 ? cursor : nullptr);

        if (result.error != CKB_OK) {
            Serial.printf("Error on page %u: %s\n", page, ckb.lastErrorStr());
            break;
        }

        Serial.printf("── Page %u: %u cells ──\n", page, result.count);

        for (uint8_t i = 0; i < result.count; i++) {
            CKBIndexerCell& c = result.cells[i];
            float ckbAmt = CKBClient::shannonToCKB(c.output.capacity);
            const char* typeLabel = identifyTypeScript(c.output.type);

            Serial.printf("  [%u] %s\n", totalCells + i,
                CKBClient::formatCKB(c.output.capacity).c_str());
            Serial.printf("      OutPoint: %s:%u\n", c.outPoint.txHash, c.outPoint.index);
            Serial.printf("      Block:    %llu  Type: %s\n",
                (unsigned long long)c.blockNumber, typeLabel);

            if (strcmp(typeLabel, "Nervos DAO") == 0) daoCells++;
            if (strcmp(typeLabel, "SUDT token") == 0 ||
                strcmp(typeLabel, "xUDT token") == 0) tokenCells++;

            totalCapacity += c.output.capacity;
        }

        totalCells += result.count;

        if (result.hasMore) {
            strlcpy(cursor, result.lastCursor, sizeof(cursor));
            page++;
        } else {
            break;
        }

        delay(200); // be polite to the node
    } while (true);

    // ── Summary ───────────────────────────────────────────────────────────────
    Serial.println("\n═══════════════════════════════════════");
    Serial.printf("Total cells:    %u\n", totalCells);
    Serial.printf("Total capacity: %s\n",
        CKBClient::formatCKB(totalCapacity).c_str());
    Serial.printf("DAO cells:      %u\n", daoCells);
    Serial.printf("Token cells:    %u\n", tokenCells);
    Serial.printf("Plain CKB:      %u\n",
        totalCells - daoCells - tokenCells);
    Serial.println("═══════════════════════════════════════");
}

void loop() { delay(60000); }
