#ifndef CKB_ESP32_H
#define CKB_ESP32_H

/*
 * CKB-ESP32  —  Nervos CKB RPC library for ESP32 / Arduino
 *
 * Wraps CKB JSON-RPC + CKB Indexer RPC into clean C++ structs and functions.
 * Uses ArduinoJson + WiFiClient (HTTPClient). No external dependencies beyond
 * the Arduino ESP32 core.
 *
 * Supports:
 *   - CKB Node RPC  (get_tip_block_number, get_block_by_number, get_transaction,
 *                    get_live_cell, local_node_info, get_peers, tx_pool_info,
 *                    get_blockchain_info, get_epoch_by_number, calculate_dao_field)
 *   - CKB Indexer   (get_cells, get_transactions, get_cells_capacity,
 *                    get_indexer_tip)
 *   - Helpers       (shannonToCKB, hexToUint64, addrToLockScript, formatCKB)
 *
 * Author:  toastmanAu  (Phill)
 * Repo:    https://github.com/toastmanAu/CKB-ESP32
 * License: MIT
 *
 * Quick start:
 *   CKBClient ckb("http://192.168.1.100:8114", "http://192.168.1.100:8116");
 *   uint64_t tip = ckb.getTipBlockNumber();
 *   CKBBalance bal = ckb.getBalance("ckb1qyq...");
 */

#include <Arduino.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <WiFiClientSecure.h>

// ─── Version ──────────────────────────────────────────────────────────────────
#define CKB_ESP32_VERSION      "1.0.0"
#define CKB_ESP32_VERSION_MAJOR 1
#define CKB_ESP32_VERSION_MINOR 0
#define CKB_ESP32_VERSION_PATCH 0

// ─── Defaults ─────────────────────────────────────────────────────────────────
#ifndef CKB_JSON_DOC_SIZE
  #define CKB_JSON_DOC_SIZE    8192   // Increase for large blocks/tx lists
#endif
#ifndef CKB_HTTP_TIMEOUT_MS
  #define CKB_HTTP_TIMEOUT_MS  8000
#endif
#ifndef CKB_MAX_CELLS
  #define CKB_MAX_CELLS        64     // Max cells returned in one Indexer query
#endif
#ifndef CKB_MAX_TXS
  #define CKB_MAX_TXS          32
#endif
#ifndef CKB_MAX_PEERS
  #define CKB_MAX_PEERS        16
#endif

// ─── Constants ────────────────────────────────────────────────────────────────
#define CKB_SHANNON_PER_CKB    100000000ULL   // 1 CKB = 10^8 shannon
#define CKB_MAINNET_PREFIX     "ckb"
#define CKB_TESTNET_PREFIX     "ckt"

// ─── Error codes ──────────────────────────────────────────────────────────────
typedef enum {
    CKB_OK              = 0,
    CKB_ERR_HTTP        = -1,   // HTTP request failed
    CKB_ERR_JSON        = -2,   // JSON parse error
    CKB_ERR_RPC         = -3,   // RPC returned error field
    CKB_ERR_NOT_FOUND   = -4,   // Resource not found (null result)
    CKB_ERR_TIMEOUT     = -5,   // Request timed out
    CKB_ERR_INVALID     = -6,   // Invalid argument
} CKBError;

// ─── Core data structures ─────────────────────────────────────────────────────

/** Script (lock/type) */
struct CKBScript {
    char codeHash[67];   // 0x + 64 hex
    char hashType[8];    // "type" | "data" | "data1" | "data2"
    char args[131];      // 0x + up to 128 hex chars (common: 42 for secp256k1)
    bool valid;
};

/** OutPoint — identifies a cell */
struct CKBOutPoint {
    char txHash[67];
    uint32_t index;
};

/** Cell output */
struct CKBCellOutput {
    uint64_t capacity;      // in shannon
    CKBScript lock;
    CKBScript type;         // may be empty (valid=false)
    bool hasType;
};

/** Live cell (outpoint + output + data) */
struct CKBLiveCell {
    CKBOutPoint outPoint;
    CKBCellOutput output;
    char outputData[131];   // hex-encoded cell data (truncated if large)
    uint64_t blockNumber;
    char txIndex[10];
    bool valid;
};

/** Transaction input */
struct CKBInput {
    CKBOutPoint previousOutput;
    char since[19];          // hex uint64
};

/** Transaction */
struct CKBTransaction {
    char hash[67];
    uint32_t version;
    CKBInput inputs[8];
    uint8_t inputCount;
    CKBCellOutput outputs[8];
    uint8_t outputCount;
    uint64_t blockNumber;
    char blockHash[67];
    uint64_t timestamp;     // ms since epoch (from block header)
    uint8_t status;         // 0=pending 1=proposed 2=committed
    bool valid;
};

/** Block header */
struct CKBBlockHeader {
    char hash[67];
    uint64_t number;
    uint64_t timestamp;     // ms
    uint32_t version;
    char parentHash[67];
    char transactionsRoot[67];
    uint64_t compactTarget;
    uint32_t nonce;         // truncated — full nonce is 128-bit
    char dao[35];           // DAO field hex
    bool valid;
};

/** Block (header + tx count) */
struct CKBBlock {
    CKBBlockHeader header;
    uint32_t txCount;
    char minerLockArgs[43]; // secp256k1 args = miner pubkey hash (20 bytes)
    bool valid;
};

/** Epoch */
struct CKBEpoch {
    uint64_t number;
    uint64_t startNumber;   // block number
    uint64_t length;
    uint64_t compactTarget;
    bool valid;
};

/** Node peer */
struct CKBPeer {
    char nodeId[53];        // libp2p peer ID
    char address[64];       // multiaddr
    uint8_t direction;      // 0=inbound 1=outbound
    bool syncedBlock;
};

/** Local node info */
struct CKBNodeInfo {
    char nodeId[53];
    char version[24];
    char networkId[12];     // "ckb" or "ckb_testnet"
    uint64_t tipBlockNumber;
    uint32_t peersCount;
    bool valid;
};

/** Tx pool info */
struct CKBTxPoolInfo {
    uint64_t pending;
    uint64_t proposed;
    uint64_t totalTxSize;
    uint64_t minFeeRate;    // shannons per 1000 bytes
    bool valid;
};

/** Blockchain info */
struct CKBChainInfo {
    bool isMainnet;
    char networkId[12];
    uint64_t epoch;
    uint64_t difficulty;    // compact target as uint64
    char medianTime[19];    // hex
    bool valid;
};

// ─── Indexer structures ───────────────────────────────────────────────────────

/** Search key for Indexer queries */
struct CKBSearchKey {
    CKBScript script;
    char scriptType[7];     // "lock" or "type"
    // Optional filters
    bool filterEnabled;
    uint64_t filterBlockMin;
    uint64_t filterBlockMax;
};

/** Indexer cell result */
struct CKBIndexerCell {
    CKBOutPoint outPoint;
    CKBCellOutput output;
    char outputData[67];
    uint64_t blockNumber;
    char txIndex[10];
};

/** Indexer cells result set */
struct CKBCellsResult {
    CKBIndexerCell cells[CKB_MAX_CELLS];
    uint8_t count;
    char lastCursor[67];    // for pagination
    bool hasMore;
    CKBError error;
};

/** Indexer transaction record */
struct CKBIndexerTx {
    char txHash[67];
    uint64_t blockNumber;
    char txIndex[10];
    uint8_t ioType;         // 0=input 1=output
    uint32_t ioIndex;
};

/** Indexer transactions result */
struct CKBTxsResult {
    CKBIndexerTx txs[CKB_MAX_TXS];
    uint8_t count;
    char lastCursor[67];
    bool hasMore;
    CKBError error;
};

/** Balance (total capacity of live cells for a lock script) */
struct CKBBalance {
    uint64_t shannon;       // raw capacity in shannon
    float ckb;              // shannon / 1e8 (convenience)
    uint32_t cellCount;
    CKBError error;
};

/** Indexer tip */
struct CKBIndexerTip {
    uint64_t blockNumber;
    char blockHash[67];
    bool valid;
};

// ─── CKBClient class ──────────────────────────────────────────────────────────

class CKBClient {
public:
    /**
     * @param nodeUrl    CKB node RPC URL  e.g. "http://192.168.1.100:8114"
     * @param indexerUrl CKB indexer URL   e.g. "http://192.168.1.100:8116"
     *                   (same as node for CKB >= v0.100 with built-in indexer)
     */
    CKBClient(const char* nodeUrl, const char* indexerUrl = nullptr);

    // ── Configuration ─────────────────────────────────────────────────────────
    void setTimeoutMs(uint32_t ms) { _timeoutMs = ms; }
    void setDebug(bool enable)     { _debug = enable; }
    CKBError lastError()     const { return _lastError; }
    const char* lastErrorStr() const;

    // ══════════════════════════════════════════════════════════════════════════
    //  NODE RPC — Chain
    // ══════════════════════════════════════════════════════════════════════════

    /** Current tip block number. Returns UINT64_MAX on error. */
    uint64_t getTipBlockNumber();

    /** Full block by number. Pass verbose=true for full tx data (slow/large). */
    CKBBlock getBlockByNumber(uint64_t number, bool verbose = false);

    /** Block by hash */
    CKBBlock getBlockByHash(const char* blockHash, bool verbose = false);

    /** Block header only (lighter than full block) */
    CKBBlockHeader getHeaderByNumber(uint64_t number);
    CKBBlockHeader getHeaderByHash(const char* blockHash);

    /** Current epoch info */
    CKBEpoch getCurrentEpoch();
    CKBEpoch getEpochByNumber(uint64_t epochNumber);

    // ══════════════════════════════════════════════════════════════════════════
    //  NODE RPC — Transactions & Cells
    // ══════════════════════════════════════════════════════════════════════════

    /** Full transaction by hash */
    CKBTransaction getTransaction(const char* txHash);

    /** Live cell at outpoint. Returns valid=false if spent/not found. */
    CKBLiveCell getLiveCell(const char* txHash, uint32_t index, bool withData = true);

    // ══════════════════════════════════════════════════════════════════════════
    //  NODE RPC — Node & Network
    // ══════════════════════════════════════════════════════════════════════════

    /** Local node info (version, peer ID, network, tip) */
    CKBNodeInfo getNodeInfo();

    /** Tx pool stats */
    CKBTxPoolInfo getTxPoolInfo();

    /** Blockchain info (network ID, epoch, etc.) */
    CKBChainInfo getBlockchainInfo();

    /** Peer list (up to CKB_MAX_PEERS) */
    uint8_t getPeers(CKBPeer peers[], uint8_t maxPeers = CKB_MAX_PEERS);

    // ══════════════════════════════════════════════════════════════════════════
    //  INDEXER RPC
    // ══════════════════════════════════════════════════════════════════════════

    /** Indexer sync tip */
    CKBIndexerTip getIndexerTip();

    /**
     * Get live cells for a lock script (i.e. cells owned by an address).
     * @param lockScript  The lock script to search for
     * @param limit       Max results per page (default 100, max CKB_MAX_CELLS)
     * @param cursor      Pagination cursor from previous result (or nullptr)
     */
    CKBCellsResult getCells(const CKBScript& lockScript,
                             const char* scriptType = "lock",
                             uint8_t limit = 64,
                             const char* cursor = nullptr,
                             uint64_t filterBlockMin = 0,
                             uint64_t filterBlockMax = 0);

    /**
     * Get transactions involving a lock script.
     * @param ioType  "input", "output", or "both"
     */
    CKBTxsResult getTransactions(const CKBScript& lockScript,
                                  const char* scriptType = "lock",
                                  const char* ioType = "both",
                                  uint8_t limit = 32,
                                  const char* cursor = nullptr);

    /**
     * Get total capacity (balance) of cells matching a lock script.
     * This is the lightest way to get a CKB address balance.
     */
    CKBBalance getCellsCapacity(const CKBScript& lockScript,
                                 const char* scriptType = "lock");

    // ══════════════════════════════════════════════════════════════════════════
    //  HIGH-LEVEL HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Get balance for a full CKB address string (ckb1qyq...).
     * Decodes the bech32 address to lock script internally.
     * Requires indexer.
     */
    CKBBalance getBalance(const char* ckbAddress);

    /**
     * Watch an address — returns true if any new transactions appeared
     * since lastKnownTip. Updates lastKnownTip to current indexer tip.
     * Use in loop() with a polled interval.
     */
    bool hasNewActivity(const CKBScript& lockScript, uint64_t& lastKnownBlock);

    /**
     * Get the most recent N transactions for an address.
     * Convenience wrapper around getTransactions.
     */
    CKBTxsResult getRecentTransactions(const char* ckbAddress, uint8_t count = 10);

    /**
     * Decode a CKB address (mainnet ckb1... or testnet ckt1...) to a lock script.
     * Supports: short (secp256k1), full (any script).
     * Returns script with valid=false on failure.
     */
    static CKBScript decodeAddress(const char* address);

    // ── Utility ───────────────────────────────────────────────────────────────

    /** Shannon to CKB float */
    static float shannonToCKB(uint64_t shannon);

    /** Shannon to CKB integer (floor) */
    static uint64_t shannonToCKBInt(uint64_t shannon);

    /** CKB to shannon */
    static uint64_t ckbToShannon(float ckb);

    /** Hex string ("0x1a2b") to uint64. Returns 0 on error. */
    static uint64_t hexToUint64(const char* hex);

    /** uint64 to hex string. Writes to buf (must be >=19 bytes). */
    static void uint64ToHex(uint64_t val, char* buf);

    /** Format shannon as human-readable CKB string e.g. "1,234.56 CKB" */
    static String formatCKB(uint64_t shannon);

    /** Format shannon as compact string e.g. "1.2K CKB" */
    static String formatCKBCompact(uint64_t shannon);

    /** Timestamp (ms) to Arduino time_t */
    static time_t msToTime(uint64_t timestampMs);

    /** Is a tx hash valid format? (0x + 64 hex chars) */
    static bool isValidTxHash(const char* hash);

    /** Is a CKB address plausibly valid? */
    static bool isValidAddress(const char* address);

private:
    char _nodeUrl[128];
    char _indexerUrl[128];
    bool _hasIndexer;
    uint32_t _timeoutMs;
    bool _debug;
    CKBError _lastError;
    int _rpcId;

    // Internal RPC caller
    bool _rpcCall(const char* url,
                  const char* method,
                  const char* params,
                  JsonDocument& doc);

    // Parser helpers
    void _parseScript(JsonObject obj, CKBScript& out);
    void _parseOutPoint(JsonObject obj, CKBOutPoint& out);
    void _parseCellOutput(JsonObject obj, CKBCellOutput& out);
    void _parseBlockHeader(JsonObject obj, CKBBlockHeader& out);
    CKBBlock _parseBlock(JsonObject obj);
    CKBTransaction _parseTransaction(JsonObject obj);

    // Address decoder helpers
    static bool _bech32Decode(const char* addr, uint8_t* data, size_t& len, char* hrp);
    static uint8_t _bech32CharToVal(char c);

    void _debugPrint(const char* msg);
};

// ─── Inline utility implementations ──────────────────────────────────────────

inline float CKBClient::shannonToCKB(uint64_t shannon) {
    return (float)shannon / (float)CKB_SHANNON_PER_CKB;
}

inline uint64_t CKBClient::shannonToCKBInt(uint64_t shannon) {
    return shannon / CKB_SHANNON_PER_CKB;
}

inline uint64_t CKBClient::ckbToShannon(float ckb) {
    return (uint64_t)(ckb * CKB_SHANNON_PER_CKB);
}

inline bool CKBClient::isValidTxHash(const char* hash) {
    if (!hash || strlen(hash) != 66) return false;
    if (hash[0] != '0' || hash[1] != 'x') return false;
    for (int i = 2; i < 66; i++) {
        char c = hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

inline bool CKBClient::isValidAddress(const char* address) {
    if (!address) return false;
    size_t len = strlen(address);
    if (len < 46) return false;
    bool mainnet = strncmp(address, "ckb1", 4) == 0;
    bool testnet = strncmp(address, "ckt1", 4) == 0;
    return mainnet || testnet;
}

#endif // CKB_ESP32_H
