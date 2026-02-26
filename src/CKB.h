#ifndef CKB_ESP32_H
#define CKB_ESP32_H

/*
 * CKB-ESP32  —  Nervos CKB RPC library for ESP32 / Arduino
 *
 * Wraps CKB JSON-RPC + Indexer RPC into clean C++ structs and functions.
 * Supports full nodes, light clients, built-in indexer, and rich indexer.
 * Uses ArduinoJson + WiFiClient (HTTPClient). No external dependencies beyond
 * the Arduino ESP32 core.
 *
 * ── Node type selection ──────────────────────────────────────────────────────
 * Define ONE of the following before including this header (or in platformio.ini):
 *
 *   #define CKB_NODE_FULL        // Full node (ckb) — default
 *                                //   node RPC + built-in indexer (v0.100+)
 *                                //   same URL for node + indexer
 *
 *   #define CKB_NODE_LIGHT       // Light node (ckb-light-client)
 *                                //   subset of RPC — no block/peer queries
 *                                //   has built-in indexer, same port
 *
 *   #define CKB_NODE_INDEXER     // Separate indexer process (legacy)
 *                                //   node URL + separate indexer URL
 *
 *   #define CKB_NODE_RICH        // Rich-indexer (ckb-rich-indexer / Mercury)
 *                                //   extended indexer API (get_balance, records)
 *                                //   indexer URL points to rich indexer port
 *
 * Default if none defined: CKB_NODE_FULL
 *
 * ── Quick start ──────────────────────────────────────────────────────────────
 * Full node (built-in indexer, same port):
 *   CKBClient ckb("http://192.168.1.100:8114");
 *
 * Light client:
 *   #define CKB_NODE_LIGHT
 *   CKBClient ckb("http://192.168.1.100:9000");
 *
 * Separate indexer:
 *   #define CKB_NODE_INDEXER
 *   CKBClient ckb("http://192.168.1.100:8114", "http://192.168.1.100:8116");
 *
 * Rich indexer (Mercury):
 *   #define CKB_NODE_RICH
 *   CKBClient ckb("http://192.168.1.100:8114", "http://192.168.1.100:8116");
 *
 * Author:  toastmanAu  (Phill)
 * Repo:    https://github.com/toastmanAu/CKB-ESP32
 * License: MIT
 */

#include <Arduino.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <WiFiClientSecure.h>
#include "ckb_blake2b.h"
#include "ckb_molecule.h"

// ─── Node type guards ─────────────────────────────────────────────────────────
#if !defined(CKB_NODE_FULL) && !defined(CKB_NODE_LIGHT) && \
    !defined(CKB_NODE_INDEXER) && !defined(CKB_NODE_RICH)
  #define CKB_NODE_FULL   // default
#endif

// Capabilities derived from node type
#if defined(CKB_NODE_FULL)
  #define CKB_HAS_BLOCK_QUERIES    1  // get_block, get_header, etc.
  #define CKB_HAS_PEER_QUERIES     1  // get_peers, local_node_info
  #define CKB_HAS_POOL_QUERIES     1  // tx_pool_info
  #define CKB_HAS_INDEXER          1  // get_cells, get_cells_capacity
  #define CKB_INDEXER_SAME_PORT    1  // indexer on same URL as node
  #define CKB_HAS_SEND_TX          1
  #define CKB_NODE_TYPE_STR        "full"
#elif defined(CKB_NODE_LIGHT)
  #define CKB_HAS_BLOCK_QUERIES    0  // light client has no block queries
  #define CKB_HAS_PEER_QUERIES     0
  #define CKB_HAS_POOL_QUERIES     0
  #define CKB_HAS_INDEXER          1  // light client has built-in indexer
  #define CKB_INDEXER_SAME_PORT    1
  #define CKB_HAS_SEND_TX          1  // send_transaction supported
  #define CKB_NODE_TYPE_STR        "light"
#elif defined(CKB_NODE_INDEXER)
  #define CKB_HAS_BLOCK_QUERIES    1
  #define CKB_HAS_PEER_QUERIES     1
  #define CKB_HAS_POOL_QUERIES     1
  #define CKB_HAS_INDEXER          1
  #define CKB_INDEXER_SAME_PORT    0  // separate indexer URL required
  #define CKB_HAS_SEND_TX          1
  #define CKB_NODE_TYPE_STR        "indexer"
#elif defined(CKB_NODE_RICH)
  #define CKB_HAS_BLOCK_QUERIES    1
  #define CKB_HAS_PEER_QUERIES     1
  #define CKB_HAS_POOL_QUERIES     1
  #define CKB_HAS_INDEXER          1
  #define CKB_HAS_RICH_INDEXER     1  // extended: get_balance, get_transaction_info
  #define CKB_INDEXER_SAME_PORT    0
  #define CKB_HAS_SEND_TX          1
  #define CKB_NODE_TYPE_STR        "rich"
#endif

// ─── Version ──────────────────────────────────────────────────────────────────
#define CKB_ESP32_VERSION      "2.0.0"
#define CKB_ESP32_VERSION_MAJOR 2
#define CKB_ESP32_VERSION_MINOR 0
#define CKB_ESP32_VERSION_PATCH 0

// ─── Defaults ─────────────────────────────────────────────────────────────────
#ifndef CKB_JSON_DOC_SIZE
  #define CKB_JSON_DOC_SIZE    8192
#endif
#ifndef CKB_HTTP_TIMEOUT_MS
  #define CKB_HTTP_TIMEOUT_MS  8000
#endif
#ifndef CKB_MAX_CELLS
  #define CKB_MAX_CELLS        64
#endif
#ifndef CKB_MAX_TXS
  #define CKB_MAX_TXS          32
#endif
#ifndef CKB_MAX_PEERS
  #define CKB_MAX_PEERS        16
#endif
#ifndef CKB_MAX_INPUTS
  #define CKB_MAX_INPUTS       8    // Max inputs in a built transaction
#endif
#ifndef CKB_TX_BUF_SIZE
  #define CKB_TX_BUF_SIZE      2048 // Molecule serialisation buffer (bytes)
#endif
#ifndef CKB_DEFAULT_FEE
  #define CKB_DEFAULT_FEE      1000ULL  // 1000 shannon default fee
#endif
// Minimum cell capacity: 61 CKB for a secp256k1 output (61 bytes * 10^8)
#define CKB_MIN_CELL_CAPACITY  6100000000ULL

// ─── Constants ────────────────────────────────────────────────────────────────
#define CKB_SHANNON_PER_CKB    100000000ULL
#define CKB_MAINNET_PREFIX     "ckb"
#define CKB_TESTNET_PREFIX     "ckt"

// secp256k1 dep group — these never change on mainnet/testnet
#define CKB_SECP256K1_DEP_MAINNET_TX "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"
#define CKB_SECP256K1_DEP_TESTNET_TX "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"
#define CKB_SECP256K1_DEP_INDEX      0
// secp256k1 lock code hash
#define CKB_SECP256K1_CODE_HASH "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"

// ─── Error codes ──────────────────────────────────────────────────────────────
typedef enum {
    CKB_OK              = 0,
    CKB_ERR_HTTP        = -1,
    CKB_ERR_JSON        = -2,
    CKB_ERR_RPC         = -3,
    CKB_ERR_NOT_FOUND   = -4,
    CKB_ERR_TIMEOUT     = -5,
    CKB_ERR_INVALID     = -6,
    CKB_ERR_UNSUPPORTED = -7,   // Operation not supported by this node type
    CKB_ERR_FUNDS       = -8,   // Insufficient funds
    CKB_ERR_OVERFLOW    = -9,   // Buffer overflow (increase CKB_TX_BUF_SIZE)
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

// ─── Light client structures ──────────────────────────────────────────────────

/**
 * Script filter for light client set_scripts / get_scripts.
 * The light client only syncs blocks relevant to registered scripts.
 */
struct CKBScriptStatus {
    CKBScript script;
    char      scriptType[7];    // "lock" or "type"
    uint64_t  blockNumber;      // start syncing from this block (0 = genesis)
};

#define CKB_MAX_LIGHT_SCRIPTS 8

/** Result of get_scripts */
struct CKBScriptStatusResult {
    CKBScriptStatus scripts[CKB_MAX_LIGHT_SCRIPTS];
    uint8_t         count;
    CKBError        error;
};

/**
 * Light client sync state — returned by get_tip_header / local status.
 * Shows which block the light client has synced to.
 */
struct CKBLightSyncState {
    uint64_t tipBlockNumber;   // highest block synced
    char     tipBlockHash[67];
    bool     isSynced;         // true when tip is close to network tip
    CKBError error;
};

// ─── Transaction structures ───────────────────────────────────────────────────

/** A cell dep (dependency) */
struct CKBCellDepEntry {
    char     txHash[67];
    uint32_t index;
    bool     isDepGroup;  // true = dep_group, false = code
};

/** A transaction input (previous output reference) */
struct CKBTxInput {
    char     txHash[67];
    uint32_t index;
    uint64_t since;       // usually 0x0
    uint64_t capacity;    // capacity of the consumed cell (for fee calculation)
    CKBScript lockScript; // lock of consumed cell (for change address)
};

/** A transaction output */
struct CKBTxOutput {
    uint64_t  capacity;          // shannon
    CKBScript lockScript;        // recipient lock
    bool      hasTypeScript;     // true if type field is set (DAO, UDT, etc.)
    CKBScript typeScript;        // only valid if hasTypeScript
    char      data[67];          // "0x" or hex data, usually "0x"
};

/**
 * CKBBuiltTx — a fully populated CKB transaction object.
 *
 * This is the central transaction type. It holds all fields in a structured,
 * readable form. You can inspect, modify, sign, and broadcast it independently.
 *
 * Workflow:
 *   1. CKBBuiltTx tx = ckb.buildTransfer(from, to, amount)
 *      — inputs selected from indexer, outputs calculated, deps set
 *   2. Inspect: tx.signingHash, tx.txHashHex, tx.inputs[], tx.outputs[]
 *   3. Sign:    tx.setSignature(sig65)   — inject secp256k1 signature
 *   4. Broadcast: CKBClient::broadcast(tx, "http://node-ip:8114")
 *      — any node, independent of where tx was built
 *
 * The tx object is fully self-contained. Pass it to any broadcast target.
 */
struct CKBBuiltTx {
    // ── Inputs ────────────────────────────────────────────────────────────────
    CKBTxInput inputs[CKB_MAX_INPUTS];
    uint8_t    inputCount;

    // ── Outputs ───────────────────────────────────────────────────────────────
    CKBTxOutput outputs[CKB_MAX_INPUTS + 1];  // +1 for change
    uint8_t     outputCount;

    // ── Cell deps ─────────────────────────────────────────────────────────────
    CKBCellDepEntry cellDeps[4];
    uint8_t         cellDepCount;

    // ── Signing ───────────────────────────────────────────────────────────────
    // signingHash is what you pass to your signing function (secp256k1, P4, etc.)
    uint8_t signingHash[32];

    // txHash is the Blake2b hash of the serialised RawTransaction
    uint8_t txHash[32];
    char    txHashHex[67];   // "0x" + 64 hex chars + null

    // ── Witness / signature ───────────────────────────────────────────────────
    uint8_t signature[65];   // r[32] + s[32] + v[1], set by setSignature()
    bool    signed_;         // true after setSignature() called

    // ── Internals (kept for broadcast) ────────────────────────────────────────
    uint8_t  _rawBytes[CKB_TX_BUF_SIZE];  // Molecule-serialised RawTransaction
    size_t   _rawLen;

    // ── Status ────────────────────────────────────────────────────────────────
    CKBError error;
    bool     valid;

    /**
     * Inject a secp256k1 signature (65 bytes: r[32]+s[32]+v[1]).
     * Call this before broadcast().
     * For SPHINCS+ or other schemes, use broadcastWithWitness() directly.
     */
    void setSignature(const uint8_t sig[65]) {
        memcpy(signature, sig, 65);
        signed_ = true;
    }

    /** Total input capacity */
    uint64_t totalInputCapacity() const {
        uint64_t t = 0;
        for (uint8_t i = 0; i < inputCount; i++) t += inputs[i].capacity;
        return t;
    }

    /** Total output capacity */
    uint64_t totalOutputCapacity() const {
        uint64_t t = 0;
        for (uint8_t i = 0; i < outputCount; i++) t += outputs[i].capacity;
        return t;
    }

    /** Fee = inputs - outputs */
    uint64_t fee() const {
        uint64_t in  = totalInputCapacity();
        uint64_t out = totalOutputCapacity();
        return (in > out) ? in - out : 0;
    }
};

// ─── CKBClient class ──────────────────────────────────────────────────────────

class CKBClient {
public:
    /**
     * Constructor — adapts to node type at compile time.
     *
     * @param nodeUrl    CKB node RPC (or light client) URL
     * @param indexerUrl Indexer URL — required for CKB_NODE_INDEXER/CKB_NODE_RICH
     *                   Ignored for CKB_NODE_FULL/CKB_NODE_LIGHT (same port)
     * @param testnet    Set true for testnet (affects secp256k1 dep group)
     */
    CKBClient(const char* nodeUrl, const char* indexerUrl = nullptr, bool testnet = false);

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

    /** Which node type is compiled in? */
    static const char* nodeTypeStr() { return CKB_NODE_TYPE_STR; }

#if defined(CKB_NODE_LIGHT)
    // ══════════════════════════════════════════════════════════════════════════
    //  LIGHT CLIENT API
    //  Only available when compiled with #define CKB_NODE_LIGHT
    //
    //  The CKB light client syncs only blocks relevant to registered scripts.
    //  Workflow:
    //    1. setScripts({your lock script}) — register addresses to watch
    //    2. Wait for sync (poll getTipHeader until tipBlockNumber advances)
    //    3. Use standard indexer methods: getBalance(), getCells(), getTransactions()
    //    4. Use fetchTransaction() instead of getTransaction() for light client
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Register scripts for the light client to sync.
     * The client will download and index all blocks containing these scripts.
     *
     * @param scripts    Array of script+type+startBlock entries
     * @param count      Number of entries
     * @param command    "all" (replace all), "partial" (merge with existing)
     * @returns CKB_OK on success
     */
    CKBError setScripts(const CKBScriptStatus* scripts, uint8_t count,
                         const char* command = "all");

    /** Convenience: register a single lock script from a CKB address */
    CKBError watchAddress(const char* ckbAddress, uint64_t fromBlock = 0);

    /**
     * Get the list of scripts currently registered with the light client.
     * Useful to verify setScripts() took effect.
     */
    CKBScriptStatusResult getScripts();

    /**
     * Fetch the current tip block header from the light client.
     * Lighter than getNodeInfo() — just the header.
     * Use this to check sync progress.
     */
    CKBBlockHeader getTipHeader();

    /**
     * Fetch a specific block header by hash.
     * Light client fetches it on demand if not already synced.
     */
    CKBBlockHeader fetchHeader(const char* blockHash);

    /**
     * Fetch a transaction from the light client.
     * Returns the tx + its confirmation status (block hash/number).
     * Use this instead of getTransaction() on light client builds.
     *
     * @param txHash    0x + 64 hex chars
     */
    CKBTransaction fetchTransaction(const char* txHash);

    /**
     * Get light client sync state — how far synced vs network tip.
     * Polls get_tip_header and local_node_info to determine lag.
     */
    CKBLightSyncState getSyncState();

    /**
     * Block until the light client has synced to at least targetBlock.
     * Polls every pollMs milliseconds, times out after timeoutMs.
     * Returns true when synced, false on timeout.
     */
    bool waitForSync(uint64_t targetBlock, uint32_t timeoutMs = 60000,
                     uint32_t pollMs = 2000);

#endif // CKB_NODE_LIGHT

    // ══════════════════════════════════════════════════════════════════════════
    //  TRANSACTION BUILDER
    //  Requires: CKB_HAS_INDEXER (all node types except raw node-only builds)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Build an unsigned CKB transfer transaction.
     *
     * Automatically:
     *   - Queries indexer for live cells belonging to fromAddr
     *   - Selects enough inputs to cover amount + fee
     *   - Calculates change output
     *   - Adds secp256k1 dep group cell dep
     *   - Serialises to Molecule format
     *   - Computes signing hash (Blake2b of tx + witness placeholder)
     *
     * Minimal required inputs — everything else is derived from the node.
     *
     * @param fromAddr     Sender CKB address (ckb1qyq... or ckt1qyq...)
     * @param toAddr       Recipient CKB address
     * @param amountShannon Amount to send in shannon (1 CKB = 10^8 shannon)
     * @param feeShannon   Fee in shannon (default CKB_DEFAULT_FEE = 1000)
     * @return CKBBuiltTx — check .valid and .error fields
     *
     * After receiving the result:
     *   1. Sign result.signingHash[32] with your key
     *   2. result.setSignature(sig65)
     *   3. CKBClient::broadcast(result, "http://node-ip:8114")
     */
    CKBBuiltTx buildTransfer(const char* fromAddr,
                              const char* toAddr,
                              uint64_t    amountShannon,
                              uint64_t    feeShannon = CKB_DEFAULT_FEE);

    /**
     * Broadcast a signed transaction to any CKB node.
     *
     * This is a static function — it does NOT require a CKBClient instance
     * configured for any particular node. Pass any reachable node URL.
     * The tx must have had setSignature() called first.
     *
     * @param tx          A signed CKBBuiltTx (call tx.setSignature() first)
     * @param nodeUrl     CKB node RPC URL, e.g. "http://192.168.1.100:8114"
     * @param txHashOut   Output buffer for the submitted tx hash (67 chars), or nullptr
     * @param timeoutMs   HTTP timeout in ms (default: CKB_HTTP_TIMEOUT_MS)
     * @return CKB_OK on success, error code otherwise
     *
     * Example:
     *   CKBBuiltTx tx = ckb.buildTransfer(from, to, amount);
     *   tx.setSignature(mySig);
     *   char hash[67];
     *   CKBError err = CKBClient::broadcast(tx, "http://192.168.68.87:8114", hash);
     */
    static CKBError broadcast(const CKBBuiltTx& tx,
                               const char* nodeUrl,
                               char* txHashOut = nullptr,
                               uint32_t timeoutMs = CKB_HTTP_TIMEOUT_MS);

    /**
     * Broadcast with a custom raw witness (for non-secp256k1 signing schemes).
     * witnessHex should be the full hex-encoded WitnessArgs molecule (e.g. SPHINCS+).
     */
    static CKBError broadcastWithWitness(const CKBBuiltTx& tx,
                                          const char* nodeUrl,
                                          const char* witnessHex,
                                          char* txHashOut = nullptr,
                                          uint32_t timeoutMs = CKB_HTTP_TIMEOUT_MS);

    /**
     * Collect live input cells for an address sufficient to cover targetShannon.
     * Used internally by buildTransfer(), exposed for custom tx building.
     *
     * @param lockScript     Lock script of the sender
     * @param targetShannon  Amount needed (amount + fee)
     * @param outInputs      Output array of CKBTxInput (CKB_MAX_INPUTS capacity)
     * @param outCount       Number of cells selected
     * @param outTotal       Total capacity of selected cells
     * @return CKB_OK, CKB_ERR_FUNDS, or error code
     */
    CKBError collectInputCells(const CKBScript& lockScript,
                                uint64_t targetShannon,
                                CKBTxInput outInputs[],
                                uint8_t& outCount,
                                uint64_t& outTotal);

private:
    char _nodeUrl[128];
    char _indexerUrl[128];
    bool _hasIndexer;
    bool _testnet;
    uint32_t _timeoutMs;
    bool _debug;
    CKBError _lastError;
    int _rpcId;

    // Tx builder helpers
    bool _buildRawTxMolecule(CKBBuiltTx& tx);
    void _computeSigningHash(CKBBuiltTx& tx);
    static void _bytesToHex(const uint8_t* bytes, size_t len, char* out);
    static bool _buildWitnessHex(const uint8_t sig65[65], char* out, size_t outCap);
    static bool _rpcCallStatic(const char* url, const char* method,
                                const char* params, JsonDocument& doc,
                                uint32_t timeoutMs);

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
