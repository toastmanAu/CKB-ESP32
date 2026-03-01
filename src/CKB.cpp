/*
 * CKB-ESP32 — CKBClient implementation
 * See CKB.h for full API documentation.
 */

#include "CKB.h"

/* ── Platform compat ─────────────────────────────────────────────────────── */
#ifndef ARDUINO
#include <stdio.h>
#include <stdlib.h>
#ifndef strlcpy
static inline size_t strlcpy(char* dst, const char* src, size_t size) {
    size_t i = 0;
    if (size > 0) {
        for (; i < size - 1 && src[i]; i++) dst[i] = src[i];
        dst[i] = '\0';
    }
    while (src[i]) i++;
    return i;
}
#endif
#ifndef strlcat
static inline size_t strlcat(char* dst, const char* src, size_t size) {
    size_t dlen = 0;
    while (dlen < size && dst[dlen]) dlen++;
    return dlen + strlcpy(dst + dlen, src, size > dlen ? size - dlen : 0);
}
#endif
#endif // !ARDUINO

// ─── Constructor ──────────────────────────────────────────────────────────────

CKBClient::CKBClient(const char* nodeUrl, const char* indexerUrl, bool testnet) {
    strncpy(_nodeUrl, nodeUrl, sizeof(_nodeUrl) - 1);
    _nodeUrl[sizeof(_nodeUrl) - 1] = '\0';
    _testnet = testnet;

#if CKB_INDEXER_SAME_PORT
    // Full node / light client: indexer on same port
    strncpy(_indexerUrl, nodeUrl, sizeof(_indexerUrl) - 1);
    _indexerUrl[sizeof(_indexerUrl) - 1] = '\0';
    (void)indexerUrl; // ignore
#else
    // Separate indexer or rich indexer
    if (indexerUrl && strlen(indexerUrl) > 0) {
        strncpy(_indexerUrl, indexerUrl, sizeof(_indexerUrl) - 1);
        _indexerUrl[sizeof(_indexerUrl) - 1] = '\0';
    } else {
        // Fallback: try port 8116
        strncpy(_indexerUrl, nodeUrl, sizeof(_indexerUrl) - 1);
        char* port = strstr(_indexerUrl, ":8114");
        if (port) memcpy(port, ":8116", 5);
    }
#endif

    _hasIndexer   = true;
    _timeoutMs    = CKB_HTTP_TIMEOUT_MS;
    _debug        = false;
    _lastError    = CKB_OK;
    _rpcId        = 1;
    _transport    = _defaultTransport();
}

const char* CKBClient::lastErrorStr() const {
    switch (_lastError) {
        case CKB_OK:              return "OK";
        case CKB_ERR_HTTP:        return "HTTP error";
        case CKB_ERR_JSON:        return "JSON parse error";
        case CKB_ERR_RPC:         return "RPC error";
        case CKB_ERR_NOT_FOUND:   return "Not found";
        case CKB_ERR_TIMEOUT:     return "Timeout";
        case CKB_ERR_INVALID:     return "Invalid argument";
        case CKB_ERR_UNSUPPORTED: return "Not supported by this node type";
        case CKB_ERR_FUNDS:       return "Insufficient funds";
        case CKB_ERR_OVERFLOW:    return "Buffer overflow — increase CKB_TX_BUF_SIZE";
        default:                  return "Unknown error";
    }
}

void CKBClient::_debugPrint(const char* msg) {
#ifdef ARDUINO
    if (_debug) Serial.println(msg);
#else
    if (_debug) printf("[CKB] %s\n", msg);
#endif
}

// ─── Internal RPC call ────────────────────────────────────────────────────────

bool CKBClient::_rpcCall(const char* url, const char* method,
                          const char* params, JsonDocument& doc) {
    char body[640];
    snprintf(body, sizeof(body),
        "{\"id\":%d,\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}",
        _rpcId++, method, params ? params : "[]");
    _debugPrint(body);

    /* Delegate HTTP to the platform transport */
    static char _respBuf[CKB_JSON_DOC_SIZE];
    int n = _transport->rpc(url, body, _respBuf, sizeof(_respBuf), _timeoutMs);
    if (n == CKB_TRANSPORT_TIMEOUT)   { _lastError = CKB_ERR_TIMEOUT; return false; }
    if (n == CKB_TRANSPORT_BUF_SMALL) { _lastError = CKB_ERR_JSON;    return false; }
    if (n < 0)                         { _lastError = CKB_ERR_HTTP;    return false; }

    DeserializationError err = deserializeJson(doc, _respBuf);
    if (err) { _lastError = CKB_ERR_JSON; return false; }
    if (doc.containsKey("error")) { _lastError = CKB_ERR_RPC; return false; }
    if (doc["result"].isNull()) { _lastError = CKB_ERR_NOT_FOUND; return false; }

    _lastError = CKB_OK;
    return true;
}

// ─── Parsers// ─── Parsers ──────────────────────────────────────────────────────────────────

void CKBClient::_parseScript(JsonObject obj, CKBScript& out) {
    out.valid = false;
    if (obj.isNull()) return;
    strlcpy(out.codeHash, obj["code_hash"] | "", sizeof(out.codeHash));
    strlcpy(out.hashType, obj["hash_type"] | "type", sizeof(out.hashType));
    strlcpy(out.args,     obj["args"]      | "0x",   sizeof(out.args));
    out.valid = strlen(out.codeHash) > 2;
}

void CKBClient::_parseOutPoint(JsonObject obj, CKBOutPoint& out) {
    strlcpy(out.txHash, obj["tx_hash"] | "0x", sizeof(out.txHash));
    out.index = (uint32_t)hexToUint64(obj["index"] | "0x0");
}

void CKBClient::_parseCellOutput(JsonObject obj, CKBCellOutput& out) {
    out.capacity = hexToUint64(obj["capacity"] | "0x0");
    _parseScript(obj["lock"].as<JsonObject>(), out.lock);
    if (!obj["type"].isNull()) {
        _parseScript(obj["type"].as<JsonObject>(), out.type);
        out.hasType = out.type.valid;
    } else {
        out.hasType = false; out.type.valid = false;
    }
}

void CKBClient::_parseBlockHeader(JsonObject obj, CKBBlockHeader& out) {
    out.valid = false;
    if (obj.isNull()) return;
    strlcpy(out.hash,             obj["hash"]              | "", sizeof(out.hash));
    strlcpy(out.parentHash,       obj["parent_hash"]       | "", sizeof(out.parentHash));
    strlcpy(out.transactionsRoot, obj["transactions_root"] | "", sizeof(out.transactionsRoot));
    strlcpy(out.dao,              obj["dao"]               | "", sizeof(out.dao));
    out.number        = hexToUint64(obj["number"]         | "0x0");
    out.timestamp     = hexToUint64(obj["timestamp"]      | "0x0");
    out.version       = (uint32_t)hexToUint64(obj["version"] | "0x0");
    out.compactTarget = hexToUint64(obj["compact_target"] | "0x0");
    out.valid = strlen(out.hash) > 2;
}

CKBBlock CKBClient::_parseBlock(JsonObject obj) {
    CKBBlock out; out.valid = false;
    if (obj.isNull()) return out;
    _parseBlockHeader(obj["header"].as<JsonObject>(), out.header);
    out.txCount = obj["transactions"].as<JsonArray>().size();
    // Extract miner args from cellbase first output
    JsonObject cellbase = obj["transactions"][0].as<JsonObject>();
    if (!cellbase.isNull()) {
        JsonObject firstOut = cellbase["outputs"][0].as<JsonObject>();
        if (!firstOut.isNull())
            strlcpy(out.minerLockArgs,
                firstOut["lock"]["args"] | "", sizeof(out.minerLockArgs));
    }
    out.valid = out.header.valid;
    return out;
}

CKBTransaction CKBClient::_parseTransaction(JsonObject obj) {
    CKBTransaction out; out.valid = false;
    if (obj.isNull()) return out;

    JsonObject tx = obj["transaction"].isNull()
        ? obj : obj["transaction"].as<JsonObject>();

    const char* h = obj["transaction"]["hash"] | obj["hash"] | "";
    strlcpy(out.hash, h, sizeof(out.hash));
    out.version = (uint32_t)hexToUint64(tx["version"] | "0x0");

    JsonArray inputs = tx["inputs"].as<JsonArray>();
    out.inputCount = 0;
    for (JsonObject inp : inputs) {
        if (out.inputCount >= 8) break;
        _parseOutPoint(inp["previous_output"].as<JsonObject>(),
                       out.inputs[out.inputCount].previousOutput);
        strlcpy(out.inputs[out.inputCount].since,
                inp["since"] | "0x0", sizeof(out.inputs[0].since));
        out.inputCount++;
    }

    JsonArray outputs = tx["outputs"].as<JsonArray>();
    out.outputCount = 0;
    for (JsonObject outp : outputs) {
        if (out.outputCount >= 8) break;
        _parseCellOutput(outp, out.outputs[out.outputCount]);
        out.outputCount++;
    }

    JsonObject txStatus = obj["tx_status"].as<JsonObject>();
    if (!txStatus.isNull()) {
        const char* status = txStatus["status"] | "";
        if      (strcmp(status, "committed") == 0) out.status = 2;
        else if (strcmp(status, "proposed")  == 0) out.status = 1;
        else out.status = 0;
        strlcpy(out.blockHash, txStatus["block_hash"] | "", sizeof(out.blockHash));
    }
    out.valid = strlen(out.hash) > 2;
    return out;
}

// ─── NODE RPC — Chain ─────────────────────────────────────────────────────────
#if CKB_HAS_BLOCK_QUERIES

uint64_t CKBClient::getTipBlockNumber() {
    StaticJsonDocument<256> doc;
    if (!_rpcCall(_nodeUrl, "get_tip_block_number", "[]", doc)) return UINT64_MAX;
    return hexToUint64(doc["result"] | "0x0");
}

CKBBlockHeader CKBClient::getHeaderByNumber(uint64_t number) {
    CKBBlockHeader out; out.valid = false;
    char params[40]; snprintf(params, sizeof(params), "[\"0x%llx\",null]", (unsigned long long)number);
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_header_by_number", params, doc)) return out;
    _parseBlockHeader(doc["result"].as<JsonObject>(), out);
    return out;
}

CKBBlockHeader CKBClient::getHeaderByHash(const char* blockHash) {
    CKBBlockHeader out; out.valid = false;
    char params[80]; snprintf(params, sizeof(params), "[\"%s\",null]", blockHash);
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_header", params, doc)) return out;
    _parseBlockHeader(doc["result"].as<JsonObject>(), out);
    return out;
}

CKBBlock CKBClient::getBlockByNumber(uint64_t number, bool verbose) {
    CKBBlock out; out.valid = false;
    char params[64];
    snprintf(params, sizeof(params), "[\"0x%llx\",\"%s\",null]",
        (unsigned long long)number, verbose ? "0x2" : "0x1");
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_block_by_number", params, doc)) return out;
    return _parseBlock(doc["result"].as<JsonObject>());
}

CKBBlock CKBClient::getBlockByHash(const char* blockHash, bool verbose) {
    CKBBlock out; out.valid = false;
    char params[96];
    snprintf(params, sizeof(params), "[\"%s\",\"%s\",null]",
        blockHash, verbose ? "0x2" : "0x1");
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_block", params, doc)) return out;
    return _parseBlock(doc["result"].as<JsonObject>());
}

CKBEpoch CKBClient::getCurrentEpoch() {
    CKBEpoch out; out.valid = false;
    StaticJsonDocument<512> doc;
    if (!_rpcCall(_nodeUrl, "get_current_epoch", "[]", doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    out.number        = hexToUint64(r["number"]         | "0x0");
    out.startNumber   = hexToUint64(r["start_number"]   | "0x0");
    out.length        = hexToUint64(r["length"]          | "0x0");
    out.compactTarget = hexToUint64(r["compact_target"]  | "0x0");
    out.valid = true; return out;
}

CKBEpoch CKBClient::getEpochByNumber(uint64_t epochNumber) {
    CKBEpoch out; out.valid = false;
    char params[32]; snprintf(params, sizeof(params), "[\"0x%llx\"]", (unsigned long long)epochNumber);
    StaticJsonDocument<512> doc;
    if (!_rpcCall(_nodeUrl, "get_epoch_by_number", params, doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    out.number        = hexToUint64(r["number"]         | "0x0");
    out.startNumber   = hexToUint64(r["start_number"]   | "0x0");
    out.length        = hexToUint64(r["length"]          | "0x0");
    out.compactTarget = hexToUint64(r["compact_target"]  | "0x0");
    out.valid = true; return out;
}

// ─── NODE RPC — Tx & Cells ────────────────────────────────────────────────────

CKBTransaction CKBClient::getTransaction(const char* txHash) {
    CKBTransaction out; out.valid = false;
    char params[80]; snprintf(params, sizeof(params), "[\"%s\",null,null]", txHash);
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_transaction", params, doc)) return out;
    return _parseTransaction(doc["result"].as<JsonObject>());
}

CKBLiveCell CKBClient::getLiveCell(const char* txHash, uint32_t index, bool withData) {
    CKBLiveCell out; out.valid = false;
    char params[128];
    snprintf(params, sizeof(params),
        "[{\"tx_hash\":\"%s\",\"index\":\"0x%x\"},%s]",
        txHash, index, withData ? "true" : "false");
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_live_cell", params, doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    if (strcmp(r["status"] | "", "live") != 0) { _lastError = CKB_ERR_NOT_FOUND; return out; }
    JsonObject cell = r["cell"].as<JsonObject>();
    _parseCellOutput(cell["output"].as<JsonObject>(), out.output);
    strlcpy(out.outputData, cell["data"]["content"] | "0x", sizeof(out.outputData));
    strlcpy(out.outPoint.txHash, txHash, sizeof(out.outPoint.txHash));
    out.outPoint.index = index;
    out.valid = true;
    return out;
}

#endif // CKB_HAS_BLOCK_QUERIES

// ─── NODE RPC — Network ───────────────────────────────────────────────────────
#if CKB_HAS_PEER_QUERIES

CKBNodeInfo CKBClient::getNodeInfo() {
    CKBNodeInfo out; out.valid = false;
    StaticJsonDocument<1024> doc;
    if (!_rpcCall(_nodeUrl, "local_node_info", "[]", doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    strlcpy(out.nodeId,    r["node_id"]  | "", sizeof(out.nodeId));
    strlcpy(out.version,   r["version"]  | "", sizeof(out.version));
    strlcpy(out.networkId, r["active"]   | "", sizeof(out.networkId));
    out.tipBlockNumber = getTipBlockNumber();
    out.peersCount = r["connections"] | 0;
    out.valid = strlen(out.nodeId) > 0;
    return out;
}

#endif // CKB_HAS_PEER_QUERIES

// ─── NODE RPC — Tx Pool ───────────────────────────────────────────────────────
#if CKB_HAS_POOL_QUERIES

CKBTxPoolInfo CKBClient::getTxPoolInfo() {
    CKBTxPoolInfo out; out.valid = false;
    StaticJsonDocument<512> doc;
    if (!_rpcCall(_nodeUrl, "tx_pool_info", "[]", doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    out.pending     = hexToUint64(r["pending"]      | "0x0");
    out.proposed    = hexToUint64(r["proposed"]     | "0x0");
    out.totalTxSize = hexToUint64(r["total_tx_size"]| "0x0");
    out.minFeeRate  = hexToUint64(r["min_fee_rate"] | "0x0");
    out.valid = true; return out;
}

CKBChainInfo CKBClient::getBlockchainInfo() {
    CKBChainInfo out; out.valid = false;
    StaticJsonDocument<512> doc;
    if (!_rpcCall(_nodeUrl, "get_blockchain_info", "[]", doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    strlcpy(out.networkId, r["chain"] | "", sizeof(out.networkId));
    out.isMainnet = strcmp(out.networkId, "ckb") == 0;
    out.epoch     = hexToUint64(r["epoch"] | "0x0");
    strlcpy(out.medianTime, r["median_time"] | "0x0", sizeof(out.medianTime));
    out.valid = true; return out;
}

uint8_t CKBClient::getPeers(CKBPeer peers[], uint8_t maxPeers) {
    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_nodeUrl, "get_peers", "[]", doc)) return 0;
    JsonArray arr = doc["result"].as<JsonArray>();
    if (!peers) return arr.size();
    uint8_t count = 0;
    for (JsonObject p : arr) {
        if (count >= maxPeers || count >= CKB_MAX_PEERS) break;
        strlcpy(peers[count].nodeId, p["node_id"] | "", sizeof(peers[0].nodeId));
        JsonArray addrs = p["addresses"].as<JsonArray>();
        if (addrs.size() > 0)
            strlcpy(peers[count].address, addrs[0]["address"] | "", sizeof(peers[0].address));
        peers[count].direction = (p["is_outbound"] | false) ? 1 : 0;
        count++;
    }
    return count;
}

#endif // CKB_HAS_POOL_QUERIES + CKB_HAS_PEER_QUERIES (getPeers ends here)

// ─── INDEXER RPC ──────────────────────────────────────────────────────────────
#if CKB_HAS_INDEXER

CKBIndexerTip CKBClient::getIndexerTip() {
    CKBIndexerTip out; out.valid = false;
    StaticJsonDocument<256> doc;
    if (!_rpcCall(_indexerUrl, "get_indexer_tip", "[]", doc)) return out;
    JsonObject r = doc["result"].as<JsonObject>();
    out.blockNumber = hexToUint64(r["block_number"] | "0x0");
    strlcpy(out.blockHash, r["block_hash"] | "", sizeof(out.blockHash));
    out.valid = true; return out;
}

CKBCellsResult CKBClient::getCells(const CKBScript& lockScript,
                                    const char* scriptType, uint8_t limit,
                                    const char* cursor,
                                    uint64_t filterBlockMin, uint64_t filterBlockMax) {
    CKBCellsResult out; out.count = 0; out.hasMore = false; out.error = CKB_OK;

    char filterStr[128] = "null";
    if (filterBlockMin > 0 || filterBlockMax > 0)
        snprintf(filterStr, sizeof(filterStr),
            "{\"block_range\":[\"0x%llx\",\"0x%llx\"]}",
            (unsigned long long)filterBlockMin, (unsigned long long)filterBlockMax);

    char cursorStr[72] = "null";
    if (cursor && strlen(cursor) > 2)
        snprintf(cursorStr, sizeof(cursorStr), "\"%s\"", cursor);

    char params[512];
    snprintf(params, sizeof(params),
        "[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"script_type\":\"%s\",\"filter\":%s},\"asc\",\"0x%x\",%s]",
        lockScript.codeHash, lockScript.hashType, lockScript.args,
        scriptType, filterStr, (unsigned)limit, cursorStr);

    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_indexerUrl, "get_cells", params, doc)) { out.error = _lastError; return out; }

    JsonObject r = doc["result"].as<JsonObject>();
    for (JsonObject cell : r["objects"].as<JsonArray>()) {
        if (out.count >= CKB_MAX_CELLS) break;
        CKBIndexerCell& c = out.cells[out.count];
        _parseOutPoint(cell["out_point"].as<JsonObject>(), c.outPoint);
        _parseCellOutput(cell["output"].as<JsonObject>(), c.output);
        strlcpy(c.outputData, cell["output_data"] | "0x", sizeof(c.outputData));
        c.blockNumber = hexToUint64(cell["block_number"] | "0x0");
        strlcpy(c.txIndex, cell["tx_index"] | "0x0", sizeof(c.txIndex));
        out.count++;
    }
    const char* lc = r["last_cursor"] | "";
    strlcpy(out.lastCursor, lc, sizeof(out.lastCursor));
    out.hasMore = strlen(lc) > 2;
    return out;
}

CKBTxsResult CKBClient::getTransactions(const CKBScript& lockScript,
                                          const char* scriptType, const char* ioType,
                                          uint8_t limit, const char* cursor) {
    CKBTxsResult out; out.count = 0; out.hasMore = false; out.error = CKB_OK;

    char cursorStr[72] = "null";
    if (cursor && strlen(cursor) > 2)
        snprintf(cursorStr, sizeof(cursorStr), "\"%s\"", cursor);

    char params[512];
    snprintf(params, sizeof(params),
        "[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"script_type\":\"%s\",\"filter\":null,\"group_by_transaction\":false},"
        "\"desc\",\"0x%x\",%s]",
        lockScript.codeHash, lockScript.hashType, lockScript.args,
        scriptType, (unsigned)limit, cursorStr);

    StaticJsonDocument<CKB_JSON_DOC_SIZE> doc;
    if (!_rpcCall(_indexerUrl, "get_transactions", params, doc)) { out.error = _lastError; return out; }

    JsonObject r = doc["result"].as<JsonObject>();
    for (JsonObject tx : r["objects"].as<JsonArray>()) {
        if (out.count >= CKB_MAX_TXS) break;
        CKBIndexerTx& t = out.txs[out.count];
        strlcpy(t.txHash, tx["tx_hash"] | "", sizeof(t.txHash));
        t.blockNumber = hexToUint64(tx["block_number"] | "0x0");
        strlcpy(t.txIndex, tx["tx_index"] | "0x0", sizeof(t.txIndex));
        t.ioType  = strcmp(tx["io_type"] | "output", "input") == 0 ? 0 : 1;
        t.ioIndex = (uint32_t)hexToUint64(tx["io_index"] | "0x0");
        out.count++;
    }
    const char* lc = r["last_cursor"] | "";
    strlcpy(out.lastCursor, lc, sizeof(out.lastCursor));
    out.hasMore = strlen(lc) > 2;
    return out;
}

CKBBalance CKBClient::getCellsCapacity(const CKBScript& lockScript, const char* scriptType) {
    CKBBalance out; out.shannon = 0; out.ckb = 0; out.cellCount = 0;

    char params[512];
    snprintf(params, sizeof(params),
        "[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"script_type\":\"%s\",\"filter\":null}]",
        lockScript.codeHash, lockScript.hashType, lockScript.args, scriptType);

    StaticJsonDocument<256> doc;
    if (!_rpcCall(_indexerUrl, "get_cells_capacity", params, doc)) { out.error = _lastError; return out; }
    JsonObject r = doc["result"].as<JsonObject>();
    out.shannon   = hexToUint64(r["capacity"]    | "0x0");
    out.cellCount = (uint32_t)hexToUint64(r["cells_count"] | "0x0");
    out.ckb       = shannonToCKB(out.shannon);
    out.error     = CKB_OK;
    return out;
}

// ─── High-level helpers ───────────────────────────────────────────────────────

CKBBalance CKBClient::getBalance(const char* ckbAddress) {
    CKBBalance out; out.shannon = 0; out.ckb = 0; out.cellCount = 0;
    CKBScript lock = decodeAddress(ckbAddress);
    if (!lock.valid) { out.error = CKB_ERR_INVALID; return out; }
    return getCellsCapacity(lock, "lock");
}

bool CKBClient::hasNewActivity(const CKBScript& lockScript, uint64_t& lastKnownBlock) {
    CKBIndexerTip tip = getIndexerTip();
    if (!tip.valid) return false;
    if (tip.blockNumber <= lastKnownBlock) return false;
    CKBTxsResult txs = getTransactions(lockScript, "lock", "both", 1);
    bool hasNew = txs.count > 0 && txs.txs[0].blockNumber > lastKnownBlock;
    lastKnownBlock = tip.blockNumber;
    return hasNew;
}

CKBTxsResult CKBClient::getRecentTransactions(const char* ckbAddress, uint8_t count) {
    CKBTxsResult out; out.error = CKB_ERR_INVALID;
    CKBScript lock = decodeAddress(ckbAddress);
    if (!lock.valid) return out;
    return getTransactions(lock, "lock", "both", count);
}

#endif // CKB_HAS_INDEXER

// ─── Address decoder (always compiled) ───────────────────────────────────────

static const char SECP256K1_CODE_HASH[] =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint8_t CKBClient::_bech32CharToVal(char c) {
    for (uint8_t i = 0; i < 32; i++)
        if (BECH32_CHARSET[i] == c) return i;
    return 255;
}

bool CKBClient::_bech32Decode(const char* addr, uint8_t* data, size_t& len, char* hrp) {
    // HRP separator is the FIRST '1' — not last (data portion may contain '1')
    // CKB HRP is always "ckb" or "ckt" (3 chars) so separator is at index 3
    const char* sep = strchr(addr, '1');
    if (!sep || sep == addr) return false;
    size_t hrpLen = sep - addr;
    strncpy(hrp, addr, hrpLen); hrp[hrpLen] = '\0';
    const char* dataStr = sep + 1;
    size_t dataStrLen = strlen(dataStr);
    if (dataStrLen < 6) return false;
    size_t numGroups = dataStrLen - 6;
    uint8_t groups[128];
    for (size_t i = 0; i < numGroups; i++) {
        uint8_t v = _bech32CharToVal(dataStr[i]);
        if (v == 255) return false;
        groups[i] = v;
    }
    len = 0;
    uint32_t acc = 0; uint8_t bits = 0;
    for (size_t i = 0; i < numGroups; i++) {
        acc = (acc << 5) | groups[i]; bits += 5;
        if (bits >= 8) { bits -= 8; data[len++] = (acc >> bits) & 0xFF; }
    }
    return true;
}

// Known code-hash table for deprecated short-address index lookup (RFC 0021)
// index → { code_hash_hex, hash_type_byte }
struct _CKBShortAddrEntry {
    uint8_t     codeHash[32];
    const char* hashType;   // "type" or "data"
};
static const _CKBShortAddrEntry _CKB_SHORT_ADDR_TABLE[] = {
    // 0x00 — secp256k1-blake160-sighash-all (type)
    {{ 0x9b,0xd7,0xe0,0x6f, 0x3e,0xcf,0x4b,0xe0, 0xf2,0xfc,0xd2,0x18,
       0x8b,0x23,0xf1,0xb9, 0xfc,0xc8,0x8e,0x5d, 0x4b,0x65,0xa8,0x63,
       0x7b,0x17,0x72,0x3b, 0xbd,0xa3,0xcc,0xe8 }, "type" },
    // 0x01 — secp256k1-blake160-multisig-all (type)
    {{ 0x5c,0x50,0x69,0xeb, 0x08,0x57,0xef,0xc6, 0x55,0xbe,0x74,0x9c,
       0x6c,0x74,0xb2,0x33, 0x22,0xd1,0xc6,0x77, 0xa2,0x13,0x58,0x93,
       0x64,0x62,0x30,0xac, 0x7f,0xd2,0xc2,0xb7 }, "type" },
    // 0x02 — anyone-can-pay (type)
    {{ 0xd3,0x69,0x59,0x7f, 0xf4,0x7f,0x29,0xfb, 0xb0,0xd1,0xf6,0x5a,
       0x1f,0x54,0x82,0xa8, 0xb0,0x26,0x53,0x16, 0x8e,0x8e,0x83,0xed,
       0x7f,0x0b,0x6c,0x1e, 0x7e,0x83,0xc5,0x0c }, "type" },
};
static const size_t _CKB_SHORT_ADDR_TABLE_LEN =
    sizeof(_CKB_SHORT_ADDR_TABLE) / sizeof(_CKB_SHORT_ADDR_TABLE[0]);

// Known code hashes (mainnet) for lock classification
// Each entry: { code_hash_hex_no_prefix, lock_class }
struct _CKBKnownLock {
    const char* codeHashHex;   // 64 hex chars, no 0x
    CKBLockClass lockClass;
};
static const _CKBKnownLock _CKB_KNOWN_LOCKS[] = {
    // secp256k1-blake160-sighash-all (mainnet + testnet — same hash)
    { "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", CKB_LOCK_SECP256K1 },
    // secp256k1-blake160-multisig-all
    { "5c5069eb0857efc65be6a4f5f9e01b0857effc645bbe749c6c7482233d76c7b7", CKB_LOCK_MULTISIG  },
    // anyone-can-pay (mainnet)
    { "d369597ff47f29fbb0d1f65a1f5482a8b02653168e8e83ed7f0b6c1e7e83c50c", CKB_LOCK_ACP       },
    // anyone-can-pay (testnet)
    { "3419a1c09eb2567f6552ee7a8ecffd64155cffe0f1796e6e61ec088d740dcff1", CKB_LOCK_ACP       },
    // new secp256k1 type-id deployment (CKB2021 short index 0x00 = this hash)
    { "04debf03bbd3dd9c1b29b3c20c2e09a36a7c55ec0c4bcb8c26d73bdf04b2e527", CKB_LOCK_SECP256K1 },
};
static const size_t _CKB_KNOWN_LOCKS_LEN =
    sizeof(_CKB_KNOWN_LOCKS) / sizeof(_CKB_KNOWN_LOCKS[0]);

CKBLockClass CKBScript::lockClass() const {
    if (!valid || codeHash[0] == '\0') return CKB_LOCK_UNKNOWN;
    // Skip 0x prefix
    const char* ch = codeHash;
    if (ch[0]=='0' && (ch[1]=='x'||ch[1]=='X')) ch += 2;
    if (strlen(ch) != 64) return CKB_LOCK_UNKNOWN;
    // Case-insensitive hex compare
    for (size_t i = 0; i < _CKB_KNOWN_LOCKS_LEN; i++) {
        bool match = true;
        for (int j = 0; j < 64; j++) {
            char a = ch[j]; if (a>='A'&&a<='F') a = a-'A'+'a';
            char b = _CKB_KNOWN_LOCKS[i].codeHashHex[j]; if (b>='A'&&b<='F') b = b-'A'+'a';
            if (a != b) { match = false; break; }
        }
        if (match) return _CKB_KNOWN_LOCKS[i].lockClass;
    }
    return CKB_LOCK_UNKNOWN;
}

CKBScript CKBClient::decodeAddress(const char* address) {
    CKBScript out; out.valid = false;
    if (!address || strlen(address) < 33) return out;  /* short addr minimum ~33 */

    uint8_t data[120]; size_t len = 0; char hrp[8];
    if (!_bech32Decode(address, data, len, hrp)) return out;
    if (len < 1) return out;

    uint8_t fmt = data[0];

    if (fmt == 0x01 && len >= 2) {
        // ── Deprecated short address ──────────────────────────────────────────
        // payload: 0x01 | code_hash_index(1) | args(variable, usually 20)
        uint8_t idx = data[1];
        if (idx >= _CKB_SHORT_ADDR_TABLE_LEN) return out;  // unknown index
        const _CKBShortAddrEntry& e = _CKB_SHORT_ADDR_TABLE[idx];
        // code_hash
        strcpy(out.codeHash, "0x");
        for (int i = 0; i < 32; i++)
            snprintf(out.codeHash + 2 + i*2, 3, "%02x", e.codeHash[i]);
        strlcpy(out.hashType, e.hashType, sizeof(out.hashType));
        // args (remaining bytes after index)
        size_t argsBytes = len - 2;
        strcpy(out.args, "0x");
        for (size_t i = 0; i < argsBytes && i < 64; i++)
            snprintf(out.args + 2 + i*2, 3, "%02x", data[2 + i]);
        out.valid = true;

    } else if (fmt == 0x00 && len >= 34) {
        // ── Full address (deprecated bech32 OR current bech32m) ───────────────
        // payload: 0x00 | code_hash(32) | hash_type(1) | args(variable)
        // Both old full and CKB2021 full have identical payload; checksum differs
        // but our decoder doesn't verify the checksum, so both work transparently.
        strcpy(out.codeHash, "0x");
        for (int i = 1; i <= 32; i++)
            snprintf(out.codeHash + 2 + (i-1)*2, 3, "%02x", data[i]);
        uint8_t ht = data[33];
        if      (ht == 0x00) strlcpy(out.hashType, "data",  sizeof(out.hashType));
        else if (ht == 0x01) strlcpy(out.hashType, "type",  sizeof(out.hashType));
        else if (ht == 0x02) strlcpy(out.hashType, "data1", sizeof(out.hashType));
        else if (ht == 0x04) strlcpy(out.hashType, "data2", sizeof(out.hashType));
        else                 strlcpy(out.hashType, "type",  sizeof(out.hashType));
        size_t argsBytes = len - 34;
        strcpy(out.args, "0x");
        for (size_t i = 0; i < argsBytes && i < 64; i++)
            snprintf(out.args + 2 + i*2, 3, "%02x", data[34 + i]);
        out.valid = true;

    } else if (fmt == 0x02 && len >= 33) {
        // ── Deprecated full with inline type script (very old format) ─────────
        // payload: 0x02 | code_hash(32) | args(variable)  — hash_type implicitly "data"
        strcpy(out.codeHash, "0x");
        for (int i = 1; i <= 32; i++)
            snprintf(out.codeHash + 2 + (i-1)*2, 3, "%02x", data[i]);
        strlcpy(out.hashType, "data", sizeof(out.hashType));
        size_t argsBytes = len - 33;
        strcpy(out.args, "0x");
        for (size_t i = 0; i < argsBytes && i < 64; i++)
            snprintf(out.args + 2 + i*2, 3, "%02x", data[33 + i]);
        out.valid = true;
    }
    return out;
}

// ─── Address encode / convert ────────────────────────────────────────────────

// bech32m polymod constant (differs from bech32's 1)
static const uint32_t BECH32M_CONST = 0x2bc830a3UL;

static uint32_t _bech32mPolymod(const uint8_t* values, size_t len) {
    static const uint32_t GEN[5] = {
        0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL,
        0x3d4233ddUL, 0x2a1462b3UL
    };
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t b = chk >> 25;
        chk = ((chk & 0x1ffffffUL) << 5) ^ values[i];
        for (int j = 0; j < 5; j++)
            if ((b >> j) & 1) chk ^= GEN[j];
    }
    return chk;
}

bool CKBClient::_bech32mEncode(const char* hrp, const uint8_t* data, size_t dataLen,
                                char* out, size_t outSize) {
    // Convert raw bytes to 5-bit groups
    uint8_t groups[200]; size_t gLen = 0;
    uint32_t acc = 0; uint8_t bits = 0;
    for (size_t i = 0; i < dataLen; i++) {
        acc = (acc << 8) | data[i]; bits += 8;
        while (bits >= 5) {
            bits -= 5;
            groups[gLen++] = (acc >> bits) & 0x1f;
            if (gLen >= sizeof(groups)) return false;
        }
    }
    if (bits) groups[gLen++] = (acc << (5 - bits)) & 0x1f;  // padding

    // Build polymod input: hrp high + 0 + hrp low + groups + 6 zeros
    size_t hrpLen = strlen(hrp);
    size_t pmLen = hrpLen + 1 + hrpLen + gLen + 6;
    uint8_t pm[300];
    if (pmLen > sizeof(pm)) return false;
    size_t p = 0;
    for (size_t i = 0; i < hrpLen; i++) pm[p++] = (uint8_t)hrp[i] >> 5;
    pm[p++] = 0;
    for (size_t i = 0; i < hrpLen; i++) pm[p++] = hrp[i] & 0x1f;
    for (size_t i = 0; i < gLen;   i++) pm[p++] = groups[i];
    for (int  i = 0; i < 6;      i++) pm[p++] = 0;
    uint32_t mod = _bech32mPolymod(pm, pmLen) ^ BECH32M_CONST;

    // Serialise: hrp + "1" + groups + checksum
    size_t needed = hrpLen + 1 + gLen + 6 + 1;  // +1 for null
    if (needed > outSize) return false;
    size_t o = 0;
    for (size_t i = 0; i < hrpLen; i++) out[o++] = hrp[i];
    out[o++] = '1';
    for (size_t i = 0; i < gLen; i++) out[o++] = BECH32_CHARSET[groups[i]];
    for (int i = 0; i < 6; i++)
        out[o++] = BECH32_CHARSET[(mod >> (5 * (5 - i))) & 0x1f];
    out[o] = '\0';
    return true;
}

bool CKBClient::encodeAddress(const CKBScript& script, char* out, size_t outSize,
                               const char* hrp) {
    if (!script.valid || !out || outSize < 50) return false;

    // Parse code_hash (strip "0x" prefix)
    const char* chHex = script.codeHash;
    if (chHex[0]=='0' && (chHex[1]=='x'||chHex[1]=='X')) chHex += 2;
    if (strlen(chHex) != 64) return false;
    uint8_t codeHash[32];
    for (int i = 0; i < 32; i++) {
        auto h = [](char c) -> int {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        int hi = h(chHex[i*2]), lo = h(chHex[i*2+1]);
        if (hi<0||lo<0) return false;
        codeHash[i] = (uint8_t)((hi<<4)|lo);
    }

    // hash_type byte
    uint8_t hashTypeByte;
    if      (strcmp(script.hashType,"data" )==0) hashTypeByte = 0x00;
    else if (strcmp(script.hashType,"type" )==0) hashTypeByte = 0x01;
    else if (strcmp(script.hashType,"data1")==0) hashTypeByte = 0x02;
    else if (strcmp(script.hashType,"data2")==0) hashTypeByte = 0x04;
    else return false;

    // Parse args (strip "0x")
    const char* argsHex = script.args;
    if (argsHex[0]=='0' && (argsHex[1]=='x'||argsHex[1]=='X')) argsHex += 2;
    size_t argsHexLen = strlen(argsHex);
    if (argsHexLen & 1) return false;  // must be even
    size_t argsLen = argsHexLen / 2;
    uint8_t args[64];
    if (argsLen > sizeof(args)) return false;
    for (size_t i = 0; i < argsLen; i++) {
        auto h = [](char c) -> int {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        int hi = h(argsHex[i*2]), lo = h(argsHex[i*2+1]);
        if (hi<0||lo<0) return false;
        args[i] = (uint8_t)((hi<<4)|lo);
    }

    // Build payload: 0x00 | code_hash(32) | hash_type(1) | args(N)
    uint8_t payload[100]; size_t payLen = 0;
    payload[payLen++] = 0x00;
    memcpy(payload + payLen, codeHash, 32); payLen += 32;
    payload[payLen++] = hashTypeByte;
    memcpy(payload + payLen, args, argsLen); payLen += argsLen;

    return _bech32mEncode(hrp, payload, payLen, out, outSize);
}

bool CKBClient::convertAddress(const char* inputAddr, char* out, size_t outSize,
                                CKBAddrFormat toFormat, bool toMainnet) {
    if (!inputAddr || !out || outSize < 50) return false;
    const char* hrp = toMainnet ? "ckb" : "ckt";

    // Decode input to a canonical CKBScript
    CKBScript script = decodeAddress(inputAddr);
    if (!script.valid) return false;

    if (toFormat == CKB_ADDR_FULL) {
        // CKB2021 bech32m full address — works for any script
        return encodeAddress(script, out, outSize, hrp);

    } else {
        // Deprecated short address — only valid for scripts in the known index table
        // (secp256k1-sighash, secp256k1-multisig, anyone-can-pay) with "type" hash_type

        // Parse the script's code_hash to raw bytes for table lookup
        const char* chHex = script.codeHash;
        if (chHex[0]=='0' && (chHex[1]=='x'||chHex[1]=='X')) chHex += 2;
        if (strlen(chHex) != 64) return false;
        uint8_t codeHashBytes[32];
        for (int i = 0; i < 32; i++) {
            auto h = [](char c)->int{
                if(c>='0'&&c<='9')return c-'0';
                if(c>='a'&&c<='f')return c-'a'+10;
                if(c>='A'&&c<='F')return c-'A'+10;
                return -1;
            };
            int hi=h(chHex[i*2]),lo=h(chHex[i*2+1]);
            if(hi<0||lo<0)return false;
            codeHashBytes[i]=(uint8_t)((hi<<4)|lo);
        }

        // Find matching index in the known table
        int8_t foundIdx = -1;
        for (size_t i = 0; i < _CKB_SHORT_ADDR_TABLE_LEN; i++) {
            if (memcmp(codeHashBytes, _CKB_SHORT_ADDR_TABLE[i].codeHash, 32) == 0
                && strcmp(script.hashType, _CKB_SHORT_ADDR_TABLE[i].hashType) == 0) {
                foundIdx = (int8_t)i;
                break;
            }
        }
        if (foundIdx < 0) return false;  // not a known short-address script

        // Parse args
        const char* argsHex = script.args;
        if (argsHex[0]=='0' && (argsHex[1]=='x'||argsHex[1]=='X')) argsHex += 2;
        size_t argsHexLen = strlen(argsHex);
        if (argsHexLen & 1) return false;
        size_t argsLen = argsHexLen / 2;
        if (argsLen > 64) return false;

        // Short payload: 0x01 | index | args(N)
        uint8_t payload[67];
        payload[0] = 0x01;
        payload[1] = (uint8_t)foundIdx;
        for (size_t i = 0; i < argsLen; i++) {
            auto h = [](char c)->int{
                if(c>='0'&&c<='9')return c-'0';
                if(c>='a'&&c<='f')return c-'a'+10;
                if(c>='A'&&c<='F')return c-'A'+10;
                return -1;
            };
            int hi=h(argsHex[i*2]),lo=h(argsHex[i*2+1]);
            if(hi<0||lo<0)return false;
            payload[2+i]=(uint8_t)((hi<<4)|lo);
        }

        // Note: deprecated short addresses historically used bech32 (not bech32m).
        // We encode with bech32m for simplicity; the payload format is the key signal.
        // The CKB2021 full format is strongly preferred over short format.
        return _bech32mEncode(hrp, payload, 2 + argsLen, out, outSize);
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

uint64_t CKBClient::hexToUint64(const char* hex) {
    if (!hex || strlen(hex) < 3) return 0;
    const char* h = (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) ? hex + 2 : hex;
    uint64_t val = 0;
    while (*h) {
        char c = *h++;
        if      (c >= '0' && c <= '9') val = val * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
        else break;
    }
    return val;
}

void CKBClient::uint64ToHex(uint64_t val, char* buf) {
    snprintf(buf, 19, "0x%llx", (unsigned long long)val);
}

char* CKBClient::formatCKB(uint64_t shannon, char* buf, size_t bufSize) {
    uint64_t ckb  = shannon / CKB_SHANNON_PER_CKB;
    uint64_t frac = (shannon % CKB_SHANNON_PER_CKB) / 100; // 6 decimal places
    if (frac == 0)
        snprintf(buf, bufSize, "%llu CKB", (unsigned long long)ckb);
    else
        snprintf(buf, bufSize, "%llu.%06llu CKB",
                 (unsigned long long)ckb, (unsigned long long)frac);
    return buf;
}

char* CKBClient::formatCKBCompact(uint64_t shannon, char* buf, size_t bufSize) {
    double ckb = (double)shannon / (double)CKB_SHANNON_PER_CKB;
    if (ckb >= 1e9)       snprintf(buf, bufSize, "%.1fB CKB", ckb / 1e9);
    else if (ckb >= 1e6)  snprintf(buf, bufSize, "%.1fM CKB", ckb / 1e6);
    else if (ckb >= 1e3)  snprintf(buf, bufSize, "%.1fK CKB", ckb / 1e3);
    else                  snprintf(buf, bufSize, "%.2f CKB", ckb);
    return buf;
}

time_t CKBClient::msToTime(uint64_t timestampMs) {
    return (time_t)(timestampMs / 1000);
}

// ─── printConfig ──────────────────────────────────────────────────────────────

#ifdef ARDUINO
void CKBClient::printConfig() {
    #ifdef ARDUINO

    Serial.println(F("── CKB-ESP32 v" CKB_ESP32_VERSION " build config ──────────────────────────────"));

    #endif
    #ifdef ARDUINO

    Serial.printf("  Node type:     %s\n",   CKB_NODE_TYPE_STR);

    #endif
    #ifdef ARDUINO

    Serial.printf("  Block queries: %s\n",   CKB_HAS_BLOCK_QUERIES ? "YES" : "no");

    #endif
    #ifdef ARDUINO

    Serial.printf("  Peer queries:  %s\n",   CKB_HAS_PEER_QUERIES  ? "YES" : "no");

    #endif
    #ifdef ARDUINO

    Serial.printf("  Pool queries:  %s\n",   CKB_HAS_POOL_QUERIES  ? "YES" : "no");

    #endif
    #ifdef ARDUINO

    Serial.printf("  Indexer:       %s\n",   CKB_HAS_INDEXER       ? "YES" : "no");

    #endif
    #ifdef ARDUINO

    Serial.printf("  Send tx:       %s\n",   CKB_HAS_SEND_TX       ? "YES" : "no");

    #endif
    #ifdef ARDUINO

    Serial.printf("  Rich indexer:  %s\n",   CKB_HAS_RICH_INDEXER  ? "YES" : "no");

    #endif
    #ifdef ARDUINO

    Serial.printf("  Signer:        %s\n",   CKB_HAS_SIGNER        ? "YES" : "no");

    #endif
#ifdef CKB_NODE_LIGHT
    #ifdef ARDUINO

    Serial.println("  Light client:  YES");

    #endif
#else
    #ifdef ARDUINO

    Serial.println("  Light client:  no");

    #endif
#endif
    #ifdef ARDUINO

    Serial.printf("  JSON buf:      %d bytes\n", CKB_JSON_DOC_SIZE);

    #endif
    #ifdef ARDUINO

    Serial.printf("  Max cells:     %d\n",        CKB_MAX_CELLS);

    #endif
    #ifdef ARDUINO

    Serial.printf("  Max txs:       %d\n",         CKB_MAX_TXS);

    #endif
    #ifdef ARDUINO

    Serial.printf("  Max peers:     %d\n",         CKB_MAX_PEERS);

    #endif
    #ifdef ARDUINO

    Serial.printf("  HTTP timeout:  %d ms\n",      CKB_HTTP_TIMEOUT_MS);

    #endif
    #ifdef ARDUINO

    Serial.println(F("─────────────────────────────────────────────────────────────────────────"));

    #endif
}
#else
void CKBClient::printConfig() {
    printf("── CKB-ESP32 build config (host build) ──\n");
    printf("  Node type: %s\n", CKB_NODE_TYPE_STR);
}
#endif // ARDUINO

// ─── signTx (signer integration) ──────────────────────────────────────────────
#if CKB_HAS_SIGNER

CKBError CKBClient::signTx(CKBBuiltTx& tx, const CKBKey& key) {
    // Refuse to sign transactions that contain unknown lock scripts.
    // Unknown locks (JoyID, Spore, etc.) require external signing — applying a
    // secp256k1 witness would produce a malformed transaction that the chain
    // rejects. The caller must use broadcastWithWitness() instead.
    if (tx.requiresExternalWitness) return CKB_ERR_UNSUPPORTED;

    // Use raw-pointer overload — avoids struct layout mismatch between
    // CKB.h's CKBBuiltTx and CKBSigner.h's CKBBuiltTx (different field offsets).
    return CKBSigner::signTxRaw(tx.signingHash, key, tx.signature, tx.signed_)
           ? CKB_OK : CKB_ERR_INVALID;
}

#endif // CKB_HAS_SIGNER


// ═══════════════════════════════════════════════════════════════════════════════
//  TRANSACTION BUILDER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

// ── Utilities ─────────────────────────────────────────────────────────────────

void CKBClient::_bytesToHex(const uint8_t* bytes, size_t len, char* out) {
    out[0] = '0'; out[1] = 'x';
    for (size_t i = 0; i < len; i++) snprintf(out + 2 + i*2, 3, "%02x", bytes[i]);
    out[2 + len*2] = '\0';
}

// Build WitnessArgs molecule with secp256k1 signature into hex string
bool CKBClient::_buildWitnessHex(const uint8_t sig65[65], char* out, size_t outCap) {
    uint8_t witBuf[128];
    CKBBuf bWit; ckb_buf_init(&bWit, witBuf, sizeof(witBuf));
    // WitnessArgs table: total(4) + 3 offsets(12) + lock fixvec(4+65)
    const size_t lockFieldSz = 4 + 65;
    const size_t headerSz    = 4 + 3*4;
    const size_t totalSz     = headerSz + lockFieldSz;
    ckb_buf_write_u32le(&bWit, (uint32_t)totalSz);
    ckb_buf_write_u32le(&bWit, (uint32_t)headerSz);              // lock at offset 16
    ckb_buf_write_u32le(&bWit, (uint32_t)(headerSz + lockFieldSz)); // input_type (absent)
    ckb_buf_write_u32le(&bWit, (uint32_t)(headerSz + lockFieldSz)); // output_type (absent)
    ckb_buf_write_u32le(&bWit, 65);                               // lock fixvec length
    ckb_buf_write(&bWit, sig65, 65);                              // sig bytes

    // hex-encode: "0x" + 2 chars per byte
    size_t hexLen = 2 + bWit.len * 2 + 1;
    if (hexLen > outCap) return false;
    _bytesToHex(witBuf, bWit.len, out);
    return true;
}

// ── Send / Build / Broadcast ──────────────────────────────────────────────────
#if CKB_HAS_SEND_TX

// ── collectInputCells ─────────────────────────────────────────────────────────

CKBError CKBClient::collectInputCells(const CKBScript& lockScript,
                                       uint64_t targetShannon,
                                       CKBTxInput outInputs[],
                                       uint8_t& outCount,
                                       uint64_t& outTotal) {
    outCount = 0; outTotal = 0;
    char cursorBuf[128] = {0};
    bool hasCursor = false;

    while (outTotal < targetShannon && outCount < CKB_MAX_INPUTS) {
        CKBCellsResult res = getCells(lockScript, "lock", 20,
                                       hasCursor ? cursorBuf : nullptr);
        if (res.error != CKB_OK || res.count == 0) break;

        for (uint8_t i = 0; i < res.count && outCount < CKB_MAX_INPUTS; i++) {
            CKBIndexerCell& c = res.cells[i];
            if (c.output.capacity == 0) continue;
            // Skip cells that have a type script (could be DAO, UDT — don't spend)
            if (c.output.type.valid) continue;

            CKBTxInput& inp = outInputs[outCount];
            strncpy(inp.txHash, c.outPoint.txHash, 67);
            inp.index      = c.outPoint.index;
            inp.since      = 0;
            inp.capacity   = c.output.capacity;
            inp.lockScript = c.output.lock;
            outCount++;
            outTotal += c.output.capacity;
            if (outTotal >= targetShannon) break;
        }
        if (!res.hasMore) break;
        strncpy(cursorBuf, res.lastCursor, sizeof(cursorBuf) - 1);
        hasCursor = true;
    }

    if (outTotal < targetShannon) { _lastError = CKB_ERR_FUNDS; return CKB_ERR_FUNDS; }
    return CKB_OK;
}

// ── _buildRawTxMolecule ───────────────────────────────────────────────────────

bool CKBClient::_buildRawTxMolecule(CKBBuiltTx& tx) {
    // Each field serialised into its own stack buffer, then assembled into a table

    // version (Uint32)
    uint8_t vBuf[4]; CKBBuf bV; ckb_buf_init(&bV, vBuf, 4);
    ckb_buf_write_u32le(&bV, 0);

    // cell_deps: fixvec<CellDep> = 4-byte count + 37 bytes each
    uint8_t depBuf[37*4 + 4]; CKBBuf bDep; ckb_buf_init(&bDep, depBuf, sizeof(depBuf));
    ckb_buf_write_u32le(&bDep, tx.cellDepCount);
    for (uint8_t i = 0; i < tx.cellDepCount; i++)
        mol_write_celldep(&bDep, tx.cellDeps[i].txHash, tx.cellDeps[i].index, tx.cellDeps[i].isDepGroup);

    // header_deps: empty fixvec
    uint8_t hdBuf[4]; CKBBuf bHD; ckb_buf_init(&bHD, hdBuf, 4);
    ckb_buf_write_u32le(&bHD, 0);

    // inputs: fixvec<CellInput> = 4-byte count + 44 bytes each
    uint8_t inBuf[44 * CKB_MAX_INPUTS + 4]; CKBBuf bIn; ckb_buf_init(&bIn, inBuf, sizeof(inBuf));
    ckb_buf_write_u32le(&bIn, tx.inputCount);
    for (uint8_t i = 0; i < tx.inputCount; i++)
        mol_write_cellinput(&bIn, tx.inputs[i].txHash, tx.inputs[i].index, tx.inputs[i].since);

    // outputs: dynvec<CellOutput>
    // Build each CellOutput into its own temp, track offsets
    uint8_t outItemBufs[CKB_MAX_INPUTS + 1][256];
    size_t  outItemLens[CKB_MAX_INPUTS + 1];
    for (uint8_t i = 0; i < tx.outputCount; i++) {
        CKBBuf boi; ckb_buf_init(&boi, outItemBufs[i], 256);
        mol_write_celloutput(&boi,
            tx.outputs[i].capacity,
            tx.outputs[i].lockScript.codeHash,
            tx.outputs[i].lockScript.hashType,
            tx.outputs[i].lockScript.args,
            false);
        outItemLens[i] = boi.len;
    }
    // dynvec: total(4) + offsets(4*n) + items
    size_t dynvecOffsetsSz = 4 * tx.outputCount;
    size_t dynvecDataSz = 0;
    for (uint8_t i = 0; i < tx.outputCount; i++) dynvecDataSz += outItemLens[i];
    size_t dynvecTotal = 4 + dynvecOffsetsSz + dynvecDataSz;

    uint8_t outsBuf[512]; CKBBuf bOuts; ckb_buf_init(&bOuts, outsBuf, sizeof(outsBuf));
    ckb_buf_write_u32le(&bOuts, (uint32_t)dynvecTotal);
    size_t cursor = 4 + dynvecOffsetsSz;
    for (uint8_t i = 0; i < tx.outputCount; i++) {
        ckb_buf_write_u32le(&bOuts, (uint32_t)cursor);
        cursor += outItemLens[i];
    }
    for (uint8_t i = 0; i < tx.outputCount; i++)
        ckb_buf_write(&bOuts, outItemBufs[i], outItemLens[i]);

    // outputs_data: dynvec<Bytes>  — each "0x" = empty fixvec (4-byte 0)
    size_t odOffsetsSz = 4 * tx.outputCount;
    size_t odItemSz    = 4;  // each empty fixvec
    size_t odTotal     = 4 + odOffsetsSz + odItemSz * tx.outputCount;
    uint8_t odBuf[128]; CKBBuf bOD; ckb_buf_init(&bOD, odBuf, sizeof(odBuf));
    ckb_buf_write_u32le(&bOD, (uint32_t)odTotal);
    for (uint8_t i = 0; i < tx.outputCount; i++)
        ckb_buf_write_u32le(&bOD, (uint32_t)(4 + odOffsetsSz + i * odItemSz));
    for (uint8_t i = 0; i < tx.outputCount; i++)
        ckb_buf_write_u32le(&bOD, 0);  // empty bytes

    // Assemble RawTransaction table
    // Fields: version, cell_deps, header_deps, inputs, outputs, outputs_data
    const size_t nFields  = 6;
    const size_t hdrSz    = 4 + nFields * 4;  // total(4) + nFields offsets
    size_t fieldLens[6]   = { bV.len, bDep.len, bHD.len, bIn.len, bOuts.len, bOD.len };
    size_t fieldOffsets[6];
    fieldOffsets[0] = hdrSz;
    for (int i = 1; i < 6; i++) fieldOffsets[i] = fieldOffsets[i-1] + fieldLens[i-1];
    size_t rawTotal = fieldOffsets[5] + fieldLens[5];

    if (rawTotal > CKB_TX_BUF_SIZE) return false;

    CKBBuf bRaw; ckb_buf_init(&bRaw, tx._rawBytes, CKB_TX_BUF_SIZE);
    ckb_buf_write_u32le(&bRaw, (uint32_t)rawTotal);
    for (int i = 0; i < 6; i++) ckb_buf_write_u32le(&bRaw, (uint32_t)fieldOffsets[i]);
    ckb_buf_write(&bRaw, vBuf,    bV.len);
    ckb_buf_write(&bRaw, depBuf,  bDep.len);
    ckb_buf_write(&bRaw, hdBuf,   bHD.len);
    ckb_buf_write(&bRaw, inBuf,   bIn.len);
    ckb_buf_write(&bRaw, outsBuf, bOuts.len);
    ckb_buf_write(&bRaw, odBuf,   bOD.len);

    tx._rawLen = bRaw.len;
    return (bRaw.len == rawTotal);
}

// ── _computeSigningHash ───────────────────────────────────────────────────────

void CKBClient::_computeSigningHash(CKBBuiltTx& tx) {
    // tx_hash = Blake2b(rawTx)
    ckb_blake2b_hash(tx._rawBytes, tx._rawLen, tx.txHash);
    _bytesToHex(tx.txHash, 32, tx.txHashHex);

    // Witness placeholder: WitnessArgs with 65 zero bytes in lock field
    uint8_t zeroSig[65] = {0};
    char witHexBuf[300];
    _buildWitnessHex(zeroSig, witHexBuf, sizeof(witHexBuf));
    // witHexBuf = "0x<hex>" — strip prefix to get raw bytes for hashing
    const char* witHex = witHexBuf + 2;
    size_t witByteLen  = strlen(witHex) / 2;
    uint8_t witBytes[128];
    for (size_t i = 0; i < witByteLen && i < sizeof(witBytes); i++) {
        char hi = witHex[i*2], lo = witHex[i*2+1];
        auto nib = [](char c) -> uint8_t {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return 0;
        };
        witBytes[i] = (nib(hi)<<4)|nib(lo);
    }

    // signing_hash = Blake2b(tx_hash || uint64le(witness_len) || witness_bytes)
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, tx.txHash, 32);
    uint64_t wlen = witByteLen;
    uint8_t wlenBuf[8]; for (int i=0;i<8;i++) wlenBuf[i]=(uint8_t)(wlen>>(i*8));
    ckb_blake2b_update(&ctx, wlenBuf, 8);
    ckb_blake2b_update(&ctx, witBytes, witByteLen);
    ckb_blake2b_final(&ctx, tx.signingHash);
}

// ── buildTransfer ─────────────────────────────────────────────────────────────

CKBBuiltTx CKBClient::buildTransfer(const char* fromAddr, const char* toAddr,
                                      uint64_t amountShannon, uint64_t feeShannon) {
    CKBBuiltTx tx;
    memset(&tx, 0, sizeof(tx));
    tx.valid = false;

    // Validate
    if (!fromAddr || !toAddr || amountShannon < CKB_MIN_CELL_CAPACITY) {
        tx.error = CKB_ERR_INVALID; return tx;
    }
    CKBScript fromLock = decodeAddress(fromAddr);
    CKBScript toLock   = decodeAddress(toAddr);
    if (!fromLock.valid || !toLock.valid) { tx.error = CKB_ERR_INVALID; return tx; }

    // 1. Collect inputs
    uint64_t needed = amountShannon + feeShannon;
    uint64_t totalIn = 0;
    CKBError err = collectInputCells(fromLock, needed,
                                      tx.inputs, tx.inputCount, totalIn);
    if (err != CKB_OK) { tx.error = err; return tx; }

    // 2. Calculate change
    uint64_t change = totalIn - amountShannon - feeShannon;
    bool hasChange  = (change >= CKB_MIN_CELL_CAPACITY);
    if (!hasChange) feeShannon += change;  // absorb dust into fee

    // 3. Build outputs
    tx.outputCount = 0;
    // Output 0: recipient
    tx.outputs[0].capacity   = amountShannon;
    tx.outputs[0].lockScript = toLock;
    strncpy(tx.outputs[0].data, "0x", 3);
    tx.outputCount = 1;
    // Output 1: change (if significant)
    if (hasChange) {
        tx.outputs[1].capacity   = change;
        tx.outputs[1].lockScript = fromLock;
        strncpy(tx.outputs[1].data, "0x", 3);
        tx.outputCount = 2;
    }

    // 4. Cell deps — injected based on lock class
    // Unknown locks (JoyID, Spore, custom): passthrough — caller must add their dep
    // Known locks: inject their standard dep group automatically
    tx.cellDepCount = 0;
    tx.requiresExternalWitness = false;
    tx.unknownLockCount = 0;

    // Scan inputs for lock types
    bool needsSecp = false;
    for (uint8_t i = 0; i < tx.inputCount; i++) {
        CKBLockClass lc = tx.inputs[i].lockScript.lockClass();
        if (lc == CKB_LOCK_SECP256K1 || lc == CKB_LOCK_ACP) needsSecp = true;
        else if (lc == CKB_LOCK_UNKNOWN) {
            tx.requiresExternalWitness = true;
            tx.unknownLockCount++;
        }
        // multisig shares the secp256k1 dep group
        if (lc == CKB_LOCK_MULTISIG) needsSecp = true;
    }

    // Always inject secp256k1 dep if any known secp-family lock is present
    if (needsSecp) {
        strncpy(tx.cellDeps[tx.cellDepCount].txHash,
                _testnet ? CKB_SECP256K1_DEP_TESTNET_TX : CKB_SECP256K1_DEP_MAINNET_TX, 67);
        tx.cellDeps[tx.cellDepCount].index      = CKB_SECP256K1_DEP_INDEX;
        tx.cellDeps[tx.cellDepCount].isDepGroup = true;
        tx.cellDepCount++;
    }
    // Unknown lock deps must be added by the caller via tx.cellDeps[] before broadcast

    // 5. Serialise to Molecule
    if (!_buildRawTxMolecule(tx)) { tx.error = CKB_ERR_OVERFLOW; return tx; }

    // 6. Compute tx hash + signing hash
    _computeSigningHash(tx);

    tx.signed_ = false;
    tx.error   = CKB_OK;
    tx.valid   = true;
    return tx;
}

// ── _rpcCallStatic ────────────────────────────────────────────────────────────

bool CKBClient::_rpcCallStatic(const char* url, const char* method,
                                 const char* params, JsonDocument& doc,
                                 uint32_t timeoutMs) {
    char body[2800];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params);

    static char _srbuf[CKB_JSON_DOC_SIZE];
    CKBTransport* t = _defaultTransport();
    int n = t->rpc(url, body, _srbuf, sizeof(_srbuf), timeoutMs);
    if (n < 0) return false;

    DeserializationError jerr = deserializeJson(doc, _srbuf);
    if (jerr) return false;
    if (doc.containsKey("error")) return false;
    return true;
}

#if CKB_HAS_SIGNER
// ── sendTransaction ───────────────────────────────────────────────────────────

CKBError CKBClient::sendTransaction(const char* toAddr,
                                     float amountCKB,
                                     const CKBKey& key,
                                     char* txHashOut,
                                     const char* nodeUrl) {
    if (!key.isValid()) return CKB_ERR_INVALID;

    // Use instance node URL if none supplied
    const char* url = (nodeUrl && nodeUrl[0]) ? nodeUrl : _nodeUrl;
    if (!url || !url[0]) return CKB_ERR_INVALID;

    // Derive from-address from the key (mainnet unless _testnet flag set)
    char fromAddr[120];
    if (!key.getAddress(fromAddr, sizeof(fromAddr), !_testnet))
        return CKB_ERR_INVALID;

    // 1. Build (convert CKB float → shannon)
    uint64_t amountShannon = ckbToShannon(amountCKB);
    CKBBuiltTx tx = buildTransfer(fromAddr, toAddr, amountShannon);
    if (!tx.valid) return tx.error;

    // 2. Sign (via signTx wrapper — avoids ODR struct mismatch)
    CKBError signErr = signTx(tx, key);
    if (signErr != CKB_OK) return signErr;

    // 3. Broadcast
    return broadcast(tx, url, txHashOut);
}

// ── broadcast ────────────────────────────────────────────────────────────────

CKBError CKBClient::broadcast(const CKBBuiltTx& tx, const char* nodeUrl,
                                char* txHashOut, uint32_t timeoutMs) {
    if (!tx.valid)   return CKB_ERR_INVALID;
    if (!tx.signed_) return CKB_ERR_INVALID;  // must call setSignature() first

    char witHex[300];
    if (!_buildWitnessHex(tx.signature, witHex, sizeof(witHex))) return CKB_ERR_OVERFLOW;

    return broadcastWithWitness(tx, nodeUrl, witHex, txHashOut, timeoutMs);
}

CKBError CKBClient::broadcastWithWitness(const CKBBuiltTx& tx, const char* nodeUrl,
                                           const char* witnessHex,
                                           char* txHashOut, uint32_t timeoutMs) {
    if (!tx.valid || !nodeUrl || !witnessHex) return CKB_ERR_INVALID;

    // ── Build inputs JSON ─────────────────────────────────────────────────────
    char inputsJson[600] = "[";
    for (uint8_t i = 0; i < tx.inputCount; i++) {
        char tmp[160];
        snprintf(tmp, sizeof(tmp),
            "%s{\"previous_output\":{\"tx_hash\":\"%s\",\"index\":\"0x%x\"},\"since\":\"0x0\"}",
            i > 0 ? "," : "",
            tx.inputs[i].txHash, tx.inputs[i].index);
        strncat(inputsJson, tmp, sizeof(inputsJson) - strlen(inputsJson) - 1);
    }
    strncat(inputsJson, "]", sizeof(inputsJson) - strlen(inputsJson) - 1);

    // ── Build outputs JSON ────────────────────────────────────────────────────
    char outputsJson[600] = "[";
    char outputsDataJson[80] = "[";
    for (uint8_t i = 0; i < tx.outputCount; i++) {
        char capHex[20]; uint64ToHex(tx.outputs[i].capacity, capHex);
        const CKBScript& lk = tx.outputs[i].lockScript;
        char tmp[300];
        snprintf(tmp, sizeof(tmp),
            "%s{\"capacity\":\"%s\",\"lock\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},\"type\":null}",
            i > 0 ? "," : "",
            capHex, lk.codeHash, lk.hashType, lk.args);
        strncat(outputsJson, tmp, sizeof(outputsJson) - strlen(outputsJson) - 1);
        char dtmp[20]; snprintf(dtmp, sizeof(dtmp), "%s\"0x\"", i > 0 ? "," : "");
        strncat(outputsDataJson, dtmp, sizeof(outputsDataJson) - strlen(outputsDataJson) - 1);
    }
    strncat(outputsJson, "]", sizeof(outputsJson) - strlen(outputsJson) - 1);
    strncat(outputsDataJson, "]", sizeof(outputsDataJson) - strlen(outputsDataJson) - 1);

    // ── Build cell_deps JSON ──────────────────────────────────────────────────
    char depsJson[300] = "[";
    for (uint8_t i = 0; i < tx.cellDepCount; i++) {
        char tmp[200];
        snprintf(tmp, sizeof(tmp),
            "%s{\"out_point\":{\"tx_hash\":\"%s\",\"index\":\"0x%x\"},\"dep_type\":\"%s\"}",
            i > 0 ? "," : "",
            tx.cellDeps[i].txHash, tx.cellDeps[i].index,
            tx.cellDeps[i].isDepGroup ? "dep_group" : "code");
        strncat(depsJson, tmp, sizeof(depsJson) - strlen(depsJson) - 1);
    }
    strncat(depsJson, "]", sizeof(depsJson) - strlen(depsJson) - 1);

    // ── Assemble send_transaction params ──────────────────────────────────────
    char params[2600];
    snprintf(params, sizeof(params),
        "[{"
        "\"version\":\"0x0\","
        "\"cell_deps\":%s,"
        "\"header_deps\":[],"
        "\"inputs\":%s,"
        "\"outputs\":%s,"
        "\"outputs_data\":%s,"
        "\"witnesses\":[\"%s\"]"
        "},\"passthrough\"]",
        depsJson, inputsJson, outputsJson, outputsDataJson, witnessHex);

    JsonDocument doc;
    if (!_rpcCallStatic(nodeUrl, "send_transaction", params, doc, timeoutMs)) {
        if (doc.containsKey("error")) {
            const char* msg = doc["error"]["message"] | "unknown";
            // Duplicate = already in pool or already committed → treat as success
            if (strstr(msg, "PoolRejectedDuplicatedTransaction") ||
                strstr(msg, "Duplicated")) {
                // Extract tx hash from error message if txHashOut requested
                // (we already have it from the tx itself — compute from raw_tx)
                return CKB_OK;
            }
            #ifdef ARDUINO

            Serial.printf("[CKB] send_transaction rejected: %s\n", msg);

            #endif
        } else {
            /* _rpcCallStatic returned false but no error field in doc —
             * can happen when relay response triggers ArduinoJson parse edge case.
             * If result is a valid 66-char tx hash, treat as success. */
            const char* hash = doc["result"] | "";
            if (strlen(hash) == 66 && hash[0] == '0' && hash[1] == 'x') {
                if (txHashOut) strncpy(txHashOut, hash, 67);
                return CKB_OK;
            }
        }
        return CKB_ERR_RPC;
    }

    const char* hash = doc["result"] | "";
    if (txHashOut && strlen(hash) > 0) strncpy(txHashOut, hash, 67);
    return CKB_OK;
}
#endif // CKB_HAS_SIGNER

#endif // CKB_HAS_SEND_TX

// ─────────────────────────────────────────────────────────────────────────────
// LIGHT CLIENT IMPLEMENTATION
// Only compiled when #define CKB_NODE_LIGHT is set before including CKB.h
// ─────────────────────────────────────────────────────────────────────────────
#ifdef CKB_NODE_LIGHT

/*
 * Light client RPC reference:
 *   set_scripts   — register scripts to watch (POST, params: [{script,script_type,block_number}], command)
 *   get_scripts   — list watched scripts (POST, no params)
 *   get_tip_header — current synced tip header (POST, no params)
 *   fetch_header  — fetch header by hash on demand (POST, params: [blockHash])
 *   fetch_transaction — fetch tx by hash (POST, params: [txHash])
 *
 * Standard methods also available on light client:
 *   get_tip_block_number, local_node_info, get_peers, get_blockchain_info,
 *   get_indexer_tip, get_cells, get_transactions, get_cells_capacity,
 *   send_transaction (after sync)
 */

// ── setScripts ────────────────────────────────────────────────────────────────

CKBError CKBClient::setScripts(const CKBScriptStatus* scripts, uint8_t count,
                                 const char* command) {
    if (!scripts || count == 0) return CKB_ERR_INVALID;

    // Build JSON params:
    // [[ {script:{code_hash,hash_type,args}, script_type, block_number}, ...], "command"]
    // Max param string: ~300 bytes per script × 8 scripts + overhead
    char param[3200];
    char* p = param;
    int remaining = sizeof(param);

    int written = snprintf(p, remaining, "[[");
    p += written; remaining -= written;

    for (uint8_t i = 0; i < count && remaining > 10; i++) {
        const CKBScriptStatus& s = scripts[i];
        char blockNumHex[19];
        uint64ToHex(s.blockNumber, blockNumHex);

        written = snprintf(p, remaining,
            "%s{"
              "\"script\":{"
                "\"code_hash\":\"%s\","
                "\"hash_type\":\"%s\","
                "\"args\":\"%s\""
              "},"
              "\"script_type\":\"%s\","
              "\"block_number\":\"%s\""
            "}",
            i > 0 ? "," : "",
            s.script.codeHash, s.script.hashType, s.script.args,
            s.scriptType,
            blockNumHex
        );
        p += written; remaining -= written;
    }

    written = snprintf(p, remaining, "],\"%s\"]", command);
    p += written; remaining -= written;

    JsonDocument doc;
    if (!_rpcCall(_nodeUrl, "set_scripts", param, doc)) return _lastError;
    return CKB_OK;
}

// ── watchAddress ──────────────────────────────────────────────────────────────

CKBError CKBClient::watchAddress(const char* ckbAddress, uint64_t fromBlock) {
    CKBScript lock = decodeAddress(ckbAddress);
    if (!lock.valid) return CKB_ERR_INVALID;

    CKBScriptStatus status;
    memset(&status, 0, sizeof(status));
    status.script      = lock;
    status.blockNumber = fromBlock;
    strncpy(status.scriptType, "lock", sizeof(status.scriptType)-1);

    return setScripts(&status, 1, "partial");
}

// ── getScripts ────────────────────────────────────────────────────────────────

CKBScriptStatusResult CKBClient::getScripts() {
    CKBScriptStatusResult result;
    memset(&result, 0, sizeof(result));

    JsonDocument doc;
    if (!_rpcCall(_nodeUrl, "get_scripts", "[]", doc)) {
        result.error = _lastError;
        return result;
    }

    JsonArray arr = doc["result"].as<JsonArray>();
    if (arr.isNull()) {
        result.error = CKB_ERR_JSON;
        return result;
    }

    uint8_t idx = 0;
    for (JsonObject item : arr) {
        if (idx >= CKB_MAX_LIGHT_SCRIPTS) break;
        CKBScriptStatus& s = result.scripts[idx];

        JsonObject scriptObj = item["script"];
        if (!scriptObj.isNull()) _parseScript(scriptObj, s.script);

        const char* st = item["script_type"] | "lock";
        strncpy(s.scriptType, st, sizeof(s.scriptType)-1);

        const char* bn = item["block_number"] | "0x0";
        s.blockNumber = hexToUint64(bn);

        idx++;
    }
    result.count = idx;
    result.error = CKB_OK;
    return result;
}

// ── getTipHeader ──────────────────────────────────────────────────────────────

CKBBlockHeader CKBClient::getTipHeader() {
    JsonDocument doc;
    CKBBlockHeader out; memset(&out, 0, sizeof(out));
    if (!_rpcCall(_nodeUrl, "get_tip_header", "[]", doc)) return out;

    JsonObject result = doc["result"];
    if (result.isNull()) { _lastError = CKB_ERR_NOT_FOUND; return out; }
    _parseBlockHeader(result, out);
    return out;
}

// ── fetchHeader ───────────────────────────────────────────────────────────────

CKBBlockHeader CKBClient::fetchHeader(const char* blockHash) {
    CKBBlockHeader out; memset(&out, 0, sizeof(out));
    if (!blockHash) { _lastError = CKB_ERR_INVALID; return out; }

    char params[80];
    snprintf(params, sizeof(params), "[\"%s\"]", blockHash);

    JsonDocument doc;
    if (!_rpcCall(_nodeUrl, "fetch_header", params, doc)) return out;

    // fetch_header returns { status: "fetched", data: { header... } }
    // or { status: "not_synced" } / { status: "fetching" }
    JsonObject result = doc["result"];
    if (result.isNull()) { _lastError = CKB_ERR_NOT_FOUND; return out; }

    const char* status = result["status"] | "unknown";
    if (strcmp(status, "fetched") == 0) {
        JsonObject header = result["data"];
        if (!header.isNull()) _parseBlockHeader(header, out);
    } else {
        // "not_synced" or "fetching" — not an error, just not ready
        _lastError = CKB_ERR_NOT_FOUND;
    }
    return out;
}

// ── fetchTransaction ──────────────────────────────────────────────────────────

CKBTransaction CKBClient::fetchTransaction(const char* txHash) {
    CKBTransaction out; memset(&out, 0, sizeof(out)); out.status = 0;
    if (!txHash) { _lastError = CKB_ERR_INVALID; return out; }

    char params[80];
    snprintf(params, sizeof(params), "[\"%s\"]", txHash);

    JsonDocument doc;
    if (!_rpcCall(_nodeUrl, "fetch_transaction", params, doc)) return out;

    // fetch_transaction v0.5.4 response:
    //   { status: "fetched",
    //     data: { transaction: {...},
    //             cycles: null,
    //             tx_status: { block_hash: "0x...", status: "committed" } } }
    //   or { status: "added" }   — queued, not yet fetched
    //   or { status: "not_synced" }
    JsonObject result = doc["result"];
    if (result.isNull()) { _lastError = CKB_ERR_NOT_FOUND; return out; }

    const char* status = result["status"] | "unknown";
    if (strcmp(status, "fetched") != 0) {
        // "added" means it's queued — caller should retry
        _lastError = CKB_ERR_NOT_FOUND;
        return out;
    }

    JsonObject data = result["data"];
    if (data.isNull()) { _lastError = CKB_ERR_JSON; return out; }

    JsonObject tx = data["transaction"];
    if (!tx.isNull()) out = _parseTransaction(tx);

    // tx_status is a nested object: { block_hash: "0x...", status: "committed" }
    JsonObject txStatusObj = data["tx_status"].as<JsonObject>();
    if (!txStatusObj.isNull()) {
        const char* bh = txStatusObj["block_hash"] | "";
        if (strlen(bh) == 66) strncpy(out.blockHash, bh, sizeof(out.blockHash)-1);

        const char* st = txStatusObj["status"] | "unknown";
        if      (strcmp(st,"pending")   == 0) out.status = 0;
        else if (strcmp(st,"proposed")  == 0) out.status = 1;
        else if (strcmp(st,"committed") == 0) out.status = 2;
    }

    out.valid = true;
    return out;
}

// ── getSyncState ──────────────────────────────────────────────────────────────

CKBLightSyncState CKBClient::getSyncState() {
    CKBLightSyncState state; memset(&state, 0, sizeof(state));

    // Get local synced tip from get_tip_header
    CKBBlockHeader tip = getTipHeader();
    if (!tip.valid) {
        state.error = _lastError;
        return state;
    }
    state.tipBlockNumber = tip.number;
    strncpy(state.tipBlockHash, tip.hash, sizeof(state.tipBlockHash)-1);

    // Light client v0.5.4: local_node_info does NOT include tipBlockNumber.
    // Heuristic: if we have peers connected, the tip header advances with the network.
    // Consider "synced" if we have at least 1 peer and the tip timestamp is recent
    // (within ~30 minutes = 300 blocks at 6s each of the current time).
    //
    // Best available signal: timestamp of tip header vs system time.
    // tip.timestamp is in milliseconds.
    unsigned long nowMs = (unsigned long)millis(); // uptime only — not wall clock
    // Without wall clock, we can only check peer connectivity as a proxy.
    // If the node has connected peers, it is receiving new blocks.
    JsonDocument doc;
    bool hasPeers = false;
    if (_rpcCall(_nodeUrl, "local_node_info", "[]", doc)) {
        JsonObject info = doc["result"];
        if (!info.isNull()) {
            const char* connHex = info["connections"] | "0x0";
            uint64_t conns = hexToUint64(connHex);
            hasPeers = (conns > 0);
        }
    }
    // If we have peers and tip is non-zero, we're at least partially synced.
    // Full sync detection requires knowing the network tip externally.
    state.isSynced = hasPeers && (state.tipBlockNumber > 0);

    state.error = CKB_OK;
    return state;
}

// ── waitForSync ───────────────────────────────────────────────────────────────

bool CKBClient::waitForSync(uint64_t targetBlock, uint32_t timeoutMs, uint32_t pollMs) {
    unsigned long deadline = millis() + timeoutMs;
    while (millis() < deadline) {
        CKBBlockHeader tip = getTipHeader();
        if (tip.valid && tip.number >= targetBlock) return true;
        if (pollMs > 0) delay(pollMs);
    }
    return false;
}

#endif // CKB_NODE_LIGHT

// ── broadcastRaw — send custom JSON-RPC body (CKBFS etc.) ───────────────────
CKBError CKBClient::broadcastRaw(const char *node_url,
                                   const char *json_body,
                                   char *tx_hash_out,
                                   uint32_t timeoutMs)
{
    if (!node_url || !json_body) return CKB_ERR_INVALID;

#ifdef ARDUINO
    /* Arduino: use explicit WiFiClient connect to avoid CYD/WiFi hang */
    const char *hostStart = strstr(node_url, "://");
    if (!hostStart) return CKB_ERR_INVALID;
    hostStart += 3;
    const char *portColon = strchr(hostStart, ':');
    uint16_t port = 80;
    char host[64] = {};
    if (portColon) {
        size_t hostLen = portColon - hostStart;
        if (hostLen >= sizeof(host)) return CKB_ERR_INVALID;
        memcpy(host, hostStart, hostLen);
        port = (uint16_t)atoi(portColon + 1);
    } else {
        strncpy(host, hostStart, sizeof(host)-1);
    }
    WiFiClient wifiClient;
    if (!wifiClient.connect(host, port, 8000)) return CKB_ERR_HTTP;
    HTTPClient http;
    http.begin(wifiClient, node_url);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(timeoutMs > 0 ? (int)timeoutMs : 20000);
    int code = http.POST((uint8_t*)json_body, strlen(json_body));
    if (code != 200) { http.end(); return CKB_ERR_HTTP; }
    String resp = http.getString();
    http.end();
    int idx = resp.indexOf("\"result\":\"0x");
    if (idx < 0) return CKB_ERR_RPC;
    idx += strlen("\"result\":\"");
    if (tx_hash_out) {
        size_t i = 0;
        while (idx+(int)i < resp.length() && resp[idx+i] != '"' && i < 66)
            { tx_hash_out[i] = resp[idx+i]; i++; }
        tx_hash_out[i] = '\0';
    }
    return CKB_OK;
#else
    /* Non-Arduino: use platform transport */
    static char _brbuf[CKB_JSON_DOC_SIZE];
    CKBTransport* t = _defaultTransport();
    int n = t->rpc(node_url, json_body, _brbuf, sizeof(_brbuf),
                   timeoutMs > 0 ? timeoutMs : 20000);
    if (n < 0) return CKB_ERR_HTTP;
    const char* res = strstr(_brbuf, "\"result\":\"0x");
    if (!res) return CKB_ERR_RPC;
    res += strlen("\"result\":\"");
    if (tx_hash_out) {
        size_t i = 0;
        while (res[i] && res[i] != '"' && i < 66) { tx_hash_out[i] = res[i]; i++; }
        tx_hash_out[i] = '\0';
    }
    return CKB_OK;
#endif
}
