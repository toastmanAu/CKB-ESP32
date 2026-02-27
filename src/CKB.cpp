/*
 * CKB-ESP32 — CKBClient implementation
 * See CKB.h for full API documentation.
 */

#include "CKB.h"

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
    if (_debug) Serial.println(msg);
}

// ─── Internal RPC call ────────────────────────────────────────────────────────

bool CKBClient::_rpcCall(const char* url, const char* method,
                          const char* params, JsonDocument& doc) {
    HTTPClient http;
    http.begin(url);
    http.setTimeout(_timeoutMs);
    http.addHeader("Content-Type", "application/json");

    char body[640];
    snprintf(body, sizeof(body),
        "{\"id\":%d,\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}",
        _rpcId++, method, params ? params : "[]");
    _debugPrint(body);

    int code = http.POST(body);
    if (code < 0 || code != 200) {
        _lastError = (code == -1) ? CKB_ERR_TIMEOUT : CKB_ERR_HTTP;
        http.end(); return false;
    }

    String payload = http.getString();
    http.end();

    DeserializationError err = deserializeJson(doc, payload);
    if (err) { _lastError = CKB_ERR_JSON; return false; }
    if (doc.containsKey("error")) { _lastError = CKB_ERR_RPC; return false; }
    if (doc["result"].isNull()) { _lastError = CKB_ERR_NOT_FOUND; return false; }

    _lastError = CKB_OK;
    return true;
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

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
    const char* sep = strrchr(addr, '1');
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

CKBScript CKBClient::decodeAddress(const char* address) {
    CKBScript out; out.valid = false;
    if (!address || strlen(address) < 46) return out;

    uint8_t data[100]; size_t len = 0; char hrp[8];
    if (!_bech32Decode(address, data, len, hrp)) return out;
    if (len < 1) return out;

    uint8_t formatByte = data[0];

    if (formatByte == 0x01 && len == 22) {
        // Short secp256k1 address: 0x01 + 20-byte args
        strlcpy(out.codeHash, SECP256K1_CODE_HASH, sizeof(out.codeHash));
        strlcpy(out.hashType, "type", sizeof(out.hashType));
        // Convert 20 bytes to hex
        strcpy(out.args, "0x");
        for (int i = 1; i <= 20; i++)
            snprintf(out.args + 2 + (i-1)*2, 3, "%02x", data[i]);
        out.valid = true;

    } else if (formatByte == 0x00 && len >= 34) {
        // Full address: 0x00 + codeHash(32) + hashType(1) + args
        strcpy(out.codeHash, "0x");
        for (int i = 1; i <= 32; i++)
            snprintf(out.codeHash + 2 + (i-1)*2, 3, "%02x", data[i]);
        uint8_t ht = data[33];
        if      (ht ==
 0x00) strlcpy(out.hashType, "data",  sizeof(out.hashType));
        else if (ht == 0x01) strlcpy(out.hashType, "type",  sizeof(out.hashType));
        else if (ht == 0x02) strlcpy(out.hashType, "data1", sizeof(out.hashType));
        else if (ht == 0x04) strlcpy(out.hashType, "data2", sizeof(out.hashType));
        else strlcpy(out.hashType, "type", sizeof(out.hashType));

        size_t argsBytes = len - 34;
        if (argsBytes == 0) {
            strlcpy(out.args, "0x", sizeof(out.args));
        } else {
            strcpy(out.args, "0x");
            for (size_t i = 0; i < argsBytes && i < 64; i++)
                snprintf(out.args + 2 + i*2, 3, "%02x", data[34 + i]);
        }
        out.valid = true;
    }
    return out;
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

String CKBClient::formatCKB(uint64_t shannon) {
    uint64_t whole = shannon / CKB_SHANNON_PER_CKB;
    uint64_t frac  = (shannon % CKB_SHANNON_PER_CKB) / 1000000; // 2 decimal places
    char buf[32];
    if (whole >= 1000000)
        snprintf(buf, sizeof(buf), "%llu,%03llu,%03llu.%02llu CKB",
            (unsigned long long)(whole/1000000),
            (unsigned long long)((whole/1000)%1000),
            (unsigned long long)(whole%1000),
            (unsigned long long)frac);
    else if (whole >= 1000)
        snprintf(buf, sizeof(buf), "%llu,%03llu.%02llu CKB",
            (unsigned long long)(whole/1000),
            (unsigned long long)(whole%1000),
            (unsigned long long)frac);
    else
        snprintf(buf, sizeof(buf), "%llu.%02llu CKB",
            (unsigned long long)whole, (unsigned long long)frac);
    return String(buf);
}

String CKBClient::formatCKBCompact(uint64_t shannon) {
    uint64_t ckb = shannon / CKB_SHANNON_PER_CKB;
    char buf[24];
    if      (ckb >= 1000000000) snprintf(buf, sizeof(buf), "%.1fB CKB", ckb / 1000000000.0);
    else if (ckb >= 1000000)    snprintf(buf, sizeof(buf), "%.1fM CKB", ckb / 1000000.0);
    else if (ckb >= 1000)       snprintf(buf, sizeof(buf), "%.1fK CKB", ckb / 1000.0);
    else                        snprintf(buf, sizeof(buf), "%llu CKB", (unsigned long long)ckb);
    return String(buf);
}

time_t CKBClient::msToTime(uint64_t timestampMs) {
    return (time_t)(timestampMs / 1000);
}

// ─── printConfig ──────────────────────────────────────────────────────────────

void CKBClient::printConfig() {
    Serial.println(F("── CKB-ESP32 v" CKB_ESP32_VERSION " build config ──────────────────────────────"));
    Serial.printf("  Node type:     %s\n",   CKB_NODE_TYPE_STR);
    Serial.printf("  Block queries: %s\n",   CKB_HAS_BLOCK_QUERIES ? "YES" : "no");
    Serial.printf("  Peer queries:  %s\n",   CKB_HAS_PEER_QUERIES  ? "YES" : "no");
    Serial.printf("  Pool queries:  %s\n",   CKB_HAS_POOL_QUERIES  ? "YES" : "no");
    Serial.printf("  Indexer:       %s\n",   CKB_HAS_INDEXER       ? "YES" : "no");
    Serial.printf("  Send tx:       %s\n",   CKB_HAS_SEND_TX       ? "YES" : "no");
    Serial.printf("  Rich indexer:  %s\n",   CKB_HAS_RICH_INDEXER  ? "YES" : "no");
    Serial.printf("  Signer:        %s\n",   CKB_HAS_SIGNER        ? "YES" : "no");
#ifdef CKB_NODE_LIGHT
    Serial.println("  Light client:  YES");
#else
    Serial.println("  Light client:  no");
#endif
    Serial.printf("  JSON buf:      %d bytes\n", CKB_JSON_DOC_SIZE);
    Serial.printf("  Max cells:     %d\n",        CKB_MAX_CELLS);
    Serial.printf("  Max txs:       %d\n",         CKB_MAX_TXS);
    Serial.printf("  Max peers:     %d\n",         CKB_MAX_PEERS);
    Serial.printf("  HTTP timeout:  %d ms\n",      CKB_HTTP_TIMEOUT_MS);
    Serial.println(F("─────────────────────────────────────────────────────────────────────────"));
}

// ─── signTx (signer integration) ──────────────────────────────────────────────
#if CKB_HAS_SIGNER

CKBError CKBClient::signTx(CKBBuiltTx& tx, const CKBKey& key) {
    return CKBSigner::signTx(tx, key) ? CKB_OK : CKB_ERR_INVALID;
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

    // 4. Cell dep: secp256k1 dep group
    tx.cellDepCount = 1;
    strncpy(tx.cellDeps[0].txHash,
            _testnet ? CKB_SECP256K1_DEP_TESTNET_TX : CKB_SECP256K1_DEP_MAINNET_TX, 67);
    tx.cellDeps[0].index      = CKB_SECP256K1_DEP_INDEX;
    tx.cellDeps[0].isDepGroup = true;

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
    HTTPClient http;
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(timeoutMs);

    char body[2800];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params);

    int code = http.POST(body);
    if (code != 200) { http.end(); return false; }

    DeserializationError jerr = deserializeJson(doc, http.getString());
    http.end();
    if (jerr) return false;
    if (doc.containsKey("error")) return false;
    return true;
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
        return CKB_ERR_RPC;
    }

    const char* hash = doc["result"] | "";
    if (txHashOut && strlen(hash) > 0) strncpy(txHashOut, hash, 67);
    return CKB_OK;
}

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
