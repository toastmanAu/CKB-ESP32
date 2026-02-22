/*
 * CKB-ESP32 — CKBClient implementation
 * See CKB.h for full API documentation.
 */

#include "CKB.h"

// ─── Constructor ──────────────────────────────────────────────────────────────

CKBClient::CKBClient(const char* nodeUrl, const char* indexerUrl) {
    strncpy(_nodeUrl, nodeUrl, sizeof(_nodeUrl) - 1);
    _nodeUrl[sizeof(_nodeUrl) - 1] = '\0';

    if (indexerUrl && strlen(indexerUrl) > 0) {
        strncpy(_indexerUrl, indexerUrl, sizeof(_indexerUrl) - 1);
        _indexerUrl[sizeof(_indexerUrl) - 1] = '\0';
    } else {
        // Default: indexer on same host, port 8116
        strncpy(_indexerUrl, nodeUrl, sizeof(_indexerUrl) - 1);
        char* port = strstr(_indexerUrl, ":8114");
        if (port) memcpy(port, ":8116", 5);
    }
    _hasIndexer   = true;
    _timeoutMs    = CKB_HTTP_TIMEOUT_MS;
    _debug        = false;
    _lastError    = CKB_OK;
    _rpcId        = 1;
}

const char* CKBClient::lastErrorStr() const {
    switch (_lastError) {
        case CKB_OK:            return "OK";
        case CKB_ERR_HTTP:      return "HTTP error";
        case CKB_ERR_JSON:      return "JSON parse error";
        case CKB_ERR_RPC:       return "RPC error";
        case CKB_ERR_NOT_FOUND: return "Not found";
        case CKB_ERR_TIMEOUT:   return "Timeout";
        case CKB_ERR_INVALID:   return "Invalid argument";
        default:                return "Unknown error";
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

// ─── NODE RPC — Network ───────────────────────────────────────────────────────

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

// ─── INDEXER RPC ──────────────────────────────────────────────────────────────

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

// ─── Address decoder ──────────────────────────────────────────────────────────

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
