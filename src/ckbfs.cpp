/*
 * ckbfs.cpp — CKBFS Protocol implementation for CKB-ESP32
 * =========================================================
 * Content lives in tx witnesses (not cell data).
 * Index cell holds molecule-encoded metadata.
 *
 * Tx layout:
 *   witnesses[0]: WitnessArgs (65-byte sig placeholder → real sig after sign)
 *   witnesses[1]: "CKBFS\x00" + content bytes
 *   outputs[0]:   change back to sender
 *   outputs[1]:   CKBFS index cell (locked forever, molecule metadata)
 */

#include "ckbfs.h"
#include "CKB.h"
#include "CKBSigner.h"
#include "ckb_blake2b.h"
#include <HTTPClient.h>
#ifdef ARDUINO
  #include <esp_task_wdt.h>
  #define WDT_FEED() esp_task_wdt_reset()
#else
  #define WDT_FEED() do {} while(0)
#endif

// ── Molecule helpers ──────────────────────────────────────────────
static size_t mol_u32le(uint8_t *out, uint32_t v) {
    out[0]=(uint8_t)v; out[1]=(uint8_t)(v>>8);
    out[2]=(uint8_t)(v>>16); out[3]=(uint8_t)(v>>24);
    return 4;
}
static size_t mol_bytes_field(uint8_t *out, const uint8_t *data, size_t len) {
    mol_u32le(out, (uint32_t)len);
    if (data && len) memcpy(out+4, data, len);
    return 4 + len;
}
static size_t mol_indexes_vec(uint8_t *out, const uint32_t *idxs, uint8_t n) {
    uint32_t total = 4 + 4 + n*4;
    mol_u32le(out, total); mol_u32le(out+4, n);
    for (int i=0; i<n; i++) mol_u32le(out+8+i*4, idxs[i]);
    return total;
}

// ── Hex utilities ─────────────────────────────────────────────────
static const char CKBFS_HEX[] = "0123456789abcdef";
static void bytes_to_hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i=0; i<n; i++) {
        out[i*2]   = CKBFS_HEX[b[i]>>4];
        out[i*2+1] = CKBFS_HEX[b[i]&0xf];
        if ((i & 0xFF) == 0) {
            WDT_FEED();
            #ifdef ARDUINO
              vTaskDelay(1);  // yield to RTOS — resets interrupt WDT too
            #endif
        }
    }
    out[n*2] = '\0';
}
static uint8_t hex_nibble(char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return 0;
}

// ── CKB secp256k1 lock (mainnet) ──────────────────────────────────
static const char SECP_CODE_HASH[] =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
static const char SECP_HASH_TYPE[] = "type";
static const char SECP_DEP_TX[] =
    "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c";

// ── Raw RPC helper (returns heap-alloc String, caller must check empty) ────────
static String rpc_post(const char *url, const char *body) {
    HTTPClient http;
    http.begin(url);
    http.setTimeout(10000);
    http.addHeader("Content-Type", "application/json");
    int code = http.POST((uint8_t*)body, strlen(body));
    String resp = (code == 200) ? http.getString() : String();
    http.end();
    return resp;
}

// ── Build CKBFS witness bytes ─────────────────────────────────────
size_t ckbfs_build_witness(const uint8_t *content, size_t content_len,
                            uint8_t *out, size_t out_size,
                            uint32_t *checksum_out)
{
    if (CKBFS_HEADER_LEN + content_len > out_size) return 0;
    memcpy(out, CKBFS_MAGIC, CKBFS_MAGIC_LEN);
    out[CKBFS_MAGIC_LEN] = CKBFS_VERSION;
    if (content && content_len) memcpy(out + CKBFS_HEADER_LEN, content, content_len);
    if (checksum_out) *checksum_out = ckbfs_adler32(content, content_len);
    return CKBFS_HEADER_LEN + content_len;
}

// ── Build molecule CKBFSData cell data ────────────────────────────
size_t ckbfs_build_cell_data(const ckbfs_meta_t *meta,
                              uint8_t *out, size_t out_size)
{
    // Build fields into temp buffer first to get sizes
    uint8_t tmp[512]; size_t pos = 0;
    size_t f0 = mol_indexes_vec(tmp+pos, meta->indexes, meta->index_count); pos += f0;
    size_t f1 = mol_u32le(tmp+pos, meta->checksum); pos += f1;
    size_t f2 = mol_bytes_field(tmp+pos,
                    (const uint8_t*)meta->content_type,
                    strlen(meta->content_type)); pos += f2;
    size_t f3 = mol_bytes_field(tmp+pos,
                    (const uint8_t*)meta->filename,
                    strlen(meta->filename)); pos += f3;
    // backlinks — empty Vec<bytes>: total_size=8, count=0
    uint8_t ev[8]; uint32_t ev32=8, ec=0;
    memcpy(ev,&ev32,4); memcpy(ev+4,&ec,4);
    memcpy(tmp+pos, ev, 8); pos += 8;

    uint32_t header_size = 4 + 5*4;  // total_size field + 5 offsets
    uint32_t total_size  = header_size + (uint32_t)pos;
    if (total_size > out_size) return 0;

    size_t wp = 0;
    memcpy(out+wp, &total_size, 4); wp += 4;
    uint32_t offsets[5] = {
        header_size,
        header_size + (uint32_t)f0,
        header_size + (uint32_t)(f0+f1),
        header_size + (uint32_t)(f0+f1+f2),
        header_size + (uint32_t)(f0+f1+f2+f3),
    };
    for (int i=0; i<5; i++) { memcpy(out+wp, &offsets[i], 4); wp += 4; }
    memcpy(out+wp, tmp, pos); wp += pos;
    return wp;
}

// ── Read: fetch raw witness bytes ────────────────────────────────
ckbfs_err_t ckbfs_fetch_witness(const char *node_url,
                                const char *tx_hash,
                                uint32_t    wit_index,
                                uint8_t    *buf,
                                size_t      buf_size,
                                size_t     *out_len)
{
    // Build get_transaction RPC body
    char body[160];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction\","
        "\"params\":[\"%s\"],\"id\":1}", tx_hash);

    String resp = rpc_post(node_url, body);
    if (resp.isEmpty()) return CKBFS_ERR_RPC;

    // Find witnesses array
    int wi = resp.indexOf("\"witnesses\":[");
    if (wi < 0) return CKBFS_ERR_NOT_FOUND;
    const char *p = resp.c_str() + wi + strlen("\"witnesses\":[");

    // Skip to wit_index-th element
    uint32_t idx = 0;
    while (*p) {
        while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\r') p++;
        if (*p == ']') break;
        if (*p != '"') { p++; continue; }
        p++;  // skip opening quote

        if (idx == wit_index) {
            // Decode hex witness: skip "0x" prefix
            if (p[0]=='0' && (p[1]=='x' || p[1]=='X')) p += 2;
            // Skip CKBFS header (6 bytes = 12 hex chars)
            if (strlen(p) < CKBFS_HEADER_LEN*2) return CKBFS_ERR_BAD_MAGIC;
            // Check magic
            char magic_hex[12]; memcpy(magic_hex, p, 10); magic_hex[10]=0;
            // "CKBFS\x00" hex = "434b424653" + "00"
            if (strncmp(p, "434b42465300", 12) != 0) return CKBFS_ERR_BAD_MAGIC;
            p += CKBFS_HEADER_LEN * 2;
            // Decode content bytes
            size_t bytes = 0;
            while (*p && *p != '"' && bytes < buf_size) {
                if (p[1] == '\0' || p[1] == '"') break;
                buf[bytes++] = (hex_nibble(p[0]) << 4) | hex_nibble(p[1]);
                p += 2;
            }
            if (out_len) *out_len = bytes;
            return CKBFS_OK;
        }
        // Skip past this witness string
        while (*p && *p != '"') p++;
        if (*p == '"') p++;
        idx++;
    }
    return CKBFS_ERR_NOT_FOUND;
}

// ── Read: high-level with checksum verify ─────────────────────────
ckbfs_err_t ckbfs_read(const char *node_url,
                       const char *tx_hash,
                       uint32_t    wit_index,
                       uint32_t    expected_checksum,
                       uint8_t    *buf,
                       size_t      buf_size,
                       size_t     *out_len)
{
    size_t len = 0;
    ckbfs_err_t e = ckbfs_fetch_witness(node_url, tx_hash, wit_index,
                                         buf, buf_size, &len);
    if (e != CKBFS_OK) return e;
    if (expected_checksum && !ckbfs_verify(buf, len, expected_checksum))
        return CKBFS_ERR_CHECKSUM;
    if (out_len) *out_len = len;
    return CKBFS_OK;
}

// ── Write: publish a CKBFS file ───────────────────────────────────
ckbfs_err_t ckbfs_publish(const char *node_url,
                           const CKBKey &key,
                           const uint8_t *content,
                           size_t content_len,
                           const char *filename,
                           const char *content_type,
                           uint64_t capacity_ckb,
                           char *tx_hash_out)
{
    if (content_len > CKBFS_MAX_CONTENT) return CKBFS_ERR_TOO_LARGE;

    // ── 1. Build CKBFS witness ────────────────────────────────────
    size_t wit_buf_len = CKBFS_HEADER_LEN + content_len;
    uint8_t *wit_buf = (uint8_t *)malloc(wit_buf_len);
    if (!wit_buf) return CKBFS_ERR_NO_MEM;
    uint32_t checksum = 0;
    size_t wit_len = ckbfs_build_witness(content, content_len,
                                          wit_buf, wit_buf_len, &checksum);
    if (!wit_len) { free(wit_buf); return CKBFS_ERR_NO_MEM; }

    // ── 2. Get lock args from key ─────────────────────────────────
    char lock_args[43] = {};
    if (!key.getLockArgsHex(lock_args, sizeof(lock_args))) {
        free(wit_buf); return CKBFS_ERR_SIGN;
    }

    // ── 3. Collect input cells ────────────────────────────────────
    CKBClient ckb(node_url);
    ckb.setTimeoutMs(8000);  // 8s max per RPC call
    CKBScript lock_script = {};
    strncpy(lock_script.codeHash, SECP_CODE_HASH, sizeof(lock_script.codeHash));
    strncpy(lock_script.hashType, SECP_HASH_TYPE, sizeof(lock_script.hashType));
    strncpy(lock_script.args, lock_args, sizeof(lock_script.args));

    uint64_t cap_shannon = capacity_ckb * 100000000ULL;
    uint64_t fee_shannon = (uint64_t)(wit_len + 1000);
    Serial.printf("[CKBFS] collectInputCells, need %llu shannon\n", cap_shannon + fee_shannon);

    CKBTxInput inputs[CKB_TX_MAX_INPUTS] = {};
    uint8_t input_count = 0;
    uint64_t total_input = 0;
    CKBError cerr = ckb.collectInputCells(lock_script,
                                           cap_shannon + fee_shannon,
                                           inputs, input_count, total_input);
    if (cerr != CKB_OK) { free(wit_buf); return CKBFS_ERR_CAPACITY; }
    if (total_input < cap_shannon + fee_shannon) { free(wit_buf); return CKBFS_ERR_CAPACITY; }
    Serial.printf("[CKBFS] got %u inputs, total %llu shannon\n", input_count, total_input);

    // ── 4. Build CKBFS index cell data ────────────────────────────
    ckbfs_meta_t meta = {};
    strncpy(meta.filename, filename, sizeof(meta.filename)-1);
    strncpy(meta.content_type, content_type, sizeof(meta.content_type)-1);
    meta.checksum     = checksum;
    meta.indexes[0]   = 1;  // witness index 1 = CKBFS content witness
    meta.index_count  = 1;
    meta.has_backlinks = false;
    uint8_t cell_data[256] = {};
    size_t cell_data_len = ckbfs_build_cell_data(&meta, cell_data, sizeof(cell_data));

    // ── 5. Build CKBBuiltTx ───────────────────────────────────────
    CKBBuiltTx tx = {};
    tx.valid = true;

    // Cell dep: secp256k1 dep group
    strncpy(tx.cellDeps[0].txHash, SECP_DEP_TX, sizeof(tx.cellDeps[0].txHash));
    tx.cellDeps[0].index      = 0;
    tx.cellDeps[0].isDepGroup = true;
    tx.cellDepCount = 1;

    // Inputs
    for (uint8_t i = 0; i < input_count; i++) tx.inputs[i] = inputs[i];
    tx.inputCount = input_count;

    // Output 0: change back to sender
    uint64_t change = total_input - cap_shannon - fee_shannon;
    strncpy(tx.outputs[0].lockScript.codeHash, SECP_CODE_HASH,
            sizeof(tx.outputs[0].lockScript.codeHash));
    strncpy(tx.outputs[0].lockScript.hashType, SECP_HASH_TYPE,
            sizeof(tx.outputs[0].lockScript.hashType));
    strncpy(tx.outputs[0].lockScript.args, lock_args,
            sizeof(tx.outputs[0].lockScript.args));
    tx.outputs[0].capacity = change;

    // Output 1: CKBFS index cell (locked to sender, permanent)
    strncpy(tx.outputs[1].lockScript.codeHash, SECP_CODE_HASH,
            sizeof(tx.outputs[1].lockScript.codeHash));
    strncpy(tx.outputs[1].lockScript.hashType, SECP_HASH_TYPE,
            sizeof(tx.outputs[1].lockScript.hashType));
    strncpy(tx.outputs[1].lockScript.args, lock_args,
            sizeof(tx.outputs[1].lockScript.args));
    tx.outputs[1].capacity = cap_shannon;
    tx.outputCount = 2;

    // ── 6. Sign ───────────────────────────────────────────────────
    CKBError serr = CKBClient::signTx(tx, key);
    Serial.printf("[CKBFS] signTx: %d\n", (int)serr);
    if (serr != CKB_OK) { free(wit_buf); return CKBFS_ERR_SIGN; }

    // ── 7. Build witness hex strings ──────────────────────────────
    // WitnessArgs[0]: signed secp256k1 witness
    uint8_t wa[CKB_WITNESS_ARGS_LEN] = {};
    CKBSigner::buildWitnessWithSig(tx.signature, wa);
    char *wa_hex = (char *)malloc(2 + CKB_WITNESS_ARGS_LEN*2 + 1);
    if (!wa_hex) { free(wit_buf); return CKBFS_ERR_NO_MEM; }
    wa_hex[0]='0'; wa_hex[1]='x';
    bytes_to_hex(wa, CKB_WITNESS_ARGS_LEN, wa_hex+2);

    // Witness[1]: CKBFS content witness
    char *ckbfs_hex = (char *)malloc(2 + wit_len*2 + 1);
    if (!ckbfs_hex) { free(wit_buf); free(wa_hex); return CKBFS_ERR_NO_MEM; }
    ckbfs_hex[0]='0'; ckbfs_hex[1]='x';
    bytes_to_hex(wit_buf, wit_len, ckbfs_hex+2);
    free(wit_buf); wit_buf = nullptr;

    // Cell data for index cell
    char *cdata_hex = (char *)malloc(2 + cell_data_len*2 + 1);
    if (!cdata_hex) { free(wa_hex); free(ckbfs_hex); return CKBFS_ERR_NO_MEM; }
    cdata_hex[0]='0'; cdata_hex[1]='x';
    bytes_to_hex(cell_data, cell_data_len, cdata_hex+2);

    // ── 8. Build JSON RPC body ────────────────────────────────────
    // Use heap for large JSON buffers to avoid stack overflow
    char *inputs_json = (char *)malloc(512);
    if (!inputs_json) { free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }
    inputs_json[0]='['; inputs_json[1]='\0';
    for (uint8_t i = 0; i < tx.inputCount; i++) {
        char tmp[160];
        snprintf(tmp, sizeof(tmp),
            "%s{\"previous_output\":{\"tx_hash\":\"%s\",\"index\":\"0x%x\"},\"since\":\"0x0\"}",
            i > 0 ? "," : "", tx.inputs[i].txHash, tx.inputs[i].index);
        strncat(inputs_json, tmp, 512-strlen(inputs_json)-1);
    }
    strncat(inputs_json, "]", 2);

    // outputs JSON: change + CKBFS index cell
    char change_hex[20], cap_hex[20];
    snprintf(change_hex, sizeof(change_hex), "0x%" PRIx64, change);
    snprintf(cap_hex, sizeof(cap_hex), "0x%" PRIx64, cap_shannon);

    char *outputs_json = (char *)malloc(512);
    if (!outputs_json) { free(inputs_json); free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }
    snprintf(outputs_json, 512,
        "[{\"capacity\":\"%s\","
         "\"lock\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
         "\"type\":null},"
         "{\"capacity\":\"%s\","
         "\"lock\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
         "\"type\":null}]",
        change_hex, SECP_CODE_HASH, SECP_HASH_TYPE, lock_args,
        cap_hex, SECP_CODE_HASH, SECP_HASH_TYPE, lock_args);

    char *deps_json = (char *)malloc(220);
    if (!deps_json) { free(outputs_json); free(inputs_json); free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }
    snprintf(deps_json, 220,
        "[{\"out_point\":{\"tx_hash\":\"%s\",\"index\":\"0x0\"},\"dep_type\":\"dep_group\"}]",
        SECP_DEP_TX);

    // Assemble full body (heap: wa_hex + ckbfs_hex can be large)
    size_t body_size = strlen(inputs_json) + strlen(outputs_json) + strlen(deps_json)
                     + 2 + CKB_WITNESS_ARGS_LEN*2   // wa_hex
                     + 2 + wit_len*2                 // ckbfs_hex
                     + 2 + cell_data_len*2           // cdata_hex
                     + 512;
    char *body = (char *)malloc(body_size);
    if (!body) { free(deps_json); free(outputs_json); free(inputs_json); free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }

    snprintf(body, body_size,
        "{\"jsonrpc\":\"2.0\",\"method\":\"send_transaction\","
        "\"params\":[{\"version\":\"0x0\","
        "\"cell_deps\":%s,"
        "\"header_deps\":[],"
        "\"inputs\":%s,"
        "\"outputs\":%s,"
        "\"outputs_data\":[\"0x\",\"%s\"],"
        "\"witnesses\":[\"%s\",\"%s\"]"
        "},\"passthrough\"],\"id\":1}",
        deps_json, inputs_json, outputs_json,
        cdata_hex, wa_hex, ckbfs_hex);

    free(deps_json); free(outputs_json); free(inputs_json);
    free(wa_hex); free(ckbfs_hex); free(cdata_hex);

    // ── 9. Broadcast ──────────────────────────────────────────────
    CKBError berr = CKBClient::broadcastRaw(node_url, body, tx_hash_out);
    Serial.printf("[CKBFS] broadcastRaw: %d\n", (int)berr);
    free(body);
    return (berr == CKB_OK) ? CKBFS_OK : CKBFS_ERR_BROADCAST;
}

// ── Write: publish with pre-specified input cell (no indexer needed) ─
ckbfs_err_t ckbfs_publish_with_input(const char *node_url,
                                      const CKBKey &key,
                                      const uint8_t *content,
                                      size_t content_len,
                                      const char *filename,
                                      const char *content_type,
                                      uint64_t capacity_ckb,
                                      const char *input_tx_hash,
                                      uint32_t input_index,
                                      uint64_t input_capacity_shannon,
                                      char *tx_hash_out)
{
    if (content_len > CKBFS_MAX_CONTENT) return CKBFS_ERR_TOO_LARGE;

    size_t wit_buf_len = CKBFS_HEADER_LEN + content_len;
    uint8_t *wit_buf = (uint8_t *)malloc(wit_buf_len);
    if (!wit_buf) return CKBFS_ERR_NO_MEM;
    uint32_t checksum = 0;
    size_t wit_len = ckbfs_build_witness(content, content_len, wit_buf, wit_buf_len, &checksum);
    if (!wit_len) { free(wit_buf); return CKBFS_ERR_NO_MEM; }

    char lock_args[43] = {};
    if (!key.getLockArgsHex(lock_args, sizeof(lock_args))) {
        free(wit_buf); return CKBFS_ERR_SIGN;
    }

    uint64_t cap_shannon  = capacity_ckb * 100000000ULL;
    uint64_t fee_shannon  = (uint64_t)(wit_len + 1000);
    uint64_t total_input  = input_capacity_shannon;

    Serial.printf("[CKBFS] using pre-specified input: %s[%u] = %llu shannon\n",
                  input_tx_hash, input_index, total_input);

    if (total_input < cap_shannon + fee_shannon) { free(wit_buf); return CKBFS_ERR_CAPACITY; }

    ckbfs_meta_t meta = {};
    strncpy(meta.filename, filename, sizeof(meta.filename)-1);
    strncpy(meta.content_type, content_type, sizeof(meta.content_type)-1);
    meta.checksum     = checksum;
    meta.indexes[0]   = 1;
    meta.index_count  = 1;
    meta.has_backlinks = false;
    uint8_t cell_data[256] = {};
    size_t cell_data_len = ckbfs_build_cell_data(&meta, cell_data, sizeof(cell_data));

    CKBBuiltTx *txp = (CKBBuiltTx*)calloc(1, sizeof(CKBBuiltTx));
    if (!txp) { free(wit_buf); return CKBFS_ERR_NO_MEM; }
    CKBBuiltTx& tx = *txp;
    tx.valid = true;

    strncpy(tx.cellDeps[0].txHash, SECP_DEP_TX, sizeof(tx.cellDeps[0].txHash));
    tx.cellDeps[0].index      = 0;
    tx.cellDeps[0].isDepGroup = true;
    tx.cellDepCount = 1;

    // Single pre-specified input
    strncpy(tx.inputs[0].txHash, input_tx_hash, sizeof(tx.inputs[0].txHash));
    tx.inputs[0].index = input_index;
    tx.inputCount = 1;

    uint64_t change = total_input - cap_shannon - fee_shannon;
    strncpy(tx.outputs[0].lockScript.codeHash, SECP_CODE_HASH, sizeof(tx.outputs[0].lockScript.codeHash));
    strncpy(tx.outputs[0].lockScript.hashType, SECP_HASH_TYPE, sizeof(tx.outputs[0].lockScript.hashType));
    strncpy(tx.outputs[0].lockScript.args, lock_args, sizeof(tx.outputs[0].lockScript.args));
    tx.outputs[0].capacity = change;

    strncpy(tx.outputs[1].lockScript.codeHash, SECP_CODE_HASH, sizeof(tx.outputs[1].lockScript.codeHash));
    strncpy(tx.outputs[1].lockScript.hashType, SECP_HASH_TYPE, sizeof(tx.outputs[1].lockScript.hashType));
    strncpy(tx.outputs[1].lockScript.args, lock_args, sizeof(tx.outputs[1].lockScript.args));
    tx.outputs[1].capacity = cap_shannon;
    tx.outputCount = 2;

    // Compute txHash + signingHash
    // RFC 0017: signing_message = blake2b(tx_hash || len(w0) || w0 || len(w1) || w1)
    // witnesses[0] = WitnessArgs placeholder (secp256k1 lock)
    // witnesses[1] = CKBFS content witness (remaining witness in same group)
    // BOTH must be included in the signing hash — verified working on-chain.
    CKBClient ckb_signer(node_url);
    if (!ckb_signer.prepareForSigning(tx)) {
        free(wit_buf); free(txp); return CKBFS_ERR_SIGN;
    }
    Serial.printf("[CKBFS] txHash: %.16s...\n", tx.txHashHex);

    // Rebuild signing hash including the CKBFS witness (wit_buf)
    {
        // WitnessArgs placeholder (witnesses[0]) — 65 zero bytes in lock field
        uint8_t wa_placeholder[CKB_WITNESS_ARGS_LEN] = {};
        CKBSigner::buildWitnessPlaceholder(wa_placeholder);

        CKB_Blake2b ctx;
        ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx, tx.txHash, 32);
        // witnesses[0]: WitnessArgs placeholder
        uint64_t w0len = CKB_WITNESS_ARGS_LEN;
        uint8_t w0lenbuf[8]; for(int i=0;i<8;i++) w0lenbuf[i]=(uint8_t)(w0len>>(i*8));
        ckb_blake2b_update(&ctx, w0lenbuf, 8);
        ckb_blake2b_update(&ctx, wa_placeholder, CKB_WITNESS_ARGS_LEN);
        // witnesses[1]: CKBFS content witness (remaining witness — must be included per RFC 0017)
        uint64_t w1len = wit_len;
        uint8_t w1lenbuf[8]; for(int i=0;i<8;i++) w1lenbuf[i]=(uint8_t)(w1len>>(i*8));
        ckb_blake2b_update(&ctx, w1lenbuf, 8);
        ckb_blake2b_update(&ctx, wit_buf, wit_len);
        ckb_blake2b_final(&ctx, tx.signingHash);
        Serial.printf("[CKBFS] sigHash: %02x%02x%02x%02x...\n",
                      tx.signingHash[0], tx.signingHash[1],
                      tx.signingHash[2], tx.signingHash[3]);
    }

    CKBError serr = CKBClient::signTx(tx, key);
    Serial.printf("[CKBFS] signTx: %d\n", (int)serr);
    if (serr != CKB_OK) { free(wit_buf); free(txp); return CKBFS_ERR_SIGN; }

    uint8_t wa[CKB_WITNESS_ARGS_LEN] = {};
    CKBSigner::buildWitnessWithSig(tx.signature, wa);
    free(txp); txp = nullptr;  // done with tx struct
    CKBSigner::buildWitnessWithSig(tx.signature, wa);
    char *wa_hex = (char *)malloc(2 + CKB_WITNESS_ARGS_LEN*2 + 1);
    if (!wa_hex) { free(wit_buf); return CKBFS_ERR_NO_MEM; }
    wa_hex[0]='0'; wa_hex[1]='x';
    bytes_to_hex(wa, CKB_WITNESS_ARGS_LEN, wa_hex+2);

    char *ckbfs_hex = (char *)malloc(2 + wit_len*2 + 1);
    if (!ckbfs_hex) { free(wit_buf); free(wa_hex); return CKBFS_ERR_NO_MEM; }
    ckbfs_hex[0]='0'; ckbfs_hex[1]='x';
    bytes_to_hex(wit_buf, wit_len, ckbfs_hex+2);
    free(wit_buf); wit_buf = nullptr;

    char *cdata_hex = (char *)malloc(2 + cell_data_len*2 + 1);
    if (!cdata_hex) { free(wa_hex); free(ckbfs_hex); return CKBFS_ERR_NO_MEM; }
    cdata_hex[0]='0'; cdata_hex[1]='x';
    bytes_to_hex(cell_data, cell_data_len, cdata_hex+2);

    char *inputs_json = (char *)malloc(256);
    if (!inputs_json) { free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }
    snprintf(inputs_json, 256,
        "[{\"previous_output\":{\"tx_hash\":\"%s\",\"index\":\"0x%x\"},\"since\":\"0x0\"}]",
        input_tx_hash, input_index);

    char change_hex[20], cap_hex[20];
    snprintf(change_hex, sizeof(change_hex), "0x%" PRIx64, change);
    snprintf(cap_hex, sizeof(cap_hex), "0x%" PRIx64, cap_shannon);

    char *outputs_json = (char *)malloc(512);
    if (!outputs_json) { free(inputs_json); free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }
    snprintf(outputs_json, 512,
        "[{\"capacity\":\"%s\",\"lock\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},\"type\":null},"
         "{\"capacity\":\"%s\",\"lock\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},\"type\":null}]",
        change_hex, SECP_CODE_HASH, SECP_HASH_TYPE, lock_args,
        cap_hex, SECP_CODE_HASH, SECP_HASH_TYPE, lock_args);

    char *deps_json = (char *)malloc(220);
    if (!deps_json) { free(outputs_json); free(inputs_json); free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }
    snprintf(deps_json, 220,
        "[{\"out_point\":{\"tx_hash\":\"%s\",\"index\":\"0x0\"},\"dep_type\":\"dep_group\"}]",
        SECP_DEP_TX);

    size_t body_size = strlen(inputs_json) + strlen(outputs_json) + strlen(deps_json)
                     + 2 + CKB_WITNESS_ARGS_LEN*2 + 2 + wit_len*2 + 2 + cell_data_len*2 + 512;
    char *body = (char *)malloc(body_size);
    if (!body) { free(deps_json); free(outputs_json); free(inputs_json); free(wa_hex); free(ckbfs_hex); free(cdata_hex); return CKBFS_ERR_NO_MEM; }

    snprintf(body, body_size,
        "{\"jsonrpc\":\"2.0\",\"method\":\"send_transaction\","
        "\"params\":[{\"version\":\"0x0\","
        "\"cell_deps\":%s,\"header_deps\":[],"
        "\"inputs\":%s,\"outputs\":%s,"
        "\"outputs_data\":[\"0x\",\"0x\"],"
        "\"witnesses\":[\"%s\",\"%s\"]"
        "},\"passthrough\"],\"id\":1}",
        deps_json, inputs_json, outputs_json, wa_hex, ckbfs_hex);

    free(deps_json); free(outputs_json); free(inputs_json);
    free(wa_hex); free(ckbfs_hex); free(cdata_hex);

    Serial.printf("[CKBFS] body size: %u\n", (unsigned)strlen(body));
    CKBError berr = CKBClient::broadcastRaw(node_url, body, tx_hash_out);
    Serial.printf("[CKBFS] broadcastRaw: %d\n", (int)berr);
    free(body);
    return (berr == CKB_OK) ? CKBFS_OK : CKBFS_ERR_BROADCAST;
}
