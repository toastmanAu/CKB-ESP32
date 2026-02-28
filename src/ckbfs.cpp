#include <HTTPClient.h>
/*
 * ckbfs.cpp — CKBFS Protocol implementation for CKB-ESP32
 * Spec: code-monad/ckbfs RFC.md (Witnesses-based content storage)
 *
 * Key design: content goes in witnesses, index metadata in cell data.
 * Transaction witnesses layout:
 *   [0] WitnessArgs with 65-byte signing placeholder → replaced with sig after sign
 *   [1] "CKBFS\x00" + content bytes
 */

#include "ckbfs.h"
#include "CKB.h"
#include "CKBSigner.h"

// ── Molecule helpers ──────────────────────────────────────────────
static size_t mol_u32le(uint8_t *out, uint32_t v) {
    out[0]=v; out[1]=v>>8; out[2]=v>>16; out[3]=v>>24; return 4;
}
static size_t mol_bytes(uint8_t *out, const uint8_t *data, size_t len) {
    mol_u32le(out, (uint32_t)len);
    if (data && len) memcpy(out+4, data, len);
    return 4 + len;
}
static size_t mol_indexes(uint8_t *out, const uint32_t *idxs, uint8_t n) {
    uint32_t total = 4 + 4 + n*4;
    mol_u32le(out, total); mol_u32le(out+4, n);
    for (int i=0;i<n;i++) mol_u32le(out+8+i*4, idxs[i]);
    return total;
}

// ── Hex utilities ─────────────────────────────────────────────────
static void bytes_to_hex(const uint8_t *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i=0;i<n;i++) { out[i*2]=h[b[i]>>4]; out[i*2+1]=h[b[i]&0xf]; }
    out[n*2]='\0';
}
static uint8_t hex_nibble(char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return 0;
}

// ── CKB secp256k1 lock (mainnet) ──────────────────────────────────
static const char SECP256K1_CODE_HASH[] =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
static const char SECP256K1_HASH_TYPE[] = "type";

// ── Bech32m (same as CKBSigner, duplicated here to avoid C++ linkage issues) ─
// (reuses CKBSigner::blake160 and getLockArgsHex from CKBKey)

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
    uint8_t tmp[512]; size_t pos = 0;

    // field 0: indexes (Vec<Uint32>)
    size_t f0 = mol_indexes(tmp+pos, meta->indexes, meta->index_count); pos += f0;
    // field 1: checksum (Uint32)
    size_t f1 = mol_u32le(tmp+pos, meta->checksum); pos += f1;
    // field 2: content_type (Bytes)
    size_t f2 = mol_bytes(tmp+pos,(const uint8_t*)meta->content_type,strlen(meta->content_type)); pos += f2;
    // field 3: filename (Bytes)
    size_t f3 = mol_bytes(tmp+pos,(const uint8_t*)meta->filename,strlen(meta->filename)); pos += f3;
    // field 4: backlinks — empty Vec
    uint32_t ev=8, ec=0;
    memcpy(tmp+pos,&ev,4); memcpy(tmp+pos+4,&ec,4); pos += 8;

    uint32_t header_size = 4 + 5*4;   // total_size + 5 field offsets
    uint32_t total_size  = header_size + (uint32_t)pos;
    if (total_size > out_size) return 0;

    size_t wp = 0;
    memcpy(out+wp, &total_size, 4); wp += 4;
    // Field offsets (relative to start of table)
    uint32_t offsets[5] = {
        header_size,
        header_size + (uint32_t)f0,
        header_size + (uint32_t)(f0+f1),
        header_size + (uint32_t)(f0+f1+f2),
        header_size + (uint32_t)(f0+f1+f2+f3),
    };
    for (int i=0;i<5;i++) { memcpy(out+wp, &offsets[i], 4); wp += 4; }
    memcpy(out+wp, tmp, pos); wp += pos;
    return wp;
}

// ── Read ──────────────────────────────────────────────────────────
ckbfs_err_t ckbfs_fetch_witness(const char *node_url,
                                const char *tx_hash,
                                uint32_t    wit_index,
                                uint8_t    *buf,
                                size_t      buf_size,
                                size_t     *out_len)
{
    // Make a direct get_transaction RPC call — CKBTransaction struct
    // doesn't include witnesses, so we parse the raw JSON response.
    static char s_body[160];
    static char s_raw[CKBFS_HEADER_LEN * 2 + 200 * 1024 + 512]; // large: full tx JSON
    snprintf(s_body, sizeof(s_body),
        "{"jsonrpc":"2.0","method":"get_transaction","
        ""params":[\"%s\"],"id":1}", tx_hash);

    // broadcastRaw doesn't fit here — use a GET-style helper.
    // We need a raw HTTP POST and response. Use HTTPClient directly.
    // CKBClient exposes broadcastRaw (POST) but for read we need similar.
    // Workaround: broadcastRaw accepts any method body, call get_transaction same way.
    // Use the same static helper via a local CKBClient instance.
    CKBClient ckb;
    ckb.setNodeUrl(node_url);

    // Call get_transaction via raw RPC (CKBClient::broadcastRaw works for any method)
    snprintf(s_body, sizeof(s_body),
        "{"jsonrpc":"2.0","method":"get_transaction","
        ""params":["%s"],"id":1}", tx_hash);

    // We need a raw RPC POST — use HTTPClient directly since CKBClient
    // doesn't expose a generic raw-response call publicly.
    // For now: parse witnesses from the raw response after a local HTTP call.
    // This is included via HTTPClient.h (pulled in by CKB.h -> esp_http_client).

    // Use a stripped-down HTTP POST to get full JSON response
    HTTPClient http;
    http.begin(node_url);
    http.setTimeout(8000);
    http.addHeader("Content-Type", "application/json");
    char body[160];
    snprintf(body, sizeof(body),
        "{"jsonrpc":"2.0","method":"get_transaction","
        ""params":["%s"],"id":1}", tx_hash);
    int code = http.POST(body);
    if (code != 200) { http.end(); return CKBFS_ERR_RPC; }
    String resp = http.getString();
    http.end();

    const char *p = strstr(resp.c_str(), ""witnesses":[");
    if (!p) return CKBFS_ERR_NOT_FOUND;
    p += strlen(""witnesses":[");

    // Skip past '['
    while (*p && *p != '[') p++;
    if (*p == '[') p++;

    uint32_t idx = 0;
    while (*p) {
        // Skip whitespace/comma
        while (*p == ' ' || *p == ',' || *p == '\n') p++;
        if (*p == ']') break;
        if (*p != '"') { p++; continue; }
        p++;  // skip opening quote

        if (idx == wit_index) {
            // This is our witness hex string
            if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) p += 2;
            // Decode hex
            size_t tlen = 0;
            static uint8_t tmp[CKBFS_HEADER_LEN + 200 * 1024];
            while (p[0] && p[1] && p[0] != '"' && tlen < sizeof(tmp)) {
                tmp[tlen++] = (hex_nibble(p[0])<<4) | hex_nibble(p[1]);
                p += 2;
            }
            if (tlen < CKBFS_HEADER_LEN) return CKBFS_ERR_NOT_FOUND;
            if (memcmp(tmp, CKBFS_MAGIC, CKBFS_MAGIC_LEN) != 0) return CKBFS_ERR_BAD_MAGIC;
            if (tmp[CKBFS_MAGIC_LEN] != CKBFS_VERSION) return CKBFS_ERR_BAD_MAGIC;
            size_t clen = tlen - CKBFS_HEADER_LEN;
            if (clen > buf_size) return CKBFS_ERR_TOO_LARGE;
            memcpy(buf, tmp + CKBFS_HEADER_LEN, clen);
            *out_len = clen;
            return CKBFS_OK;
        }
        // Skip this witness string
        while (*p && *p != '"') p++;
        if (*p == '"') p++;
        idx++;
    }
    return CKBFS_ERR_NOT_FOUND;
}

ckbfs_err_t ckbfs_read(const char *node_url,
                       const char *tx_hash,
                       uint32_t    wit_index,
                       uint32_t    expected_checksum,
                       uint8_t    *buf,
                       size_t      buf_size,
                       size_t     *out_len)
{
    ckbfs_err_t e = ckbfs_fetch_witness(node_url, tx_hash, wit_index,
                                        buf, buf_size, out_len);
    if (e != CKBFS_OK) return e;
    if (expected_checksum && !ckbfs_verify(buf, *out_len, expected_checksum))
        return CKBFS_ERR_CHECKSUM;
    return CKBFS_OK;
}

// ── Publish ───────────────────────────────────────────────────────
// Broadcasts a tx with TWO witnesses:
//   witnesses[0] = WitnessArgs (signing placeholder, replaced with sig)
//   witnesses[1] = CKBFS content bytes
// Uses a custom RPC call since broadcastWithWitness() only supports one witness.

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

    // 1. Build CKBFS witness bytes
    static uint8_t s_wit_buf[CKBFS_HEADER_LEN + CKBFS_MAX_CONTENT];
    uint32_t checksum = 0;
    size_t wit_len = ckbfs_build_witness(content, content_len,
                                          s_wit_buf, sizeof(s_wit_buf), &checksum);
    if (!wit_len) return CKBFS_ERR_NO_MEM;

    // 2. Get lock args from key
    char lock_args[43];
    if (!key.getLockArgsHex(lock_args, sizeof(lock_args))) return CKBFS_ERR_NO_MEM;

    // 3. Collect input cells
    CKBClient ckb;
    ckb.setNodeUrl(node_url);

    CKBScript lock_script;
    strncpy(lock_script.codeHash, SECP256K1_CODE_HASH, sizeof(lock_script.codeHash));
    strncpy(lock_script.hashType, SECP256K1_HASH_TYPE, sizeof(lock_script.hashType));
    strncpy(lock_script.args, lock_args, sizeof(lock_script.args));

    uint64_t capacity_shannon = capacity_ckb * 100000000ULL;
    uint64_t fee_shannon = (uint64_t)(wit_len + 1000);  // rough fee estimate

    CKBTxInput inputs[CKB_TX_MAX_INPUTS];
    uint8_t    input_count = 0;
    uint64_t   total_input = 0;

    CKBError cerr = ckb.collectInputCells(lock_script,
                                           capacity_shannon + fee_shannon,
                                           inputs, input_count, total_input);
    if (cerr != CKB_OK) return CKBFS_ERR_CAPACITY;

    // 4. Build outputs
    // Output 0: change back to sender
    uint64_t change = total_input - capacity_shannon - fee_shannon;
    if (total_input < capacity_shannon + fee_shannon) return CKBFS_ERR_CAPACITY;

    // 5. Compute signing hash (standard WitnessArgs approach)
    // signing_hash = blake2b_ckb(tx_hash_placeholder + witness[0] length + witness[0] placeholder)
    // We need the tx hash first, which requires building the raw tx molecule.
    // Use CKBSigner::computeSigningHash after getting tx_hash from the node dry-run.
    //
    // Simplified approach: use buildTransfer skeleton + sign + custom broadcast
    // Build a minimal CKBBuiltTx manually
    CKBBuiltTx tx = {};
    tx.valid = true;

    // Cell deps: secp256k1 dep group (mainnet)
    strncpy(tx.cellDeps[0].txHash,
            "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
            sizeof(tx.cellDeps[0].txHash));
    tx.cellDeps[0].index = 0;
    tx.cellDeps[0].isDepGroup = true;
    tx.cellDepCount = 1;

    // Inputs
    for (uint8_t i = 0; i < input_count; i++) tx.inputs[i] = inputs[i];
    tx.inputCount = input_count;

    // Output: change only (CKBFS cell is implicit in the witness — no type script version)
    strncpy(tx.outputs[0].lockScript.codeHash, SECP256K1_CODE_HASH,
            sizeof(tx.outputs[0].lockScript.codeHash));
    strncpy(tx.outputs[0].lockScript.hashType, SECP256K1_HASH_TYPE,
            sizeof(tx.outputs[0].lockScript.hashType));
    strncpy(tx.outputs[0].lockScript.args, lock_args,
            sizeof(tx.outputs[0].lockScript.args));
    tx.outputs[0].capacity = change;
    tx.outputCount = 1;
    tx.totalInputCapacity  = total_input;
    tx.totalOutputCapacity = change;

    // 6. Sign — CKBSigner computes tx hash internally and returns signing hash
    if (!CKBSigner::signTx(tx, key)) return CKBFS_ERR_SIGN;

    // 7. Build CKBFS witness hex string ("0x" + hex of s_wit_buf)
    static char s_ckbfs_wit_hex[2 + CKBFS_HEADER_LEN*2 + CKBFS_MAX_CONTENT*2 + 2];
    s_ckbfs_wit_hex[0] = '0'; s_ckbfs_wit_hex[1] = 'x';
    bytes_to_hex(s_wit_buf, wit_len, s_ckbfs_wit_hex + 2);

    // 8. Build WitnessArgs[0] hex (the signed witness)
    uint8_t wa[CKB_WITNESS_ARGS_LEN];
    CKBSigner::buildWitnessWithSig(tx.signature, wa);
    static char s_wa_hex[2 + CKB_WITNESS_ARGS_LEN*2 + 2];
    s_wa_hex[0] = '0'; s_wa_hex[1] = 'x';
    bytes_to_hex(wa, CKB_WITNESS_ARGS_LEN, s_wa_hex + 2);

    // 9. Custom broadcast with two witnesses
    // Reuse CKBClient internals via a manual RPC call built from the tx
    // Build inputs/outputs/deps JSON strings then call send_transaction
    char inputs_json[600] = "[";
    for (uint8_t i = 0; i < tx.inputCount; i++) {
        char tmp[160];
        snprintf(tmp, sizeof(tmp),
            "%s{\"previous_output\":{\"tx_hash\":\"%s\",\"index\":\"0x%x\"},\"since\":\"0x0\"}",
            i > 0 ? "," : "", tx.inputs[i].txHash, tx.inputs[i].index);
        strncat(inputs_json, tmp, sizeof(inputs_json) - strlen(inputs_json) - 1);
    }
    strncat(inputs_json, "]", 2);

    // Capacity as hex string
    char cap_hex[20];
    snprintf(cap_hex, sizeof(cap_hex), "0x%" PRIx64, change);

    char outputs_json[512];
    snprintf(outputs_json, sizeof(outputs_json),
        "[{\"capacity\":\"%s\","
        "\"lock\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"type\":null}]",
        cap_hex, SECP256K1_CODE_HASH, SECP256K1_HASH_TYPE, lock_args);

    // Allocate RPC body (large: contains full witness hex)
    size_t body_size = 512 + 2 + wit_len * 2 + 2 + CKB_WITNESS_ARGS_LEN * 2 + 256;
    char *body = (char *)malloc(body_size);
    if (!body) return CKBFS_ERR_NO_MEM;

    // deps JSON
    char deps_json[200];
    snprintf(deps_json, sizeof(deps_json),
        "[{\"out_point\":{\"tx_hash\":\"%s\",\"index\":\"0x0\"},\"dep_type\":\"dep_group\"}]",
        tx.cellDeps[0].txHash);

    snprintf(body, body_size,
        "{\"jsonrpc\":\"2.0\",\"method\":\"send_transaction\","
        "\"params\":[{\"version\":\"0x0\","
        "\"cell_deps\":%s,"
        "\"header_deps\":[],"
        "\"inputs\":%s,"
        "\"outputs\":%s,"
        "\"outputs_data\":[\"0x\"],"
        "\"witnesses\":[\"%s\",\"%s\"]"
        "},\"passthrough\"],\"id\":1}",
        deps_json, inputs_json, outputs_json,
        s_wa_hex, s_ckbfs_wit_hex);


    // Send via CKBClient::broadcastRaw (handles tx hash extraction)
    static char s_resp[256];
    CKBError berr = CKBClient::broadcastRaw(node_url, body, tx_hash_out);
    free(body);
    return (berr == CKB_OK) ? CKBFS_OK : CKBFS_ERR_BROADCAST;
}
