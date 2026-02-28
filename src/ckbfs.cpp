/*
 * ckbfs.cpp — CKBFS Protocol implementation for CKB-ESP32
 * Spec: code-monad/ckbfs RFC.md (Witnesses-based content storage)
 *
 * Read path:  get_transaction RPC → extract witnesses[index] → strip 6B header
 * Write path: build witness + molecule cell data → sign tx → broadcast
 */

#include "ckbfs.h"
#include "CKB.h"
#include "CKBSigner.h"

// ── Molecule helpers for CKBFSData ────────────────────────────────────────────
// molecule: Bytes = length(4LE) + data
static size_t mol_write_bytes(uint8_t *out, const uint8_t *data, size_t len) {
    uint32_t l = (uint32_t)len;
    memcpy(out, &l, 4);
    if (data && len) memcpy(out + 4, data, len);
    return 4 + len;
}

// molecule Uint32 = 4LE bytes
static size_t mol_write_u32(uint8_t *out, uint32_t v) {
    memcpy(out, &v, 4);
    return 4;
}

// molecule: vector<Uint32> = total_size(4LE) + item_count(4LE) + items
static size_t mol_write_indexes(uint8_t *out, const uint32_t *idxs, uint8_t count) {
    uint32_t total = 4 + 4 + count * 4;
    memcpy(out, &total, 4);
    uint32_t cnt = count;
    memcpy(out + 4, &cnt, 4);
    for (int i = 0; i < count; i++) memcpy(out + 8 + i * 4, &idxs[i], 4);
    return total;
}

// ── ckbfs_build_witness ───────────────────────────────────────────────────────
size_t ckbfs_build_witness(const uint8_t *content, size_t content_len,
                            uint8_t *out, size_t out_size,
                            uint32_t *checksum_out)
{
    if (CKBFS_HEADER_LEN + content_len > out_size) return 0;
    memcpy(out, CKBFS_MAGIC, CKBFS_MAGIC_LEN);
    out[CKBFS_MAGIC_LEN] = CKBFS_VERSION;
    memcpy(out + CKBFS_HEADER_LEN, content, content_len);
    if (checksum_out) *checksum_out = ckbfs_adler32(content, content_len);
    return CKBFS_HEADER_LEN + content_len;
}

// ── ckbfs_build_cell_data ─────────────────────────────────────────────────────
// molecule CKBFSData table:
//   fields: index(Indexes), checksum(Uint32), content_type(Bytes), filename(Bytes), backlinks(BackLinks)
// Table layout: total_size(4) + field_offsets(N*4) + field_data
size_t ckbfs_build_cell_data(const ckbfs_meta_t *meta,
                              uint8_t *out, size_t out_size)
{
    uint8_t tmp[512];
    size_t pos = 0;

    // field 0: indexes
    size_t f0_start = 0;
    size_t f0 = mol_write_indexes(tmp + pos, meta->indexes, meta->index_count);
    pos += f0;

    // field 1: checksum (Uint32)
    size_t f1_start = pos;
    size_t f1 = mol_write_u32(tmp + pos, meta->checksum);
    pos += f1;

    // field 2: content_type (Bytes)
    size_t f2_start = pos;
    size_t f2 = mol_write_bytes(tmp + pos,
                                (const uint8_t *)meta->content_type,
                                strlen(meta->content_type));
    pos += f2;

    // field 3: filename (Bytes)
    size_t f3_start = pos;
    size_t f3 = mol_write_bytes(tmp + pos,
                                (const uint8_t *)meta->filename,
                                strlen(meta->filename));
    pos += f3;

    // field 4: backlinks (BackLinks vector — empty for single-part publish)
    size_t f4_start = pos;
    // empty vector: total_size=8, count=0
    uint32_t empty_vec_total = 8, empty_vec_count = 0;
    memcpy(tmp + pos, &empty_vec_total, 4); pos += 4;
    memcpy(tmp + pos, &empty_vec_count, 4); pos += 4;
    size_t f4 = 8;

    // Now build the molecule table header
    // table: total_size(4) + offsets[5](20) + field_data
    uint32_t header_size = 4 + 5 * 4; // 24 bytes
    uint32_t total_size = header_size + (uint32_t)pos;

    if (total_size > out_size) return 0;

    size_t wp = 0;
    memcpy(out + wp, &total_size, 4); wp += 4;

    // offsets relative to start of table (including header)
    uint32_t o0 = header_size;
    uint32_t o1 = o0 + f0;
    uint32_t o2 = o1 + f1;
    uint32_t o3 = o2 + f2;
    uint32_t o4 = o3 + f3;
    memcpy(out + wp, &o0, 4); wp += 4;
    memcpy(out + wp, &o1, 4); wp += 4;
    memcpy(out + wp, &o2, 4); wp += 4;
    memcpy(out + wp, &o3, 4); wp += 4;
    memcpy(out + wp, &o4, 4); wp += 4;

    memcpy(out + wp, tmp, pos); wp += pos;
    return wp;
}

// ── HTTP helper: extract a JSON string field ──────────────────────────────────
static bool json_extract_str(const char *json, const char *key,
                              char *out, size_t out_len)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(json, search);
    if (!p) return false;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

// ── ckbfs_fetch_witness ───────────────────────────────────────────────────────
ckbfs_err_t ckbfs_fetch_witness(const char *node_url,
                                const char *tx_hash,
                                uint32_t    wit_index,
                                uint8_t    *buf,
                                size_t      buf_size,
                                size_t     *out_len)
{
    // CKBClient does the RPC work
    CKBClient ckb;
    ckb.setNodeUrl(node_url);

    // get_transaction — response has witnesses array as hex strings
    static char rpc_resp[8192];
    char body[256];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction\","
        "\"params\":[\"%s\"],\"id\":1}", tx_hash);

    if (!ckb.rpcCall(body, rpc_resp, sizeof(rpc_resp)))
        return CKBFS_ERR_RPC;

    // Find witnesses array and the Nth element
    const char *wit_arr = strstr(rpc_resp, "\"witnesses\":[");
    if (!wit_arr) return CKBFS_ERR_NOT_FOUND;
    wit_arr += strlen("\"witnesses\":[");

    // Walk to wit_index-th "0x..." entry
    uint32_t idx = 0;
    const char *p = wit_arr;
    while (idx < wit_index) {
        p = strchr(p, '"');
        if (!p) return CKBFS_ERR_NOT_FOUND;
        p++; // skip "
        p = strchr(p, '"');
        if (!p) return CKBFS_ERR_NOT_FOUND;
        p++; idx++;
        // skip comma/space
        while (*p == ',' || *p == ' ') p++;
    }

    // p now points to start of our witness hex string (after opening quote or at "0x")
    if (*p == '"') p++;
    if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) p += 2;

    // Decode hex into a temp buffer
    static uint8_t tmp[CKBFS_HEADER_LEN + 4096];
    size_t tmp_len = 0;
    const char *h = p;
    while (h[0] && h[1] && h[0] != '"' && tmp_len < sizeof(tmp)) {
        char hi = h[0], lo = h[1];
        auto n = [](char c) -> uint8_t {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return 0;
        };
        tmp[tmp_len++] = (n(hi)<<4) | n(lo);
        h += 2;
    }

    if (tmp_len < CKBFS_HEADER_LEN) return CKBFS_ERR_NOT_FOUND;

    // Validate CKBFS magic
    if (memcmp(tmp, CKBFS_MAGIC, CKBFS_MAGIC_LEN) != 0) return CKBFS_ERR_BAD_MAGIC;
    if (tmp[CKBFS_MAGIC_LEN] != CKBFS_VERSION) return CKBFS_ERR_BAD_MAGIC;

    // Strip 6-byte header
    size_t content_len = tmp_len - CKBFS_HEADER_LEN;
    if (content_len > buf_size) return CKBFS_ERR_TOO_LARGE;
    memcpy(buf, tmp + CKBFS_HEADER_LEN, content_len);
    *out_len = content_len;
    return CKBFS_OK;
}

// ── ckbfs_read ────────────────────────────────────────────────────────────────
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
    if (expected_checksum != 0 && !ckbfs_verify(buf, *out_len, expected_checksum))
        return CKBFS_ERR_CHECKSUM;
    return CKBFS_OK;
}

// ── ckbfs_publish ─────────────────────────────────────────────────────────────
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

    // 1. Build witness bytes
    static uint8_t witness_buf[CKBFS_HEADER_LEN + CKBFS_MAX_CONTENT];
    uint32_t checksum = 0;
    size_t wit_len = ckbfs_build_witness(content, content_len,
                                          witness_buf, sizeof(witness_buf),
                                          &checksum);
    if (!wit_len) return CKBFS_ERR_NO_MEM;

    // 2. Build molecule cell data
    ckbfs_meta_t meta = {};
    strncpy(meta.filename, filename, CKBFS_MAX_FILENAME - 1);
    strncpy(meta.content_type, content_type, CKBFS_MAX_CTYPE - 1);
    meta.checksum = checksum;
    meta.indexes[0] = 1; // witness index 1 (index 0 = WitnessArgs signing placeholder)
    meta.index_count = 1;

    static uint8_t cell_data[512];
    size_t cell_data_len = ckbfs_build_cell_data(&meta, cell_data, sizeof(cell_data));
    if (!cell_data_len) return CKBFS_ERR_NO_MEM;

    // 3. Use CKBClient to collect inputs + build + sign + broadcast
    CKBClient ckb;
    ckb.setNodeUrl(node_url);

    // Get sender's lock args for input collection
    char lock_args_hex[43];
    key.getLockArgsHex(lock_args_hex, sizeof(lock_args_hex));

    uint64_t capacity_shannon = capacity_ckb * 100000000ULL;
    uint64_t fee_shannon = 1000000; // 0.01 CKB fee

    // Collect inputs
    CKBBuiltTx tx = {};
    if (ckb.collectInputCells(lock_args_hex,
                               capacity_shannon + fee_shannon,
                               tx) != CKB_OK)
        return CKBFS_ERR_CAPACITY;

    // Output 0: change back to sender
    uint64_t change = tx.totalInputCapacity - capacity_shannon - fee_shannon;
    char sender_addr[110];
    key.getAddress(sender_addr, sizeof(sender_addr), true);

    // Output 1: CKBFS index cell (locked forever under sender's lock)
    // Note: no type script = no on-chain validation, but content is still
    // permanently readable from witnesses. For validated CKBFS, add the
    // type script code_hash once deployed to mainnet.

    tx.outputs[0].capacity = change;
    snprintf(tx.outputs[0].lockCodeHash, sizeof(tx.outputs[0].lockCodeHash),
             "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");
    snprintf(tx.outputs[0].lockHashType, sizeof(tx.outputs[0].lockHashType), "type");
    snprintf(tx.outputs[0].lockArgs, sizeof(tx.outputs[0].lockArgs), "%s", lock_args_hex);
    tx.outputCount = 1;

    // (CKBFS cell output added via broadcastWithWitness — simplified approach:
    //  encode cell_data as hex and include in a custom output)
    // For now: publish as pure witness data, no type script enforcement.
    // The tx broadcasts witness[1] with CKBFS content — permanently on chain.

    // Sign
    uint8_t signing_hash[32];
    CKBSigner::computeSigningHashRaw(
        (uint8_t*)tx.signingHash, signing_hash);
    uint8_t sig[65];
    if (!CKBSigner::sign(signing_hash, key, sig)) return CKBFS_ERR_SIGN;
    memcpy(tx.signature, sig, 65);
    tx.signed_ = true;

    // Build witness with sig + CKBFS content
    // Extra witness (index 1): the raw CKBFS witness bytes (hex encoded for RPC)
    static char wit_hex[CKBFS_HEADER_LEN * 2 + CKBFS_MAX_CONTENT * 2 + 4];
    strcpy(wit_hex, "0x");
    for (size_t i = 0; i < wit_len; i++)
        sprintf(wit_hex + 2 + i*2, "%02x", witness_buf[i]);

    // Broadcast via ckb.broadcastWithWitness() — passes extra witness in witnesses array
    // This is a simplified broadcast — full implementation needs to include
    // both the WitnessArgs[0] + the CKBFS witness[1] in the witnesses field
    char result_hash[67] = {};
    CKBError err = ckb.broadcastWithWitness(tx, wit_hex, result_hash);
    if (err != CKB_OK) return CKBFS_ERR_BROADCAST;

    if (tx_hash_out) strncpy(tx_hash_out, result_hash, 66);
    return CKBFS_OK;
}
