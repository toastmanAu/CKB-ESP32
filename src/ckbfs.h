/*
 * ckbfs.h — CKBFS Protocol for CKB-ESP32
 * =========================================
 * Implements CKBFS v1 (code-monad/ckbfs RFC.md):
 * Store and retrieve arbitrary data via CKB transaction witnesses.
 *
 * KEY FACTS about CKBFS:
 *   - Content lives in WITNESSES, not cell data
 *   - Cell data = molecule-encoded metadata (filename, content_type, checksum, backlinks)
 *   - Witness format: "CKBFS" (5B) + 0x00 (version) + content bytes
 *   - Checksum: Adler-32 of content bytes only (not the 6-byte header)
 *   - Permanent: CKBFS cells can never be destroyed, only transferred
 *   - Capacity locked forever — budget ~61 CKB minimum for metadata cell
 *
 * EMBEDDED USE CASES (fits in single transaction, <500KB):
 *   - Device config / calibration data
 *   - Firmware manifests (hash + version + URL)
 *   - NFC-readable CKB records
 *   - Public device identity (pubkey + metadata)
 *
 * READING (no wallet needed):
 *   ckbfs_fetch(nodeUrl, tx_hash, witness_index, buf, &len)
 *     → GET transaction, extract witnesses[index][6..], done
 *
 * WRITING (requires CKBKey + live CKB node + enough CKB):
 *   ckbfs_publish(nodeUrl, key, content, len, filename, content_type, &out_tx_hash)
 *     → Builds tx with witness + CKBFS cell output, signs, broadcasts
 *
 * CKBFS type script on mainnet:
 *   code_hash: 0x... (deploy when available — currently testnet only)
 *   For embedded use, lock-only (no type script) is sufficient for
 *   simple data storage where on-chain validation isn't required.
 */

#pragma once
#ifdef ARDUINO
  #include <Arduino.h>
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ── Sizes / limits ────────────────────────────────────────────────────────────
#define CKBFS_MAGIC           "CKBFS"
#define CKBFS_MAGIC_LEN       5
#define CKBFS_VERSION         0x00
#define CKBFS_HEADER_LEN      6          // magic(5) + version(1)
#define CKBFS_MAX_CONTENT     (480*1024) // ~480KB, well under 500KB block limit
#define CKBFS_MAX_FILENAME    128
#define CKBFS_MAX_CTYPE       64
#define CKBFS_MIN_CAPACITY    6100000000ULL // ~61 CKB in shannon (rough minimum)

// ── Adler-32 ─────────────────────────────────────────────────────────────────
static inline uint32_t ckbfs_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a)       % 65521;
    }
    return (b << 16) | a;
}

// Continue/recover Adler-32 from a saved state (for multi-part append)
static inline uint32_t ckbfs_adler32_continue(uint32_t prev,
                                               const uint8_t *data, size_t len) {
    uint32_t a = prev & 0xFFFF, b = prev >> 16;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a)       % 65521;
    }
    return (b << 16) | a;
}

// ── CKBFS metadata (decoded from molecule cell data) ─────────────────────────
typedef struct {
    char     filename[CKBFS_MAX_FILENAME];
    char     content_type[CKBFS_MAX_CTYPE];
    uint32_t checksum;         // Adler-32 of content bytes
    uint32_t indexes[8];       // witness indexes in originating tx (max 8 parts)
    uint8_t  index_count;
    bool     has_backlinks;
    char     prev_tx_hash[67]; // "0x" + 64 hex — last backlink tx
    uint32_t prev_indexes[8];
    uint8_t  prev_index_count;
    uint32_t prev_checksum;
} ckbfs_meta_t;

// ── Result codes ─────────────────────────────────────────────────────────────
typedef enum {
    CKBFS_OK               =  0,
    CKBFS_ERR_NO_MEM       = -1,
    CKBFS_ERR_RPC          = -2,
    CKBFS_ERR_CHECKSUM     = -3,
    CKBFS_ERR_BAD_MAGIC    = -4,
    CKBFS_ERR_NOT_FOUND    = -5,
    CKBFS_ERR_TOO_LARGE    = -6,
    CKBFS_ERR_SIGN         = -7,
    CKBFS_ERR_BROADCAST    = -8,
    CKBFS_ERR_CAPACITY     = -9,
} ckbfs_err_t;

// ── Read API ──────────────────────────────────────────────────────────────────

/**
 * Fetch raw content from a CKBFS witness.
 * Strips the 6-byte CKBFS header ("CKBFS" + 0x00).
 * Does NOT verify checksum against cell metadata.
 *
 * @param node_url   CKB RPC endpoint, e.g. "http://192.168.68.87:8114"
 * @param tx_hash    "0x" + 64 hex chars
 * @param wit_index  witness index (from ckbfs_meta_t.indexes[])
 * @param buf        output buffer
 * @param buf_size   size of buf
 * @param out_len    bytes written (excludes null terminator)
 * @return CKBFS_OK or error code
 */
ckbfs_err_t ckbfs_fetch_witness(const char *node_url,
                                const char *tx_hash,
                                uint32_t    wit_index,
                                uint8_t    *buf,
                                size_t      buf_size,
                                size_t     *out_len);

/**
 * Verify Adler-32 checksum of fetched content.
 * Call after ckbfs_fetch_witness() to validate integrity.
 */
static inline bool ckbfs_verify(const uint8_t *content, size_t len,
                                uint32_t expected_checksum) {
    return ckbfs_adler32(content, len) == expected_checksum;
}

/**
 * High-level: fetch + verify in one call.
 * Requires knowing the expected checksum (from cell metadata or out-of-band).
 */
ckbfs_err_t ckbfs_read(const char *node_url,
                       const char *tx_hash,
                       uint32_t    wit_index,
                       uint32_t    expected_checksum,  // pass 0 to skip verify
                       uint8_t    *buf,
                       size_t      buf_size,
                       size_t     *out_len);

// ── Write API ─────────────────────────────────────────────────────────────────

/**
 * Publish a new CKBFS file (single transaction, up to ~480KB).
 * Requires: a funded CKBKey and a live CKB full node.
 *
 * Builds a transaction:
 *   Witness[0]: WitnessArgs placeholder (for signing)
 *   Witness[1]: "CKBFS" + 0x00 + content_bytes
 *   Output[0]:  change cell (capacity back to sender)
 *   Output[1]:  CKBFS index cell (molecule CKBFSData, locked forever)
 *
 * @param node_url      CKB RPC endpoint
 * @param key           funded CKBKey (needs enough CKB for capacity + fee)
 * @param content       raw bytes to store
 * @param content_len   length of content
 * @param filename      null-terminated filename string
 * @param content_type  MIME type, e.g. "text/plain" or "application/json"
 * @param capacity_ckb  CKB to lock in CKBFS cell (minimum ~61, more = more data space)
 * @param tx_hash_out   output: 67-char "0x..." tx hash on success
 * @return CKBFS_OK or error code
 */
ckbfs_err_t ckbfs_publish(const char *node_url,
                           const CKBKey &key,
                           const uint8_t *content,
                           size_t content_len,
                           const char *filename,
                           const char *content_type,
                           uint64_t capacity_ckb,
                           char *tx_hash_out /* 67 bytes */);

/**
 * Build just the witness bytes for a CKBFS publish.
 * Useful for manual tx building or testing without a live node.
 *
 * @param content      raw content bytes
 * @param content_len  length
 * @param out          output buffer (content_len + 6 bytes needed)
 * @param out_size     size of out
 * @param checksum_out Adler-32 checksum of content (for cell metadata)
 * @return bytes written, or 0 on error
 */
size_t ckbfs_build_witness(const uint8_t *content, size_t content_len,
                            uint8_t *out, size_t out_size,
                            uint32_t *checksum_out);

/**
 * Build molecule-encoded CKBFSData for the index cell.
 * @param meta      filled ckbfs_meta_t (filename, content_type, checksum, indexes)
 * @param out       output buffer (~256 bytes sufficient for single-part)
 * @param out_size  size of out
 * @return bytes written, or 0 on error
 */
size_t ckbfs_build_cell_data(const ckbfs_meta_t *meta,
                              uint8_t *out, size_t out_size);

// ── Convenience: store a null-terminated string ───────────────────────────────
static inline ckbfs_err_t ckbfs_publish_string(
    const char *node_url, const CKBKey &key,
    const char *str, const char *filename,
    uint64_t capacity_ckb, char *tx_hash_out)
{
    return ckbfs_publish(node_url, key,
                         (const uint8_t *)str, strlen(str),
                         filename, "text/plain",
                         capacity_ckb, tx_hash_out);
}

// ── Convenience: read into a String (Arduino only) ───────────────────────────
#ifdef ARDUINO
static inline ckbfs_err_t ckbfs_read_string(
    const char *node_url, const char *tx_hash,
    uint32_t wit_index, uint32_t checksum,
    String &out)
{
    static uint8_t _buf[4096];
    size_t len = 0;
    ckbfs_err_t e = ckbfs_read(node_url, tx_hash, wit_index, checksum,
                                _buf, sizeof(_buf), &len);
    if (e == CKBFS_OK) {
        _buf[len] = '\0';
        out = String((char *)_buf);
    }
    return e;
}
#endif


// ── Storage cost estimation ───────────────────────────────────────────────────

typedef struct {
    uint64_t capacity_ckb;      /* CKB locked permanently in index cell */
    uint64_t capacity_shannon;  /* same in shannon (1 CKB = 1e8 shannon) */
    uint64_t fee_shannon;       /* estimated tx fee for witness size */
    uint64_t total_shannon;     /* capacity + fee (what you need in wallet) */
    bool     use_type_script;   /* whether CKBFS type script adds overhead */
    size_t   cell_bytes;        /* total cell size in bytes */
    size_t   witness_bytes;     /* witness size (content + 6B header) */
    size_t   tx_count;          /* number of transactions needed */
} ckbfs_cost_t;

/**
 * Estimate the CKB capacity and fee required to store data via CKBFS.
 *
 * Capacity breakdown (all in bytes = CKB):
 *   Base cell:    8 (capacity) + 32 (lock code_hash) + 1 (hash_type) + 20 (lock args) = 61
 *   Type script:  32 + 1 + 32 = 65  (only if use_type_script = true)
 *   Cell data:    24 (molecule header) + 12 (indexes) + 4 (checksum)
 *               + 4 + len(content_type) + 4 + len(filename) + 8 (empty backlinks)
 *
 * Fee:  1000 shannon per KB of witness data (CKB default min fee rate)
 *       = 1 shannon per byte
 *
 * IMPORTANT: capacity is locked FOREVER. You cannot recover it.
 * Witness bytes do NOT add to capacity — only cell structure does.
 *
 * @param content_len    size of data you want to store (bytes)
 * @param filename       filename string (affects cell data size)
 * @param content_type   MIME type string (affects cell data size)
 * @param use_type_script  true = CKBFS type enforced on-chain (+65 CKB)
 *                         false = lock-only (cheaper, no on-chain validation)
 * @param out            filled with cost breakdown
 */
static inline void ckbfs_estimate_cost(size_t content_len,
                                        const char *filename,
                                        const char *content_type,
                                        bool use_type_script,
                                        ckbfs_cost_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));

    // How many txs needed (max ~480KB witness per tx)
    size_t wit_per_tx = 480 * 1024 - CKBFS_HEADER_LEN;
    out->tx_count = content_len == 0 ? 1 :
                    (content_len + wit_per_tx - 1) / wit_per_tx;
    out->witness_bytes = content_len + CKBFS_HEADER_LEN;

    // Cell data size (molecule CKBFSData)
    size_t fn_len  = filename     ? strlen(filename)     : 0;
    size_t ct_len  = content_type ? strlen(content_type) : 0;
    size_t cell_data = 24          // molecule table header (total_size + 5 offsets)
                     + 12          // indexes Vec<Uint32> — header(8) + one entry(4)
                     + 4           // checksum Uint32
                     + (4 + ct_len) // content_type Bytes
                     + (4 + fn_len) // filename Bytes
                     + 8;           // backlinks empty Vec

    // Cell structure (bytes = CKB, 1:1)
    size_t cell_struct = 8          // capacity field
                       + 32 + 1 + 20  // lock: code_hash + hash_type + args
                       + cell_data;

    if (use_type_script) cell_struct += 32 + 1 + 32; // type: code_hash + hash_type + args(TypeID)

    out->use_type_script = use_type_script;
    out->cell_bytes      = cell_struct;

    // Each tx in a multi-tx file needs its own index cell
    uint64_t total_cell_bytes = (uint64_t)cell_struct * out->tx_count;
    out->capacity_ckb     = total_cell_bytes;  // 1 byte = 1 CKB
    out->capacity_shannon = total_cell_bytes * 100000000ULL;

    // Fee: 1 shannon per byte of witness (1000 shannon/KB min fee rate)
    // Plus ~500 bytes for the rest of the tx structure
    out->fee_shannon = ((uint64_t)out->witness_bytes + 500) * 1;

    out->total_shannon = out->capacity_shannon + out->fee_shannon;
}

/**
 * Pretty-print a ckbfs_cost_t to Serial (Arduino) or stdout.
 * Shows capacity, fee, total, and current USD estimate if ckb_price_usd > 0.
 */
static inline void ckbfs_print_cost(const ckbfs_cost_t *c, double ckb_price_usd)
{
#ifdef ARDUINO
    Serial.printf("CKBFS Storage Cost:\n");
    Serial.printf("  Cell size:    %u bytes\n", (unsigned)c->cell_bytes);
    Serial.printf("  Witness size: %u bytes\n", (unsigned)c->witness_bytes);
    Serial.printf("  Transactions: %u\n", (unsigned)c->tx_count);
    Serial.printf("  Capacity:     %llu CKB (LOCKED FOREVER)\n", (unsigned long long)c->capacity_ckb);
    Serial.printf("  Tx fee:       %llu shannon (~%.6f CKB)\n",
                  (unsigned long long)c->fee_shannon,
                  c->fee_shannon / 1e8);
    Serial.printf("  Total needed: %.4f CKB\n",
                  c->total_shannon / 1e8);
    if (ckb_price_usd > 0) {
        Serial.printf("  USD cost:     $%.4f (at $%.4f/CKB)\n",
                      (c->total_shannon / 1e8) * ckb_price_usd, ckb_price_usd);
        Serial.printf("  Locked USD:   $%.4f permanent\n",
                      c->capacity_ckb * ckb_price_usd);
    }
    Serial.printf("  Type script:  %s\n", c->use_type_script ? "yes (+65 CKB)" : "no (lock-only)");
#else
    printf("CKBFS Storage Cost:\n");
    printf("  Cell size:    %zu bytes\n", c->cell_bytes);
    printf("  Witness size: %zu bytes\n", c->witness_bytes);
    printf("  Transactions: %zu\n", c->tx_count);
    printf("  Capacity:     %llu CKB (LOCKED FOREVER)\n", (unsigned long long)c->capacity_ckb);
    printf("  Tx fee:       %llu shannon (~%.6f CKB)\n",
           (unsigned long long)c->fee_shannon, c->fee_shannon / 1e8);
    printf("  Total needed: %.4f CKB\n", c->total_shannon / 1e8);
    if (ckb_price_usd > 0)
        printf("  USD cost:     $%.4f (capacity $%.4f locked forever)\n",
               (c->total_shannon / 1e8) * ckb_price_usd,
               c->capacity_ckb * ckb_price_usd);
    printf("  Type script:  %s\n", c->use_type_script ? "yes (+65 CKB)" : "no (lock-only)");
#endif
}
