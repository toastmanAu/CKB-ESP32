// ckb_molecule.h — Minimal Molecule serialisation for CKB transactions
// Implements only what's needed to build a valid CKB RawTransaction.
// Molecule spec: https://github.com/nervosnetwork/molecule
//
// All CKB Molecule types needed for tx building:
//   Byte32, Uint32, Uint64, Script, OutPoint, CellInput, CellOutput,
//   CellDep, RawTransaction, WitnessArgs

#pragma once
#include <stdint.h>
#include <string.h>

// ── Dynamic byte buffer (stack/heap hybrid) ───────────────────────────────────
// We keep a flat byte array + length. Caller must ensure sufficient capacity.
typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
} CKBBuf;

static inline void ckb_buf_init(CKBBuf* b, uint8_t* storage, size_t cap) {
    b->data = storage; b->len = 0; b->cap = cap;
}
static inline bool ckb_buf_write(CKBBuf* b, const void* src, size_t n) {
    if (b->len + n > b->cap) return false;
    memcpy(b->data + b->len, src, n);
    b->len += n; return true;
}
static inline bool ckb_buf_write_u8(CKBBuf* b, uint8_t v) { return ckb_buf_write(b, &v, 1); }
static inline bool ckb_buf_write_u32le(CKBBuf* b, uint32_t v) {
    uint8_t tmp[4] = {(uint8_t)v,(uint8_t)(v>>8),(uint8_t)(v>>16),(uint8_t)(v>>24)};
    return ckb_buf_write(b, tmp, 4);
}
static inline bool ckb_buf_write_u64le(CKBBuf* b, uint64_t v) {
    uint8_t tmp[8];
    for (int i=0;i<8;i++) tmp[i]=(uint8_t)(v>>(i*8));
    return ckb_buf_write(b, tmp, 8);
}
// Write a hex string (e.g. "0x1a2b...") as raw bytes
static inline bool ckb_buf_write_hex(CKBBuf* b, const char* hex, size_t byteLen) {
    if (!hex) return false;
    if (hex[0]=='0' && (hex[1]=='x'||hex[1]=='X')) hex += 2;
    for (size_t i = 0; i < byteLen; i++) {
        char hi = hex[i*2], lo = hex[i*2+1];
        auto nib = [](char c) -> uint8_t {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return 0;
        };
        uint8_t byte = (nib(hi)<<4) | nib(lo);
        if (!ckb_buf_write_u8(b, byte)) return false;
    }
    return true;
}

// ── Molecule: write a 4-byte LE length at a given offset ─────────────────────
static inline void ckb_buf_patch_u32le(CKBBuf* b, size_t offset, uint32_t v) {
    b->data[offset+0] = (uint8_t)v;
    b->data[offset+1] = (uint8_t)(v>>8);
    b->data[offset+2] = (uint8_t)(v>>16);
    b->data[offset+3] = (uint8_t)(v>>24);
}

// ── Molecule primitives ───────────────────────────────────────────────────────

// Script (table): code_hash(32) + hash_type(1) + args(variable)
// Returns bytes written
static inline size_t mol_write_script(CKBBuf* b, const char* codeHash, const char* hashType, const char* args) {
    // args hex bytes
    const char* argsHex = args;
    if (argsHex[0]=='0'&&(argsHex[1]=='x'||argsHex[1]=='X')) argsHex += 2;
    size_t argsLen = strlen(argsHex) / 2;

    size_t totalSize = 4 + 3*4 + 32 + 1 + (4 + argsLen);
    // table header: total_size(4) + offsets(4 each field = 3 fields)
    // fields: code_hash, hash_type, args
    size_t headerSize = 4 + 3*4; // 16
    size_t start = b->len;

    ckb_buf_write_u32le(b, (uint32_t)totalSize);          // total size
    ckb_buf_write_u32le(b, (uint32_t)headerSize);          // offset[0]: code_hash at 16
    ckb_buf_write_u32le(b, (uint32_t)(headerSize + 32));   // offset[1]: hash_type at 48
    ckb_buf_write_u32le(b, (uint32_t)(headerSize + 33));   // offset[2]: args at 49
    ckb_buf_write_hex(b, codeHash, 32);                    // code_hash 32 bytes
    // hash_type byte
    uint8_t ht = 0; // "data"
    if (strcmp(hashType, "type") == 0) ht = 1;
    else if (strcmp(hashType, "data1") == 0) ht = 2;
    else if (strcmp(hashType, "data2") == 0) ht = 4;
    ckb_buf_write_u8(b, ht);
    // args: fixvec (4-byte length + data)
    ckb_buf_write_u32le(b, (uint32_t)argsLen);
    if (args[0]=='0'&&(args[1]=='x'||args[1]=='X'))
        ckb_buf_write_hex(b, args, argsLen);
    else
        ckb_buf_write_hex(b, args, argsLen);
    return b->len - start;
}

// OutPoint (struct): tx_hash(32) + index(4) = 36 bytes
static inline void mol_write_outpoint(CKBBuf* b, const char* txHash, uint32_t index) {
    ckb_buf_write_hex(b, txHash, 32);
    ckb_buf_write_u32le(b, index);
}

// CellInput (struct): since(8) + out_point(36) = 44 bytes
static inline void mol_write_cellinput(CKBBuf* b, const char* txHash, uint32_t index, uint64_t since = 0) {
    ckb_buf_write_u64le(b, since);
    mol_write_outpoint(b, txHash, index);
}

// CellDep (struct): out_point(36) + dep_type(1) = 37 bytes
static inline void mol_write_celldep(CKBBuf* b, const char* txHash, uint32_t index, bool isDepGroup) {
    mol_write_outpoint(b, txHash, index);
    ckb_buf_write_u8(b, isDepGroup ? 1 : 0);
}

// CellOutput (table): capacity(8) + lock(script) + type(option<script>)
static inline size_t mol_write_celloutput(CKBBuf* b, uint64_t capacity,
        const char* lockCodeHash, const char* lockHashType, const char* lockArgs,
        bool hasType = false) {
    size_t start = b->len;

    // measure lock script size
    uint8_t scriptBuf[200];
    CKBBuf sb; ckb_buf_init(&sb, scriptBuf, sizeof(scriptBuf));
    mol_write_script(&sb, lockCodeHash, lockHashType, lockArgs);
    size_t lockSize = sb.len;

    // table: total(4) + offsets(3*4=12) + capacity(8) + lock + type_option
    size_t headerSize = 4 + 3*4; // 16
    size_t totalSize = headerSize + 8 + lockSize + (hasType ? 0 : 0); // no type for simple transfer

    ckb_buf_write_u32le(b, (uint32_t)totalSize);
    ckb_buf_write_u32le(b, (uint32_t)headerSize);           // capacity at offset 16
    ckb_buf_write_u32le(b, (uint32_t)(headerSize + 8));     // lock at 24
    ckb_buf_write_u32le(b, (uint32_t)(headerSize + 8 + lockSize)); // type (empty option)
    ckb_buf_write_u64le(b, capacity);
    ckb_buf_write(b, scriptBuf, lockSize);
    // type: empty Option<Script> = no bytes (absent in table means end of content)
    return b->len - start;
}

// fixvec<byte>: 4-byte count + raw bytes (for outputs_data "0x" entries)
static inline void mol_write_bytes(CKBBuf* b, const uint8_t* data, uint32_t len) {
    ckb_buf_write_u32le(b, len);
    if (len > 0) ckb_buf_write(b, data, len);
}

// WitnessArgs (table): lock(bytes_opt) + input_type(bytes_opt) + output_type(bytes_opt)
// For secp256k1: lock = 65-byte zeroes placeholder (signing), input_type/output_type empty
static inline size_t mol_write_witness_placeholder(CKBBuf* b) {
    size_t start = b->len;
    // 65-byte lock option (Some(zeroes))
    uint8_t zero65[65] = {0};
    // WitnessArgs table: total(4) + offsets(3*4) + lock_opt + input_type_opt + output_type_opt
    // lock_opt = Some: 4(total) + 4(offset) + fixvec(4+65) = present as a fixvec bytes_opt
    // Actually WitnessArgs: each field is Bytes (fixvec<byte>) wrapped in Option
    // Present option = the bytes directly; absent = empty (no content past last offset)
    // lock field: present, 65 zero bytes
    size_t lockFieldSize = 4 + 65; // fixvec: 4 len + 65 data
    size_t headerSize = 4 + 3*4;   // total + 3 offsets
    size_t totalSize = headerSize + lockFieldSize; // input_type and output_type absent

    ckb_buf_write_u32le(b, (uint32_t)totalSize);
    ckb_buf_write_u32le(b, (uint32_t)headerSize);                    // lock at 16
    ckb_buf_write_u32le(b, (uint32_t)(headerSize + lockFieldSize));  // input_type at end
    ckb_buf_write_u32le(b, (uint32_t)(headerSize + lockFieldSize));  // output_type at end (same = empty)
    // lock bytes (fixvec)
    ckb_buf_write_u32le(b, 65);
    ckb_buf_write(b, zero65, 65);
    return b->len - start;
}

// Serialize a complete RawTransaction to buf, returns false on overflow
// Inputs: arrays of tx hashes + indices, scripts for outputs, etc.
// This is called internally by buildTransfer()
