/*
 * CKBSigner.cpp  —  secp256k1 on-device signing for CKB (ESP32)
 *
 * Uses:
 *   - Trezor ECDSA library (trezor_crypto/) for secp256k1 sign + RFC6979
 *   - BLAKE2 reference (blake2b/) for CKB's personalised hash
 *
 * The Trezor ecdsa_sign_digest() call returns both the DER-format (r,s) AND
 * the recovery byte (pby) in one shot — no separate recid computation needed.
 */

#include "CKBSigner.h"
#include <string.h>
#include <stdio.h>

// ── Trezor crypto (C library, compile as C) ───────────────────────────────────
extern "C" {
  #include "trezor_crypto/ecdsa.h"
  #include "trezor_crypto/secp256k1.h"
  #include "trezor_crypto/hasher.h"
}

// ── BLAKE2 reference ──────────────────────────────────────────────────────────
extern "C" {
  #include "blake2b/blake2.h"
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

void CKBSigner::bytesToHex(const uint8_t* bytes, size_t len, char* out) {
    static const char HEX_CHARS[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]     = HEX_CHARS[bytes[i] >> 4];
        out[i*2 + 1] = HEX_CHARS[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

bool CKBSigner::hexToBytes(const char* hex, uint8_t* out, size_t outLen) {
    if (!hex) return false;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    if (strlen(hex) != outLen * 2) return false;
    for (size_t i = 0; i < outLen; i++) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i*2]);
        int lo = nibble(hex[i*2+1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// BLAKE2b with CKB personal string
// ─────────────────────────────────────────────────────────────────────────────

bool CKBSigner::blake2bCKB(const uint8_t* data, size_t len,
                             uint8_t hashOut[CKB_HASH_SIZE]) {
    // "ckb-default-hash" is exactly 16 bytes = BLAKE2B_PERSONALBYTES
    static const uint8_t PERSONAL[BLAKE2B_PERSONALBYTES] = {
        'c','k','b','-','d','e','f','a','u','l','t','-','h','a','s','h'
    };

    blake2b_param P;
    memset(&P, 0, sizeof(P));
    P.digest_length = 32;
    P.fanout        = 1;
    P.depth         = 1;
    memcpy(P.personal, PERSONAL, BLAKE2B_PERSONALBYTES);

    blake2b_state S;
    if (blake2b_init_param(&S, &P) < 0) return false;
    if (blake2b_update(&S, data, len) < 0) return false;
    if (blake2b_final(&S, hashOut, 32) < 0) return false;
    return true;
}

void CKBSigner::blake160(const uint8_t* data, size_t len,
                          uint8_t out[CKB_LOCK_ARGS_SIZE]) {
    uint8_t hash[32];
    blake2bCKB(data, len, hash);
    memcpy(out, hash, 20);
}

// ─────────────────────────────────────────────────────────────────────────────
// WitnessArgs Molecule encoding
// ─────────────────────────────────────────────────────────────────────────────
/*
 * CKB Molecule layout for WitnessArgs{lock=65 bytes, input_type=absent, output_type=absent}:
 *
 *   Molecule Table (3 fields, each Option<Bytes>):
 *     Header = total_size(4) + offset[0](4) + offset[1](4) + offset[2](4) = 16 bytes
 *     lock field   = length(4) + data(65) = 69 bytes  (Option<Bytes> present)
 *     input_type   = absent → 0 bytes, offset points to end
 *     output_type  = absent → 0 bytes, offset points to end
 *     Total = 16 + 69 = 85 bytes
 *
 *   Bytes [hex]:
 *     55 00 00 00   total_size = 85
 *     10 00 00 00   offset[0]  = 16  (lock field starts right after header)
 *     55 00 00 00   offset[1]  = 85  (input_type absent, points to end)
 *     55 00 00 00   offset[2]  = 85  (output_type absent, points to end)
 *     41 00 00 00   lock byte length = 65
 *     [65 bytes]    lock data (zeroed placeholder or real signature)
 */

static inline void _writeLE32(uint8_t* buf, uint32_t v) {
    buf[0] = (uint8_t)(v);
    buf[1] = (uint8_t)(v >> 8);
    buf[2] = (uint8_t)(v >> 16);
    buf[3] = (uint8_t)(v >> 24);
}

static void _buildWitnessArgs(const uint8_t lockData[65],
                               uint8_t out[CKB_WITNESS_ARGS_LEN]) {
    memset(out, 0, CKB_WITNESS_ARGS_LEN);
    _writeLE32(out + 0,  85);   // total size
    _writeLE32(out + 4,  16);   // offset[0]: lock field starts at byte 16
    _writeLE32(out + 8,  85);   // offset[1]: input_type absent (at end)
    _writeLE32(out + 12, 85);   // offset[2]: output_type absent (at end)
    _writeLE32(out + 16, 65);   // lock field byte length
    memcpy(out + 20, lockData, 65);
}

void CKBSigner::buildWitnessPlaceholder(uint8_t out[CKB_WITNESS_ARGS_LEN]) {
    uint8_t zeros[65] = {0};
    _buildWitnessArgs(zeros, out);
}

void CKBSigner::buildWitnessWithSig(const uint8_t sig[CKB_SIG_SIZE],
                                     uint8_t out[CKB_WITNESS_ARGS_LEN]) {
    _buildWitnessArgs(sig, out);
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing hash
// ─────────────────────────────────────────────────────────────────────────────

bool CKBSigner::computeSigningHashRaw(const uint8_t txHash[CKB_HASH_SIZE],
                                       uint8_t hashOut[CKB_HASH_SIZE]) {
    /*
     * signing_hash = blake2b_ckb(
     *     tx_hash (32 bytes)
     *  || witness_byte_length (4 bytes, LE uint32)   = 85
     *  || witness_placeholder (85 bytes)
     * )
     * Total input: 32 + 4 + 85 = 121 bytes
     */
    uint8_t witness[CKB_WITNESS_ARGS_LEN];
    buildWitnessPlaceholder(witness);

    uint8_t msg[32 + 4 + CKB_WITNESS_ARGS_LEN];
    memcpy(msg, txHash, 32);
    _writeLE32(msg + 32, (uint32_t)CKB_WITNESS_ARGS_LEN);
    memcpy(msg + 36, witness, CKB_WITNESS_ARGS_LEN);

    return blake2bCKB(msg, sizeof(msg), hashOut);
}

bool CKBSigner::computeSigningHash(const char* txHashHex,
                                    uint8_t hashOut[CKB_HASH_SIZE]) {
    uint8_t txHash[32];
    if (!hexToBytes(txHashHex, txHash, 32)) return false;
    return computeSigningHashRaw(txHash, hashOut);
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign
// ─────────────────────────────────────────────────────────────────────────────

bool CKBSigner::sign(const uint8_t hash[CKB_HASH_SIZE],
                      const CKBKey& key,
                      uint8_t sigOut[CKB_SIG_SIZE]) {
    if (!key.isValid()) return false;

    // Trezor ecdsa_sign_digest:
    //   curve      — secp256k1
    //   priv_key   — 32-byte private key
    //   digest     — 32-byte message hash
    //   sig        — 64-byte output: [r(32) | s(32)]
    //   pby        — 1-byte output: recovery byte (0 or 1, occasionally 2 or 3)
    //   is_canonical — NULL (accept all valid signatures)
    //
    // RFC6979 deterministic k is used automatically (USE_RFC6979=1 in options.h).
    uint8_t rawSig[64];
    uint8_t recId = 0;

    int ret = ecdsa_sign_digest(
        &secp256k1,      // curve
        key.raw(),       // private key (32 bytes)
        hash,            // digest (32 bytes)
        rawSig,          // output: r(32) + s(32)
        &recId,          // output: recovery byte
        NULL             // is_canonical: NULL = accept all
    );

    if (ret != 0) return false;

    // CKB witness signature format: [r(32) | s(32) | recid(1)]
    memcpy(sigOut, rawSig, 64);
    sigOut[64] = recId & 0x03;  // mask to 0-3 (usually 0 or 1)

    return true;
}

bool CKBSigner::signTxRaw(const uint8_t signingHashIn[CKB_HASH_SIZE],
                           const CKBKey& key,
                           uint8_t sigOut[CKB_SIG_SIZE],
                           bool& signedOut) {
    signedOut = false;
    if (!sign(signingHashIn, key, sigOut)) return false;
    signedOut = true;
    return true;
}

bool CKBSigner::signTx(CKBBuiltTx& tx, const CKBKey& key) {
    return signTxRaw(tx.signingHash, key, tx.signature, tx.signed_);
}

// ─────────────────────────────────────────────────────────────────────────────
// CKBKey
// ─────────────────────────────────────────────────────────────────────────────

bool CKBKey::loadPrivateKey(const uint8_t privKey[CKB_PRIVKEY_SIZE]) {
    memcpy(_privKey, privKey, 32);
    // Reject all-zero key explicitly (invalid secp256k1 private key)
    bool allZero = true;
    for (int i = 0; i < 32; i++) if (_privKey[i] != 0) { allZero = false; break; }
    if (allZero) { _valid = false; return false; }
    // Validate by computing public key — checks key is on-curve and < group order
    uint8_t pub[33];
    ecdsa_get_public_key33(&secp256k1, _privKey, pub); _valid = (pub[0] == 0x02 || pub[0] == 0x03);
    return _valid;
}

bool CKBKey::loadPrivateKeyHex(const char* hexStr) {
    uint8_t bytes[32];
    if (!CKBSigner::hexToBytes(hexStr, bytes, 32)) {
        _valid = false;
        return false;
    }
    return loadPrivateKey(bytes);
}

bool CKBKey::getPublicKey(uint8_t pubKeyOut[CKB_PUBKEY_SIZE]) const {
    if (!_valid) return false;
    ecdsa_get_public_key33(&secp256k1, _privKey, pubKeyOut); return (pubKeyOut[0] == 0x02 || pubKeyOut[0] == 0x03);
}

bool CKBKey::getLockArgs(uint8_t lockArgsOut[CKB_LOCK_ARGS_SIZE]) const {
    uint8_t compPub[33];
    if (!getPublicKey(compPub)) return false;
    CKBSigner::blake160(compPub, 33, lockArgsOut);
    return true;
}

bool CKBKey::getLockArgsHex(char* buf, size_t bufLen) const {
    if (bufLen < 43) return false;
    uint8_t args[20];
    if (!getLockArgs(args)) return false;
    buf[0] = '0'; buf[1] = 'x';
    CKBSigner::bytesToHex(args, 20, buf + 2);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Address generation (bech32m, secp256k1/blake160 lock)
// ─────────────────────────────────────────────────────────────────────────────
/*
 * CKB full address format (post-2021):
 *   payload = [0x00][code_hash(32)][hash_type(1)][args(20)]  = 54 bytes
 *   address = bech32m(hrp, payload)
 *   hrp = "ckb" (mainnet) or "ckt" (testnet)
 *
 * secp256k1/blake160 lock:
 *   code_hash = 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
 *   hash_type  = 0x01 (type)
 *   args       = blake160(compressed_pubkey)  [20 bytes]
 */

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const uint32_t BECH32M_CONST = 0x2bc830a3;

static uint32_t _bech32Polymod(const uint8_t* v, size_t len) {
    uint32_t c = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t c0 = (uint8_t)(c >> 25);
        c = ((c & 0x1FFFFFF) << 5) ^ v[i];
        if (c0 & 0x01) c ^= 0x3b6a57b2;
        if (c0 & 0x02) c ^= 0x26508e6d;
        if (c0 & 0x04) c ^= 0x1ea119fa;
        if (c0 & 0x08) c ^= 0x3d4233dd;
        if (c0 & 0x10) c ^= 0x2a1462b3;
    }
    return c;
}

// Convert from fromBits-wide data to toBits-wide data (base conversion).
static bool _convertBits(const uint8_t* in, size_t inLen,
                          int fromBits, int toBits, bool pad,
                          uint8_t* out, size_t* outLen) {
    int acc = 0, bits = 0;
    size_t olen = 0;
    int maxv = (1 << toBits) - 1;
    for (size_t i = 0; i < inLen; i++) {
        if (in[i] >> fromBits) return false;
        acc = (acc << fromBits) | in[i];
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            out[olen++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) out[olen++] = (uint8_t)((acc << (toBits - bits)) & maxv);
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
        return false;
    }
    *outLen = olen;
    return true;
}

bool CKBKey::getAddress(char* buf, size_t bufLen, bool mainnet) const {
    if (!_valid || bufLen < 100) return false;

    uint8_t lockArgs[20];
    if (!getLockArgs(lockArgs)) return false;

    // secp256k1/blake160 code hash
    static const uint8_t CODE_HASH[32] = {
        0x9b,0xd7,0xe0,0x6f, 0x3e,0xcf,0x4b,0xe0,
        0xf2,0xfc,0xd2,0x18, 0x8b,0x23,0xf1,0xb9,
        0xfc,0xc8,0x8e,0x5d, 0x4b,0x65,0xa8,0x63,
        0x7b,0x17,0x72,0x3b, 0xbd,0xa3,0xcc,0xe8
    };

    // payload = [0x00][code_hash:32][hash_type:0x01][args:20] = 54 bytes
    uint8_t payload[54];
    payload[0] = 0x00;
    memcpy(payload + 1, CODE_HASH, 32);
    payload[33] = 0x01;
    memcpy(payload + 34, lockArgs, 20);

    const char* hrp = mainnet ? "ckb" : "ckt";
    size_t hrpLen   = strlen(hrp);

    // Convert 8-bit payload to 5-bit groups
    uint8_t data5[100];
    size_t  data5Len = 0;
    if (!_convertBits(payload, 54, 8, 5, true, data5, &data5Len)) return false;

    // Build checksum input: hrp high bits + 0 + hrp low bits + data5 + 6 zeros
    size_t enc_len = hrpLen + 1 + hrpLen + data5Len + 6;
    if (enc_len > 200) return false;
    uint8_t enc[200];
    size_t pos = 0;
    for (size_t i = 0; i < hrpLen; i++) enc[pos++] = (uint8_t)(hrp[i] >> 5);
    enc[pos++] = 0;
    for (size_t i = 0; i < hrpLen; i++) enc[pos++] = (uint8_t)(hrp[i] & 0x1F);
    memcpy(enc + pos, data5, data5Len); pos += data5Len;
    memset(enc + pos, 0, 6); pos += 6;

    uint32_t chk = _bech32Polymod(enc, pos) ^ BECH32M_CONST;

    // Build output: hrp + "1" + data5 chars + checksum chars
    size_t outPos = 0;
    if (outPos + hrpLen + 1 + data5Len + 6 + 1 >= bufLen) return false;
    memcpy(buf + outPos, hrp, hrpLen); outPos += hrpLen;
    buf[outPos++] = '1';
    for (size_t i = 0; i < data5Len; i++) {
        buf[outPos++] = BECH32_CHARSET[data5[i]];
    }
    for (int i = 0; i < 6; i++) {
        buf[outPos++] = BECH32_CHARSET[(chk >> (5 * (5 - i))) & 0x1F];
    }
    buf[outPos] = '\0';
    return true;
}
