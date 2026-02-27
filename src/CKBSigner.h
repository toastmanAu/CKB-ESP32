/*
 * CKBSigner.h  —  secp256k1 on-device signing for CKB transactions (ESP32)
 *
 * Provides:
 *   CKBKey     — load private key, derive pubkey / lock args / CKB address
 *   CKBBuiltTx — unsigned transaction ready for signing and broadcast
 *   CKBSigner  — compute signing hash, sign transaction
 *
 * ── Signing scheme (standard secp256k1/blake160 lock) ────────────────────────
 *   1. Build tx (inputs, outputs, cell deps)
 *   2. Obtain tx_hash (32 bytes) from node dry-run or compute it
 *   3. signing_hash = blake2b_ckb(tx_hash || witness_len_le32 || witness_placeholder)
 *      where witness_placeholder = WitnessArgs{lock: 0x00*65, input_type: absent, output_type: absent}
 *   4. sig[65] = [recid | r(32) | s(32)]  — secp256k1 ECDSA, RFC6979 deterministic k
 *   5. Broadcast tx with witness = WitnessArgs{lock: sig[65]}
 *
 * ── Dependencies (all vendored, no external install required) ─────────────────
 *   - trezor_crypto/ : Trezor ecdsa + rfc6979 (MIT)
 *   - blake2b/       : BLAKE2 reference impl (CC0)
 *
 * Author:  toastmanAu (Phill)
 * Repo:    https://github.com/toastmanAu/CKB-ESP32
 * License: MIT
 */

#ifndef CKB_SIGNER_H
#define CKB_SIGNER_H

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

// ─── Sizes ────────────────────────────────────────────────────────────────────
#define CKB_PRIVKEY_SIZE     32
#define CKB_PUBKEY_SIZE      33   // compressed (02/03 + 32)
#define CKB_SIG_SIZE         65   // [recid(1) | r(32) | s(32)]
#define CKB_HASH_SIZE        32
#define CKB_LOCK_ARGS_SIZE   20   // blake160(compressed_pubkey)

// WitnessArgs molecule with 65-byte lock field: 85 bytes total
// Layout: header(16) + lock_length(4) + lock_data(65) = 85
#define CKB_WITNESS_ARGS_LEN 85

// ─── CKBBuiltTx — an unsigned transaction ready to sign & broadcast ───────────

#define CKB_TX_MAX_INPUTS   8
#define CKB_TX_MAX_OUTPUTS  8
#define CKB_TX_MAX_CELLDEPS 4

// CKBBuiltTx structs — only defined here if CKB.h hasn't included them already.
// When CKB_WITH_SIGNER is set, CKB.h includes CKBSigner.h *after* defining its
// own versions of these structs — guard prevents redefinition.
#ifndef CKB_ESP32_H

struct CKBTxCellDep {
    char txHash[67];    // "0x" + 64 hex
    uint32_t index;
    uint8_t depType;    // 0=code, 1=dep_group
};

struct CKBTxInput {
    char previousTxHash[67];
    uint32_t previousIndex;
    uint64_t inputCapacity;   // shannon — for fee calculation
};

struct CKBTxOutput {
    uint64_t capacity;        // shannon
    char lockCodeHash[67];
    char lockHashType[8];     // "type" | "data" | "data1"
    char lockArgs[131];       // "0x" + up to 128 hex chars
    bool hasType;
};

struct CKBBuiltTx {
    // Transaction fields
    CKBTxCellDep cellDeps[CKB_TX_MAX_CELLDEPS];
    uint8_t      cellDepCount;
    CKBTxInput   inputs[CKB_TX_MAX_INPUTS];
    uint8_t      inputCount;
    CKBTxOutput  outputs[CKB_TX_MAX_OUTPUTS];
    uint8_t      outputCount;

    // Signing state
    uint8_t  signingHash[CKB_HASH_SIZE];  // set by CKBSigner::computeSigningHash()
    uint8_t  signature[CKB_SIG_SIZE];     // set by CKBSigner::signTx()
    bool     signed_;                     // true after signTx() succeeds

    // Totals
    uint64_t totalInputCapacity;
    uint64_t totalOutputCapacity;
    uint64_t fee() const { return totalInputCapacity - totalOutputCapacity; }

    bool  valid;
    char  error[64];
};

// ─── CKBKey — secp256k1 key pair ─────────────────────────────────────────────

#endif // !CKB_ESP32_H — end of struct definitions guarded against CKB.h

class CKBKey {
public:
    CKBKey() : _valid(false) {}

    /** Load from 32 raw bytes */
    bool loadPrivateKey(const uint8_t privKey[CKB_PRIVKEY_SIZE]);

    /** Load from hex string ("0x..." or bare 64 hex chars) */
    bool loadPrivateKeyHex(const char* hexStr);

    /** Compressed public key (33 bytes: 02/03 + 32) */
    bool getPublicKey(uint8_t pubKeyOut[CKB_PUBKEY_SIZE]) const;

    /** CKB lock args = blake160(compressed_pubkey) — 20 bytes */
    bool getLockArgs(uint8_t lockArgsOut[CKB_LOCK_ARGS_SIZE]) const;

    /** CKB lock args as hex string — writes "0x" + 40 hex chars into buf (≥43 bytes) */
    bool getLockArgsHex(char* buf, size_t bufLen) const;

    /**
     * Full CKB address (ckb1qyq... mainnet or ckt1qyq... testnet)
     * Uses secp256k1/blake160 lock code hash, bech32m encoding.
     * buf must be ≥ 100 bytes.
     */
    bool getAddress(char* buf, size_t bufLen, bool mainnet = true) const;

    bool isValid()          const { return _valid; }
    const uint8_t* raw()    const { return _privKey; }

private:
    uint8_t _privKey[CKB_PRIVKEY_SIZE];
    bool    _valid;
};

// ─── CKBSigner ────────────────────────────────────────────────────────────────

class CKBSigner {
public:
    /**
     * Compute CKB signing hash from a transaction hash.
     *
     *   signing_hash = blake2b_ckb(
     *       tx_hash (32 bytes)
     *    || witness_length (4 bytes, LE, = CKB_WITNESS_ARGS_LEN = 85)
     *    || witness_placeholder (85 bytes)
     *   )
     *
     * @param txHashHex  "0x" + 64 hex chars — tx hash from node
     * @param hashOut    32-byte output
     */
    static bool computeSigningHash(const char* txHashHex,
                                   uint8_t hashOut[CKB_HASH_SIZE]);

    /** Raw bytes overload */
    static bool computeSigningHashRaw(const uint8_t txHash[CKB_HASH_SIZE],
                                      uint8_t hashOut[CKB_HASH_SIZE]);

    /**
     * Sign a 32-byte hash with a CKBKey.
     * Produces 65-byte CKB witness signature: [r(32) | s(32) | recid(1)]
     * Uses RFC6979 deterministic nonce (no TRNG dependency for k).
     */
    static bool sign(const uint8_t hash[CKB_HASH_SIZE],
                     const CKBKey& key,
                     uint8_t sigOut[CKB_SIG_SIZE]);

    /**
     * High-level: sign a CKBBuiltTx.
     * tx.signingHash must be set first (call computeSigningHash*).
     */
    static bool signTx(CKBBuiltTx& tx, const CKBKey& key);

    /**
     * Raw-pointer overload — struct-layout-independent.
     * Use when the caller's CKBBuiltTx may have a different layout
     * (e.g. the extended CKB.h version vs the standalone CKBSigner.h version).
     * signingHashIn: 32-byte input hash
     * sigOut:        65-byte output buffer for [recid|r|s]
     * signedOut:     set to true on success
     */
    static bool signTxRaw(const uint8_t signingHashIn[CKB_HASH_SIZE],
                          const CKBKey& key,
                          uint8_t sigOut[CKB_SIG_SIZE],
                          bool&   signedOut);

    // ── WitnessArgs molecule helpers ──────────────────────────────────────────

    /** Build an 85-byte WitnessArgs molecule with 65 zero bytes in the lock field */
    static void buildWitnessPlaceholder(uint8_t out[CKB_WITNESS_ARGS_LEN]);

    /** Build an 85-byte WitnessArgs molecule with a real signature in the lock field */
    static void buildWitnessWithSig(const uint8_t sig[CKB_SIG_SIZE],
                                    uint8_t out[CKB_WITNESS_ARGS_LEN]);

    // ── Utilities ─────────────────────────────────────────────────────────────

    /** blake2b-256 with CKB personal string "ckb-default-hash" */
    static bool blake2bCKB(const uint8_t* data, size_t len,
                           uint8_t hashOut[CKB_HASH_SIZE]);

    /** blake160 = first 20 bytes of blake2bCKB */
    static void blake160(const uint8_t* data, size_t len,
                         uint8_t out[CKB_LOCK_ARGS_SIZE]);

    /** Hex utilities */
    static void   bytesToHex(const uint8_t* bytes, size_t len, char* out);
    static bool   hexToBytes(const char* hex, uint8_t* out, size_t outLen);
};

#endif // CKB_SIGNER_H
