/*
 * ckb_bip39.h — BIP39 mnemonic → seed → CKB private key
 *
 * Implements:
 *   1. BIP39: mnemonic + passphrase → 512-bit seed (PBKDF2-HMAC-SHA512)
 *   2. BIP32: seed → HD node → child key derivation
 *   3. CKB path: m/44'/309'/0'/0/0 (CKB mainnet, account 0, index 0)
 *
 * Zero external dependencies — uses trezor_crypto primitives already
 * present in CKB-ESP32 (sha2.h, hmac.h, secp256k1.h, memzero.h).
 *
 * Usage:
 *   char privkey_hex[65];
 *   char address[96];
 *   int rc = ckb_mnemonic_to_privkey(
 *       "word1 word2 ... word12",
 *       "",                    // passphrase (empty = standard)
 *       0,                     // account index
 *       0,                     // address index
 *       privkey_hex,           // out: 64-char hex privkey
 *       address                // out: CKB bech32 address
 *   );
 *   if (rc == 0) { ... }
 *
 * Security notes:
 *   - Call memzero() on all local seed/key buffers after use
 *   - Never log or print privkey_hex
 *   - Store only in NVS with encryption if possible
 *
 * CKB derivation path: m/44'/309'/0'/account/index
 *   44'  = purpose (BIP44)
 *   309' = CKB coin type (SLIP-0044)
 *   0'   = first hardened account
 */

#pragma once

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "trezor_crypto/sha2.h"
#include "trezor_crypto/hmac.h"
#include "trezor_crypto/secp256k1.h"
#include "trezor_crypto/memzero.h"
#include "ckb_blake2b.h"

/* ── BIP39 wordlist (2048 words, English) ─────────────────────────
 * We include only the word validation + index lookup.
 * The full wordlist is in ckb_bip39_wordlist.h
 */
#include "ckb_bip39_wordlist.h"

/* ── PBKDF2-HMAC-SHA512 ──────────────────────────────────────────── */
static void _pbkdf2_hmac_sha512(
    const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t       iterations,
    uint8_t       *out,   /* 64 bytes */
    size_t         out_len
) {
    /* Single block: block_index=1 (BIP39 seed fits in one SHA512 block) */
    uint8_t u[64];
    uint8_t block[4] = {0, 0, 0, 1};   /* block counter, big-endian */

    /* U1 = HMAC-SHA512(pass, salt || block) */
    HMAC_SHA512_CTX ctx;
    hmac_sha512_Init(&ctx, pass, pass_len);
    hmac_sha512_Update(&ctx, salt, salt_len);
    hmac_sha512_Update(&ctx, block, 4);
    hmac_sha512_Final(&ctx, u);

    memcpy(out, u, out_len < 64 ? out_len : 64);

    /* Subsequent iterations */
    for (uint32_t i = 1; i < iterations; i++) {
        uint8_t prev[64];
        memcpy(prev, u, 64);
        hmac_sha512(pass, pass_len, prev, 64, u);
        for (int j = 0; j < (int)(out_len < 64 ? out_len : 64); j++)
            out[j] ^= u[j];
    }

    memzero(u, sizeof(u));
}

/* ── BIP39: mnemonic → 512-bit seed ──────────────────────────────── */
static void _bip39_mnemonic_to_seed(
    const char *mnemonic,    /* space-separated words */
    const char *passphrase,  /* "" for standard */
    uint8_t    *seed_out     /* 64 bytes */
) {
    /* salt = "mnemonic" + passphrase */
    char salt[512];
    snprintf(salt, sizeof(salt), "mnemonic%s", passphrase ? passphrase : "");

    _pbkdf2_hmac_sha512(
        (const uint8_t *)mnemonic,  strlen(mnemonic),
        (const uint8_t *)salt,      strlen(salt),
        2048,                        /* BIP39 iterations */
        seed_out, 64
    );
}

/* ── BIP32: HD key node ──────────────────────────────────────────── */
typedef struct {
    uint8_t  key[32];     /* private key */
    uint8_t  chain[32];   /* chain code */
} _HDNode;

static void _hd_from_seed(const uint8_t *seed64, _HDNode *node) {
    /* Master key: HMAC-SHA512(key="Bitcoin seed", data=seed) */
    static const char *HMAC_KEY = "Bitcoin seed";
    uint8_t I[64];
    hmac_sha512((const uint8_t *)HMAC_KEY, strlen(HMAC_KEY), seed64, 64, I);
    memcpy(node->key,   I,      32);
    memcpy(node->chain, I + 32, 32);
    memzero(I, sizeof(I));
}

static int _hd_derive_child(_HDNode *parent, uint32_t index, _HDNode *child) {
    /*
     * CKI: Child Key Derivation (BIP32)
     * Hardened if index >= 0x80000000
     */
    uint8_t data[37];
    uint8_t I[64];

    if (index >= 0x80000000) {
        /* Hardened: data = 0x00 || parent_key || index_BE */
        data[0] = 0x00;
        memcpy(data + 1, parent->key, 32);
    } else {
        /* Normal: data = compressed_pubkey || index_BE */
        uint8_t pubkey[33];
        const ecdsa_curve *curve = &secp256k1;
        /* Compute compressed pubkey from privkey */
        bignum256 pk_bn;
        curve_point R;
        bn_read_be(parent->key, &pk_bn);
        scalar_multiply(curve, &pk_bn, &R);
        pubkey[0] = 0x02 | (R.y.val[0] & 1);
        bn_write_be(&R.x, pubkey + 1);
        memcpy(data, pubkey, 33);
    }

    data[33] = (index >> 24) & 0xff;
    data[34] = (index >> 16) & 0xff;
    data[35] = (index >>  8) & 0xff;
    data[36] = (index      ) & 0xff;

    hmac_sha512(parent->chain, 32, data, 37, I);

    /* child_key = (IL + parent_key) mod n */
    bignum256 il, pk, n;
    bn_read_be(I, &il);
    bn_read_be(parent->key, &pk);
    n = secp256k1.order;  /* bignum256 direct copy — bn_read_be needs bytes */

    /* Check IL < n */
    if (bn_is_less(&n, &il) || bn_is_equal(&n, &il)) {
        memzero(I, sizeof(I));
        return -1;  /* invalid key — skip this index */
    }

    bn_addmod(&il, &pk, &n);
    if (bn_is_zero(&il)) {
        memzero(I, sizeof(I));
        return -1;  /* invalid key */
    }

    bn_write_be(&il, child->key);
    memcpy(child->chain, I + 32, 32);

    memzero(I, sizeof(I));
    memzero(data, sizeof(data));
    return 0;
}

/* ── CKB address from compressed pubkey (bech32m) ────────────────── */
/* CKB uses blake2b(pubkey)[0..20] as lock args, secp256k1 lock */
static void _pubkey_from_privkey(const uint8_t *privkey32, uint8_t *pubkey33) {
    const ecdsa_curve *curve = &secp256k1;
    bignum256 pk_bn;
    curve_point R;
    bn_read_be(privkey32, &pk_bn);
    scalar_multiply(curve, &pk_bn, &R);
    pubkey33[0] = 0x02 | (R.y.val[0] & 1);
    bn_write_be(&R.x, pubkey33 + 1);
}

/* Bech32 charset */
static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const int  BECH32_GEN[5]    = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

static uint32_t _bech32_polymod(const uint8_t *values, size_t len) {
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++)
            if ((b >> j) & 1) chk ^= BECH32_GEN[j];
    }
    return chk;
}

static void _bech32m_encode(const char *hrp, const uint8_t *data, size_t data_len,
                             char *out, size_t out_len) {
    /* Convert 8-bit data to 5-bit groups */
    uint8_t enc[128];
    int enc_len = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < data_len; i++) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            enc[enc_len++] = (acc >> bits) & 31;
        }
    }
    if (bits > 0) enc[enc_len++] = (acc << (5 - bits)) & 31;

    /* Build polymod input: hrp_expand + witness_version + enc + 6 zeros */
    size_t hrp_len = strlen(hrp);
    uint8_t poly[256];
    int pi = 0;
    for (size_t i = 0; i < hrp_len; i++) poly[pi++] = hrp[i] >> 5;
    poly[pi++] = 0;
    for (size_t i = 0; i < hrp_len; i++) poly[pi++] = hrp[i] & 31;
    poly[pi++] = 0;  /* witness version */
    for (int i = 0; i < enc_len; i++) poly[pi++] = enc[i];
    for (int i = 0; i < 6; i++) poly[pi++] = 0;

    /* bech32m constant = 0x2bc830a3 */
    uint32_t checksum = _bech32_polymod(poly, pi) ^ 0x2bc830a3;

    /* Build output string */
    size_t pos = 0;
    for (size_t i = 0; i < hrp_len && pos < out_len - 1; i++)
        out[pos++] = hrp[i];
    if (pos < out_len - 1) out[pos++] = '1';
    if (pos < out_len - 1) out[pos++] = BECH32_CHARSET[0]; /* witness version 0 */
    for (int i = 0; i < enc_len && pos < out_len - 1; i++)
        out[pos++] = BECH32_CHARSET[enc[i]];
    for (int i = 5; i >= 0 && pos < out_len - 1; i--)
        out[pos++] = BECH32_CHARSET[(checksum >> (5 * i)) & 31];
    out[pos] = '\0';
}

/* Build full CKB address: lock_type(secp256k1) + lock_args(blake2b[0:20]) */
static void _ckb_address_from_pubkey(const uint8_t *pubkey33, char *addr_out, size_t addr_len) {
    /*
     * CKB full address format (RFC):
     *   payload = 0x00 (format type) + code_hash(secp256k1 lock, 32B) + hash_type(0x01) + args(20B)
     * Total payload: 1 + 32 + 1 + 20 = 54 bytes
     *
     * secp256k1 lock code hash (mainnet, type hash):
     *   0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
     */
    static const uint8_t SECP256K1_CODE_HASH[32] = {
        0x9b,0xd7,0xe0,0x6f,0x3e,0xcf,0x4b,0xe0,
        0xf2,0xfc,0xd2,0x18,0x8b,0x23,0xf1,0xb9,
        0xfc,0xc8,0x8e,0x5d,0x4b,0x65,0xa8,0x63,
        0x7b,0x17,0x72,0x3b,0xbd,0xa3,0xcc,0xe8
    };

    /* lock_args = blake2b(pubkey33)[0:20] */
    uint8_t hash[32];
    CKB_Blake2b bs;
    ckb_blake2b_init(&bs);
    ckb_blake2b_update(&bs, pubkey33, 33);
    ckb_blake2b_final(&bs, hash);

    /* Build address payload */
    uint8_t payload[54];
    payload[0] = 0x00;                          /* full format */
    memcpy(payload + 1,  SECP256K1_CODE_HASH, 32);
    payload[33] = 0x01;                         /* hash_type = type */
    memcpy(payload + 34, hash, 20);             /* lock args (20 bytes) */

    _bech32m_encode("ckb", payload, 54, addr_out, addr_len);
}

/* ── Validate BIP39 mnemonic (word count only for embedded) ──────── */
static bool _bip39_validate(const char *mnemonic) {
    if (!mnemonic || !*mnemonic) return false;
    int count = 1;
    for (const char *p = mnemonic; *p; p++)
        if (*p == ' ') count++;
    return (count == 12 || count == 15 || count == 18 || count == 21 || count == 24);
}

/* ─────────────────────────────────────────────────────────────────────
 * PUBLIC API
 * ───────────────────────────────────────────────────────────────────── */

/*
 * ckb_mnemonic_to_privkey()
 *
 * Derives CKB private key + address from BIP39 mnemonic.
 * Path: m/44'/309'/0'/0/index
 *
 * Returns 0 on success, -1 on error.
 * On success fills privkey_hex (64+1 chars) and address (96+1 chars).
 *
 * IMPORTANT: zero privkey_hex after storing to NVS.
 */
#define CKB_ADDRESS_BUFSIZE 104  /* safe buffer for full CKB bech32m address */

static int ckb_mnemonic_to_privkey(
    const char *mnemonic,
    const char *passphrase,   /* "" for standard BIP39 */
    uint32_t    account,      /* 0 for first account */
    uint32_t    index,        /* 0 for first address */
    char       *privkey_hex,  /* out: 65 bytes (64 + null) */
    char       *address       /* out: 97 bytes */
) {
    if (!_bip39_validate(mnemonic)) return -1;

    /* Step 1: mnemonic → 512-bit seed */
    uint8_t seed[64];
    _bip39_mnemonic_to_seed(mnemonic, passphrase, seed);

    /* Step 2: seed → master HD node */
    _HDNode node, child;
    _hd_from_seed(seed, &node);
    memzero(seed, sizeof(seed));

    /* Step 3: derive m/44'/309'/0'/account/index */
    /* 44' */ if (_hd_derive_child(&node, 0x8000002C, &child)) return -1; node = child;
    /* 309'*/ if (_hd_derive_child(&node, 0x80000135, &child)) return -1; node = child;
    /* 0'  */ if (_hd_derive_child(&node, 0x80000000, &child)) return -1; node = child;
    /* acct*/ if (_hd_derive_child(&node, account,            &child)) return -1; node = child;
    /* idx */ if (_hd_derive_child(&node, index,              &child)) return -1; node = child;

    /* Step 4: format private key as hex */
    for (int i = 0; i < 32; i++)
        snprintf(privkey_hex + i * 2, 3, "%02x", child.key[i]);
    privkey_hex[64] = '\0';

    /* Step 5: derive address (optional — caller may pass NULL) */
    uint8_t pubkey[33];
    _pubkey_from_privkey(child.key, pubkey);
    if (address) _ckb_address_from_pubkey(pubkey, address, CKB_ADDRESS_BUFSIZE);

    /* Zero sensitive intermediates */
    memzero(&node,  sizeof(node));
    memzero(&child, sizeof(child));
    memzero(pubkey, sizeof(pubkey));

    return 0;
}

/*
 * ckb_privkey_to_address()
 *
 * Derives CKB address from raw hex private key.
 * Useful for displaying address when key is already stored.
 */
static int ckb_privkey_to_address(const char *privkey_hex, char *address) {
    if (!privkey_hex || strlen(privkey_hex) != 64) return -1;

    uint8_t privkey[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        if (sscanf(privkey_hex + i * 2, "%02x", &b) != 1) return -1;
        privkey[i] = (uint8_t)b;
    }

    /* Reject zero key — invalid for secp256k1 */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (privkey[i]) { all_zero = false; break; }
    if (all_zero) { memzero(privkey, sizeof(privkey)); return -1; }

    uint8_t pubkey[33];
    _pubkey_from_privkey(privkey, pubkey);
    if (address) _ckb_address_from_pubkey(pubkey, address, CKB_ADDRESS_BUFSIZE);

    memzero(privkey, sizeof(privkey));
    memzero(pubkey, sizeof(pubkey));
    return 0;
}
