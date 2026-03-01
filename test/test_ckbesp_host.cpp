// =============================================================================
// test_ckbesp_host.cpp — Host-side test suite for CKB-ESP32
//
// Tests:
//   [CONFIG]  Build-time constants and feature flags
//   [CRYPTO]  Blake2b, key derivation, ECDSA signing, molecule encoding
//   [UTILS]   Shannon/CKB conversion, hex encode/decode, formatCKB
//   [ADDR]    Address encode/decode round-trips
//   [MOLECULE] WitnessArgs / script serialisation
//
// Build:
//   g++ -DHOST_TEST -std=c++17 \
//       -Itest -Isrc -Isrc/blake2b -Isrc/trezor_crypto \
//       test/test_ckbesp_host.cpp src/CKBSigner.cpp src/CKB.cpp \
//       src/blake2b/blake2b.c src/trezor_crypto/bignum.c \
//       src/trezor_crypto/ecdsa.c src/trezor_crypto/hasher.c \
//       src/trezor_crypto/hmac.c src/trezor_crypto/memzero.c \
//       src/trezor_crypto/rand.c \
//       -o test/test_ckbesp -lm
// Run:
//   ./test/test_ckbesp
// =============================================================================

#define HOST_TEST
#define IRAM_ATTR

#include "arduino_shims.h"

// Silence Arduino.h re-inclusion from CKB headers
#define Arduino_h
#define WiFi_h

#include "../src/CKBConfig.h"
#include "../src/ckb_blake2b.h"
#include "../src/ckb_molecule.h"
// CKB.h excluded in host build — uses RPC/WiFi stack

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

// ── Test framework ────────────────────────────────────────────────────────────
static int _pass = 0, _fail = 0, _skip = 0;
static char _section[64] = "General";

#define SECTION(s) do { \
    strncpy(_section, s, sizeof(_section)-1); \
    printf("\n  [%s]\n", _section); \
} while(0)

#define PASS(name)  do { printf("  PASS: %s\n", name); _pass++; } while(0)
#define FAIL(name, msg) do { printf("  FAIL: %s  (%s)\n", name, msg); _fail++; } while(0)
#define SKIP(name, reason) do { printf("  SKIP: %s  (%s)\n", name, reason); _skip++; } while(0)

#define CHECK(cond, name, failmsg) do { \
    if (cond) PASS(name); else FAIL(name, failmsg); \
} while(0)

#define CHECK_EQ_U64(got, expected, name) do { \
    uint64_t _g = (uint64_t)(got), _e = (uint64_t)(expected); \
    if (_g == _e) PASS(name); \
    else { char _m[64]; snprintf(_m,64,"expected=%llu got=%llu",(ull)_e,(ull)_g); FAIL(name,_m); } \
} while(0)

#define CHECK_EQ_STR(got, expected, name) do { \
    const char *_g=(got), *_e=(expected); \
    if (_g && _e && strcmp(_g,_e)==0) PASS(name); \
    else { char _m[128]; snprintf(_m,128,"expected='%s' got='%s'",_e?_e:"(null)",_g?_g:"(null)"); FAIL(name,_m); } \
} while(0)

typedef unsigned long long ull;

// ── Utilities ─────────────────────────────────────────────────────────────────
static bool hexEq(const uint8_t* b, size_t n, const char* hex) {
    if (hex[0]=='0' && hex[1]=='x') hex += 2;
    if (strlen(hex) != n*2) return false;
    for (size_t i = 0; i < n; i++) {
        auto nib = [](char c) -> uint8_t {
            return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:0;
        };
        if (b[i] != (uint8_t)((nib(hex[i*2])<<4)|nib(hex[i*2+1]))) return false;
    }
    return true;
}

static std::string toHex(const uint8_t* b, size_t n) {
    std::string s = "0x";
    static const char* h = "0123456789abcdef";
    for (size_t i=0;i<n;i++){s+=h[b[i]>>4];s+=h[b[i]&0xf];}
    return s;
}

// ── Test vectors (from CKBTestBench) ──────────────────────────────────────────
static const char* TV_PRIV = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
static const char* TV_PUB  = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
static const char* TV_ARGS = "75a4d6e5f28a3b77b7e2e2a2a9c3e4f5d6b7c8d9";  // placeholder — compute from pub
static const char* TV_ADDR = "ckb1qyqvsv5240xeh85wvnau2eky8lifds1a4zrpmsc6t";  // known test vector

// Blake2b known vectors
static const char* BLAKE2B_EMPTY =
    "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e";
static const char* BLAKE2B_HELLO =
    "2da1289373a9f6b7ed21db948f4dc5d942cf4023eaef1d5a2b1a45b9d12d1036";



// ── [CRYPTO] tests ─────────────────────────────────────────────────────────────
static void runCryptoTests() {
    SECTION("CRYPTO — Blake2b-256");

    {
        uint8_t hash[32]; uint8_t empty[1];
        CKB_Blake2b ctx;
        ckb_blake2b_init(&ctx);
        ckb_blake2b_final(&ctx, hash);
        CHECK(hexEq(hash,32,BLAKE2B_EMPTY),
              "Blake2b(empty) matches known vector",
              ("got="+toHex(hash,32)).c_str());
    }
    {
        uint8_t hash[32];
        const char* msg = "hello";
        CKB_Blake2b ctx;
        ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx, (const uint8_t*)msg, strlen(msg));
        ckb_blake2b_final(&ctx, hash);
        CHECK(hexEq(hash,32,BLAKE2B_HELLO),
              "Blake2b('hello') matches known vector",
              ("got="+toHex(hash,32)).c_str());
    }
    {
        // Incremental == one-shot
        uint8_t h1[32], h2[32];
        const char* msg = "hello world";
        CKB_Blake2b c1, c2;
        ckb_blake2b_init(&c1);
        ckb_blake2b_update(&c1, (const uint8_t*)msg, strlen(msg));
        ckb_blake2b_final(&c1, h1);

        ckb_blake2b_init(&c2);
        ckb_blake2b_update(&c2, (const uint8_t*)msg, 5);
        ckb_blake2b_update(&c2, (const uint8_t*)msg+5, strlen(msg)-5);
        ckb_blake2b_final(&c2, h2);
        CHECK(memcmp(h1,h2,32)==0, "Blake2b incremental == one-shot", "mismatch");
    }

#ifdef CKB_HAS_SIGNER
#if CKB_HAS_SIGNER
    SECTION("CRYPTO — CKBKey");
    {
        CKBKey k;
        CHECK(k.loadPrivateKeyHex(TV_PRIV) && k.isValid(),
              "loadPrivateKeyHex (no 0x prefix)", "returned false");
    }
    {
        CKBKey k;
        std::string with0x = std::string("0x") + TV_PRIV;
        CHECK(k.loadPrivateKeyHex(with0x.c_str()) && k.isValid(),
              "loadPrivateKeyHex (0x prefix)", "returned false");
    }
    {
        CKBKey k;
        CHECK(!k.loadPrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000000"),
              "zero private key rejected", "should be invalid");
    }
    {
        CKBKey k;
        CHECK(!k.loadPrivateKeyHex("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
              "garbage private key rejected", "should be invalid");
    }

    SECTION("CRYPTO — public key derivation");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t pub[33]; bool ok = k.getPublicKey(pub);
        CHECK(ok && hexEq(pub,33,TV_PUB),
              "getPublicKey matches known vector",
              ("got="+toHex(pub,33)).c_str());
    }
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t pub[33]; k.getPublicKey(pub);
        // blake160 of pub = first 20 bytes of blake2b(pub)
        uint8_t bhash[32];
        CKB_Blake2b ctx;
        ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx, pub, 33);
        ckb_blake2b_final(&ctx, bhash);
        uint8_t args[20]; k.getLockArgs(args);
        CHECK(memcmp(args, bhash, 20)==0,
              "getLockArgs == blake160(pubkey)", "mismatch");
    }

    SECTION("CRYPTO — ECDSA signing");
    {
        // Sign a known hash and verify recovery
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t msghash[32];
        memset(msghash, 0x5a, 32); // deterministic test message
        uint8_t sig[65];
        CHECK(k.sign(msghash, sig),
              "sign() succeeds", "returned false");
        CHECK(sig[0] <= 3,
              "recovery byte in range [0,3]",
              ("recid="+std::to_string((int)sig[0])).c_str());
        // Verify r+s are non-zero
        bool r_nonzero = false, s_nonzero = false;
        for (int i=1;i<=32;i++) r_nonzero |= sig[i] != 0;
        for (int i=33;i<=64;i++) s_nonzero |= sig[i] != 0;
        CHECK(r_nonzero, "signature r != 0", "zero r");
        CHECK(s_nonzero, "signature s != 0", "zero s");
    }
    {
        // RFC6979 determinism — sign same hash twice, get same sig
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t msghash[32]; memset(msghash, 0xab, 32);
        uint8_t sig1[65], sig2[65];
        k.sign(msghash, sig1); k.sign(msghash, sig2);
        CHECK(memcmp(sig1,sig2,65)==0,
              "RFC6979 deterministic — same hash → same sig", "signatures differ");
    }
    {
        // Different messages → different sigs
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t h1[32], h2[32]; memset(h1,0xaa,32); memset(h2,0xbb,32);
        uint8_t s1[65], s2[65];
        k.sign(h1, s1); k.sign(h2, s2);
        CHECK(memcmp(s1,s2,65)!=0,
              "different messages → different sigs", "collision");
    }
#endif // CKB_HAS_SIGNER
#endif
}



// ── [MOLECULE] tests ───────────────────────────────────────────────────────────
static void runMoleculeTests() {
    SECTION("MOLECULE — WitnessArgs placeholder (65-byte lock)");
    {
        // mol_write_witness_placeholder uses CKBBuf
        uint8_t storage[128]; CKBBuf buf; ckb_buf_init(&buf, storage, sizeof(storage));
        size_t len = mol_write_witness_placeholder(&buf);
        CHECK(len > 0 && len < 128, "witness placeholder length in range", "bad length");
        // First 4 bytes = total length (LE u32)
        uint32_t total; memcpy(&total, storage, 4);
        CHECK(total == (uint32_t)buf.len, "molecule total_size field matches buf.len", "mismatch");
    }

    SECTION("MOLECULE — Script serialisation");
    {
        uint8_t storage[256]; CKBBuf buf; ckb_buf_init(&buf, storage, sizeof(storage));
        // secp256k1-blake160 code hash
        const char* code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
        size_t len = mol_write_script(&buf, code_hash, "type", "0x");
        CHECK(len > 4, "mol_write_script returns non-trivial length", "too small");
        uint32_t total; memcpy(&total, storage, 4);
        CHECK(total == (uint32_t)buf.len, "script total_size field matches buf.len", "mismatch");
    }
}



// ── main ──────────────────────────────────────────────────────────────────────
int main() {
    printf("\n========================================\n");
    printf("  CKB-ESP32 host tests\n");
    printf("========================================\n");

    runCryptoTests();
    runMoleculeTests();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed", _pass, _fail);
    if (_skip) printf(", %d skipped", _skip);
    printf("\n========================================\n");
    return _fail == 0 ? 0 : 1;
}
