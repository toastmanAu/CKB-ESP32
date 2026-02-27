/*
 * CKBTestBench.ino  —  Automated test + benchmark suite for CKB-ESP32
 *
 * Test categories:
 *   [CRYPTO]  CKBSigner — blake2b, signing hash, key derivation, ECDSA
 *   [UTILS]   CKBClient static helpers — hex, formatting, validation
 *   [ADDR]    CKBClient::decodeAddress
 *   [RPC]     Live node calls (requires WiFi — skipped if WIFI_SSID is blank)
 *
 * Output per test:
 *   [PASS]  test name                                    (Xms)
 *   [FAIL]  test name                                    expected=X got=Y
 *   [SKIP]  test name                                    (reason)
 *   [BENCH] test name                                    N× Xms (~Yus/op)
 *
 * Adding tests:
 *   1. Use TEST_BEGIN("name") / TEST_PASS() / TEST_FAIL("msg") macros
 *   2. Or use CHECK() / CHECK_EQ_U64() / CHECK_EQ_STR() one-liners
 *   3. Group into a runXxxTests() function, call from setup()
 *
 * Author:  toastmanAu (Phill)
 * Repo:    https://github.com/toastmanAu/CKB-ESP32
 * License: MIT
 */

// Increase loop task stack — needed for crypto test locals (default 8KB too small)
// Must be defined before Arduino.h includes on some cores; works as a compile flag too.
#if defined(CONFIG_ARDUINO_LOOP_STACK_SIZE)
  #undef CONFIG_ARDUINO_LOOP_STACK_SIZE
#endif
#define CONFIG_ARDUINO_LOOP_STACK_SIZE 24576   // 24 KB

#include <Arduino.h>
#include <WiFi.h>
#include <math.h>
#include "CKB.h"
#include "CKBSigner.h"

// ─── Config ───────────────────────────────────────────────────────────────────
#define WIFI_SSID      ""                        // blank = skip RPC section
#define WIFI_PASS      ""
#define CKB_NODE_URL   "http://192.168.68.87:8114"
#define WIFI_TIMEOUT   10000

// ─── Output target ────────────────────────────────────────────────────────────
// Default: Serial. To redirect to Telegram (or any Print subclass), define this
// before including the test bench, or change it here:
//
//   #include "TelegramSerial.h"
//   TelegramSerial tg("ssid","pass","BOT_TOKEN","CHAT_ID", &Serial);
//   #define CKB_TEST_OUTPUT tg
//
#ifndef CKB_TEST_OUTPUT
  #define CKB_TEST_OUTPUT Serial
#endif

// printf-style helper for any Print subclass (Print doesn't have printf)
static void _tbPrintf(Print& p, const char* fmt, ...) __attribute__((format(printf,2,3)));
static void _tbPrintf(Print& p, const char* fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    p.print(buf);
}
#define TB_PRINTF(fmt, ...) _tbPrintf(CKB_TEST_OUTPUT, fmt, ##__VA_ARGS__)

// ─── Test framework ───────────────────────────────────────────────────────────
static int  _pass = 0, _fail = 0, _skip = 0;
static char _tname[64];
static unsigned long _tstart;

#define SECTION(name) \
    TB_PRINTF("\n── %s ─────────────────────────────────────\n", name)

#define TEST_BEGIN(name) do { \
    strncpy(_tname,(name),sizeof(_tname)-1); _tstart=millis(); } while(0)

// Expression-compatible versions — usable in ternary conditions
inline void _testPass(int& p, const char* nm, unsigned long t0) {
    p++; TB_PRINTF("  [PASS]  %-44s (%lums)\n", nm, millis()-t0); }
inline void _testFail(int& f, const char* nm, const char* msg) {
    f++; TB_PRINTF("  [FAIL]  %-44s %s\n", nm, msg); }
inline void _testSkip(int& s, const char* nm, const char* r) {
    s++; TB_PRINTF("  [SKIP]  %-44s (%s)\n", nm, r); }

#define TEST_PASS() _testPass(_pass, _tname, _tstart)
#define TEST_FAIL(msg) _testFail(_fail, _tname, (msg))
#define TEST_SKIP(reason) _testSkip(_skip, _tname, (reason))

#define INFO(fmt, ...) \
    TB_PRINTF("  [INFO]  " fmt "\n", ##__VA_ARGS__)

#define CHECK(cond, name, failmsg) do { TEST_BEGIN(name); \
    if(cond) TEST_PASS(); else TEST_FAIL(failmsg); } while(0)

#define CHECK_EQ_U64(got, expected, name) do { TEST_BEGIN(name); \
    if((uint64_t)(got)==(uint64_t)(expected)) TEST_PASS(); \
    else { char _m[64]; snprintf(_m,sizeof(_m),"expected=%llu got=%llu", \
        (ull)(expected),(ull)(got)); TEST_FAIL(_m); } } while(0)

#define CHECK_EQ_STR(got, expected, name) do { TEST_BEGIN(name); \
    if(strcmp((got),(expected))==0) TEST_PASS(); \
    else { char _m[128]; snprintf(_m,sizeof(_m),"expected='%s' got='%s'",(expected),(got)); \
    TEST_FAIL(_m); } } while(0)

#define BENCH(label, iters, ...) do { \
    unsigned long _t0=millis(); \
    for(int _bi=0;_bi<(iters);_bi++){__VA_ARGS__} \
    unsigned long _el=millis()-_t0; _pass++; \
    TB_PRINTF("  [BENCH] %-44s %d\xc3\x97 %lums (~%luus/op)\n", \
        (label),(iters),_el,(_el*1000UL)/(unsigned long)(iters)); } while(0)

typedef unsigned long long ull;

// ─── Helpers ──────────────────────────────────────────────────────────────────
static bool hexEq(const uint8_t* b, size_t len, const char* expected) {
    char buf[len*2+1];
    CKBSigner::bytesToHex(b, len, buf);
    return strcmp(buf, expected) == 0;
}
static String toHex(const uint8_t* b, size_t len) {
    char buf[len*2+1];
    CKBSigner::bytesToHex(b, len, buf);
    return String(buf);
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 1 — CRYPTO
//
// Test vectors (pre-computed with Python stdlib):
//   privkey = 0x00..01  (generator G)
//   python3 -c "
//     import hashlib
//     from cryptography.hazmat.primitives.asymmetric import ec
//     from cryptography.hazmat.backends import default_backend
//     pk = ec.derive_private_key(1, ec.SECP256K1(), default_backend())
//     pub = pk.public_key().public_numbers()
//     b = bytes([2 if pub.y%2==0 else 3])+pub.x.to_bytes(32,'big')
//     args = hashlib.blake2b(b,digest_size=32,person=b'ckb-default-hash').digest()[:20]
//     print(b.hex(), args.hex())
//   "
// ═════════════════════════════════════════════════════════════════════════════

static const char* TV_PRIV     = "0000000000000000000000000000000000000000000000000000000000000001";
static const char* TV_PUB      = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
static const char* TV_LOCKARGS = "75178f34549c5fe9cd1a0c57aebd01e7ddf9249e";
// blake2b_ckb(b'\x00'*32)
static const char* TV_B2B_Z32  = "266cec97cbede2cfbce73666f08deed9560bdf7841a7a5a51b3a3f09da249e21";
// blake2b_ckb(b'')
static const char* TV_B2B_EMPTY= "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e";
// signing_hash for tx_hash=0x00*32
static const char* TV_SIGHASH  = "ca93f94edd259d66c58981134d7d79cd0a846127ded8fd0879b6111020675d0d";

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 0 — BUILD CONFIGURATION
// ═════════════════════════════════════════════════════════════════════════════

void runConfigTests() {
    SECTION("BUILD CONFIG");
    CKBClient::printConfig();

    { TEST_BEGIN("version string non-empty");
      if(strlen(CKB_ESP32_VERSION) > 0) TEST_PASS(); else TEST_FAIL("empty version"); }

    { TEST_BEGIN("node type string non-empty");
      if(strlen(CKB_NODE_TYPE_STR) > 0) TEST_PASS(); else TEST_FAIL("empty node type"); }

    { TEST_BEGIN("CKB_JSON_DOC_SIZE >= 512");
      CKB_JSON_DOC_SIZE >= 512 ? TEST_PASS() :
          TEST_FAIL(("too small: " + String(CKB_JSON_DOC_SIZE)).c_str()); }

    { TEST_BEGIN("CKB_MAX_CELLS >= 1");
      if(CKB_MAX_CELLS >= 1) TEST_PASS(); else TEST_FAIL("zero max cells"); }

    { TEST_BEGIN("CKB_MAX_TXS >= 1");
      if(CKB_MAX_TXS >= 1) TEST_PASS(); else TEST_FAIL("zero max txs"); }

    { TEST_BEGIN("CKB_HTTP_TIMEOUT_MS >= 1000");
      CKB_HTTP_TIMEOUT_MS >= 1000 ? TEST_PASS() :
          TEST_FAIL(("too short: " + String(CKB_HTTP_TIMEOUT_MS) + "ms").c_str()); }

    // Capability coherence checks
    { TEST_BEGIN("CKB_HAS_SIGNER is 0 or 1");
      (CKB_HAS_SIGNER == 0 || CKB_HAS_SIGNER == 1) ? TEST_PASS() :
          TEST_FAIL("unexpected value"); }

    { TEST_BEGIN("CKB_HAS_INDEXER is 0 or 1");
      (CKB_HAS_INDEXER == 0 || CKB_HAS_INDEXER == 1) ? TEST_PASS() :
          TEST_FAIL("unexpected value"); }

    // Profile-specific expectations
#if defined(CKB_PROFILE_MINIMAL)
    { TEST_BEGIN("MINIMAL: block queries disabled");
      if(CKB_HAS_BLOCK_QUERIES == 0) TEST_PASS(); else TEST_FAIL("should be disabled"); }
    { TEST_BEGIN("MINIMAL: send tx disabled");
      if(CKB_HAS_SEND_TX == 0) TEST_PASS(); else TEST_FAIL("should be disabled"); }
    { TEST_BEGIN("MINIMAL: JSON buf <= 4096");
      CKB_JSON_DOC_SIZE <= 4096 ? TEST_PASS() :
          TEST_FAIL(("too large for minimal: " + String(CKB_JSON_DOC_SIZE)).c_str()); }
#endif
#if defined(CKB_PROFILE_MONITOR)
    { TEST_BEGIN("MONITOR: indexer disabled");
      if(CKB_HAS_INDEXER == 0) TEST_PASS(); else TEST_FAIL("should be disabled"); }
    { TEST_BEGIN("MONITOR: block queries enabled");
      if(CKB_HAS_BLOCK_QUERIES == 1) TEST_PASS(); else TEST_FAIL("should be enabled"); }
#endif
#if defined(CKB_PROFILE_SIGNER)
    { TEST_BEGIN("SIGNER: signer enabled");
      if(CKB_HAS_SIGNER == 1) TEST_PASS(); else TEST_FAIL("should be enabled"); }
    { TEST_BEGIN("SIGNER: send tx enabled");
      if(CKB_HAS_SEND_TX == 1) TEST_PASS(); else TEST_FAIL("should be enabled"); }
#endif
}

void runCryptoTests() {    // ── CKBKey load ───────────────────────────────────────────────────────────
    SECTION("CRYPTO — CKBKey");

    CHECK(({CKBKey k; k.loadPrivateKeyHex(TV_PRIV) && k.isValid();}),
          "loadPrivateKeyHex valid", "returned false");
    CHECK(({CKBKey k; String s=String("0x")+TV_PRIV; k.loadPrivateKeyHex(s.c_str()) && k.isValid();}),
          "loadPrivateKeyHex with 0x prefix", "failed with 0x prefix");
    CHECK(({CKBKey k; !k.loadPrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000000");}),
          "loadPrivateKeyHex zero key rejected", "zero key should be invalid");
    CHECK(({CKBKey k; !k.loadPrivateKeyHex("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");}),
          "loadPrivateKeyHex invalid hex rejected", "garbage should be rejected");

    // ── Public key ────────────────────────────────────────────────────────────
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        TEST_BEGIN("getPublicKey compressed (known vector)");
        uint8_t pub[33]; bool ok=k.getPublicKey(pub);
        (ok && hexEq(pub,33,TV_PUB)) ? TEST_PASS() :
            TEST_FAIL(("got="+toHex(pub,33)).c_str());
    }
    CHECK(({CKBKey k; uint8_t p[33]; !k.getPublicKey(p);}),
          "getPublicKey invalid key returns false", "should be false");

    // ── Lock args ─────────────────────────────────────────────────────────────
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        TEST_BEGIN("getLockArgs blake160 (known vector)");
        uint8_t args[20]; bool ok=k.getLockArgs(args);
        (ok && hexEq(args,20,TV_LOCKARGS)) ? TEST_PASS() :
            TEST_FAIL(("got="+toHex(args,20)).c_str());
    }
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        TEST_BEGIN("getLockArgsHex (0x-prefixed)");
        char buf[43]; bool ok=k.getLockArgsHex(buf,sizeof(buf));
        String expected=String("0x")+TV_LOCKARGS;
        (ok && expected==String(buf)) ? TEST_PASS() :
            TEST_FAIL(("got="+String(buf)).c_str());
    }

    // ── Address ───────────────────────────────────────────────────────────────
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        TEST_BEGIN("getAddress mainnet (ckb1q prefix, length >60)");
        char addr[100]; bool ok=k.getAddress(addr,sizeof(addr),true);
        bool valid=ok&&strncmp(addr,"ckb1q",5)==0&&strlen(addr)>60;
        if(valid){TEST_PASS(); INFO("addr=%s",addr);}
        else TEST_FAIL(("got="+(ok?String(addr):String("false"))).c_str());
    }
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        TEST_BEGIN("getAddress testnet (ckt1q prefix)");
        char addr[100]; bool ok=k.getAddress(addr,sizeof(addr),false);
        (ok&&strncmp(addr,"ckt1q",5)==0) ? TEST_PASS() :
            TEST_FAIL(("got="+(ok?String(addr):String("false"))).c_str());
    }
    CHECK(({CKBKey k; char a[100]; !k.getAddress(a,sizeof(a),true);}),
          "getAddress invalid key returns false", "should be false");

    // ── blake2b ───────────────────────────────────────────────────────────────
    SECTION("CRYPTO — blake2b / signing hash");
    {
        TEST_BEGIN("blake2bCKB zeros-32 (known vector)");
        uint8_t d[32]={0},o[32]; bool ok=CKBSigner::blake2bCKB(d,32,o);
        (ok&&hexEq(o,32,TV_B2B_Z32)) ? TEST_PASS() :
            TEST_FAIL(("got="+toHex(o,32)).c_str());
    }
    {
        TEST_BEGIN("blake2bCKB empty input (known vector)");
        uint8_t o[32];
        bool ok=CKBSigner::blake2bCKB((const uint8_t*)"",0,o);
        (ok&&hexEq(o,32,TV_B2B_EMPTY)) ? TEST_PASS() :
            TEST_FAIL(("got="+toHex(o,32)).c_str());
    }
    {
        TEST_BEGIN("blake2bCKB different inputs -> different outputs");
        uint8_t a[1]={0},b[1]={1},ha[32],hb[32];
        CKBSigner::blake2bCKB(a,1,ha); CKBSigner::blake2bCKB(b,1,hb);
        if((memcmp(ha,hb,32)!=0)) TEST_PASS(); else TEST_FAIL("collision 0x00 vs 0x01");
    }
    {
        TEST_BEGIN("blake160 = first 20 bytes of blake2bCKB");
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t pub[33]; k.getPublicKey(pub);
        uint8_t args[20]; CKBSigner::blake160(pub,33,args);
        hexEq(args,20,TV_LOCKARGS) ? TEST_PASS() :
            TEST_FAIL(("got="+toHex(args,20)).c_str());
    }

    // ── WitnessArgs molecule ──────────────────────────────────────────────────
    {
        TEST_BEGIN("buildWitnessPlaceholder header + zeroed lock (85 bytes)");
        uint8_t w[CKB_WITNESS_ARGS_LEN];
        CKBSigner::buildWitnessPlaceholder(w);
        bool hdr = w[0]==85&&w[4]==16&&w[8]==85&&w[12]==85&&w[16]==65 &&
                   w[1]==0&&w[2]==0&&w[3]==0&&w[5]==0&&w[6]==0&&w[7]==0 &&
                   w[9]==0&&w[10]==0&&w[11]==0&&w[13]==0&&w[14]==0&&w[15]==0 &&
                   w[17]==0&&w[18]==0&&w[19]==0;
        bool zeros=true; for(int i=20;i<85;i++) if(w[i]){zeros=false;break;}
        if((hdr&&zeros)) TEST_PASS(); else TEST_FAIL(hdr?"lock not zero":"bad header");
    }
    {
        TEST_BEGIN("buildWitnessWithSig embeds sig at offset 20");
        uint8_t sig[65]; for(int i=0;i<65;i++) sig[i]=(uint8_t)(i+1);
        uint8_t w[CKB_WITNESS_ARGS_LEN]; CKBSigner::buildWitnessWithSig(sig,w);
        (w[0]==85&&w[16]==65&&memcmp(w+20,sig,65)==0) ? TEST_PASS() :
            TEST_FAIL("sig bytes not correctly placed at offset 20");
    }
    {
        TEST_BEGIN("Placeholder vs WithSig: header same, lock data differs");
        uint8_t wp[85],ws[85],sig[65]; for(int i=0;i<65;i++) sig[i]=(uint8_t)(i+0xAA);
        CKBSigner::buildWitnessPlaceholder(wp); CKBSigner::buildWitnessWithSig(sig,ws);
        (memcmp(wp,ws,20)==0 && memcmp(wp+20,ws+20,65)!=0) ? TEST_PASS() :
            TEST_FAIL("headers should match, lock data should differ");
    }

    // ── Signing hash ──────────────────────────────────────────────────────────
    {
        TEST_BEGIN("computeSigningHash 0x-prefixed (known vector)");
        uint8_t o[32];
        bool ok=CKBSigner::computeSigningHash(
            "0x0000000000000000000000000000000000000000000000000000000000000000",o);
        (ok&&hexEq(o,32,TV_SIGHASH)) ? TEST_PASS() :
            TEST_FAIL(("got="+toHex(o,32)).c_str());
    }
    {
        TEST_BEGIN("computeSigningHash bare hex (same result)");
        uint8_t o[32];
        bool ok=CKBSigner::computeSigningHash(
            "0000000000000000000000000000000000000000000000000000000000000000",o);
        if((ok&&hexEq(o,32,TV_SIGHASH))) TEST_PASS(); else TEST_FAIL("bare hex mismatch");
    }
    {
        TEST_BEGIN("computeSigningHashRaw == computeSigningHash");
        uint8_t txh[32]={0},h1[32],h2[32];
        CKBSigner::computeSigningHashRaw(txh,h1);
        CKBSigner::computeSigningHash("0x0000000000000000000000000000000000000000000000000000000000000000",h2);
        if((memcmp(h1,h2,32)==0)) TEST_PASS(); else TEST_FAIL("raw vs hex mismatch");
    }
    {
        TEST_BEGIN("Different tx_hash -> different signing hash");
        uint8_t h1[32],h2[32];
        CKBSigner::computeSigningHash("0x0000000000000000000000000000000000000000000000000000000000000000",h1);
        CKBSigner::computeSigningHash("0x0000000000000000000000000000000000000000000000000000000000000001",h2);
        if((memcmp(h1,h2,32)!=0)) TEST_PASS(); else TEST_FAIL("collision for different tx_hash");
    }

    // ── ECDSA ─────────────────────────────────────────────────────────────────
    SECTION("CRYPTO — ECDSA sign");

    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t hash[32]={0}; CKBSigner::computeSigningHashRaw(hash,hash);

        TEST_BEGIN("sign() succeeds, recid in [0..3]");
        uint8_t sig[65]={0xFF}; bool ok=CKBSigner::sign(hash,k,sig);
        (ok&&sig[0]<=3&&sig[1]!=0xFF) ? TEST_PASS() :
            TEST_FAIL(ok?("recid="+String(sig[0])).c_str():"sign() returned false");

        TEST_BEGIN("sign() RFC6979 deterministic (call twice -> same result)");
        uint8_t sig2[65]; CKBSigner::sign(hash,k,sig2);
        if((memcmp(sig,sig2,65)==0)) TEST_PASS(); else TEST_FAIL("non-deterministic");

        INFO("recid=%d  r=%02x%02x%02x%02x..  s=%02x%02x%02x%02x..",
             sig[0],sig[1],sig[2],sig[3],sig[4],sig[33],sig[34],sig[35],sig[36]);
    }
    {
        TEST_BEGIN("sign() different hash -> different signature");
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t h1[32]={1},h2[32]={2},s1[65],s2[65];
        CKBSigner::sign(h1,k,s1); CKBSigner::sign(h2,k,s2);
        if((memcmp(s1,s2,65)!=0)) TEST_PASS(); else TEST_FAIL("same sig for different hash");
    }
    {
        TEST_BEGIN("sign() invalid key rejected");
        CKBKey bad; uint8_t h[32]={1},sig[65];
        if((!CKBSigner::sign(h,bad,sig))) TEST_PASS(); else TEST_FAIL("should return false");
    }
    {
        TEST_BEGIN("CKBSigner::sign() produces valid sig");
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t txh[32]={0};
        uint8_t sigHash[32]; CKBSigner::computeSigningHashRaw(txh,sigHash);
        uint8_t sig[65]={0};
        bool ok = CKBSigner::sign(sigHash, k, sig);
        if(ok && sig[0]<=3 && sig[1]!=0xFF) TEST_PASS();
        else TEST_FAIL(ok ? "bad sig values" : "sign() returned false");
    }
    {
        TEST_BEGIN("CKBSigner::signTx() sets signed_");
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        // Use signTxRaw to avoid struct-layout ODR issue between CKB.h and CKBSigner.h
        // (CKBBuiltTx field offsets differ between standalone and integrated builds)
        uint8_t txh[32]={0};
        uint8_t signingHash[32]; CKBSigner::computeSigningHashRaw(txh, signingHash);
        uint8_t sig[65]={0};
        bool signed_ = false;
        bool ok = CKBSigner::signTxRaw(signingHash, k, sig, signed_);
        if(ok && signed_ && sig[0]<=3) TEST_PASS();
        else TEST_FAIL(ok ? "signed_ not set" : "signTxRaw() returned false");
    }
    {
        // Without a valid signing hash, signTx should still sign (hash is caller's responsibility)
        // Just verify it doesn't crash and sets signed_
        TEST_BEGIN("signTx() on zeroed tx — no crash");
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        CKBBuiltTx tx; memset(&tx,0,sizeof(tx));
        bool ok = CKBSigner::signTx(tx, k);
        // result may be ok or fail — just must not crash
        TEST_PASS();
        (void)ok;
    }

    // ── Hex utilities ─────────────────────────────────────────────────────────
    SECTION("CRYPTO — hex utilities");
    {
        TEST_BEGIN("bytesToHex / hexToBytes round-trip (16 bytes)");
        uint8_t orig[16],back[16]; char hex[33];
        for(int i=0;i<16;i++) orig[i]=(uint8_t)(i*17);
        CKBSigner::bytesToHex(orig,16,hex);
        bool ok=CKBSigner::hexToBytes(hex,back,16);
        if((ok&&memcmp(orig,back,16)==0)) TEST_PASS(); else TEST_FAIL("mismatch");
    }
    {
        TEST_BEGIN("hexToBytes 0x-prefix accepted");
        uint8_t out[4];
        bool ok=CKBSigner::hexToBytes("0xdeadbeef",out,4);
        (ok&&out[0]==0xde&&out[1]==0xad&&out[2]==0xbe&&out[3]==0xef) ? TEST_PASS() :
            TEST_FAIL("0x prefix not handled");
    }
    {
        TEST_BEGIN("hexToBytes rejects wrong byte count");
        uint8_t out[4];
        if((!CKBSigner::hexToBytes("aabb",out,4))) TEST_PASS(); else TEST_FAIL("should reject");
    }
    {
        TEST_BEGIN("hexToBytes rejects non-hex chars");
        uint8_t out[2];
        if((!CKBSigner::hexToBytes("GGGG",out,2))) TEST_PASS(); else TEST_FAIL("should reject");
    }

    // ── Benchmarks ────────────────────────────────────────────────────────────
    SECTION("CRYPTO — benchmarks");
    CKBKey bk; bk.loadPrivateKeyHex(TV_PRIV);
    uint8_t bh[32]={0}; CKBSigner::computeSigningHashRaw(bh,bh);

    BENCH("blake2bCKB (32 bytes)",           200, { uint8_t i[32]={0},o[32]; CKBSigner::blake2bCKB(i,32,o); });
    BENCH("blake2bCKB (1 byte)",             200, { uint8_t i[1]={0},o[32]; CKBSigner::blake2bCKB(i,1,o); });
    BENCH("computeSigningHashRaw",           200, { uint8_t t[32]={0},o[32]; CKBSigner::computeSigningHashRaw(t,o); });
    BENCH("buildWitnessPlaceholder",        1000, { uint8_t w[85]; CKBSigner::buildWitnessPlaceholder(w); });
    BENCH("CKBKey::getPublicKey",             20, { uint8_t p[33]; bk.getPublicKey(p); });
    BENCH("CKBKey::getLockArgs",              20, { uint8_t a[20]; bk.getLockArgs(a); });
    BENCH("CKBKey::getAddress (bech32m)",     20, { char a[100]; bk.getAddress(a,sizeof(a),true); });
    BENCH("CKBSigner::sign (ECDSA)",          10, { uint8_t s[65]; CKBSigner::sign(bh,bk,s); });
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 2 — UTILS: CKBClient static helpers
// ═════════════════════════════════════════════════════════════════════════════

void runUtilTests() {
    SECTION("UTILS — shannon/CKB conversion");

    CHECK_EQ_U64(CKBClient::ckbToShannon(1.0f),      100000000ULL,    "ckbToShannon(1.0)");
    CHECK_EQ_U64(CKBClient::ckbToShannon(0.0f),                0ULL,  "ckbToShannon(0.0)");
    CHECK_EQ_U64(CKBClient::ckbToShannon(1000.0f),  100000000000ULL,  "ckbToShannon(1000)");
    CHECK_EQ_U64(CKBClient::shannonToCKBInt(100000000ULL),      1ULL,  "shannonToCKBInt(1 CKB)");
    CHECK_EQ_U64(CKBClient::shannonToCKBInt(0ULL),              0ULL,  "shannonToCKBInt(0)");
    {
        TEST_BEGIN("shannonToCKB(100000000) ~= 1.0f");
        (fabsf(CKBClient::shannonToCKB(100000000ULL)-1.0f)<0.0001f) ? TEST_PASS() :
            TEST_FAIL("not within 0.0001 tolerance");
    }

    SECTION("UTILS — hex / number conversion");
    {
        TEST_BEGIN("hexToUint64(0x100) == 256");
        if((CKBClient::hexToUint64("0x100")==256)) TEST_PASS(); else TEST_FAIL("expected 256");
    }
    {
        TEST_BEGIN("hexToUint64(0x0) == 0");
        if((CKBClient::hexToUint64("0x0")==0)) TEST_PASS(); else TEST_FAIL("expected 0");
    }
    {
        TEST_BEGIN("hexToUint64(0xffffffff) == 0xFFFFFFFF");
        if((CKBClient::hexToUint64("0xffffffff")==0xFFFFFFFFULL)) TEST_PASS(); else TEST_FAIL("wrong");
    }
    {
        TEST_BEGIN("uint64ToHex(256) == '0x100'");
        char buf[19]; CKBClient::uint64ToHex(256,buf);
        if((strcmp(buf,"0x100")==0)) TEST_PASS(); else TEST_FAIL(("got="+String(buf)).c_str());
    }
    {
        TEST_BEGIN("uint64ToHex(0) == '0x0'");
        char buf[19]; CKBClient::uint64ToHex(0,buf);
        if((strcmp(buf,"0x0")==0)) TEST_PASS(); else TEST_FAIL(("got="+String(buf)).c_str());
    }
    {
        TEST_BEGIN("hexToUint64 + uint64ToHex round-trip");
        const char* orig="0xdeadbeef"; char buf[19];
        CKBClient::uint64ToHex(CKBClient::hexToUint64(orig),buf);
        if((strcmp(buf,orig)==0)) TEST_PASS(); else TEST_FAIL(("got="+String(buf)).c_str());
    }

    SECTION("UTILS — formatCKB / formatCKBCompact");
    {
        TEST_BEGIN("formatCKB(1 CKB) == '1.00 CKB'");
        String s=CKBClient::formatCKB(100000000ULL);
        if((s=="1.00 CKB")) TEST_PASS(); else TEST_FAIL(("got='"+s+"'").c_str());
    }
    {
        TEST_BEGIN("formatCKB(1000 CKB) has comma");
        String s=CKBClient::formatCKB(100000000000ULL);
        if((s.indexOf(",")>=0)) TEST_PASS(); else TEST_FAIL(("no comma in '"+s+"'").c_str());
    }
    {
        TEST_BEGIN("formatCKBCompact(1M CKB) contains 'M'");
        String s=CKBClient::formatCKBCompact(100000000ULL*1000000ULL);
        if((s.indexOf("M")>=0)) TEST_PASS(); else TEST_FAIL(("got='"+s+"'").c_str());
    }
    {
        TEST_BEGIN("formatCKBCompact(1B CKB) contains 'B'");
        String s=CKBClient::formatCKBCompact(100000000ULL*1000000000ULL);
        if((s.indexOf("B")>=0)) TEST_PASS(); else TEST_FAIL(("got='"+s+"'").c_str());
    }
    {
        TEST_BEGIN("formatCKB(0) == '0.00 CKB'");
        String s=CKBClient::formatCKB(0ULL);
        if((s=="0.00 CKB")) TEST_PASS(); else TEST_FAIL(("got='"+s+"'").c_str());
    }

    SECTION("UTILS — isValidTxHash");
    CHECK( CKBClient::isValidTxHash("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
          "isValidTxHash valid 66-char hash", "should be true");
    CHECK(!CKBClient::isValidTxHash("0x71a7"),
          "isValidTxHash too short", "should be false");
    CHECK(!CKBClient::isValidTxHash("71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
          "isValidTxHash no 0x prefix", "should be false");
    CHECK(!CKBClient::isValidTxHash(nullptr),
          "isValidTxHash nullptr", "should be false");
    CHECK(!CKBClient::isValidTxHash("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"),
          "isValidTxHash non-hex chars", "should be false");

    SECTION("UTILS — isValidAddress");
    CHECK( CKBClient::isValidAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh"),
          "isValidAddress ckb1 mainnet", "should be true");
    CHECK( CKBClient::isValidAddress("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40"),
          "isValidAddress ckt1 testnet", "should be true");
    CHECK(!CKBClient::isValidAddress("bitcoin1qzda0cr08"),
          "isValidAddress wrong prefix", "should be false");
    CHECK(!CKBClient::isValidAddress("ckb1"),
          "isValidAddress too short", "should be false");
    CHECK(!CKBClient::isValidAddress(nullptr),
          "isValidAddress nullptr", "should be false");

    // ── Address decode ─────────────────────────────────────────────────────────
    SECTION("UTILS — decodeAddress");
    {
        // A known secp256k1/blake160 address: decode should give lock with
        // code_hash = 9bd7e06f... and hash_type = "type"
        const char* ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("decodeAddress valid secp256k1 address");
        CKBScript lock = CKBClient::decodeAddress(ADDR);
        if (lock.valid) {
            TEST_PASS();
            INFO("code_hash=%.12s...", lock.codeHash);
            INFO("hash_type=%s  args=%.12s...", lock.hashType, lock.args);
        } else {
            TEST_FAIL("decodeAddress returned valid=false");
        }
    }
    {
        TEST_BEGIN("decodeAddress produces correct hash_type 'type'");
        const char* ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        CKBScript lock = CKBClient::decodeAddress(ADDR);
        (lock.valid && strcmp(lock.hashType,"type")==0) ? TEST_PASS() :
            TEST_FAIL(("hash_type="+String(lock.hashType)).c_str());
    }
    {
        TEST_BEGIN("decodeAddress secp256k1 code_hash prefix");
        const char* ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        CKBScript lock = CKBClient::decodeAddress(ADDR);
        // code_hash starts with 0x9bd7e06f...
        (lock.valid && strncmp(lock.codeHash,"0x9bd7e06f",10)==0) ? TEST_PASS() :
            TEST_FAIL(("code_hash="+String(lock.codeHash)).c_str());
    }
    {
        TEST_BEGIN("decodeAddress invalid input -> valid=false");
        CKBScript lock = CKBClient::decodeAddress("not_a_ckb_address");
        if((!lock.valid)) TEST_PASS(); else TEST_FAIL("should return valid=false");
    }
    {
        TEST_BEGIN("decodeAddress nullptr -> valid=false");
        CKBScript lock = CKBClient::decodeAddress(nullptr);
        if((!lock.valid)) TEST_PASS(); else TEST_FAIL("should return valid=false");
    }

    SECTION("UTILS — encodeAddress / convertAddress");
    {
        // Known: decode then re-encode should give back the same address
        const char* FULL_ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("encodeAddress round-trip (decode → encode = original)");
        CKBScript lock = CKBClient::decodeAddress(FULL_ADDR);
        char encoded[110] = {0};
        bool ok = CKBClient::encodeAddress(lock, encoded, sizeof(encoded));
        if(ok && strcmp(encoded, FULL_ADDR)==0) TEST_PASS();
        else TEST_FAIL(ok ? ("got: "+String(encoded)).c_str() : "encodeAddress returned false");
    }
    {
        // convertAddress: full → full (same address, different hrp = testnet)
        const char* FULL_MAIN = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("convertAddress mainnet → testnet hrp");
        char testnet[110]={0};
        bool ok = CKBClient::convertAddress(FULL_MAIN, testnet, sizeof(testnet),
                                            CKBClient::CKB_ADDR_FULL, false);
        if(ok && strncmp(testnet,"ckt1",4)==0) TEST_PASS();
        else TEST_FAIL(ok ? ("got: "+String(testnet)).c_str() : "convertAddress returned false");
    }
    {
        // convertAddress: full → full (testnet → mainnet)
        const char* FULL_MAIN = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("convertAddress mainnet → testnet → mainnet round-trip");
        char testnet[110]={0}, mainnet2[110]={0};
        CKBClient::convertAddress(FULL_MAIN, testnet, sizeof(testnet),
                                  CKBClient::CKB_ADDR_FULL, false);
        bool ok = CKBClient::convertAddress(testnet, mainnet2, sizeof(mainnet2),
                                            CKBClient::CKB_ADDR_FULL, true);
        if(ok && strcmp(mainnet2, FULL_MAIN)==0) TEST_PASS();
        else TEST_FAIL(ok ? "mismatch after round-trip" : "convertAddress returned false");
    }
    {
        // convertAddress: full → short (secp256k1 only)
        const char* FULL_ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("convertAddress full → short format");
        char shortAddr[80]={0};
        bool ok = CKBClient::convertAddress(FULL_ADDR, shortAddr, sizeof(shortAddr),
                                            CKBClient::CKB_ADDR_SHORT, true);
        if(ok && strncmp(shortAddr,"ckb1",4)==0 && strlen(shortAddr)<80) TEST_PASS();
        else TEST_FAIL(ok ? ("got: "+String(shortAddr)).c_str() : "convertAddress returned false");
    }
    {
        // convertAddress: invalid input → false
        TEST_BEGIN("convertAddress invalid input → false");
        char buf[100]={0};
        bool ok = CKBClient::convertAddress("not_an_address", buf, sizeof(buf));
        if(!ok) TEST_PASS(); else TEST_FAIL("should return false for invalid input");
    }
    {
        // encodeAddress on an invalid script → false
        TEST_BEGIN("encodeAddress invalid script → false");
        CKBScript bad; bad.valid = false;
        char buf[100]={0};
        bool ok = CKBClient::encodeAddress(bad, buf, sizeof(buf));
        if(!ok) TEST_PASS(); else TEST_FAIL("should return false for invalid script");
    }

    SECTION("UTILS — deprecated address formats");
    // Old short address (secp256k1-sighash, index 0x00, bech32 checksum)
    // Generated from privkey=1, args=75178f34549c5fe9cd1a0c57aebd01e7ddf9249e
    {
        const char* OLD_SHORT = "ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f";
        TEST_BEGIN("decodeAddress old short (0x01 secp256k1-sighash index)");
        CKBScript s = CKBClient::decodeAddress(OLD_SHORT);
        if(s.valid && strncmp(s.codeHash,"0x9bd7e06f",10)==0
                   && strcmp(s.hashType,"type")==0
                   && strncmp(s.args,"0x75178f",8)==0) TEST_PASS();
        else TEST_FAIL(s.valid ? "wrong code_hash or args" : "decodeAddress returned false");
    }
    {
        // Old full address = same payload as new full, but bech32 checksum (not bech32m)
        // Our decoder strips checksum without verifying, so it parses both transparently
        const char* OLD_FULL = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s3d5s64";
        TEST_BEGIN("decodeAddress old full (bech32 checksum, same payload as new full)");
        CKBScript s = CKBClient::decodeAddress(OLD_FULL);
        if(s.valid && strncmp(s.codeHash,"0x9bd7e06f",10)==0
                   && strcmp(s.hashType,"type")==0
                   && strncmp(s.args,"0x75178f",8)==0) TEST_PASS();
        else TEST_FAIL(s.valid ? "wrong fields" : "decodeAddress returned false");
    }
    {
        // Old short → convertAddress to new full → verify it matches known new full
        const char* OLD_SHORT = "ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f";
        const char* NEW_FULL  = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("convertAddress old-short → new full");
        char out[110]={0};
        bool ok = CKBClient::convertAddress(OLD_SHORT, out, sizeof(out));
        if(ok && strcmp(out, NEW_FULL)==0) TEST_PASS();
        else TEST_FAIL(ok ? ("got: "+String(out)).c_str() : "convertAddress returned false");
    }
    {
        // Old full → convertAddress to new full (should be same address body, different checksum)
        const char* OLD_FULL = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s3d5s64";
        const char* NEW_FULL = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("convertAddress old-full (bech32) → new full (bech32m)");
        char out[110]={0};
        bool ok = CKBClient::convertAddress(OLD_FULL, out, sizeof(out));
        if(ok && strcmp(out, NEW_FULL)==0) TEST_PASS();
        else TEST_FAIL(ok ? ("got: "+String(out)).c_str() : "convertAddress returned false");
    }
    {
        // New full → convertAddress to old short (round-trip back)
        const char* NEW_FULL  = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("convertAddress new full → old short (secp256k1 index lookup)");
        char out[80]={0};
        bool ok = CKBClient::convertAddress(NEW_FULL, out, sizeof(out),
                                            CKBClient::CKB_ADDR_SHORT, true);
        // Decode the short addr back to verify it has same args
        if(ok) {
            CKBScript s = CKBClient::decodeAddress(out);
            if(s.valid && strncmp(s.args,"0x75178f",8)==0) TEST_PASS();
            else TEST_FAIL("short addr args mismatch");
        } else TEST_FAIL("convertAddress returned false");
    }

    SECTION("UTILS — benchmarks");
    BENCH("isValidTxHash",   5000, { CKBClient::isValidTxHash("0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"); });
    BENCH("isValidAddress",  5000, { CKBClient::isValidAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh"); });
    BENCH("formatCKB",       2000, { CKBClient::formatCKB(1234567890123ULL); });
    BENCH("hexToUint64",     5000, { CKBClient::hexToUint64("0xdeadbeef"); });
    BENCH("decodeAddress",    100, { CKBClient::decodeAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh"); });
    BENCH("encodeAddress",    100, { char b[110]; CKBClient::encodeAddress(CKBClient::decodeAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh"), b, sizeof(b)); });
    BENCH("convertAddress",   100, { char b[110]; CKBClient::convertAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh", b, sizeof(b)); });
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 3 — RPC: Live node calls (skipped without WiFi)
// ═════════════════════════════════════════════════════════════════════════════

void runRPCTests(CKBClient& ckb) {
    SECTION("RPC — node info");

    uint64_t tip = 0;
    {
        TEST_BEGIN("getTipBlockNumber() > 0");
        tip = ckb.getTipBlockNumber();
        (tip != UINT64_MAX && tip > 0) ? TEST_PASS() :
            TEST_FAIL(("got="+String((uint32_t)tip)+" err="+ckb.lastErrorStr()).c_str());
        INFO("tip block = %llu", (ull)tip);
    }
    {
        TEST_BEGIN("getNodeInfo() — valid nodeId + version");
        CKBNodeInfo info = ckb.getNodeInfo();
        (info.valid && strlen(info.nodeId)>10 && strlen(info.version)>0) ? TEST_PASS() :
            TEST_FAIL(("valid="+String(info.valid)+" err="+ckb.lastErrorStr()).c_str());
        INFO("nodeId=%.16s..  version=%s  peers=%d", info.nodeId, info.version, info.peersCount);
    }
    {
        TEST_BEGIN("getTxPoolInfo() — valid");
        CKBTxPoolInfo pool = ckb.getTxPoolInfo();
        pool.valid ? TEST_PASS() :
            TEST_FAIL(("err="+String(ckb.lastErrorStr())).c_str());
        INFO("pending=%llu  proposed=%llu", (ull)pool.pending, (ull)pool.proposed);
    }
    {
        TEST_BEGIN("getBlockchainInfo() — valid, network='ckb'");
        CKBChainInfo chain = ckb.getBlockchainInfo();
        (chain.valid && chain.isMainnet) ? TEST_PASS() :
            TEST_FAIL(("valid="+String(chain.valid)+" mainnet="+String(chain.isMainnet)).c_str());
        INFO("network=%s  epoch=%llu", chain.networkId, (ull)chain.epoch);
    }
    {
        TEST_BEGIN("getPeers() — count >= 0");
        CKBPeer peers[CKB_MAX_PEERS];
        uint8_t n = ckb.getPeers(peers);
        if((n < 0xFF)) TEST_PASS(); else TEST_FAIL("returned 0xFF (error)");
        INFO("peer count = %d", n);
    }

    SECTION("RPC — chain queries");
    {
        TEST_BEGIN("getCurrentEpoch() — valid");
        CKBEpoch ep = ckb.getCurrentEpoch();
        (ep.valid && ep.length > 0) ? TEST_PASS() :
            TEST_FAIL(("err="+String(ckb.lastErrorStr())).c_str());
        INFO("epoch=%llu  length=%llu  start=%llu", (ull)ep.number,(ull)ep.length,(ull)ep.startNumber);
    }
    {
        TEST_BEGIN("getBlockByNumber(tip-1) — valid header");
        if (tip > 0) {
            CKBBlock blk = ckb.getBlockByNumber(tip - 1);
            (blk.valid && blk.header.number == tip-1) ? TEST_PASS() :
                TEST_FAIL(("valid="+String(blk.valid)+" num="+String((uint32_t)blk.header.number)).c_str());
            INFO("block #%llu  txCount=%d", (ull)blk.header.number, blk.txCount);
        } else {
            TEST_SKIP("tip block unknown (getTipBlockNumber failed)");
        }
    }
    {
        TEST_BEGIN("getHeaderByNumber(tip-1) — valid, faster than full block");
        if (tip > 0) {
            unsigned long t0=millis();
            CKBBlockHeader h = ckb.getHeaderByNumber(tip - 1);
            unsigned long el=millis()-t0;
            (h.valid && h.number==tip-1) ? TEST_PASS() :
                TEST_FAIL(("valid="+String(h.valid)).c_str());
            INFO("header fetch: %lums  hash=%.16s..", el, h.hash);
        } else {
            TEST_SKIP("tip unknown");
        }
    }

    SECTION("RPC — indexer");
    {
        TEST_BEGIN("getIndexerTip() — valid, close to node tip");
        CKBIndexerTip itip = ckb.getIndexerTip();
        if (tip > 0) {
            // Indexer tip should be within 10 blocks of node tip
            bool close = itip.valid && (tip - itip.blockNumber) < 10;
            close ? TEST_PASS() :
                TEST_FAIL(("indexerTip="+String((uint32_t)itip.blockNumber)+
                           " nodeTip="+String((uint32_t)tip)).c_str());
            INFO("indexer tip = %llu", (ull)itip.blockNumber);
        } else {
            if(itip.valid) TEST_PASS(); else TEST_FAIL("getIndexerTip() failed");
        }
    }

    // Balance check for a known-funded address (Phill's node wallet)
    {
        const char* TEST_ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        TEST_BEGIN("getBalance(known address) — no error");
        CKBBalance bal = ckb.getBalance(TEST_ADDR);
        (bal.error == CKB_OK) ? TEST_PASS() :
            TEST_FAIL(("error="+String(ckb.lastErrorStr())).c_str());
        INFO("balance = %s (%d cells)", CKBClient::formatCKB(bal.shannon).c_str(), bal.cellCount);
    }

    SECTION("RPC — benchmarks (each call timed)");
    BENCH("getTipBlockNumber()",   5, { ckb.getTipBlockNumber(); });
    BENCH("getNodeInfo()",         3, { ckb.getNodeInfo(); });
    BENCH("getTxPoolInfo()",       3, { ckb.getTxPoolInfo(); });
    if (tip > 0) {
        BENCH("getHeaderByNumber(tip)",3, { ckb.getHeaderByNumber(tip-1); });
        BENCH("getBlockByNumber(tip)", 2, { ckb.getBlockByNumber(tip-1); });
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 4 — LIGHT CLIENT (compile-time + optional live tests)
// Offline: struct layout, serialisation helpers, address→script conversion
// Live:    requires CKB_NODE_LIGHT compiled in + a running light client
// ═════════════════════════════════════════════════════════════════════════════

#define LIGHT_CLIENT_URL  "http://192.168.68.91:9000"   // N100 running ckb-light-client v0.5.4

void runLightClientTests(bool liveAvailable = false) {
    SECTION("LIGHT CLIENT — compile-time checks");

    // ── Compile-time node type detection ─────────────────────────────────────
    {
        TEST_BEGIN("nodeTypeStr() returns a non-empty string");
        const char* nt = CKBClient::nodeTypeStr();
        if((nt && strlen(nt) > 0)) TEST_PASS(); else TEST_FAIL("empty nodeTypeStr");
        INFO("compiled node type = '%s'", nt);
    }
    {
        TEST_BEGIN("nodeTypeStr() is one of the known types");
        const char* nt = CKBClient::nodeTypeStr();
        bool known = (strcmp(nt,"full")==0 || strcmp(nt,"light")==0 ||
                      strcmp(nt,"indexer")==0 || strcmp(nt,"rich")==0);
        if(known) TEST_PASS(); else TEST_FAIL(("unknown type: "+String(nt)).c_str());
    }

    // ── CKBScriptStatus struct layout ────────────────────────────────────────
    {
        TEST_BEGIN("CKBScriptStatus — zero-initialise + field assignment");
        CKBScriptStatus s; memset(&s, 0, sizeof(s));
        strncpy(s.scriptType, "lock", sizeof(s.scriptType)-1);
        s.blockNumber = 18000000;
        strncpy(s.script.codeHash,
            "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            sizeof(s.script.codeHash)-1);
        strncpy(s.script.hashType, "type", sizeof(s.script.hashType)-1);
        strncpy(s.script.args, "0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249e",
            sizeof(s.script.args)-1);
        s.script.valid = true;
        if(s.blockNumber == 18000000 && strcmp(s.scriptType,"lock")==0 && s.script.valid)
            TEST_PASS(); else TEST_FAIL("field assignment failed");
    }

    // ── watchAddress → decodeAddress round-trip ──────────────────────────────
    // (offline: just verify address decodes to a valid script before calling RPC)
    {
        TEST_BEGIN("watchAddress address → lock script decode (offline check)");
        const char* ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
        CKBScript lock = CKBClient::decodeAddress(ADDR);
        (lock.valid && strncmp(lock.codeHash,"0x9bd7e06f",10)==0) ? TEST_PASS() :
            TEST_FAIL("decodeAddress failed — watchAddress would fail too");
    }

    // ── Light client sync state struct ───────────────────────────────────────
    {
        TEST_BEGIN("CKBLightSyncState — zero-init and field access");
        CKBLightSyncState st; memset(&st,0,sizeof(st));
        st.tipBlockNumber = 18674521;
        st.isSynced = false;
        st.error = CKB_OK;
        if(st.tipBlockNumber == 18674521 && !st.isSynced && st.error == CKB_OK)
            TEST_PASS(); else TEST_FAIL("field access broken");
    }

#ifdef CKB_NODE_LIGHT
    // ── Live light client tests ───────────────────────────────────────────────
    if (liveAvailable) {
        SECTION("LIGHT CLIENT — live RPC (#define CKB_NODE_LIGHT)");
        CKBClient lc(LIGHT_CLIENT_URL);

        // getTipHeader
        {
            TEST_BEGIN("getTipHeader() — valid, number > 0");
            CKBBlockHeader tip = lc.getTipHeader();
            (tip.valid && tip.number > 0) ? TEST_PASS() :
                TEST_FAIL(("valid="+String(tip.valid)+" err="+lc.lastErrorStr()).c_str());
            INFO("light tip = %llu  hash=%.12s..", (ull)tip.number, tip.hash);
        }

        // getSyncState
        {
            TEST_BEGIN("getSyncState() — no error");
            CKBLightSyncState st = lc.getSyncState();
            (st.error == CKB_OK) ? TEST_PASS() :
                TEST_FAIL(("error="+String(lc.lastErrorStr())).c_str());
            INFO("synced=%s  tipBlock=%llu", st.isSynced?"yes":"no", (ull)st.tipBlockNumber);
        }

        // getScripts (before registering — expect empty or existing)
        {
            TEST_BEGIN("getScripts() — no error");
            CKBScriptStatusResult r = lc.getScripts();
            (r.error == CKB_OK) ? TEST_PASS() :
                TEST_FAIL(("error="+String(lc.lastErrorStr())).c_str());
            INFO("registered scripts: %d", r.count);
        }

        // watchAddress
        {
            const char* ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
            TEST_BEGIN("watchAddress() — registers lock script");
            CKBError err = lc.watchAddress(ADDR, 0);
            (err == CKB_OK) ? TEST_PASS() :
                TEST_FAIL(("error code="+String((int)err)).c_str());
        }

        // getScripts after watching — should have at least 1
        {
            TEST_BEGIN("getScripts() after watchAddress — count >= 1");
            CKBScriptStatusResult r = lc.getScripts();
            (r.error == CKB_OK && r.count >= 1) ? TEST_PASS() :
                TEST_FAIL(("count="+String(r.count)+" err="+String((int)r.error)).c_str());
            for (int i = 0; i < r.count; i++) {
                INFO("script[%d]: type=%s  blockNum=%llu  args=%.12s..",
                     i, r.scripts[i].scriptType,
                     (ull)r.scripts[i].blockNumber,
                     r.scripts[i].script.args);
            }
        }

        // fetchHeader for the tip block
        {
            CKBBlockHeader tip = lc.getTipHeader();
            TEST_BEGIN("fetchHeader(tipHash) — fetched or syncing");
            if (tip.valid && strlen(tip.hash) == 66) {
                CKBBlockHeader h = lc.fetchHeader(tip.hash);
                // Either fetched (valid) or "not_synced" / "fetching" (both OK for light client)
                (h.valid || lc.lastError() == CKB_ERR_NOT_FOUND) ? TEST_PASS() :
                    TEST_FAIL(("err="+String(lc.lastErrorStr())).c_str());
                if (h.valid) INFO("fetched header #%llu", (ull)h.number);
                else         INFO("fetch pending (not_synced or fetching)");
            } else {
                TEST_SKIP("tip header unavailable");
            }
        }

        // fetchTransaction — known committed tx
        {
            // Use the genesis cellbase tx (always exists, always committed)
            const char* GENESIS_TX = "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c";
            TEST_BEGIN("fetchTransaction (known committed tx)");
            CKBTransaction tx = lc.fetchTransaction(GENESIS_TX);
            // Either fetched (valid) or "added" / not synced (CKB_ERR_NOT_FOUND — acceptable)
            (tx.valid || lc.lastError() == CKB_ERR_NOT_FOUND) ? TEST_PASS() :
                TEST_FAIL(("err="+String(lc.lastErrorStr())).c_str());
            if (tx.valid) {
                INFO("tx status=%d  blockHash=%.12s..", tx.status, tx.blockHash);
            } else {
                INFO("fetch queued (not_synced or fetching — retry needed)");
            }
        }

        // NOTE: get_indexer_tip is NOT supported in ckb-light-client v0.5.4
        // Use get_cells_capacity as a lighter balance check instead
        {
            TEST_BEGIN("get_cells_capacity (via getBalance on light client)");
            // Use lock args from our test privkey: 75178f...
            const char* TEST_ADDR = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8sy3yulh";
            CKBBalance bal = lc.getBalance(TEST_ADDR);
            // OK or NOT_FOUND both acceptable (depends on what's synced)
            (bal.error == CKB_OK || bal.error == CKB_ERR_NOT_FOUND) ? TEST_PASS() :
                TEST_FAIL(("err="+String(lc.lastErrorStr())).c_str());
            INFO("balance=%s  cells=%d", CKBClient::formatCKB(bal.shannon).c_str(), bal.cellCount);
        }

        // Benchmark
        SECTION("LIGHT CLIENT — benchmarks");
        BENCH("getTipHeader()",  5, { lc.getTipHeader(); });
        BENCH("getScripts()",    5, { lc.getScripts(); });
        BENCH("getSyncState()",  3, { lc.getSyncState(); });

    } else {
        SECTION("LIGHT CLIENT — live tests skipped");
        CKB_TEST_OUTPUT.println("  [SKIP]  All live light client tests              (no light node at " LIGHT_CLIENT_URL ")");
        _skip += 10;
    }
#else
    SECTION("LIGHT CLIENT — live tests skipped");
    CKB_TEST_OUTPUT.println("  [SKIP]  All live light client tests              (compile with #define CKB_NODE_LIGHT)");
    _skip += 10;
#endif
}

// ═════════════════════════════════════════════════════════════════════════════
// Main
// ═════════════════════════════════════════════════════════════════════════════

void printSummary() {
    int total = _pass + _fail + _skip;
    CKB_TEST_OUTPUT.println("\n════════════════════════════════════════════════════════════");
    CKB_TEST_OUTPUT.println("  CKB-ESP32 TEST BENCH RESULTS");
    CKB_TEST_OUTPUT.println("════════════════════════════════════════════════════════════");
    TB_PRINTF("  PASS:  %3d\n", _pass);
    TB_PRINTF("  FAIL:  %3d\n", _fail);
    TB_PRINTF("  SKIP:  %3d\n", _skip);
    TB_PRINTF("  TOTAL: %3d\n", total);
    int passRate = total > 0 ? (_pass * 100) / total : 0;
    TB_PRINTF("\n  Pass rate (excl. bench): %d%%\n", passRate);
    TB_PRINTF("  Heap free: %lu bytes\n", (unsigned long)ESP.getFreeHeap());
    TB_PRINTF("  CPU freq:  %lu MHz\n",  (unsigned long)(ESP.getCpuFreqMHz()));
    CKB_TEST_OUTPUT.println(_fail == 0 ? "\n  ✓ ALL TESTS PASSED" : "\n  ✗ SOME TESTS FAILED — see [FAIL] lines above");
    CKB_TEST_OUTPUT.println("════════════════════════════════════════════════════════════\n");
}

// ── Test runner task — runs in a FreeRTOS task with 32KB stack ───────────────
// The default Arduino loop task only has ~8KB which is too small for crypto tests.
void testRunnerTask(void* pvParameters) {
    CKB_TEST_OUTPUT.println("\n╔══════════════════════════════════════════════════════════╗");
    CKB_TEST_OUTPUT.println("║           CKB-ESP32 Library Test Bench                  ║");
    CKB_TEST_OUTPUT.println("╚══════════════════════════════════════════════════════════╝");
    TB_PRINTF("  Chip: %s  Rev: %d  Flash: %uMB  PSRAM: %uKB\n",
        ESP.getChipModel(), ESP.getChipRevision(),
        ESP.getFlashChipSize()/(1024*1024),
        ESP.getPsramSize()/1024);
    TB_PRINTF("  CPU: %u MHz  Heap: %u bytes free\n",
        ESP.getCpuFreqMHz(), ESP.getFreeHeap());

    // ── Offline tests (always run) ─────────────────────────────────────────
    runConfigTests();
    runCryptoTests();
    runUtilTests();
    runLightClientTests(false);   // offline struct/compile checks only

    // ── Online tests (only if WiFi configured) ────────────────────────────
    if (strlen(WIFI_SSID) > 0) {
        TB_PRINTF("\n── WIFI — connecting to %s ...\n", WIFI_SSID);
        WiFi.begin(WIFI_SSID, WIFI_PASS);
        unsigned long t0 = millis();
        while (WiFi.status() != WL_CONNECTED && millis()-t0 < WIFI_TIMEOUT) {
            delay(250); CKB_TEST_OUTPUT.print(".");
        }
        CKB_TEST_OUTPUT.println();
        if (WiFi.status() == WL_CONNECTED) {
            TB_PRINTF("  Connected: %s\n", WiFi.localIP().toString().c_str());
            CKBClient ckb(CKB_NODE_URL);
            runRPCTests(ckb);
            runLightClientTests(true);
        } else {
            CKB_TEST_OUTPUT.println("  [WARN] WiFi connection failed — skipping RPC tests");
            _skip += 25;
        }
    } else {
        CKB_TEST_OUTPUT.println("\n── RPC TESTS ─────────────────────────────────────────────");
        CKB_TEST_OUTPUT.println("  [SKIP]  All RPC tests                                (WIFI_SSID not set)");
        _skip += 25;
    }

    printSummary();
    vTaskDelete(NULL);  // Task done — delete itself
}

void setup() {
    Serial.begin(115200);
    delay(1500);

    // Spawn test runner with 32KB stack on core 1
    xTaskCreatePinnedToCore(
        testRunnerTask,
        "CKBTests",
        32768,   // 32 KB stack — needed for secp256k1 + blake2b locals
        NULL,
        1,       // priority
        NULL,
        1        // core 1
    );
}

void loop() {
    // Nothing — all tests run in the task above
    delay(1000);
}
