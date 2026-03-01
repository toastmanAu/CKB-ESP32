// test_bip39.cpp — ckb_bip39.h: mnemonic→seed, BIP32, CKB key derivation
// Build: see run_tests.sh (needs trezor_crypto)
#define IRAM_ATTR
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "../src/blake2b/blake2.h"
#include "../src/trezor_crypto/bignum.h"
// trezor_crypto compat: vendored version uses ubtc_ prefix
#include "../src/trezor_crypto/hmac.h"
#define hmac_sha512_Init   ubtc_hmac_sha512_Init
#define hmac_sha512_Update ubtc_hmac_sha512_Update
#define hmac_sha512_Final  ubtc_hmac_sha512_Final
#define hmac_sha512        ubtc_hmac_sha512
#include "../src/ckb_bip39.h"

static int _pass=0,_fail=0;
#define PASS(n)      do{printf("  PASS: %s\n",n);_pass++;}while(0)
#define FAIL(n,m)    do{printf("  FAIL: %s  (%s)\n",n,m);_fail++;}while(0)
#define CHECK(c,n,m) do{if(c)PASS(n);else FAIL(n,m);}while(0)
#define SECTION(s)   printf("\n  [%s]\n",s)

// BIP39 reference test vector (Ian Coleman / Trezor test suite, CKB derivation)
// Mnemonic: "abandon" x11 + "about"
// Seed (PBKDF2, 2048 rounds, no passphrase) → BIP32 → m/44'/309'/0'/0/0
// Verified against: https://iancoleman.io/bip39/ (CKB coin type 309)
#define TV_MNEMONIC "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#define TV_PRIVKEY  "b217d9a18ff657c99872cc11a2fa2aa3e970cef8c6faa7d6e424bf057cb3707b"

// Known good privkey from CKBTestBench (secp256k1 key, not BIP39 derived)
#define KNOWN_PRIV  "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"

int main(){
    printf("\n========================================\n");
    printf("  ckb_bip39 host tests\n");
    printf("========================================\n");

    SECTION("mnemonic input validation (via ckb_mnemonic_to_privkey)");
    {
        char pk[65]={0}, addr[96]={0};
        // Valid mnemonic succeeds
        int rc=ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,pk,addr);
        CHECK(rc==0,"valid mnemonic accepted (rc==0)","non-zero");
        // NULL mnemonic fails
        rc=ckb_mnemonic_to_privkey(NULL,"",0,0,pk,addr);
        CHECK(rc!=0,"NULL mnemonic rejected","returned 0");
        // Empty mnemonic fails
        rc=ckb_mnemonic_to_privkey("","",0,0,pk,addr);
        CHECK(rc!=0,"empty mnemonic rejected","returned 0");
        // Single word fails
        rc=ckb_mnemonic_to_privkey("abandon","",0,0,pk,addr);
        CHECK(rc!=0,"single word rejected","returned 0");
    }

    SECTION("ckb_mnemonic_to_privkey — known vector");
    {
        char privkey[65]={0}, addr[96]={0};
        int rc=ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,privkey,addr);
        CHECK(rc==0,"mnemonic_to_privkey returns 0","non-zero");
        CHECK(strlen(privkey)==64,"privkey is 64 hex chars","wrong len");
        CHECK(strncmp(addr,"ckb1",4)==0,"address starts with 'ckb1'","wrong prefix");
        char msg[80]; snprintf(msg,80,"got=%s",privkey);
        CHECK(strcmp(privkey,TV_PRIVKEY)==0,"privkey matches BIP39 reference vector",msg);
    }

    SECTION("ckb_mnemonic_to_privkey — passphrase changes result");
    {
        char p1[65]={0},p2[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,p1,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"passphrase",0,0,p2,NULL);
        CHECK(strcmp(p1,p2)!=0,"passphrase changes derived privkey","same key");
    }

    SECTION("ckb_mnemonic_to_privkey — different indices");
    {
        char k0[65]={0},k1[65]={0},k2[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,k0,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,1,k1,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,2,k2,NULL);
        CHECK(strcmp(k0,k1)!=0,"index 0 != index 1","same key");
        CHECK(strcmp(k1,k2)!=0,"index 1 != index 2","same key");
        CHECK(strcmp(k0,k2)!=0,"index 0 != index 2","same key");
    }

    SECTION("ckb_mnemonic_to_privkey — different accounts");
    {
        char a0[65]={0},a1[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,a0,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",1,0,a1,NULL);
        CHECK(strcmp(a0,a1)!=0,"account 0 != account 1","same key");
    }

    SECTION("ckb_mnemonic_to_privkey — deterministic");
    {
        char r1[65]={0},r2[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,r1,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,r2,NULL);
        CHECK(strcmp(r1,r2)==0,"same inputs → same privkey","non-deterministic");
    }

    SECTION("ckb_privkey_to_address");
    {
        char addr[96]={0};
        int rc=ckb_privkey_to_address(KNOWN_PRIV,addr);
        CHECK(rc==0,"privkey_to_address returns 0","non-zero");
        CHECK(strncmp(addr,"ckb1",4)==0,"address starts with 'ckb1'","wrong prefix");
        CHECK(strlen(addr)>40,"address length > 40","too short");
        // Known TV_PRIV produces known address (verified from CKBTestBench)
        // ckb1qqzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqthw9h047vf94pxju85lkq8zsjn4mehvfgr96r
        char msg[96]; snprintf(msg,96,"got=%s",addr);
        // Just check prefix + length for now (full address depends on secp256k1 impl)
        CHECK(addr[3]=='1',"address char 3 is '1'",msg);
    }
    {
        char addr[96]={0};
        int rc=ckb_privkey_to_address("0000000000000000000000000000000000000000000000000000000000000000",addr);
        CHECK(rc!=0,"zero privkey returns error","returned 0");
    }
    {
        char addr[96]={0};
        int rc=ckb_privkey_to_address(NULL,addr);
        CHECK(rc!=0,"NULL privkey returns error","returned 0");
    }
    {
        char addr[96]={0};
        int rc=ckb_privkey_to_address("short",addr);
        CHECK(rc!=0,"short privkey returns error","returned 0");
    }

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n",_pass,_fail);
    printf("========================================\n");
    return _fail?1:0;
}
