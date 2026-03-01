// test_bip39.cpp — ckb_bip39.h: mnemonic→seed, BIP32, CKB key derivation
// Build: see run_tests.sh (needs trezor_crypto objects)
#define IRAM_ATTR
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// trezor_crypto vendored version uses ubtc_ prefix — shim before ckb_bip39.h
#include "trezor_crypto/hmac.h"
#define hmac_sha512_Init   ubtc_hmac_sha512_Init
#define hmac_sha512_Update ubtc_hmac_sha512_Update
#define hmac_sha512_Final  ubtc_hmac_sha512_Final
#define hmac_sha512        ubtc_hmac_sha512
#include "trezor_crypto/bignum.h"

#include "ckb_bip39.h"

static int _pass=0,_fail=0;
#define PASS(n)      do{printf("  PASS: %s\n",n);_pass++;}while(0)
#define FAIL(n,m)    do{printf("  FAIL: %s  (%s)\n",n,m);_fail++;}while(0)
#define CHECK(c,n,m) do{if(c)PASS(n);else FAIL(n,m);}while(0)
#define SECTION(s)   printf("\n  [%s]\n",s)

// BIP39 reference vector — abandon x11 + about, CKB path m/44'/309'/0'/0/0
// Derived privkey verified against CKB-ESP32 implementation
#define TV_MNEMONIC "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#define TV_PRIVKEY  "b217d9a18ff657c99872cc11a2fa2aa3e970cef8c6faa7d6e424bf057cb3707b"

// Known secp256k1 test key (from CKBTestBench)
#define KNOWN_PRIV  "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"

int main(){
    printf("\n========================================\n");
    printf("  ckb_bip39 host tests\n");
    printf("========================================\n");

    SECTION("input validation (via ckb_mnemonic_to_privkey)");
    {
        char pk[65]={0}, addr[104]={0};
        CHECK(ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,pk,addr)==0,
              "valid 12-word mnemonic accepted","non-zero");
        CHECK(ckb_mnemonic_to_privkey(NULL,"",0,0,pk,addr)!=0,
              "NULL mnemonic rejected","returned 0");
        CHECK(ckb_mnemonic_to_privkey("","",0,0,pk,addr)!=0,
              "empty mnemonic rejected","returned 0");
        CHECK(ckb_mnemonic_to_privkey("abandon","",0,0,pk,addr)!=0,
              "single-word mnemonic rejected","returned 0");
    }

    SECTION("known BIP39 vector");
    {
        char pk[65]={0}, addr[104]={0};
        int rc=ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,pk,addr);
        CHECK(rc==0,"mnemonic_to_privkey returns 0","non-zero");
        char msg[80]; snprintf(msg,sizeof(msg),"got=%s",pk);
        CHECK(strcmp(pk,TV_PRIVKEY)==0,"privkey matches reference vector",msg);
        CHECK(strlen(pk)==64,"privkey is 64 hex chars","wrong len");
        CHECK(strncmp(addr,"ckb1",4)==0,"address starts with ckb1","wrong prefix");
    }

    SECTION("passphrase changes derived key");
    {
        char p1[65]={0},p2[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,p1,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"passphrase",0,0,p2,NULL);
        CHECK(strcmp(p1,p2)!=0,"passphrase produces different key","same key");
    }

    SECTION("different indices produce different keys");
    {
        char k0[65]={0},k1[65]={0},k2[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,k0,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,1,k1,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,2,k2,NULL);
        CHECK(strcmp(k0,k1)!=0,"index 0 != index 1","same key");
        CHECK(strcmp(k1,k2)!=0,"index 1 != index 2","same key");
    }

    SECTION("different accounts produce different keys");
    {
        char a0[65]={0},a1[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,a0,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",1,0,a1,NULL);
        CHECK(strcmp(a0,a1)!=0,"account 0 != account 1","same key");
    }

    SECTION("deterministic — same inputs same output");
    {
        char r1[65]={0},r2[65]={0};
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,r1,NULL);
        ckb_mnemonic_to_privkey(TV_MNEMONIC,"",0,0,r2,NULL);
        CHECK(strcmp(r1,r2)==0,"two calls same inputs == same key","non-deterministic");
    }

    SECTION("ckb_privkey_to_address");
    {
        char addr[104]={0};
        CHECK(ckb_privkey_to_address(KNOWN_PRIV,addr)==0,
              "known privkey returns 0","non-zero");
        CHECK(strncmp(addr,"ckb1",4)==0,"address starts with ckb1","wrong prefix");
        CHECK(strlen(addr)>40,"address length > 40","too short");
        char msg[96]; snprintf(msg,sizeof(msg),"got=%s",addr);
        CHECK(addr[3]=='1',"address[3]=='1'",msg);
    }
    {
        char addr[104]={0};
        CHECK(ckb_privkey_to_address(
              "0000000000000000000000000000000000000000000000000000000000000000",addr)!=0,
              "zero privkey rejected","returned 0");
    }
    {
        char addr[104]={0};
        CHECK(ckb_privkey_to_address(NULL,addr)!=0,
              "NULL privkey rejected","returned 0");
    }
    {
        char addr[104]={0};
        CHECK(ckb_privkey_to_address("tooshort",addr)!=0,
              "short privkey rejected","returned 0");
    }

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n",_pass,_fail);
    printf("========================================\n");
    return _fail?1:0;
}
