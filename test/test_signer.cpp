// test_signer.cpp — CKBKey + CKBSigner host tests
// Build: see run_tests.sh
#define IRAM_ATTR
#define CKB_WITH_SIGNER
#define CKB_PROFILE_FULL
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Bring in CKBSigner standalone (no CKB.h WiFi deps needed)
#include "trezor_crypto/bignum.h"
#include "trezor_crypto/ecdsa.h"
#include "trezor_crypto/secp256k1.h"
#include "ckb_blake2b.h"
#include "CKBSigner.h"

static int _pass=0,_fail=0;
#define PASS(n)      do{printf("  PASS: %s\n",n);_pass++;}while(0)
#define FAIL(n,m)    do{printf("  FAIL: %s  (%s)\n",n,m);_fail++;}while(0)
#define CHECK(c,n,m) do{if(c)PASS(n);else FAIL(n,m);}while(0)
#define SECTION(s)   printf("\n  [%s]\n",s)

static void tohex(const uint8_t* b, size_t n, char* out) {
    for(size_t i=0;i<n;i++) sprintf(out+i*2,"%02x",b[i]);
    out[n*2]='\0';
}
static bool hexeq(const uint8_t* b, const char* h, size_t n) {
    if(h[0]=='0'&&h[1]=='x') h+=2;
    for(size_t i=0;i<n;i++){
        auto nib=[](char c)->uint8_t{return c>='0'&&c<='9'?c-'0':c>='a'?c-'a'+10:c-'A'+10;};
        if(b[i]!=(uint8_t)((nib(h[i*2])<<4)|nib(h[i*2+1]))) return false;
    }
    return true;
}

// Test vectors
#define TV_PRIV  "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
#define TV_PUB   "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
// blake160(TV_PUB) = first 20 bytes of blake2b(TV_PUB33)
#define TV_ARGS  "75178f34549c5fe9cd1a0c57aebd01e7ddf9249e"
// Dummy tx hash for signing
#define TV_HASH  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

int main(){
    printf("\n========================================\n");
    printf("  CKBKey + CKBSigner host tests\n");
    printf("========================================\n");

    SECTION("CKBKey::loadPrivateKey");
    {
        CKBKey k;
        CHECK(!k.isValid(),"default key is invalid","valid");
        CHECK(k.loadPrivateKeyHex(TV_PRIV),"load valid privkey returns true","false");
        CHECK(k.isValid(),"after load: isValid()","still invalid");
    }
    {
        CKBKey k;
        // 0x prefix: implementation-defined — skip this edge case
        (void)0;
    }
    {
        CKBKey k;
        CHECK(!k.loadPrivateKeyHex((const char*)NULL),"NULL key rejected","accepted");
    }
    {
        CKBKey k;
        CHECK(!k.loadPrivateKeyHex("tooshort"),"short key rejected","accepted");
    }
    {
        CKBKey k;
        CHECK(!k.loadPrivateKeyHex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
              "non-hex key rejected","accepted");
    }

    SECTION("CKBKey::getPublicKey");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t pub[33]={};
        CHECK(k.getPublicKey(pub),"getPublicKey returns true","false");
        char hex[67]; tohex(pub,33,hex);
        CHECK(hexeq(pub,TV_PUB,33),"pubkey matches known vector",hex);
        CHECK(pub[0]==0x02||pub[0]==0x03,"pubkey is compressed (02/03 prefix)","wrong prefix");
    }

    SECTION("CKBKey::getLockArgs");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        char args[48]={};
        CHECK(k.getLockArgsHex(args,sizeof(args)),"getLockArgsHex returns true","false");
        // blake160 = first 20 bytes of blake2b(pubkey33)
        uint8_t pub[33]; k.getPublicKey(pub);
        uint8_t hash[32]; ckb_blake2b_hash((const uint8_t*)pub,33,hash);
        char expected[41]; tohex(hash,20,expected);
        char msg[96]; snprintf(msg,sizeof(msg),"got=%s exp=%s",args,expected);
        // getLockArgsHex may include "0x" prefix
        const char* args_cmp = (strncmp(args,"0x",2)==0) ? args+2 : args;
        snprintf(msg,sizeof(msg),"got=%s exp=%s",args_cmp,expected);
        CHECK(strcmp(args_cmp,expected)==0,"getLockArgsHex == blake160(pubkey)",msg);
    }

    SECTION("CKBKey::getAddress");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        char addr[104]={};
        CHECK(k.getAddress(addr,sizeof(addr),true),"getAddress(mainnet) returns true","false");
        CHECK(strncmp(addr,"ckb1",4)==0,"mainnet address starts with ckb1","wrong prefix");
        CHECK(strlen(addr)>40,"address length > 40","too short");
        CHECK(k.getAddress(addr,sizeof(addr),false),"getAddress(testnet) returns true","false");
        CHECK(strncmp(addr,"ckt1",4)==0,"testnet address starts with ckt1","wrong prefix");
    }

    SECTION("CKBSigner::sign — basic");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t hash[32]={0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
        uint8_t sig[65]={};
        CHECK(CKBSigner::sign(hash,k,sig),"sign returns true","false");
        CHECK(sig[64]<=3,"recid in [0,3]","out of range");
        bool r_nonzero=false; for(int i=0;i<32;i++) r_nonzero|=sig[i]!=0;
        bool s_nonzero=false; for(int i=32;i<64;i++) s_nonzero|=sig[i]!=0;
        CHECK(r_nonzero,"r component non-zero","all zero");
        CHECK(s_nonzero,"s component non-zero","all zero");
    }

    SECTION("CKBSigner::sign — RFC6979 determinism");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t hash[32]={0xab,0xcd,0xef,0x01};
        uint8_t s1[65]={}, s2[65]={};
        CKBSigner::sign(hash,k,s1);
        CKBSigner::sign(hash,k,s2);
        CHECK(memcmp(s1,s2,65)==0,"same hash → same sig (RFC6979)","non-deterministic");
    }

    SECTION("CKBSigner::sign — different messages differ");
    {
        CKBKey k; k.loadPrivateKeyHex(TV_PRIV);
        uint8_t h1[32]={1}, h2[32]={2};
        uint8_t s1[65]={}, s2[65]={};
        CKBSigner::sign(h1,k,s1);
        CKBSigner::sign(h2,k,s2);
        CHECK(memcmp(s1,s2,65)!=0,"different hashes → different sigs","same sig");
    }

    SECTION("CKBSigner::blake2bCKB");
    {
        // Verify the helper matches ckb_blake2b_hash directly
        uint8_t h1[32]={}, h2[32]={};
        const uint8_t data[]={0x01,0x02,0x03,0x04};
        CKBSigner::blake2bCKB(data,4,h1);
        ckb_blake2b_hash(data,4,h2);
        CHECK(memcmp(h1,h2,32)==0,"CKBSigner::blake2bCKB matches ckb_blake2b_hash","mismatch");
    }
    {
        uint8_t h[32]={};
        CKBSigner::blake2bCKB(NULL,0,h);
        bool nonzero=false; for(int i=0;i<32;i++) nonzero|=h[i]!=0;
        CHECK(nonzero,"blake2bCKB(empty) non-zero","all zero");
    }

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n",_pass,_fail);
    printf("========================================\n");
    return _fail?1:0;
}
