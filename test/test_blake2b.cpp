// test_blake2b.cpp — CKB Blake2b-256 (personalised "ckb-default-hash")
// Build: g++ -DHOST_TEST -std=c++17 -Isrc -Isrc/blake2b test/test_blake2b.cpp src/blake2b/blake2b.c -o test/test_blake2b
#define IRAM_ATTR
#include "../src/ckb_blake2b.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static int _pass=0,_fail=0;
#define PASS(n)     do{printf("  PASS: %s\n",n);_pass++;}while(0)
#define FAIL(n,m)   do{printf("  FAIL: %s  (%s)\n",n,m);_fail++;}while(0)
#define CHECK(c,n,m) do{if(c)PASS(n);else FAIL(n,m);}while(0)
#define SECTION(s)  printf("\n  [%s]\n",s)

static bool hexeq(const uint8_t*b,const char*h){
    if(h[0]=='0'&&h[1]=='x')h+=2;
    for(int i=0;i<32;i++){
        auto nib=[](char c)->uint8_t{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:0;};
        if(b[i]!=(uint8_t)((nib(h[i*2])<<4)|nib(h[i*2+1])))return false;
    }
    return true;
}
static void tohex(const uint8_t*b,char*out){for(int i=0;i<32;i++)sprintf(out+i*2,"%02x",b[i]);}

// CKB-personalised known vectors (verified against reference impl)
#define TV_EMPTY "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e"
#define TV_HELLO "2da1289373a9f6b7ed21db948f4dc5d942cf4023eaef1d5a2b1a45b9d12d1036"
#define TV_ABC   "521c604cc09b814b0a9106305395def35d0211b9996a3e0f326ae4d671bd8fc2"

int main(){
    printf("\n========================================\n");
    printf("  ckb_blake2b host tests\n");
    printf("========================================\n");
    uint8_t h[32]; char hex[65];

    SECTION("Known vectors");
    {
        CKB_Blake2b ctx; ckb_blake2b_init(&ctx); ckb_blake2b_final(&ctx,h);
        tohex(h,hex);
        CHECK(hexeq(h,TV_EMPTY),"Blake2b(empty) == known vector",hex);
    }
    {
        CKB_Blake2b ctx; ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx,(uint8_t*)"hello",5);
        ckb_blake2b_final(&ctx,h); tohex(h,hex);
        CHECK(hexeq(h,TV_HELLO),"Blake2b('hello') == known vector",hex);
    }
    {
        CKB_Blake2b ctx; ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx,(uint8_t*)"abc",3);
        ckb_blake2b_final(&ctx,h); tohex(h,hex);
        CHECK(hexeq(h,TV_ABC),"Blake2b('abc') == known vector",hex);
    }

    SECTION("Incremental == one-shot");
    {
        const char*msg="hello world";
        uint8_t h1[32],h2[32];
        CKB_Blake2b c1,c2;
        ckb_blake2b_init(&c1);
        ckb_blake2b_update(&c1,(uint8_t*)msg,strlen(msg));
        ckb_blake2b_final(&c1,h1);

        ckb_blake2b_init(&c2);
        ckb_blake2b_update(&c2,(uint8_t*)msg,5);
        ckb_blake2b_update(&c2,(uint8_t*)msg+5,strlen(msg)-5);
        ckb_blake2b_final(&c2,h2);
        CHECK(memcmp(h1,h2,32)==0,"incremental == one-shot","mismatch");
    }
    {
        // 4-part incremental
        const char*p[]={"aa","bb","cc","dd"};
        uint8_t hfull[32],hpart[32];
        char full[9]="aabbccdd";
        CKB_Blake2b cx; ckb_blake2b_init(&cx);
        ckb_blake2b_update(&cx,(uint8_t*)full,8); ckb_blake2b_final(&cx,hfull);
        ckb_blake2b_init(&cx);
        for(int i=0;i<4;i++) ckb_blake2b_update(&cx,(uint8_t*)p[i],2);
        ckb_blake2b_final(&cx,hpart);
        CHECK(memcmp(hfull,hpart,32)==0,"4-part incremental == one-shot","mismatch");
    }

    SECTION("Convenience function");
    {
        uint8_t h1[32],h2[32];
        ckb_blake2b_hash((uint8_t*)"hello",5,h1);
        CKB_Blake2b ctx; ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx,(uint8_t*)"hello",5);
        ckb_blake2b_final(&ctx,h2);
        CHECK(memcmp(h1,h2,32)==0,"ckb_blake2b_hash() == manual","mismatch");
    }

    SECTION("Re-init");
    {
        uint8_t h1[32],h2[32];
        CKB_Blake2b ctx;
        ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx,(uint8_t*)"first",5);
        ckb_blake2b_final(&ctx,h1);

        ckb_blake2b_init(&ctx); // re-use
        ckb_blake2b_update(&ctx,(uint8_t*)"first",5);
        ckb_blake2b_final(&ctx,h2);
        CHECK(memcmp(h1,h2,32)==0,"re-init produces same result","mismatch");

        ckb_blake2b_init(&ctx);
        ckb_blake2b_update(&ctx,(uint8_t*)"second",6);
        ckb_blake2b_final(&ctx,h2);
        CHECK(memcmp(h1,h2,32)!=0,"re-init with different input differs","same as prev");
    }

    SECTION("Edge cases");
    {
        uint8_t zeros[64]={0}, ff[64]; memset(ff,0xff,64);
        uint8_t hz[32],hf[32];
        ckb_blake2b_hash(zeros,64,hz);
        ckb_blake2b_hash(ff,64,hf);
        CHECK(memcmp(hz,hf,32)!=0,"all-zeros != all-0xff","same hash");
        // Single byte
        ckb_blake2b_hash(zeros,1,hz);
        ckb_blake2b_hash(zeros,1,hf);
        CHECK(memcmp(hz,hf,32)==0,"single byte deterministic","non-deterministic");
    }
    {
        // Large input (1 KB) — shouldn't crash
        uint8_t big[1024]; memset(big,0x5a,sizeof(big));
        ckb_blake2b_hash(big,sizeof(big),h);
        bool nonzero=false; for(int i=0;i<32;i++) nonzero|=h[i]!=0;
        CHECK(nonzero,"1KB input produces non-zero hash","all zero output");
    }

    SECTION("Output is always 32 bytes non-zero (for non-empty input)");
    {
        ckb_blake2b_hash((uint8_t*)"x",1,h);
        bool nonzero=false; for(int i=0;i<32;i++) nonzero|=h[i]!=0;
        CHECK(nonzero,"hash of 'x' is non-zero","all-zero");
    }

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n",_pass,_fail);
    printf("========================================\n");
    return _fail?1:0;
}
