// test_molecule.cpp — ckb_molecule.h buffer + Molecule serialisation
// Build: g++ -DHOST_TEST -std=c++17 -Isrc -Isrc/blake2b test/test_molecule.cpp src/blake2b/blake2b.c -o test/test_molecule
#define IRAM_ATTR
#include "../src/ckb_molecule.h"
#include "../src/ckb_blake2b.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int _pass=0,_fail=0;
#define PASS(n)      do{printf("  PASS: %s\n",n);_pass++;}while(0)
#define FAIL(n,m)    do{printf("  FAIL: %s  (%s)\n",n,m);_fail++;}while(0)
#define CHECK(c,n,m) do{if(c)PASS(n);else FAIL(n,m);}while(0)
#define SECTION(s)   printf("\n  [%s]\n",s)

static uint32_t le32(const uint8_t*b){return b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24);}
static uint64_t le64(const uint8_t*b){uint64_t v=0;for(int i=7;i>=0;i--)v=(v<<8)|b[i];return v;}

int main(){
    printf("\n========================================\n");
    printf("  ckb_molecule host tests\n");
    printf("========================================\n");

    SECTION("CKBBuf basic operations");
    {
        uint8_t storage[64]; CKBBuf b; ckb_buf_init(&b,storage,64);
        CHECK(b.len==0,"buf init: len==0","wrong");
        CHECK(b.cap==64,"buf init: cap==64","wrong");
        CHECK(ckb_buf_write_u8(&b,0x42),"write_u8 returns true","false");
        CHECK(b.len==1,"after write_u8: len==1","wrong");
        CHECK(storage[0]==0x42,"write_u8 correct value","wrong");
    }
    {
        uint8_t storage[16]; CKBBuf b; ckb_buf_init(&b,storage,16);
        ckb_buf_write_u32le(&b,0xDEADBEEF);
        CHECK(b.len==4,"write_u32le: len==4","wrong");
        CHECK(le32(storage)==0xDEADBEEF,"write_u32le correct LE","wrong");
    }
    {
        uint8_t storage[16]; CKBBuf b; ckb_buf_init(&b,storage,16);
        ckb_buf_write_u64le(&b,0x0102030405060708ULL);
        CHECK(b.len==8,"write_u64le: len==8","wrong");
        CHECK(le64(storage)==0x0102030405060708ULL,"write_u64le correct LE","wrong");
    }
    {
        // hex write
        uint8_t storage[8]; CKBBuf b; ckb_buf_init(&b,storage,8);
        CHECK(ckb_buf_write_hex(&b,"0xdeadbeef",4),"write_hex returns true","false");
        CHECK(b.len==4,"write_hex: len==4","wrong");
        CHECK(storage[0]==0xde&&storage[1]==0xad&&storage[2]==0xbe&&storage[3]==0xef,
              "write_hex correct bytes","wrong bytes");
    }
    {
        // overflow protection
        uint8_t storage[2]; CKBBuf b; ckb_buf_init(&b,storage,2);
        ckb_buf_write_u8(&b,1); ckb_buf_write_u8(&b,2);
        CHECK(!ckb_buf_write_u8(&b,3),"overflow: write_u8 returns false","returned true");
        CHECK(b.len==2,"overflow: len unchanged at 2","wrong");
    }

    SECTION("mol_write_witness_placeholder");
    {
        // Standard 65-byte lock placeholder
        // Expected structure: table header + 3 field offsets + fields
        // lock field = bytes(0x00*65) = 4(len) + 65(data) = 69
        // input_type = none (bytes(empty)) = 4+0=4
        // output_type = none = 4+0=4
        // table = 4(total) + 4(offset_count) + 3*4(offsets) + 69+4+4 = 4+4+12+77=97? 
        // Actual: verified empirically
        uint8_t storage[256]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        size_t len=mol_write_witness_placeholder(&b);
        CHECK(len>0,"witness placeholder: len>0","zero");
        CHECK(b.len==len,"witness placeholder: buf.len==returned len","mismatch");
        // total_size field (first 4 bytes) must match actual length
        uint32_t total=le32(storage);
        char msg[32]; snprintf(msg,32,"total=%u len=%zu",total,(size_t)len);
        CHECK(total==(uint32_t)len,"witness placeholder: total_size field correct",msg);
        // Must be > 65 (contains 65 zero bytes + headers)
        CHECK(len>65,"witness placeholder: len > 65 bytes","too short");
    }

    SECTION("mol_write_script");
    {
        uint8_t storage[256]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        const char* CH="0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
        size_t len=mol_write_script(&b,CH,"type","0x");
        CHECK(len>4,"mol_write_script: len>4","too small");
        uint32_t total=le32(storage);
        char msg[32]; snprintf(msg,32,"total=%u len=%zu",total,(size_t)len);
        CHECK(total==(uint32_t)len,"mol_write_script: total_size correct",msg);
        // code_hash (32 bytes) should appear in the output
        uint8_t ch_bytes[32];
        for(int i=0;i<32;i++){
            const char*h=CH+2+i*2;
            auto nib=[](char c)->uint8_t{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:0;};
            ch_bytes[i]=(uint8_t)((nib(h[0])<<4)|nib(h[1]));
        }
        bool found=false;
        for(size_t i=0;i+32<=len;i++) if(memcmp(storage+i,ch_bytes,32)==0){found=true;break;}
        CHECK(found,"mol_write_script: code_hash survives in output","not found");
    }
    {
        // hash_type "data" vs "type" produce different output
        uint8_t s1[256],s2[256]; CKBBuf b1,b2;
        ckb_buf_init(&b1,s1,256); ckb_buf_init(&b2,s2,256);
        const char* CH="0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
        size_t l1=mol_write_script(&b1,CH,"data","0x");
        size_t l2=mol_write_script(&b2,CH,"type","0x");
        CHECK(memcmp(s1,s2,l1>l2?l2:l1)!=0,"hash_type data != type","same bytes");
    }

    SECTION("mol_write_outpoint");
    {
        uint8_t storage[64]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        const char* TX="0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c";
        mol_write_outpoint(&b,TX,0);
        CHECK(b.len==36,"outpoint: exactly 36 bytes (32 hash + 4 index)","wrong len");
        // index 0 → last 4 bytes LE = 0x00000000
        CHECK(le32(storage+32)==0,"outpoint index 0 = LE 0x00000000","wrong");
    }
    {
        uint8_t storage[64]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        const char* TX="0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c";
        mol_write_outpoint(&b,TX,7);
        CHECK(le32(storage+32)==7,"outpoint index 7 = LE 0x00000007","wrong");
    }

    SECTION("mol_write_cellinput");
    {
        uint8_t storage[64]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        const char* TX="0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c";
        mol_write_cellinput(&b,TX,0,0); // since=0
        // cellinput = since(8 LE) + outpoint(36) = 44
        CHECK(b.len==44,"cellinput: 44 bytes (8 since + 36 outpoint)","wrong len");
        CHECK(le64(storage)==0,"cellinput since=0 correct","wrong");
    }

    SECTION("mol_write_celloutput");
    {
        uint8_t storage[256]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        const char* CH="0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
        uint64_t cap=6100000000ULL; // 61 CKB
        mol_write_celloutput(&b,cap,CH,"type","0x");
        CHECK(b.len>8,"celloutput: len > 8","too short");
        // capacity is at offset 16 (after total_size + 3 field offsets = 4+12)
        uint64_t got_cap=le64(storage+16);
        char msg[32]; snprintf(msg,32,"got=%llu",(unsigned long long)got_cap);
        CHECK(got_cap==cap,"celloutput: capacity LE u64 correct",msg);
    }

    SECTION("mol_write_bytes");
    {
        uint8_t storage[32]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        uint8_t payload[]={0xDE,0xAD,0xBE,0xEF};
        mol_write_bytes(&b,payload,4);
        // bytes = 4(len LE u32) + 4(data) = 8
        CHECK(b.len==8,"mol_write_bytes: 8 bytes total","wrong");
        CHECK(le32(storage)==4,"mol_write_bytes: length prefix == 4","wrong");
        CHECK(memcmp(storage+4,payload,4)==0,"mol_write_bytes: payload intact","corrupted");
    }
    {
        // Empty bytes
        uint8_t storage[8]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        mol_write_bytes(&b,NULL,0);
        CHECK(b.len==4,"mol_write_bytes(empty): 4 bytes","wrong");
        CHECK(le32(storage)==0,"mol_write_bytes(empty): length prefix == 0","wrong");
    }

    SECTION("ckb_buf_patch_u32le");
    {
        uint8_t storage[8]; CKBBuf b; ckb_buf_init(&b,storage,sizeof(storage));
        ckb_buf_write_u32le(&b,0xAAAAAAAA);
        ckb_buf_write_u32le(&b,0xBBBBBBBB);
        ckb_buf_patch_u32le(&b,0,0x12345678); // patch first word
        CHECK(le32(storage  )==0x12345678,"patch first u32 correct","wrong");
        CHECK(le32(storage+4)==0xBBBBBBBB,"second u32 unchanged","corrupted");
    }

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n",_pass,_fail);
    printf("========================================\n");
    return _fail?1:0;
}
