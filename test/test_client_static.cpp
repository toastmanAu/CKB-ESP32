// test_client_static.cpp — CKBClient static utility methods (no WiFi/RPC needed)
// Build: see run_tests.sh
#define IRAM_ATTR
#define CKB_NODE_FULL
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "CKB.h"   // pulls in static methods; CKBTransport auto-selects POSIX

static int _pass=0,_fail=0;
#define PASS(n)      do{printf("  PASS: %s\n",n);_pass++;}while(0)
#define FAIL(n,m)    do{printf("  FAIL: %s  (%s)\n",n,m);_fail++;}while(0)
#define CHECK(c,n,m) do{if(c)PASS(n);else FAIL(n,m);}while(0)
#define SECTION(s)   printf("\n  [%s]\n",s)

int main(){
    printf("\n========================================\n");
    printf("  CKBClient static utilities\n");
    printf("========================================\n");

    SECTION("Shannon conversion");
    {
        CHECK(CKBClient::ckbToShannon(1.0f)==100000000ULL,
              "1.0 CKB = 100,000,000 shannon","wrong");
        CHECK(CKBClient::ckbToShannon(0.0f)==0ULL,
              "0 CKB = 0 shannon","wrong");
        CHECK(CKBClient::ckbToShannon(61.0f)==6100000000ULL,
              "61 CKB = 6,100,000,000 shannon","wrong");
        CHECK(CKBClient::shannonToCKBInt(100000000ULL)==1,
              "100M shannon = 1 CKB (int)","wrong");
        CHECK(CKBClient::shannonToCKBInt(0)==0,
              "0 shannon = 0 CKB","wrong");
        float ckb = CKBClient::shannonToCKB(100000000ULL);
        CHECK(fabsf(ckb-1.0f)<0.0001f,"100M shannon ≈ 1.0 CKB (float)","wrong");
        // Large value
        CHECK(CKBClient::shannonToCKBInt(6100000000ULL)==61,
              "6.1B shannon = 61 CKB","wrong");
    }

    SECTION("hexToUint64 / uint64ToHex");
    {
        CHECK(CKBClient::hexToUint64("0x0")==0,"0x0 == 0","wrong");
        CHECK(CKBClient::hexToUint64("0x1")==1,"0x1 == 1","wrong");
        CHECK(CKBClient::hexToUint64("0x100")==256,"0x100 == 256","wrong");
        CHECK(CKBClient::hexToUint64("0xff")==255,"0xff == 255","wrong");
        CHECK(CKBClient::hexToUint64("0xffffffffffffffff")==UINT64_MAX,
              "0xffff...ffff == UINT64_MAX","wrong");
        CHECK(CKBClient::hexToUint64("100")==256,"100 (no 0x) == 256","wrong");

        char buf[20]={};
        CKBClient::uint64ToHex(256,buf);
        CHECK(strcmp(buf,"0x100")==0,"uint64ToHex(256) == '0x100'",buf);
        CKBClient::uint64ToHex(0,buf);
        CHECK(strcmp(buf,"0x0")==0,"uint64ToHex(0) == '0x0'",buf);
        CKBClient::uint64ToHex(UINT64_MAX,buf);
        CHECK(strcmp(buf,"0xffffffffffffffff")==0,"uint64ToHex(UINT64_MAX) correct",buf);
    }

    SECTION("formatCKB / formatCKBCompact");
    {
        char buf[32]={};
        CKBClient::formatCKB(100000000ULL,buf,sizeof(buf));
        CHECK(strstr(buf,"1")!=NULL,"formatCKB(100M) contains '1'",buf);
        CHECK(strstr(buf,"CKB")!=NULL,"formatCKB contains 'CKB'",buf);

        CKBClient::formatCKBCompact(100000000ULL,buf,sizeof(buf));
        CHECK(strstr(buf,"CKB")!=NULL,"formatCKBCompact contains 'CKB'",buf);
        CHECK(strlen(buf)<strlen("1,000,000.000000 CKB"),"formatCKBCompact shorter","not shorter");

        // Large value
        CKBClient::formatCKBCompact(1000000000000000ULL,buf,sizeof(buf)); // 10M CKB
        CHECK(strstr(buf,"M")!=NULL||strstr(buf,"K")!=NULL||strstr(buf,"B")!=NULL,
              "formatCKBCompact large value uses suffix","no suffix");
    }

    SECTION("isValidTxHash");
    {
        CHECK(CKBClient::isValidTxHash(
              "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
              "valid 66-char hex hash","rejected");
        CHECK(!CKBClient::isValidTxHash(NULL),
              "NULL hash rejected","accepted");
        CHECK(!CKBClient::isValidTxHash(""),
              "empty hash rejected","accepted");
        CHECK(!CKBClient::isValidTxHash("0x1234"),
              "short hash rejected","accepted");
        CHECK(!CKBClient::isValidTxHash(
              "71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c"),
              "hash without 0x rejected","accepted");
        CHECK(!CKBClient::isValidTxHash(
              "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46X"),
              "hash with non-hex char rejected","accepted");
    }

    SECTION("isValidAddress — all three formats");
    {
        // Short (deprecated bech32, fmt=0x01)
        CHECK(CKBClient::isValidAddress("ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f"),
              "short secp256k1 addr (mainnet)","rejected");
        // Old full (deprecated bech32, fmt=0x00)
        CHECK(CKBClient::isValidAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s3d5s64"),
              "old full bech32 addr","rejected");
        // CKB2021 full (bech32m, fmt=0x00)
        CHECK(CKBClient::isValidAddress("ckb1qqzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqthw9h047vf94pxju85lkq8zsjn4mehvfgr96r"),
              "CKB2021 full bech32m addr","rejected");
        // Testnet
        CHECK(CKBClient::isValidAddress("ckt1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f"),
              "testnet short addr","rejected");
        CHECK(!CKBClient::isValidAddress(NULL),
              "NULL rejected","accepted");
        CHECK(!CKBClient::isValidAddress(""),
              "empty rejected","accepted");
        CHECK(!CKBClient::isValidAddress("btc1qshortaddr"),
              "non-CKB prefix rejected","accepted");
    }

    SECTION("decodeAddress — all three formats");
    {
        // Short (bech32, fmt=0x01)
        {
            CKBScript sc = CKBClient::decodeAddress("ckb1qyq829u0x32fchlfe5dqc4awh5q70h0eyj0q2zdh7f");
            CHECK(sc.valid,"short addr decodes valid","invalid");
            CHECK(strlen(sc.codeHash)>10,"short: codeHash non-empty","empty");
            CHECK(strcmp(sc.hashType,"type")==0,"short: hashType==type","wrong");
            // args = lock_args (blake160 of pubkey)
            CHECK(strstr(sc.args,"75178f34")!=NULL,"short: args contains lock_args","wrong args");
        }
        // Old full bech32 (fmt=0x00)
        {
            CKBScript sc = CKBClient::decodeAddress("ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s3d5s64");
            CHECK(sc.valid,"old full bech32 decodes valid","invalid");
            CHECK(strlen(sc.codeHash)>10,"old full: codeHash non-empty","empty");
            CHECK(strstr(sc.args,"75178f34")!=NULL,"old full: args contains lock_args","wrong args");
        }
        // CKB2021 full bech32m (fmt=0x00)
        {
            CKBScript sc = CKBClient::decodeAddress("ckb1qqzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqthw9h047vf94pxju85lkq8zsjn4mehvfgr96r");
            CHECK(sc.valid,"CKB2021 bech32m decodes valid","invalid");
            CHECK(strlen(sc.codeHash)>10,"CKB2021: codeHash non-empty","empty");
        }
    }
    SECTION("encodeAddress round-trip");
    {
        // CKB2021 → encode → starts with ckb1
        CKBScript sc = CKBClient::decodeAddress("ckb1qqzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqthw9h047vf94pxju85lkq8zsjn4mehvfgr96r");
        char out[120]={};
        CHECK(CKBClient::encodeAddress(sc,out,sizeof(out),"ckb"),
              "encodeAddress returns true","false");
        CHECK(strncmp(out,"ckb1",4)==0,"re-encoded starts ckb1","wrong prefix");
    }

    SECTION("nodeTypeStr");
    {
        const char* t=CKBClient::nodeTypeStr();
        CHECK(t!=NULL && strlen(t)>0,"nodeTypeStr returns non-empty string","empty/null");
    }

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n",_pass,_fail);
    printf("========================================\n");
    return _fail?1:0;
}
