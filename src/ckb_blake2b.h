// ckb_blake2b.h — Minimal Blake2b-256 for CKB-ESP32
// Adapted from the public domain reference implementation.
// CKB uses Blake2b-256 with personalisation "ckb-default-hash"
//
// Usage:
//   CKB_Blake2b ctx;
//   ckb_blake2b_init(&ctx);
//   ckb_blake2b_update(&ctx, data, len);
//   ckb_blake2b_final(&ctx, hash32);

#pragma once
#include <stdint.h>
#include <string.h>

#define CKB_BLAKE2B_OUTBYTES 32
#define CKB_BLAKE2B_BLOCKBYTES 128
#define CKB_BLAKE2B_PERSONALBYTES 16
#define CKB_BLAKE2B_PERSONAL "ckb-default-hash"

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[CKB_BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    uint8_t  last_node;
} CKB_Blake2b;

static const uint64_t _ckb_blake2b_IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const uint8_t _ckb_blake2b_sigma[12][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3}
};

static inline uint64_t _ckb_rotr64(uint64_t x, int n) { return (x >> n) | (x << (64-n)); }

static void _ckb_blake2b_compress(CKB_Blake2b* S, const uint8_t block[CKB_BLAKE2B_BLOCKBYTES]) {
    uint64_t m[16], v[16];
    for (int i = 0; i < 16; i++) {
        uint64_t tmp = 0;
        for (int j = 0; j < 8; j++) tmp |= ((uint64_t)block[i*8+j]) << (j*8);
        m[i] = tmp;
    }
    for (int i = 0; i < 8; i++) v[i] = S->h[i];
    v[8]  = _ckb_blake2b_IV[0]; v[9]  = _ckb_blake2b_IV[1];
    v[10] = _ckb_blake2b_IV[2]; v[11] = _ckb_blake2b_IV[3];
    v[12] = _ckb_blake2b_IV[4] ^ S->t[0];
    v[13] = _ckb_blake2b_IV[5] ^ S->t[1];
    v[14] = _ckb_blake2b_IV[6] ^ S->f[0];
    v[15] = _ckb_blake2b_IV[7] ^ S->f[1];
#define CKB_G(r,i,a,b,c,d) \
    a = a + b + m[_ckb_blake2b_sigma[r][2*i]]; \
    d = _ckb_rotr64(d^a,32); c = c+d; b=_ckb_rotr64(b^c,24); \
    a = a + b + m[_ckb_blake2b_sigma[r][2*i+1]]; \
    d = _ckb_rotr64(d^a,16); c = c+d; b=_ckb_rotr64(b^c,63);
    for (int r = 0; r < 12; r++) {
        CKB_G(r,0,v[0],v[4],v[8],v[12]);  CKB_G(r,1,v[1],v[5],v[9],v[13]);
        CKB_G(r,2,v[2],v[6],v[10],v[14]); CKB_G(r,3,v[3],v[7],v[11],v[15]);
        CKB_G(r,4,v[0],v[5],v[10],v[15]); CKB_G(r,5,v[1],v[6],v[11],v[12]);
        CKB_G(r,6,v[2],v[7],v[8],v[13]);  CKB_G(r,7,v[3],v[4],v[9],v[14]);
    }
#undef CKB_G
    for (int i = 0; i < 8; i++) S->h[i] ^= v[i] ^ v[i+8];
}

static inline void _ckb_blake2b_increment_counter(CKB_Blake2b* S, uint64_t inc) {
    S->t[0] += inc;
    if (S->t[0] < inc) S->t[1]++;
}

static inline void ckb_blake2b_init(CKB_Blake2b* S) {
    memset(S, 0, sizeof(CKB_Blake2b));
    // IV XOR parameter block: outlen=32, fanout=1, depth=1, personal="ckb-default-hash"
    uint8_t P[64] = {0};
    P[0] = CKB_BLAKE2B_OUTBYTES; // digest length
    P[1] = 0;                     // key length (no key)
    P[2] = 1;                     // fanout
    P[3] = 1;                     // depth
    // personalisation at offset 48
    memcpy(P + 48, CKB_BLAKE2B_PERSONAL, 16);
    uint64_t p0; memcpy(&p0, P,    8);
    uint64_t p1; memcpy(&p1, P+8,  8);
    uint64_t p6; memcpy(&p6, P+48, 8);
    uint64_t p7; memcpy(&p7, P+56, 8);
    S->h[0] = _ckb_blake2b_IV[0] ^ p0;
    S->h[1] = _ckb_blake2b_IV[1] ^ p1;
    S->h[2] = _ckb_blake2b_IV[2];
    S->h[3] = _ckb_blake2b_IV[3];
    S->h[4] = _ckb_blake2b_IV[4];
    S->h[5] = _ckb_blake2b_IV[5];
    S->h[6] = _ckb_blake2b_IV[6] ^ p6;
    S->h[7] = _ckb_blake2b_IV[7] ^ p7;
}

static inline void ckb_blake2b_update(CKB_Blake2b* S, const void* in, size_t inlen) {
    const uint8_t* p = (const uint8_t*)in;
    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = CKB_BLAKE2B_BLOCKBYTES - left;
        if (inlen > fill) {
            memcpy(S->buf + left, p, fill);
            _ckb_blake2b_increment_counter(S, CKB_BLAKE2B_BLOCKBYTES);
            _ckb_blake2b_compress(S, S->buf);
            S->buflen = 0;
            p += fill; inlen -= fill;
        } else {
            memcpy(S->buf + left, p, inlen);
            S->buflen += inlen;
            inlen = 0;
        }
    }
}

static inline void ckb_blake2b_final(CKB_Blake2b* S, uint8_t* out) {
    _ckb_blake2b_increment_counter(S, S->buflen);
    S->f[0] = (uint64_t)-1;
    memset(S->buf + S->buflen, 0, CKB_BLAKE2B_BLOCKBYTES - S->buflen);
    _ckb_blake2b_compress(S, S->buf);
    for (int i = 0; i < 4; i++) {
        uint64_t v = S->h[i];
        for (int j = 0; j < 8; j++) out[i*8+j] = (v >> (j*8)) & 0xFF;
    }
}

// Convenience: hash a single buffer
static inline void ckb_blake2b_hash(const void* data, size_t len, uint8_t out[32]) {
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, data, len);
    ckb_blake2b_final(&ctx, out);
}
