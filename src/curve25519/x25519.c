// x25519.c — X25519 Diffie-Hellman (RFC 7748)
// Exact implementation of RFC 7748 §5 Montgomery ladder.
// Field arithmetic: 10x 26/25-bit limbs (i32), no __int128__ needed.
// Portable: Xtensa (ESP32), ARM Thumb (ESP32-S3/S2), aarch64, x86_64.
// Public domain.

#include "x25519.h"

typedef int32_t  i32;
typedef uint32_t u32;
typedef int64_t  i64;

// Field element: 10 limbs
// limbs 0,2,4,6,8 → 26-bit; limbs 1,3,5,7,9 → 25-bit
typedef i32 fe[10];

#define MASK26 ((i32)0x3FFFFFF)
#define MASK25 ((i32)0x1FFFFFF)

static void fe_0(fe h)                   { for(int i=0;i<10;i++) h[i]=0; }
static void fe_1(fe h)                   { fe_0(h); h[0]=1; }
static void fe_copy(fe h, const fe f)    { for(int i=0;i<10;i++) h[i]=f[i]; }
static void fe_add(fe h, const fe f, const fe g) { for(int i=0;i<10;i++) h[i]=f[i]+g[i]; }
static void fe_sub(fe h, const fe f, const fe g) { for(int i=0;i<10;i++) h[i]=f[i]-g[i]; }

static void fe_cswap(fe f, fe g, u32 b) {
    u32 mask = (u32)(-(i32)b);
    for(int i=0;i<10;i++) { u32 t=mask&(u32)(f[i]^g[i]); f[i]^=(i32)t; g[i]^=(i32)t; }
}

static void fe_frombytes(fe h, const uint8_t s[32]) {
    // Split 255-bit little-endian number into 10 limbs (26/25 bits alternating)
    // Generated from first principles matching Curve25519 RFC 7748 bit layout.
    i64 h0 = (u32)s[0]              | ((u32)s[1]<<8)   | ((u32)s[2]<<16)  | ((u32)(s[3]&0x3)<<24);
    i64 h1 = ((u32)s[3]>>2)         | ((u32)s[4]<<6)   | ((u32)s[5]<<14)  | ((u32)(s[6]&0x7)<<22);
    i64 h2 = ((u32)s[6]>>3)         | ((u32)s[7]<<5)   | ((u32)s[8]<<13)  | ((u32)(s[9]&0x1f)<<21);
    i64 h3 = ((u32)s[9]>>5)         | ((u32)s[10]<<3)  | ((u32)s[11]<<11) | ((u32)(s[12]&0x3f)<<19);
    i64 h4 = ((u32)s[12]>>6)        | ((u32)s[13]<<2)  | ((u32)s[14]<<10) | ((u32)s[15]<<18);
    i64 h5 = (u32)s[16]             | ((u32)s[17]<<8)  | ((u32)s[18]<<16) | ((u32)(s[19]&0x1)<<24);
    i64 h6 = ((u32)s[19]>>1)        | ((u32)s[20]<<7)  | ((u32)s[21]<<15) | ((u32)(s[22]&0x7)<<23);
    i64 h7 = ((u32)s[22]>>3)        | ((u32)s[23]<<5)  | ((u32)s[24]<<13) | ((u32)(s[25]&0xf)<<21);
    i64 h8 = ((u32)s[25]>>4)        | ((u32)s[26]<<4)  | ((u32)s[27]<<12) | ((u32)(s[28]&0x3f)<<20);
    i64 h9 = ((u32)s[28]>>6)        | ((u32)s[29]<<2)  | ((u32)s[30]<<10) | ((u32)(s[31]&0x7f)<<18);
    h[0]=(i32)h0; h[1]=(i32)h1; h[2]=(i32)h2; h[3]=(i32)h3; h[4]=(i32)h4;
    h[5]=(i32)h5; h[6]=(i32)h6; h[7]=(i32)h7; h[8]=(i32)h8; h[9]=(i32)h9;
}

static void fe_tobytes(uint8_t s[32], const fe h) {
    // Final carry pass + reduce mod 2^255-19
    i32 q = (19*h[9]+(1<<24))>>25;
    q=(h[0]+q)>>26; q=(h[1]+q)>>25; q=(h[2]+q)>>26; q=(h[3]+q)>>25; q=(h[4]+q)>>26;
    q=(h[5]+q)>>25; q=(h[6]+q)>>26; q=(h[7]+q)>>25; q=(h[8]+q)>>26; q=(h[9]+q)>>25;
    i32 t[10];
    t[0]=h[0]+19*q; t[1]=h[1]+(t[0]>>26); t[0]&=MASK26;
    t[2]=h[2]+(t[1]>>25); t[1]&=MASK25;
    t[3]=h[3]+(t[2]>>26); t[2]&=MASK26;
    t[4]=h[4]+(t[3]>>25); t[3]&=MASK25;
    t[5]=h[5]+(t[4]>>26); t[4]&=MASK26;
    t[6]=h[6]+(t[5]>>25); t[5]&=MASK25;
    t[7]=h[7]+(t[6]>>26); t[6]&=MASK26;
    t[8]=h[8]+(t[7]>>25); t[7]&=MASK25;
    t[9]=h[9]+(t[8]>>26); t[8]&=MASK26;
                           t[9]&=MASK25;
    s[ 0]=(uint8_t) t[0];         s[ 1]=(uint8_t)(t[0]>>8);
    s[ 2]=(uint8_t)(t[0]>>16);    s[ 3]=(uint8_t)((t[0]>>24)|(t[1]<<2));
    s[ 4]=(uint8_t)(t[1]>>6);     s[ 5]=(uint8_t)(t[1]>>14);
    s[ 6]=(uint8_t)((t[1]>>22)|(t[2]<<3)); s[ 7]=(uint8_t)(t[2]>>5);
    s[ 8]=(uint8_t)(t[2]>>13);    s[ 9]=(uint8_t)((t[2]>>21)|(t[3]<<5));
    s[10]=(uint8_t)(t[3]>>3);     s[11]=(uint8_t)(t[3]>>11);
    s[12]=(uint8_t)((t[3]>>19)|(t[4]<<6)); s[13]=(uint8_t)(t[4]>>2);
    s[14]=(uint8_t)(t[4]>>10);    s[15]=(uint8_t)(t[4]>>18);
    s[16]=(uint8_t) t[5];         s[17]=(uint8_t)(t[5]>>8);
    s[18]=(uint8_t)(t[5]>>16);    s[19]=(uint8_t)((t[5]>>24)|(t[6]<<1));
    s[20]=(uint8_t)(t[6]>>7);     s[21]=(uint8_t)(t[6]>>15);
    s[22]=(uint8_t)((t[6]>>23)|(t[7]<<3)); s[23]=(uint8_t)(t[7]>>5);
    s[24]=(uint8_t)(t[7]>>13);    s[25]=(uint8_t)((t[7]>>21)|(t[8]<<4));
    s[26]=(uint8_t)(t[8]>>4);     s[27]=(uint8_t)(t[8]>>12);
    s[28]=(uint8_t)((t[8]>>20)|(t[9]<<6)); s[29]=(uint8_t)(t[9]>>2);
    s[30]=(uint8_t)(t[9]>>10);    s[31]=(uint8_t)(t[9]>>18);
}

static void fe_carry(fe h) {
    i64 c;
    c=h[0]>>26; h[1]+=(i32)c; h[0]-=(i32)(c<<26);
    c=h[1]>>25; h[2]+=(i32)c; h[1]-=(i32)(c<<25);
    c=h[2]>>26; h[3]+=(i32)c; h[2]-=(i32)(c<<26);
    c=h[3]>>25; h[4]+=(i32)c; h[3]-=(i32)(c<<25);
    c=h[4]>>26; h[5]+=(i32)c; h[4]-=(i32)(c<<26);
    c=h[5]>>25; h[6]+=(i32)c; h[5]-=(i32)(c<<25);
    c=h[6]>>26; h[7]+=(i32)c; h[6]-=(i32)(c<<26);
    c=h[7]>>25; h[8]+=(i32)c; h[7]-=(i32)(c<<25);
    c=h[8]>>26; h[9]+=(i32)c; h[8]-=(i32)(c<<26);
    c=h[9]>>25; h[0]+=(i32)(19*c); h[9]-=(i32)(c<<25);
    c=h[0]>>26; h[1]+=(i32)c; h[0]-=(i32)(c<<26);
}

static void fe_mul(fe h, const fe f, const fe g) {
    i32 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    i32 f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    i32 g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    i32 g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    i32 g1_19=19*g1,g2_19=19*g2,g3_19=19*g3,g4_19=19*g4;
    i32 g5_19=19*g5,g6_19=19*g6,g7_19=19*g7,g8_19=19*g8,g9_19=19*g9;
    i32 f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;
    i64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    h0=(i64)f0*g0   +(i64)f1_2*g9_19+(i64)f2*g8_19+(i64)f3_2*g7_19+(i64)f4*g6_19
      +(i64)f5_2*g5_19+(i64)f6*g4_19+(i64)f7_2*g3_19+(i64)f8*g2_19+(i64)f9_2*g1_19;
    h1=(i64)f0*g1   +(i64)f1*g0    +(i64)f2*g9_19+(i64)f3*g8_19+(i64)f4*g7_19
      +(i64)f5*g6_19+(i64)f6*g5_19+(i64)f7*g4_19+(i64)f8*g3_19+(i64)f9*g2_19;
    h2=(i64)f0*g2   +(i64)f1_2*g1  +(i64)f2*g0   +(i64)f3_2*g9_19+(i64)f4*g8_19
      +(i64)f5_2*g7_19+(i64)f6*g6_19+(i64)f7_2*g5_19+(i64)f8*g4_19+(i64)f9_2*g3_19;
    h3=(i64)f0*g3   +(i64)f1*g2    +(i64)f2*g1   +(i64)f3*g0    +(i64)f4*g9_19
      +(i64)f5*g8_19+(i64)f6*g7_19+(i64)f7*g6_19+(i64)f8*g5_19+(i64)f9*g4_19;
    h4=(i64)f0*g4   +(i64)f1_2*g3  +(i64)f2*g2   +(i64)f3_2*g1  +(i64)f4*g0
      +(i64)f5_2*g9_19+(i64)f6*g8_19+(i64)f7_2*g7_19+(i64)f8*g6_19+(i64)f9_2*g5_19;
    h5=(i64)f0*g5   +(i64)f1*g4    +(i64)f2*g3   +(i64)f3*g2    +(i64)f4*g1
      +(i64)f5*g0   +(i64)f6*g9_19+(i64)f7*g8_19+(i64)f8*g7_19+(i64)f9*g6_19;
    h6=(i64)f0*g6   +(i64)f1_2*g5  +(i64)f2*g4   +(i64)f3_2*g3  +(i64)f4*g2
      +(i64)f5_2*g1 +(i64)f6*g0   +(i64)f7_2*g9_19+(i64)f8*g8_19+(i64)f9_2*g7_19;
    h7=(i64)f0*g7   +(i64)f1*g6    +(i64)f2*g5   +(i64)f3*g4    +(i64)f4*g3
      +(i64)f5*g2   +(i64)f6*g1   +(i64)f7*g0   +(i64)f8*g9_19+(i64)f9*g8_19;
    h8=(i64)f0*g8   +(i64)f1_2*g7  +(i64)f2*g6   +(i64)f3_2*g5  +(i64)f4*g4
      +(i64)f5_2*g3 +(i64)f6*g2   +(i64)f7_2*g1 +(i64)f8*g0   +(i64)f9_2*g9_19;
    h9=(i64)f0*g9   +(i64)f1*g8    +(i64)f2*g7   +(i64)f3*g6    +(i64)f4*g5
      +(i64)f5*g4   +(i64)f6*g3   +(i64)f7*g2   +(i64)f8*g1   +(i64)f9*g0;
    h[0]=(i32)h0; h[1]=(i32)h1; h[2]=(i32)h2; h[3]=(i32)h3; h[4]=(i32)h4;
    h[5]=(i32)h5; h[6]=(i32)h6; h[7]=(i32)h7; h[8]=(i32)h8; h[9]=(i32)h9;
    fe_carry(h);
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_mul_small(fe h, const fe f, i32 b) {
    for(int i=0;i<10;i++) h[i]=(i32)((i64)f[i]*b);
    fe_carry(h);
}

static void fe_invert(fe h, const fe f) {
    fe t0,t1,t2,t3;
    // f^(p-2) = f^(2^255-21) via square-and-multiply
    fe_sq(t0,f);                              // 2
    fe_sq(t1,t0); fe_sq(t1,t1);              // 8
    fe_mul(t1,t1,f);                          // 9
    fe_mul(t0,t0,t1);                         // 11
    fe_sq(t2,t0); fe_mul(t1,t2,t1);          // 2^5-1
    fe_sq(t2,t1); for(int i=1;i<5;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);   // 2^10-1
    fe_sq(t2,t1); for(int i=1;i<10;i++) fe_sq(t2,t2); fe_mul(t2,t2,t1);  // 2^20-1
    fe_sq(t3,t2); for(int i=1;i<20;i++) fe_sq(t3,t3); fe_mul(t2,t3,t2);  // 2^40-1
    for(int i=0;i<10;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);                // 2^50-1
    fe_sq(t2,t1); for(int i=1;i<50;i++) fe_sq(t2,t2); fe_mul(t2,t2,t1);  // 2^100-1
    fe_sq(t3,t2); for(int i=1;i<100;i++) fe_sq(t3,t3); fe_mul(t2,t3,t2); // 2^200-1
    for(int i=0;i<50;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);                // 2^250-1
    fe_sq(t1,t1); fe_sq(t1,t1); fe_sq(t1,t1); fe_sq(t1,t1); fe_sq(t1,t1);
    fe_mul(h,t1,t0);  // 2^255-21 = p-2
}

// ─── RFC 7748 §5 Montgomery ladder ───────────────────────────────────────────

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u_point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0]  &= 248;   // RFC 7748 clamp
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, A, AA, B, BB, E, C, D, DA, CB, tmp;
    fe_frombytes(x1, u_point);
    fe_1(x2); fe_0(z2);
    fe_copy(x3, x1); fe_1(z3);

    u32 swap = 0;
    for (int t = 254; t >= 0; t--) {
        u32 k_t = (e[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = k_t;

        // RFC 7748 Appendix A, verbatim:
        fe_add(A,  x2, z2);       // A  = x_2 + z_2
        fe_sq(AA,  A);            // AA = A^2
        fe_sub(B,  x2, z2);       // B  = x_2 - z_2
        fe_sq(BB,  B);            // BB = B^2
        fe_sub(E,  AA, BB);       // E  = AA - BB
        fe_add(C,  x3, z3);       // C  = x_3 + z_3
        fe_sub(D,  x3, z3);       // D  = x_3 - z_3
        fe_mul(DA, D,  A);        // DA = D * A
        fe_mul(CB, C,  B);        // CB = C * B
        fe_add(tmp, DA, CB);      // DA + CB
        fe_sq(x3, tmp);           // x_3 = (DA+CB)^2
        fe_sub(tmp, DA, CB);      // DA - CB
        fe_sq(z3, tmp);           // z_3 = (DA-CB)^2
        fe_mul(z3, x1, z3);       // z_3 = x_1 * (DA-CB)^2
        fe_mul(x2, AA, BB);       // x_2 = AA * BB
        fe_mul_small(tmp, E, 121665);  // a24*E, a24 = (486662-2)/4 = 121665
        fe_add(tmp, AA, tmp);     // AA + a24*E
        fe_mul(z2, E, tmp);       // z_2 = E * (AA + a24*E)
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    uint8_t base[32] = {9};  // Curve25519 base point: u = 9
    x25519(out, scalar, base);
}
