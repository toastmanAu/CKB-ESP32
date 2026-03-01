// x25519.h — X25519 Diffie-Hellman (RFC 7748)
//
// HOST_TEST mode: backed by libsodium (crypto_scalarmult_curve25519)
// Device mode:   backed by portable 26/25-bit limb Montgomery ladder (x25519.c)
//
// API:
//   x25519(out, scalar, point)   — DH: out = scalar * point
//   x25519_base(out, scalar)     — out = scalar * basepoint (u=9)
//   x25519_clamp(scalar)         — clamp in-place per RFC 7748 §5

#pragma once
#include <stdint.h>
#include <string.h>

#ifdef HOST_TEST
  #include <sodium.h>
  static inline void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]) {
      crypto_scalarmult_curve25519(out, scalar, u);
  }
  static inline void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
      crypto_scalarmult_curve25519_base(out, scalar);
  }
#else
  // Device: portable C Montgomery ladder (x25519.c)
  void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u_point[32]);
  void x25519_base(uint8_t out[32], const uint8_t scalar[32]);
#endif

static inline void x25519_clamp(uint8_t s[32]) {
    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;
}
