/* address.h stub — unused functions excluded for CKB-ESP32 */
#ifndef __ADDRESS_H__
#define __ADDRESS_H__
#include <stdint.h>
#include <stddef.h>
static inline size_t address_prefix_bytes_len(uint32_t v) { (void)v; return 1; }
static inline void address_write_prefix_bytes(uint32_t v, uint8_t *out) { (void)v; (void)out; }
static inline int address_check_prefix(const uint8_t *out, uint32_t v) { (void)out; (void)v; return 0; }
static inline int base58_decode_check(const char *s, int ht, uint8_t *out, int len) { (void)s;(void)ht;(void)out;(void)len; return 0; }
#endif
