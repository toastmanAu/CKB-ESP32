/* base58.h stub — unused functions excluded for CKB-ESP32 */
#ifndef __BASE58_H__
#define __BASE58_H__
#include <stdint.h>
#include <stddef.h>
typedef int HasherType_b58;  /* avoid clash */
static inline int base58_encode_check(const uint8_t *data, int len, int ht, char *str, int strsize) { (void)data;(void)len;(void)ht;(void)str;(void)strsize; return 0; }
#endif
