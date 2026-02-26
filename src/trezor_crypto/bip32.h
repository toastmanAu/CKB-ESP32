/* bip32.h stub — only curve_info typedef needed for CKB-ESP32 signing */
#ifndef __BIP32_H__
#define __BIP32_H__

#include "ecdsa.h"
#include "hasher.h"

typedef struct {
    const char*        bip32_name;
    const ecdsa_curve* params;
    HasherType         hasher_base58;
    HasherType         hasher_sign;
    HasherType         hasher_script;   /* alias — same field, secp256k1.c uses this name */
    HasherType         hasher_pubkey;
} curve_info;

#endif /* __BIP32_H__ */
