# CKB-ESP32 Host Test Report

**Date:** 2026-03-01 15:32  |  **Commit:** `44240f6`  |  **Platform:** aarch64 Linux  |  **Compiler:** g++ 11.4.0
22.04.3
11.4.0

## Summary

| Suite | Passed | Failed | Time |
|-------|--------|--------|------|
| 🟢 blake2b | 12 | 0 | 0s |
| 🟢 molecule | 36 | 0 | 0s |
| 🟢 bip39 | 20 | 0 | 1s |
| 🟢 signer | 24 | 0 | 2s |
| 🟢 client_static | 46 | 0 | 3s |
| **Total** | **138** | **0** | 6s |

## Test Cases

### blake2b

<details><summary>✅ 12 passed, 0 failed</summary>

```
PASS: Blake2b(empty) == known vector
PASS: Blake2b('hello') == known vector
PASS: Blake2b('abc') == known vector
PASS: incremental == one-shot
PASS: 4-part incremental == one-shot
PASS: ckb_blake2b_hash() == manual
PASS: re-init produces same result
PASS: re-init with different input differs
PASS: all-zeros != all-0xff
PASS: single byte deterministic
PASS: 1KB input produces non-zero hash
PASS: hash of 'x' is non-zero
```

</details>

### molecule

<details><summary>✅ 36 passed, 0 failed</summary>

```
PASS: buf init: len==0
PASS: buf init: cap==64
PASS: write_u8 returns true
PASS: after write_u8: len==1
PASS: write_u8 correct value
PASS: write_u32le: len==4
PASS: write_u32le correct LE
PASS: write_u64le: len==8
PASS: write_u64le correct LE
PASS: write_hex returns true
PASS: write_hex: len==4
PASS: write_hex correct bytes
PASS: overflow: write_u8 returns false
PASS: overflow: len unchanged at 2
PASS: witness placeholder: len>0
PASS: witness placeholder: buf.len==returned len
PASS: witness placeholder: total_size field correct
PASS: witness placeholder: len > 65 bytes
PASS: mol_write_script: len>4
PASS: mol_write_script: total_size correct
PASS: mol_write_script: code_hash survives in output
PASS: hash_type data != type
PASS: outpoint: exactly 36 bytes (32 hash + 4 index)
PASS: outpoint index 0 = LE 0x00000000
PASS: outpoint index 7 = LE 0x00000007
PASS: cellinput: 44 bytes (8 since + 36 outpoint)
PASS: cellinput since=0 correct
PASS: celloutput: len > 8
PASS: celloutput: capacity LE u64 correct
PASS: mol_write_bytes: 8 bytes total
PASS: mol_write_bytes: length prefix == 4
PASS: mol_write_bytes: payload intact
PASS: mol_write_bytes(empty): 4 bytes
PASS: mol_write_bytes(empty): length prefix == 0
PASS: patch first u32 correct
PASS: second u32 unchanged
```

</details>

### bip39

<details><summary>✅ 20 passed, 0 failed</summary>

```
PASS: valid 12-word mnemonic accepted
PASS: NULL mnemonic rejected
PASS: empty mnemonic rejected
PASS: single-word mnemonic rejected
PASS: mnemonic_to_privkey returns 0
PASS: privkey matches reference vector
PASS: privkey is 64 hex chars
PASS: address starts with ckb1
PASS: passphrase produces different key
PASS: index 0 != index 1
PASS: index 1 != index 2
PASS: account 0 != account 1
PASS: two calls same inputs == same key
PASS: known privkey returns 0
PASS: address starts with ckb1
PASS: address length > 40
PASS: address[3]=='1'
PASS: zero privkey rejected
PASS: NULL privkey rejected
PASS: short privkey rejected
```

</details>

### signer

<details><summary>✅ 24 passed, 0 failed</summary>

```
PASS: default key is invalid
PASS: load valid privkey returns true
PASS: after load: isValid()
PASS: NULL key rejected
PASS: short key rejected
PASS: non-hex key rejected
PASS: getPublicKey returns true
PASS: pubkey matches known vector
PASS: pubkey is compressed (02/03 prefix)
PASS: getLockArgsHex returns true
PASS: getLockArgsHex == blake160(pubkey)
PASS: getAddress(mainnet) returns true
PASS: mainnet address starts with ckb1
PASS: address length > 40
PASS: getAddress(testnet) returns true
PASS: testnet address starts with ckt1
PASS: sign returns true
PASS: recid in [0,3]
PASS: r component non-zero
PASS: s component non-zero
PASS: same hash → same sig (RFC6979)
PASS: different hashes → different sigs
PASS: CKBSigner::blake2bCKB matches ckb_blake2b_hash
PASS: blake2bCKB(empty) non-zero
```

</details>

### client_static

<details><summary>✅ 46 passed, 0 failed</summary>

```
PASS: 1.0 CKB = 100,000,000 shannon
PASS: 0 CKB = 0 shannon
PASS: 61 CKB = 6,100,000,000 shannon
PASS: 100M shannon = 1 CKB (int)
PASS: 0 shannon = 0 CKB
PASS: 100M shannon ≈ 1.0 CKB (float)
PASS: 6.1B shannon = 61 CKB
PASS: 0x0 == 0
PASS: 0x1 == 1
PASS: 0x100 == 256
PASS: 0xff == 255
PASS: 0xffff...ffff == UINT64_MAX
PASS: 100 (no 0x) == 256
PASS: uint64ToHex(256) == '0x100'
PASS: uint64ToHex(0) == '0x0'
PASS: uint64ToHex(UINT64_MAX) correct
PASS: formatCKB(100M) contains '1'
PASS: formatCKB contains 'CKB'
PASS: formatCKBCompact contains 'CKB'
PASS: formatCKBCompact shorter
PASS: formatCKBCompact large value uses suffix
PASS: valid 66-char hex hash
PASS: NULL hash rejected
PASS: empty hash rejected
PASS: short hash rejected
PASS: hash without 0x rejected
PASS: hash with non-hex char rejected
PASS: short secp256k1 addr (mainnet)
PASS: old full bech32 addr
PASS: CKB2021 full bech32m addr
PASS: testnet short addr
PASS: NULL rejected
PASS: empty rejected
PASS: non-CKB prefix rejected
PASS: short addr decodes valid
PASS: short: codeHash non-empty
PASS: short: hashType==type
PASS: short: args contains lock_args
PASS: old full bech32 decodes valid
PASS: old full: codeHash non-empty
PASS: old full: args contains lock_args
PASS: CKB2021 bech32m decodes valid
PASS: CKB2021: codeHash non-empty
PASS: encodeAddress returns true
PASS: re-encoded starts ckb1
PASS: nodeTypeStr returns non-empty string
```

</details>

