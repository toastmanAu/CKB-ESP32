# CKB-ESP32

> Embedded CKB SDK for Arduino — build, sign, and broadcast Nervos transactions directly from ESP32 hardware.

No relay. No cloud. No custodian. The chip does everything.

[![Confirmed on Nervos Mainnet](https://img.shields.io/badge/mainnet-confirmed-brightgreen)](https://explorer.nervos.org/transaction/0x1db4d7677aaa03063ed87a6d927309b0ff4ce0bd18ec1f721432c11766f663d9)

---

## What it does

A complete CKB transaction lifecycle runs entirely on-device:

1. **Query** — fetch live cells and balance for any address (full node or light client)
2. **Build** — collect UTXOs, calculate change, serialise to Molecule encoding
3. **Sign** — secp256k1 RFC6979 deterministic signing, no external dependencies
4. **Broadcast** — submit signed transaction to the network and confirm on-chain

Tested on an ESP32-D0WD-V3 (classic dual-core, 240MHz) against Nervos mainnet.

---

## Architecture

The library is split into independent modules, compiled only when needed:

```
CKBConfig.h       ← build profile selection (MINIMAL / DISPLAY / SIGNER / MONITOR / FULL)
CKB.h / CKB.cpp   ← CKBClient: all RPC, transaction building, broadcasting
CKBSigner.h/.cpp  ← on-device secp256k1 signing (trezor-crypto, pure C)
ckb_molecule.h    ← Molecule serialisation (Script, Output, Transaction, WitnessArgs)
ckb_blake2b.h     ← Blake2b-256 with CKB personalisation string
```

No ESP-IDF, no mbedTLS, no external registry dependencies.

---

## Build Profiles

Select a profile in your sketch before `#include "CKB.h"` to control flash/RAM usage:

| Profile | Use case | JSON buffer | Included |
|---------|----------|-------------|----------|
| `CKB_PROFILE_MINIMAL` | Light client, balance only | 2 KB | Light client RPC only |
| `CKB_PROFILE_DISPLAY` | Node stats, balance display | 4 KB | Node + indexer RPC, no send |
| `CKB_PROFILE_SIGNER` | Send transactions | 4 KB | Node + indexer + signer + send |
| `CKB_PROFILE_MONITOR` | Block/peer/pool monitoring | 8 KB | Node + block + peer + pool, no send |
| `CKB_PROFILE_FULL` | Everything | 16 KB | All modules |

```cpp
#define CKB_PROFILE_SIGNER   // pick one before the include
#include "CKB.h"
#include "CKBSigner.h"
```

Fine-grained control with `CKB_NO_*` and `CKB_WITH_*` defines — see `CKBConfig.h`.

---

## Quick Start

### PlatformIO

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps =
    https://github.com/toastmanAu/CKB-ESP32.git
    bblanchon/ArduinoJson@^7.0.0
```

### Arduino IDE

Download ZIP → Sketch → Include Library → Add .ZIP Library

---

## Usage

### Check balance

```cpp
#define CKB_PROFILE_DISPLAY
#include "CKB.h"
#include <WiFi.h>

CKBClient ckb("http://192.168.1.100:8114");

void setup() {
    // WiFi.begin(...) / waitForConnection ...

    CKBBalance bal = ckb.getBalance("ckb1q...");
    Serial.printf("Balance: %.4f CKB\n", CKBClient::shannonToCKB(bal.shannon));
}
```

### Send a transaction — one-shot

```cpp
#define CKB_PROFILE_SIGNER
#include "CKB.h"
#include "CKBSigner.h"

// NOTE: load credentials from NVS in production — see Key Security section
CKBClient ckb("http://192.168.1.100:8114");
CKBKey key;

void setup() {
    key.loadPrivateKeyHex("your-private-key-hex");  // or load from NVS

    char txHash[67] = {0};
    CKBError err = ckb.sendTransaction(
        "ckb1q...",   // recipient address
        100.0f,        // amount in CKB
        key,           // key — from address derived automatically
        txHash         // optional: output buffer for tx hash
    );

    if (err == CKB_OK)
        Serial.printf("Sent! TX: %s\n", txHash);
}
```

### Send a transaction — manual (full control)

```cpp
// 1. Build
CKBBuiltTx tx = ckb.buildTransfer(fromAddr, toAddr, CKBClient::ckbToShannon(100.0f));
if (!tx.valid) { /* handle error */ }

// 2. Sign
if (ckb.signTx(tx, key) != CKB_OK) { /* handle error */ }

// 3. Broadcast
char txHash[67] = {0};
CKBError err = CKBClient::broadcast(tx, NODE_URL, txHash);
```

### Light client (reduced bandwidth)

```cpp
#define CKB_PROFILE_MINIMAL
#define CKB_NODE_LIGHT        // enables light client API
#include "CKB.h"

CKBClient ckb("http://192.168.1.100:9000");  // ckb-light-client port

ckb.watchAddress("ckb1q...");
ckb.waitForSync(30000);
CKBBalance bal = ckb.getBalance("ckb1q...");
```

---

## API Reference

### CKBClient

```cpp
CKBClient(const char* nodeUrl, const char* indexerUrl = nullptr, bool testnet = false);
```

#### Node RPC — Chain

| Method | Returns | Description |
|--------|---------|-------------|
| `getTipBlockNumber()` | `uint64_t` | Current tip block number |
| `getBlockByNumber(n, verbose)` | `CKBBlock` | Block by number |
| `getBlockByHash(hash, verbose)` | `CKBBlock` | Block by hash |
| `getHeaderByNumber(n)` | `CKBBlockHeader` | Header only |
| `getHeaderByHash(hash)` | `CKBBlockHeader` | Header by hash |
| `getCurrentEpoch()` | `CKBEpoch` | Current epoch info |
| `getEpochByNumber(n)` | `CKBEpoch` | Epoch by number |

#### Node RPC — Transactions & Cells

| Method | Returns | Description |
|--------|---------|-------------|
| `getTransaction(txHash)` | `CKBTransaction` | Full transaction |
| `getLiveCell(txHash, index)` | `CKBLiveCell` | Live cell at outpoint |

#### Node RPC — Network

| Method | Returns | Description |
|--------|---------|-------------|
| `getNodeInfo()` | `CKBNodeInfo` | Local node info |
| `getTxPoolInfo()` | `CKBTxPoolInfo` | Mempool statistics |
| `getBlockchainInfo()` | `CKBChainInfo` | Chain and sync info |
| `getPeers(peers[], max)` | `uint8_t` | Connected peer count |

#### Indexer RPC

| Method | Returns | Description |
|--------|---------|-------------|
| `getIndexerTip()` | `CKBIndexerTip` | Indexer sync tip |
| `getCells(lockScript, ...)` | `CKBCellsResult` | Live cells for a script |
| `getTransactions(lockScript, ...)` | `CKBTxsResult` | Transactions for a script |
| `getCellsCapacity(lockScript)` | `CKBBalance` | Total capacity sum |

#### High-level Helpers

| Method | Returns | Description |
|--------|---------|-------------|
| `getBalance(address)` | `CKBBalance` | Balance for a CKB address |
| `getBalance(key)` | `CKBBalance` | Balance derived from key (no address needed) |
| `hasNewActivity(lockScript, &lastBlock)` | `bool` | True if new txs since last check |
| `getRecentTransactions(address, n)` | `CKBTxsResult` | Last N transactions |

#### Transaction Building & Sending

| Method | Returns | Description |
|--------|---------|-------------|
| `buildTransfer(from, to, shannon, fee)` | `CKBBuiltTx` | Build unsigned transaction |
| `signTx(tx, key)` | `CKBError` | Sign in-place (secp256k1-blake160) |
| `broadcast(tx, nodeUrl, txHashOut)` | `CKBError` | Submit pre-signed transaction |
| `sendTransaction(to, amountCKB, key, txHashOut)` | `CKBError` | One-shot: build + sign + broadcast |

#### Static Utilities

| Method | Description |
|--------|-------------|
| `decodeAddress(address)` | CKB address → `CKBScript` |
| `encodeAddress(lockScript, mainnet)` | `CKBScript` → bech32m address |
| `ckbToShannon(ckb)` | `float` CKB → `uint64_t` shannon |
| `shannonToCKB(shannon)` | `uint64_t` → `float` |
| `formatCKB(shannon)` | `"1,234.5600 CKB"` |
| `formatCKBCompact(shannon)` | `"1.2K CKB"` |
| `hexToUint64(hex)` | `"0x1a2b"` → `uint64_t` |

#### Light Client API (`#define CKB_NODE_LIGHT`)

| Method | Returns | Description |
|--------|---------|-------------|
| `setScripts(scripts[], count)` | `CKBError` | Register scripts to watch |
| `watchAddress(address)` | `CKBError` | Watch a single address |
| `getSyncState()` | `CKBSyncState` | Current sync progress |
| `waitForSync(timeoutMs)` | `CKBError` | Block until synced |
| `getTipHeader()` | `CKBBlockHeader` | Light client tip |
| `fetchTransaction(txHash)` | `bool` | Fetch tx from the network |

---

## Data Structures

```cpp
struct CKBScript    { char codeHash[67]; char hashType[8]; char args[131]; bool valid; };
struct CKBOutPoint  { char txHash[67]; uint32_t index; };
struct CKBBalance   { uint64_t shannon; float ckb; uint32_t cellCount; CKBError error; };
struct CKBBlock     { CKBBlockHeader header; uint32_t txCount; char minerLockArgs[43]; bool valid; };
struct CKBEpoch     { uint64_t number; uint64_t startNumber; uint64_t length; bool valid; };
struct CKBNodeInfo  { char nodeId[53]; char version[24]; uint64_t tipBlockNumber; uint32_t peersCount; bool valid; };
struct CKBCellsResult { CKBIndexerCell cells[CKB_MAX_CELLS]; uint8_t count; char lastCursor[67]; bool hasMore; };
struct CKBTxsResult   { CKBIndexerTx  txs[CKB_MAX_TXS];    uint8_t count; bool hasMore; CKBError error; };

struct CKBBuiltTx {
    bool     valid;
    bool     signed_;
    uint8_t  inputCount;
    uint8_t  outputCount;
    uint64_t fee();              // computed from inputs - outputs
    uint8_t  txHash[32];         // Blake2b hash of raw tx (no witnesses)
    uint8_t  signingHash[32];    // hash the lock script verifies
    uint8_t  signature[65];      // [r(32) | s(32) | recid(1)] after signing
    CKBError error;
};
```

---

## CKBSigner

```cpp
#include "CKBSigner.h"

// Load a key
CKBKey key;
key.loadPrivateKeyHex("64-char-hex");    // from hex string
key.loadPrivateKeyBytes(bytes, 32);      // from raw bytes

// Derive the address (no need to hardcode it)
char addr[120];
key.getAddress(addr, sizeof(addr), true);   // true = mainnet

// Check lock args (what goes in the lock script)
char args[42];
key.getLockArgsHex(args, sizeof(args));     // "0x4454b23e..."

// Clear key material from RAM
key.clear();
```

Signing uses [trezor-crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto) vendored in `src/crypto/`. RFC6979 deterministic k, secp256k1 curve, Blake2b-256 signing hash.

---

## Key Security on ESP32

The signer module stores and uses a raw secp256k1 private key in RAM. Before deploying
any build that holds real funds, understand the threat model and apply the appropriate
mitigations for your use case.

### Threat model

| Threat | Risk | Mitigation |
|--------|------|------------|
| Firmware dump via JTAG/UART | Private key extracted from flash | NVS encryption, eFuse flash encryption |
| Heap/stack read via serial debug | Key visible in memory | Clear key after use (`key.clear()`), disable debug output |
| UART replay / man-in-the-middle | Signed tx replayed | Use `since` field for time-locks; one-shot keys |
| Physical device theft | Attacker has full access | Passphrase-derived keys; spending limits |
| Hardcoded key in firmware | Key in git history forever | Never hardcode — use NVS or derivation |

---

### Option 1 — NVS (Non-Volatile Storage) ✅ Recommended minimum

Store the key in ESP32's NVS partition rather than compiled into flash. NVS survives
reboots but is separate from firmware — flashing new firmware doesn't overwrite it.

```cpp
#include <Preferences.h>

void loadKeyFromNVS(CKBKey& key) {
    Preferences prefs;
    prefs.begin("ckb", true);               // read-only namespace
    String hexKey = prefs.getString("privkey", "");
    prefs.end();
    if (hexKey.length() == 64)
        key.loadPrivateKeyHex(hexKey.c_str());
}

// Write once (provisioning step, then remove this code):
void provisionKey(const char* hexKey) {
    Preferences prefs;
    prefs.begin("ckb", false);
    prefs.putString("privkey", hexKey);
    prefs.end();
}
```

NVS is plaintext by default — combine with **flash encryption** (Option 4) for real protection.

---

### Option 2 — Derived key from passphrase

Never store the raw key. Derive it at runtime from a passphrase the user enters (button
combo, PIN pad, BLE, serial prompt). The key exists in RAM only for the duration of signing.

```cpp
#include "mbedtls/sha256.h"

// Derive a deterministic private key from a passphrase + salt.
// For production use a proper KDF (PBKDF2 via mbedtls/pkcs5.h) with high iteration count.
bool deriveKey(const char* passphrase, const char* salt, CKBKey& key) {
    uint8_t digest[32];
    char combined[128];
    snprintf(combined, sizeof(combined), "%s:%s", salt, passphrase);
    mbedtls_sha256((uint8_t*)combined, strlen(combined), digest, 0);
    char hexKey[65];
    for (int i = 0; i < 32; i++) sprintf(hexKey + i*2, "%02x", digest[i]);
    hexKey[64] = '\0';
    return key.loadPrivateKeyHex(hexKey);
}
```

**Wipe the key when done:**
```cpp
key.clear();   // zeroes internal key material
```

---

### Option 3 — Spending limits in firmware

Enforce a per-transaction cap and a daily rolling limit in firmware. Even if the key is
compromised, the attacker can only move a bounded amount.

```cpp
static uint64_t dailySent = 0;
static uint32_t dayStart  = 0;

CKBError guardedSend(CKBClient& ckb, const char* to, float amountCKB, const CKBKey& key) {
    const uint64_t MAX_TX_SHANNON    = CKBClient::ckbToShannon(100.0f);
    const uint64_t MAX_DAILY_SHANNON = CKBClient::ckbToShannon(500.0f);

    uint64_t shannon = CKBClient::ckbToShannon(amountCKB);
    if (shannon > MAX_TX_SHANNON) return CKB_ERR_INVALID;

    uint32_t now = millis() / 1000;
    if (now - dayStart > 86400) { dailySent = 0; dayStart = now; }
    if (dailySent + shannon > MAX_DAILY_SHANNON) return CKB_ERR_INVALID;

    CKBError err = ckb.sendTransaction(to, amountCKB, key);
    if (err == CKB_OK) dailySent += shannon;
    return err;
}
```

---

### Option 4 — ESP32 flash encryption + Secure Boot (production devices)

For devices shipping to end users or holding significant funds:

1. **Flash encryption** — AES-XTS hardware encryption of the entire flash. Keys are burned
   into eFuses and never leave the chip. Enable in `menuconfig → Security features →
   Enable flash encryption on boot`. Once enabled, plaintext flashing is disabled.

2. **Secure Boot v2** — firmware signature verification at boot. Only firmware signed with
   your RSA/ECDSA key will run. Prevents malicious firmware injection even with physical access.

3. **eFuse write-protection** — lock eFuse blocks after provisioning so they can't be
   overwritten. Irreversible — test thoroughly before burning.

These are ESP-IDF features and require the IDF toolchain (not pure Arduino). PlatformIO
supports them via `board_build.cmake_extra_args`.

> ⚠️ Flash encryption + Secure Boot are **one-way operations**. A mistake bricks the device.
> Test on a sacrificial board first.

---

### Practical guidance by use case

| Use case | Key storage | Extra hardening |
|----------|-------------|-----------------|
| Demo / devkit / test funds only | NVS plaintext | None needed |
| POS terminal (receive-only) | N/A — no signing key needed | — |
| POS terminal (auto-settlement) | NVS + passphrase derivation | Spending limits |
| Unattended device, real funds | NVS + flash encryption | Secure Boot |
| High-value hardware wallet | External secure element (ATECC608) | Full IDF stack |

For the highest security on ESP32-class hardware, pair the library with an
**ATECC608A/B** secure element (I²C). The private key never leaves the secure element;
signing happens on-chip. The `CKBSigner` module can accept a pre-computed signature from
any source via `CKBBuiltTx::setSignature()`.

---

## Use Cases

| Project | Description |
|---------|-------------|
| **CKB POS terminal** | Watch for incoming payments, auto-settle to another address |
| **NerdMiner CKB** | Show live network stats (tip, peers, pool) alongside mining |
| **Whale watcher** | Alert on large transfers via buzzer or display |
| **Hardware wallet** | Sign CKB transactions with keys stored in secure element |
| **IoT micro-payments** | Devices pay-per-use autonomously |
| **ESP32 POS + Quantum Purse** | Compatible with SPHINCS+ signing via `setSignature()` |

---

## Requirements

- ESP32 (any variant with WiFi; tested on ESP32-D0WD-V3)
- [ArduinoJson](https://arduinojson.org/) v7+
- CKB full node (port 8114) or [ckb-light-client](https://github.com/nervosnetwork/ckb-light-client) (port 9000)

---

## Examples

| Example | Profile | Description |
|---------|---------|-------------|
| `BasicNodeInfo` | DISPLAY | Tip, chain info, epoch, peers, latest block |
| `WatchAddress` | DISPLAY | Poll for incoming payments, print amounts |
| `IndexerCells` | DISPLAY | Paginate all cells, detect DAO/SUDT/xUDT |
| `TransferCKB` | SIGNER | Build, sign, and broadcast a transfer |
| `LightClientSync` | MINIMAL | Light client sync + balance check |

---

## Stack note

Transaction building and cryptographic operations require stack space beyond the Arduino
default (8 KB). Run CKB operations in a dedicated FreeRTOS task with at least 32 KB:

```cpp
void ckbTask(void*) {
    // ... CKB operations ...
    vTaskDelete(nullptr);
}

void setup() {
    xTaskCreatePinnedToCore(ckbTask, "ckb", 32768, nullptr, 1, nullptr, 1);
}
```

---

## License

MIT — see [LICENSE](LICENSE)

---

Built by [toastmanAu](https://github.com/toastmanAu) · Part of the [BlackBox](https://blackboxdata.xyz) CKB ecosystem
