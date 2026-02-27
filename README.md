# CKB-ESP32

> Nervos CKB RPC library for ESP32 / Arduino

Clean C++ wrapper around the CKB Node JSON-RPC and CKB Indexer JSON-RPC APIs. Drop it into any ESP32 project and query the Nervos blockchain in a few lines.

## Features

- **Node RPC** — tip block, block by number/hash, block header, transaction, live cell, epoch, tx pool, blockchain info, peers
- **Indexer RPC** — `get_cells`, `get_transactions`, `get_cells_capacity`, `get_indexer_tip`
- **High-level helpers** — `getBalance(address)`, `hasNewActivity()`, `getRecentTransactions()`
- **Address decoding** — bech32/bech32m → lock script (short secp256k1 + full format)
- **Formatting** — `formatCKB()`, `formatCKBCompact()`, `shannonToCKB()`
- **Pagination** — full cursor-based pagination for cell/tx queries
- **Type detection** — DAO, SUDT, xUDT cell identification in examples
- Error handling with `CKBError` enum and `lastErrorStr()`

## Requirements

- ESP32 (any variant with WiFi)
- [ArduinoJson](https://arduinojson.org/) v7+
- CKB full node with RPC enabled (port 8114)
- CKB Indexer (built-in since CKB v0.100, port 8116) — for balance/cell queries

## Installation

### PlatformIO
```ini
[env:your_board]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps =
    https://github.com/toastmanAu/CKB-ESP32.git
    bblanchon/ArduinoJson@^7.0.0
```

### Arduino IDE
Download ZIP → Sketch → Include Library → Add .ZIP Library

## Quick Start

```cpp
#include <WiFi.h>
#include "CKB.h"

CKBClient ckb("http://192.168.1.100:8114", "http://192.168.1.100:8116");

void setup() {
    // ... WiFi connect ...

    // Get tip block
    uint64_t tip = ckb.getTipBlockNumber();
    Serial.printf("Tip: %llu\n", tip);

    // Get balance for an address
    CKBBalance bal = ckb.getBalance("ckb1qyq...");
    Serial.printf("Balance: %s\n", CKBClient::formatCKB(bal.shannon).c_str());

    // Get recent transactions
    CKBTxsResult txs = ckb.getRecentTransactions("ckb1qyq...", 5);
    for (uint8_t i = 0; i < txs.count; i++) {
        Serial.printf("Tx: %s @ block %llu\n",
            txs.txs[i].txHash, txs.txs[i].blockNumber);
    }
}
```

## API Reference

### CKBClient

```cpp
CKBClient(const char* nodeUrl, const char* indexerUrl = nullptr);
```

**Node RPC — Chain**
| Method | Returns | Description |
|--------|---------|-------------|
| `getTipBlockNumber()` | `uint64_t` | Current tip block |
| `getBlockByNumber(n, verbose)` | `CKBBlock` | Block by number |
| `getBlockByHash(hash, verbose)` | `CKBBlock` | Block by hash |
| `getHeaderByNumber(n)` | `CKBBlockHeader` | Header only (lighter) |
| `getHeaderByHash(hash)` | `CKBBlockHeader` | Header by hash |
| `getCurrentEpoch()` | `CKBEpoch` | Current epoch info |
| `getEpochByNumber(n)` | `CKBEpoch` | Epoch by number |

**Node RPC — Transactions & Cells**
| Method | Returns | Description |
|--------|---------|-------------|
| `getTransaction(txHash)` | `CKBTransaction` | Full transaction |
| `getLiveCell(txHash, index)` | `CKBLiveCell` | Live cell at outpoint |

**Node RPC — Network**
| Method | Returns | Description |
|--------|---------|-------------|
| `getNodeInfo()` | `CKBNodeInfo` | Local node info |
| `getTxPoolInfo()` | `CKBTxPoolInfo` | Mempool stats |
| `getBlockchainInfo()` | `CKBChainInfo` | Chain info |
| `getPeers(peers[], max)` | `uint8_t` | Connected peers |

**Indexer RPC**
| Method | Returns | Description |
|--------|---------|-------------|
| `getIndexerTip()` | `CKBIndexerTip` | Indexer sync tip |
| `getCells(lockScript, ...)` | `CKBCellsResult` | Live cells for script |
| `getTransactions(lockScript, ...)` | `CKBTxsResult` | Transactions for script |
| `getCellsCapacity(lockScript)` | `CKBBalance` | Total capacity |

**High-level Helpers**
| Method | Returns | Description |
|--------|---------|-------------|
| `getBalance(address)` | `CKBBalance` | Balance for CKB address string |
| `hasNewActivity(lockScript, &lastBlock)` | `bool` | True if new txs since last check |
| `getRecentTransactions(address, n)` | `CKBTxsResult` | Last N txs for address |

**Static Utilities**
| Method | Description |
|--------|-------------|
| `decodeAddress(address)` | CKB address → `CKBScript` |
| `formatCKB(shannon)` | `"1,234.56 CKB"` |
| `formatCKBCompact(shannon)` | `"1.2K CKB"` |
| `shannonToCKB(shannon)` | float |
| `hexToUint64(hex)` | `"0x1a2b"` → uint64 |

## Data Structures

```cpp
struct CKBScript    { char codeHash[67]; char hashType[8]; char args[131]; bool valid; };
struct CKBOutPoint  { char txHash[67]; uint32_t index; };
struct CKBBalance   { uint64_t shannon; float ckb; uint32_t cellCount; CKBError error; };
struct CKBBlock     { CKBBlockHeader header; uint32_t txCount; char minerLockArgs[43]; bool valid; };
struct CKBEpoch     { uint64_t number; uint64_t startNumber; uint64_t length; bool valid; };
struct CKBNodeInfo  { char nodeId[53]; char version[24]; uint64_t tipBlockNumber; uint32_t peersCount; bool valid; };
struct CKBCellsResult { CKBIndexerCell cells[64]; uint8_t count; char lastCursor[67]; bool hasMore; };
struct CKBTxsResult   { CKBIndexerTx txs[32]; uint8_t count; bool hasMore; CKBError error; };
```

## Configuration

Override before including `CKB.h`:
```cpp
#define CKB_JSON_DOC_SIZE   16384  // Increase for verbose block queries
#define CKB_HTTP_TIMEOUT_MS 10000
#define CKB_MAX_CELLS       64
#define CKB_MAX_TXS         32
```

## Examples

| Example | Description |
|---------|-------------|
| `BasicNodeInfo` | Tip, chain info, epoch, peers, latest block |
| `WatchAddress` | Poll for incoming payments, print amounts |
| `IndexerCells` | Paginate all cells, detect DAO/SUDT/xUDT |

## Use Cases

- **BlackBox POS** — watch merchant address for payment confirmation
- **Price/stats display** — show tip block, tx count, pool size on TFT
- **NerdMiner** — display live network stats alongside mining info
- **Wallet display** — show balance on e-ink or OLED
- **Whale watcher** — alert on large transfers (ESP32 + buzzer)

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

// Derive a deterministic private key from a passphrase + salt
// NOT BIP39 — simple SHA-256 stretch. Use for low-value / demo builds only.
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

For a production passphrase-derived key use a proper KDF (PBKDF2, scrypt, or Argon2)
with a high iteration count — mbedTLS includes PBKDF2 via `mbedtls/pkcs5.h`.

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
    const uint64_t MAX_TX_SHANNON   = CKBClient::ckbToShannon(100.0f);  // 100 CKB per tx
    const uint64_t MAX_DAILY_SHANNON = CKBClient::ckbToShannon(500.0f); // 500 CKB/day

    uint64_t shannon = CKBClient::ckbToShannon(amountCKB);
    if (shannon > MAX_TX_SHANNON) return CKB_ERR_INVALID;

    uint32_t now = millis() / 1000;
    if (now - dayStart > 86400) { dailySent = 0; dayStart = now; }  // reset daily
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

## License

MIT — see [LICENSE](LICENSE)

---

Built by [toastmanAu](https://github.com/toastmanAu) · Part of the [BlackBox](https://blackboxdata.xyz) CKB ecosystem
