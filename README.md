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

## License

MIT — see [LICENSE](LICENSE)

---

Built by [toastmanAu](https://github.com/toastmanAu) · Part of the [BlackBox](https://blackboxdata.xyz) CKB ecosystem
