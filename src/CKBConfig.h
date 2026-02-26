#pragma once
/*
 * CKBConfig.h — Build configuration for CKB-ESP32
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * ── STEP 1: Choose a node type ───────────────────────────────────────────────
 * Define ONE before #including CKB.h, or in platformio.ini build_flags:
 *
 *   CKB_NODE_FULL      Full node (ckb) + built-in indexer  — default
 *   CKB_NODE_LIGHT     ckb-light-client (low sync overhead, built-in indexer)
 *   CKB_NODE_INDEXER   Full node + separate ckb-indexer process
 *   CKB_NODE_RICH      Full node + Mercury / ckb-rich-indexer
 *
 * ── STEP 2 (optional): Choose a profile preset ───────────────────────────────
 * Profiles tune capabilities and buffer sizes for a specific ESP32 use case.
 * Set in platformio.ini build_flags or before #including CKB.h.
 *
 *   CKB_PROFILE_MINIMAL
 *       Smallest possible footprint. Balance check only.
 *       Target: ESP32-C3 / C6 (4 MB flash, 400 KB RAM)
 *       Forces: CKB_NODE_LIGHT (if no node type set)
 *       Strips: block queries, peer queries, pool queries, send_tx
 *       Buffers: JSON=2048, cells=8, txs=4, peers=4
 *
 *   CKB_PROFILE_DISPLAY
 *       Balance + recent transactions. Read-only, no signing/send.
 *       Target: wallet displays, price trackers, ESP32-S3 TFT builds
 *       Strips: block queries, pool queries, send_tx
 *       Buffers: JSON=4096, cells=32, txs=16
 *
 *   CKB_PROFILE_SIGNER
 *       Sign + broadcast. Minimal indexer (balance only). No block explorer.
 *       Target: ESP32-P4 hardware wallet, POS terminal
 *       Includes: CKB_WITH_SIGNER, send_tx, balance check
 *       Strips: block queries, peer queries, pool queries
 *       Buffers: JSON=4096, cells=16
 *
 *   CKB_PROFILE_MONITOR
 *       Block explorer / node dashboard. Chain + network queries, no wallet.
 *       Target: node status displays, admin dashboards
 *       Includes: block queries, peer queries, pool queries
 *       Strips: indexer, send_tx
 *
 *   CKB_PROFILE_FULL
 *       Everything. Use on ESP32-S3 / P4 with ample flash.
 *       Includes: all capabilities + signer
 *       Buffers: JSON=16384, cells=64, txs=32
 *
 * ── STEP 3 (optional): Fine-grain overrides ──────────────────────────────────
 * Strip or add individual capabilities on top of the profile defaults.
 * Define before #including CKB.h:
 *
 *   CKB_NO_BLOCK_QUERIES  — strip getBlock*, getHeader*, getEpoch*, getTransaction
 *   CKB_NO_PEER_QUERIES   — strip getNodeInfo, getPeers, getBlockchainInfo
 *   CKB_NO_POOL_QUERIES   — strip getTxPoolInfo
 *   CKB_NO_SEND_TX        — strip sendTransaction, broadcast, buildTransfer
 *   CKB_NO_INDEXER        — strip getCells, getBalance, getTransactions, etc.
 *   CKB_WITH_SIGNER       — add CKBSigner integration (+~15 KB flash)
 *                           pulls in trezor_crypto + blake2b
 *                           adds CKBClient::signTx() convenience method
 *
 * ── STEP 4 (optional): Buffer size tuning ────────────────────────────────────
 * All #ifndef-guarded — set in platformio.ini build_flags or before #include:
 *
 *   CKB_JSON_DOC_SIZE    JSON parse arena, bytes          (default: 8192)
 *   CKB_MAX_CELLS        max cells per query result       (default: 64)
 *   CKB_MAX_TXS          max txs per query result         (default: 32)
 *   CKB_MAX_PEERS        max peers tracked                (default: 16)
 *   CKB_HTTP_TIMEOUT_MS  HTTP request timeout, ms         (default: 8000)
 *   CKB_TX_BUF_SIZE      Molecule serialisation buf, bytes (default: 2048)
 *   CKB_MAX_INPUTS       max inputs in a built tx         (default: 8)
 *   CKB_DEFAULT_FEE      default fee in shannon           (default: 1000)
 *
 * ── platformio.ini examples ───────────────────────────────────────────────────
 *
 *   [env:BalanceDisplay]             ; ESP32-S3 wallet display
 *   build_flags =
 *       -D CKB_NODE_LIGHT
 *       -D CKB_PROFILE_DISPLAY
 *       -D CKB_MAX_CELLS=16
 *
 *   [env:HardwareWallet]             ; ESP32-P4 signing device
 *   build_flags =
 *       -D CKB_NODE_LIGHT
 *       -D CKB_PROFILE_SIGNER
 *       -D CKB_WITH_SIGNER
 *
 *   [env:NodeMonitor]                ; Full node dashboard
 *   build_flags =
 *       -D CKB_NODE_FULL
 *       -D CKB_PROFILE_MONITOR
 *
 *   [env:TinyC3]                     ; Minimal ESP32-C3 balance checker
 *   build_flags =
 *       -D CKB_PROFILE_MINIMAL
 */

// ─── Profile presets ──────────────────────────────────────────────────────────
// Processed first so user-defined buffer sizes (#ifndef) win over profile defaults.

#if defined(CKB_PROFILE_MINIMAL)
  #if !defined(CKB_NODE_FULL) && !defined(CKB_NODE_LIGHT) && \
      !defined(CKB_NODE_INDEXER) && !defined(CKB_NODE_RICH)
    #define CKB_NODE_LIGHT
  #endif
  #define CKB_NO_BLOCK_QUERIES
  #define CKB_NO_PEER_QUERIES
  #define CKB_NO_POOL_QUERIES
  #define CKB_NO_SEND_TX
  #ifndef CKB_JSON_DOC_SIZE
    #define CKB_JSON_DOC_SIZE    2048
  #endif
  #ifndef CKB_MAX_CELLS
    #define CKB_MAX_CELLS        8
  #endif
  #ifndef CKB_MAX_TXS
    #define CKB_MAX_TXS          4
  #endif
  #ifndef CKB_MAX_PEERS
    #define CKB_MAX_PEERS        4
  #endif
  #ifndef CKB_HTTP_TIMEOUT_MS
    #define CKB_HTTP_TIMEOUT_MS  5000
  #endif

#elif defined(CKB_PROFILE_DISPLAY)
  #define CKB_NO_BLOCK_QUERIES
  #define CKB_NO_POOL_QUERIES
  #define CKB_NO_SEND_TX
  #ifndef CKB_JSON_DOC_SIZE
    #define CKB_JSON_DOC_SIZE    4096
  #endif
  #ifndef CKB_MAX_CELLS
    #define CKB_MAX_CELLS        32
  #endif
  #ifndef CKB_MAX_TXS
    #define CKB_MAX_TXS          16
  #endif

#elif defined(CKB_PROFILE_SIGNER)
  #define CKB_NO_BLOCK_QUERIES
  #define CKB_NO_PEER_QUERIES
  #define CKB_NO_POOL_QUERIES
  #ifndef CKB_WITH_SIGNER
    #define CKB_WITH_SIGNER
  #endif
  #ifndef CKB_JSON_DOC_SIZE
    #define CKB_JSON_DOC_SIZE    4096
  #endif
  #ifndef CKB_MAX_CELLS
    #define CKB_MAX_CELLS        16
  #endif

#elif defined(CKB_PROFILE_MONITOR)
  #define CKB_NO_INDEXER
  #define CKB_NO_SEND_TX
  #ifndef CKB_JSON_DOC_SIZE
    #define CKB_JSON_DOC_SIZE    8192
  #endif

#elif defined(CKB_PROFILE_FULL)
  #ifndef CKB_WITH_SIGNER
    #define CKB_WITH_SIGNER
  #endif
  #ifndef CKB_JSON_DOC_SIZE
    #define CKB_JSON_DOC_SIZE    16384
  #endif
  #ifndef CKB_MAX_CELLS
    #define CKB_MAX_CELLS        64
  #endif
  #ifndef CKB_MAX_TXS
    #define CKB_MAX_TXS          32
  #endif

#endif // profiles

// ─── Node type default ────────────────────────────────────────────────────────
#if !defined(CKB_NODE_FULL) && !defined(CKB_NODE_LIGHT) && \
    !defined(CKB_NODE_INDEXER) && !defined(CKB_NODE_RICH)
  #define CKB_NODE_FULL
#endif

// ─── Capability defaults from node type ───────────────────────────────────────
// Internal _CKB_DEFAULT_* flags — do not use directly.

#if defined(CKB_NODE_FULL)
  #define _CKB_DEF_BLOCK    1
  #define _CKB_DEF_PEER     1
  #define _CKB_DEF_POOL     1
  #define _CKB_DEF_INDEXER  1
  #define _CKB_DEF_SEND     1
  #define CKB_INDEXER_SAME_PORT  1
  #define CKB_NODE_TYPE_STR      "full"
#elif defined(CKB_NODE_LIGHT)
  #define _CKB_DEF_BLOCK    0
  #define _CKB_DEF_PEER     0
  #define _CKB_DEF_POOL     0
  #define _CKB_DEF_INDEXER  1
  #define _CKB_DEF_SEND     1
  #define CKB_INDEXER_SAME_PORT  1
  #define CKB_NODE_TYPE_STR      "light"
#elif defined(CKB_NODE_INDEXER)
  #define _CKB_DEF_BLOCK    1
  #define _CKB_DEF_PEER     1
  #define _CKB_DEF_POOL     1
  #define _CKB_DEF_INDEXER  1
  #define _CKB_DEF_SEND     1
  #define CKB_INDEXER_SAME_PORT  0
  #define CKB_NODE_TYPE_STR      "indexer"
#elif defined(CKB_NODE_RICH)
  #define _CKB_DEF_BLOCK    1
  #define _CKB_DEF_PEER     1
  #define _CKB_DEF_POOL     1
  #define _CKB_DEF_INDEXER  1
  #define _CKB_DEF_SEND     1
  #define _CKB_DEF_RICH     1
  #define CKB_INDEXER_SAME_PORT  0
  #define CKB_NODE_TYPE_STR      "rich"
#endif

// ─── Apply CKB_NO_* overrides → final CKB_HAS_* flags ────────────────────────

#if _CKB_DEF_BLOCK && !defined(CKB_NO_BLOCK_QUERIES)
  #define CKB_HAS_BLOCK_QUERIES 1
#else
  #define CKB_HAS_BLOCK_QUERIES 0
#endif

#if _CKB_DEF_PEER && !defined(CKB_NO_PEER_QUERIES)
  #define CKB_HAS_PEER_QUERIES 1
#else
  #define CKB_HAS_PEER_QUERIES 0
#endif

#if _CKB_DEF_POOL && !defined(CKB_NO_POOL_QUERIES)
  #define CKB_HAS_POOL_QUERIES 1
#else
  #define CKB_HAS_POOL_QUERIES 0
#endif

#if _CKB_DEF_INDEXER && !defined(CKB_NO_INDEXER)
  #define CKB_HAS_INDEXER 1
#else
  #define CKB_HAS_INDEXER 0
#endif

#if _CKB_DEF_SEND && !defined(CKB_NO_SEND_TX)
  #define CKB_HAS_SEND_TX 1
#else
  #define CKB_HAS_SEND_TX 0
#endif

#if defined(_CKB_DEF_RICH)
  #define CKB_HAS_RICH_INDEXER 1
#else
  #define CKB_HAS_RICH_INDEXER 0
#endif

#if defined(CKB_WITH_SIGNER)
  #define CKB_HAS_SIGNER 1
#else
  #define CKB_HAS_SIGNER 0
#endif

// ─── Buffer size defaults ─────────────────────────────────────────────────────
// Profiles may have already set some of these above.

#ifndef CKB_JSON_DOC_SIZE
  #define CKB_JSON_DOC_SIZE    8192
#endif
#ifndef CKB_HTTP_TIMEOUT_MS
  #define CKB_HTTP_TIMEOUT_MS  8000
#endif
#ifndef CKB_MAX_CELLS
  #define CKB_MAX_CELLS        64
#endif
#ifndef CKB_MAX_TXS
  #define CKB_MAX_TXS          32
#endif
#ifndef CKB_MAX_PEERS
  #define CKB_MAX_PEERS        16
#endif
#ifndef CKB_MAX_INPUTS
  #define CKB_MAX_INPUTS       8
#endif
#ifndef CKB_TX_BUF_SIZE
  #define CKB_TX_BUF_SIZE      2048
#endif
#ifndef CKB_DEFAULT_FEE
  #define CKB_DEFAULT_FEE      1000ULL
#endif
#ifndef CKB_MAX_LIGHT_SCRIPTS
  #define CKB_MAX_LIGHT_SCRIPTS 8
#endif
