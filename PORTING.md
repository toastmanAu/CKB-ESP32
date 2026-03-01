# CKB-ESP32 — Platform Portability Guide

CKB-ESP32 is designed to run on **any C++17 platform** with zero changes to
application code. The transport layer and JSON backend are swappable at
compile time.

## Supported Platforms

| Platform              | Transport              | JSON          | Status |
|-----------------------|------------------------|---------------|--------|
| Arduino / PlatformIO  | CKBArduinoTransport    | ArduinoJson   | ✅     |
| ESP-IDF (no Arduino)  | CKBIDFTransport        | ArduinoJson   | ✅     |
| Linux / macOS / host  | CKBPosixTransport      | ArduinoJson*  | ✅     |
| Unit tests            | CKBMockTransport       | ArduinoJson*  | ✅     |
| Rust FFI              | CKBPosixTransport      | ArduinoJson*  | 🔜     |

\* ArduinoJson is header-only. For non-Arduino builds, clone it into
  `third_party/ArduinoJson` and add `-Ithird_party/ArduinoJson/src` to
  your `CXXFLAGS` / `CMakeLists.txt`.

## What's already portable (zero deps)

- `ckb_blake2b.h` — CKB-personalised Blake2b-256
- `ckb_molecule.h` — Molecule serialisation (CKBBuf, mol_write_*)
- `ckb_bip39.h` — BIP39 mnemonic → BIP32 → CKB address
- `CKBSigner.h/.cpp` — secp256k1 sign/verify/recover
- `trezor_crypto/` — underlying crypto primitives

## Transport architecture

```
CKBClient
    └── CKBTransport (pure virtual)
            ├── CKBArduinoTransport  (Arduino: HTTPClient)
            ├── CKBIDFTransport      (ESP-IDF: esp_http_client)
            ├── CKBPosixTransport    (Linux/macOS: BSD sockets)
            └── CKBMockTransport     (tests: inject canned JSON)
```

### Override at runtime

```cpp
MyCustomTransport myTransport;
CKBClient ckb("http://192.168.1.1:8114");
ckb.setTransport(&myTransport);
```

### Implement your own

```cpp
class MyTransport : public CKBTransport {
public:
    int rpc(const char* url, const char* body,
            char* out, size_t outCap, uint32_t timeoutMs) override {
        // ... your HTTP implementation ...
        // return bytes written on success, negative CKB_TRANSPORT_* on error
    }
};
```

## Linux / host build

```bash
# 1. Get ArduinoJson (header-only, no build step)
git clone https://github.com/bblanchon/ArduinoJson third_party/ArduinoJson

# 2. Compile
g++ -std=c++17 \
  -Isrc -Isrc/blake2b -Isrc/trezor_crypto \
  -Ithird_party/ArduinoJson/src \
  your_app.cpp \
  src/CKB.cpp src/CKBSigner.cpp \
  src/blake2b/blake2b.c \
  src/trezor_crypto/bignum.c src/trezor_crypto/ecdsa.c \
  src/trezor_crypto/hasher.c src/trezor_crypto/hmac.c \
  src/trezor_crypto/sha2.c src/trezor_crypto/ripemd160.c \
  src/trezor_crypto/rand.c src/trezor_crypto/rfc6979.c \
  -o your_app -lm
```

## ESP-IDF (no arduino-esp32)

Add to your `CMakeLists.txt`:
```cmake
set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/components")
# Then add CKB-ESP32 as a component with its CMakeLists.txt
```

The library auto-detects `ESP_PLATFORM` and selects `CKBIDFTransport`.

## Arduino / PlatformIO (unchanged)

```ini
# platformio.ini — no changes required
lib_deps =
    https://github.com/toastmanAu/CKB-ESP32
    bblanchon/ArduinoJson
```

## String API changes

Two methods changed signature to avoid `String` return (Arduino-specific type):

```cpp
// Old (Arduino only):
String formatCKB(uint64_t shannon);
String formatCKBCompact(uint64_t shannon);

// New (all platforms):
char* formatCKB(uint64_t shannon, char* buf, size_t bufSize);
char* formatCKBCompact(uint64_t shannon, char* buf, size_t bufSize);

// Arduino convenience wrappers (still available):
String formatCKBStr(uint64_t shannon);
String formatCKBCompactStr(uint64_t shannon);
```
