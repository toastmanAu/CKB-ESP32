
## Architecture Rules (established 2026-03-01)

### Platform-agnostic by default
All new code in this repo MUST compile on Linux/host with no Arduino SDK.

**The rule:** If you write it, it must pass `g++ -std=c++17 -Isrc -Isrc/blake2b -Isrc/trezor_crypto -Ithird_party/ArduinoJson/src` without errors.

**What this means in practice:**
- No bare `#include <Arduino.h>` — always guard with `#ifdef ARDUINO`
- No `String` return types — use `char* buf, size_t bufSize` pattern
- No `Serial.print*` — guard with `#ifdef ARDUINO` / `#else printf(...) #endif`
- No `HTTPClient`, `WiFiClient`, `millis()`, `delay()` outside `#ifdef ARDUINO`
- No `strlcpy` without the compat shim (already in `CKB.cpp` — add to new .cpp files if needed)

**Transport:** All HTTP/RPC calls go through `CKBTransport::rpc()`. Never call HTTPClient directly. The right transport is auto-selected at compile time:
- Arduino/PlatformIO → `CKBArduinoTransport`
- ESP-IDF (no Arduino) → `CKBIDFTransport`  
- Linux/host/tests → `CKBPosixTransport`
- Unit tests → `CKBMockTransport` (inject via `setTransport()`)

**JSON:** ArduinoJson is used throughout but is header-only. For host builds, clone it into `third_party/ArduinoJson/` and add `-Ithird_party/ArduinoJson/src` — already present in this repo.

### Host build command (canonical)
```bash
cd /home/phill/workspace/CKB-ESP32

# One-time: C objects that must be compiled as C11
gcc -std=c11 -w -c src/trezor_crypto/secp256k1.c -Isrc/trezor_crypto -Isrc -o test/secp256k1.o
gcc -std=c11 -w -c src/trezor_crypto/memzero.c   -Isrc/trezor_crypto -o test/memzero.o
gcc -std=c11 -w -c src/trezor_crypto/sha3.c       -Isrc/trezor_crypto -o test/sha3.o

# Compile any file:
g++ -std=c++17 -w \
  -Isrc -Isrc/blake2b -Isrc/trezor_crypto \
  -Ithird_party/ArduinoJson/src \
  -c src/YOUR_FILE.cpp -o /tmp/YOUR_FILE.o

# Full link (with crypto):
g++ -std=c++17 -w \
  -Isrc -Isrc/blake2b -Isrc/trezor_crypto \
  -Ithird_party/ArduinoJson/src \
  test/test_foo.cpp \
  src/CKB.cpp src/CKBSigner.cpp \
  src/blake2b/blake2b.c \
  src/trezor_crypto/bignum.c src/trezor_crypto/ecdsa.c \
  src/trezor_crypto/hasher.c src/trezor_crypto/hmac.c \
  src/trezor_crypto/sha2.c src/trezor_crypto/ripemd160.c \
  src/trezor_crypto/rand.c src/trezor_crypto/rfc6979.c \
  test/secp256k1.o test/memzero.o test/sha3.o \
  -o test/test_foo -lm
```

### New file checklist
Before committing any new `.h` or `.cpp`:
- [ ] Compiles with the host build command above
- [ ] No unguarded Arduino/platform types (`String`, `Serial`, `millis`, etc.)
- [ ] HTTP calls go through `CKBTransport`, not `HTTPClient` directly
- [ ] `printf` fallback provided alongside any `Serial.printf` block
