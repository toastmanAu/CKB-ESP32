#pragma once
// arduino_shims.h — minimal Arduino API shims for CKB-ESP32 host tests
// Include before any CKB-ESP32 headers.

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <string>

// ── millis / delay ────────────────────────────────────────────────────────────
#define WY_ARDUINO_SHIMS_DEFINED
static uint32_t millis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
static void delay(uint32_t) {}
static void yield() {}

// ── IRAM_ATTR ─────────────────────────────────────────────────────────────────
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif
#ifndef DRAM_ATTR
#define DRAM_ATTR
#endif
#ifndef PROGMEM
#define PROGMEM
#endif

// min/max: intentionally not defined here (conflicts with std::numeric_limits)

// ── Arduino String → std::string ─────────────────────────────────────────────
typedef std::string String;
inline String String_from(const char* s) { return s ? s : ""; }
inline String operator+(const String& a, const char* b) { return a + std::string(b); }

// ── Serial stub ───────────────────────────────────────────────────────────────
struct _SerialStub {
    void begin(int) {}
    void print(const char* s)   { fputs(s, stdout); }
    void println(const char* s) { puts(s); }
    void printf(const char* f, ...) {
        va_list a; va_start(a, f); vprintf(f, a); va_end(a);
    }
    void flush() { fflush(stdout); }
};
static _SerialStub Serial;

// ── WiFiClient stub ───────────────────────────────────────────────────────────
#define WY_WIFI_CLIENT_DEFINED
struct WiFiClient {
    bool connect(const char*, uint16_t) { return false; }
    bool connected() const { return false; }
    bool available() const { return false; }
    int  read() { return -1; }
    size_t write(const uint8_t*, size_t n) { return n; }
    void stop() {}
};

// ArduinoJson stub: see test/fake_arduino/ArduinoJson.h

// ── Logging macros (CKB-ESP32 uses these) ─────────────────────────────────────
#define log_e(fmt,...) fprintf(stderr, "[E] " fmt "\n", ##__VA_ARGS__)
#define log_w(fmt,...) fprintf(stderr, "[W] " fmt "\n", ##__VA_ARGS__)
#define log_i(fmt,...) fprintf(stdout, "[I] " fmt "\n", ##__VA_ARGS__)
#define log_d(fmt,...)  /* debug suppressed in host tests */
