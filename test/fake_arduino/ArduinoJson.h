#pragma once
// ArduinoJson stub for CKB-ESP32 host builds
#ifndef ARDUINOJSON_VERSION
#define ARDUINOJSON_VERSION "stub"
#define ARDUINOJSON_MAJOR_VERSION 7

#include "../arduino_shims.h"
#include <string.h>

struct JsonVariant {
    const char* _s = nullptr;
    JsonVariant() = default;
    JsonVariant(const char* s) : _s(s) {}
    operator const char*() const { return _s ? _s : ""; }
    operator bool()        const { return _s && *_s && strcmp(_s,"false")!=0; }
    operator uint64_t()    const { return _s ? (uint64_t)strtoull(_s,nullptr,0) : 0; }
    operator uint32_t()    const { return _s ? (uint32_t)strtoul(_s,nullptr,0) : 0; }
    operator int()         const { return _s ? (int)atoi(_s) : 0; }
    bool isNull()          const { return !_s || !*_s; }
    bool is(const char*)   const { return false; }
    JsonVariant operator[](const char*) const { return JsonVariant(); }
    JsonVariant operator[](int)         const { return JsonVariant(); }
    bool containsKey(const char*)       const { return false; }
    // operator| (default value) — ArduinoJson v7
    const char* operator|(const char* d) const { return isNull() ? d : _s; }
    int         operator|(int d)         const { return isNull() ? d : (int)atoi(_s); }
    uint64_t    operator|(uint64_t d)    const { return isNull() ? d : (uint64_t)strtoull(_s,nullptr,0); }
    bool        operator|(bool d)        const { return isNull() ? d : (bool)*this; }
};

struct JsonObject  : JsonVariant {
    bool isNull() const { return true; }
    JsonVariant operator[](const char*) const { return JsonVariant(); }
};
struct JsonArray   : JsonVariant {
    int size() const { return 0; }
    JsonVariant operator[](int) const { return JsonVariant(); }
};

struct JsonDocument {
    char _buf[8192] = {};
    bool _ok = false;
    JsonVariant operator[](const char*) const { return JsonVariant(); }
    JsonVariant as() const { return JsonVariant(); }
    bool containsKey(const char*) const { return false; }
    void clear() { _ok = false; _buf[0]='\0'; }
};

// Also keep StaticJsonDocument for any code using it
template<size_t N>
struct StaticJsonDocument : JsonDocument {};

struct DeserializationError {
    bool ok;
    const char* c_str() const { return ok ? "Ok" : "Error"; }
    DeserializationError(bool v=false): ok(v) {}
    operator bool() const { return !ok; }  // true = error (ArduinoJson convention)
    bool operator==(const DeserializationError& o) const { return ok==o.ok; }
    bool operator!=(const DeserializationError& o) const { return ok!=o.ok; }
    static DeserializationError Ok;
};
inline DeserializationError DeserializationError::Ok(true);

static inline DeserializationError deserializeJson(JsonDocument& d, const char* s) {
    if (!s) return DeserializationError(false);
    strncpy(d._buf, s, sizeof(d._buf)-1); d._ok=true;
    return DeserializationError(true);
}
static inline DeserializationError deserializeJson(JsonDocument& d, const std::string& s) {
    return deserializeJson(d, s.c_str());
}
static inline DeserializationError deserializeJson(JsonDocument& d, WiFiClient&) {
    return DeserializationError(false);
}
template<size_t N>
static inline DeserializationError deserializeJson(StaticJsonDocument<N>& d, const char* s) {
    return deserializeJson(static_cast<JsonDocument&>(d), s);
}
template<size_t N>
static inline DeserializationError deserializeJson(StaticJsonDocument<N>& d, const std::string& s) {
    return deserializeJson(static_cast<JsonDocument&>(d), s.c_str());
}
#endif
