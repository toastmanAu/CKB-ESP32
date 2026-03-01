#pragma once
#include "Arduino.h"
#include <string.h>

// strlcpy — not in standard glibc, Arduino provides it
#ifndef strlcpy
static inline size_t strlcpy(char* dst, const char* src, size_t sz) {
    if (!sz) return src ? strlen(src) : 0;
    strncpy(dst, src, sz-1); dst[sz-1]='\0';
    return src ? strlen(src) : 0;
}
#endif

struct HTTPClient {
    bool begin(const char*) { return false; }
    bool begin(WiFiClient&, const char*) { return false; }
    void addHeader(const char*, const char*) {}
    void setTimeout(int) {}
    void setConnectTimeout(int) {}
    int  POST(const String&) { return -1; }
    int  POST(const char*) { return -1; }
    int  GET() { return -1; }
    String getString() { return "{}"; }
    void end() {}
};
