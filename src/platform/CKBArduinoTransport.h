#pragma once
/*
 * CKBArduinoTransport.h — Arduino/PlatformIO transport (HTTPClient)
 *
 * Automatically selected on Arduino + PlatformIO targets.
 * Works with all ESP32 variants (ESP32, S2, S3, C3, C6, P4).
 *
 * Dependencies: HTTPClient (bundled in arduino-esp32 SDK)
 */

#ifdef ARDUINO

#include "CKBTransport.h"
#include <HTTPClient.h>
#include <string.h>

class CKBArduinoTransport : public CKBTransport {
public:
    int rpc(const char* url, const char* body,
            char* out, size_t outCap, uint32_t timeoutMs) override {

        HTTPClient http;
        http.begin(url);
        http.setTimeout((int)timeoutMs);
        http.addHeader("Content-Type", "application/json");

        int code = http.POST((uint8_t*)body, strlen(body));
        if (code < 0) { http.end(); return CKB_TRANSPORT_TIMEOUT; }
        if (code != 200) { http.end(); return CKB_TRANSPORT_HTTP_ERR; }

        String payload = http.getString();
        http.end();

        if (payload.length() + 1 > outCap) return CKB_TRANSPORT_BUF_SMALL;
        memcpy(out, payload.c_str(), payload.length() + 1);
        return (int)payload.length();
    }
};

#endif // ARDUINO
