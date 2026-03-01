#pragma once
/*
 * CKBTransport.h — Platform-agnostic RPC transport interface
 * ─────────────────────────────────────────────────────────────────────────────
 * CKBClient calls rpc() for every JSON-RPC request. Swap the transport to
 * run the same library on any platform:
 *
 *   Arduino / PlatformIO  →  CKBArduinoTransport  (HTTPClient + WiFiClient)
 *   ESP-IDF               →  CKBIDFTransport       (esp_http_client)
 *   Linux / macOS / host  →  CKBPosixTransport     (BSD sockets)
 *   Unit tests            →  CKBMockTransport      (inject canned responses)
 *
 * Platform auto-selection happens in CKB.h unless you call
 * CKBClient::setTransport() to override.
 */

#include <stddef.h>
#include <stdint.h>

/* ── Transport error codes ─────────────────────────────────────────────────── */
#define CKB_TRANSPORT_OK         0
#define CKB_TRANSPORT_TIMEOUT   -1
#define CKB_TRANSPORT_HTTP_ERR  -2
#define CKB_TRANSPORT_BUF_SMALL -3
#define CKB_TRANSPORT_NO_CONN   -4

class CKBTransport {
public:
    virtual ~CKBTransport() {}

    /*
     * rpc() — Send a JSON-RPC POST and receive the response body.
     *
     * url        Full HTTP URL, e.g. "http://192.168.1.1:8114"
     * body       Complete JSON-RPC request body (null-terminated)
     * out        Caller-supplied buffer for the response
     * outCap     Capacity of out (bytes)
     * timeoutMs  Request timeout in milliseconds
     *
     * Returns bytes written to out (>0) on success,
     * or a negative CKB_TRANSPORT_* error code on failure.
     */
    virtual int rpc(const char* url,
                    const char* body,
                    char*       out,
                    size_t      outCap,
                    uint32_t    timeoutMs) = 0;
};
