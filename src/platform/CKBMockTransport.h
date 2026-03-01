#pragma once
/*
 * CKBMockTransport.h — Deterministic mock transport for unit tests
 *
 * Inject a canned JSON-RPC response. The next rpc() call returns it.
 * Chain multiple responses for multi-call tests.
 *
 * Usage:
 *   CKBMockTransport mock;
 *   mock.enqueue(R"({"id":1,"jsonrpc":"2.0","result":"0x11e1a30a"})");
 *   CKBClient client("http://localhost:8114", &mock);
 *   uint64_t tip = client.getTipBlockNumber(); // returns 0x11e1a30a
 */

#include "CKBTransport.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define CKB_MOCK_QUEUE_MAX 16

class CKBMockTransport : public CKBTransport {
public:
    CKBMockTransport() : _head(0), _tail(0), _callCount(0) {}

    /* Enqueue a canned response (copied — safe to pass temporaries) */
    void enqueue(const char* json) {
        if ((_tail + 1) % CKB_MOCK_QUEUE_MAX == _head) return; // full
        strncpy(_queue[_tail], json, sizeof(_queue[0]) - 1);
        _queue[_tail][sizeof(_queue[0]) - 1] = '\0';
        _tail = (_tail + 1) % CKB_MOCK_QUEUE_MAX;
    }

    /* Enqueue a generic error response */
    void enqueueError(int code = -32000, const char* msg = "mock error") {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{\"id\":1,\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"%s\"}}",
            code, msg);
        enqueue(buf);
    }

    /* Clear all queued responses */
    void reset() { _head = _tail = _callCount = 0; }

    /* How many rpc() calls were made */
    int callCount() const { return _callCount; }

    /* Last body sent by CKBClient (for assertions) */
    const char* lastBody() const { return _lastBody; }

    int rpc(const char* /*url*/, const char* body,
            char* out, size_t outCap, uint32_t /*timeoutMs*/) override {
        _callCount++;
        strncpy(_lastBody, body, sizeof(_lastBody) - 1);
        _lastBody[sizeof(_lastBody) - 1] = '\0';

        if (_head == _tail) {
            /* Queue empty — return a minimal "not found" response */
            const char* empty = "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":null}";
            if (strlen(empty) + 1 > outCap) return CKB_TRANSPORT_BUF_SMALL;
            memcpy(out, empty, strlen(empty) + 1);
            return (int)strlen(empty);
        }

        const char* resp = _queue[_head];
        _head = (_head + 1) % CKB_MOCK_QUEUE_MAX;

        size_t len = strlen(resp);
        if (len + 1 > outCap) return CKB_TRANSPORT_BUF_SMALL;
        memcpy(out, resp, len + 1);
        return (int)len;
    }

private:
    char _queue[CKB_MOCK_QUEUE_MAX][8192];
    int  _head, _tail, _callCount;
    char _lastBody[1024] = {};
};
