#pragma once
/*
 * CKBPosixTransport.h — POSIX/Linux/macOS/ESP-IDF transport (BSD sockets)
 *
 * Automatically selected when ARDUINO is not defined.
 * Works on: Linux, macOS, ESP-IDF (native POSIX socket layer),
 *           host-side unit tests.
 *
 * No external dependencies — pure BSD sockets + POSIX.
 */

#ifndef ARDUINO

#include "CKBTransport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Platform socket headers */
#if defined(ESP_PLATFORM) && !defined(ARDUINO)
  /* ESP-IDF */
  #include "lwip/sockets.h"
  #include "lwip/netdb.h"
#else
  /* Linux / macOS / host */
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <sys/select.h>
#endif

class CKBPosixTransport : public CKBTransport {
public:
    int rpc(const char* url, const char* body,
            char* out, size_t outCap, uint32_t timeoutMs) override {

        /* Parse http://host:port from url */
        char host[128] = {};
        int  port = 8114;
        const char* path = "/";

        const char* p = url;
        if (strncmp(p, "http://", 7) == 0) p += 7;

        /* extract host:port */
        const char* colon = strchr(p, ':');
        const char* slash = strchr(p, '/');
        if (colon && (!slash || colon < slash)) {
            size_t hlen = (size_t)(colon - p);
            if (hlen >= sizeof(host)) return CKB_TRANSPORT_HTTP_ERR;
            memcpy(host, p, hlen);
            port = atoi(colon + 1);
            if (slash) path = slash;
        } else if (slash) {
            size_t hlen = (size_t)(slash - p);
            if (hlen >= sizeof(host)) return CKB_TRANSPORT_HTTP_ERR;
            memcpy(host, p, hlen);
            path = slash;
        } else {
            if (strlen(p) >= sizeof(host)) return CKB_TRANSPORT_HTTP_ERR;
            strcpy(host, p);
        }

        /* Resolve host */
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char portstr[8]; snprintf(portstr, sizeof(portstr), "%d", port);
        if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
            return CKB_TRANSPORT_NO_CONN;

        int sock = socket(res->ai_family, res->ai_socktype, 0);
        if (sock < 0) { freeaddrinfo(res); return CKB_TRANSPORT_NO_CONN; }

        /* Set send/recv timeout */
        struct timeval tv;
        tv.tv_sec  = (long)(timeoutMs / 1000);
        tv.tv_usec = (long)((timeoutMs % 1000) * 1000);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
            freeaddrinfo(res); _close(sock);
            return CKB_TRANSPORT_NO_CONN;
        }
        freeaddrinfo(res);

        /* Build HTTP/1.1 request */
        size_t bodyLen = strlen(body);
        char req[1024];
        int reqLen = snprintf(req, sizeof(req),
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host, port, bodyLen);
        if (reqLen < 0 || (size_t)reqLen >= sizeof(req)) {
            _close(sock); return CKB_TRANSPORT_HTTP_ERR;
        }

        /* Send headers + body */
        if (send(sock, req, (size_t)reqLen, 0) < 0 ||
            send(sock, body, bodyLen, 0) < 0) {
            _close(sock); return CKB_TRANSPORT_TIMEOUT;
        }

        /* Receive full response into a temp buffer */
        static char _resp[65536];  /* 64 KB — matches CKB_JSON_BUF_SIZE max */
        size_t total = 0;
        ssize_t n;
        while ((n = recv(sock, _resp + total, sizeof(_resp) - total - 1, 0)) > 0)
            total += (size_t)n;
        _close(sock);
        _resp[total] = '\0';

        /* Skip HTTP headers (find \r\n\r\n) */
        const char* hdrEnd = strstr(_resp, "\r\n\r\n");
        if (!hdrEnd) return CKB_TRANSPORT_HTTP_ERR;
        const char* jsonStart = hdrEnd + 4;

        /* Check HTTP status */
        if (strncmp(_resp, "HTTP/1.", 7) != 0) return CKB_TRANSPORT_HTTP_ERR;
        int status = atoi(_resp + 9);
        if (status != 200) return CKB_TRANSPORT_HTTP_ERR;

        /* Handle chunked transfer encoding */
        bool chunked = (strstr(_resp, "Transfer-Encoding: chunked") != nullptr ||
                        strstr(_resp, "transfer-encoding: chunked") != nullptr);
        if (chunked) {
            jsonStart = _unchunk(jsonStart, out, outCap);
            if (!jsonStart) return CKB_TRANSPORT_BUF_SMALL;
            return (int)strlen(out);
        }

        size_t jsonLen = strlen(jsonStart);
        if (jsonLen + 1 > outCap) return CKB_TRANSPORT_BUF_SMALL;
        memcpy(out, jsonStart, jsonLen + 1);
        return (int)jsonLen;
    }

private:
    static void _close(int sock) {
#ifdef _WIN32
        ::closesocket(sock);
#else
        ::close(sock);
#endif
    }

    /* Simple chunked-encoding decoder — writes to out, returns out on success */
    static const char* _unchunk(const char* src, char* out, size_t outCap) {
        size_t written = 0;
        while (*src) {
            /* Read chunk size (hex) */
            char* end;
            size_t chunkSz = (size_t)strtoul(src, &end, 16);
            if (end == src) break;
            /* Skip \r\n after size line */
            src = end;
            while (*src == '\r' || *src == '\n') src++;
            if (chunkSz == 0) break; /* last chunk */
            if (written + chunkSz + 1 > outCap) return nullptr;
            memcpy(out + written, src, chunkSz);
            written += chunkSz;
            src += chunkSz;
            while (*src == '\r' || *src == '\n') src++;
        }
        out[written] = '\0';
        return out;
    }
};

#endif // !ARDUINO
