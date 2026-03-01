#pragma once
/*
 * CKBIDFTransport.h — ESP-IDF transport (esp_http_client)
 *
 * Selected when ESP_PLATFORM is defined but ARDUINO is not
 * (i.e. pure ESP-IDF projects, not arduino-esp32).
 *
 * Dependencies: esp_http_client component (bundled in ESP-IDF).
 */

#if defined(ESP_PLATFORM) && !defined(ARDUINO)

#include "CKBTransport.h"
#include "esp_http_client.h"
#include <string.h>
#include <stdlib.h>

class CKBIDFTransport : public CKBTransport {
public:
    int rpc(const char* url, const char* body,
            char* out, size_t outCap, uint32_t timeoutMs) override {

        /* Accumulate response via event handler */
        _RxCtx ctx = { out, outCap, 0, false };

        esp_http_client_config_t cfg = {};
        cfg.url             = url;
        cfg.timeout_ms      = (int)timeoutMs;
        cfg.event_handler   = _httpEvt;
        cfg.user_data       = &ctx;

        esp_http_client_handle_t client = esp_http_client_init(&cfg);
        if (!client) return CKB_TRANSPORT_NO_CONN;

        esp_http_client_set_method(client, HTTP_METHOD_POST);
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_post_field(client, body, (int)strlen(body));

        esp_err_t err = esp_http_client_perform(client);
        int status    = esp_http_client_get_status_code(client);
        esp_http_client_cleanup(client);

        if (err != ESP_OK)  return CKB_TRANSPORT_TIMEOUT;
        if (status != 200)  return CKB_TRANSPORT_HTTP_ERR;
        if (ctx.overflow)   return CKB_TRANSPORT_BUF_SMALL;

        out[ctx.written] = '\0';
        return (int)ctx.written;
    }

private:
    struct _RxCtx {
        char*  buf;
        size_t cap;
        size_t written;
        bool   overflow;
    };

    static esp_err_t _httpEvt(esp_http_client_event_t* evt) {
        if (evt->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;
        auto* ctx = static_cast<_RxCtx*>(evt->user_data);
        size_t avail = ctx->cap - ctx->written - 1;
        if ((size_t)evt->data_len > avail) { ctx->overflow = true; return ESP_OK; }
        memcpy(ctx->buf + ctx->written, evt->data, evt->data_len);
        ctx->written += (size_t)evt->data_len;
        return ESP_OK;
    }
};

#endif // ESP_PLATFORM && !ARDUINO
