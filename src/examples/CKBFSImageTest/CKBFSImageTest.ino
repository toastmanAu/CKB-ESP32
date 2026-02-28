/*
 * CKBFSImageTest.ino — Store a JPEG on CKB chain, retrieve, display, report
 * ===========================================================================
 * Hardware: ESP32-2432S028R (CYD — Cheap Yellow Display)
 *   ILI9341 320×240 TFT · XPT2046 touch · ESP32 (no PSRAM)
 *
 * Workflow:
 *   1. Download image from IMAGE_URL
 *   2. Display original on TFT
 *   3. Re-encode to JPEG at IMAGE_QUALITY (compress)
 *   4. Estimate + log CKBFS storage cost
 *   5. Publish image to CKB chain via CKBFS
 *   6. Wait for tx confirmation (~6s blocks)
 *   7. Retrieve raw bytes back from chain witness
 *   8. Display retrieved image, verify byte-for-byte match
 *   9. Send stats report + image to Telegram
 *
 * No hardcoded values — fill in config below, then flash.
 * Provide IMAGE_URL here in chat or via serial monitor.
 *
 * Dependencies (add to platformio.ini lib_deps):
 *   toastmanAu/CKB-ESP32
 *   bodmer/TFT_eSPI
 *   bodmer/TJpgDec
 *   bitbank2/JPEGENC
 *
 * Telegram delivery: uses raw HTTP POST (no TelegramSerial dependency).
 * TelegramSerial requires WiFi creds in constructor — not compatible here
 * since we manage WiFi ourselves for better control.
 *
 * PlatformIO env: see platformio_ckbfstest.ini
 * Repo: toastmanAu/CKB-ESP32 · examples/CKBFSImageTest
 */

// ═══════════════════════════════════════════════════════════════════
//  CONFIG — fill all fields, nothing has a default
// ═══════════════════════════════════════════════════════════════════

#define WIFI_SSID        ""    // your WiFi SSID
#define WIFI_PASS        ""    // your WiFi password

// CKB full node RPC (must have get_transaction, send_transaction)
#define CKB_NODE_URL     ""    // e.g. "http://192.168.68.87:8114"

// Funded wallet — needs at least 200 CKB (covers capacity + fees)
// 64 hex chars, no 0x prefix
#define PRIVKEY_HEX      ""

// Image source — direct link to a JPEG (PNG won't decode on TJpgDec)
// Keep under 100KB for reliable download on CYD SRAM budget
#define IMAGE_URL        ""    // e.g. "http://example.com/photo.jpg"
#define IMAGE_FILENAME   ""    // e.g. "test.jpg"

// JPEG re-encode quality (1=tiny/low quality, 100=large/lossless)
// 50-70 is a good balance for this test
#define IMAGE_QUALITY    60

// Telegram bot — for report delivery
#define TG_BOT_TOKEN     ""    // "1234567890:AAF..."
#define TG_CHAT_ID       ""    // your chat ID, e.g. "1790655432"

// ═══════════════════════════════════════════════════════════════════
//  MEMORY BUDGET (CYD has ~300KB usable heap after WiFi+TFT)
//  Keep image source under this limit
// ═══════════════════════════════════════════════════════════════════
#define IMG_BUF_SIZE  (90 * 1024)   // 90KB per buffer × 3 = 270KB total

// ═══════════════════════════════════════════════════════════════════
//  INCLUDES
// ═══════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <TFT_eSPI.h>
#include <TJpgDec.h>
#include <JPEGENC.h>
#include "CKB.h"
#include "CKBSigner.h"
#include "ckbfs.h"

// ═══════════════════════════════════════════════════════════════════
//  GLOBALS
// ═══════════════════════════════════════════════════════════════════
TFT_eSPI tft = TFT_eSPI();

// Image buffers — heap-allocated in setup() to avoid BSS overflow
static uint8_t *s_src_buf   = nullptr;   // downloaded source JPEG
static uint8_t *s_enc_buf   = nullptr;   // re-encoded (compressed) JPEG
static uint8_t *s_chain_buf = nullptr;   // retrieved from chain

static size_t s_src_len   = 0;
static size_t s_enc_len   = 0;
static size_t s_chain_len = 0;

static char s_tx_hash[67] = {};

// TJpgDec render target
static uint16_t s_render_x = 0, s_render_y = 0;

// Timing
static uint32_t t_total_start;
static uint32_t t_download_ms, t_encode_ms, t_publish_ms,
                t_confirm_ms,  t_retrieve_ms;

// ═══════════════════════════════════════════════════════════════════
//  DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════════════

// TJpgDec callback — writes directly to TFT (no framebuffer needed)
bool tft_block(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t *bmp) {
    if (y >= tft.height()) return false;
    tft.pushImage(x + s_render_x, y + s_render_y, w, h, bmp);
    return true;
}

void display_jpeg(const uint8_t *data, size_t len, const char *label) {
    tft.fillScreen(TFT_BLACK);

    uint16_t iw, ih;
    TJpgDec.setCallback(tft_block);
    TJpgDec.getJpgSize(&iw, &ih, data, len);

    uint8_t scale = 1;
    while ((iw / scale) > 320 || (ih / scale) > 240) scale *= 2;
    TJpgDec.setJpgScale(scale);

    s_render_x = (320 - iw / scale) / 2;
    s_render_y = (240 - ih / scale) / 2;
    TJpgDec.drawJpg(0, 0, data, len);

    // Label bar at bottom
    tft.fillRect(0, 224, 320, 16, TFT_BLACK);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setTextSize(1);
    tft.drawString(label, 4, 226);
}

void status(int y, const char *msg, uint16_t colour = TFT_WHITE) {
    tft.fillRect(0, y, 320, 14, TFT_BLACK);
    tft.setTextColor(colour, TFT_BLACK);
    tft.setTextSize(1);
    tft.drawString(msg, 4, y);
    Serial.println(msg);
}

// ═══════════════════════════════════════════════════════════════════
//  HTTP HELPERS
// ═══════════════════════════════════════════════════════════════════

bool http_download(const char *url, uint8_t *buf, size_t limit, size_t *out) {
    HTTPClient http;
    http.begin(url);
    http.setTimeout(20000);
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    int code = http.GET();
    if (code != 200) {
        Serial.printf("[DL] HTTP %d\n", code);
        http.end(); return false;
    }
    int clen = http.getSize();
    if (clen > (int)limit) {
        Serial.printf("[DL] Too large: %d > %d\n", clen, (int)limit);
        http.end(); return false;
    }
    WiFiClient *stream = http.getStreamPtr();
    size_t total = 0;
    uint32_t deadline = millis() + 20000;
    while (millis() < deadline && (clen < 0 || total < (size_t)clen)) {
        if (stream->available()) {
            total += stream->readBytes(buf + total, min(stream->available(), (int)(limit - total)));
        } else {
            if (!http.connected()) break;
            delay(5);
        }
    }
    http.end();
    *out = total;
    return total > 0;
}

// Send text message to Telegram
bool tg_send_text(const char *msg) {
    HTTPClient http;
    char url[128];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", TG_BOT_TOKEN);
    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    // Escape newlines in message for JSON
    String body = "{\"chat_id\":\"";
    body += TG_CHAT_ID;
    body += "\",\"text\":\"";
    String m(msg);
    m.replace("\\", "\\\\");
    m.replace("\"", "\\\"");
    m.replace("\n", "\\n");
    body += m;
    body += "\"}";

    int code = http.POST(body);
    http.end();
    Serial.printf("[TG] text: %d\n", code);
    return code == 200;
}

// Send image file to Telegram via sendPhoto (multipart/form-data)
bool tg_send_photo(const uint8_t *jpeg, size_t len, const char *caption) {
    // Build complete multipart body in one allocation
    const String boundary = "CKBFSBnd";
    String head = "--" + boundary + "\r\n"
                  "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
                  + String(TG_CHAT_ID) + "\r\n"
                  "--" + boundary + "\r\n"
                  "Content-Disposition: form-data; name=\"caption\"\r\n\r\n"
                  + String(caption) + "\r\n"
                  "--" + boundary + "\r\n"
                  "Content-Disposition: form-data; name=\"photo\"; filename=\"ckbfs.jpg\"\r\n"
                  "Content-Type: image/jpeg\r\n\r\n";
    String tail = "\r\n--" + boundary + "--\r\n";

    size_t total_len = head.length() + len + tail.length();

    // Allocate combined body
    uint8_t *body = (uint8_t *)malloc(total_len);
    if (!body) {
        Serial.printf("[TG] OOM for photo body (%zu bytes)\n", total_len);
        return false;
    }
    memcpy(body, head.c_str(), head.length());
    memcpy(body + head.length(), jpeg, len);
    memcpy(body + head.length() + len, tail.c_str(), tail.length());

    HTTPClient http;
    char url[128];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendPhoto", TG_BOT_TOKEN);
    http.begin(url);
    http.addHeader("Content-Type", "multipart/form-data; boundary=" + boundary);
    int code = http.POST(body, total_len);
    http.end();
    free(body);
    Serial.printf("[TG] photo: %d\n", code);
    return code == 200;
}

// ═══════════════════════════════════════════════════════════════════
//  JPEG RE-ENCODE (TJpgDec RGB565 → JPEGENC)
// ═══════════════════════════════════════════════════════════════════

// TJpgDec RGB565 capture into a heap buffer for JPEGENC
static uint16_t *s_rgb565   = nullptr;
static uint16_t  s_cap_w    = 0;
static uint16_t  s_cap_h    = 0;

bool capture_block(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t *bmp) {
    if (!s_rgb565) return false;
    for (int row = 0; row < h && (y + row) < s_cap_h; row++) {
        memcpy(s_rgb565 + (y + row) * s_cap_w + x,
               bmp + row * w,
               w * sizeof(uint16_t));
    }
    return true;
}

bool reencode_jpeg(const uint8_t *src, size_t src_len, int quality,
                   uint8_t *out, size_t out_size, size_t *out_len) {
    uint16_t iw, ih;
    TJpgDec.setJpgScale(1);
    TJpgDec.getJpgSize(&iw, &ih, src, src_len);
    if (!iw || !ih) return false;

    // Scale to fit 320×240
    uint8_t scale = 1;
    while ((iw / scale) > 320 || (ih / scale) > 240) scale *= 2;
    TJpgDec.setJpgScale(scale);
    iw /= scale; ih /= scale;

    // Allocate RGB565 decode buffer
    size_t rgb_bytes = iw * ih * sizeof(uint16_t);
    s_rgb565 = (uint16_t *)malloc(rgb_bytes);
    if (!s_rgb565) {
        Serial.printf("[ENC] OOM for RGB565 buf (%zu bytes)\n", rgb_bytes);
        return false;
    }
    memset(s_rgb565, 0, rgb_bytes);

    s_cap_w = iw; s_cap_h = ih;
    TJpgDec.setCallback(capture_block);
    TJpgDec.drawJpg(0, 0, src, src_len);

    // JPEGENC: RGB565 → JPEG
    JPEGENC jpg;
    JPEGENCODE enc;
    int buf_len = jpg.open(out, out_size);
    if (!buf_len) {
        free(s_rgb565); s_rgb565 = nullptr;
        Serial.println("[ENC] JPEGENC open failed");
        return false;
    }
    int rc = jpg.encodeBegin(&enc, iw, ih, JPEG_PIXEL_RGB565,
                              JPEG_SUBSAMPLE_420, quality);
    if (rc != JPEGE_SUCCESS) {
        free(s_rgb565); s_rgb565 = nullptr;
        Serial.printf("[ENC] encodeBegin failed: %d\n", rc);
        return false;
    }
    rc = jpg.addFrame(&enc, (uint8_t *)s_rgb565, iw * sizeof(uint16_t));
    if (rc != JPEGE_SUCCESS) {
        free(s_rgb565); s_rgb565 = nullptr;
        Serial.printf("[ENC] addFrame failed: %d\n", rc);
        return false;
    }
    *out_len = jpg.close();

    free(s_rgb565); s_rgb565 = nullptr;
    return *out_len > 0;
}

// ═══════════════════════════════════════════════════════════════════
//  CONFIRMATION POLL
// ═══════════════════════════════════════════════════════════════════

bool wait_confirmed(const char *tx_hash, uint32_t timeout_ms) {
    CKBClient ckb;
    ckb.setNodeUrl(CKB_NODE_URL);
    uint32_t start = millis();
    while (millis() - start < timeout_ms) {
        CKBTransaction tx = ckb.getTransaction(tx_hash);
        if (tx.status == CKB_TX_COMMITTED) return true;
        char buf[40];
        snprintf(buf, sizeof(buf), "Confirming... %lus",
                 (millis() - start) / 1000);
        status(220, buf, TFT_YELLOW);
        delay(3000);
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
//  SETUP — one-shot test
// ═══════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    delay(500);

    // TFT init
    tft.init();
    tft.setRotation(1);
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.setTextSize(1);
    tft.drawString("CKBFSImageTest v1.0", 4, 4);

    // Config check
    if (!strlen(WIFI_SSID) || !strlen(PRIVKEY_HEX) || !strlen(CKB_NODE_URL) ||
        !strlen(IMAGE_URL) || !strlen(TG_BOT_TOKEN) || !strlen(TG_CHAT_ID)) {
        status(20, "ERROR: Fill in all CONFIG fields", TFT_RED);
        while (1) delay(1000);
    }

    // Allocate image buffers from heap
    s_src_buf   = (uint8_t *)malloc(IMG_BUF_SIZE);
    s_enc_buf   = (uint8_t *)malloc(IMG_BUF_SIZE);
    s_chain_buf = (uint8_t *)malloc(IMG_BUF_SIZE);
    if (!s_src_buf || !s_enc_buf || !s_chain_buf) {
        status(20, "OOM — reduce IMG_BUF_SIZE", TFT_RED);
        Serial.printf("Free heap: %u\n", ESP.getFreeHeap());
        while (1) delay(1000);
    }
    Serial.printf("Heap after buffers: %u bytes free\n", ESP.getFreeHeap());

    // WiFi
    status(20, "Connecting WiFi...");
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts++ < 40) delay(500);
    if (WiFi.status() != WL_CONNECTED) {
        status(20, "WiFi failed!", TFT_RED); while (1) delay(1000);
    }
    status(20, ("WiFi: " + WiFi.localIP().toString()).c_str(), TFT_GREEN);

    // Key
    CKBKey key;
    if (!key.loadPrivateKeyHex(PRIVKEY_HEX)) {
        status(30, "Bad privkey!", TFT_RED); while (1) delay(1000);
    }
    char addr[110];
    key.getAddress(addr, sizeof(addr), true);
    Serial.println("Wallet: " + String(addr));

    tg_send_text(("🔑 Wallet: " + String(addr) + "\n🚀 CKBFSImageTest starting...").c_str());

    t_total_start = millis();

    // ── 1. DOWNLOAD ───────────────────────────────────────────────
    status(40, "1/8 Downloading image...");
    uint32_t t0 = millis();
    if (!http_download(IMAGE_URL, s_src_buf, IMG_BUF_SIZE, &s_src_len)) {
        status(40, "Download failed!", TFT_RED);
        tg_send_text("❌ Download failed"); while (1) delay(1000);
    }
    t_download_ms = millis() - t0;
    char msg[80];
    snprintf(msg, sizeof(msg), "1/8 Downloaded: %zuKB in %ums",
             s_src_len / 1024, t_download_ms);
    status(40, msg, TFT_GREEN);

    // ── 2. DISPLAY ORIGINAL ───────────────────────────────────────
    status(50, "2/8 Displaying original...");
    display_jpeg(s_src_buf, s_src_len, "Original");
    delay(2500);

    // ── 3. RE-ENCODE (COMPRESS) ───────────────────────────────────
    tft.fillScreen(TFT_BLACK);
    snprintf(msg, sizeof(msg), "3/8 Compressing (Q%d)...", IMAGE_QUALITY);
    status(4, msg);
    t0 = millis();
    if (!reencode_jpeg(s_src_buf, s_src_len, IMAGE_QUALITY,
                       s_enc_buf, IMG_BUF_SIZE, &s_enc_len)) {
        status(14, "Encode failed!", TFT_RED);
        tg_send_text("❌ JPEG encode failed"); while (1) delay(1000);
    }
    t_encode_ms = millis() - t0;
    float ratio = (float)s_src_len / s_enc_len;
    snprintf(msg, sizeof(msg), "3/8 %zuKB→%zuKB (%.1fx) %ums",
             s_src_len/1024, s_enc_len/1024, ratio, t_encode_ms);
    status(14, msg, TFT_GREEN);

    // ── 4. COST ESTIMATE ─────────────────────────────────────────
    ckbfs_cost_t cost;
    ckbfs_estimate_cost(s_enc_len, IMAGE_FILENAME, "image/jpeg", false, &cost);
    snprintf(msg, sizeof(msg), "4/8 Cost: %lluCKB locked, %.5f fee",
             cost.capacity_ckb, cost.fee_shannon / 1e8);
    status(24, msg, TFT_CYAN);
    Serial.printf("CKBFS cost: %llu CKB capacity, %llu shannon fee, %zu txs\n",
                  cost.capacity_ckb, cost.fee_shannon, cost.tx_count);

    // ── 5. PUBLISH TO CHAIN ───────────────────────────────────────
    status(34, "5/8 Publishing to CKB...");
    tg_send_text(("📤 Publishing " + String(s_enc_len/1024) + "KB to CKB chain...").c_str());
    t0 = millis();
    ckbfs_err_t ferr = ckbfs_publish(CKB_NODE_URL, key,
                                      s_enc_buf, s_enc_len,
                                      IMAGE_FILENAME, "image/jpeg",
                                      cost.capacity_ckb + 1,
                                      s_tx_hash);
    t_publish_ms = millis() - t0;
    if (ferr != CKBFS_OK) {
        snprintf(msg, sizeof(msg), "Publish failed: %d", (int)ferr);
        status(34, msg, TFT_RED);
        tg_send_text(("❌ Publish failed: " + String((int)ferr)).c_str());
        while (1) delay(1000);
    }
    snprintf(msg, sizeof(msg), "5/8 TX submitted (%ums)", t_publish_ms);
    status(34, msg, TFT_GREEN);
    Serial.println("TX: " + String(s_tx_hash));
    tg_send_text(("✅ TX submitted: " + String(s_tx_hash)).c_str());

    // ── 6. WAIT FOR CONFIRMATION ──────────────────────────────────
    status(44, "6/8 Waiting for confirmation...");
    t0 = millis();
    bool confirmed = wait_confirmed(s_tx_hash, 180000);  // 3 min max
    t_confirm_ms = millis() - t0;
    if (confirmed) {
        snprintf(msg, sizeof(msg), "6/8 Confirmed in %.1fs", t_confirm_ms / 1000.0f);
        status(44, msg, TFT_GREEN);
        tg_send_text(("✅ Confirmed in " + String(t_confirm_ms/1000) + "s").c_str());
    } else {
        status(44, "6/8 Timeout — continuing", TFT_YELLOW);
        tg_send_text("⚠️ Confirm timeout — retrieving anyway");
    }

    // ── 7. RETRIEVE FROM CHAIN ────────────────────────────────────
    status(54, "7/8 Retrieving from chain...");
    t0 = millis();
    ferr = ckbfs_read(CKB_NODE_URL, s_tx_hash, 1, 0,
                      s_chain_buf, IMG_BUF_SIZE, &s_chain_len);
    t_retrieve_ms = millis() - t0;
    if (ferr != CKBFS_OK) {
        snprintf(msg, sizeof(msg), "Retrieve failed: %d", (int)ferr);
        status(54, msg, TFT_RED);
        tg_send_text(("❌ Retrieve failed: " + String((int)ferr)).c_str());
        while (1) delay(1000);
    }
    snprintf(msg, sizeof(msg), "7/8 Retrieved %zuKB in %ums",
             s_chain_len/1024, t_retrieve_ms);
    status(54, msg, TFT_GREEN);

    // ── 8. DISPLAY FROM CHAIN + VERIFY ───────────────────────────
    bool match = (s_chain_len == s_enc_len &&
                  memcmp(s_chain_buf, s_enc_buf, s_enc_len) == 0);
    display_jpeg(s_chain_buf, s_chain_len,
                 match ? "From chain - MATCH" : "From chain - SIZE MISMATCH");
    delay(2500);

    // ── 9. REPORT ────────────────────────────────────────────────
    uint32_t t_total = millis() - t_total_start;

    char report[800];
    snprintf(report, sizeof(report),
        "🖼️ CKBFSImageTest Complete!\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        "📁 %s\n"
        "📏 Source:     %zu bytes (%.1fKB)\n"
        "🗜️ Compressed: %zu bytes (%.1fKB) Q%d — %.1fx\n"
        "🔗 TX: %s\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⏱️ Timing:\n"
        "  Download:  %ums\n"
        "  Encode:    %ums\n"
        "  Publish:   %ums\n"
        "  Confirm:   %us\n"
        "  Retrieve:  %ums\n"
        "  TOTAL:     %us (%.1fs)\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        "💰 Cost:\n"
        "  Locked: %llu CKB (permanent)\n"
        "  Fee:    %.6f CKB\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        "✅ Round-trip: %s",
        IMAGE_FILENAME,
        s_src_len,   s_src_len   / 1024.0f,
        s_enc_len,   s_enc_len   / 1024.0f, IMAGE_QUALITY, ratio,
        s_tx_hash,
        t_download_ms, t_encode_ms, t_publish_ms,
        t_confirm_ms / 1000,
        t_retrieve_ms, t_total / 1000, t_total / 1000.0f,
        cost.capacity_ckb, cost.fee_shannon / 1e8,
        match ? "PASS (bytes identical)" : "WARN (mismatch)"
    );

    Serial.println(report);
    tg_send_text(report);

    // Send the retrieved image as a photo
    char caption[80];
    snprintf(caption, sizeof(caption), "CKBFS image — %s", s_tx_hash);
    tg_send_photo(s_chain_buf, s_chain_len, caption);

    // Final TFT summary
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.drawString("CKBFS TEST COMPLETE", 60, 4);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(String(s_src_len/1024) + "KB -> " + String(s_enc_len/1024) + "KB (Q" + IMAGE_QUALITY + ")", 4, 20);
    tft.drawString(String(cost.capacity_ckb) + " CKB locked forever", 4, 30);
    tft.drawString("Total: " + String(t_total / 1000.0f, 1) + "s", 4, 40);
    tft.drawString(match ? "Round-trip: PASS" : "Round-trip: WARN", 4, 50);
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.drawString(String(s_tx_hash).substring(0, 20) + "...", 4, 60);

    // Free buffers
    free(s_src_buf);
    free(s_enc_buf);
    free(s_chain_buf);
}

void loop() {
    // One-shot — nothing to do. Reset board to run again.
    delay(5000);
}
