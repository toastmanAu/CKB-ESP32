/*
 * CKBFSImageTest.ino — Store an image on CKB chain, retrieve and view it
 * =======================================================================
 * Hardware: ESP32-2432S028R (CYD — Cheap Yellow Display)
 *   - ILI9341 320×240 TFT (SPI)
 *   - XPT2046 touch (SPI, shared bus)
 *   - ESP32-D0WD-V3 (4MB flash, 520KB SRAM)
 *
 * Workflow:
 *   1. Download image from IMAGE_URL
 *   2. JPEG decode → RGB565 framebuffer → display it
 *   3. Re-encode to JPEG at IMAGE_QUALITY (compress)
 *   4. Estimate CKBFS storage cost, log to Telegram
 *   5. Publish to CKB chain via CKBFS
 *   6. Wait for confirmation (~6 second blocks)
 *   7. Download back from chain (raw bytes from witness)
 *   8. JPEG decode → display on TFT (verify round-trip)
 *   9. Send image + stats report to Telegram chat
 *
 * Fill in config below — no variables are hardcoded.
 * All results (speed, size, cost, tx hash) sent to your Telegram chat.
 *
 * Dependencies (PlatformIO / Arduino Library Manager):
 *   - CKB-ESP32         (toastmanAu/CKB-ESP32)
 *   - TelegramSerial    (toastmanAu/TelegramSerial) -- for report delivery
 *   - TFT_eSPI          (Bodmer) -- ILI9341 driver for CYD
 *   - TJpgDec           (Bodmer) -- JPEG decoder (tiny, fits in SRAM)
 *   - esp32             (espressif) -- includes esp_camera JPEG encoder
 *
 * Repo: toastmanAu/CKB-ESP32 · examples/CKBFSImageTest
 */

// ═══════════════════════════════════════════════════════════════════
//  CONFIG — fill these in, no defaults provided
// ═══════════════════════════════════════════════════════════════════

// WiFi
#define WIFI_SSID       ""          // your WiFi SSID
#define WIFI_PASS       ""          // your WiFi password

// CKB node (full node with RPC open)
#define CKB_NODE_URL    ""          // e.g. "http://192.168.68.87:8114"

// CKB wallet — private key hex (no 0x prefix), needs ~200 CKB funded
#define PRIVKEY_HEX     ""          // 64 hex chars

// Image to store — direct URL to a JPEG or PNG
// Recommended: small image, <200KB, publicly accessible
#define IMAGE_URL       ""          // e.g. "http://example.com/photo.jpg"
#define IMAGE_FILENAME  ""          // e.g. "test-image.jpg"

// JPEG re-encode quality (1–100). Lower = smaller file, more compression.
// 60 is a good balance. 90 is near-lossless.
#define IMAGE_QUALITY   60

// Telegram for result delivery (TelegramSerial)
#define TG_BOT_TOKEN    ""          // your bot token
#define TG_CHAT_ID      ""          // your chat ID (e.g. "1790655432")

// ═══════════════════════════════════════════════════════════════════
//  INCLUDES
// ═══════════════════════════════════════════════════════════════════

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <TFT_eSPI.h>
#include <TJpgDec.h>
#include "CKB.h"
#include "CKBSigner.h"
#include "ckbfs.h"

// TelegramSerial for report delivery
#define TELEGRAM_BOT_TOKEN TG_BOT_TOKEN
#define TELEGRAM_CHAT_ID   TG_CHAT_ID
#include <TelegramSerial.h>
TelegramSerial tg(&Serial);

// ═══════════════════════════════════════════════════════════════════
//  CYD DISPLAY PINS (ESP32-2432S028R)
// ═══════════════════════════════════════════════════════════════════
// TFT_eSPI configured via User_Setup.h or build flags.
// CYD pin mapping (for reference):
//   TFT_MOSI=13, TFT_SCLK=14, TFT_CS=15, TFT_DC=2, TFT_RST=-1, TFT_BL=21
//   Touch: TOUCH_CS=33 (shared SPI bus)

TFT_eSPI tft = TFT_eSPI();

// ═══════════════════════════════════════════════════════════════════
//  BUFFERS
// ═══════════════════════════════════════════════════════════════════

// Raw downloaded image bytes (before re-encode)
static uint8_t s_raw_buf[200 * 1024];   // 200KB — enough for most source images
static size_t  s_raw_len = 0;

// Re-encoded JPEG bytes (what we store on chain)
static uint8_t s_jpeg_buf[200 * 1024];
static size_t  s_jpeg_len = 0;

// Retrieved bytes from chain (should match s_jpeg_buf)
static uint8_t s_chain_buf[200 * 1024];
static size_t  s_chain_len = 0;

// Display framebuffer (320×240 RGB565 = 150KB — tight, use DRAM)
static uint16_t s_fb[320 * 240];

// Confirmed tx hash
static char s_tx_hash[67] = {};

// ═══════════════════════════════════════════════════════════════════
//  TIMING
// ═══════════════════════════════════════════════════════════════════
static unsigned long t_download_start, t_download_end;
static unsigned long t_encode_start,   t_encode_end;
static unsigned long t_publish_start,  t_publish_end;
static unsigned long t_confirm_start,  t_confirm_end;
static unsigned long t_retrieve_start, t_retrieve_end;
static unsigned long t_total_start;

// ═══════════════════════════════════════════════════════════════════
//  TJpgDec callback — writes decoded pixels into s_fb
// ═══════════════════════════════════════════════════════════════════
static uint16_t s_tft_x = 0, s_tft_y = 0;
static uint16_t s_disp_w = 320, s_disp_h = 240;

static bool tft_output(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t *bitmap) {
    if (y >= s_disp_h) return false;
    // Store into framebuffer
    for (int row = 0; row < h && (y + row) < s_disp_h; row++) {
        for (int col = 0; col < w && (x + col) < s_disp_w; col++) {
            s_fb[(y + row) * s_disp_w + (x + col)] = bitmap[row * w + col];
        }
    }
    return true;
}

static void display_jpeg(const uint8_t *data, size_t len, const char *label) {
    tft.fillScreen(TFT_BLACK);
    TJpgDec.setCallback(tft_output);
    TJpgDec.setJpgScale(1);
    memset(s_fb, 0, sizeof(s_fb));

    uint16_t iw, ih;
    TJpgDec.getJpgSize(&iw, &ih, data, len);

    // Scale to fit 320×240
    uint8_t scale = 1;
    while (iw/scale > 320 || ih/scale > 240) scale *= 2;
    TJpgDec.setJpgScale(scale);

    s_tft_x = (320 - iw/scale) / 2;
    s_tft_y = (240 - ih/scale) / 2;
    s_disp_w = 320; s_disp_h = 240;

    TJpgDec.drawJpg(s_tft_x, s_tft_y, data, len);

    // Push framebuffer to TFT
    tft.pushImage(0, 0, 320, 240, s_fb);

    // Label overlay
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(1);
    tft.drawString(label, 4, 4);
}

// ═══════════════════════════════════════════════════════════════════
//  HTTP download into buffer
// ═══════════════════════════════════════════════════════════════════
static bool http_download(const char *url, uint8_t *buf, size_t buf_size, size_t *out_len) {
    HTTPClient http;
    http.begin(url);
    http.setTimeout(30000);
    int code = http.GET();
    if (code != 200) {
        Serial.printf("[CKBFS] HTTP %d for %s\n", code, url);
        http.end();
        return false;
    }
    int content_len = http.getSize();
    if (content_len > (int)buf_size) {
        Serial.printf("[CKBFS] Image too large: %d > %d\n", content_len, (int)buf_size);
        http.end();
        return false;
    }
    WiFiClient *stream = http.getStreamPtr();
    size_t total = 0;
    while (http.connected() && total < (size_t)content_len) {
        size_t avail = stream->available();
        if (avail) {
            size_t r = stream->readBytes(buf + total, min(avail, buf_size - total));
            total += r;
        }
        delay(1);
    }
    *out_len = total;
    http.end();
    return total > 0;
}

// ═══════════════════════════════════════════════════════════════════
//  JPEG re-encode using esp_jpg_encode (esp32 built-in)
// ═══════════════════════════════════════════════════════════════════
// We decode the source JPEG → RGB888, then re-encode at target quality.
// This lets us control compression ratio.

static uint8_t  *s_rgb_buf    = nullptr;   // heap-allocated RGB888
static size_t    s_rgb_w = 0, s_rgb_h = 0;
static size_t    s_rgb_len = 0;

// TJpgDec callback to build RGB888 buffer
static bool rgb_capture(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t *bitmap) {
    if (!s_rgb_buf) return false;
    for (int row = 0; row < h && (uint16_t)(y+row) < s_rgb_h; row++) {
        for (int col = 0; col < w && (uint16_t)(x+col) < s_rgb_w; col++) {
            uint16_t px = bitmap[row*w + col];
            size_t idx = ((y+row) * s_rgb_w + (x+col)) * 3;
            s_rgb_buf[idx+0] = ((px >> 11) & 0x1F) << 3;  // R
            s_rgb_buf[idx+1] = ((px >>  5) & 0x3F) << 2;  // G
            s_rgb_buf[idx+2] = ( px        & 0x1F) << 3;  // B
        }
    }
    return true;
}

// esp_jpg_encode output callback
static bool jpg_encode_cb(void *arg, size_t index, const uint8_t *data, size_t len) {
    if (s_jpeg_len + len > sizeof(s_jpeg_buf)) return false;
    memcpy(s_jpeg_buf + s_jpeg_len, data, len);
    s_jpeg_len += len;
    return true;
}

static bool reencode_jpeg(const uint8_t *src, size_t src_len, int quality) {
    uint16_t iw, ih;
    TJpgDec.setJpgScale(1);
    TJpgDec.getJpgSize(&iw, &ih, src, src_len);
    if (iw == 0 || ih == 0) return false;

    // Cap to 320×240 — CYD display size
    uint8_t scale = 1;
    while (iw/scale > 320 || ih/scale > 240) scale *= 2;
    iw /= scale; ih /= scale;
    TJpgDec.setJpgScale(scale);

    s_rgb_w = iw; s_rgb_h = ih;
    s_rgb_len = iw * ih * 3;
    s_rgb_buf = (uint8_t*)ps_malloc(s_rgb_len);   // PSRAM not available on CYD — use heap
    if (!s_rgb_buf) s_rgb_buf = (uint8_t*)malloc(s_rgb_len);
    if (!s_rgb_buf) { Serial.println("[CKBFS] OOM for RGB buffer"); return false; }
    memset(s_rgb_buf, 0, s_rgb_len);

    TJpgDec.setCallback(rgb_capture);
    TJpgDec.drawJpg(0, 0, src, src_len);  // populates s_rgb_buf

    // Re-encode
    s_jpeg_len = 0;
    // esp_jpg_encode: (void* src, esp_jpg_src_type, w, h, format, quality, cb, arg, chunksize)
    // Available as frame2jpg() when using esp_camera — fall back to writing raw RGB565 JPEG
    // via a minimal JFIF writer since esp32 non-camera builds don't expose frame2jpg.
    //
    // We use TJpgDec's output + a tiny JFIF wrapper.
    // For real JPEG encoding on CYD (no PSRAM, no camera), best option is JPEGENC library.
    // This sketch requires JPEGENC (Larry Bank):
    //   pio: lib_deps = bitbank2/JPEGENC
    //   Arduino: install "JPEGENC" by Larry Bank

    // JPEGENC is #included conditionally:
    #ifdef JPEGENC_H__
    JPEGENCODE jpe;
    JPEGENC jpg;
    jpg.open(s_jpeg_buf, sizeof(s_jpeg_buf));
    jpe.cx = jpe.cy = 0;
    jpe.iWidth = iw; jpe.iHeight = ih;
    jpe.iQFactor = quality;
    jpe.ucPixelType = JPEG_PIXEL_RGB888;
    jpe.iStride = iw * 3;
    jpe.iMCUCount = 0; jpe.pPixels = s_rgb_buf;
    jpg.addFrame(&jpe);
    s_jpeg_len = jpg.close();
    #else
    // Fallback: store raw RGB565 as-is with minimal BMP header
    // (not JPEG, but still valid binary — CKBFS stores any bytes)
    Serial.println("[CKBFS] JPEGENC not found — storing re-decoded RGB565 as BMP");
    // 54-byte BMP header
    uint32_t row_sz = iw * 2;
    uint32_t file_sz = 54 + ih * row_sz;
    s_jpeg_buf[0]='B'; s_jpeg_buf[1]='M';
    memcpy(s_jpeg_buf+2,  &file_sz, 4);
    memset(s_jpeg_buf+6,  0, 4);
    uint32_t off=54; memcpy(s_jpeg_buf+10, &off, 4);
    uint32_t hdr=40; memcpy(s_jpeg_buf+14, &hdr, 4);
    memcpy(s_jpeg_buf+18, &iw, 4); memcpy(s_jpeg_buf+22, &ih, 4);
    s_jpeg_buf[26]=1; s_jpeg_buf[27]=0;  // planes=1
    uint16_t bpp=16; memcpy(s_jpeg_buf+28, &bpp, 2);
    memset(s_jpeg_buf+30, 0, 24);
    for (uint32_t r=0; r<ih; r++) {
        // BMP stores bottom-up
        memcpy(s_jpeg_buf + 54 + r*row_sz,
               s_fb + (ih-1-r)*iw,
               row_sz);
    }
    s_jpeg_len = file_sz;
    #endif

    free(s_rgb_buf); s_rgb_buf = nullptr;
    return s_jpeg_len > 0;
}

// ═══════════════════════════════════════════════════════════════════
//  Wait for tx confirmation
// ═══════════════════════════════════════════════════════════════════
static bool wait_confirmed(CKBClient &ckb, const char *tx_hash, uint32_t timeout_ms) {
    uint32_t start = millis();
    char resp[512];
    while (millis() - start < timeout_ms) {
        // get_transaction status
        char body[200];
        snprintf(body, sizeof(body),
            "{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction\","
            "\"params\":[\"%s\"],\"id\":1}", tx_hash);
        if (ckb.rpcCall(body, resp, sizeof(resp))) {
            if (strstr(resp, "\"committed\"")) return true;
        }
        tft.drawString("Waiting for confirm...", 4, 220);
        delay(2000);
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
//  SEND IMAGE TO TELEGRAM
// ═══════════════════════════════════════════════════════════════════
static void send_image_to_telegram(const uint8_t *jpeg, size_t len, const char *caption) {
    // Use HTTP multipart upload to Telegram sendPhoto API
    HTTPClient http;
    char url[128];
    snprintf(url, sizeof(url),
             "https://api.telegram.org/bot%s/sendPhoto", TG_BOT_TOKEN);
    http.begin(url);

    String boundary = "----CKBFSBoundary";
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

    size_t total = head.length() + len + tail.length();
    http.addHeader("Content-Type", "multipart/form-data; boundary=" + boundary);
    http.addHeader("Content-Length", String(total));

    // Streaming upload
    WiFiClient *client = http.getStreamPtr();
    http.sendRequest("POST", (uint8_t*)head.c_str(), head.length());
    // Note: for large images, chunked send is better — simplified here
    http.sendRequest("POST", (uint8_t*)jpeg, len);
    http.sendRequest("POST", (uint8_t*)tail.c_str(), tail.length());
    int code = http.POST((uint8_t*)nullptr, 0);
    Serial.printf("[TG] sendPhoto: %d\n", code);
    http.end();
}

// ═══════════════════════════════════════════════════════════════════
//  SETUP
// ═══════════════════════════════════════════════════════════════════
void setup() {
    Serial.begin(115200);
    delay(500);

    // Display init
    tft.init();
    tft.setRotation(1);  // landscape
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setTextSize(1);
    tft.drawString("CKBFSImageTest", 4, 4);

    // Config sanity checks
    if (strlen(WIFI_SSID) == 0 || strlen(PRIVKEY_HEX) == 0 ||
        strlen(CKB_NODE_URL) == 0 || strlen(IMAGE_URL) == 0 ||
        strlen(TG_BOT_TOKEN) == 0 || strlen(TG_CHAT_ID) == 0) {
        tft.setTextColor(TFT_RED, TFT_BLACK);
        tft.drawString("CONFIG INCOMPLETE — fill in all fields", 4, 20);
        Serial.println("ERROR: All config fields must be filled in.");
        while (1) delay(1000);
    }

    // WiFi
    tft.drawString("Connecting WiFi...", 4, 20);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    int tries = 0;
    while (WiFi.status() != WL_CONNECTED && tries++ < 30) delay(500);
    if (WiFi.status() != WL_CONNECTED) {
        tft.setTextColor(TFT_RED); tft.drawString("WiFi failed!", 4, 30); while(1) delay(1000);
    }
    tft.drawString("WiFi OK: " + WiFi.localIP().toString(), 4, 30);
    Serial.println("WiFi: " + WiFi.localIP().toString());

    // Telegram init
    tg.begin(TG_BOT_TOKEN, TG_CHAT_ID);

    // Load key
    CKBKey key;
    if (!key.loadPrivateKeyHex(PRIVKEY_HEX)) {
        tft.setTextColor(TFT_RED); tft.drawString("Bad privkey!", 4, 40); while(1) delay(1000);
    }
    char addr[110]; key.getAddress(addr, sizeof(addr), true);
    Serial.println("Wallet: " + String(addr));
    tg.println("🔑 Wallet: " + String(addr));

    t_total_start = millis();

    // ── STEP 1: Download image ────────────────────────────────────
    tft.drawString("Step 1: Downloading image...", 4, 50);
    tg.println("📥 Downloading image from URL...");
    t_download_start = millis();
    if (!http_download(IMAGE_URL, s_raw_buf, sizeof(s_raw_buf), &s_raw_len)) {
        tft.setTextColor(TFT_RED); tft.drawString("Download failed!", 4, 60); while(1) delay(1000);
    }
    t_download_end = millis();
    Serial.printf("Downloaded %zu bytes in %lums\n", s_raw_len, t_download_end - t_download_start);

    // ── STEP 2: Display original ──────────────────────────────────
    tft.drawString("Step 2: Displaying original...", 4, 60);
    display_jpeg(s_raw_buf, s_raw_len, "Original");
    delay(2000);

    // ── STEP 3: Re-encode (compress) ─────────────────────────────
    tft.fillScreen(TFT_BLACK);
    tft.drawString("Step 3: Compressing (Q=" + String(IMAGE_QUALITY) + ")...", 4, 4);
    t_encode_start = millis();
    if (!reencode_jpeg(s_raw_buf, s_raw_len, IMAGE_QUALITY)) {
        tft.setTextColor(TFT_RED); tft.drawString("Encode failed!", 4, 14); while(1) delay(1000);
    }
    t_encode_end = millis();
    float ratio = (float)s_raw_len / s_jpeg_len;
    Serial.printf("Re-encoded: %zu → %zu bytes (%.1fx) in %lums\n",
                  s_raw_len, s_jpeg_len, ratio, t_encode_end - t_encode_start);

    // ── STEP 4: Cost estimate ─────────────────────────────────────
    ckbfs_cost_t cost;
    ckbfs_estimate_cost(s_jpeg_len, IMAGE_FILENAME, "image/jpeg", false, &cost);
    Serial.printf("CKBFS cost: %llu CKB locked, %llu shannon fee\n",
                  cost.capacity_ckb, cost.fee_shannon);
    tg.printf("📊 Cost estimate: %llu CKB locked (%.6f CKB fee) — %zu txs\n",
              cost.capacity_ckb, cost.fee_shannon / 1e8, cost.tx_count);

    // ── STEP 5: Publish to CKB chain ─────────────────────────────
    tft.fillScreen(TFT_BLACK);
    tft.drawString("Step 5: Publishing to CKB...", 4, 4);
    tg.println("⛓️ Publishing to CKB chain via CKBFS...");
    t_publish_start = millis();
    ckbfs_err_t err = ckbfs_publish(CKB_NODE_URL, key,
                                     s_jpeg_buf, s_jpeg_len,
                                     IMAGE_FILENAME, "image/jpeg",
                                     cost.capacity_ckb + 1,  // +1 CKB buffer
                                     s_tx_hash);
    t_publish_end = millis();
    if (err != CKBFS_OK) {
        tft.setTextColor(TFT_RED);
        tft.drawString("Publish failed: " + String((int)err), 4, 14);
        tg.printf("❌ Publish failed: %d\n", err);
        while(1) delay(1000);
    }
    Serial.printf("Published! TX: %s (%lums)\n", s_tx_hash, t_publish_end - t_publish_start);
    tft.drawString("TX: " + String(s_tx_hash).substring(0, 20) + "...", 4, 14);
    tg.println("✅ TX submitted: " + String(s_tx_hash));

    // ── STEP 6: Wait for confirmation ────────────────────────────
    tft.drawString("Step 6: Waiting for confirm (~6s)...", 4, 30);
    CKBClient ckb; ckb.setNodeUrl(CKB_NODE_URL);
    t_confirm_start = millis();
    bool confirmed = wait_confirmed(ckb, s_tx_hash, 120000);
    t_confirm_end = millis();
    if (!confirmed) {
        tft.setTextColor(TFT_YELLOW);
        tft.drawString("Timeout — continuing anyway", 4, 40);
        tg.println("⚠️ Confirmation timeout — may still confirm");
    } else {
        tft.drawString("Confirmed! " + String((t_confirm_end - t_confirm_start)/1000) + "s", 4, 40);
        tg.printf("✅ Confirmed in %lus\n", (t_confirm_end - t_confirm_start)/1000);
    }

    // ── STEP 7: Retrieve from chain ───────────────────────────────
    tft.drawString("Step 7: Retrieving from chain...", 4, 50);
    tg.println("📤 Retrieving image from chain...");
    t_retrieve_start = millis();
    err = ckbfs_read(CKB_NODE_URL, s_tx_hash, 1,
                     0,  // skip checksum verify for now
                     s_chain_buf, sizeof(s_chain_buf), &s_chain_len);
    t_retrieve_end = millis();
    if (err != CKBFS_OK) {
        tft.setTextColor(TFT_RED);
        tft.drawString("Retrieve failed: " + String((int)err), 4, 60);
        tg.printf("❌ Retrieve failed: %d\n", err);
        while(1) delay(1000);
    }

    // ── STEP 8: Display retrieved image ──────────────────────────
    bool match = (s_chain_len == s_jpeg_len &&
                  memcmp(s_chain_buf, s_jpeg_buf, s_jpeg_len) == 0);
    display_jpeg(s_chain_buf, s_chain_len, match ? "From chain (MATCH)" : "From chain");
    delay(2000);

    // ── STEP 9: Build stats report and send ──────────────────────
    unsigned long t_total = millis() - t_total_start;

    char report[1024];
    snprintf(report, sizeof(report),
        "🖼️ CKBFSImageTest Complete!\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "📁 File: %s\n"
        "📏 Original: %zu bytes (%.1f KB)\n"
        "🗜️ Compressed (Q%d): %zu bytes (%.1f KB) — %.1fx smaller\n"
        "🔗 TX Hash: %s\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⏱️ Timing:\n"
        "  Download:  %lums\n"
        "  Encode:    %lums\n"
        "  Publish:   %lums\n"
        "  Confirm:   %lus\n"
        "  Retrieve:  %lums\n"
        "  TOTAL:     %lums (%.1fs)\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "💰 Cost:\n"
        "  Capacity locked: %llu CKB (permanent)\n"
        "  Tx fee:          %.6f CKB\n"
        "  Total:           %.6f CKB\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "✅ Round-trip: %s",
        IMAGE_FILENAME,
        s_raw_len, s_raw_len / 1024.0f,
        IMAGE_QUALITY, s_jpeg_len, s_jpeg_len / 1024.0f,
        (float)s_raw_len / (s_jpeg_len > 0 ? s_jpeg_len : 1),
        s_tx_hash,
        t_download_end  - t_download_start,
        t_encode_end    - t_encode_start,
        t_publish_end   - t_publish_start,
        (t_confirm_end  - t_confirm_start) / 1000,
        t_retrieve_end  - t_retrieve_start,
        t_total, t_total / 1000.0f,
        cost.capacity_ckb,
        cost.fee_shannon / 1e8,
        cost.total_shannon / 1e8,
        match ? "PASS ✅ (bytes identical)" : "WARN ⚠️ (size mismatch)"
    );

    Serial.println(report);
    tg.println(report);

    // Send the actual image to Telegram
    send_image_to_telegram(s_chain_buf, s_chain_len,
                           ("CKBFS round-trip: " + String(s_tx_hash)).c_str());

    // Display final stats on TFT
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.drawString("COMPLETE", 4, 4);
    tft.drawString("TX: " + String(s_tx_hash).substring(0, 22), 4, 14);
    tft.drawString(String(s_raw_len/1024) + "KB → " + String(s_jpeg_len/1024) + "KB", 4, 24);
    tft.drawString(String(cost.capacity_ckb) + " CKB locked", 4, 34);
    tft.drawString("Total: " + String(t_total/1000.0f, 1) + "s", 4, 44);
    tft.drawString(match ? "Round-trip: PASS" : "Round-trip: WARN", 4, 54);
}

void loop() {
    // Nothing — one-shot test. Reset to run again.
    delay(5000);
}
