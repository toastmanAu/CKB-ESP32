/*
 * TelegramSerialDemo.ino  —  TelegramSerial usage example
 *
 * Shows three usage patterns:
 *   1. Direct — send messages explicitly via tg.send() or tg.println()
 *   2. Mirror — also echoes everything to hardware Serial
 *   3. Drop-in — substitute into CKBTestBench by changing one line
 *
 * To use with CKBTestBench:
 *   1. Add TelegramSerial.h/.cpp to your project
 *   2. Fill in credentials below
 *   3. Change:  #define CKB_TEST_OUTPUT Serial
 *      To:      #define CKB_TEST_OUTPUT tg
 *   4. Call tg.begin() before runXxxTests(), tg.update() in loop()
 *
 * Author:  toastmanAu (Phill)
 * Repo:    https://github.com/toastmanAu/CKB-ESP32
 * License: MIT
 */

#include <Arduino.h>
#include "TelegramSerial.h"

// ── Credentials ───────────────────────────────────────────────────────────────
#define WIFI_SSID    "YourNetworkName"
#define WIFI_PASS    "YourPassword"
#define BOT_TOKEN    "123456789:ABC-YourBotTokenHere"
#define CHAT_ID      "-1001234567890"   // group/channel: negative; user: positive

// ── Instance ──────────────────────────────────────────────────────────────────
// Mirror to Serial so you can still see output locally.
// Remove &Serial arg to send only to Telegram.
TelegramSerial tg(WIFI_SSID, WIFI_PASS, BOT_TOKEN, CHAT_ID, &Serial);

// ── If using as CKBTestBench output target ─────────────────────────────────────
// Uncomment this line and include CKB.h / CKBTestBench headers:
// #define CKB_TEST_OUTPUT tg

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("Connecting...");
    if (!tg.begin()) {
        Serial.println("WiFi failed — output will buffer until connected");
    }

    // ── Pattern 1: send() for one-shot messages ────────────────────────────────
    tg.send("ESP32 booted — TelegramSerial ready");
    tg.update();   // flush immediately (optional — update() in loop handles it)

    // ── Pattern 2: println() exactly like Serial ───────────────────────────────
    tg.println("Chip: " + String(ESP.getChipModel()));
    tg.println("Free heap: " + String(ESP.getFreeHeap()) + " bytes");
    tg.println("CPU: " + String(ESP.getCpuFreqMHz()) + " MHz");

    // ── Pattern 3: printf-style via print() ───────────────────────────────────
    char buf[80];
    snprintf(buf, sizeof(buf), "Flash: %uMB  PSRAM: %uKB",
             ESP.getFlashChipSize() / (1024*1024),
             ESP.getPsramSize() / 1024);
    tg.println(buf);

    // Messages queue up and drain on each update() call in loop()
    Serial.printf("Queued: %d messages\n", tg.queued());
}

void loop() {
    // Drain the send queue — one message per call, rate-limited automatically
    tg.update();
    delay(100);
}
