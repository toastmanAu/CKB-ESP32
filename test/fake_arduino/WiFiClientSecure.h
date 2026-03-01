#pragma once
#include "Arduino.h"
struct WiFiClientSecure : WiFiClient {
    void setInsecure() {}
    void setCACert(const char*) {}
};
