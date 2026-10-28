#pragma once
// Copy this file to secrets.h and fill in your WiFi credentials.
// secrets.h is gitignored so your credentials never get committed.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// 6-digit PIN for the dashboard (everything except the page itself), the Activity log
// and firmware/blocklist uploads. Sent in an X-Pin header, so curl needs -H "X-Pin: ...".
static const char* WEB_PIN = "123456";
