# esp8266-adblock

ESP8266 port of [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock):
a Pi-hole-style DNS blocker for the whole home network. It blocks ads, trackers, adult
sites, gambling, scams and malware, and forces SafeSearch. The blocklist is stored as
sorted 40-bit FNV-1a hashes in flash and binary-searched, so about 550k domains fit on a
board with 80 KB of RAM.

The blocklist format is identical to upstream, so `tools/build_blocklist.py` and upstream's
prebuilt `blocklist.bin` both work unchanged.

## Hardware

Any ESP8266 board with 4 MB flash (NodeMCU v2/v3, Wemos D1 mini). Power it from the
router's USB port or a phone charger and leave it running.

Flash layout (`eagle.flash.4m3m.ld`): 1 MB sketch + 3 MB LittleFS, room for about 600k
domains. Firmware OTA works while the firmware fits in the free half of the sketch area.
It is about 507 KB now. If OTA refuses a bigger build, flash it over USB.

## Build & flash

```bash
cp src/secrets.example.h src/secrets.h      # set WiFi (optional) and WEB_PASS / OTA_PASS
python3 tools/build_blocklist.py data/blocklist.bin <sources...>   # see "Family preset"
pio run -t upload                           # D1 mini: pio run -e d1_mini -t upload
pio run -t uploadfs                         # writes data/ (blocklist.bin, custom.txt)
pio device monitor
```

`data/custom.txt` (one domain per line, optional) seeds the custom block list.

## Family preset (what the board runs)

Hagezi Pro (ads/trackers) + NSFW (porn) + Gambling mini + Fake (fake shops/scams) + TIF mini
(phishing/malware/scam) + Pop-up ads + Perflyst SmartTV and Android tracking (TV ACR such
as Samba TV on TCL). That's about 549k domains / 2.6 MB:

```bash
H=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard
python3 tools/build_blocklist.py data/blocklist.bin \
  $H/pro-onlydomains.txt $H/nsfw-onlydomains.txt $H/gambling.mini-onlydomains.txt \
  $H/fake-onlydomains.txt $H/tif.mini-onlydomains.txt $H/popupads-onlydomains.txt \
  https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt \
  https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt
```

Upload the result from the dashboard (*Settings → Upload a new blocklist*) or with
`pio run -t uploadfs`. Don't set the *Automatic blocklist update* URL to upstream's release
asset while using this preset: it would replace the list with upstream's smaller one.

The firmware also forces **Google SafeSearch, YouTube Restricted Mode (moderate) and Bing
strict search** (`safeSearchIP()` in `src/main.cpp`).

## Scam protection

Two built-in checks on top of the blocklist, each with its own switch on the dashboard:

- **Remote-control apps:** AnyDesk, TeamViewer, RustDesk, AirDroid, UltraViewer, ToDesk,
  Chrome Remote Desktop, Quick Assist and others. Thai call-center scammers ("police",
  "DSI", "bank staff") make victims install one of these and then empty the account.
  Turn this off if someone in the home uses one for real IT support.
- **Fake bank / government sites:** a domain whose registered name uses a Thai bank or
  agency name (Krungthai/KTB, SCB, KBank, Bangkok Bank, Krungsri, ttb, GSB, PromptPay,
  TrueMoney, PEA/MEA/PWA, Thailand Post, DSI, SSO...) but isn't the official site, e.g.
  `krungthai-secure.xyz`, `scb-th.com`, `krungthai.co.th.login-secure.com`. Sites under
  `.go.th`, `.or.th`, `.co.th`, `.ac.th` and `.mi.th` are THNIC-verified and never flagged.

The dashboard lists recent hits with the device that tried them. **Always allowed** sites
override every block (blocklist, custom and scam checks), which fixes false positives.
The lists live in `REMOTE_APPS`, `BRAND_PARTS`, `BRAND_WORDS` and `BRAND_OFFICIAL` in
`src/main.cpp`.

## Dashboard

**http://adblock.local** (or the board's IP). It's mobile-first and follows the phone's
light/dark mode:

- Protection status with one-tap *Pause 5 min / 30 min / 1 hr* and *Turn back on*
- Block any website: paste a link or a Thai address such as `รัก.com`; it's converted to
  punycode automatically and shown in Thai letters
- Devices with block rates, a per-device *Block all* switch, and names you can edit
  (stored in your browser)
- Settings: system info, blocklist upload, scheduled update, firmware update, forget WiFi

Changes ask for the dashboard password (`WEB_USER` / `WEB_PASS` in `secrets.h`).

## Running 24/7

- **Power cut:** the board boots by itself when power returns.
- **Router down or rebooting:** short drops reconnect automatically. If WiFi stays down
  for 2 minutes, the board reboots. If it can't join at boot, it opens the setup network
  and retries every minute.
- **Memory:** it reboots itself if free heap drops below 6 KB.
- *Last restart* under Settings shows why it last restarted.

Stats reset on every restart. The blocklist, custom domains and banned devices are kept.

## WiFi setup

If the board can't join a network, it starts the open AP **`ESP-AdBlock-XXXX`**. Join it
and use the setup page (or open http://192.168.4.1). Saved credentials live in the SDK's
WiFi config sector, so `uploadfs` doesn't erase them. `secrets.h` WiFi is used as a fallback.

To forget WiFi, press **FLASH** (GPIO0) within 3 s of boot while the LED blinks, or use
*Settings → Forget WiFi*.

## Make the whole home use it

1. In the router's DHCP settings, set DNS to the board's IP. Give the board a fixed IP
   (DHCP reservation) first.
2. Turn off browser *Secure DNS* (Chrome/Edge/Firefox/Brave) and Android *Private DNS*.
   Otherwise those devices skip the board.
3. Test: `dig @<board-ip> doubleclick.net` should return `0.0.0.0`.

DNS can't remove ads inside YouTube, Facebook, Instagram, TikTok, LINE, or the Shopee/Lazada
apps (they come from the same servers as the content). It also doesn't cover phones on
mobile data or using a VPN.

## Differences from the C3 version

| | ESP32-C3 | ESP8266 |
|---|---|---|
| Blocklist space | 1.3 MB (~250k) | 3 MB (~600k) |
| Flash index | 4096 entries (20 KB) | 1024 entries (5 KB) + in-bucket binary search |
| Clients / custom domains / bans | 96 / 200 / 32 | 32 / 64 / 16 |
| WiFi creds store | NVS (Preferences) | SDK config sector |
| Forget-WiFi button | hold BOOT at power-on | press FLASH within 3 s after boot |
| SafeSearch | no | Google, YouTube, Bing |
| Self-healing reboot | no | WiFi down 2 min / low heap |
| Hostname | c3adblock.local | adblock.local |

## License

MIT, see [LICENSE](LICENSE). Original work by M-Abozaid.
