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
domains. A firmware update over WiFi stages the new image next to the running one, so the
firmware must stay under ~515 KB (it is ~509 KB). If an update is refused as too big, flash
it over USB.

## Build & flash

```bash
cp src/secrets.example.h src/secrets.h      # set WiFi (optional) and WEB_PIN
python3 tools/build_blocklist.py data/blocklist.bin <sources...>   # see "Family preset"
pio run -t upload                           # D1 mini: pio run -e d1_mini -t upload
pio run -t uploadfs                         # writes data/ (blocklist.bin, custom.txt)
pio device monitor
```

`data/custom.txt` (one domain per line, optional) seeds the custom block list.

After the first USB flash, everything updates over WiFi from the dashboard:

- **Firmware:** `pio run`, then upload `.pio/build/nodemcuv2/firmware.bin` in
  *Settings → Firmware*. Settings, lists and WiFi are kept.
- **Blocklist:** build a new `blocklist.bin` and upload it in *Settings → Blocklist*.

The dashboard asks for a 6-digit PIN (`WEB_PIN` in `src/secrets.h`), with no username. To
change it, edit `secrets.h`, rebuild, and upload the new firmware. From a computer:

```bash
curl -H "X-Pin: <PIN>" -F "f=@.pio/build/nodemcuv2/firmware.bin" http://adblock.local/update
curl -H "X-Pin: <PIN>" http://adblock.local/stats.json
```

## Family preset (what the board runs)

Hagezi Pro (ads/trackers) + NSFW (porn) + Gambling mini + Fake (fake shops/scams) + TIF mini
(phishing/malware/scam) + Pop-up ads + DoH/VPN/Proxy bypass + Perflyst SmartTV and Android
tracking (TV ACR such as Samba TV on TCL). That's about 566k domains / 2.7 MB:

```bash
H=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard
python3 tools/build_blocklist.py data/blocklist.bin \
  $H/pro-onlydomains.txt $H/nsfw-onlydomains.txt $H/gambling.mini-onlydomains.txt \
  $H/fake-onlydomains.txt $H/tif.mini-onlydomains.txt $H/popupads-onlydomains.txt \
  $H/doh-vpn-proxy-bypass-onlydomains.txt \
  https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt \
  https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt
```

Upload the result from the dashboard (*Settings → Blocklist → Upload*) or with
`pio run -t uploadfs`. Don't set the *Automatic blocklist update* URL to upstream's release
asset while using this preset: it would replace the list with upstream's smaller one.

The bypass list stops devices from skipping the box: encrypted DNS (Chrome/Edge/Firefox
*Secure DNS*, Android *Private DNS* set to a provider such as `dns.google`), VPN and proxy
apps, and **iCloud Private Relay**. For Private Relay the box answers with no address, as
Apple asks networks to, so iPhones and Macs show *"Private Relay is turned off for this
network"* and use the box. A device with Secure DNS or Private DNS forced on can't load
sites until it's switched back to automatic. If someone needs a VPN for work, add its
domain under **Always allowed**.

The firmware also forces **Google SafeSearch, YouTube Restricted Mode (moderate) and Bing
strict search** (`safeSearchIP()` in `src/main.cpp`).

## Scam protection

Three built-in checks on top of the blocklist, each with its own switch on the dashboard:

- **Remote-control apps:** AnyDesk, TeamViewer, RustDesk, AirDroid, UltraViewer, ToDesk,
  Chrome Remote Desktop, Quick Assist and others. Thai call-center scammers ("police",
  "DSI", "bank staff") make victims install one of these and then empty the account.
  Turn this off if someone in the home uses one for real IT support.
- **Fake bank / government sites:** a domain whose registered name uses a Thai bank or
  agency name (Krungthai/KTB, SCB, KBank, Bangkok Bank, Krungsri, ttb, GSB, PromptPay,
  TrueMoney, PEA/MEA/PWA, Thailand Post, DSI, SSO...) but isn't the official site, e.g.
  `krungthai-secure.xyz`, `scb-th.com`, `krungthai.co.th.login-secure.com`. Sites under
  `.go.th`, `.or.th`, `.co.th`, `.ac.th` and `.mi.th` are THNIC-verified and never flagged.
- **Virus & hacker addresses:** names under free dynamic-DNS and tunnel services (No-IP's
  `sytes.net`/`ddns.net`/`hopto.org`..., DuckDNS, FreeDNS, Dynu, ngrok, Cloudflare quick
  tunnels). Remote-access viruses (njRAT, AsyncRAT, Remcos...) use them to reach their
  owner. The services' own sites stay reachable, and `dyndns.org` isn't listed because
  home cameras update their address through it. If a camera or NAS at home uses one of
  these names, add it under **Always allowed**.

  A device that shows up here again and again (the hit counts up, e.g. `compaq.sytes.net ·
  Windows PC · 2,400×`) is probably infected: run a full antivirus scan on it.

The dashboard lists the last 10 threats with the device that tried them and how often. **Always allowed** sites
override every block (blocklist, custom and scam checks), which fixes false positives.
The lists live in `REMOTE_APPS`, `BRAND_PARTS`, `BRAND_WORDS`, `BRAND_OFFICIAL` and `HACKER_HOSTS` in
`src/main.cpp`.

## Dashboard

**http://adblock.local** (or the board's IP). Minimal, mobile-first, follows the phone's
light/dark mode. Five tabs:

- **Home:** blocked count, protection status with *Pause 5 min / 30 min / 1 h* and
  *Resume*, protection switches (remote-control apps, fake bank sites), recent scams stopped
- **Activity:** the last 64 sites looked up, with the device that asked, how often, and
  whether it was blocked. Filter by device or show blocked only; *Block* / *Allow* acts on
  the whole site. Lives in RAM only (cleared on restart).
- **Devices:** every device using the box, recognized automatically: names that Apple
  devices and TVs announce over Bonjour ("iPad ของ Thananon", "Thananon's MacBook Pro"),
  and the type (iPhone, iPad, Mac, Android, Android TV, Windows PC, smart TV, consoles)
  from the lookups each OS makes. Tap a name to rename it (stored in your browser).
- **Sites:** block or always-allow any website (links and Thai addresses such as `รัก.com`
  are converted automatically), with lists of both
- **Settings:** address, WiFi, memory, uptime, blocklist upload and auto-update, firmware
  update, forget WiFi

The dashboard opens with a PIN screen. Type the 6 digits and it unlocks; the phone remembers
the PIN, so it is asked only once. *Settings → Lock* forgets it on that phone. After 5 wrong
PINs the box refuses every try for 1 minute. The box has no HTTPS, so the PIN travels
unencrypted inside the home network: don't reuse it for anything important.

Notes on Devices:

- A device appears after its first lookup since the box last restarted; a sleeping phone
  can take a while.
- Phones that just got the new DNS from the router only switch when they reconnect to WiFi
  or renew their lease (up to the router's lease time, often 1 day).
- iPhones and Android phones don't announce a name, so they show as "Apple device" or
  "Android" until you rename them. Phones that rotate their private WiFi address show up as
  a new device and lose that name; set *Private Wi-Fi Address* to **Fixed** (iPhone) or
  *MAC address type* to **Phone MAC** (Android) on the home network to keep them stable.

## Memory

The ESP8266 has about 80 KB of RAM, so the firmware keeps the heap steady for 24/7 use:

- `/stats.json` and `/log.json` are streamed in 256-byte chunks instead of built as one big
  `String`
- custom and allow lists keep only 64-bit hashes in RAM; the names stay in LittleFS
- the setup portal, log messages and HTTP replies live in flash (`PROGMEM` / `F()`)
- the Activity log is a fixed 64-entry ring (~3.3 KB)
- device names are collected in 90-second mDNS bursts (at boot, when a new device appears,
  and every 30 min) because the mDNS library caches every answer while a query is installed

About 26 KB stays free with ~550k domains loaded (about 22 KB during a name burst).
*Settings → Memory* shows free heap and how much of it is in one piece.

## Running 24/7

- **Power cut:** the board boots by itself when power returns.
- **Router down or rebooting:** short drops reconnect automatically. If WiFi stays down
  for 2 minutes, the board reboots. If it can't join at boot, it opens the setup network
  and retries every minute.
- **Memory:** it reboots itself if free heap drops below 6 KB.
- *Last restart* under Settings shows why it last restarted.

Stats, the Devices list and the Activity log start empty after every restart. The
blocklist, custom and allowed sites, scam switches and blocked devices are kept.

## WiFi setup

If the board can't join a network, it starts the open AP **`ESP-AdBlock-XXXX`**. Join it
and use the setup page (or open http://192.168.4.1). Saved credentials live in the SDK's
WiFi config sector, so `uploadfs` doesn't erase them. `secrets.h` WiFi is used as a fallback.

To forget WiFi, press **FLASH** (GPIO0) within 3 s of boot while the LED blinks, or use
*Settings → Forget WiFi*.

## Make the whole home use it

1. Give the board a fixed IP (DHCP reservation for its MAC), then in the router's
   **LAN / DHCP** settings set the primary DNS to the board's IP. Leave the secondary
   empty, or set it to a [second board](#two-boards) — never to a public DNS such as
   8.8.8.8, which lets devices skip the blocking. Don't change the WAN DNS: then
   every lookup comes from the router and the Devices list shows only one device.
   No router reset is needed; devices switch when they reconnect.
2. Turn off browser *Secure DNS* (Chrome/Edge/Firefox/Brave) and Android *Private DNS*.
   Otherwise those devices skip the board.
3. Test: `dig @<board-ip> doubleclick.net` should return `0.0.0.0`.

If the board is unplugged or broken, devices can't look up any site. To go back, clear the
DNS fields in the router's DHCP settings and reconnect the devices.

### Two boards

A second ESP8266 can run alongside the first as the router's **secondary DNS**, so the
house stays online and filtered if one board crashes, restarts or loses power. Both
answer at the same time; each device picks one (often the primary, switching when it
doesn't answer).

```bash
pio run -e nodemcuv2_backup -t upload   --upload-port /dev/cu.usbserial-XXXX
pio run -e nodemcuv2_backup -t uploadfs --upload-port /dev/cu.usbserial-XXXX
```

The backup is the same firmware with the dashboard at **http://adblock2.local**. Give it
its own DHCP reservation and put its IP in the router's secondary DNS field. Firmware
updates use `.pio/build/nodemcuv2_backup/firmware.bin`.

The boards don't sync. Add custom blocks, allowed sites and scam switches on **both**
dashboards (or add them to `data/custom.txt`); stats, Devices and Activity are split
between them, and *Block device* only stops lookups that go to that board. Plug the two
into different chargers so one bad adapter can't take both down.

DNS can't remove ads inside YouTube, Facebook, Instagram, TikTok, LINE, or the Shopee/Lazada
apps (they come from the same servers as the content). It also doesn't cover phones on
mobile data or using a VPN.

## Troubleshooting

- **A site or app breaks:** press *Pause 5 min*. If it works while paused, find the blocked
  host in *Activity* (filter *Blocked*) and press *Allow*. Some sites need their own ad
  scripts to work; for example pantip's comments need `frukt.pantip.com`.
- **Ads still show:** the browser may use its own *Secure DNS*, or the ads come from the
  site's own domain. Find the ad host in *Activity* and press *Block*, or add a browser
  blocker such as uBlock Origin for in-page ads.
- **Devices missing:** see the notes under *Dashboard*.
- **Blocklist upload fails and *Sites listed* shows 0:** the box restarted mid-upload,
  usually because it was uploaded right after a restart, while the box is collecting
  device names and has the least memory. Wait until it has been up 2 minutes and upload
  again. Until then it doesn't block anything, but the internet keeps working.
- **Firmware update refused:** the build is over ~515 KB; flash over USB with
  `pio run -t upload`.

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
| Scam protection | no | remote-control apps, fake Thai bank/government sites |
| Allow list | no | overrides every block |
| Device names / type | no | Bonjour names + OS from lookups |
| Activity log | no | last 64 lookups, PIN-protected |
| Firmware update | dashboard + ArduinoOTA | dashboard only (keeps the image under ~515 KB) |
| Hostname | c3adblock.local | adblock.local |

## License

MIT, see [LICENSE](LICENSE). Original work by M-Abozaid.
