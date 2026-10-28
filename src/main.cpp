// ESP8266 AdBlock — DNS sinkhole + web dashboard for the ESP8266 (port of esp32-c3-adblock).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.
//
// ESP8266 differences vs the C3 original:
//  - ~40KB of usable heap, so the flash index, client table and custom list are smaller
//  - WiFi creds live in the SDK's own config sector (no NVS/Preferences); it survives uploadfs
//  - GPIO0 (FLASH button) can't be held at power-on (it would enter the bootloader), so the
//    "forget WiFi" gesture is: press FLASH within 3 s after boot
//  - no on-die temperature sensor

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESP8266mDNS.h>
#include <ESP8266WebServer.h>
#include <Updater.h>           // firmware OTA
#include <ESP8266HTTPClient.h> // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch (BearSSL)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
#ifndef ADBLOCK_HOSTNAME
#define ADBLOCK_HOSTNAME "adblock"
#endif
static const char* HOSTNAME = ADBLOCK_HOSTNAME;    // -> http://adblock.local (backup board: adblock2)
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 1024;   // 5 KB first-level flash index (20 KB on the C3 is too much here)
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 64;         // bucket slice read in one go; larger buckets are narrowed first
static const int FORGET_PIN = 0;         // FLASH button on NodeMCU (GPIO0)
static const uint32_t WIFI_LOST_REBOOT_MS = 120000;   // reboot if WiFi stays down this long
static const uint32_t MIN_FREE_HEAP = 6000;           // reboot before fragmentation starves the stack

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
ESP8266WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheState[CACHE_SIZE];   // 0 = empty, 1 = not listed, 2 = listed
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; bool banned; uint8_t os; uint32_t blocked, allowed; };   // os: see OS_* below
static const int MAX_CLIENTS = 32;
Dev clients[MAX_CLIENTS]; int numClients = 0;

// A domain list kept as hashes in RAM and as text on flash (one domain per line), so
// the names themselves never sit in the heap. Used for the custom block and allow lists.
static uint64_t fnv40(const char* s, size_t n);
static void normDomain(String& d) { d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d.remove(0, 4); }
struct DomainList {
  const char* path; uint64_t* hash; int max; int count;
  bool has(uint64_t h) const { for (int i = 0; i < count; i++) if (hash[i] == h) return true; return false; }
  template <typename F> void each(F fn) const {
    File f = LittleFS.open(path, "r"); if (!f) return;
    char l[254];
    while (f.available()) {
      size_t n = f.readBytesUntil('\n', l, sizeof(l) - 1); l[n] = 0;
      while (n && (l[n-1] == '\r' || l[n-1] == ' ')) l[--n] = 0;
      if (n && strchr(l, '.')) fn(l);
    }
    f.close();
  }
  void load() { count = 0; each([this](const char* d) { if (count < max) hash[count++] = fnv40(d, strlen(d)); }); }
  bool add(String d) {
    normDomain(d);
    if (!d.length() || d.indexOf('.') < 0 || count >= max) return false;
    uint64_t h = fnv40(d.c_str(), d.length()); if (has(h)) return false;
    File f = LittleFS.open(path, "a"); if (!f) return false;
    f.println(d); f.close(); hash[count++] = h; return true;
  }
  void remove(String d) {
    normDomain(d);
    uint64_t h = fnv40(d.c_str(), d.length()); if (!has(h)) return;
    File out = LittleFS.open("/list.tmp", "w"); if (!out) return;
    each([&](const char* l) { if (fnv40(l, strlen(l)) != h) out.println(l); });
    out.close(); LittleFS.remove(path); LittleFS.rename("/list.tmp", path); load();
  }
};
static const int MAX_CUSTOM = 64, MAX_ALLOW = 32;
static uint64_t customHash[MAX_CUSTOM], allowHash[MAX_ALLOW];
static DomainList customList = { "/custom.txt", customHash, MAX_CUSTOM, 0 };
static DomainList allowList  = { "/allow.txt",  allowHash,  MAX_ALLOW,  0 };

static const int MAX_BAN = 16;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}
static uint64_t readHashAt(uint32_t pos) {
  uint8_t b[HASH_BYTES];
  blocklist.seek(pos * HASH_BYTES);
  blocklist.read(b, HASH_BYTES);
  return unpackHash(b);
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek(pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  memset(cacheState, 0, sizeof(cacheState));
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;

  // With a small index a bucket can hold a few hundred hashes: narrow it with single
  // reads until the remainder fits rangeBuf, then scan that slice in one flash read.
  while (endPos - startPos + 1 > (uint32_t)MAX_RANGE) {
    uint32_t mid = startPos + (endPos - startPos) / 2;
    uint64_t v = readHashAt(mid);
    if (v == h) return true;
    if (v < h) startPos = mid + 1; else endPos = mid - 1;
  }
  uint32_t rangeCount = endPos - startPos + 1;

  blocklist.seek(startPos * HASH_BYTES);
  blocklist.read(rangeBuf, rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (customList.has(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  uint8_t want[HASH_BYTES]; packHash(h, want);
  if (cacheState[slot] && memcmp(cacheKey[slot], want, HASH_BYTES) == 0) return cacheState[slot] == 2;
  bool res = inFlash(h);
  cacheState[slot] = res ? 2 : 1;
  memcpy(cacheKey[slot], want, HASH_BYTES);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
// ---------- scam protection ----------
// Three built-in checks on top of the blocklist, each with its own dashboard switch:
//  - remote-control apps: Thai call-center scammers talk victims into installing AnyDesk,
//    TeamViewer & co. and then empty the bank account through them
//  - fake bank/government sites: the registered name uses a Thai bank or agency name but
//    isn't the official site (krungthai-secure.xyz, scb-th.com, pea-refund.net, ...)
//  - hacker addresses: free dynamic-DNS and tunnel names (x.sytes.net, x.duckdns.org,
//    x.ngrok.io). Remote-access viruses use them to reach their owner; a PC asking for one
//    every few seconds is likely infected, so the hit list shows how often it asked.
// The allow list overrides every block (blocklist, custom, scam) to fix false positives.
static const char REMOTE_APPS[] PROGMEM =
  "anydesk.com anydesk.de teamviewer.com rustdesk.com airdroid.com airdroid.cn splashtop.com "
  "zohoassist.com assist.zoho.com logmein.com logme.in gotoassist.com screenconnect.com "
  "ultraviewer.net supremocontrol.com nanosystems.it getscreen.me remotepc.com iperiusremote.com "
  "aweray.com aweray.net oray.com oray.net todesk.com showmypc.com mikogo.com dwservice.net "
  "hoptodesk.com remoteutilities.com ammyy.com remotedesktop.google.com "
  "remotedesktop-pa.googleapis.com remoteassistance.support.services.microsoft.com";
// Matched anywhere inside the registered name ("mykrungthai-login" hits "krungthai").
static const char BRAND_PARTS[] PROGMEM =
  "krungthai kasikorn bangkokbank krungsri promptpay truemoney thaipost thailandpost scbeasy";
// Matched only as a whole word of the registered name ("scb-th" hits, "scuba" doesn't).
static const char BRAND_WORDS[] PROGMEM =
  "scb ktb kbank kplus bbl gsb mymo ttb baac uob cimb kkp ghb ghbank lhbank pea mea pwa dsi sso dol";
// Official non-.th sites that use those names (.go.th/.or.th/.co.th/.ac.th/.mi.th are
// THNIC-verified registrations and always trusted).
static const char BRAND_OFFICIAL[] PROGMEM =
  "krungthai.com kasikornbank.com bangkokbank.com krungsri.com krungsrionline.com scbeasy.com "
  "ttbbank.com cimbthai.com truemoney.com promptpay.io";

// Only names *under* these are blocked; the services' own sites stay reachable. dyndns.org
// is left out: home cameras update their address through members.dyndns.org.
static const char HACKER_HOSTS[] PROGMEM =
  "sytes.net ddns.net hopto.org zapto.org no-ip.org no-ip.biz no-ip.info myftp.org myftp.biz "
  "servehttp.com serveftp.com servegame.com servebeer.com serveblog.net servepics.com "
  "redirectme.net bounceme.net webhop.me myvnc.com ddnsking.com gotdns.ch 3utilities.com "
  "duckdns.org mooo.com us.to chickenkiller.com crabdance.com jumpingcrab.com ignorelist.com "
  "strangled.net dynu.net ddnsfree.com freeddns.org mywire.org linkpc.net publicvm.com "
  "ngrok.io ngrok-free.app ngrok.app trycloudflare.com serveo.net loca.lt portmap.io portmap.host";

static const int MAX_REMOTE = 48;
static uint64_t remoteHash[MAX_REMOTE]; static int numRemote = 0;
static bool scamRemoteOn = true, scamBankOn = true, scamHackerOn = true;
static uint32_t scamBlocked = 0;


struct ScamHit { char d[64]; uint32_t ip, at; uint8_t kind; uint16_t n; };   // kind 1 = remote app, 2 = fake brand, 3 = hacker address
static const int MAX_HITS = 10;
static ScamHit hits[MAX_HITS]; static int numHits = 0;           // hits[0] = newest

// Calls fn(word) for each space-separated word of a PROGMEM list until fn returns true.
template <typename F> static bool anyWord(PGM_P list, F fn) {
  char w[64]; size_t n = 0;
  for (PGM_P p = list; ; p++) {
    char ch = pgm_read_byte(p);
    if (ch == ' ' || ch == 0) {
      if (n) { w[n] = 0; if (fn(w)) return true; n = 0; }
      if (!ch) return false;
    } else if (n < sizeof(w) - 1) w[n++] = ch;
  }
}
// Same parent-suffix walk as isBlocked(): "a.b.anydesk.com" matches "anydesk.com".
static bool suffixIn(const char* d, const uint64_t* set, int n) {
  for (const char* p = d; p && *p; ) {
    uint64_t h = fnv40(p, strlen(p));
    for (int i = 0; i < n; i++) if (set[i] == h) return true;
    const char* dot = strchr(p, '.'); if (!dot || !strchr(dot + 1, '.')) break; p = dot + 1;
  }
  return false;
}
static bool isAllowed(const char* d) { return allowList.count && suffixIn(d, allowHash, allowList.count); }

// Registered name: last two labels, or three under ccTLD second levels (x.co.th, x.com.au).
static const char* registrable(const char* d, bool* thaiVerified) {
  const char* lab[3] = { d, d, d }; int found = 0;
  for (const char* p = d + strlen(d); p > d && found < 3; p--) if (p[-1] == '.') lab[found++] = p;
  *thaiVerified = false;
  if (found < 2) return d;
  size_t sldLen = lab[0] - lab[1] - 1, tldLen = strlen(lab[0]);
  static const char* const SLDS[] = { "co", "or", "go", "ac", "in", "mi", "com", "net", "org", "gov", "edu" };
  bool ccSld = false;
  if (tldLen == 2) for (const char* s : SLDS) if (strlen(s) == sldLen && strncmp(lab[1], s, sldLen) == 0) { ccSld = true; break; }
  if (!ccSld) return lab[1];
  *thaiVerified = strcmp(lab[0], "th") == 0 && sldLen == 2 && strncmp(lab[1], "in", 2) != 0;
  return found >= 3 ? lab[2] : d;
}
static bool fakeBrand(const char* d) {
  bool thaiVerified; const char* reg = registrable(d, &thaiVerified);
  if (thaiVerified) return false;
  if (anyWord(BRAND_OFFICIAL, [&](const char* w) { return strcmp(reg, w) == 0; })) return false;
  // A real-looking address used as a mere prefix: "krungthai.co.th.login-secure.com",
  // "kasikornbank.com.verify.net". The registered name is the scammer's.
  static const char* const TH_SLD[] = { ".co.th.", ".go.th.", ".or.th.", ".ac.th.", ".in.th." };
  for (const char* s : TH_SLD) if (strstr(d, s)) return true;
  if (reg > d) {
    String sub(d); sub.remove(reg - d);              // "kasikornbank.com."
    if (sub.indexOf(".com.") >= 0 &&
        anyWord(BRAND_PARTS, [&](const char* w) { return sub.indexOf(w) >= 0; })) return true;
  }
  char name[64]; size_t n = 0;                     // the chosen name, e.g. "krungthai-secure"
  while (reg[n] && reg[n] != '.' && n < sizeof(name) - 1) { name[n] = reg[n]; n++; }
  name[n] = 0;
  if (anyWord(BRAND_PARTS, [&](const char* w) { return strstr(name, w) != nullptr; })) return true;
  return anyWord(BRAND_WORDS, [&](const char* w) {
    size_t wl = strlen(w);
    for (const char* p = name; (p = strstr(p, w)); p++) {
      bool before = p == name || !isalpha((uint8_t)p[-1]);
      bool after  = !isalpha((uint8_t)p[wl]);
      if (before && after) return true;
    }
    return false;
  });
}
static bool hackerHost(const char* d) {
  size_t dl = strlen(d);
  return anyWord(HACKER_HOSTS, [&](const char* w) {
    size_t wl = strlen(w);
    if (dl <= wl + 1 || d[dl - wl - 1] != '.' || strcmp(d + dl - wl, w) != 0) return false;
    return !(dl == wl + 4 && strncmp(d, "www.", 4) == 0);   // www.duckdns.org etc. is the service itself
  });
}
static uint8_t scamKind(const char* d) {
  if (scamRemoteOn && suffixIn(d, remoteHash, numRemote)) return 1;
  if (scamBankOn && fakeBrand(d)) return 2;
  if (scamHackerOn && hackerHost(d)) return 3;
  return 0;
}
static void recordHit(const char* d, uint32_t ip, uint8_t kind) {
  scamBlocked++;
  // A repeat moves to the top with its count, so a virus calling home every few
  // seconds stays visible instead of filling the list.
  int i = 0;
  while (i < numHits && !(hits[i].ip == ip && strncmp(hits[i].d, d, sizeof(hits[i].d) - 1) == 0)) i++;
  ScamHit h = i < numHits ? hits[i] : ScamHit{};
  if (i == numHits) {
    if (numHits < MAX_HITS) numHits++;
    i = numHits - 1;
    strncpy(h.d, d, sizeof(h.d) - 1); h.d[sizeof(h.d) - 1] = 0; h.ip = ip; h.kind = kind;
  }
  for (; i > 0; i--) hits[i] = hits[i - 1];
  if (h.n < 0xFFFF) h.n++;
  h.at = millis(); hits[0] = h;
}

static void loadScam() {
  numRemote = 0;
  anyWord(REMOTE_APPS, [](const char* w) { if (numRemote < MAX_REMOTE) remoteHash[numRemote++] = fnv40(w, strlen(w)); return false; });
  File f = LittleFS.open("/scam.cfg", "r");
  if (!f) return;
  scamRemoteOn = f.readStringUntil('\n').toInt() != 0; scamBankOn = f.readStringUntil('\n').toInt() != 0;
  String h = f.readStringUntil('\n'); if (h.length()) scamHackerOn = h.toInt() != 0;   // older files have 2 lines
  f.close();
}
static void saveScam() { File f = LittleFS.open("/scam.cfg", "w"); if (!f) return; f.println(scamRemoteOn ? 1 : 0); f.println(scamBankOn ? 1 : 0); f.println(scamHackerOn ? 1 : 0); f.close(); }
static bool addAllow(const String& d) { customList.remove(d); return allowList.add(d); }   // allowing beats an older custom block

static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static void noteNewDevice(uint32_t ip);
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) {
    // A device's first lookup can arrive before its ARP entry exists: retry until known.
    Dev* c = &clients[i];
    if (!(c->mac[0] | c->mac[1] | c->mac[2] | c->mac[3] | c->mac[4] | c->mac[5])) getMac(ip, c->mac);
    return c;
  }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->banned = isBannedIP(ip); c->os = 0;
    noteNewDevice(ip);
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- device recognition ----------
// Two passive sources, no probing:
//  - names: Apple devices and TVs announce themselves over mDNS/Bonjour ("iPad ของ Thananon",
//    a TV's room name, its model); background service queries collect them per IP
//  - type: each OS looks up tell-tale hosts (Apple's, Google's Android connectivity check,
//    Microsoft's, TV makers'), so the domains a device queries reveal what it is
enum : uint8_t { OS_NONE, OS_APPLE, OS_IPHONE, OS_IPAD, OS_MAC, OS_APPLETV, OS_ANDROID, OS_ANDROIDTV,
                 OS_WINDOWS, OS_LINUX, OS_SMARTTV, OS_PLAYSTATION, OS_XBOX, OS_NINTENDO };
static uint8_t osRank(uint8_t os) {               // generic guesses can be refined by specific ones
  return os == OS_NONE ? 0 : (os == OS_APPLE || os == OS_ANDROID || os == OS_WINDOWS || os == OS_LINUX) ? 1 : 2;
}
// "suffix:type" pairs (type = OS_* number)
static const char OS_HINTS[] PROGMEM =
  "apple.com:1 icloud.com:1 mzstatic.com:1 swscan.apple.com:4 "
  "connectivitycheck.gstatic.com:6 android.clients.google.com:6 androidtvchannels-pa.googleapis.com:7 "
  "msftconnecttest.com:8 msftncsi.com:8 windowsupdate.com:8 "
  "connectivity-check.ubuntu.com:9 nmcheck.gnome.org:9 "
  "tclclouds.com:10 samsungcloudsolution.com:10 samsungacr.com:10 lgtvsdp.com:10 lgsmartad.com:10 "
  "playstation.net:11 xboxlive.com:12 nintendo.net:13";
static bool endsWithDomain(const char* d, const char* sfx) {
  size_t dl = strlen(d), sl = strlen(sfx);
  return dl >= sl && strcmp(d + dl - sl, sfx) == 0 && (dl == sl || d[dl - sl - 1] == '.');
}
static void learnOs(Dev* c, const char* domain) {
  if (osRank(c->os) == 2) return;
  anyWord(OS_HINTS, [&](const char* w) {
    char* colon = strchr((char*)w, ':'); if (!colon) return false;
    *colon = 0; uint8_t os = atoi(colon + 1);
    if (osRank(os) > osRank(c->os) && endsWithDomain(domain, w)) { c->os = os; return osRank(os) == 2; }
    return false;
  });
}

struct NetName { uint32_t ip; uint8_t os; char name[31]; };
static const int MAX_NAMES = 16;
static NetName netNames[MAX_NAMES]; static int numNames = 0, nextName = 0;
static const NetName* findName(uint32_t ip) { for (int i = 0; i < numNames; i++) if (netNames[i].ip == ip) return &netNames[i]; return nullptr; }
static void setName(uint32_t ip, const char* name, size_t len, uint8_t os) {
  NetName* n = (NetName*)findName(ip);
  if (!n) { n = &netNames[nextName]; nextName = (nextName + 1) % MAX_NAMES; if (numNames < MAX_NAMES) numNames++; n->ip = ip; n->os = 0; n->name[0] = 0; }
  if (len) { len = min(len, sizeof(n->name) - 1); memcpy(n->name, name, len); n->name[len] = 0; }
  if (osRank(os) >= osRank(n->os)) n->os = os;
}
// Works on a model ("iPad13,4", "MacBookPro18,1") or a device name ("iPad ของ Thananon").
static uint8_t osFromModel(const char* m) {
  if (!m) return OS_NONE;
  if (strstr(m, "iPhone")) return OS_IPHONE;
  if (strstr(m, "iPad")) return OS_IPAD;
  if (strstr(m, "AppleTV") || strstr(m, "Apple TV")) return OS_APPLETV;
  if (strstr(m, "Mac")) return OS_MAC;
  return OS_NONE;
}
// kind: 0 companion-link (Apple), 1 airplay, 2 androidtvremote2, 3 googlecast
static void onService(int kind, const MDNSResponder::MDNSServiceInfo& cinfo, MDNSResponder::AnswerType, bool set) {
  if (!set) return;
  auto& info = const_cast<MDNSResponder::MDNSServiceInfo&>(cinfo);
  const char* dom = info.serviceDomain();
  if (!dom || !info.IP4AddressAvailable()) return;
  std::vector<IPAddress> ips = info.IP4Adresses(); if (ips.empty()) return;
  const char* end = strstr(dom, "._"); size_t len = end ? (size_t)(end - dom) : strlen(dom);
  const char* name = dom;
  uint8_t os = OS_NONE;
  const char* model = info.txtAvailable() ? (kind == 0 ? info.value("rpMd") : kind == 1 ? info.value("model") : kind == 3 ? info.value("md") : nullptr) : nullptr;
  if (kind == 0) {
    os = osFromModel(model);
    if (!os) { String n(name); n.remove(len); os = osFromModel(n.c_str()); }   // iPads/iPhones often omit the model
    if (!os) os = OS_APPLE;
  }
  if (kind == 1) { os = osFromModel(model); if (!os) os = model ? OS_SMARTTV : OS_NONE; }
  if (kind == 2) os = OS_ANDROIDTV;
  if (kind == 3) {                                   // Chromecast/Google TV: instance is a UUID, use the friendly name
    const char* fn = info.txtAvailable() ? info.value("fn") : nullptr;
    if (fn) { name = fn; len = strlen(fn); }
    os = OS_ANDROIDTV;
  }
  setName((uint32_t)ips[0], name, len, os);
}
// The mDNS library keeps every answer cached while a query is installed, which costs several
// KB on a busy network. So listen in short bursts: names are copied into netNames, then the
// queries are removed. A burst runs at boot, when a new device shows up, and every 30 min.
static const uint32_t DISCOVERY_MS = 90000, DISCOVERY_EVERY_MS = 30UL * 60000, DISCOVERY_MIN_GAP_MS = 120000;
static MDNSResponder::hMDNSServiceQuery mdnsQ[4];
static bool discovering = false, discoveryWanted = true;
static uint32_t discoveryAt = 0;
static void startDeviceDiscovery() {
  mdnsQ[0] = MDNS.installServiceQuery("companion-link", "tcp", [](const MDNSResponder::MDNSServiceInfo& i, MDNSResponder::AnswerType t, bool s) { onService(0, i, t, s); });
  mdnsQ[1] = MDNS.installServiceQuery("airplay", "tcp",        [](const MDNSResponder::MDNSServiceInfo& i, MDNSResponder::AnswerType t, bool s) { onService(1, i, t, s); });
  mdnsQ[2] = MDNS.installServiceQuery("androidtvremote2", "tcp", [](const MDNSResponder::MDNSServiceInfo& i, MDNSResponder::AnswerType t, bool s) { onService(2, i, t, s); });
  mdnsQ[3] = MDNS.installServiceQuery("googlecast", "tcp",     [](const MDNSResponder::MDNSServiceInfo& i, MDNSResponder::AnswerType t, bool s) { onService(3, i, t, s); });
  discovering = true; discoveryWanted = false; discoveryAt = millis();
}
static void stopDeviceDiscovery() {
  for (auto& q : mdnsQ) if (q) { MDNS.removeServiceQuery(q); q = 0; }
  discovering = false; discoveryAt = millis();
}
static void deviceDiscoveryTick() {
  uint32_t since = millis() - discoveryAt;
  if (discovering) { if (since > DISCOVERY_MS) stopDeviceDiscovery(); }
  else if ((discoveryWanted && since > DISCOVERY_MIN_GAP_MS) || since > DISCOVERY_EVERY_MS) startDeviceDiscovery();
}
static void noteNewDevice(uint32_t ip) { if (!findName(ip)) discoveryWanted = true; }   // listen for its name soon

// ---------- lookup log ----------
// The last LOG_SIZE lookups (domain, device, result) for the dashboard's Activity tab.
// RAM only: it starts empty after a restart and never wears the flash. A device repeating
// a recent lookup bumps that line's count instead of pushing older lines out.
enum : uint8_t { LOG_ALLOWED, LOG_BLOCKED, LOG_SCAM, LOG_TRUNC = 0x80 };
struct LogEntry { uint32_t ip, at; uint16_t count; uint8_t status; char d[41]; };   // 52 bytes
static const int LOG_SIZE = 64;                                                     // ~3.3 KB
static LogEntry qlog[LOG_SIZE]; static int logHead = 0, logCount = 0;
static void logQuery(const char* d, size_t len, uint32_t ip, uint8_t status) {
  if (endsWithDomain(d, "arpa") || endsWithDomain(d, "local")) return;
  const size_t keep = sizeof(qlog[0].d) - 1;
  if (len > keep) { d += len - keep; len = keep; status |= LOG_TRUNC; }   // keep the end: the site's own name
  for (int k = 1; k <= min(logCount, 8); k++) {
    LogEntry& e = qlog[(logHead - k + LOG_SIZE) % LOG_SIZE];
    if (e.ip == ip && strcmp(e.d, d) == 0) { e.at = millis(); e.status = status; if (e.count < 0xFFFF) e.count++; return; }
  }
  LogEntry& e = qlog[logHead];
  e.ip = ip; e.at = millis(); e.count = 1; e.status = status; memcpy(e.d, d, len); e.d[len] = 0;
  logHead = (logHead + 1) % LOG_SIZE; if (logCount < LOG_SIZE) logCount++;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
// Answer an A query with `ip` (0.0.0.0 = sinkholed); any other qtype gets an empty
// NOERROR answer, so AAAA/HTTPS lookups can't route around the forced IPv4 answer.
static int buildAnswer(int qend, uint16_t qtype, const IPAddress& ip) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, ip[0],ip[1],ip[2],ip[3]};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}

// iCloud Private Relay hides lookups from the box. Apple devices turn it off for the
// network (with a notice) only on a negative answer, not on 0.0.0.0, so blocked relay
// hosts get an empty answer for every type.
static bool privateRelay(const char* d) { return strcmp(d, "mask.icloud.com") == 0 || strcmp(d, "mask-h2.icloud.com") == 0; }

// Forced SafeSearch / YouTube Restricted Mode: answer the search hosts with the providers'
// published "safe" addresses (forcesafesearch.google.com, restrictmoderate.youtube.com,
// strict.bing.com). Those servers present valid certs for the normal hostnames.
static const IPAddress SAFE_GOOGLE(216, 239, 38, 120);
static const IPAddress SAFE_YOUTUBE(216, 239, 38, 119);   // .120 = strict Restricted Mode
static const IPAddress SAFE_BING(204, 79, 197, 220);
static const char* const YOUTUBE_HOSTS[] = {
  "youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com", "youtube-nocookie.com",
};
static bool safeSearchIP(const char* d, IPAddress& ip) {   // d has "www." already stripped
  if (strncmp(d, "google.", 7) == 0) { ip = SAFE_GOOGLE; return true; }   // google.com, google.co.th, ...
  for (const char* h : YOUTUBE_HOSTS) if (strcmp(d, h) == 0) { ip = SAFE_YOUTUBE; return true; }
  if (strcmp(d, "bing.com") == 0) { ip = SAFE_BING; return true; }
  return false;
}
// Forward to upstream and wait for the reply that actually belongs to THIS query:
// drain stale datagrams first, send with a fresh random txid, and only accept a reply
// whose txid, question section, and source address/port match. The client's own txid
// is restored on the way back. (On the ESP8266, parsePacket() discards any unread
// remainder of the previous datagram, so it doubles as the drain.)
static int forwardUpstream(int qlen, int qend) {
  while (upstreamCli.parsePacket() > 0) {}               // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)ESP.random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    if (c && dl) learnOs(c, domain);
    bool ban = c && c->banned;
    bool blocked = ban;
    uint8_t scam = 0;
    if (!ban && blockingOn && dl && !isAllowed(domain)) {
      scam = scamKind(domain);
      if (scam) recordHit(domain, (uint32_t)cip, scam);
      blocked = scam || (numHashes && isBlocked(domain));
    }
    int rlen;
    IPAddress safeIP;
    if (blocked) { rlen = buildAnswer(qend, privateRelay(domain) ? 0 : qtype, IPAddress(0, 0, 0, 0)); totalBlocked++; if (c) c->blocked++; }
    else if (blockingOn && dl && safeSearchIP(domain, safeIP)) { rlen = buildAnswer(qend, qtype, safeIP); totalAllowed++; if (c) c->allowed++; }
    else         { rlen = forwardUpstream(qlen, qend);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
    if (dl) logQuery(domain, dl, (uint32_t)cip, scam ? LOG_SCAM : blocked ? LOG_BLOCKED : LOG_ALLOWED);
  }
  return did;
}

// ---------- web ----------
// HTML text/attribute escaping for the setup portal: a scanned SSID or the submitted
// WiFi name is attacker-controllable during provisioning (the portal AP is open).
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM)

// Streams a response in 256-byte chunks, so the stats JSON never needs one big heap
// block however many devices and domains it lists (the dashboard polls it every 3 s).
struct ChunkOut {
  char b[256]; size_t n = 0;
  void flush() { if (n) { web.sendContent(b, n); n = 0; } }
  void raw(const char* s, size_t l) {
    while (l) { size_t k = min(l, sizeof(b) - n); memcpy(b + n, s, k); n += k; s += k; l -= k; if (n == sizeof(b)) flush(); }
  }
  void lit(PGM_P s) { for (char c; (c = pgm_read_byte(s++)); ) raw(&c, 1); }      // PROGMEM literal
  void str(const char* s) {                                                    // JSON string
    raw("\"", 1);
    for (; *s; s++) { if (*s == '"' || *s == '\\') raw("\\", 1); if ((uint8_t)*s >= 0x20) raw(s, 1); }
    raw("\"", 1);
  }
  void num(int32_t v) { char t[12]; raw(t, snprintf(t, sizeof(t), "%d", (int)v)); }
  void unum(uint32_t v) { char t[12]; raw(t, snprintf(t, sizeof(t), "%u", (unsigned)v)); }
  void boolean(bool v) { if (v) lit(PSTR("true")); else lit(PSTR("false")); }
  void ip(uint32_t v) { IPAddress a(v); char t[16]; raw(t, snprintf(t, sizeof(t), "\"%u.%u.%u.%u\"", a[0], a[1], a[2], a[3])); }
};
#define J(s) o.lit(PSTR(s))

static bool requireAuth();
static void handleStats() {
  if (!requireAuth()) return;
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "application/json", "");
  ChunkOut o;
  J("{\"ip\":"); o.ip((uint32_t)WiFi.localIP());
  J(",\"ssid\":"); o.str(WiFi.SSID().c_str());
  J(",\"rssi\":"); o.num(WiFi.RSSI());
  J(",\"up\":"); o.unum(millis() / 1000);
  J(",\"heap\":"); o.unum(ESP.getFreeHeap());
  J(",\"maxblock\":"); o.unum(ESP.getMaxFreeBlockSize());
  J(",\"frag\":"); o.unum(ESP.getHeapFragmentation());
  J(",\"boot\":"); o.str(ESP.getResetReason().c_str());
  J(",\"blocked\":"); o.unum(totalBlocked);
  J(",\"allowed\":"); o.unum(totalAllowed);
  J(",\"domains\":"); o.unum(numHashes);
  J(",\"blocking\":"); o.boolean(blockingOn);
  J(",\"resumeIn\":"); o.unum(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0);
  J(",\"defcreds\":"); o.boolean(strcmp(WEB_PIN, "123456") == 0);
  J(",\"upurl\":"); o.str(updateUrl.c_str());
  J(",\"upiv\":"); o.unum(updateIntervalH);
  J(",\"upstat\":"); o.str(updateStatus.c_str());
  J(",\"clients\":[");
  for (int i = 0; i < numClients; i++) {
    const Dev& c = clients[i]; char mac[20];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5]);
    if (i) J(",");
    J("{\"ip\":"); o.ip(c.ip); J(",\"mac\":"); o.str(mac);
    J(",\"blocked\":"); o.unum(c.blocked); J(",\"allowed\":"); o.unum(c.allowed);
    J(",\"banned\":"); o.boolean(c.banned);
    const NetName* n = findName(c.ip);
    J(",\"os\":"); o.unum(n && osRank(n->os) >= osRank(c.os) ? n->os : c.os);
    if (n && n->name[0]) { J(",\"name\":"); o.str(n->name); }
    J("}");
  }
  bool first = true;
  J("],\"custom\":["); customList.each([&](const char* d) { if (!first) J(","); first = false; o.str(d); });
  first = true;
  J("],\"allow\":[");  allowList.each([&](const char* d) { if (!first) J(","); first = false; o.str(d); });
  J("],\"scam\":{\"remote\":"); o.boolean(scamRemoteOn);
  J(",\"bank\":"); o.boolean(scamBankOn);
  J(",\"hacker\":"); o.boolean(scamHackerOn);
  J(",\"blocked\":"); o.unum(scamBlocked);
  J(",\"hits\":[");
  for (int i = 0; i < numHits; i++) {
    if (i) J(",");
    J("{\"d\":"); o.str(hits[i].d); J(",\"ip\":"); o.ip(hits[i].ip);
    J(",\"k\":"); o.unum(hits[i].kind); J(",\"n\":"); o.unum(hits[i].n); J(",\"ago\":"); o.unum((millis() - hits[i].at) / 1000); J("}");
  }
  J("]}}");
  o.flush();
  web.sendContent("");                               // end of chunked response
}
// Lookup log, newest first. Behind the dashboard PIN: it's the family's browsing.
static void handleLog() {
  if (!requireAuth()) return;
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "application/json", "");
  ChunkOut o;
  J("[");
  for (int k = 1; k <= logCount; k++) {
    const LogEntry& e = qlog[(logHead - k + LOG_SIZE) % LOG_SIZE];
    if (k > 1) J(",");
    J("{\"d\":"); o.str(e.d); J(",\"ip\":"); o.ip(e.ip);
    J(",\"s\":"); o.unum(e.status & 0x7F); J(",\"t\":"); o.boolean(e.status & LOG_TRUNC);
    J(",\"n\":"); o.unum(e.count); J(",\"ago\":"); o.unum((millis() - e.at) / 1000); J("}");
  }
  J("]");
  o.flush();
  web.sendContent("");
}
#undef J
// Everything except the page itself needs the dashboard PIN in an X-Pin header. Only the
// dashboard's own same-origin fetch() can set a custom header, so a cross-site <img>/<form>
// can't drive it (CSRF). After 5 wrong PINs every try is refused for a minute, which keeps
// guessing all million 6-digit PINs out of reach.
static const char* PIN_HEADER = "X-Pin";
static uint8_t pinFails = 0;
static uint32_t pinLockAt = 0;
// 0 = right PIN, 401 = missing or wrong, 429 = locked out
static int pinCheck() {
  if (pinLockAt && millis() - pinLockAt < 60000UL) return 429;
  pinLockAt = 0;
  String p = web.header(PIN_HEADER);
  if (p.length() && p == WEB_PIN) { pinFails = 0; return 0; }
  if (p.length() && ++pinFails >= 5) { pinFails = 0; pinLockAt = millis() | 1; }
  return 401;
}
static bool requireAuth() {
  int c = pinCheck(); if (!c) return true;
  if (c == 429) web.send_P(429, PSTR("text/plain"), PSTR("too many tries, wait 1 min"));
  else web.send_P(401, PSTR("text/plain"), PSTR("PIN needed"));
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send_P(200, PSTR("text/plain"), PSTR("ok"));
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.send_P(401, PSTR("text/plain"), PSTR("PIN needed")); return; }
  if (upOk) web.send_P(200, PSTR("text/plain"), PSTR("ok"));
  else web.send_P(500, PSTR("text/plain"), PSTR("rejected: empty or size not a multiple of 5 (not a blocklist.bin?)"));
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = pinCheck() == 0;
      if (!upAuthOk) { Serial.println(F("[ota] blocklist upload: wrong PIN")); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf_P(PSTR("[ota] receiving %s\n"), u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf_P(PSTR("[ota] %s -> %u domains\n"), upOk ? "OK" : "REJECTED", (unsigned)numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println(F("[ota] aborted"));
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf_P(PSTR("[remote] GET %s (heap %u)\n"), url.c_str(), (unsigned)ESP.getFreeHeap());
  BearSSL::WiFiClientSecure cs; cs.setInsecure();   // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf_P(PSTR("[remote] %s\n"), updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf_P(PSTR("[remote] %s\n"), updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.send_P(401, PSTR("text/plain"), PSTR("PIN needed")); return; }
  bool ok = !Update.hasError();
  if (ok) web.send_P(200, PSTR("text/plain"), PSTR("ok, rebooting"));
  else web.send_P(500, PSTR("text/plain"), PSTR("firmware update failed"));
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = pinCheck() == 0;
    if (!fwAuthOk) { Serial.println(F("[fw-ota] wrong PIN, rejecting flash")); return; }
    Serial.printf_P(PSTR("[fw-ota] %s\n"), u.filename.c_str());
    // The new image is staged in the free space after the running sketch.
    uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
    if (!Update.begin(maxSketchSpace, U_FLASH)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf_P(PSTR("[fw-ota] %u bytes OK\n"), (unsigned)u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.end(); Serial.println(F("[fw-ota] aborted"));
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Provisioned creds are stored in the SDK's own WiFi config sector (outside LittleFS, so
// `pio run -t uploadfs` doesn't wipe them). Falls back to the compile-time secrets.h creds.
static void getSavedCreds(String& ssid, String& pass) {
  struct station_config conf;
  memset(&conf, 0, sizeof(conf));
  wifi_station_get_config_default(&conf);
  char s[33] = {0}, p[65] = {0};
  memcpy(s, conf.ssid, 32); memcpy(p, conf.password, 64);
  ssid = s; pass = p;
}
static void saveCreds(const String& ssid, const String& pass) {
  struct station_config conf;
  memset(&conf, 0, sizeof(conf));
  memcpy(conf.ssid, ssid.c_str(), min((size_t)32, (size_t)ssid.length()));
  memcpy(conf.password, pass.c_str(), min((size_t)64, (size_t)pass.length()));
  ETS_UART_INTR_DISABLE(); wifi_station_set_config(&conf); ETS_UART_INTR_ENABLE();
}
static void clearCreds() { saveCreds("", ""); }
static bool hasCreds() {
  String ss, pw; getSavedCreds(ss, pw);
  return ss.length() > 0 || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool joinWiFi(const char* ssid, const char* pass, const char* source) {
  Serial.printf_P(PSTR("WiFi: connecting to \"%s\" (%s)\n"), ssid, source);
  WiFi.mode(WIFI_STA); WiFi.setSleepMode(WIFI_NONE_SLEEP); WiFi.hostname(HOSTNAME);
  WiFi.setAutoReconnect(true);
  WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print(F(".")); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}
// Provisioned creds first, then secrets.h (also when the provisioned network is gone).
// Whichever one works is saved, so the next boot goes straight to it.
static bool connectWiFi() {
  String ss, pw; getSavedCreds(ss, pw);
  if (ss.length() && joinWiFi(ss.c_str(), pw.c_str(), "provisioned")) return true;
  if (!WIFI_SSID || !*WIFI_SSID || strcmp(WIFI_SSID, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  if (ss == WIFI_SSID && pw == WIFI_PASS) return false;                                      // already tried
  if (!joinWiFi(WIFI_SSID, WIFI_PASS, "secrets.h")) return false;
  saveCreds(WIFI_SSID, WIFI_PASS);
  return true;
}

// Setup portal pages live in flash (PROGMEM); only the scanned network list is built in RAM.
static const char PORTAL_HEAD[] PROGMEM =
  "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
  "<title>AdBlock setup</title><style>"
  ":root{--bg:#fafafa;--fg:#18181b;--mut:#71717a;--line:#e4e4e7;--card:#fff}"
  "@media(prefers-color-scheme:dark){:root{--bg:#09090b;--fg:#fafafa;--mut:#a1a1aa;--line:#27272a;--card:#18181b}}"
  "body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,sans-serif}"
  "main{max-width:380px;margin:12vh auto;padding:0 20px}h1{font-size:22px;margin:0 0 6px}p{color:var(--mut);margin:0 0 24px}"
  "input,button{display:block;width:100%;box-sizing:border-box;font:inherit;padding:13px 14px;border-radius:12px;margin:0 0 10px}"
  "input{border:1px solid var(--line);background:var(--card);color:var(--fg)}"
  "button{border:0;background:var(--fg);color:var(--bg);font-weight:600;cursor:pointer;margin-top:6px}"
  "</style></head><body><main><h1>Connect AdBlock</h1><p>Choose your home WiFi (2.4&nbsp;GHz). The box restarts and joins it.</p>"
  "<form method=POST action=/wifisave><input list=nets name=s placeholder='WiFi name' required autocomplete=off><datalist id=nets>";
static const char PORTAL_TAIL[] PROGMEM =
  "</datalist><input name=p type=password placeholder='Password'><button>Connect</button></form></main></body></html>";
static const char SAVED_HEAD[] PROGMEM =
  "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
  "<body style='font:16px/1.6 system-ui,sans-serif;text-align:center;margin:20vh 20px'><h2>Saved</h2><p>Joining <b>";
static const char SAVED_TAIL[] PROGMEM =
  "</b>&hellip;<br>Reconnect your phone to your normal WiFi, then open <b>adblock.local</b>.</p></body>";

static void handlePortalRoot() {
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "text/html", "");
  web.sendContent_P(PORTAL_HEAD); web.sendContent(portalOpts); web.sendContent_P(PORTAL_TAIL); web.sendContent("");
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send_P(400, PSTR("text/plain"), PSTR("missing WiFi name")); return; }
  saveCreds(ss, pw);
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "text/html", "");
  web.sendContent_P(SAVED_HEAD); web.sendContent(htmlEscape(ss)); web.sendContent_P(SAVED_TAIL); web.sendContent("");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  WiFi.mode(WIFI_STA); WiFi.disconnect();
  int n = WiFi.scanNetworks();                 // scan while still in STA mode
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[28]; snprintf(ap, sizeof(ap), "ESP-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf_P(PSTR("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n"),
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here (e.g. the board came back from a power cut before the router did):
  // if nobody is using the portal, reboot and retry WiFi every minute.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 60000UL) { Serial.println(F("[setup] retrying WiFi")); ESP.restart(); }
  }
}

// GPIO0 held at power-on means "enter the ROM bootloader" on the ESP8266, so instead
// give a 3 s window after boot (LED blinking) to press FLASH and wipe the saved WiFi.
static void checkForgetButton() {
  pinMode(FORGET_PIN, INPUT_PULLUP);
  pinMode(LED_BUILTIN, OUTPUT);
  bool pressed = false;
  for (uint32_t t0 = millis(); millis() - t0 < 3000 && !pressed; ) {
    digitalWrite(LED_BUILTIN, (millis() / 100) & 1);
    if (digitalRead(FORGET_PIN) == LOW) { delay(60); pressed = digitalRead(FORGET_PIN) == LOW; }
    delay(10);
  }
  digitalWrite(LED_BUILTIN, HIGH);             // LED is active-low: off
  if (pressed) { clearCreds(); Serial.println(F("[setup] FLASH pressed -> cleared saved WiFi")); }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println(F("\n[esp8266-adblock] booting"));
  WiFi.persistent(false);                      // WiFi.begin() must not rewrite the flash config each boot
  if (!LittleFS.begin()) {
    Serial.println(F("LittleFS mount failed -> formatting"));
    LittleFS.format(); LittleFS.begin();
  }
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf_P(PSTR("blocklist: %u domains\n"), (unsigned)numHashes);
    buildFlashIndex();
  }
  customList.load(); allowList.load(); loadBanned(); loadUpdateCfg(); loadScam();
  Serial.printf_P(PSTR("custom: %d, allowed: %d, banned: %d\n"), customList.count, allowList.count, numBanned);

  Serial.println(F("press FLASH within 3 s to forget saved WiFi"));
  checkForgetButton();

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf_P(PSTR("WiFi up: %s\n"), WiFi.localIP().toString().c_str());
  if (MDNS.begin(HOSTNAME)) {
    MDNS.addService("http", "tcp", 80); startDeviceDiscovery();
    Serial.printf_P(PSTR("dashboard: http://%s.local\n"), HOSTNAME);
  }

  if (strcmp(WEB_PIN, "123456") == 0)
    Serial.println(F("[WARN] secrets.h still has the example WEB_PIN 123456 — set your own PIN."));

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  web.collectHeaders(PIN_HEADER);  // needed for requireAuth()'s PIN check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/log.json", handleLog);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; customList.add(web.arg("d")); web.send_P(200, PSTR("text/plain"), PSTR("ok")); });
  web.on("/unblock", []() { if (!requireAuth()) return; customList.remove(web.arg("d")); web.send_P(200, PSTR("text/plain"), PSTR("ok")); });
  web.on("/allow", []() { if (!requireAuth()) return; addAllow(web.arg("d")); web.send_P(200, PSTR("text/plain"), PSTR("ok")); });
  web.on("/unallow", []() { if (!requireAuth()) return; allowList.remove(web.arg("d")); web.send_P(200, PSTR("text/plain"), PSTR("ok")); });
  web.on("/scamset", []() {                  // /scamset?remote=0|1&bank=0|1&hacker=0|1
    if (!requireAuth()) return;
    if (web.hasArg("remote")) scamRemoteOn = web.arg("remote") == "1";
    if (web.hasArg("bank"))   scamBankOn   = web.arg("bank") == "1";
    if (web.hasArg("hacker")) scamHackerOn = web.arg("hacker") == "1";
    saveScam(); web.send_P(200, PSTR("text/plain"), PSTR("ok"));
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send_P(200, PSTR("text/plain"), PSTR("paused"));
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send_P(200, PSTR("text/plain"), PSTR("resumed")); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send_P(200, PSTR("text/plain"), PSTR("cleared — rebooting into setup portal"));
    clearCreds(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send_P(200, PSTR("text/plain"), PSTR("ok"));
  });
  web.begin();
  Serial.printf_P(PSTR("DNS :53 + dashboard :80 + OTA up (free heap %u)\n"), (unsigned)ESP.getFreeHeap());
}

// Unattended 24/7 operation: the SDK reconnects on its own after short drops, but if the
// router stays unreachable (or the heap gets too fragmented) a clean reboot is the most
// reliable recovery. A power cut needs nothing: the board simply boots again.
static void selfHeal() {
  static uint32_t wifiLostAt = 0;
  if (WiFi.status() == WL_CONNECTED) wifiLostAt = 0;
  else if (wifiLostAt == 0) { wifiLostAt = millis(); Serial.println(F("[heal] WiFi lost, waiting for reconnect")); }
  else if (millis() - wifiLostAt > WIFI_LOST_REBOOT_MS) { Serial.println(F("[heal] WiFi still down -> reboot")); ESP.restart(); }
  if (ESP.getFreeHeap() < MIN_FREE_HEAP) { Serial.println(F("[heal] low heap -> reboot")); ESP.restart(); }
}

void loop() {
  selfHeal();
  deviceDiscoveryTick();
  MDNS.update();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
