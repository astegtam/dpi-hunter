// DPI Hunter - by astegtam
// Network security / research tool. Provided for EDUCATIONAL PURPOSES ONLY.
// Ag guvenligi / arastirma araci. YALNIZCA EGITIM AMACLI sunulmaktadir.
// Build (MSVC x64): cl /O2 /EHsc DpiHunter.cpp  (WinDivert.lib + windivert.h next to it)
// This file is UTF-8 with BOM; keep it that way so the UI text survives compilation.
#pragma execution_character_set("utf-8")
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#ifdef _MSC_VER
#pragma warning(disable: 28159 4996)
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <conio.h>
#include <string>
#include <set>
#include <map>
#include <vector>
#include <deque>
#include <fstream>
#include <algorithm>

#include "windivert.h"
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#define MAXBUF              0xFFFF
#define AUTO_TEST_TIMEOUT   3000
#define FIRST_TEST_DELAY    8000
#define PERIODIC_TEST       300000
#define RETRY_SOON          60000
#define SUCCESS_THRESHOLD   60
#define RECENT_MAX          96
#define CONFIG_FILE         "dpi_hunter.cfg"
#define LAST_FILE           "dpi_hunter.last"
#define HOSTS_FILE          "dpi_hunter.hosts"
#define LOG_FILE            "dpi_hunter.log"
#define LOG_MAX_BYTES       (512 * 1024)
#define COOLDOWN_MS         60000
#define MAX_FAILS           3
#define SAFE_RETRY_MS       600000
#define SIG_TRIGGER         3
#define SIG_WINDOW_MS       15000
#define DNS_WORKERS         4
#define DNS_QUEUE_MAX       512
#define DNS_FAIL_LIMIT      5
#define DNS_PAUSE_MS        300000
#define DOH_TIMEOUT_MS      1500
#define DNS_TEST_TIMEOUT    1500
#define DNS_TEST_QUERIES    3
#define MAX_PORTS           16
#define MAX_RANGES          8
#define PEND_MAX            64
#define UFLOW_MAX           2048
#define UDP_FAKE_PACKETS    3
#define TASK_NAME           "DPI Hunter"
#define MUTEX_NAME          "Global\\DPIHunter_astegtam_single"

#define C_RESET   "\x1b[0m"
#define C_BOLD    "\x1b[1m"
#define C_DIM     "\x1b[38;2;112;120;140m"
#define C_RED     "\x1b[38;2;255;96;112m"
#define C_GREEN   "\x1b[38;2;84;230;150m"
#define C_YELLOW  "\x1b[38;2;255;200;90m"
#define C_BLUE    "\x1b[38;2;96;165;255m"
#define C_MAGENTA "\x1b[38;2;190;125;255m"
#define C_CYAN    "\x1b[38;2;72;216;255m"
#define C_WHITE   "\x1b[38;2;236;240;250m"
#define C_SELBG   "\x1b[48;2;28;36;58m"

// ---------------------------------------------------------------- strategies
enum Strategy {
    S_SPLIT2 = 0, S_SPLIT_SNI, S_SPLIT_MID, S_MULTISPLIT, S_DISORDER, S_MULTIDISORDER,
    S_SEQOVL, S_DELAY,
    S_FAKE_TTL, S_FAKE_BADSUM, S_FAKE_BADSEQ, S_FAKE_MD5,
    S_FAKE_SPLIT, S_FAKE_DISORDER, S_FAKEDSPLIT, S_COMBO,
    STRAT_DISABLED, STRAT_COUNT
};
#define STRAT_BYPASS_COUNT  STRAT_DISABLED

static const char* STRAT_NAMES[STRAT_COUNT] = {
    "Split-2", "Split-SNI", "Split-MidSNI", "MultiSplit", "Disorder", "MultiDisorder",
    "SeqOvl", "Delay-Split",
    "Fake-TTL", "Fake-BadSum", "Fake-BadSeq", "Fake-MD5",
    "Fake+Split", "Fake+Disorder", "FakedSplit", "Combo",
    "Safe-Mode"
};
static const char* STRAT_DESC_EN[STRAT_COUNT] = {
    "Split after the 2nd byte",
    "Split right before the hostname",
    "Split in the middle of the hostname",
    "3 cuts: byte 1, before and inside the hostname",
    "Split inside hostname, second part first",
    "3 cuts, all segments in reverse order",
    "Split + junk bytes overlapping the sequence",
    "Split with a short delay between parts",
    "Decoy hello with low TTL, then the real one",
    "Decoy hello with broken TCP checksum",
    "Decoy hello with wrong SEQ/ACK",
    "Decoy hello with TCP MD5 option",
    "Low-TTL decoy + split inside hostname",
    "Low-TTL decoy + reversed split",
    "Decoys mixed between the real parts",
    "TTL + MD5 decoys, then MultiSplit (tough ISPs)",
    "Safe mode: nothing is modified"
};
static const char* STRAT_DESC_TR[STRAT_COUNT] = {
    "2. bayttan sonra böl",
    "Alan adından hemen önce böl",
    "Alan adının ortasından böl",
    "3 kesim: 1. bayt, alan adı önü ve ortası",
    "Alan adı ortasından böl, ikinci parça önce",
    "3 kesim, tüm parçalar ters sırada",
    "Böl + sıra numarasına binen çöp baytlar",
    "Parçalar arasında kısa gecikmeyle böl",
    "Düşük TTL'li sahte hello, sonra gerçeği",
    "Bozuk TCP checksum'lı sahte hello",
    "Yanlış SEQ/ACK'li sahte hello",
    "TCP MD5 seçenekli sahte hello",
    "Düşük TTL sahte + alan adı ortasından böl",
    "Düşük TTL sahte + ters sıralı böl",
    "Gerçek parçaların arasına sahte parçalar",
    "TTL + MD5 sahteler, sonra MultiSplit (zor ISS)",
    "Güvenli mod: hiçbir şey değiştirilmez"
};

// ---------------------------------------------------------------- DoH
struct DohProvider {
    std::string    name;
    std::string    cfgName;
    std::wstring   host;
    std::wstring   path;
    const char*    noteEn;
    const char*    noteTr;
};
#define DOH_COUNT 12
#define DOH_MAX_COUNT 13
static DohProvider DOH[DOH_MAX_COUNT] = {
    { "Cloudflare",   "cloudflare",  L"1.1.1.1",         L"/dns-query", "No filtering, fastest",   "Filtresiz, en hızlı" },
    { "Cloudflare-2", "cloudflare2", L"1.0.0.1",         L"/dns-query", "Cloudflare secondary",    "Cloudflare yedek" },
    { "Google",       "google",      L"8.8.8.8",         L"/dns-query", "Reliable, global",        "Güvenilir, küresel" },
    { "Google-2",     "google2",     L"8.8.4.4",         L"/dns-query", "Google secondary",        "Google yedek" },
    { "Quad9",        "quad9",       L"9.9.9.9",         L"/dns-query", "Blocks malware",          "Zararlı siteleri engeller" },
    { "Quad9-2",      "quad9b",      L"149.112.112.112", L"/dns-query", "Quad9 secondary",         "Quad9 yedek" },
    { "AdGuard",      "adguard",     L"94.140.14.14",    L"/dns-query", "Blocks ads and trackers", "Reklam ve izleyici engeller" },
    { "AdGuard-2",    "adguard2",    L"94.140.15.15",    L"/dns-query", "AdGuard secondary",       "AdGuard yedek" },
    { "Mullvad",      "mullvad",     L"194.242.2.2",     L"/dns-query", "Privacy, no logs",        "Gizlilik, kayıt tutmaz" },
    { "DNS.SB",       "dnssb",       L"185.222.222.222", L"/dns-query", "No filtering, EU",        "Filtresiz, AB" },
    { "DNS.SB-2",     "dnssb2",      L"45.11.45.11",     L"/dns-query", "DNS.SB secondary",        "DNS.SB yedek" },
    { "LibreDNS",     "libredns",    L"116.202.176.26",  L"/dns-query", "Libre, no tracking",      "Özgür, izleme yok" },
    { "Custom",       "custom",      L"",                L"/dns-query", "Manual input",            "Elle girilen" }
};

enum DnsMode { DNS_FAST = 0, DNS_FULL, DNS_OFF };
enum QuicMode { QUIC_DROP = 0, QUIC_FAKE, QUIC_PASS };
enum RunMode { RUN_AUTO = 0, RUN_MANUAL, RUN_TEST, RUN_ANALYZE, RUN_EXIT, RUN_SETTINGS, RUN_HELP };

struct PortRange { int a, b; };
static const int DEFAULT_PORTS[] = { 80, 443, 8080, 8443, 2053, 2083, 2087, 2096 };
#define DEFAULT_UDP_PORTS "49152-65535,19294-19344"

struct Settings {
    DnsMode          dnsMode;
    bool             dohAuto;
    int              dohProvider;
    std::string      dohCustom;
    std::vector<int> ports;
    bool             httpEnabled;
    int              fakeTtl;
    int              fakeRepeats;
    QuicMode         quic;
    bool             game;
    std::string      udpPorts;
    bool             deep;
    bool             logEnabled;
    int              lang;
    bool             intro;
    bool             accepted;
    RunMode          runMode;
    int              manualStrategy;

    Settings() : dnsMode(DNS_FAST), dohAuto(true), dohProvider(0),
        httpEnabled(true), fakeTtl(6), fakeRepeats(2), quic(QUIC_DROP), game(true),
        udpPorts(DEFAULT_UDP_PORTS), deep(true), logEnabled(true), lang(0), intro(true),
        accepted(false), runMode(RUN_AUTO), manualStrategy(S_SPLIT2) {
        for (size_t i = 0; i < sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]); i++)
            ports.push_back(DEFAULT_PORTS[i]);
    }
};

struct Stats {
    volatile LONG total, fragmented, fakeSent, quicBlocked, quicFaked, udpFaked;
    volatile LONG passed, signals, dnsDoh, dnsFallback, passiveDropped, hostFixes;
};
static Stats g_stats = { 0 };

// ---------------------------------------------------------------- globals
static int           g_lang = 0;
#define TR(en, tr)   (g_lang ? (tr) : (en))

static volatile LONG g_running = TRUE;
static volatile LONG g_inRun = 0;
static volatile LONG g_strategy = S_SPLIT2;
static volatile LONG g_lastGood = S_SPLIT2;
static volatile LONG g_backToMenu = 0;
static volatile LONG g_forceTest = 0;
static HANDLE        g_handle = INVALID_HANDLE_VALUE;
static HANDLE        g_stopEvent = NULL;
static HANDLE        g_doneEvent = NULL;
static unsigned char g_packet[MAXBUF];
static bool          g_httpEnabled = true;
static int           g_fakeTtl = 6;
static int           g_fakeRepeats = 2;
static QuicMode      g_quicMode = QUIC_DROP;
static bool          g_game = true;
static bool          g_deep = true;
static std::vector<PortRange> g_udpRanges;
static DnsMode       g_dnsMode = DNS_FAST;
static bool          g_dnsEnabled = false;
static bool          g_logEnabled = true;
static volatile LONG g_dohPref = 0;
static volatile LONG g_dohPrefFail = 0;
static volatile LONG g_dohFail = 0;
static volatile LONG g_dohPaused = 0;
static volatile LONG g_dohPausedUntil = 0;
static volatile LONG g_emergencyFlag = 0;
static volatile LONG g_emergencyRunning = 0;
static volatile LONG g_consecutiveFails = 0;
static volatile LONG g_ignoreHost = 0;
static char          g_emergencyHost[256] = { 0 };
static DWORD         g_safeSince = 0;
static DWORD         g_runStart = 0;

static bool          g_autoSwitch = true;
static volatile LONG g_analyzeMode = 0;
static bool          g_blockPassive = false;
static bool          g_dohForced = false;
static bool          g_noIntro = false;
static std::vector<std::string> g_analyzeSites;

static CRITICAL_SECTION g_consoleLock, g_handleLock, g_emLock, g_seenLock,
                        g_dnsLock, g_logLock, g_hostLock, g_ipLock;
static std::set<std::string> g_unfixable;
static std::set<std::string> g_blacklist;
static std::set<std::string> g_exclude;
static std::map<std::string, int> g_hostStrat;
static HANDLE g_dnsSem = NULL;
struct DnsJob;
static std::deque<DnsJob*> g_dnsQueue;

static std::string g_lblDns, g_lblList, g_lblMode;

static inline bool isRunning() { return InterlockedCompareExchange(&g_running, 1, 1) != 0; }
static inline Strategy getStrategy() { return (Strategy)InterlockedCompareExchange(&g_strategy, 0, 0); }
static inline void setStrategy(Strategy s) { InterlockedExchange(&g_strategy, (LONG)s); }
static inline int imin(int a, int b) { return a < b ? a : b; }
static inline int imax(int a, int b) { return a > b ? a : b; }

static bool sleepOrStop(DWORD ms) {
    if (!g_stopEvent) { Sleep(ms); return !isRunning(); }
    return WaitForSingleObject(g_stopEvent, ms) == WAIT_OBJECT_0;
}
static void scpy(char* dst, size_t cap, const char* src) {
    if (!cap) return;
    size_t n = strlen(src); if (n >= cap) n = cap - 1;
    memcpy(dst, src, n); dst[n] = 0;
}

// ---------------------------------------------------------------- console
static HANDLE g_hOut = NULL;
static bool   g_isCon = false;

static void cput(const char* s, int n) {
    if (n <= 0) return;
    if (!g_isCon) { fwrite(s, 1, (size_t)n, stdout); fflush(stdout); return; }
    std::wstring w; w.resize((size_t)n);
    int wn = MultiByteToWideChar(CP_UTF8, 0, s, n, &w[0], n);
    int off = 0;
    while (off < wn) {
        DWORD wr = 0; int chunk = imin(wn - off, 8000);
        if (!WriteConsoleW(g_hOut, w.c_str() + off, (DWORD)chunk, &wr, NULL)) break;
        off += chunk;
    }
}
static void puts8(const std::string& s) { cput(s.c_str(), (int)s.size()); }
static void P(const char* fmt, ...) {
    char b[4096]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    if (n < 0) return; if (n >= (int)sizeof(b)) n = (int)sizeof(b) - 1;
    cput(b, n);
}
static std::string fmt(const char* f, ...) {
    char b[2048]; va_list ap; va_start(ap, f);
    int n = vsnprintf(b, sizeof(b), f, ap); va_end(ap);
    if (n < 0) return ""; if (n >= (int)sizeof(b)) n = (int)sizeof(b) - 1;
    return std::string(b, (size_t)n);
}
static void conSize(int& w, int& h) {
    CONSOLE_SCREEN_BUFFER_INFO c;
    if (g_isCon && GetConsoleScreenBufferInfo(g_hOut, &c)) {
        w = c.srWindow.Right - c.srWindow.Left + 1; h = c.srWindow.Bottom - c.srWindow.Top + 1;
    } else { w = 100; h = 30; }
    if (w < 40) w = 40; if (h < 12) h = 12;
}
// visible length of a UTF-8 string, ANSI escapes ignored
static int vislen(const std::string& s) {
    int n = 0;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1b) { while (i < s.size() && !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z'))) i++; continue; }
        if ((c & 0xC0) != 0x80) n++;
    }
    return n;
}
static std::string padTo(const std::string& s, int w) {
    int v = vislen(s); return v >= w ? s : s + std::string((size_t)(w - v), ' ');
}
// cut to at most maxVis visible cells; escape sequences are kept so colours still get reset
static std::string clip(const std::string& s, int maxVis) {
    std::string o; int n = 0;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1b) {
            size_t j = i;
            while (j < s.size() && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z'))) j++;
            o.append(s, i, j - i + 1); i = j + 1; continue;
        }
        size_t l = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : 4;
        if (n < maxVis) { o.append(s, i, l); n++; }
        i += l;
    }
    return o;
}
static std::string rep(const char* g, int n) { std::string o; for (int i = 0; i < n; i++) o += g; return o; }
static std::string rgb(int r, int g, int b) { return fmt("\x1b[38;2;%d;%d;%dm", r, g, b); }
// cyan -> violet -> pink
static std::string gradCol(double t, double shade = 1.0) {
    if (t < 0) t = 0; if (t > 1) t = 1;
    double r, g, b;
    if (t < 0.5) { double u = t * 2; r = 64 + (150 - 64) * u; g = 224 + (110 - 224) * u; b = 255; }
    else { double u = (t - 0.5) * 2; r = 150 + (255 - 150) * u; g = 110 + (95 - 110) * u; b = 255 + (180 - 255) * u; }
    return rgb((int)(r * shade), (int)(g * shade), (int)(b * shade));
}
static void splitU8(const char* s, std::vector<std::string>& out) {
    out.clear();
    for (size_t i = 0; s[i];) {
        unsigned char c = (unsigned char)s[i];
        size_t l = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : 4;
        out.push_back(std::string(s + i, l)); i += l;
    }
}
static std::string gradText(const char* s, double t0 = 0.0, double t1 = 1.0) {
    std::vector<std::string> g; splitU8(s, g); std::string o;
    for (size_t i = 0; i < g.size(); i++) {
        double t = g.size() > 1 ? t0 + (t1 - t0) * (double)i / (double)(g.size() - 1) : t0;
        o += gradCol(t); o += g[i];
    }
    return o + C_RESET;
}
static void cursorShow(bool on) { P(on ? "\x1b[?25h" : "\x1b[?25l"); }
static void clearScreen() { P("\x1b[r\x1b[2J\x1b[3J\x1b[H"); }

enum { K_UP = 1000, K_DOWN, K_LEFT, K_RIGHT, K_ENTER = 13, K_ESC = 27 };
static int getKey() {
    int c = _getch();
    if (c == EOF) { Sleep(50); return K_ESC; }   // no console input (redirected): behave like Esc instead of spinning
    if (c == 0 || c == 0xE0) {
        int d = _getch();
        switch (d) { case 72: return K_UP; case 80: return K_DOWN; case 75: return K_LEFT; case 77: return K_RIGHT; }
        return 0;
    }
    return c;
}
static void flushKeys() { while (_kbhit()) _getch(); }
static bool readLine(std::string& out) {
    char buf[512]; cursorShow(true);
    bool ok = fgets(buf, sizeof(buf), stdin) != NULL;
    cursorShow(false);
    if (!ok) { out.clear(); return false; }
    out = buf; return true;
}
static void initConsole() {
    SetConsoleOutputCP(CP_UTF8); SetConsoleCP(CP_UTF8);
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD m = 0;
    g_isCon = GetConsoleMode(g_hOut, &m) != 0;
    if (g_isCon) SetConsoleMode(g_hOut, m | 0x0004 /*VT*/ | 0x0001 /*PROCESSED*/);
    HANDLE hi = GetStdHandle(STD_INPUT_HANDLE);
    if (GetConsoleMode(hi, &m)) {
        m &= ~ENABLE_QUICK_EDIT_MODE; m &= ~ENABLE_MOUSE_INPUT; m |= ENABLE_EXTENDED_FLAGS;
        SetConsoleMode(hi, m);
    }
    SetConsoleTitleA("DPI Hunter");
}
static void restoreConsole() { P("\x1b[r" C_RESET "\x1b[?25h"); }

static void pauseAny() {
    P("\n  %s%s%s", C_DIM, TR("Press any key to continue...", "Devam etmek için bir tuşa bas..."), C_RESET);
    flushKeys(); _getch(); P("\n");
}

// ---------------------------------------------------------------- stop / ctrl
static void requestStop() {
    InterlockedExchange(&g_running, FALSE);
    if (g_stopEvent) SetEvent(g_stopEvent);
    EnterCriticalSection(&g_handleLock);
    HANDLE h = g_handle;
    if (h && h != INVALID_HANDLE_VALUE) WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
    LeaveCriticalSection(&g_handleLock);
}
static BOOL WINAPI ctrlHandler(DWORD sig) {
    if (!InterlockedCompareExchange(&g_inRun, 0, 0)) { restoreConsole(); ExitProcess(0); }
    requestStop();
    if (g_doneEvent) WaitForSingleObject(g_doneEvent, (sig == CTRL_C_EVENT || sig == CTRL_BREAK_EVENT) ? 5000 : 4000);
    restoreConsole();
    if (sig == CTRL_C_EVENT || sig == CTRL_BREAK_EVENT) ExitProcess(0);
    return TRUE;
}

// ---------------------------------------------------------------- strings
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
static std::string lower(std::string s) {
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = (char)(s[i] - 'A' + 'a');
    return s;
}
static bool endsWith(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}
static void stripBom(std::string& s) {
    if (s.size() >= 3 && (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB && (unsigned char)s[2] == 0xBF)
        s.erase(0, 3);
}
static int stratByName(const std::string& v) {
    std::string l = lower(v);
    for (int i = 0; i < STRAT_BYPASS_COUNT; i++) if (l == lower(STRAT_NAMES[i])) return i;
    return -1;
}

static void saveLastStrategy() {
    LONG g = InterlockedCompareExchange(&g_lastGood, 0, 0);
    if (g < 0 || g >= STRAT_BYPASS_COUNT) return;
    std::ofstream f(LAST_FILE);
    if (f.is_open()) f << STRAT_NAMES[g] << "\n";
}
static int loadLastStrategy() {
    std::ifstream f(LAST_FILE);
    std::string s;
    if (!f.is_open() || !std::getline(f, s)) return -1;
    return stratByName(trim(s));
}
static void setWorkingDir() {
    char p[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, p, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    char* s = strrchr(p, '\\');
    if (s) { *s = 0; SetCurrentDirectoryA(p); }
}

// ---------------------------------------------------------------- log
static const char* DISCLAIMER_EN[] = {
    "DPI Hunter is a network security and research tool.",
    "It is provided for EDUCATIONAL PURPOSES ONLY, \"as is\", without any warranty.",
    "You alone are responsible for how you use it. Follow the laws of your country",
    "and the terms of your internet service provider."
};
static const char* DISCLAIMER_TR[] = {
    "DPI Hunter bir ağ güvenliği ve araştırma aracıdır.",
    "YALNIZCA EĞİTİM AMAÇLI olarak, \"olduğu gibi\" ve hiçbir garanti verilmeden sunulur.",
    "Kullanımından doğan tüm sorumluluk kullanıcıya aittir. Bulunduğun ülkenin",
    "yasalarına ve internet servis sağlayıcının sözleşmesine uygun kullan."
};
#define DISCLAIMER_LINES 4
#define DISCLAIMER_SHORT TR("Security tool - for educational purposes only", "Güvenlik aracı - yalnızca eğitim amaçlıdır")

static int g_logCount = 0;
static void logFile(const char* tag, const char* text) {
    if (!g_logEnabled) return;
    EnterCriticalSection(&g_logLock);
    if ((g_logCount++ % 200) == 0) {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        if (GetFileAttributesExA(LOG_FILE, GetFileExInfoStandard, &fa) && fa.nFileSizeLow > LOG_MAX_BYTES)
            MoveFileExA(LOG_FILE, LOG_FILE ".old", MOVEFILE_REPLACE_EXISTING);
    }
    FILE* f = fopen(LOG_FILE, "ab");
    if (f) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %-5s %s\r\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, tag, text);
        fclose(f);
    }
    LeaveCriticalSection(&g_logLock);
}
static void logLine(const char* tag, const char* color, const char* text) {
    SYSTEMTIME st; GetLocalTime(&st);
    EnterCriticalSection(&g_consoleLock);
    P("  %s%02d:%02d:%02d%s %s%-5s%s %s\n", C_DIM, st.wHour, st.wMinute, st.wSecond, C_RESET, color, tag, C_RESET, text);
    LeaveCriticalSection(&g_consoleLock);
    logFile(tag, text);
}

// ---------------------------------------------------------------- admin / autostart
static bool isAdmin() {
    BOOL a = FALSE; PSID g = NULL;
    SID_IDENTIFIER_AUTHORITY n = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&n, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) {
        CheckTokenMembership(NULL, g, &a);
        FreeSid(g);
    }
    return a != FALSE;
}
static bool relaunchAsAdmin(int argc, char** argv) {
    char p[MAX_PATH];
    if (!GetModuleFileNameA(NULL, p, MAX_PATH)) return false;
    std::string args;
    for (int i = 1; i < argc; i++) {
        if (!args.empty()) args += ' ';
        args += '"'; args += argv[i]; args += '"';
    }
    SHELLEXECUTEINFOA sei; memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = p;
    sei.lpParameters = args.empty() ? NULL : args.c_str();
    sei.nShow = SW_NORMAL;
    return ShellExecuteExA(&sei) != FALSE;
}
static bool autostartEnabled() {
    return system("schtasks /Query /TN \"" TASK_NAME "\" >nul 2>&1") == 0;
}
static bool autostartSet(bool on) {
    if (!on) return system("schtasks /Delete /TN \"" TASK_NAME "\" /F >nul 2>&1") == 0;
    char p[MAX_PATH];
    if (!GetModuleFileNameA(NULL, p, MAX_PATH)) return false;
    std::string cmd = "schtasks /Create /TN \"" TASK_NAME "\" /TR \"\\\"" + std::string(p) +
        "\\\" --auto --no-intro\" /SC ONLOGON /RL HIGHEST /F >nul 2>&1";
    return system(cmd.c_str()) == 0;
}

// ---------------------------------------------------------------- config
static int parseDohName(const std::string& v) {
    for (int i = 0; i < DOH_MAX_COUNT; i++) if (v == DOH[i].cfgName) return i;
    return -1;
}
static bool parsePorts(const std::string& v, std::vector<int>& out) {
    out.clear();
    size_t pos = 0;
    while (pos <= v.size() && (int)out.size() < MAX_PORTS) {
        size_t c = v.find(',', pos);
        std::string t = trim(v.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
        if (!t.empty()) {
            char* e = NULL; long p = strtol(t.c_str(), &e, 10);
            if (e && *e == 0 && p >= 1 && p <= 65535 &&
                std::find(out.begin(), out.end(), (int)p) == out.end()) out.push_back((int)p);
        }
        if (c == std::string::npos) break;
        pos = c + 1;
    }
    return !out.empty();
}
static bool parseRanges(const std::string& v, std::vector<PortRange>& out) {
    out.clear();
    size_t pos = 0;
    while (pos <= v.size() && (int)out.size() < MAX_RANGES) {
        size_t c = v.find(',', pos);
        std::string t = trim(v.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
        if (!t.empty()) {
            size_t d = t.find('-');
            long a = strtol(t.c_str(), NULL, 10), b = d == std::string::npos ? a : strtol(t.c_str() + d + 1, NULL, 10);
            if (a >= 1 && b >= a && b <= 65535 && a != 53 && !(a <= 443 && b >= 443)) { PortRange r = { (int)a, (int)b }; out.push_back(r); }
        }
        if (c == std::string::npos) break;
        pos = c + 1;
    }
    return !out.empty();
}
static bool parseOnOff(const std::string& v, bool& o) {
    if (v == "on" || v == "true" || v == "1" || v == "yes") { o = true; return true; }
    if (v == "off" || v == "false" || v == "0" || v == "no") { o = false; return true; }
    return false;
}
static bool parseDnsMode(const std::string& v, DnsMode& o) {
    if (v == "fast") { o = DNS_FAST; return true; }
    if (v == "full") { o = DNS_FULL; return true; }
    if (v == "off") { o = DNS_OFF; return true; }
    return false;
}
static bool parseQuic(const std::string& v, QuicMode& o) {
    if (v == "drop") { o = QUIC_DROP; return true; }
    if (v == "fake") { o = QUIC_FAKE; return true; }
    if (v == "pass" || v == "keep") { o = QUIC_PASS; return true; }
    return false;
}
static bool parseInt(const std::string& v, int lo, int hi, int& o) {
    char* e = NULL; long t = strtol(v.c_str(), &e, 10);
    if (!e || *e != 0 || v.empty() || t < lo || t > hi) return false;
    o = (int)t; return true;
}
static bool validIPv4(const std::string& s) { IN_ADDR a; return inet_pton(AF_INET, s.c_str(), &a) == 1; }
static void setCustomDoh(const std::string& ip) {
    DOH[DOH_COUNT].name = ip.empty() ? "Custom" : ip;
    DOH[DOH_COUNT].host = std::wstring(ip.begin(), ip.end());
}

// returns true when a config file existed
static bool configRead(Settings& st) {
    std::ifstream f(CONFIG_FILE);
    if (!f.is_open()) return false;
    bool gotAuto = false, gotDoh = false, autoVal = true;
    std::string line; bool first = true;
    while (std::getline(f, line)) {
        if (first) { stripBom(line); first = false; }
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = lower(trim(line.substr(0, eq)));
        std::string v = lower(trim(line.substr(eq + 1)));
        bool b; int n;
        if (k == "dns_mode") { DnsMode m; if (parseDnsMode(v, m)) st.dnsMode = m; }
        else if (k == "doh_auto") { if (parseOnOff(v, b)) { autoVal = b; gotAuto = true; } }
        else if (k == "doh") { int i = parseDohName(v); if (i >= 0) { st.dohProvider = i; gotDoh = true; } }
        else if (k == "doh_custom") { if (validIPv4(v)) st.dohCustom = v; }
        else if (k == "ports") { std::vector<int> p; if (parsePorts(v, p)) st.ports = p; }
        else if (k == "udp_ports") { std::vector<PortRange> r; if (parseRanges(v, r)) st.udpPorts = v; }
        else if (k == "http") { if (parseOnOff(v, b)) st.httpEnabled = b; }
        else if (k == "ttl") { if (parseInt(v, 1, 20, n)) st.fakeTtl = n; }
        else if (k == "fake_repeats") { if (parseInt(v, 1, 10, n)) st.fakeRepeats = n; }
        else if (k == "quic") { QuicMode q; if (parseQuic(v, q)) st.quic = q; }
        else if (k == "game") { if (parseOnOff(v, b)) st.game = b; }
        else if (k == "deep") { if (parseOnOff(v, b)) st.deep = b; }
        else if (k == "log") { if (parseOnOff(v, b)) st.logEnabled = b; }
        else if (k == "intro") { if (parseOnOff(v, b)) st.intro = b; }
        else if (k == "accepted") { if (parseOnOff(v, b)) st.accepted = b; }
        else if (k == "lang") { st.lang = (v == "tr") ? 1 : 0; }
    }
    // an explicit doh_auto always wins; a bare "doh=" line (old configs) means "use this one"
    st.dohAuto = gotAuto ? autoVal : !gotDoh;
    if (st.dohProvider == DOH_COUNT && st.dohCustom.empty()) { st.dohProvider = 0; st.dohAuto = true; }
    return true;
}
static void configWrite(const Settings& st) {
    std::ofstream f(CONFIG_FILE);
    if (!f.is_open()) return;
    f << "# DPI Hunter configuration\n";
    f << "# Security / research tool - for educational purposes only.\n\n";
    f << "lang=" << (st.lang ? "tr" : "en") << "\n";
    f << "dns_mode=" << (st.dnsMode == DNS_FAST ? "fast" : st.dnsMode == DNS_FULL ? "full" : "off") << "\n";
    f << "doh=" << DOH[st.dohProvider].cfgName << "\n";
    f << "doh_auto=" << (st.dohAuto ? "on" : "off") << "\n";
    if (!st.dohCustom.empty()) f << "doh_custom=" << st.dohCustom << "\n";
    f << "ports=";
    for (size_t i = 0; i < st.ports.size(); i++) { if (i) f << ","; f << st.ports[i]; }
    f << "\nhttp=" << (st.httpEnabled ? "on" : "off") << "\n";
    f << "ttl=" << st.fakeTtl << "\n";
    f << "fake_repeats=" << st.fakeRepeats << "\n";
    f << "quic=" << (st.quic == QUIC_DROP ? "drop" : st.quic == QUIC_FAKE ? "fake" : "pass") << "\n";
    f << "game=" << (st.game ? "on" : "off") << "\n";
    f << "udp_ports=" << st.udpPorts << "\n";
    f << "deep=" << (st.deep ? "on" : "off") << "\n";
    f << "log=" << (st.logEnabled ? "on" : "off") << "\n";
    f << "intro=" << (st.intro ? "on" : "off") << "\n";
    f << "accepted=" << (st.accepted ? "on" : "off") << "\n";
}
static void applySettings(const Settings& st) {
    g_lang = st.lang; g_httpEnabled = st.httpEnabled; g_fakeTtl = st.fakeTtl; g_fakeRepeats = st.fakeRepeats;
    g_quicMode = st.quic; g_game = st.game; g_deep = st.deep; g_dnsMode = st.dnsMode; g_logEnabled = st.logEnabled;
    if (!parseRanges(st.udpPorts, g_udpRanges)) parseRanges(DEFAULT_UDP_PORTS, g_udpRanges);
    setCustomDoh(st.dohCustom);
}
static void parseArgs(int argc, char** argv, Settings& st) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i], k, v;
        size_t eq = a.find('=');
        if (eq != std::string::npos) { k = a.substr(0, eq); v = a.substr(eq + 1); }
        else k = a;
        k = lower(k); v = lower(v);
        if (eq == std::string::npos && i + 1 < argc && argv[i + 1][0] != '-' &&
            (k == "--dns" || k == "--doh" || k == "--ports" || k == "--ttl" || k == "--strategy" || k == "--http" ||
             k == "--quic" || k == "--game" || k == "--repeats" || k == "--lang" || k == "--udp-ports"))
            v = lower(argv[++i]);
        bool b; int n;
        if (k == "--auto")    st.runMode = RUN_AUTO;
        else if (k == "--manual")  st.runMode = RUN_MANUAL;
        else if (k == "--test")    st.runMode = RUN_TEST;
        else if (k == "--analyze") st.runMode = RUN_ANALYZE;
        else if (k == "--no-dns")  st.dnsMode = DNS_OFF;
        else if (k == "--dns") { DnsMode m; if (parseDnsMode(v, m)) st.dnsMode = m; }
        else if (k == "--doh") { int x = parseDohName(v); if (x >= 0 && (x != DOH_COUNT || !st.dohCustom.empty())) { st.dohProvider = x; st.dohAuto = false; g_dohForced = true; } }
        else if (k == "--doh-auto") { st.dohAuto = true; g_dohForced = false; }
        else if (k == "--ports") { std::vector<int> p; if (parsePorts(v, p)) st.ports = p; }
        else if (k == "--udp-ports") { std::vector<PortRange> r; if (parseRanges(v, r)) st.udpPorts = v; }
        else if (k == "--http") { if (parseOnOff(v, b)) st.httpEnabled = b; }
        else if (k == "--no-http") st.httpEnabled = false;
        else if (k == "--no-log")  st.logEnabled = false;
        else if (k == "--log")     st.logEnabled = true;
        else if (k == "--no-intro") g_noIntro = true;
        else if (k == "--block-passive") g_blockPassive = true;
        else if (k == "--keep-quic") st.quic = QUIC_PASS;
        else if (k == "--quic") { QuicMode q; if (parseQuic(v, q)) st.quic = q; }
        else if (k == "--game") { if (parseOnOff(v, b)) st.game = b; }
        else if (k == "--no-game") st.game = false;
        else if (k == "--lang") st.lang = (v == "tr") ? 1 : 0;
        else if (k == "--ttl") { if (parseInt(v, 1, 20, n)) st.fakeTtl = n; }
        else if (k == "--repeats") { if (parseInt(v, 1, 10, n)) st.fakeRepeats = n; }
        else if (k == "--strategy") { int s = stratByName(v); if (s >= 0) { st.manualStrategy = s; st.runMode = RUN_MANUAL; } }
    }
}

// ================================================================ UI
static const char* LOGO[6] = {
    "██████╗ ██████╗ ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ",
    "██╔══██╗██╔══██╗██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗",
    "██║  ██║██████╔╝██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝",
    "██║  ██║██╔═══╝ ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗",
    "██████╔╝██║     ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║",
    "╚═════╝ ╚═╝     ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
};
#define LOGO_ROWS 6
#define LOGO_TOP  2
static std::vector<std::string> g_logo[LOGO_ROWS];
static int g_logoW = 0;
static void logoInit() {
    if (g_logoW) return;
    for (int r = 0; r < LOGO_ROWS; r++) { splitU8(LOGO[r], g_logo[r]); g_logoW = imax(g_logoW, (int)g_logo[r].size()); }
}
static bool logoFits(int w, int h) { return w >= g_logoW + 4 && h >= 26; }

// head < 0: fully revealed. glitch != 0: sprinkle noise glyphs.
static void renderLogo(std::string& o, int left, int head, unsigned glitch) {
    for (int r = 0; r < LOGO_ROWS; r++) {
        o += fmt("\x1b[%d;%dH", LOGO_TOP + r, left);
        const std::vector<std::string>& g = g_logo[r];
        int n = (int)g.size();
        double shade = 1.0 - 0.07 * r;
        for (int c = 0; c < n; c++) {
            if (head >= 0 && c > head) break;
            if (g[c] == " ") { o += " "; continue; }
            if (head >= 0 && c > head - 3) o += "\x1b[38;2;255;255;255m";
            else o += gradCol((double)c / (double)(n - 1), shade);
            unsigned hsh = (unsigned)(r * 131 + c * 31 + 7) * 2654435761u ^ (glitch * 40503u);
            if (glitch && ((hsh >> 16) % 13) == 0) o += ((hsh >> 8) & 1) ? "▒" : "░"; else o += g[c];
        }
        o += C_RESET "\x1b[K";
    }
}
static bool introSleep(DWORD ms) { Sleep(ms); return _kbhit() != 0; }

static void playIntro() {
    logoInit();
    int w, h; conSize(w, h);
    cursorShow(false); clearScreen();
    bool skip = false;
    int left = imax(1, (w - g_logoW) / 2 + 1);
    int rowBy = LOGO_TOP + LOGO_ROWS + 1;
    const char* by = "by astegtam";
    if (logoFits(w, h)) {
        for (int head = 0; head <= g_logoW + 3 && !skip; head += 2) {
            std::string o; renderLogo(o, left, head, 0); puts8(o);
            skip = introSleep(11);
        }
        for (int i = 1; i <= 6 && !skip; i++) {
            std::string o; renderLogo(o, left, -1, (unsigned)i * 977u + GetTickCount()); puts8(o);
            skip = introSleep(38);
        }
        { std::string o; renderLogo(o, left, -1, 0); puts8(o); }
    } else {
        rowBy = 4; left = 3;
        P("\x1b[2;3H%s%s%s", C_BOLD, gradText("D P I   H U N T E R").c_str(), C_RESET);
    }
    // signature, typed
    int byCol = logoFits(w, h) ? left + g_logoW - (int)strlen(by) : 3;
    for (size_t i = 0; by[i] && !skip; i++) {
        P("\x1b[%d;%dH%s%c%s", rowBy, byCol + (int)i, C_WHITE, by[i], C_RESET);
        skip = introSleep(28);
    }
    P("\x1b[%d;%dH%s%s%s", rowBy, byCol, C_WHITE, by, C_RESET);
    // rule growing from the centre
    int ruleW = imin(w - 6, logoFits(w, h) ? g_logoW : 50);
    int ruleLeft = logoFits(w, h) ? left : 3;
    for (int k = 1; k <= 12 && !skip; k++) {
        int half = ruleW * k / 24;
        P("\x1b[%d;%dH%s%s%s", rowBy + 1, ruleLeft + ruleW / 2 - half, C_DIM, rep("─", half * 2).c_str(), C_RESET);
        skip = introSleep(16);
    }
    P("\x1b[%d;%dH%s%s%s", rowBy + 1, ruleLeft, C_DIM, rep("─", ruleW).c_str(), C_RESET);
    // tagline + disclaimer
    std::string tag = TR("Network security tool  ·  For educational purposes only", "Ağ güvenliği aracı  ·  Yalnızca eğitim amaçlıdır");
    int tcol = imax(1, ruleLeft + (ruleW - vislen(tag)) / 2);
    P("\x1b[%d;%dH%s%s%s", rowBy + 3, tcol, C_DIM, tag.c_str(), C_RESET);
    if (!skip) skip = introSleep(120);
    P("\x1b[%d;%dH%s%s%s", rowBy + 3, tcol, C_WHITE, tag.c_str(), C_RESET);
    const char** d = g_lang ? DISCLAIMER_TR : DISCLAIMER_EN;
    for (int i = 0; i < DISCLAIMER_LINES; i++) {
        int c = imax(1, ruleLeft + (ruleW - vislen(d[i])) / 2);
        P("\x1b[%d;%dH%s%s%s", rowBy + 5 + i, c, C_DIM, d[i], C_RESET);
        if (!skip) skip = introSleep(55);
    }
    // loading bar
    int barW = imin(36, ruleW), barCol = ruleLeft + (ruleW - barW) / 2, barRow = rowBy + 5 + DISCLAIMER_LINES + 1;
    for (int k = 0; k <= barW && !skip; k++) {
        std::string o = fmt("\x1b[%d;%dH", barRow, barCol);
        for (int i = 0; i < barW; i++) { o += i < k ? gradCol((double)i / barW) : std::string(C_DIM); o += i < k ? "▬" : "─"; }
        o += C_RESET; puts8(o);
        skip = introSleep(14);
    }
    if (!skip) Sleep(260);
    flushKeys();
}

// draws logo header, returns the next free row
static int drawBanner(std::string& o, int w, int h) {
    logoInit();
    if (logoFits(w, h)) {
        int left = imax(1, (w - g_logoW) / 2 + 1);
        o += "\x1b[1;1H\x1b[K";
        renderLogo(o, left, -1, 0);
        o += fmt("\x1b[%d;1H\x1b[K\x1b[%d;%dH%sby astegtam%s", LOGO_TOP + LOGO_ROWS, LOGO_TOP + LOGO_ROWS + 1, left + g_logoW - 11, C_WHITE, C_RESET);
        o += fmt("\x1b[%d;1H\x1b[K", LOGO_TOP + LOGO_ROWS + 2);
        return LOGO_TOP + LOGO_ROWS + 3;
    }
    o += "\x1b[1;1H\x1b[K";
    o += fmt("\x1b[2;1H\x1b[K   %s%s%s", C_BOLD, gradText("D P I   H U N T E R").c_str(), C_RESET);
    o += fmt("\x1b[3;1H\x1b[K   %sby astegtam%s", C_WHITE, C_RESET);
    o += "\x1b[4;1H\x1b[K";
    return 5;
}

struct MItem { std::string label, value, hint; };

static void drawMenu(const std::string& title, const std::vector<MItem>& items, int sel, const std::string& keys) {
    int w, h; conSize(w, h);
    std::string o = "\x1b[?25l";
    int row = drawBanner(o, w, h);
    int left = logoFits(w, h) ? imax(3, (w - g_logoW) / 2 + 1) : 3;
    std::string pad((size_t)(left - 1), ' ');
    o += fmt("\x1b[%d;1H\x1b[K%s%s%s%s%s", row++, pad.c_str(), C_BOLD, C_WHITE, title.c_str(), C_RESET);
    o += fmt("\x1b[%d;1H\x1b[K", row++);
    int labW = 12, valW = 0;
    for (size_t i = 0; i < items.size(); i++) { labW = imax(labW, vislen(items[i].label)); valW = imax(valW, vislen(items[i].value)); }
    int maxRows = h - row - 3;
    int first = 0;
    if ((int)items.size() > maxRows && maxRows > 0) first = imin(imax(0, sel - maxRows / 2), (int)items.size() - maxRows);
    for (int i = first; i < (int)items.size() && row <= h - 3; i++) {
        const MItem& it = items[(size_t)i];
        const std::string hint = clip(it.hint, w - left - 3 - (labW + 2) - (valW ? valW + 2 : 0) - 3);
        o += fmt("\x1b[%d;1H\x1b[K%s", row++, pad.c_str());
        if (i == sel) {
            o += gradCol(0.0); o += "► "; o += C_SELBG C_BOLD C_WHITE " ";
            o += padTo(it.label, labW + 2);
            if (valW) { o += C_RESET C_SELBG C_CYAN; o += padTo(it.value, valW + 2); }
            o += C_RESET "  " C_DIM; o += hint; o += C_RESET;
        } else {
            o += "   "; o += C_WHITE; o += padTo(it.label, labW + 2);
            if (valW) { o += C_CYAN; o += padTo(it.value, valW + 2); }
            o += C_RESET "  " C_DIM; o += hint; o += C_RESET;
        }
    }
    while (row <= h - 3) o += fmt("\x1b[%d;1H\x1b[K", row++);
    o += fmt("\x1b[%d;1H\x1b[K%s%s%s%s", h - 2, pad.c_str(), C_DIM, rep("─", imin(w - left - 1, g_logoW ? g_logoW : 60)).c_str(), C_RESET);
    o += fmt("\x1b[%d;1H\x1b[K%s%s%s%s", h - 1, pad.c_str(), C_DIM, clip(keys, w - left - 1).c_str(), C_RESET);
    o += fmt("\x1b[%d;1H\x1b[K%s%s%s%s", h, pad.c_str(), C_DIM, DISCLAIMER_SHORT, C_RESET);
    puts8(o);
}
#define KEYS_NAV TR("↑↓ move   Enter select   Esc back", "↑↓ gezin   Enter seç   Esc geri")

// simple pick-one menu. returns index or -1 on Esc.
static int menuSelect(const std::string& title, const std::vector<MItem>& items, int sel) {
    clearScreen();
    int n = (int)items.size();
    while (true) {
        drawMenu(title, items, sel, KEYS_NAV);
        int k = getKey();
        if (k == K_UP) sel = (sel + n - 1) % n;
        else if (k == K_DOWN) sel = (sel + 1) % n;
        else if (k == K_ENTER) return sel;
        else if (k == K_ESC) return -1;
        else if (k >= '1' && k <= '9' && k - '1' < n) return k - '1';
    }
}

static void showTextScreen(const std::string& title, const std::vector<std::string>& lines, const std::string& footer) {
    clearScreen();
    int w, h; conSize(w, h);
    std::string o; int row = drawBanner(o, w, h);
    int left = logoFits(w, h) ? imax(3, (w - g_logoW) / 2 + 1) : 3;
    std::string pad((size_t)(left - 1), ' ');
    o += fmt("\x1b[%d;1H%s%s%s%s%s", row++, pad.c_str(), C_BOLD, C_WHITE, title.c_str(), C_RESET); row++;
    for (size_t i = 0; i < lines.size() && row < h - 1; i++) o += fmt("\x1b[%d;1H%s%s", row++, pad.c_str(), clip(lines[i], w - left - 1).c_str());
    row++;
    o += fmt("\x1b[%d;1H%s%s%s%s", row, pad.c_str(), C_DIM, footer.c_str(), C_RESET);
    puts8(o);
}

// first-run acceptance. returns false if the user declined.
static bool showDisclaimer(bool needAccept) {
    const char** d = g_lang ? DISCLAIMER_TR : DISCLAIMER_EN;
    std::vector<std::string> l;
    for (int i = 0; i < DISCLAIMER_LINES; i++) l.push_back(std::string(C_WHITE) + d[i] + C_RESET);
    showTextScreen(TR("TERMS OF USE", "KULLANIM KOŞULLARI"), l,
        needAccept ? TR("[Enter] I understand and accept     [Esc] Exit", "[Enter] Okudum, kabul ediyorum     [Esc] Çıkış")
                   : TR("Press any key to return", "Dönmek için bir tuşa bas"));
    flushKeys();
    while (true) {
        int k = getKey();
        if (!needAccept) return true;
        if (k == K_ENTER) return true;
        if (k == K_ESC) return false;
    }
}

static void printHelp() {
    std::vector<std::string> l;
    const char* W = C_WHITE; const char* D = C_DIM; const char* R = C_RESET;
    l.push_back(fmt("%s%s%s", W, TR("USAGE", "KULLANIM"), R));
    l.push_back(fmt("  Dpi.Hunter.exe              %s%s%s", D, TR("menu", "menü"), R));
    l.push_back(fmt("  --auto | --manual | --analyze | --test   %s%s%s", D, TR("start a mode directly", "modu doğrudan başlat"), R));
    l.push_back("");
    l.push_back(fmt("%s%s%s", W, TR("OPTIONS", "SEÇENEKLER"), R));
    l.push_back(fmt("  --strategy=NAME        %s%s%s", D, TR("pick a strategy (implies --manual)", "strateji seç (--manual sayılır)"), R));
    l.push_back(fmt("  --dns=fast|full|off    %s%s%s", D, TR("DNS handling", "DNS modu"), R));
    l.push_back(fmt("  --doh=NAME | --doh-auto %s%s%s", D, TR("DoH provider", "DoH sağlayıcı"), R));
    l.push_back(fmt("  --ttl=N  --repeats=N   %s%s%s", D, TR("decoy TTL (1-20) / repeat count (1-10)", "sahte paket TTL (1-20) / tekrar (1-10)"), R));
    l.push_back(fmt("  --quic=drop|fake|pass  %s%s%s", D, TR("QUIC (UDP/443) handling", "QUIC (UDP/443) davranışı"), R));
    l.push_back(fmt("  --game=on|off          %s%s%s", D, TR("game / voice UDP mode", "oyun / ses UDP modu"), R));
    l.push_back(fmt("  --udp-ports=A-B,C-D    %s%s%s", D, TR("UDP port ranges for game mode", "oyun modu UDP port aralıkları"), R));
    l.push_back(fmt("  --ports=443,80         %s%s%s", D, TR("TCP ports to protect", "korunacak TCP portları"), R));
    l.push_back(fmt("  --no-dns --no-http --no-log --no-intro --block-passive --lang=tr|en"));
    l.push_back("");
    l.push_back(fmt("%s%s%s", W, TR("FILES (next to the exe)", "DOSYALAR (exe'nin yanında)"), R));
    l.push_back(fmt("  blacklist.txt  %s%s%s", D, TR("only these domains are touched (optional)", "sadece bu alan adlarına dokunulur (isteğe bağlı)"), R));
    l.push_back(fmt("  exclude.txt    %s%s%s", D, TR("never touch these domains", "bu alan adlarına asla dokunma"), R));
    l.push_back(fmt("  dpi_hunter.hosts %s%s%s", D, TR("learned per-domain strategies", "öğrenilen alan adı stratejileri"), R));
    l.push_back("");
    l.push_back(fmt("%s%s%s", D, DISCLAIMER_SHORT, R));
    showTextScreen(TR("HELP", "YARDIM"), l, TR("Press any key to return", "Dönmek için bir tuşa bas"));
    flushKeys(); _getch();
}

static int manualStrategyMenu(int sel) {
    std::vector<MItem> items;
    for (int i = 0; i < STRAT_BYPASS_COUNT; i++) {
        MItem m; m.label = STRAT_NAMES[i]; m.hint = g_lang ? STRAT_DESC_TR[i] : STRAT_DESC_EN[i];
        items.push_back(m);
    }
    if (sel < 0 || sel >= STRAT_BYPASS_COUNT) sel = 0;
    clearScreen();
    int n = (int)items.size();
    while (true) {
        drawMenu(TR("PICK A STRATEGY", "STRATEJİ SEÇ"), items, sel, KEYS_NAV);
        int k = getKey();
        if (k == K_UP) sel = (sel + n - 1) % n;
        else if (k == K_DOWN) sel = (sel + 1) % n;
        else if (k == K_ENTER) return sel;
        else if (k == K_ESC) return -1;
    }
}

// ---------------------------------------------------------------- DoH latency test
struct DnsTestResult {
    int   provIdx;
    bool  reachable;
    DWORD avgMs, minMs, maxMs;
    int   successes;
};

static void buildDnsQuery(const char* name, unsigned short txid, std::vector<unsigned char>& out) {
    out.clear();
    out.push_back((unsigned char)(txid >> 8));
    out.push_back((unsigned char)(txid & 0xFF));
    out.push_back(0x01); out.push_back(0x00); out.push_back(0x00); out.push_back(0x01);
    for (int i = 0; i < 6; i++) out.push_back(0x00);
    const char* p = name;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63) { out.clear(); return; }
        out.push_back((unsigned char)len);
        out.insert(out.end(), p, p + len);
        if (!dot) break;
        p = dot + 1;
    }
    out.push_back(0); out.push_back(0); out.push_back(1); out.push_back(0); out.push_back(1);
}

static bool dohQueryOnce(const DohProvider& prov, const char* name, DWORD* outMs) {
    if (prov.host.empty()) return false;
    HINTERNET sess = WinHttpOpen(L"DPIHunterTest", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return false;
    WinHttpSetTimeouts(sess, DNS_TEST_TIMEOUT, DNS_TEST_TIMEOUT, DNS_TEST_TIMEOUT, DNS_TEST_TIMEOUT);
    HINTERNET conn = WinHttpConnect(sess, prov.host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(sess); return false; }
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", prov.path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(sess); return false; }
    std::vector<unsigned char> q;
    buildDnsQuery(name, (unsigned short)(GetTickCount() & 0xFFFF), q);
    if (q.empty()) { WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(sess); return false; }
    const wchar_t* hdr = L"Content-Type: application/dns-message\r\nAccept: application/dns-message";
    DWORD t0 = GetTickCount();
    bool ok = false;
    if (WinHttpSendRequest(req, hdr, (DWORD)-1L, (LPVOID)&q[0], (DWORD)q.size(), (DWORD)q.size(), 0) && WinHttpReceiveResponse(req, NULL)) {
        DWORD st = 0, sz = sizeof(st);
        if (WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz, WINHTTP_NO_HEADER_INDEX) && st == 200) {
            DWORD av = 0;
            if (WinHttpQueryDataAvailable(req, &av) && av >= 12) ok = true;
        }
    }
    DWORD t1 = GetTickCount();
    WinHttpCloseHandle(req); WinHttpCloseHandle(conn); WinHttpCloseHandle(sess);
    if (ok) *outMs = t1 - t0;
    return ok;
}

struct DnsTestJob { int provIdx; DnsTestResult result; DohProvider prov; };

static DWORD WINAPI dnsTestThread(LPVOID p) {
    DnsTestJob* j = (DnsTestJob*)p;
    DnsTestResult& r = j->result;
    r.provIdx = j->provIdx; r.reachable = false; r.avgMs = r.minMs = r.maxMs = 0; r.successes = 0;
    DWORD warm = 0;
    if (!dohQueryOnce(j->prov, "example.com", &warm)) return 0;
    static const char* names[] = { "example.com", "cloudflare.com", "wikipedia.org" };
    DWORD total = 0, mn = 0xFFFFFFFF, mx = 0;
    int ok = 0;
    for (int i = 0; i < DNS_TEST_QUERIES; i++) {
        DWORD ms = 0;
        if (dohQueryOnce(j->prov, names[i % 3], &ms)) { total += ms; if (ms < mn) mn = ms; if (ms > mx) mx = ms; ok++; }
    }
    if (ok > 0) { r.reachable = true; r.successes = ok; r.avgMs = total / ok; r.minMs = mn; r.maxMs = mx; }
    return 0;
}

static int runDnsTests(std::vector<DnsTestResult>& results) {
    int count = DOH_COUNT;
    if (!DOH[DOH_COUNT].host.empty()) count++;
    static DnsTestJob jobs[DOH_MAX_COUNT];
    std::vector<HANDLE> threads;
    for (int i = 0; i < count; i++) {
        jobs[i].provIdx = i; jobs[i].prov = DOH[i];
        jobs[i].result.provIdx = i; jobs[i].result.reachable = false;
        HANDLE h = CreateThread(NULL, 0, dnsTestThread, &jobs[i], 0, NULL);
        if (h) threads.push_back(h);
    }
    if (!threads.empty()) WaitForMultipleObjects((DWORD)threads.size(), &threads[0], TRUE, INFINITE);
    for (size_t i = 0; i < threads.size(); i++) CloseHandle(threads[i]);
    results.clear();
    for (int i = 0; i < count; i++) results.push_back(jobs[i].result);
    int best = -1; DWORD bm = 0xFFFFFFFF;
    for (size_t i = 0; i < results.size(); i++)
        if (results[i].reachable && results[i].avgMs < bm) { bm = results[i].avgMs; best = results[i].provIdx; }
    return best;
}

// interactive provider picker. returns true if st was changed.
static bool doDnsTestInteractive(Settings& st) {
    clearScreen();
    P("\n  %s%s%s\n", C_CYAN, TR("Measuring DoH latency...", "DoH gecikmesi ölçülüyor..."), C_RESET);
    std::vector<DnsTestResult> results;
    int rec = runDnsTests(results);
    while (true) {
        clearScreen();
        std::vector<MItem> items;
        for (size_t i = 0; i < results.size(); i++) {
            MItem m; m.label = DOH[i].name;
            if (results[i].reachable) m.value = fmt("%4lu ms", (unsigned long)results[i].avgMs);
            else m.value = TR("unreachable", "ulaşılamıyor");
            m.hint = g_lang ? DOH[i].noteTr : DOH[i].noteEn;
            if ((int)i == rec) m.hint = std::string(C_GREEN) + TR("recommended  ", "önerilen  ") + C_DIM + m.hint;
            items.push_back(m);
        }
        MItem a; a.label = TR("Automatic", "Otomatik"); a.hint = TR("measure and pick the fastest at every start", "her açılışta ölç, en hızlıyı seç"); items.push_back(a);
        MItem c; c.label = TR("Custom IP...", "Özel IP gir..."); c.hint = TR("your own DoH server (IPv4)", "kendi DoH sunucun (IPv4)"); items.push_back(c);
        MItem o; o.label = TR("Turn DoH off", "DoH'u kapat"); o.hint = TR("use normal DNS", "normal DNS kullan"); items.push_back(o);
        int n = (int)results.size();
        int sel = menuSelect(TR("DNS (DoH) PROVIDERS", "DNS (DoH) SAĞLAYICILARI"), items, rec >= 0 ? rec : 0);
        if (sel < 0) return false;
        if (sel < n) {
            st.dohProvider = sel; st.dohAuto = false; if (st.dnsMode == DNS_OFF) st.dnsMode = DNS_FAST;
            return true;
        }
        if (sel == n) { st.dohAuto = true; if (st.dnsMode == DNS_OFF) st.dnsMode = DNS_FAST; return true; }
        if (sel == n + 2) { st.dnsMode = DNS_OFF; return true; }
        clearScreen();
        P("\n  %s%s%s", C_YELLOW, TR("DoH server IPv4 address (e.g. 1.1.1.1): ", "DoH sunucusu IPv4 adresi (örn. 1.1.1.1): "), C_RESET);
        std::string ip; readLine(ip); ip = trim(ip);
        if (ip.empty()) continue;
        if (!validIPv4(ip)) { P("  %s%s%s\n", C_RED, TR("Not a valid IPv4 address.", "Geçerli bir IPv4 adresi değil."), C_RESET); Sleep(900); continue; }
        st.dohCustom = ip; setCustomDoh(ip);
        P("  %s%s%s\n", C_CYAN, TR("Measuring...", "Ölçülüyor..."), C_RESET);
        rec = runDnsTests(results);
    }
}

// ---------------------------------------------------------------- preset blacklist
static bool writePresetBlacklist() {
    static const char* d[] = {
        "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
        "roblox.com", "rbxcdn.com", "roblox.cn", "robloxlabs.com",
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
        "x.com", "twitter.com", "t.co", "twimg.com",
        "instagram.com", "cdninstagram.com",
        "twitch.tv", "ttvnw.net", "jtvnw.net",
        "imgur.com", "pastebin.com", "wattpad.com", "soundcloud.com", "sndcdn.com"
    };
    std::ofstream f("blacklist.txt");
    if (!f.is_open()) return false;
    f << "# DPI Hunter - only the domains listed here are modified.\n# Delete this file to protect every site.\n";
    for (size_t i = 0; i < sizeof(d) / sizeof(d[0]); i++) f << d[i] << "\n";
    return true;
}
static bool fileExists(const char* n) { return GetFileAttributesA(n) != INVALID_FILE_ATTRIBUTES; }

// ---------------------------------------------------------------- settings menu
static const char* onoff(bool b) { return b ? TR("on", "açık") : TR("off", "kapalı"); }

static void settingsMenu(Settings& st) {
    int sel = 0;
    bool autoOn = autostartEnabled();
    std::string note;
    clearScreen();
    while (true) {
        std::vector<MItem> it; MItem m;
#define ADD(l, v, hnt) m.label = (l); m.value = (v); m.hint = (hnt); it.push_back(m)
        ADD(TR("Language", "Dil"), st.lang ? "Türkçe" : "English", "");
        ADD(TR("DNS mode", "DNS modu"), st.dnsMode == DNS_FAST ? "fast" : st.dnsMode == DNS_FULL ? "full" : onoff(false),
            TR("fast: blacklist only / full: every query via DoH", "fast: sadece liste / full: tüm sorgular DoH"));
        ADD(TR("DoH provider", "DoH sağlayıcı"), st.dohAuto ? TR("automatic", "otomatik") : DOH[st.dohProvider].name.c_str(),
            TR("Enter: latency test and pick", "Enter: gecikme testi yap ve seç"));
        ADD(TR("Decoy TTL", "Sahte paket TTL"), fmt("%d", st.fakeTtl), TR("← → change (auto-lowered per server)", "← → değiştir (sunucuya göre otomatik düşer)"));
        ADD(TR("Decoy repeats", "Sahte tekrar"), fmt("%d", st.fakeRepeats), TR("how many decoys per packet", "paket başına kaç sahte"));
        ADD("QUIC (UDP/443)", st.quic == QUIC_DROP ? "drop" : st.quic == QUIC_FAKE ? "fake" : "pass",
            TR("drop: force TCP / fake: decoy first / pass: untouched", "drop: TCP'ye zorla / fake: önce sahte / pass: dokunma"));
        ADD(TR("Game / voice mode", "Oyun / ses modu"), onoff(st.game), TR("UDP decoys for Roblox, Discord voice...", "Roblox, Discord ses vb. için UDP sahteleri"));
        ADD(TR("HTTP (port 80)", "HTTP (port 80)"), onoff(st.httpEnabled), TR("Host header fragmentation", "Host başlığı parçalama"));
        ADD(TR("Deep tracking", "Derin takip"), onoff(st.deep), TR("handle hellos split over 2 packets (Chrome)", "2 pakete bölünen hello'ları yakala (Chrome)"));
        ADD(TR("Log file", "Log dosyası"), onoff(st.logEnabled), LOG_FILE);
        ADD(TR("Intro animation", "Giriş animasyonu"), onoff(st.intro), "");
        ADD(TR("Start with Windows", "Windows ile başlat"), onoff(autoOn), TR("scheduled task, AUTO mode", "zamanlanmış görev, AUTO modu"));
        ADD(TR("Create preset blacklist", "Hazır liste oluştur"), fileExists("blacklist.txt") ? TR("exists", "var") : TR("none", "yok"),
            TR("Discord, Roblox, YouTube, X... -> blacklist.txt", "Discord, Roblox, YouTube, X... -> blacklist.txt"));
        ADD(TR("Terms of use", "Kullanım koşulları"), "", "");
#undef ADD
        if (!note.empty()) { it[(size_t)sel].hint = std::string(C_GREEN) + note + C_RESET; }
        drawMenu(TR("SETTINGS", "AYARLAR"), it, sel, TR("↑↓ move   ← → / Enter change   Esc back (saved automatically)", "↑↓ gezin   ← → / Enter değiştir   Esc geri (otomatik kaydedilir)"));
        note.clear();
        int k = getKey(); int n = (int)it.size();
        if (k == K_UP) { sel = (sel + n - 1) % n; continue; }
        if (k == K_DOWN) { sel = (sel + 1) % n; continue; }
        if (k == K_ESC) break;
        if (k != K_ENTER && k != K_LEFT && k != K_RIGHT) continue;
        int dir = (k == K_LEFT) ? -1 : 1;
        switch (sel) {
        case 0: st.lang = !st.lang; g_lang = st.lang; clearScreen(); break;
        case 1: st.dnsMode = (DnsMode)(((int)st.dnsMode + 3 + dir) % 3); break;
        case 2:
            if (k == K_ENTER) { doDnsTestInteractive(st); clearScreen(); }
            else if (st.dohAuto) { st.dohAuto = false; st.dohProvider = dir > 0 ? 0 : DOH_COUNT - 1; }
            else { int p = st.dohProvider + dir; if (p < 0 || p >= DOH_COUNT) st.dohAuto = true; else st.dohProvider = p; }
            break;
        case 3: st.fakeTtl = imin(20, imax(1, st.fakeTtl + dir)); break;
        case 4: st.fakeRepeats = imin(10, imax(1, st.fakeRepeats + dir)); break;
        case 5: st.quic = (QuicMode)(((int)st.quic + 3 + dir) % 3); break;
        case 6: st.game = !st.game; break;
        case 7: st.httpEnabled = !st.httpEnabled; break;
        case 8: st.deep = !st.deep; break;
        case 9: st.logEnabled = !st.logEnabled; break;
        case 10: st.intro = !st.intro; break;
        case 11:
            if (autostartSet(!autoOn)) autoOn = !autoOn;
            else note = TR("could not change the scheduled task", "zamanlanmış görev değiştirilemedi");
            break;
        case 12:
            if (k == K_ENTER) {
                if (fileExists("blacklist.txt")) note = TR("blacklist.txt already exists - delete it first", "blacklist.txt zaten var - önce onu sil");
                else note = writePresetBlacklist() ? TR("blacklist.txt created", "blacklist.txt oluşturuldu") : TR("could not write the file", "dosya yazılamadı");
            }
            break;
        case 13: if (k == K_ENTER) { showDisclaimer(false); clearScreen(); } break;
        }
        configWrite(st); applySettings(st);
    }
}

static RunMode mainMenu() {
    std::vector<MItem> it; MItem m;
#define ADD(l, hnt) m.label = (l); m.hint = (hnt); it.push_back(m)
    ADD(TR("AUTO", "OTOMATİK"), TR("finds and keeps the working strategy by itself", "çalışan stratejiyi kendi bulur ve korur"));
    ADD(TR("MANUAL", "MANUEL"), TR("you pick the strategy, no auto switching", "stratejiyi sen seçersin, otomatik değişmez"));
    ADD(TR("ANALYZE", "ANALİZ"), TR("tries every strategy, saves the best one", "tüm stratejileri dener, en iyisini kaydeder"));
    ADD(TR("DNS TEST", "DNS TESTİ"), TR("measure DoH providers and choose", "DoH sağlayıcılarını ölç ve seç"));
    ADD(TR("SETTINGS", "AYARLAR"), TR("language, DNS, QUIC, game mode, autostart...", "dil, DNS, QUIC, oyun modu, otomatik başlatma..."));
    ADD(TR("HELP", "YARDIM"), TR("command line options and files", "komut satırı seçenekleri ve dosyalar"));
    ADD(TR("EXIT", "ÇIKIŞ"), "");
#undef ADD
    static int sel = 0;
    int r = menuSelect(TR("MAIN MENU", "ANA MENÜ"), it, sel);
    if (r < 0) return RUN_EXIT;
    sel = r;
    static const RunMode map[] = { RUN_AUTO, RUN_MANUAL, RUN_ANALYZE, RUN_TEST, RUN_SETTINGS, RUN_HELP, RUN_EXIT };
    return map[r];
}

// ================================================================ dashboard
#define HDR_ROWS 7
static bool g_dashOn = false;
static int  g_dashW = 0, g_dashH = 0;
#define SPARK_N 48
static int  g_spark[SPARK_N] = { 0 };

static int hostStratCount() {
    EnterCriticalSection(&g_hostLock); int n = (int)g_hostStrat.size(); LeaveCriticalSection(&g_hostLock); return n;
}
// caller holds g_consoleLock
static void dashDraw() {
    if (!g_dashOn) return;
    int w, h; conSize(w, h);
    std::string o;
    if (w != g_dashW || h != g_dashH) {
        g_dashW = w; g_dashH = h;
        o += fmt("\x1b[%d;%dr\x1b[%d;1H", HDR_ROWS + 1, h - 2, h - 2);
    }
    o += "\x1b" "7\x1b[?25l";
    Strategy cur = getStrategy();
    DWORD up = (GetTickCount() - g_runStart) / 1000;
    std::string rule = std::string(C_DIM) + rep("─", w - 2) + C_RESET;
    o += fmt("\x1b[1;1H\x1b[K %s%s%s", C_BOLD, gradText("■ DPI HUNTER").c_str(), C_RESET);
    o += fmt("\x1b[1;%dH%sby astegtam%s", imax(16, w - 12), C_WHITE, C_RESET);
    o += "\x1b[2;1H\x1b[K " + rule;
    const char* stCol = cur == STRAT_DISABLED ? C_YELLOW : C_GREEN;
    const char* stTxt = cur == STRAT_DISABLED ? TR("SAFE MODE", "GÜVENLİ MOD") : TR("ACTIVE", "AKTİF");
    o += "\x1b[3;1H\x1b[K" + clip(fmt("  %s●%s %s%s%s%s   %s%s%s %s%s%s   %s%s%s %02lu:%02lu:%02lu   %s%s%s %s",
        stCol, C_RESET, C_BOLD, stCol, stTxt, C_RESET,
        C_DIM, TR("Strategy", "Strateji"), C_RESET, C_CYAN, STRAT_NAMES[cur], C_RESET,
        C_DIM, TR("Uptime", "Süre"), C_RESET, (unsigned long)(up / 3600), (unsigned long)((up / 60) % 60), (unsigned long)(up % 60),
        C_DIM, TR("Mode", "Mod"), C_RESET, g_lblMode.c_str()), w - 1);
    o += "\x1b[4;1H\x1b[K" + clip(fmt("  %sDNS%s %s   %sQUIC%s %s   %sUDP%s %s   %sTTL%s %d×%d   %s%s%s %s   %s%s%s %d",
        C_DIM, C_RESET, g_lblDns.c_str(),
        C_DIM, C_RESET, g_quicMode == QUIC_DROP ? "drop" : g_quicMode == QUIC_FAKE ? "fake" : "pass",
        C_DIM, C_RESET, onoff(g_game),
        C_DIM, C_RESET, g_fakeTtl, g_fakeRepeats,
        C_DIM, TR("List", "Liste"), C_RESET, g_lblList.c_str(),
        C_DIM, TR("Learned", "Öğrenilen"), C_RESET, hostStratCount()), w - 1);
    o += "\x1b[5;1H\x1b[K" + clip(fmt("  %s%s%s %ld   %s%s%s %ld   %sFake%s %ld   %sQUIC%s %ld   %sUDP%s %ld   %sDoH%s %ld/%ld   %s%s%s %ld   %s%s%s %ld",
        C_DIM, TR("Packets", "Paket"), C_RESET, (long)g_stats.total,
        C_DIM, TR("Split", "Bölünen"), C_RESET, (long)g_stats.fragmented,
        C_DIM, C_RESET, (long)g_stats.fakeSent,
        C_DIM, C_RESET, (long)(g_stats.quicBlocked + g_stats.quicFaked),
        C_DIM, C_RESET, (long)g_stats.udpFaked,
        C_DIM, C_RESET, (long)g_stats.dnsDoh, (long)g_stats.dnsFallback,
        C_DIM, TR("Signals", "Sinyal"), C_RESET, (long)g_stats.signals,
        C_DIM, TR("Fixes", "Onarım"), C_RESET, (long)g_stats.hostFixes), w - 1);
    {
        static const char* bars[] = { " ", "_", "▄", "█" };   // only glyphs every console font has
        int mx = 1; for (int i = 0; i < SPARK_N; i++) mx = imax(mx, g_spark[i]);
        int n = imin(SPARK_N, w - 6);
        o += "\x1b[6;1H\x1b[K  ";
        for (int i = SPARK_N - n; i < SPARK_N; i++) {
            int lvl = g_spark[i] <= 0 ? 0 : 1 + (g_spark[i] * 2) / mx; if (lvl > 3) lvl = 3;
            o += gradCol((double)(i - (SPARK_N - n)) / (double)imax(1, n - 1)); o += bars[lvl];
        }
        o += C_RESET;
    }
    o += "\x1b[7;1H\x1b[K " + rule;
    o += fmt("\x1b[%d;1H\x1b[K ", h - 1) + rule;
    std::string keys = g_analyzeMode
        ? fmt("  %s[M]%s %s   %s[Q]%s %s", C_CYAN, C_RESET, TR("Menu", "Menü"), C_CYAN, C_RESET, TR("Quit", "Çıkış"))
        : fmt("  %s[S]%s %s   %s[T]%s %s   %s[M]%s %s   %s[Q]%s %s", C_CYAN, C_RESET, TR("Next strategy", "Strateji değiştir"),
            C_CYAN, C_RESET, TR("Test now", "Şimdi test et"), C_CYAN, C_RESET, TR("Menu", "Menü"), C_CYAN, C_RESET, TR("Quit", "Çıkış"));
    o += fmt("\x1b[%d;1H\x1b[K", h) + clip(keys, w - 1);
    int dl = vislen(DISCLAIMER_SHORT);
    if (w > vislen(keys) + dl + 6) o += fmt("\x1b[%d;%dH%s%s%s", h, w - dl, C_DIM, DISCLAIMER_SHORT, C_RESET);
    o += "\x1b" "8";
    puts8(o);
    SetConsoleTitleA(fmt("DPI Hunter - %s", STRAT_NAMES[cur]).c_str());
}
static void dashRefresh() { EnterCriticalSection(&g_consoleLock); dashDraw(); LeaveCriticalSection(&g_consoleLock); }
static void dashBegin() {
    EnterCriticalSection(&g_consoleLock);
    clearScreen(); cursorShow(false);
    g_dashOn = true; g_dashW = g_dashH = 0;
    memset(g_spark, 0, sizeof(g_spark));
    int w, h; conSize(w, h);
    P("\x1b[%d;%dr\x1b[%d;1H", HDR_ROWS + 1, h - 2, HDR_ROWS + 1);
    g_dashW = w; g_dashH = h;
    dashDraw();
    LeaveCriticalSection(&g_consoleLock);
}
static void dashEnd() {
    EnterCriticalSection(&g_consoleLock);
    g_dashOn = false;
    P("\x1b[r");
    SetConsoleTitleA("DPI Hunter");
    LeaveCriticalSection(&g_consoleLock);
}

// ================================================================ host helpers
static void loadHostList(const char* fn, std::set<std::string>& dst) {
    std::ifstream f(fn);
    if (!f.is_open()) return;
    std::string line; bool first = true;
    while (std::getline(f, line)) {
        if (first) { stripBom(line); first = false; }
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t p = line.find("://"); if (p != std::string::npos) line = line.substr(p + 3);
        p = line.find('/'); if (p != std::string::npos) line = line.substr(0, p);
        if (!line.empty() && line[0] == '.') line.erase(0, 1);
        if (!line.empty()) dst.insert(lower(line));
    }
}
static bool inList(const std::set<std::string>& l, const std::string& h) {
    if (l.empty()) return false;
    size_t p = 0;
    while (true) {
        if (l.count(h.substr(p))) return true;
        p = h.find('.', p);
        if (p == std::string::npos) return false;
        ++p;
    }
}
static bool isBlacklisted(const std::string& h) { return g_blacklist.empty() ? true : inList(g_blacklist, h); }
static bool isExcluded(const std::string& h) { return inList(g_exclude, h); }
static bool isPlainHost(const std::string& h) {
    if (h.size() < 3 || h.size() > 200) return false;
    if (h[0] == '.' || h.find('.') == std::string::npos) return false;
    bool digitsOnly = true;
    for (size_t i = 0; i < h.size(); i++) if (!((h[i] >= '0' && h[i] <= '9') || h[i] == '.')) { digitsOnly = false; break; }
    if (digitsOnly) return false;
    for (size_t i = 0; i < h.size(); i++) {
        char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
    }
    return true;
}
// registrable-ish domain: last two labels, three for "x.com.tr" style names
static std::string baseDomain(const std::string& h) {
    size_t p1 = h.rfind('.'); if (p1 == std::string::npos || p1 == 0) return h;
    size_t p2 = h.rfind('.', p1 - 1); if (p2 == std::string::npos) return h;
    std::string sld = h.substr(p2 + 1, p1 - p2 - 1); size_t tldLen = h.size() - p1 - 1;
    static const char* gen[] = { "com","net","org","gov","edu","co","ac","gen","web","k12","av","bel","pol","biz","info","tv","name","dr" };
    bool g = false;
    if (tldLen == 2) for (size_t i = 0; i < sizeof(gen) / sizeof(gen[0]); i++) if (sld == gen[i]) { g = true; break; }
    if (!g) return h.substr(p2 + 1);
    if (p2 == 0) return h;
    size_t p3 = h.rfind('.', p2 - 1);
    return p3 == std::string::npos ? h : h.substr(p3 + 1);
}

// ---------------------------------------------------------------- per-domain strategy memory
static Strategy effStrategy(const std::string& host) {
    Strategy g = getStrategy();
    if (g == STRAT_DISABLED || host.empty() || InterlockedCompareExchange(&g_ignoreHost, 0, 0)) return g;
    int r = -1;
    EnterCriticalSection(&g_hostLock);
    if (!g_hostStrat.empty()) {
        std::map<std::string, int>::const_iterator it = g_hostStrat.find(baseDomain(host));
        if (it != g_hostStrat.end()) r = it->second;
    }
    LeaveCriticalSection(&g_hostLock);
    return r >= 0 ? (Strategy)r : g;
}
static void setHostStrat(const std::string& base, int s) {
    EnterCriticalSection(&g_hostLock);
    if (s < 0) g_hostStrat.erase(base);
    else { if (g_hostStrat.size() > 500) g_hostStrat.clear(); g_hostStrat[base] = s; }
    LeaveCriticalSection(&g_hostLock);
}
static int getHostStrat(const std::string& base) {
    int r = -1;
    EnterCriticalSection(&g_hostLock);
    std::map<std::string, int>::const_iterator it = g_hostStrat.find(base);
    if (it != g_hostStrat.end()) r = it->second;
    LeaveCriticalSection(&g_hostLock);
    return r;
}
static void saveHostStrats() {
    EnterCriticalSection(&g_hostLock);
    std::ofstream f(HOSTS_FILE);
    if (f.is_open()) {
        f << "# DPI Hunter - learned per-domain strategies (domain=Strategy). Safe to delete.\n";
        for (std::map<std::string, int>::const_iterator it = g_hostStrat.begin(); it != g_hostStrat.end(); ++it)
            if (it->second >= 0 && it->second < STRAT_BYPASS_COUNT) f << it->first << "=" << STRAT_NAMES[it->second] << "\n";
    }
    LeaveCriticalSection(&g_hostLock);
}
static void loadHostStrats() {
    EnterCriticalSection(&g_hostLock);
    g_hostStrat.clear();
    std::ifstream f(HOSTS_FILE);
    std::string line;
    while (f.is_open() && std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string d = lower(trim(line.substr(0, eq)));
        int s = stratByName(trim(line.substr(eq + 1)));
        if (s >= 0 && isPlainHost(d) && g_hostStrat.size() < 500) g_hostStrat[d] = s;
    }
    LeaveCriticalSection(&g_hostLock);
}

// ---------------------------------------------------------------- parsers
// Pattern scan for the server_name extension; works on any TCP segment of a ClientHello.
static bool extractSni(const char* d, unsigned int len, char** out, unsigned int* outLen) {
    if (len < 10) return false;
    for (uint32_t p = 0; p + 9 < len; p++) {
        if (d[p] == 0 && d[p + 1] == 0 && d[p + 2] == 0 && d[p + 4] == 0 && d[p + 6] == 0 && d[p + 7] == 0 &&
            (unsigned char)d[p + 3] - (unsigned char)d[p + 5] == 2 && (unsigned char)d[p + 5] - (unsigned char)d[p + 8] == 3) {
            unsigned int hl = (unsigned char)d[p + 8];
            if (hl < 3 || hl > 253 || p + 9 + hl > len) continue;
            const char* hn = &d[p + 9];
            bool ok = true, dot = false;
            for (unsigned int i = 0; i < hl; i++) {
                char c = hn[i];
                if (c == '.') dot = true;
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) { ok = false; break; }
            }
            if (!ok || !dot) continue;
            *out = (char*)hn; *outLen = hl; return true;
        }
    }
    return false;
}
static bool isHttpRequest(const UINT8* p, UINT len) {
    if (len < 8 || p[0] < 'A' || p[0] > 'Z') return false;
    static const char* m[] = { "GET ","POST ","HEAD ","PUT ","DELETE ","OPTIONS ","CONNECT ","PATCH ","TRACE " };
    for (int i = 0; i < 9; i++) {
        size_t ml = strlen(m[i]);
        if (len >= ml && memcmp(p, m[i], ml) == 0) return true;
    }
    return false;
}
static bool extractHttpHost(const char* d, unsigned int len, char** out, unsigned int* outLen) {
    if (len < 12) return false;
    unsigned int hdrEnd = len;
    for (unsigned int i = 0; i + 3 < len; i++)
        if (d[i] == '\r' && d[i + 1] == '\n' && d[i + 2] == '\r' && d[i + 3] == '\n') { hdrEnd = i + 2; break; }
    for (unsigned int i = 0; i + 5 < hdrEnd; i++) {
        if (i != 0 && d[i - 1] != '\n') continue;
        if ((d[i] | 0x20) == 'h' && (d[i + 1] | 0x20) == 'o' && (d[i + 2] | 0x20) == 's' && (d[i + 3] | 0x20) == 't' && d[i + 4] == ':') {
            unsigned int j = i + 5;
            while (j < hdrEnd && (d[j] == ' ' || d[j] == '\t')) j++;
            unsigned int start = j;
            while (j < hdrEnd && d[j] != '\r' && d[j] != '\n') j++;
            if (j >= hdrEnd) return false;
            unsigned int end = j;
            while (end > start && (d[end - 1] == ' ' || d[end - 1] == '\t')) end--;
            if (end <= start || d[start] == '[') return false;
            for (unsigned int k = start; k < end; k++) if (d[k] == ':') { end = k; break; }
            if (end <= start || end - start > 253) return false;
            *out = (char*)(d + start); *outLen = end - start; return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------- addresses / tables (packet thread only)
struct IpKey { UINT32 a[4]; };
static IpKey keyV4(UINT32 v) { IpKey k; k.a[0] = v; k.a[1] = 0; k.a[2] = 0; k.a[3] = 0; return k; }
static IpKey keyV6(const UINT32* v) { IpKey k; memcpy(k.a, v, 16); return k; }
static bool keyEq(const IpKey& x, const IpKey& y) { return memcmp(x.a, y.a, 16) == 0; }
static bool operator<(const IpKey& x, const IpKey& y) { return memcmp(x.a, y.a, 16) < 0; }
static unsigned keyHash(const IpKey& k) { return (unsigned)((k.a[0] ^ k.a[1] ^ k.a[2] ^ k.a[3]) * 2654435761u); }

static std::set<IpKey> g_blkIps;   // addresses of blacklisted names, learned from DoH answers

static bool isLocalDst(PWINDIVERT_IPHDR ip, PWINDIVERT_IPV6HDR ip6) {
    if (ip) {
        const UINT8* b = (const UINT8*)&ip->DstAddr;
        return b[0] == 127 || b[0] == 10 || b[0] == 0 || b[0] >= 224 || (b[0] == 172 && (b[1] & 0xF0) == 16) ||
            (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && (b[1] & 0xC0) == 64);
    }
    if (ip6) {
        const UINT8* b = (const UINT8*)ip6->DstAddr;
        return (b[0] & 0xFE) == 0xFC || b[0] == 0xFF || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) ||
            (ip6->DstAddr[0] == 0 && ip6->DstAddr[1] == 0 && ip6->DstAddr[2] == 0 && ip6->DstAddr[3] == htonl(1));
    }
    return false;
}

// recently seen hellos: retransmission + RST matching
struct Recent { IpKey key; USHORT dport, sport; UINT32 seq; DWORD tick; char host[128]; bool rst; };
static Recent g_recent[RECENT_MAX];
static int g_recentIdx = 0;

// returns true when this exact hello was already seen (= the OS is retransmitting it)
static bool noteHello(const IpKey& k, USHORT dport, USHORT sport, UINT32 seq, const char* host) {
    DWORD now = GetTickCount();
    for (int i = 0; i < RECENT_MAX; i++) {
        Recent& r = g_recent[i];
        if (r.host[0] && r.seq == seq && r.sport == sport && r.dport == dport && keyEq(r.key, k) && (now - r.tick) < 30000) return true;
    }
    g_recentIdx = (g_recentIdx + 1) % RECENT_MAX;
    Recent& r = g_recent[g_recentIdx];
    r.key = k; r.dport = dport; r.sport = sport; r.seq = seq; r.tick = now; r.rst = false;
    scpy(r.host, sizeof(r.host), host);
    return false;
}
static std::string matchRst(const IpKey& k, USHORT remotePort, USHORT localPort) {
    DWORD now = GetTickCount();
    for (int i = 0; i < RECENT_MAX; i++) {
        Recent& r = g_recent[i];
        if (r.host[0] && !r.rst && r.dport == remotePort && r.sport == localPort && keyEq(r.key, k) && (now - r.tick) < 4000) { r.rst = true; return r.host; }
    }
    return "";
}

// "this host looks blocked" counter (RST after hello, or hello retransmitted)
struct Sig { int n; DWORD t0; };
static std::map<std::string, Sig> g_sig;
static void noteSignal(const std::string& host) {
    InterlockedIncrement(&g_stats.signals);
    if (!g_autoSwitch || InterlockedCompareExchange(&g_emergencyRunning, 0, 0) || InterlockedCompareExchange(&g_emergencyFlag, 0, 0)) return;
    std::string b = baseDomain(host);
    DWORD now = GetTickCount();
    if (g_sig.size() > 128) g_sig.clear();
    Sig& s = g_sig[b];
    if (s.n == 0 || (now - s.t0) > SIG_WINDOW_MS) { s.n = 0; s.t0 = now; }
    if (++s.n >= SIG_TRIGGER) {
        s.n = 0;
        EnterCriticalSection(&g_emLock);
        scpy(g_emergencyHost, sizeof(g_emergencyHost), host.c_str());
        InterlockedExchange(&g_emergencyFlag, 1);
        LeaveCriticalSection(&g_emLock);
    }
}

// ClientHellos that continue in the next TCP segment and whose SNI we have not seen yet
struct Pend { IpKey key; USHORT sport, dport; UINT32 nextSeq; DWORD tick; bool used; };
static Pend g_pend[PEND_MAX];
static int g_pendCount = 0, g_pendIdx = 0;
static void pendAdd(const IpKey& k, USHORT sport, USHORT dport, UINT32 nextSeq) {
    g_pendIdx = (g_pendIdx + 1) % PEND_MAX;
    Pend& p = g_pend[g_pendIdx];
    if (!p.used) g_pendCount++;
    p.key = k; p.sport = sport; p.dport = dport; p.nextSeq = nextSeq; p.tick = GetTickCount(); p.used = true;
}
static Pend* pendFind(const IpKey& k, USHORT sport, USHORT dport, UINT32 seq) {
    if (g_pendCount <= 0) return NULL;
    DWORD now = GetTickCount();
    for (int i = 0; i < PEND_MAX; i++) {
        Pend& p = g_pend[i];
        if (!p.used) continue;
        if ((now - p.tick) > 3000) { p.used = false; g_pendCount--; continue; }
        if (p.nextSeq == seq && p.sport == sport && p.dport == dport && keyEq(p.key, k)) return &p;
    }
    return NULL;
}

// hop distance learned from SYN-ACKs -> decoy TTL that dies just before the server
struct HopEntry { IpKey key; BYTE hops; };
static HopEntry g_hops[256];
static BYTE autoTtl(const IpKey& k, int def) {
    const HopEntry& e = g_hops[keyHash(k) >> 24];
    int t = def;
    if (e.hops > 1 && keyEq(e.key, k) && (int)e.hops - 1 < t) t = (int)e.hops - 1;
    if (t < 1) t = 1; if (t > 20) t = 20;
    return (BYTE)t;
}

// UDP flows for game / voice mode
struct UFlow { IpKey key; USHORT dport, sport; BYTE cnt; DWORD tick; };
static UFlow g_uflow[UFLOW_MAX];
static bool udpInRange(USHORT p) {
    for (size_t i = 0; i < g_udpRanges.size(); i++) if (p >= g_udpRanges[i].a && p <= g_udpRanges[i].b) return true;
    return false;
}

// ================================================================ packet crafting
#define F_TTL     1
#define F_BADSUM  2
#define F_BADSEQ  4
#define F_MD5     8
#define SP_REV    1
#define SP_DELAY  2
#define SP_OVL    4

struct Ctx {
    const unsigned char* pkt;   // full original packet
    UINT len;                   // its length
    const WINDIVERT_ADDRESS* addr;
    UINT tcpOff, hdrLen, plLen; // tcp header offset, ip+tcp header size, payload size
    BYTE ttl;                   // decoy TTL for this destination
    bool v6;
};
static int g_idInc = 0;

// Sends one TCP segment built from the original headers.
//   start/len : slice of the stream (relative to the original payload)
//   data      : NULL = real bytes, else decoy bytes (len bytes)
//   fool      : F_* flags that make the server ignore the segment
//   ovl       : junk bytes put in front, sequence moved back by the same amount
static bool sendSeg(const Ctx& c, UINT start, UINT len, const UINT8* data, int fool, UINT ovl) {
    static unsigned char buf[MAXBUF + 64];
    if (len == 0) return true;
    UINT hl = c.hdrLen, extra = 0;
    memcpy(buf, c.pkt, hl);
    PWINDIVERT_TCPHDR t = (PWINDIVERT_TCPHDR)(buf + c.tcpOff);
    if (fool & F_MD5) {
        UINT tcpHl = (UINT)t->HdrLength * 4;
        if (tcpHl + 20 <= 60 && c.tcpOff + tcpHl == hl) {
            unsigned char* o = buf + hl;
            o[0] = 1; o[1] = 1; o[2] = 19; o[3] = 18; memset(o + 4, 0x5A, 16);
            t->HdrLength = (UINT8)(t->HdrLength + 5); extra = 20;
        } else fool |= F_BADSEQ;
    }
    UINT total = hl + extra + ovl + len;
    if (total > MAXBUF) return false;
    unsigned char* p = buf + hl + extra;
    if (ovl) memset(p, 0, ovl);
    memcpy(p + ovl, data ? data : c.pkt + hl + start, len);
    UINT32 seq = ntohl(t->SeqNum) + start - ovl;
    if (fool & F_BADSEQ) { seq -= 10000; t->AckNum = htonl(ntohl(t->AckNum) - 66000); }
    t->SeqNum = htonl(seq);
    if (c.v6) {
        PWINDIVERT_IPV6HDR h = (PWINDIVERT_IPV6HDR)buf;
        h->Length = htons((UINT16)(total - 40));
        if (fool & F_TTL) h->HopLimit = c.ttl;
    } else {
        PWINDIVERT_IPHDR h = (PWINDIVERT_IPHDR)buf;
        h->Length = htons((UINT16)total);
        h->Id = htons((UINT16)(ntohs(h->Id) + g_idInc));
        if (fool & F_TTL) h->TTL = c.ttl;
    }
    g_idInc++;
    WINDIVERT_ADDRESS a = *c.addr;
    WinDivertHelperCalcChecksums(buf, total, &a, 0);
    if (fool & F_BADSUM) t->Checksum = htons((UINT16)(ntohs(t->Checksum) - 1));
    return WinDivertSend(g_handle, buf, total, NULL, &a) != FALSE;
}

// Cuts the payload at the given positions and sends the pieces.
static bool sendSplits(const Ctx& c, const UINT* pos, int n, int flags) {
    UINT b[8]; int cnt = 0;
    for (int i = 0; i < n && cnt < 6; i++) if (pos[i] > 0 && pos[i] < c.plLen) b[cnt++] = pos[i];
    if (cnt == 0) return false;
    std::sort(b, b + cnt);
    cnt = (int)(std::unique(b, b + cnt) - b);
    UINT edge[9]; edge[0] = 0;
    for (int i = 0; i < cnt; i++) edge[i + 1] = b[i];
    edge[cnt + 1] = c.plLen;
    int segs = cnt + 1; bool all = true;
    for (int k = 0; k < segs; k++) {
        int i = (flags & SP_REV) ? segs - 1 - k : k;
        UINT ovl = ((flags & SP_OVL) && i == 0) ? 16 : 0;
        if (!sendSeg(c, edge[i], edge[i + 1] - edge[i], NULL, 0, ovl)) all = false;
        if ((flags & SP_DELAY) && k + 1 < segs) Sleep(12);
    }
    return all;
}

static void makeFakeHost(UINT8* dst, unsigned int len) {
    const char* base = "www.google.com";
    const unsigned int bl = 14;
    if (len >= bl) { unsigned int pad = len - bl; for (unsigned int i = 0; i < pad; i++) dst[i] = 'w'; memcpy(dst + pad, base, bl); }
    else memcpy(dst, base + (bl - len), len);
}
static UINT8 g_fakePl[MAXBUF];
static void sendFakeWhole(const Ctx& c, int fool, int reps) {
    for (int i = 0; i < reps; i++) { sendSeg(c, 0, c.plLen, g_fakePl, fool, 0); InterlockedIncrement(&g_stats.fakeSent); }
}

static void applyStrategy(const Ctx& c, Strategy s, bool hasHost, UINT hOff, UINT hLen) {
    g_idInc = 0;
    const UINT L = c.plLen;
    const UINT pS = hasHost ? hOff : 2;
    const UINT pM = hasHost ? hOff + (hLen > 1 ? hLen / 2 : 1) : 2;
    const UINT one[1] = { 2 }, sni[1] = { pS }, mid[1] = { pM }, multi[3] = { 1, pS, pM }, dly[2] = { 2, pM };
    bool done = false;
    const bool fakeKind = (s >= S_FAKE_TTL && s <= S_COMBO);
    if (fakeKind && !hasHost) s = S_SPLIT2;          // nothing to hide in this segment, plain split is enough
    if (fakeKind && hasHost) {
        if (L > sizeof(g_fakePl) || hOff + hLen > L) s = S_SPLIT_MID;
        else { memcpy(g_fakePl, c.pkt + c.hdrLen, L); makeFakeHost(g_fakePl + hOff, hLen); }
    }
    const int reps = g_fakeRepeats;
    switch (s) {
    case S_SPLIT2:        done = sendSplits(c, one, 1, 0); break;
    case S_SPLIT_SNI:     done = sendSplits(c, sni, 1, 0); break;
    case S_SPLIT_MID:     done = sendSplits(c, mid, 1, 0); break;
    case S_MULTISPLIT:    done = sendSplits(c, multi, 3, 0); break;
    case S_DISORDER:      done = sendSplits(c, mid, 1, SP_REV); break;
    case S_MULTIDISORDER: done = sendSplits(c, multi, 3, SP_REV); break;
    case S_SEQOVL:        done = sendSplits(c, mid, 1, SP_OVL); break;
    case S_DELAY:         done = sendSplits(c, dly, 2, SP_DELAY); break;
    case S_FAKE_TTL:      sendFakeWhole(c, F_TTL, reps); break;
    case S_FAKE_BADSUM:   sendFakeWhole(c, F_BADSUM, reps); break;
    case S_FAKE_BADSEQ:   sendFakeWhole(c, F_BADSEQ, reps); break;
    case S_FAKE_MD5:      sendFakeWhole(c, F_MD5, reps); break;
    case S_FAKE_SPLIT:    sendFakeWhole(c, F_TTL, reps); done = sendSplits(c, mid, 1, 0); break;
    case S_FAKE_DISORDER: sendFakeWhole(c, F_TTL, reps); done = sendSplits(c, mid, 1, SP_REV); break;
    case S_FAKEDSPLIT:
        if (pM > 0 && pM < L) {
            sendSeg(c, 0, pM, g_fakePl, F_TTL, 0);
            bool a = sendSeg(c, 0, pM, NULL, 0, 0);
            sendSeg(c, 0, pM, g_fakePl, F_TTL, 0);
            sendSeg(c, pM, L - pM, g_fakePl + pM, F_TTL, 0);
            bool b = sendSeg(c, pM, L - pM, NULL, 0, 0);
            sendSeg(c, pM, L - pM, g_fakePl + pM, F_TTL, 0);
            InterlockedExchangeAdd(&g_stats.fakeSent, 4);
            done = a && b;
        }
        break;
    case S_COMBO:
        sendFakeWhole(c, F_TTL, reps); sendFakeWhole(c, F_MD5, 1);
        done = sendSplits(c, multi, 3, 0);
        break;
    default: break;
    }
    if (done) { InterlockedIncrement(&g_stats.fragmented); return; }
    WinDivertSend(g_handle, c.pkt, c.len, NULL, c.addr);
    InterlockedIncrement(&g_stats.passed);
}

// decoy UDP datagrams (game / voice mode and QUIC "fake" mode)
static void sendFakeUdp(const unsigned char* pkt, UINT hdrLen, bool v6, const WINDIVERT_ADDRESS* addr, UINT fakeLen, UINT8 firstByte, int reps) {
    static unsigned char buf[2048];
    if (hdrLen < 28 || hdrLen + fakeLen > sizeof(buf)) return;
    memcpy(buf, pkt, hdrLen);
    memset(buf + hdrLen, 0, fakeLen);
    buf[hdrLen] = firstByte;
    UINT total = hdrLen + fakeLen;
    PWINDIVERT_UDPHDR u = (PWINDIVERT_UDPHDR)(buf + hdrLen - 8);
    u->Length = htons((UINT16)(8 + fakeLen));
    BYTE ttl = (BYTE)imin(20, imax(1, g_fakeTtl));
    for (int i = 0; i < reps; i++) {
        if (v6) { PWINDIVERT_IPV6HDR h = (PWINDIVERT_IPV6HDR)buf; h->Length = htons((UINT16)(total - 40)); h->HopLimit = ttl; }
        else { PWINDIVERT_IPHDR h = (PWINDIVERT_IPHDR)buf; h->Length = htons((UINT16)total); h->Id = htons((UINT16)(ntohs(h->Id) + 1)); h->TTL = ttl; }
        WINDIVERT_ADDRESS a = *addr;
        WinDivertHelperCalcChecksums(buf, total, &a, 0);
        WinDivertSend(g_handle, buf, total, NULL, &a);
    }
}
static bool isQuic(PVOID p, UINT l) { return p && l >= 1200 && (((UINT8*)p)[0] & 0xC0) == 0xC0; }

// ================================================================ reachability tests
typedef std::vector<unsigned char> Bytes;
static void p8(Bytes& b, unsigned v) { b.push_back((unsigned char)(v & 0xFF)); }
static void p16(Bytes& b, unsigned v) { p8(b, v >> 8); p8(b, v); }
static void p24(Bytes& b, unsigned v) { p8(b, v >> 16); p16(b, v); }
static void pB(Bytes& b, const void* p, size_t n) { const unsigned char* c = (const unsigned char*)p; b.insert(b.end(), c, c + n); }
static void pExt(Bytes& o, unsigned t, const Bytes& d) { p16(o, t); p16(o, (unsigned)d.size()); o.insert(o.end(), d.begin(), d.end()); }
static unsigned char rb(unsigned& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return (unsigned char)(s & 0xFF); }

// Browser-sized ClientHello (~1.8 KB, padded) so the test crosses two TCP segments like Chrome does.
static void buildClientHello(const char* host, Bytes& out) {
    unsigned s = GetTickCount() ^ 0x9E3779B9u ^ (unsigned)(size_t)host;
    if (s == 0) s = 1;
    size_t hl = strlen(host);
    Bytes ext;
    { Bytes d; p16(d, (unsigned)(hl + 3)); p8(d, 0); p16(d, (unsigned)hl); pB(d, host, hl); pExt(ext, 0x0000, d); }
    { Bytes d; p16(d, 6); p16(d, 0x001d); p16(d, 0x0017); p16(d, 0x0018); pExt(ext, 0x000a, d); }
    { Bytes d; p8(d, 1); p8(d, 0); pExt(ext, 0x000b, d); }
    { const unsigned sig[] = { 0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601 }; Bytes d; p16(d, 2 * 8); for (int i = 0; i < 8; i++) p16(d, sig[i]); pExt(ext, 0x000d, d); }
    { Bytes d; p8(d, 4); p16(d, 0x0304); p16(d, 0x0303); pExt(ext, 0x002b, d); }
    { Bytes d; p8(d, 1); p8(d, 1); pExt(ext, 0x002d, d); }
    { Bytes d; p16(d, 36); p16(d, 0x001d); p16(d, 32); for (int i = 0; i < 32; i++) p8(d, rb(s)); pExt(ext, 0x0033, d); }
    { Bytes d(1500, 0); pExt(ext, 0x0015, d); }
    Bytes body;
    p16(body, 0x0303); for (int i = 0; i < 32; i++) p8(body, rb(s)); p8(body, 32); for (int i = 0; i < 32; i++) p8(body, rb(s));
    const unsigned c[] = { 0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0x009c,0x009d,0x002f,0x0035 };
    p16(body, 2 * 13); for (int i = 0; i < 13; i++) p16(body, c[i]);
    p8(body, 1); p8(body, 0); p16(body, (unsigned)ext.size()); body.insert(body.end(), ext.begin(), ext.end());
    Bytes hs; p8(hs, 0x01); p24(hs, (unsigned)body.size()); hs.insert(hs.end(), body.begin(), body.end());
    out.clear(); p8(out, 0x16); p16(out, 0x0301); p16(out, (unsigned)hs.size()); out.insert(out.end(), hs.begin(), hs.end());
}

enum TestResult { TEST_OK, TEST_BLOCKED, TEST_NODNS, TEST_NOCONN };

static SOCKET connectTO(const char* host, const char* port, struct addrinfo** r) {
    *r = NULL; struct addrinfo h; memset(&h, 0, sizeof(h));
    h.ai_family = AF_INET; h.ai_socktype = SOCK_STREAM; h.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(host, port, &h, r) != 0 || !*r) return INVALID_SOCKET;
    SOCKET s = socket((*r)->ai_family, (*r)->ai_socktype, (*r)->ai_protocol);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb); connect(s, (*r)->ai_addr, (int)(*r)->ai_addrlen);
    fd_set w, e; FD_ZERO(&w); FD_SET(s, &w); FD_ZERO(&e); FD_SET(s, &e);
    timeval tv; tv.tv_sec = AUTO_TEST_TIMEOUT / 1000; tv.tv_usec = (AUTO_TEST_TIMEOUT % 1000) * 1000;
    int sel = select(0, NULL, &w, &e, &tv);
    if (sel <= 0 || FD_ISSET(s, &e)) { closesocket(s); return INVALID_SOCKET; }
    int err = 0, el = sizeof(err); getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &el);
    if (err != 0) { closesocket(s); return INVALID_SOCKET; }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    DWORD rt = AUTO_TEST_TIMEOUT; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&rt, sizeof(rt));
    return s;
}
// The TLS answer is the only thing that counts: a plain-HTTP reply (or an ISP block page) must not mask a TLS block.
static TestResult testTls(const char* host) {
    size_t hl = strlen(host); if (hl == 0 || hl > 200) return TEST_NODNS;
    struct addrinfo* r = NULL; SOCKET s = connectTO(host, "443", &r);
    if (s == INVALID_SOCKET) { if (r) { freeaddrinfo(r); return TEST_NOCONN; } return TEST_NODNS; }
    Bytes hello; buildClientHello(host, hello);
    if (send(s, (const char*)&hello[0], (int)hello.size(), 0) != (int)hello.size()) { closesocket(s); freeaddrinfo(r); return TEST_BLOCKED; }
    unsigned char resp[8]; int n = recv(s, (char*)resp, sizeof(resp), 0);
    closesocket(s); freeaddrinfo(r);
    if (n >= 3 && (resp[0] == 0x16 || resp[0] == 0x15) && resp[1] == 0x03) return TEST_OK;
    return TEST_BLOCKED;
}

struct TJob { std::string host; TestResult r; };
static DWORD WINAPI tjobThread(LPVOID p) { TJob* j = (TJob*)p; j->r = testTls(j->host.c_str()); return 0; }
static void testMany(std::vector<TJob>& jobs) {
    std::vector<HANDLE> th;
    for (size_t i = 0; i < jobs.size(); i++) {
        jobs[i].r = TEST_NOCONN;
        HANDLE h = CreateThread(NULL, 0, tjobThread, &jobs[i], 0, NULL);
        if (h) th.push_back(h); else jobs[i].r = testTls(jobs[i].host.c_str());
    }
    if (!th.empty()) WaitForMultipleObjects((DWORD)th.size(), &th[0], TRUE, INFINITE);
    for (size_t i = 0; i < th.size(); i++) CloseHandle(th[i]);
}

// Finds a strategy for ONE domain and remembers it; the global strategy and every other site stay untouched.
static bool fixHost(const std::string& host) {
    Strategy glob = getStrategy();
    if (glob >= STRAT_BYPASS_COUNT) return false;
    std::string b = baseDomain(host);
    int had = getHostStrat(b);
    int startS = had >= 0 ? had : (int)glob;
    logLine("SCAN", C_YELLOW, fmt(TR("%s looks blocked, searching a strategy for it...", "%s engelli görünüyor, ona özel strateji aranıyor..."), b.c_str()).c_str());
    for (int step = 1; step <= STRAT_BYPASS_COUNT; step++) {
        if (!isRunning()) break;
        int cand = (startS + step) % STRAT_BYPASS_COUNT;
        setHostStrat(b, cand);
        if (sleepOrStop(120)) break;
        TestResult r = testTls(host.c_str());
        if (r == TEST_OK) {
            if (cand == (int)glob) setHostStrat(b, -1);
            saveHostStrats();
            InterlockedIncrement(&g_stats.hostFixes);
            logLine("FIX", C_GREEN C_BOLD, fmt("%s -> %s", b.c_str(), STRAT_NAMES[cand]).c_str());
            return true;
        }
        if (r != TEST_BLOCKED) break;      // DNS / TCP problem, not something a strategy can fix
    }
    setHostStrat(b, had);
    return false;
}

static std::map<std::string, DWORD> g_nextTry;   // test thread only
static void emergencyRecovery(const char* host) {
    std::string b = baseDomain(host);
    DWORD now = GetTickCount();
    std::map<std::string, DWORD>::const_iterator it = g_nextTry.find(b);
    if (it != g_nextTry.end() && (int)(now - it->second) < 0) return;
    if (g_nextTry.size() > 200) g_nextTry.clear();
    g_nextTry[b] = now + COOLDOWN_MS;
    InterlockedExchange(&g_emergencyRunning, 1);
    TestResult r = testTls(host);
    if (r == TEST_BLOCKED && !fixHost(host)) {
        g_nextTry[b] = GetTickCount() + SAFE_RETRY_MS;
        logLine("FAIL", C_YELLOW, fmt(TR("%s: no strategy helped (IP or DNS block?)", "%s: hiçbir strateji işe yaramadı (IP ya da DNS engeli?)"), b.c_str()).c_str());
    }
    InterlockedExchange(&g_emergencyRunning, 0);
}

static const char* DEFAULT_SITES[] = { "discord.com", "roblox.com", "x.com", "youtube.com", "instagram.com", "reddit.com" };

static void pickTestSites(std::vector<std::string>& out) {
    out.clear(); static size_t cursor = 0;
    std::vector<std::string> base, pool;
    if (!g_blacklist.empty()) {
        for (std::set<std::string>::const_iterator it = g_blacklist.begin(); it != g_blacklist.end(); ++it)
            if (isPlainHost(*it) && !isExcluded(*it)) base.push_back(*it);
    } else {
        for (size_t i = 0; i < sizeof(DEFAULT_SITES) / sizeof(DEFAULT_SITES[0]); i++)
            if (!isExcluded(DEFAULT_SITES[i])) base.push_back(DEFAULT_SITES[i]);
    }
    EnterCriticalSection(&g_seenLock);
    for (size_t i = 0; i < base.size(); i++) if (!g_unfixable.count(base[i])) pool.push_back(base[i]);
    LeaveCriticalSection(&g_seenLock);
    if (pool.empty()) return;
    size_t n = pool.size() < 3 ? pool.size() : 3;
    for (size_t i = 0; i < n; i++) out.push_back(pool[(cursor + i) % pool.size()]);
    cursor += n;
}

static DWORD periodicRound() {
    std::vector<std::string> sites; pickTestSites(sites); if (sites.empty()) return PERIODIC_TEST;
    Strategy cur = getStrategy();
    std::vector<TJob> jobs(sites.size());
    for (size_t i = 0; i < sites.size(); i++) jobs[i].host = sites[i];
    testMany(jobs);
    if (!isRunning()) return PERIODIC_TEST;
    int ok = 0; std::vector<std::string> blocked; std::string line;
    for (size_t i = 0; i < jobs.size(); i++) {
        if (jobs[i].r == TEST_OK) { ok++; line += std::string(C_GREEN) + "√ " + C_RESET + jobs[i].host + "  "; }
        else if (jobs[i].r == TEST_BLOCKED) { blocked.push_back(jobs[i].host); line += std::string(C_RED) + "× " + C_RESET + jobs[i].host + "  "; }
        else line += std::string(C_DIM) + "· " + jobs[i].host + C_RESET + "  ";
        if (jobs[i].r == TEST_OK) { EnterCriticalSection(&g_seenLock); g_unfixable.erase(jobs[i].host); LeaveCriticalSection(&g_seenLock); }
    }
    logLine("TEST", C_BLUE C_BOLD, line.c_str());
    int tested = ok + (int)blocked.size(); if (tested == 0) return PERIODIC_TEST;
    if (blocked.empty()) { InterlockedExchange(&g_consecutiveFails, 0); InterlockedExchange(&g_lastGood, (LONG)cur); return PERIODIC_TEST; }

    int fixed = 0, firstFix = -1;
    for (size_t i = 0; i < blocked.size() && isRunning(); i++) {
        if (fixHost(blocked[i])) { fixed++; if (firstFix < 0) firstFix = (int)effStrategy(blocked[i]); }
        else {
            EnterCriticalSection(&g_seenLock);
            if (g_unfixable.size() > 100) g_unfixable.clear();
            g_unfixable.insert(blocked[i]);
            LeaveCriticalSection(&g_seenLock);
        }
    }
    // most sites needed the same kind of help -> make it the default for sites we have never seen
    if (firstFix >= 0 && firstFix != (int)cur && ok * 100 / tested < SUCCESS_THRESHOLD) {
        setStrategy((Strategy)firstFix); InterlockedExchange(&g_lastGood, (LONG)firstFix);
        logLine("SWAP", C_YELLOW C_BOLD, fmt(TR("Default strategy is now %s", "Varsayılan strateji artık %s"), STRAT_NAMES[firstFix]).c_str());
    }
    if (fixed > 0 || ok > 0) { InterlockedExchange(&g_consecutiveFails, 0); return PERIODIC_TEST; }

    logLine("FAIL", C_YELLOW, TR("Nothing works right now (IP/DNS block or no internet?)", "Şu an hiçbir şey çalışmıyor (IP/DNS engeli ya da internet yok?)"));
    LONG f = InterlockedIncrement(&g_consecutiveFails);
    if (f >= MAX_FAILS) {
        g_safeSince = GetTickCount(); setStrategy(STRAT_DISABLED);
        logLine("SAFE", C_YELLOW C_BOLD, TR("Entered Safe-Mode (retry in 10 min)", "Güvenli moda geçildi (10 dk sonra tekrar denenecek)"));
        InterlockedExchange(&g_consecutiveFails, 0); return PERIODIC_TEST;
    }
    return RETRY_SOON;
}

static DWORD WINAPI testThread(LPVOID) {
    if (!g_autoSwitch) return 0;
    if (sleepOrStop(FIRST_TEST_DELAY)) return 0;
    DWORD interval = PERIODIC_TEST; DWORD last = GetTickCount() - PERIODIC_TEST;
    while (isRunning()) {
        DWORD now = GetTickCount();
        if (getStrategy() == STRAT_DISABLED) {
            if ((now - g_safeSince) >= SAFE_RETRY_MS) {
                setStrategy((Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0));
                logLine("SAFE", C_YELLOW, TR("Safe-Mode expired, retrying", "Güvenli mod bitti, tekrar deneniyor"));
                last = now - PERIODIC_TEST; interval = PERIODIC_TEST;
                InterlockedExchange(&g_emergencyFlag, 0);
                EnterCriticalSection(&g_seenLock); g_unfixable.clear(); LeaveCriticalSection(&g_seenLock);
            }
            if (sleepOrStop(1000)) break;
            continue;
        }
        if (InterlockedCompareExchange(&g_emergencyFlag, 0, 0)) {
            char h[256];
            EnterCriticalSection(&g_emLock); scpy(h, sizeof(h), g_emergencyHost); InterlockedExchange(&g_emergencyFlag, 0); LeaveCriticalSection(&g_emLock);
            if (h[0]) emergencyRecovery(h);
        }
        if (InterlockedExchange(&g_forceTest, 0)) last = GetTickCount() - interval;
        now = GetTickCount();
        if ((now - last) >= interval) {
            InterlockedExchange(&g_emergencyRunning, 1); interval = periodicRound(); InterlockedExchange(&g_emergencyRunning, 0);
            last = GetTickCount();
        }
        if (sleepOrStop(250)) break;
    }
    return 0;
}

// ================================================================ DNS over HTTPS
struct DnsJob { std::vector<unsigned char> pkt; WINDIVERT_ADDRESS addr; UINT hdrLen; bool v6; };

static bool parseDnsName(const UINT8* d, UINT len, std::string& name) {
    name.clear(); UINT pos = 12;
    while (pos < len) {
        UINT l = d[pos]; if (l == 0) { pos++; break; } if (l & 0xC0) return false; if (pos + 1 + l > len) return false;
        if (!name.empty()) name += '.'; name.append((const char*)&d[pos + 1], l); pos += 1 + l; if (name.size() > 253) return false;
    }
    if (pos + 4 > len) return false; name = lower(name); return !name.empty();
}
static bool shouldInterceptDns(const std::string& name) {
    if (g_dnsMode == DNS_OFF) return false;
    if (g_dnsMode == DNS_FAST && !g_blacklist.empty()) return isBlacklisted(name);
    if (name.find('.') == std::string::npos) return false;
    static const char* skip[] = { ".local",".lan",".home",".internal",".localdomain",".arpa",".corp",".intranet",".private" };
    for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++) if (endsWith(name, skip[i])) return false;
    return true;
}
static bool dohAvailable() {
    if (!InterlockedCompareExchange(&g_dohPaused, 0, 0)) return true;
    DWORD until = (DWORD)InterlockedCompareExchange(&g_dohPausedUntil, 0, 0);
    if ((int)(GetTickCount() - until) >= 0) {
        InterlockedExchange(&g_dohPaused, 0); InterlockedExchange(&g_dohFail, 0);
        logLine("DNS", C_GREEN, TR("DoH active again", "DoH tekrar devrede"));
        return true;
    }
    return false;
}
// remember the addresses of blacklisted names so QUIC is only dropped for them
static void harvestIps(const std::vector<unsigned char>& r) {
    if (r.size() < 12) return;
    UINT qd = ((UINT)r[4] << 8) | r[5], an = ((UINT)r[6] << 8) | r[7];
    size_t p = 12;
    for (UINT i = 0; i <= qd + an; i++) {
        if (i == qd + an) break;
        while (p < r.size()) {
            UINT l = r[p];
            if (l == 0) { p++; break; }
            if ((l & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + l;
        }
        if (i < qd) { p += 4; continue; }
        if (p + 10 > r.size()) return;
        UINT type = ((UINT)r[p] << 8) | r[p + 1], rdl = ((UINT)r[p + 8] << 8) | r[p + 9];
        p += 10;
        if (p + rdl > r.size()) return;
        IpKey k; bool got = false;
        if (type == 1 && rdl == 4) { UINT32 v; memcpy(&v, &r[p], 4); k = keyV4(v); got = true; }
        else if (type == 28 && rdl == 16) { memcpy(k.a, &r[p], 16); got = true; }
        if (got) {
            EnterCriticalSection(&g_ipLock);
            if (g_blkIps.size() > 4096) g_blkIps.clear();
            g_blkIps.insert(k);
            LeaveCriticalSection(&g_ipLock);
        }
        p += rdl;
    }
}
struct DohClient { HINTERNET session; HINTERNET conn[DOH_MAX_COUNT]; };
static void dohInit(DohClient& c) {
    c.session = WinHttpOpen(L"DPIHunter", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (c.session) WinHttpSetTimeouts(c.session, DOH_TIMEOUT_MS, DOH_TIMEOUT_MS, DOH_TIMEOUT_MS, DOH_TIMEOUT_MS);
    for (int i = 0; i < DOH_MAX_COUNT; i++) c.conn[i] = NULL;
}
static void dohClose(DohClient& c) {
    for (int i = 0; i < DOH_MAX_COUNT; i++) if (c.conn[i]) { WinHttpCloseHandle(c.conn[i]); c.conn[i] = NULL; }
    if (c.session) { WinHttpCloseHandle(c.session); c.session = NULL; }
}
static bool dohQuery(DohClient& c, int prov, const unsigned char* q, DWORD ql, std::vector<unsigned char>& resp) {
    if (!c.session || DOH[prov].host.empty()) return false;
    if (!c.conn[prov]) { c.conn[prov] = WinHttpConnect(c.session, DOH[prov].host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0); if (!c.conn[prov]) return false; }
    HINTERNET rq = WinHttpOpenRequest(c.conn[prov], L"POST", DOH[prov].path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!rq) { WinHttpCloseHandle(c.conn[prov]); c.conn[prov] = NULL; return false; }
    bool ok = false; resp.clear();
    const wchar_t* hdr = L"Content-Type: application/dns-message\r\nAccept: application/dns-message";
    if (WinHttpSendRequest(rq, hdr, (DWORD)-1L, (LPVOID)q, ql, ql, 0) && WinHttpReceiveResponse(rq, NULL)) {
        DWORD st = 0, sz = sizeof(st);
        if (WinHttpQueryHeaders(rq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz, WINHTTP_NO_HEADER_INDEX) && st == 200) {
            for (;;) {
                DWORD av = 0; if (!WinHttpQueryDataAvailable(rq, &av)) break;
                if (av == 0) { ok = true; break; } if (resp.size() + av > 16384) break;
                size_t old = resp.size(); resp.resize(old + av);
                DWORD got = 0; if (!WinHttpReadData(rq, &resp[old], av, &got)) break;
                resp.resize(old + got);
            }
        }
    }
    WinHttpCloseHandle(rq);
    if (!ok) { WinHttpCloseHandle(c.conn[prov]); c.conn[prov] = NULL; resp.clear(); return false; }
    return resp.size() >= 12;
}
static void makeTrunc(std::vector<unsigned char>& r) {
    size_t p = 12; while (p < r.size() && r[p] != 0) { if (r[p] & 0xC0) break; p += (size_t)r[p] + 1; }
    p += 5; if (p > r.size()) p = r.size(); r.resize(p); r[2] |= 0x02; for (int i = 6; i < 12; i++) r[i] = 0;
}
static bool sendDnsReply(const DnsJob& j, const unsigned char* dns, UINT dl) {
    UINT hl = j.hdrLen; if (hl < 28 || hl + dl > MAXBUF) return false;
    std::vector<unsigned char> buf(hl + dl); unsigned char* b = &buf[0];
    memcpy(b, &j.pkt[0], hl); memcpy(b + hl, dns, dl);
    WINDIVERT_ADDRESS a = j.addr; a.Outbound = 0;
    PWINDIVERT_UDPHDR u = (PWINDIVERT_UDPHDR)(b + hl - 8);
    if (j.v6) { PWINDIVERT_IPV6HDR h = (PWINDIVERT_IPV6HDR)b; for (int i = 0; i < 4; i++) { UINT32 t = h->SrcAddr[i]; h->SrcAddr[i] = h->DstAddr[i]; h->DstAddr[i] = t; } h->Length = htons((UINT16)(hl - 40 + dl)); h->HopLimit = 64; }
    else { PWINDIVERT_IPHDR h = (PWINDIVERT_IPHDR)b; UINT32 t = h->SrcAddr; h->SrcAddr = h->DstAddr; h->DstAddr = t; h->Length = htons((UINT16)(hl + dl)); h->TTL = 64; }
    USHORT sp = u->SrcPort; u->SrcPort = u->DstPort; u->DstPort = sp; u->Length = htons((UINT16)(8 + dl));
    WinDivertHelperCalcChecksums(b, hl + dl, &a, 0);
    return WinDivertSend(g_handle, b, hl + dl, NULL, &a) != FALSE;
}
static void processDnsJob(DohClient& c, DnsJob& j) {
    const unsigned char* q = &j.pkt[j.hdrLen]; DWORD ql = (DWORD)(j.pkt.size() - j.hdrLen);
    std::vector<unsigned char> resp; bool ok = false;
    int start = (int)InterlockedCompareExchange(&g_dohPref, 0, 0);
    if (start < 0 || start >= DOH_MAX_COUNT) start = 0;
    for (int t = 0; t < 3 && !ok && isRunning(); t++) {
        int prov = (start + t * 2) % DOH_MAX_COUNT;
        if (DOH[prov].host.empty()) continue;
        if (dohQuery(c, prov, q, ql, resp) && (resp[2] & 0x80)) {
            ok = true;
            if (t == 0) InterlockedExchange(&g_dohPrefFail, 0);
            else if (InterlockedIncrement(&g_dohPrefFail) >= 3) {
                // the chosen provider failed three times in a row: only now move on, and say so
                InterlockedExchange(&g_dohPref, prov); InterlockedExchange(&g_dohPrefFail, 0);
                logLine("DNS", C_YELLOW, fmt(TR("%s keeps failing, switched to %s", "%s cevap vermiyor, %s kullanılıyor"), DOH[start].name.c_str(), DOH[prov].name.c_str()).c_str());
            }
        }
    }
    if (ok) {
        if (!g_blacklist.empty()) { std::string nm; if (parseDnsName(q, ql, nm) && isBlacklisted(nm)) harvestIps(resp); }
        resp[0] = q[0]; resp[1] = q[1];
        size_t lim = (q[10] | q[11]) ? 1232 : 512;
        if (resp.size() > lim) makeTrunc(resp);
        if (sendDnsReply(j, &resp[0], (UINT)resp.size())) { InterlockedIncrement(&g_stats.dnsDoh); InterlockedExchange(&g_dohFail, 0); return; }
    }
    LONG f = InterlockedIncrement(&g_dohFail);
    if (f >= DNS_FAIL_LIMIT) {
        InterlockedExchange(&g_dohPausedUntil, (LONG)(GetTickCount() + DNS_PAUSE_MS));
        if (InterlockedCompareExchange(&g_dohPaused, 1, 0) == 0)
            logLine("DNS", C_YELLOW, TR("DoH unreachable, normal DNS for 5 min", "DoH'a ulaşılamıyor, 5 dk normal DNS"));
    }
    InterlockedIncrement(&g_stats.dnsFallback);
    WinDivertSend(g_handle, &j.pkt[0], (UINT)j.pkt.size(), NULL, &j.addr);
}
static DWORD WINAPI dnsWorker(LPVOID) {
    DohClient c; dohInit(c); HANDLE waits[2] = { g_dnsSem, g_stopEvent };
    while (isRunning()) {
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE); if (w != WAIT_OBJECT_0) break;
        DnsJob* j = NULL; EnterCriticalSection(&g_dnsLock); if (!g_dnsQueue.empty()) { j = g_dnsQueue.front(); g_dnsQueue.pop_front(); } LeaveCriticalSection(&g_dnsLock);
        if (!j) continue; processDnsJob(c, *j); delete j;
    }
    dohClose(c); return 0;
}
static void handleDns(UINT pl, const WINDIVERT_ADDRESS* addr, PWINDIVERT_IPHDR ip, PWINDIVERT_IPV6HDR ip6, PVOID payload, UINT payloadLen) {
    bool icept = false;
    if (g_dnsEnabled && payload && payloadLen >= 17 && dohAvailable()) {
        const UINT8* d = (const UINT8*)payload;
        bool loop = false;
        if (ip) loop = (((const UINT8*)&ip->DstAddr)[0] == 127);
        else if (ip6) loop = (ip6->DstAddr[0] == 0 && ip6->DstAddr[1] == 0 && ip6->DstAddr[2] == 0 && ip6->DstAddr[3] == htonl(1));
        std::string name;
        if (!loop && (d[2] & 0x80) == 0 && ((d[2] >> 3) & 0x0F) == 0 && d[4] == 0 && d[5] == 1 && parseDnsName(d, payloadLen, name) && shouldInterceptDns(name)) icept = true;
    }
    if (icept) {
        DnsJob* j = new DnsJob; j->pkt.assign(g_packet, g_packet + pl); j->addr = *addr; j->hdrLen = (UINT)((UINT8*)payload - g_packet); j->v6 = (ip6 != NULL);
        EnterCriticalSection(&g_dnsLock); bool full = g_dnsQueue.size() >= (size_t)DNS_QUEUE_MAX; if (!full) g_dnsQueue.push_back(j); LeaveCriticalSection(&g_dnsLock);
        if (!full) { ReleaseSemaphore(g_dnsSem, 1, NULL); return; } delete j;
    }
    WinDivertSend(g_handle, g_packet, pl, NULL, addr); InterlockedIncrement(&g_stats.passed);
}
// poisoned answers cached before we started would otherwise survive for hours
static void flushDnsCache() {
    HMODULE m = LoadLibraryA("dnsapi.dll");
    if (!m) return;
    typedef BOOL(WINAPI* FlushFn)(void);
    FlushFn f = (FlushFn)(void*)GetProcAddress(m, "DnsFlushResolverCache");
    if (f) f();
    FreeLibrary(m);
}

// ================================================================ runtime threads
static volatile LONG g_quitReq = 0;

static DWORD WINAPI uiThread(LPVOID) {
    DWORD lastDraw = 0, lastSample = GetTickCount();
    LONG lastTotal = g_stats.total;
    while (isRunning()) {
        while (_kbhit()) {
            int k = getKey();
            if (k == 'q' || k == 'Q') { InterlockedExchange(&g_quitReq, 1); requestStop(); }
            else if (k == 'm' || k == 'M' || k == K_ESC) { InterlockedExchange(&g_backToMenu, 1); requestStop(); }
            else if ((k == 't' || k == 'T') && g_autoSwitch) {
                InterlockedExchange(&g_forceTest, 1);
                logLine("TEST", C_BLUE, TR("Test requested", "Test istendi"));
            }
            else if ((k == 's' || k == 'S') && !g_analyzeMode) {
                Strategy c = getStrategy();
                Strategy n = (c >= STRAT_BYPASS_COUNT) ? S_SPLIT2 : (Strategy)((c + 1) % STRAT_BYPASS_COUNT);
                setStrategy(n); InterlockedExchange(&g_lastGood, (LONG)n);
                logLine("SWAP", C_YELLOW, fmt(TR("Strategy set by hand: %s", "Strateji elle değiştirildi: %s"), STRAT_NAMES[n]).c_str());
                lastDraw = 0;
            }
        }
        DWORD now = GetTickCount();
        if (now - lastSample >= 1000) {
            LONG t = g_stats.total;
            memmove(g_spark, g_spark + 1, sizeof(int) * (SPARK_N - 1));
            g_spark[SPARK_N - 1] = (int)(t - lastTotal);
            lastTotal = t; lastSample = now;
        }
        if (now - lastDraw >= 500) { dashRefresh(); lastDraw = now; }
        if (sleepOrStop(80)) break;
    }
    return 0;
}

static std::string buildFilter(const std::vector<int>& ports, bool dns) {
    std::string dst, src;
    for (size_t i = 0; i < ports.size(); i++) {
        if (i) { dst += " or "; src += " or "; }
        dst += "tcp.DstPort == " + std::to_string(ports[i]); src += "tcp.SrcPort == " + std::to_string(ports[i]);
    }
    std::string f = "(outbound and !loopback and tcp and tcp.PayloadLength > 0 and (" + dst + ")";
    // without deep tracking only packets that start a TLS hello or an HTTP request are needed
    if (!g_deep) f += " and tcp.PayloadLength >= 6 and ((tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01) or (tcp.Payload[0] >= 0x41 and tcp.Payload[0] <= 0x5A))";
    f += ")";
    if (g_quicMode != QUIC_PASS)
        f += " or (outbound and !loopback and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0)";
    f += " or (inbound and tcp and tcp.Rst and (" + src + "))";
    f += " or (inbound and tcp and tcp.Syn and tcp.Ack and (" + src + "))";
    if (dns) f += " or (outbound and udp and udp.DstPort == 53 and udp.PayloadLength > 0)";
    if (g_game && !g_udpRanges.empty()) {
        std::string r;
        for (size_t i = 0; i < g_udpRanges.size(); i++) {
            if (i) r += " or ";
            r += "(udp.DstPort >= " + std::to_string(g_udpRanges[i].a) + " and udp.DstPort <= " + std::to_string(g_udpRanges[i].b) + ")";
        }
        f += " or (outbound and !loopback and udp and udp.PayloadLength > 0 and (" + r + "))";
    }
    return f;
}

static const char* explainOpen(DWORD e) {
    switch (e) {
    case 2: return TR("WinDivert64.sys not found (keep it next to the .exe)", "WinDivert64.sys bulunamadı (.exe'nin yanında dursun)");
    case 5: return TR("access denied (run as administrator)", "erişim reddedildi (yönetici olarak çalıştır)");
    case 87: return TR("invalid filter / WinDivert.dll and .sys versions differ", "geçersiz filtre / WinDivert.dll ile .sys sürümü uyuşmuyor");
    case 577: return TR("driver signature rejected", "sürücü imzası reddedildi");
    case 654: return TR("incompatible driver version (another WinDivert tool running?)", "uyumsuz sürücü sürümü (başka bir WinDivert aracı mı açık?)");
    case 1275: return TR("driver blocked (Defender / Memory Integrity)", "sürücü engellendi (Defender / Bellek Bütünlüğü)");
    default: return TR("check WinDivert.dll / WinDivert64.sys", "WinDivert.dll / WinDivert64.sys dosyalarını kontrol et");
    }
}

static void askAnalyzeSites() {
    g_analyzeSites.clear();
    clearScreen();
    P("\n  %s%s%s\n  %s%s%s\n\n  %s> %s", C_BOLD C_WHITE, TR("ANALYZE", "ANALİZ"), C_RESET, C_DIM,
        TR("Sites to test, comma separated. Just press Enter for the default list.", "Test edilecek siteler, virgülle ayır. Varsayılan liste için sadece Enter'a bas."),
        C_RESET, C_YELLOW, C_RESET);
    std::string s; if (!readLine(s)) return;
    s = trim(s); size_t pos = 0;
    while (pos < s.size() && g_analyzeSites.size() < 6) {
        size_t next = s.find(',', pos);
        std::string site = lower(trim(s.substr(pos, next == std::string::npos ? std::string::npos : next - pos)));
        size_t p = site.find("://"); if (p != std::string::npos) site = site.substr(p + 3);
        p = site.find('/');          if (p != std::string::npos) site = site.substr(0, p);
        if (isPlainHost(site)) g_analyzeSites.push_back(site);
        if (next == std::string::npos) break;
        pos = next + 1;
    }
}

// Tests every strategy against all sites in parallel, keeps the best one active and saves it.
static DWORD WINAPI analyzeThread(LPVOID) {
    if (sleepOrStop(1200)) return 0;
    std::vector<std::string> sites = g_analyzeSites;
    if (sites.empty()) for (size_t i = 0; i < sizeof(DEFAULT_SITES) / sizeof(DEFAULT_SITES[0]); i++) sites.push_back(DEFAULT_SITES[i]);
    const int nS = (int)sites.size();
    {
        std::string hd = fmt("  %s%-15s", C_BOLD C_WHITE, TR("Strategy", "Strateji"));
        for (int i = 0; i < nS; i++) hd += fmt(" %-13.13s", sites[(size_t)i].c_str());
        EnterCriticalSection(&g_consoleLock); P("%s%s\n", hd.c_str(), C_RESET); LeaveCriticalSection(&g_consoleLock);
    }
    Strategy orig = getStrategy();
    int best = -1, bestOk = 0;
    for (int s = 0; s < STRAT_BYPASS_COUNT; s++) {
        if (!isRunning()) return 0;
        setStrategy((Strategy)s); if (sleepOrStop(250)) return 0;
        std::vector<TJob> jobs((size_t)nS);
        for (int i = 0; i < nS; i++) jobs[(size_t)i].host = sites[(size_t)i];
        testMany(jobs);
        int ok = 0; std::string row = fmt("  %s%-15s%s", C_CYAN, STRAT_NAMES[s], C_RESET), plain;
        for (int i = 0; i < nS; i++) {
            TestResult r = jobs[(size_t)i].r;
            if (r == TEST_OK) { row += fmt(" %s%-13s%s", C_GREEN, "OK", C_RESET); ok++; plain += " OK"; }
            else if (r == TEST_BLOCKED) { row += fmt(" %s%-13s%s", C_RED, "FAIL", C_RESET); plain += " FAIL"; }
            else { row += fmt(" %s%-13s%s", C_DIM, "-", C_RESET); plain += " -"; }
        }
        if (ok > bestOk) { bestOk = ok; best = s; }
        if (ok == nS) row += fmt(" %s◄%s", C_GREEN, C_RESET);
        EnterCriticalSection(&g_consoleLock); P("%s\n", row.c_str()); LeaveCriticalSection(&g_consoleLock);
        logFile("ANLZ", (std::string(STRAT_NAMES[s]) + plain).c_str());
    }
    if (best >= 0) {
        setStrategy((Strategy)best); InterlockedExchange(&g_lastGood, (LONG)best); saveLastStrategy();
        logLine("BEST", C_GREEN C_BOLD, fmt(TR("%s (%d/%d sites) - saved, AUTO will start with it. It is active now, try your sites.",
            "%s (%d/%d site) - kaydedildi, OTOMATİK bununla başlayacak. Şu an devrede, sitelerini deneyebilirsin."), STRAT_NAMES[best], bestOk, nS).c_str());
    } else {
        setStrategy(orig);
        logLine("FAIL", C_YELLOW, TR("No strategy worked (IP/DNS block, or no internet?)", "Hiçbir strateji çalışmadı (IP/DNS engeli ya da internet yok?)"));
    }
    logLine("INFO", C_DIM, TR("Press M to return to the menu", "Menüye dönmek için M'ye bas"));
    return 0;
}

static DWORD WINAPI dnsSelfTestThread(LPVOID) {
    if (sleepOrStop(2000)) return 0;
    std::string base = "example.com";
    for (std::set<std::string>::const_iterator it = g_blacklist.begin(); it != g_blacklist.end(); ++it)
        if (isPlainHost(*it)) { base = *it; break; }
    std::string name = fmt("dpih%lu.%s", (unsigned long)GetTickCount(), base.c_str());
    LONG before = g_stats.dnsDoh;
    struct addrinfo hints; memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL; getaddrinfo(name.c_str(), "80", &hints, &res); if (res) freeaddrinfo(res);
    Sleep(300);
    if (g_stats.dnsDoh > before) logLine("DNS", C_GREEN, TR("Self-test OK: queries are answered via DoH", "Öz-test tamam: sorgular DoH üzerinden cevaplanıyor"));
    else logLine("DNS", C_YELLOW, TR("Self-test: query NOT intercepted (VPN, browser DoH or custom DNS?)", "Öz-test: sorgu yakalanamadı (VPN, tarayıcı DoH'u ya da özel DNS?)"));
    return 0;
}

// ================================================================ packet loop
static inline void passPkt(UINT pl, const WINDIVERT_ADDRESS* a) {
    WinDivertSend(g_handle, g_packet, pl, NULL, a); InterlockedIncrement(&g_stats.passed);
}

static void processPacket(UINT pl, WINDIVERT_ADDRESS& addr) {
    PWINDIVERT_IPHDR ip = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_TCPHDR tcp = NULL; PWINDIVERT_UDPHDR udp = NULL;
    PVOID payload = NULL; UINT payloadLen = 0;
    if (!WinDivertHelperParsePacket(g_packet, pl, &ip, &ip6, NULL, NULL, NULL, &tcp, &udp, &payload, &payloadLen, NULL, NULL) || (!ip && !ip6)) {
        WinDivertSend(g_handle, g_packet, pl, NULL, &addr); return;
    }

    if (!addr.Outbound) {
        if (tcp && tcp->Syn && tcp->Ack) {
            IpKey sk = ip ? keyV4(ip->SrcAddr) : keyV6(ip6->SrcAddr);
            int ttlSeen = ip ? (int)ip->TTL : (int)ip6->HopLimit;
            int initTtl = ttlSeen <= 64 ? 64 : (ttlSeen <= 128 ? 128 : 255);
            int hops = initTtl - ttlSeen;
            if (hops >= 1 && hops <= 40) { HopEntry& he = g_hops[keyHash(sk) >> 24]; he.key = sk; he.hops = (BYTE)hops; }
        }
        else if (tcp && tcp->Rst) {
            IpKey k = ip ? keyV4(ip->SrcAddr) : keyV6(ip6->SrcAddr);
            std::string h = matchRst(k, ntohs(tcp->SrcPort), ntohs(tcp->DstPort));
            if (!h.empty()) {
                if (g_blockPassive && ip && ntohs(ip->Id) <= 1) { InterlockedIncrement(&g_stats.passiveDropped); return; }
                noteSignal(h);
            }
        }
        WinDivertSend(g_handle, g_packet, pl, NULL, &addr);
        return;
    }

    InterlockedIncrement(&g_stats.total);
    const Strategy glob = getStrategy();
    const bool v6 = (ip6 != NULL);
    const IpKey dk = ip ? keyV4(ip->DstAddr) : keyV6(ip6->DstAddr);

    if (udp) {
        USHORT dp = ntohs(udp->DstPort);
        if (dp == 53) { handleDns(pl, &addr, ip, ip6, payload, payloadLen); return; }
        if (glob != STRAT_DISABLED && payload && payloadLen > 0 && !isLocalDst(ip, ip6)) {
            UINT hdr = (UINT)((UINT8*)payload - g_packet);
            if (dp == 443) {
                if (g_quicMode != QUIC_PASS && isQuic(payload, payloadLen)) {
                    bool target = true;
                    if (!g_blacklist.empty() && g_dnsEnabled) {
                        EnterCriticalSection(&g_ipLock);
                        if (!g_blkIps.empty()) target = g_blkIps.count(dk) > 0;
                        LeaveCriticalSection(&g_ipLock);
                    }
                    if (target) {
                        if (g_quicMode == QUIC_DROP) { InterlockedIncrement(&g_stats.quicBlocked); return; }
                        sendFakeUdp(g_packet, hdr, v6, &addr, 620, 0x40, g_fakeRepeats);
                        InterlockedIncrement(&g_stats.quicFaked);
                    }
                }
            }
            else if (g_game && udpInRange(dp)) {
                USHORT sp = ntohs(udp->SrcPort);
                DWORD now = GetTickCount();
                UFlow& f = g_uflow[(keyHash(dk) ^ ((unsigned)dp * 31u) ^ ((unsigned)sp * 131u)) % UFLOW_MAX];
                if (f.dport == dp && f.sport == sp && keyEq(f.key, dk) && (now - f.tick) < 30000) { if (f.cnt < 255) f.cnt++; }
                else { f.key = dk; f.dport = dp; f.sport = sp; f.cnt = 1; }
                f.tick = now;
                if (f.cnt <= UDP_FAKE_PACKETS) {
                    sendFakeUdp(g_packet, hdr, v6, &addr, 64, 0x00, imax(2, g_fakeRepeats));
                    InterlockedIncrement(&g_stats.udpFaked);
                }
            }
        }
        passPkt(pl, &addr);
        return;
    }

    if (!tcp || !payload || payloadLen == 0 || glob == STRAT_DISABLED || isLocalDst(ip, ip6)) { passPkt(pl, &addr); return; }

    UINT8* pp = (UINT8*)payload;
    const USHORT sport = ntohs(tcp->SrcPort), dport = ntohs(tcp->DstPort);
    const UINT32 seq = ntohl(tcp->SeqNum);
    const bool isTls = (payloadLen >= 6 && pp[0] == 0x16 && pp[5] == 0x01);
    const bool isHttp = (!isTls && g_httpEnabled && isHttpRequest(pp, payloadLen));
    char* hostPtr = NULL; unsigned int hostLen = 0;

    if (isTls) {
        if (!extractSni((char*)pp, payloadLen, &hostPtr, &hostLen)) {
            hostPtr = NULL;
            UINT recLen = ((UINT)pp[3] << 8) | pp[4];
            if (recLen + 5 > payloadLen && g_deep) {
                // the hello continues in the next segment and the name is probably there
                pendAdd(dk, sport, dport, seq + payloadLen);
                if (!g_blacklist.empty() || !g_exclude.empty()) { passPkt(pl, &addr); return; }
            }
        }
    }
    else if (isHttp) {
        if (!extractHttpHost((const char*)pp, payloadLen, &hostPtr, &hostLen)) { passPkt(pl, &addr); return; }
    }
    else {
        Pend* pd = pendFind(dk, sport, dport, seq);
        if (!pd) { passPkt(pl, &addr); return; }
        if (extractSni((char*)pp, payloadLen, &hostPtr, &hostLen)) { pd->used = false; g_pendCount--; }
        else { pd->nextSeq = seq + payloadLen; passPkt(pl, &addr); return; }
    }

    const bool hasHost = (hostPtr != NULL);
    std::string host;
    if (hasHost) {
        host = lower(std::string(hostPtr, hostLen));
        if (isExcluded(host) || !isBlacklisted(host)) { passPkt(pl, &addr); return; }
        if (noteHello(dk, dport, sport, seq, host.c_str())) noteSignal(host);
    }

    Ctx c;
    c.pkt = g_packet; c.len = pl; c.addr = &addr; c.v6 = v6;
    c.tcpOff = (UINT)((UINT8*)tcp - g_packet); c.hdrLen = (UINT)(pp - g_packet); c.plLen = payloadLen;
    c.ttl = autoTtl(dk, g_fakeTtl);
    if (c.hdrLen + c.plLen > pl) { passPkt(pl, &addr); return; }
    applyStrategy(c, effStrategy(host), hasHost, hasHost ? (UINT)((UINT8*)hostPtr - pp) : 0, hostLen);
}

static int runTool(const Settings& st, RunMode mode) {
    InterlockedExchange(&g_running, TRUE);
    if (g_stopEvent) ResetEvent(g_stopEvent);
    if (g_doneEvent) ResetEvent(g_doneEvent);
    InterlockedExchange(&g_emergencyFlag, 0); InterlockedExchange(&g_emergencyRunning, 0);
    InterlockedExchange(&g_consecutiveFails, 0); InterlockedExchange(&g_dohPaused, 0);
    InterlockedExchange(&g_dohFail, 0); InterlockedExchange(&g_dohPrefFail, 0);
    InterlockedExchange(&g_backToMenu, 0); InterlockedExchange(&g_quitReq, 0); InterlockedExchange(&g_forceTest, 0);
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_recent, 0, sizeof(g_recent)); memset(g_pend, 0, sizeof(g_pend)); g_pendCount = 0;
    memset(g_uflow, 0, sizeof(g_uflow)); memset(g_hops, 0, sizeof(g_hops));
    g_sig.clear(); g_nextTry.clear();
    EnterCriticalSection(&g_seenLock); g_unfixable.clear(); LeaveCriticalSection(&g_seenLock);
    EnterCriticalSection(&g_ipLock); g_blkIps.clear(); LeaveCriticalSection(&g_ipLock);
    EnterCriticalSection(&g_dnsLock);
    while (!g_dnsQueue.empty()) { delete g_dnsQueue.front(); g_dnsQueue.pop_front(); }
    LeaveCriticalSection(&g_dnsLock);
    if (getStrategy() == STRAT_DISABLED) setStrategy((Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0));

    g_blacklist.clear(); g_exclude.clear();
    {
        const char* names[] = { "blacklist.txt", "listem.txt", "list.txt" };
        for (int i = 0; i < 3; i++) if (fileExists(names[i])) { loadHostList(names[i], g_blacklist); break; }
        loadHostList("exclude.txt", g_exclude);
        g_lblList = g_blacklist.empty() ? std::string(TR("all sites", "tüm siteler")) : fmt("%d", (int)g_blacklist.size());
        if (!g_exclude.empty()) g_lblList += fmt(" (-%d)", (int)g_exclude.size());
    }
    if (mode == RUN_AUTO) loadHostStrats();
    g_lblMode = mode == RUN_AUTO ? TR("AUTO", "OTOMATİK") : mode == RUN_MANUAL ? TR("MANUAL", "MANUEL") : TR("ANALYZE", "ANALİZ");

    // DNS choice lives in locals: a failed measurement must not rewrite the user's settings
    DnsMode dnsMode = st.dnsMode; int prov = st.dohProvider;
    if (prov < 0 || prov >= DOH_MAX_COUNT || DOH[prov].host.empty()) prov = 0;
    clearScreen();
    if (dnsMode != DNS_OFF && st.dohAuto && !g_dohForced) {
        P("\n  %s%s%s\n", C_CYAN, TR("Measuring DoH latency...", "DoH gecikmesi ölçülüyor..."), C_RESET);
        std::vector<DnsTestResult> results;
        int rec = runDnsTests(results);
        if (rec >= 0) prov = rec;
        else { dnsMode = DNS_OFF; P("  %s%s%s\n", C_YELLOW, TR("No DoH server reachable, using normal DNS this time.", "Hiçbir DoH sunucusuna ulaşılamadı, bu sefer normal DNS."), C_RESET); Sleep(1200); }
    }
    g_dnsMode = dnsMode;
    g_dnsEnabled = (dnsMode != DNS_OFF);
    InterlockedExchange(&g_dohPref, prov);
    g_lblDns = g_dnsEnabled ? fmt("DoH · %s", DOH[prov].name.c_str()) : std::string(onoff(false));
    if (g_dnsEnabled) flushDnsCache();

    std::string filter = buildFilter(st.ports, g_dnsEnabled);
    g_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_handle == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        P("\n  %s%s %lu%s\n  %s%s%s\n", C_RED, TR("WinDivert could not be opened. Error:", "WinDivert açılamadı. Hata:"), (unsigned long)e, C_RESET, C_YELLOW, explainOpen(e), C_RESET);
        P("\n  %s\n    - %s\n    - %s\n    - %s\n    - %s\n", TR("Things to check:", "Kontrol et:"),
            TR("Run as administrator", "Yönetici olarak çalıştır"),
            TR("WinDivert.dll + WinDivert64.sys next to the .exe", "WinDivert.dll + WinDivert64.sys .exe'nin yanında olsun"),
            TR("Close GoodbyeDPI / zapret / other WinDivert tools", "GoodbyeDPI / zapret / diğer WinDivert araçlarını kapat"),
            TR("Add the folder to your antivirus exclusions", "Klasörü antivirüs istisnalarına ekle"));
        return 1;
    }
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_SIZE, 32 * 1024 * 1024);

    g_runStart = GetTickCount();
    InterlockedExchange(&g_inRun, 1);
    dashBegin();
    logFile("START", DISCLAIMER_EN[1]);
    logLine("INFO", C_DIM, DISCLAIMER_SHORT);
    logLine("INFO", C_DIM, fmt("%s: %s", TR("Starting with", "Başlangıç stratejisi"), STRAT_NAMES[getStrategy()]).c_str());

    HANDLE hTest = CreateThread(NULL, 0, InterlockedCompareExchange(&g_analyzeMode, 0, 0) ? analyzeThread : testThread, NULL, 0, NULL);
    HANDLE hUi = CreateThread(NULL, 0, uiThread, NULL, 0, NULL);
    HANDLE hDns[DNS_WORKERS] = { 0 }; int dnsThreads = 0;
    if (g_dnsEnabled) {
        g_dnsSem = CreateSemaphoreA(NULL, 0, 0x7FFFFFFF, NULL);
        if (g_dnsSem) for (int i = 0; i < DNS_WORKERS; i++) { HANDLE h = CreateThread(NULL, 0, dnsWorker, NULL, 0, NULL); if (h) hDns[dnsThreads++] = h; }
        if (dnsThreads == 0) g_dnsEnabled = false;
    }
    HANDLE hSelf = NULL; if (g_dnsEnabled) hSelf = CreateThread(NULL, 0, dnsSelfTestThread, NULL, 0, NULL);

    int recvErr = 0;
    while (isRunning()) {
        UINT pl = 0; WINDIVERT_ADDRESS addr;
        if (!WinDivertRecv(g_handle, g_packet, sizeof(g_packet), &pl, &addr)) {
            DWORD e = GetLastError(); if (e == ERROR_NO_DATA || !isRunning()) break; if (e == ERROR_INSUFFICIENT_BUFFER) continue;
            if (++recvErr > 50) { logLine("ERR", C_RED C_BOLD, fmt("WinDivertRecv error %lu", (unsigned long)e).c_str()); break; }
            Sleep(10); continue;
        }
        recvErr = 0;
        processPacket(pl, addr);
    }

    InterlockedExchange(&g_running, FALSE); if (g_stopEvent) SetEvent(g_stopEvent);
    if (hTest) { WaitForSingleObject(hTest, INFINITE); CloseHandle(hTest); }
    if (hUi) { WaitForSingleObject(hUi, INFINITE); CloseHandle(hUi); }
    if (hSelf) { WaitForSingleObject(hSelf, INFINITE); CloseHandle(hSelf); }
    if (dnsThreads > 0) { WaitForMultipleObjects((DWORD)dnsThreads, hDns, TRUE, INFINITE); for (int i = 0; i < dnsThreads; i++) CloseHandle(hDns[i]); }
    EnterCriticalSection(&g_dnsLock); while (!g_dnsQueue.empty()) { delete g_dnsQueue.front(); g_dnsQueue.pop_front(); } LeaveCriticalSection(&g_dnsLock);
    if (g_dnsSem) { CloseHandle(g_dnsSem); g_dnsSem = NULL; }

    EnterCriticalSection(&g_handleLock); HANDLE h = g_handle; g_handle = INVALID_HANDLE_VALUE; WinDivertClose(h); LeaveCriticalSection(&g_handleLock);
    if (g_autoSwitch) { saveLastStrategy(); saveHostStrats(); }
    logFile("STOP", "stopped");
    dashEnd();
    InterlockedExchange(&g_inRun, 0);
    if (g_doneEvent) SetEvent(g_doneEvent);
    return 0;
}

int main(int argc, char** argv) {
    initConsole(); setWorkingDir();
    InitializeCriticalSection(&g_consoleLock); InitializeCriticalSection(&g_handleLock); InitializeCriticalSection(&g_emLock);
    InitializeCriticalSection(&g_seenLock); InitializeCriticalSection(&g_dnsLock); InitializeCriticalSection(&g_logLock);
    InitializeCriticalSection(&g_hostLock); InitializeCriticalSection(&g_ipLock);
    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL); g_doneEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    Settings st;
    if (!configRead(st)) st.lang = (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_TURKISH) ? 1 : 0;
    Settings saved = st;                 // what goes to disk; command line switches stay one-off
    parseArgs(argc, argv, st);
    applySettings(st);
    cursorShow(false);

    bool forcedCLI = false;
    for (int i = 1; i < argc; i++) {
        std::string a = lower(argv[i]);
        if (a == "--help" || a == "-h" || a == "-?" || a == "/?") { printHelp(); restoreConsole(); return 0; }
        if (a == "--auto" || a == "--manual" || a == "--test" || a == "--analyze" || a == "--strategy" || a.find("--strategy=") == 0) forcedCLI = true;
    }

    if (!isAdmin()) {
        if (relaunchAsAdmin(argc, argv)) ExitProcess(0);
        P("  %s%s%s\n", C_RED, TR("Could not get administrator rights.", "Yönetici izni alınamadı."), C_RESET);
        pauseAny(); restoreConsole(); return 1;
    }
    HANDLE mtx = CreateMutexA(NULL, TRUE, MUTEX_NAME);
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        P("\n  %s%s%s\n", C_YELLOW, TR("DPI Hunter is already running.", "DPI Hunter zaten çalışıyor."), C_RESET);
        pauseAny(); restoreConsole(); return 1;
    }
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { P("  %sWSAStartup failed%s\n", C_RED, C_RESET); pauseAny(); restoreConsole(); return 1; }

    if (!st.accepted) {
        if (!showDisclaimer(true)) { clearScreen(); restoreConsole(); return 0; }
        st.accepted = true; saved.accepted = true;
    }
    configWrite(saved);
    if (st.intro && !g_noIntro) playIntro();

    int exitCode = 0;
    while (true) {
        RunMode mode = st.runMode;
        if (!forcedCLI) {
            mode = mainMenu();
            if (mode == RUN_EXIT) break;
            if (mode == RUN_HELP) { printHelp(); continue; }
            if (mode == RUN_SETTINGS) { settingsMenu(st); continue; }
        }
        if (mode == RUN_TEST) {
            if (doDnsTestInteractive(st)) { configWrite(st); applySettings(st); }
            if (forcedCLI) break;
            continue;
        }
        if (mode == RUN_ANALYZE) {
            askAnalyzeSites();
            InterlockedExchange(&g_analyzeMode, 1); g_autoSwitch = false; InterlockedExchange(&g_ignoreHost, 1);
        }
        else if (mode == RUN_MANUAL) {
            if (!forcedCLI) {
                int s = manualStrategyMenu(st.manualStrategy);
                if (s < 0) continue;
                st.manualStrategy = s;
            }
            setStrategy((Strategy)st.manualStrategy); InterlockedExchange(&g_lastGood, (LONG)st.manualStrategy);
            g_autoSwitch = false; InterlockedExchange(&g_ignoreHost, 1);
        }
        else {
            int ls = loadLastStrategy();
            if (ls >= 0) { setStrategy((Strategy)ls); InterlockedExchange(&g_lastGood, (LONG)ls); }
            g_autoSwitch = true; InterlockedExchange(&g_ignoreHost, 0);
        }
        exitCode = runTool(st, mode);
        InterlockedExchange(&g_analyzeMode, 0);
        if (exitCode != 0) pauseAny();
        if (InterlockedCompareExchange(&g_quitReq, 0, 0)) break;
        if (forcedCLI && !InterlockedCompareExchange(&g_backToMenu, 0, 0) && exitCode == 0) break;
        forcedCLI = false;
    }

    clearScreen(); restoreConsole();
    P("\n  %s  %sby astegtam%s\n  %s%s%s\n\n", gradText("DPI HUNTER").c_str(), C_WHITE, C_RESET, C_DIM, DISCLAIMER_SHORT, C_RESET);
    WSACleanup();
    if (mtx) CloseHandle(mtx);
    return exitCode;
}
