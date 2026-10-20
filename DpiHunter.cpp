#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable: 28159)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <conio.h>
#include <string>
#include <set>
#include <vector>
#include <deque>
#include <fstream>
#include <algorithm>

#include "windivert.h"
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

#define MAXBUF              0xFFFF
#define AUTO_TEST_TIMEOUT   3000
#define FIRST_TEST_DELAY    8000
#define PERIODIC_TEST       300000
#define RETRY_SOON          60000
#define SUCCESS_THRESHOLD   60
#define RECENT_MAX          64
#define RECENT_TTL          1500
#define CONFIG_FILE         "dpi_hunter.cfg"
#define LAST_FILE           "dpi_hunter.last"
#define LOG_FILE            "dpi_hunter.log"
#define LOG_MAX_BYTES       (512 * 1024)
#define COOLDOWN_MS         60000
#define MAX_FAILS           3
#define SAFE_RETRY_MS       600000
#define RST_TRIGGER         3
#define RST_WINDOW_MS       15000
#define DNS_WORKERS         4
#define DNS_QUEUE_MAX       512
#define DNS_FAIL_LIMIT      5
#define DNS_PAUSE_MS        300000
#define DOH_TIMEOUT_MS      1500
#define DNS_TEST_TIMEOUT    1500
#define DNS_TEST_QUERIES    3
#define MAX_PORTS           16

#define C_RESET   "\x1b[0m"
#define C_BOLD    "\x1b[1m"
#define C_DIM     "\x1b[90m"
#define C_RED     "\x1b[31m"
#define C_GREEN   "\x1b[32m"
#define C_YELLOW  "\x1b[33m"
#define C_BLUE    "\x1b[34m"
#define C_MAGENTA "\x1b[35m"
#define C_CYAN    "\x1b[36m"
#define C_WHITE   "\x1b[97m"

enum Strategy {
    STRAT_SNI_FRAG_1 = 0, STRAT_SNI_FRAG_2, STRAT_SNI_FRAG_BEFORE,
    STRAT_FRAG_AT_2, STRAT_FRAG_AT_3,
    STRAT_FAKE_TTL_HI, STRAT_FAKE_TTL_LO, STRAT_FAKE_WRONG_SEQ,
    STRAT_FAKE_BAD_CHKSUM,
    STRAT_HOST_FAKE_SPLIT, STRAT_FAKE_LO_BAD_CHK, STRAT_MULTISPLIT_4,
    STRAT_REVERSE_FRAG, STRAT_RECORD_FRAG, STRAT_DESYNC, STRAT_QUIC_FAKE,
    STRAT_DISABLED, STRAT_COUNT
};
#define STRAT_BYPASS_COUNT  STRAT_DISABLED

static const char* STRAT_NAMES[STRAT_COUNT] = {
    "SNI-Frag-1", "SNI-Frag-2", "SNI-Frag-Before",
    "Frag-At-2", "Frag-At-3",
    "Fake-TTL-Hi", "Fake-TTL-Lo", "Fake-WrongSEQ", "Fake-BadChkSum",
    "HostFakeSplit", "Fake-Lo-BadChk", "MultiSplit-4", "Reverse-Frag",
    "Record-Frag", "Desync", "QUIC-Fake",
    "Safe-Mode"
};
static const char* STRAT_DESC[STRAT_COUNT] = {
    "Split 1 byte after SNI start",
    "Split 2 bytes after SNI start",
    "Split right before SNI",
    "Split at byte 2 of TLS payload",
    "Split at byte 3 of TLS payload",
    "Fake ClientHello, high TTL",
    "Fake ClientHello, low TTL",
    "Fake with wrong sequence number",
    "Fake with broken TCP checksum",
    "Fake SNI + real split (best for tough ISPs)",
    "Fake low-TTL, broken checksum (decoy)",
    "Split payload into 4 fragments",
    "Send second fragment first",
    "Split at TLS record header byte 5",
    "Send fragments with a short delay",
    "Fake a QUIC Initial instead of dropping",
    "Safe mode: no modification"
};

struct DohProvider {
    std::string    name;
    std::string    cfgName;
    std::wstring   host;
    std::wstring   path;
    std::string    note;
};
#define DOH_COUNT 12
#define DOH_MAX_COUNT 13
static DohProvider DOH[DOH_MAX_COUNT] = {
    { "Cloudflare",   "cloudflare",  L"1.1.1.1",         L"/dns-query", "No filtering, fastest" },
    { "Cloudflare-2", "cloudflare2", L"1.0.0.1",         L"/dns-query", "Cloudflare secondary" },
    { "Google",       "google",      L"8.8.8.8",         L"/dns-query", "Reliable, global" },
    { "Google-2",     "google2",     L"8.8.4.4",         L"/dns-query", "Google secondary" },
    { "Quad9",        "quad9",       L"9.9.9.9",         L"/dns-query", "Blocks malware" },
    { "Quad9-2",      "quad9b",      L"149.112.112.112", L"/dns-query", "Quad9 secondary" },
    { "AdGuard",      "adguard",     L"94.140.14.14",    L"/dns-query", "Blocks ads and trackers" },
    { "AdGuard-2",    "adguard2",    L"94.140.15.15",    L"/dns-query", "AdGuard secondary" },
    { "Mullvad",      "mullvad",     L"194.242.2.2",     L"/dns-query", "Privacy, no logs" },
    { "DNS.SB",       "dnssb",       L"185.222.222.222", L"/dns-query", "No filtering, EU" },
    { "DNS.SB-2",     "dnssb2",      L"45.11.45.11",     L"/dns-query", "DNS.SB secondary" },
    { "LibreDNS",     "libredns",    L"116.202.176.26",  L"/dns-query", "Libre, no tracking" },
    { "Custom",       "custom",      L"",                L"/dns-query", "Manual input" }
};

enum DnsMode { DNS_FAST = 0, DNS_FULL, DNS_OFF };
enum RunMode { RUN_AUTO = 0, RUN_MANUAL, RUN_TEST, RUN_ANALYZE, RUN_EXIT, RUN_HELP };

static const int DEFAULT_PORTS[] = { 80, 443, 8080, 8443, 2053, 2083, 2087, 2096 };

struct Settings {
    DnsMode          dnsMode;
    bool             dohAuto;
    int              dohProvider;
    std::vector<int> ports;
    bool             httpEnabled;
    int              fakeTtl;
    RunMode          runMode;
    int              manualStrategy;
    bool             logEnabled;

    Settings() : dnsMode(DNS_FAST), dohAuto(true), dohProvider(0),
        httpEnabled(true), fakeTtl(6), runMode(RUN_AUTO),
        manualStrategy(STRAT_FRAG_AT_2), logEnabled(true) {
        for (size_t i = 0; i < sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]); i++)
            ports.push_back(DEFAULT_PORTS[i]);
    }
};

static volatile LONG g_running = TRUE;
static volatile LONG g_strategy = STRAT_FRAG_AT_2;
static volatile LONG g_lastGood = STRAT_FRAG_AT_2;
static HANDLE        g_handle = INVALID_HANDLE_VALUE;
static HANDLE        g_stopEvent = NULL;
static HANDLE        g_doneEvent = NULL;
static unsigned char g_packet[MAXBUF];
static bool          g_httpEnabled = true;
static int           g_fakeTtl = 6;
static DnsMode       g_dnsMode = DNS_FAST;
static bool          g_dnsEnabled = false;
static bool          g_logEnabled = true;
static volatile LONG g_dohPref = 0;
static volatile LONG g_dohFail = 0;
static volatile LONG g_dohPaused = 0;
static volatile LONG g_dohPausedUntil = 0;
static volatile LONG g_emergencyFlag = 0;
static volatile LONG g_emergencyRunning = 0;
static volatile LONG g_lastEmergencyTick = 0;
static volatile LONG g_consecutiveFails = 0;
static char          g_emergencyHost[256] = { 0 };
static DWORD         g_safeSince = 0;
static DWORD         g_rstWindowStart = 0;
static int           g_rstCount = 0;
static std::string   g_rstLastHost;
static SHORT         g_strategyRow = -1;

static bool          g_autoSwitch = true;
static volatile LONG g_analyzeMode = 0;
static bool          g_blockPassive = false;
static bool          g_dropQuic = true;

static bool          g_menuStrategy = false;
static bool          g_dohForced = false;
static bool          g_askDnsInteractive = false;
static std::vector<std::string> g_analyzeSites;

static CRITICAL_SECTION g_consoleLock, g_handleLock, g_emLock,
g_seenLock, g_dnsLock, g_logLock;
static std::set<std::string> g_failedHosts;
static std::set<std::string> g_unfixable;
static std::set<std::string> g_blacklist;
static HANDLE g_dnsSem = NULL;
static std::deque<struct DnsJob*> g_dnsQueue;

// Forward Declarations
static void printHelp();
static void doDnsTestInteractive(Settings& st);

static inline bool isRunning() { return InterlockedCompareExchange(&g_running, 1, 1) != 0; }
static inline Strategy getStrategy() { return (Strategy)InterlockedCompareExchange(&g_strategy, 0, 0); }
static inline void setStrategy(Strategy s) { InterlockedExchange(&g_strategy, (LONG)s); }

static bool sleepOrStop(DWORD ms) {
    if (!g_stopEvent) { Sleep(ms); return !isRunning(); }
    return WaitForSingleObject(g_stopEvent, ms) == WAIT_OBJECT_0;
}

static void requestStop() {
    InterlockedExchange(&g_running, FALSE);
    if (g_stopEvent) SetEvent(g_stopEvent);
    EnterCriticalSection(&g_handleLock);
    HANDLE h = g_handle;
    if (h && h != INVALID_HANDLE_VALUE) WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
    LeaveCriticalSection(&g_handleLock);
}

static BOOL WINAPI ctrlHandler(DWORD sig) {
    requestStop();
    if (sig == CTRL_C_EVENT || sig == CTRL_BREAK_EVENT) {
        if (g_doneEvent) WaitForSingleObject(g_doneEvent, 5000);
        ExitProcess(0);
    }
    if (g_doneEvent) WaitForSingleObject(g_doneEvent, 4000);
    return TRUE;
}

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
    s = lower(trim(s));
    for (int i = 0; i < STRAT_BYPASS_COUNT; i++)
        if (s == lower(STRAT_NAMES[i])) return i;
    return -1;
}

static void enableAnsi() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD m = 0;
    if (GetConsoleMode(h, &m)) SetConsoleMode(h, m | 0x0004);
}
static void disableQuickEdit() {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD m = 0;
    if (GetConsoleMode(h, &m)) {
        m &= ~ENABLE_QUICK_EDIT_MODE; m &= ~ENABLE_MOUSE_INPUT; m |= ENABLE_EXTENDED_FLAGS;
        SetConsoleMode(h, m);
    }
}
static void clearScreen() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD w;
    if (GetConsoleScreenBufferInfo(h, &csbi)) {
        DWORD n = csbi.dwSize.X * csbi.dwSize.Y;
        COORD home = { 0, 0 };
        FillConsoleOutputCharacterA(h, ' ', n, home, &w);
        FillConsoleOutputAttribute(h, csbi.wAttributes, n, home, &w);
        SetConsoleCursorPosition(h, home);
    }
}
static void printTs() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("%s[%02d:%02d:%02d]%s", C_DIM, st.wHour, st.wMinute, st.wSecond, C_RESET);
}
static void setWorkingDir() {
    char p[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, p, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    char* s = strrchr(p, '\\');
    if (s) { *s = 0; SetCurrentDirectoryA(p); }
}

static void rotateLog() {
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (GetFileAttributesExA(LOG_FILE, GetFileExInfoStandard, &fa) &&
        fa.nFileSizeLow > LOG_MAX_BYTES) {
        MoveFileExA(LOG_FILE, LOG_FILE ".old", MOVEFILE_REPLACE_EXISTING);
    }
}

static void logLine(const char* tag, const char* color, const char* text) {
    EnterCriticalSection(&g_consoleLock);
    printf("  "); printTs();
    printf(" %s%s%s %s\n", color, tag, C_RESET, text);
    fflush(stdout);
    LeaveCriticalSection(&g_consoleLock);

    if (g_logEnabled) {
        EnterCriticalSection(&g_logLock);
        rotateLog();
        std::ofstream f(LOG_FILE, std::ios::app);
        if (f.is_open()) {
            SYSTEMTIME st; GetLocalTime(&st);
            f << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] " << tag << " " << text << "\n";
        }
        LeaveCriticalSection(&g_logLock);
    }
}

static void pauseAny() {
    printf("\n  %sPress any key to continue...%s", C_DIM, C_RESET);
    fflush(stdout);
    _getch();
}

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
    SHELLEXECUTEINFOA sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = p;
    sei.lpParameters = args.empty() ? NULL : args.c_str();
    sei.nShow = SW_NORMAL;
    return ShellExecuteExA(&sei) != FALSE;
}

struct Messages {
    const char* openFail, * stopped, * stratSwitch, * emergencyDetected, * emergencyFound;
    const char* emergencyCooldown, * safeEntered, * statusActive, * blDisabled, * logHeader;
    const char* safeRetry, * noFix, * noValidTest, * rstBenign, * dnsOn, * dnsOff;
    const char* dnsDown, * dnsBack, * httpOn, * httpOff;
};
static const Messages g_str = {
    "WinDivert could not be opened! Error: ", "Stopped", "Switching",
    "Several resets detected", "Fixed", "Cooldown (spam prevented)",
    "Entered Safe-Mode (retry in 10 min)", "ACTIVE", "disabled (all TLS/HTTP protected)",
    "Log", "Safe-Mode expired, retrying", "No strategy fixed it (may be an IP/DNS block)",
    "No valid test, strategy not changed", "Reset was harmless, site is reachable",
    "Encrypted (DoH)", "off", "DoH unreachable, normal DNS for 5 min",
    "DoH active again", "enabled (Host fragmentation)", "disabled"
};

static int parseDohName(const std::string& v) {
    if (v == "custom") return -1;
    for (int i = 0; i < DOH_COUNT; i++) if (v == DOH[i].cfgName) return i;
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
            if (e && *e == 0 && p >= 1 && p <= 65535) {
                bool dup = false;
                for (size_t i = 0; i < out.size(); i++) if (out[i] == (int)p) dup = true;
                if (!dup) out.push_back((int)p);
            }
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

static bool configRead(Settings& st, bool& complete) {
    complete = false;
    std::ifstream f(CONFIG_FILE);
    if (!f.is_open()) return false;
    bool gotDns = false, gotDoh = false, gotPorts = false, gotHttp = false, gotTtl = false;
    std::string line; bool first = true;
    while (std::getline(f, line)) {
        if (first) { stripBom(line); first = false; }
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = lower(trim(line.substr(0, eq)));
        std::string v = lower(trim(line.substr(eq + 1)));
        if (k == "dns_mode") { DnsMode m; if (parseDnsMode(v, m)) { st.dnsMode = m; gotDns = true; } }
        else if (k == "doh_auto") { bool b; if (parseOnOff(v, b)) st.dohAuto = b; }
        else if (k == "doh") { int i = parseDohName(v); if (i >= 0) { st.dohProvider = i; gotDoh = true; st.dohAuto = false; } }
        else if (k == "ports") { std::vector<int> p; if (parsePorts(v, p)) { st.ports = p; gotPorts = true; } }
        else if (k == "http") { bool b; if (parseOnOff(v, b)) { st.httpEnabled = b; gotHttp = true; } }
        else if (k == "ttl") { char* e = NULL; long t = strtol(v.c_str(), &e, 10); if (e && *e == 0 && t >= 1 && t <= 20) { st.fakeTtl = (int)t; gotTtl = true; } }
        else if (k == "log") { bool b; if (parseOnOff(v, b)) st.logEnabled = b; }
    }
    if (gotPorts && !gotHttp) {
        const int add[] = { 80, 8080 };
        for (int i = 0; i < 2; i++)
            if (std::find(st.ports.begin(), st.ports.end(), add[i]) == st.ports.end() && (int)st.ports.size() < MAX_PORTS)
                st.ports.push_back(add[i]);
    }
    complete = gotDns && gotDoh && gotPorts && gotHttp && gotTtl;
    return true;
}
static void configWrite(const Settings& st) {
    std::ofstream f(CONFIG_FILE);
    if (!f.is_open()) return;
    f << "# DPI Hunter v5.1 configuration\n\n";
    f << "dns_mode=" << (st.dnsMode == DNS_FAST ? "fast" : st.dnsMode == DNS_FULL ? "full" : "off") << "\n";
    f << "doh_auto=" << (st.dohAuto ? "on" : "off") << "\n";
    f << "doh=" << DOH[st.dohProvider].cfgName << "\n";
    f << "ports=";
    for (size_t i = 0; i < st.ports.size(); i++) { if (i) f << ","; f << st.ports[i]; }
    f << "\nhttp=" << (st.httpEnabled ? "on" : "off") << "\n";
    f << "ttl=" << st.fakeTtl << "\n";
    f << "log=" << (st.logEnabled ? "on" : "off") << "\n";
}
static void parseArgs(int argc, char** argv, Settings& st) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i], k, v;
        size_t eq = a.find('=');
        if (eq != std::string::npos) { k = a.substr(0, eq); v = a.substr(eq + 1); }
        else k = a;
        k = lower(k); v = lower(v);
        if (eq == std::string::npos && i + 1 < argc && argv[i + 1][0] != '-' &&
            (k == "--dns" || k == "--doh" || k == "--ports" || k == "--ttl" || k == "--strategy" || k == "--http"))
            v = lower(argv[++i]);
        if (k == "--auto")    st.runMode = RUN_AUTO;
        else if (k == "--manual")  st.runMode = RUN_MANUAL;
        else if (k == "--test")    st.runMode = RUN_TEST;
        else if (k == "--analyze") st.runMode = RUN_ANALYZE;
        else if (k == "--no-dns")  st.dnsMode = DNS_OFF;
        else if (k == "--dns") { DnsMode m; if (parseDnsMode(v, m)) st.dnsMode = m; }
        else if (k == "--doh") { int x = parseDohName(v); if (x >= 0) { st.dohProvider = x; st.dohAuto = false; g_dohForced = true; } }
        else if (k == "--doh-auto") { st.dohAuto = true; g_dohForced = false; }
        else if (k == "--ports") { std::vector<int> p; if (parsePorts(v, p)) st.ports = p; }
        else if (k == "--http") { bool b; if (parseOnOff(v, b)) st.httpEnabled = b; }
        else if (k == "--no-http") st.httpEnabled = false;
        else if (k == "--no-log")  st.logEnabled = false;
        else if (k == "--log")     st.logEnabled = true;
        else if (k == "--block-passive") g_blockPassive = true;
        else if (k == "--keep-quic") g_dropQuic = false;
        else if (k == "--ttl") { char* e; long t = strtol(v.c_str(), &e, 10); if (e && *e == 0 && t >= 1 && t <= 20) st.fakeTtl = (int)t; }
        else if (k == "--strategy") {
            for (int s = 0; s < STRAT_BYPASS_COUNT; s++)
                if (v == lower(STRAT_NAMES[s])) { st.manualStrategy = s; st.runMode = RUN_MANUAL; break; }
        }
    }
}

static void printBanner() {
    clearScreen();
    printf("\n");
    printf("  %sDPI Hunter v5.1%s\n", C_BOLD C_WHITE, C_RESET);
    printf("  by astegtam\n\n");
    printf("  --------------------------\n\n");
}

static void printPanel(const char* bl, const char* dns, const char* ports, const char* http, int ttl) {
    Strategy cur = getStrategy();
    printf("\n  %s%s[ Status ]%s\n", C_BOLD, C_GREEN, C_RESET);
    printf("  %s--------------------------------%s\n", C_DIM, C_RESET);
    printf("  %-10s %s%sACTIVE%s\n", "State", C_GREEN, C_BOLD, C_RESET);

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    fflush(stdout);
    if (GetConsoleScreenBufferInfo(h, &csbi)) g_strategyRow = csbi.dwCursorPosition.Y;
    else g_strategyRow = -1;

    printf("  %-10s %s%s%s\n", "Strategy", C_CYAN, STRAT_NAMES[cur], C_RESET);
    printf("  %-10s %s%s%s\n", "Blacklist", C_YELLOW, bl, C_RESET);
    printf("  %-10s %s%s%s\n", "DNS", C_YELLOW, dns, C_RESET);
    printf("  %-10s %s%s%s\n", "Ports", C_YELLOW, ports, C_RESET);
    printf("  %-10s %s%s%s\n", "HTTP", C_YELLOW, http, C_RESET);
    printf("  %-10s %s%d%s\n", "Fake TTL", C_YELLOW, ttl, C_RESET);
    printf("\n");
    fflush(stdout);
}

static void updateStrategyRow() {
    Strategy cur = getStrategy();
    char t[96];
    sprintf_s(t, sizeof(t), "DPI Hunter v5.1 - %s", STRAT_NAMES[cur]);
    SetConsoleTitleA(t);
    if (g_strategyRow < 0) return;
    EnterCriticalSection(&g_consoleLock);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(h, &csbi)) {
        COORD saved = csbi.dwCursorPosition;
        COORD pos = { 0, g_strategyRow };
        char row[48] = { 0 }; DWORD got = 0;
        bool ok = false;
        if (ReadConsoleOutputCharacterA(h, row, 40, pos, &got) && got > 0) {
            row[got < 47 ? got : 47] = 0;
            ok = (strstr(row, "Strategy") != NULL);
        }
        if (ok) {
            fflush(stdout);
            SetConsoleCursorPosition(h, pos);
            printf("  %s%-10s %s%s%s\x1b[K", C_DIM, "Strategy", C_CYAN, STRAT_NAMES[cur], C_RESET);
            fflush(stdout);
            SetConsoleCursorPosition(h, saved);
        }
    }
    LeaveCriticalSection(&g_consoleLock);
}

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
        if (len == 0 || len > 63) return;
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
    r.provIdx = j->provIdx;
    r.reachable = false;
    r.avgMs = r.minMs = r.maxMs = 0;
    r.successes = 0;
    DWORD warm = 0;
    if (!dohQueryOnce(j->prov, "example.com", &warm)) return 0;
    static const char* names[] = { "example.com", "cloudflare.com", "wikipedia.org" };
    DWORD total = 0, mn = 0xFFFFFFFF, mx = 0;
    int ok = 0;
    for (int i = 0; i < DNS_TEST_QUERIES; i++) {
        DWORD ms = 0;
        if (dohQueryOnce(j->prov, names[i % 3], &ms)) {
            total += ms;
            if (ms < mn) mn = ms;
            if (ms > mx) mx = ms;
            ok++;
        }
    }
    if (ok > 0) {
        r.reachable = true; r.successes = ok;
        r.avgMs = total / ok; r.minMs = mn; r.maxMs = mx;
    }
    return 0;
}

static int runDnsTests(std::vector<DnsTestResult>& results, bool includeCustom) {
    int count = DOH_COUNT;
    if (includeCustom && !DOH[DOH_COUNT].host.empty()) count++;
    results.assign(count, DnsTestResult());
    static DnsTestJob jobs[DOH_MAX_COUNT];
    std::vector<HANDLE> threads;
    for (int i = 0; i < count; i++) {
        jobs[i].provIdx = i;
        jobs[i].prov = DOH[i];
        HANDLE h = CreateThread(NULL, 0, dnsTestThread, &jobs[i], 0, NULL);
        if (h) threads.push_back(h);
    }
    if (!threads.empty()) WaitForMultipleObjects((DWORD)threads.size(), &threads[0], TRUE, INFINITE);
    for (size_t i = 0; i < threads.size(); i++) CloseHandle(threads[i]);
    for (int i = 0; i < count; i++) results[i] = jobs[i].result;

    int best = -1; DWORD bm = 0xFFFFFFFF;
    for (size_t i = 0; i < results.size(); i++)
        if (results[i].reachable && results[i].avgMs < bm) { bm = results[i].avgMs; best = results[i].provIdx; }
    return best;
}

static void printDnsTable(const std::vector<DnsTestResult>& r, int rec) {
    printf("\n  %s%sDNS LATENCY TEST%s\n", C_BOLD, C_WHITE, C_RESET);
    printf("  %s------------------------------------------------------------%s\n", C_DIM, C_RESET);
    printf("  %s%-3s %-16s %8s %7s %7s  %s%s\n", C_BOLD C_WHITE, "#", "Provider", "Average", "Min", "Max", "Note", C_RESET);
    printf("  %s------------------------------------------------------------%s\n", C_DIM, C_RESET);

    for (size_t i = 0; i < r.size(); i++) {
        const char* mark = (int)i == rec ? "> " : "  ";
        const char* mc = (int)i == rec ? C_GREEN C_BOLD : C_RESET;
        if (r[i].reachable) {
            const char* lc = r[i].avgMs < 30 ? C_GREEN : r[i].avgMs < 80 ? C_YELLOW : C_RED;
            printf("  %s%s%-3d %-16s %s%5lums%s   %5lums %5lums  %s%s%s\n",
                mc, mark, (int)i + 1, DOH[i].name.c_str(), lc, (long)r[i].avgMs, C_RESET,
                (long)r[i].minMs, (long)r[i].maxMs, C_DIM, DOH[i].note.c_str(), C_RESET);
        }
        else {
            printf("  %s%s%-3d %-16s   ---                  %s%s%s\n",
                mc, mark, (int)i + 1, DOH[i].name.c_str(), C_DIM, "unreachable", C_RESET);
        }
    }

    printf("\n  %s> Recommended:%s ", C_BOLD, C_RESET);
    if (rec >= 0)
        printf("%s%s%s\n\n", C_GREEN C_BOLD, DOH[rec].name.c_str(), C_RESET);
    else
        printf("%s! None reachable.%s\n\n", C_YELLOW, C_RESET);
}

static void doDnsTestInteractive(Settings& st) {
    bool hasManual = !DOH[DOH_COUNT].host.empty();
    std::vector<DnsTestResult> results;
    int rec = runDnsTests(results, hasManual);

    while (true) {
        printDnsTable(results, rec);
        printf("  %sEnter # (1-%d), Enter for recommended, [M] for Manual, 0 to disable DoH: %s",
            C_YELLOW C_BOLD, (int)results.size(), C_RESET);
        fflush(stdout);

        char buf[128];
        if (!fgets(buf, sizeof(buf), stdin)) { st.dnsMode = DNS_OFF; break; }
        std::string s = trim(buf);

        if (s == "0") { st.dnsMode = DNS_OFF; break; }
        if (s == "m" || s == "M") {
            printf("  %sEnter DoH IPv4 address (e.g. 1.1.1.1): %s", C_YELLOW, C_RESET);
            fflush(stdout);
            char ip[64];
            if (fgets(ip, sizeof(ip), stdin)) {
                std::string ipStr = trim(ip);
                if (!ipStr.empty()) {
                    IN_ADDR a4;
                    if (inet_pton(AF_INET, ipStr.c_str(), &a4) != 1) {
                        printf("  %sNot a valid IPv4 address.%s\n", C_RED, C_RESET);
                        continue;
                    }
                    DOH[DOH_COUNT].name = ipStr;
                    DOH[DOH_COUNT].host = std::wstring(ipStr.begin(), ipStr.end());
                    hasManual = true;
                    results.clear();
                    rec = runDnsTests(results, hasManual);
                }
            }
            continue;
        }

        int n = s.empty() ? 0 : atoi(s.c_str());
        if (n >= 1 && n <= (int)results.size()) {
            st.dohProvider = n - 1;
            st.dohAuto = false;
            g_dohForced = true;
            break;
        }
        else if (s.empty() && rec >= 0) {
            st.dohProvider = rec;
            st.dohAuto = false;
            g_dohForced = true;
            break;
        }
        else {
            printf("  %sInvalid choice, try again.%s\n", C_RED, C_RESET);
        }
    }
}

static RunMode mainMenu(Settings& st) {
    while (true) {
        printBanner();
        printf("  %sChoose a mode or type a command (e.g. --ttl=4, --auto, help):%s\n\n", C_BOLD C_WHITE, C_RESET);
        printf("    %s[1]%s  AUTO       Auto strategy + auto DNS\n", C_GREEN C_BOLD, C_RESET);
        printf("    %s[2]%s  MANUAL     Pick strategy and DNS\n", C_GREEN C_BOLD, C_RESET);
        printf("    %s[3]%s  TEST       Measure DNS latency only\n", C_GREEN C_BOLD, C_RESET);
        printf("    %s[4]%s  ANALYZE    Test every strategy\n", C_GREEN C_BOLD, C_RESET);
        printf("    %s[5]%s  HELP       Show options\n", C_GREEN C_BOLD, C_RESET);
        printf("    %s[6]%s  EXIT\n\n", C_RED C_BOLD, C_RESET);
        printf("  %s> %s", C_YELLOW C_BOLD, C_RESET);
        fflush(stdout);

        char buf[512];
        if (!fgets(buf, sizeof(buf), stdin)) return RUN_EXIT;
        std::string line = lower(trim(buf));

        if (line.empty()) return RUN_AUTO;

        if (line == "1" || line == "auto") return RUN_AUTO;
        if (line == "2" || line == "manual") return RUN_MANUAL;
        if (line == "3" || line == "test") return RUN_TEST;
        if (line == "4" || line == "analyze") return RUN_ANALYZE;
        if (line == "5" || line == "help" || line == "--help") { printHelp(); continue; }
        if (line == "6" || line == "exit" || line == "quit") return RUN_EXIT;

        if (line[0] == '-') {
            std::vector<std::string> args;
            args.push_back("dpi_hunter.exe");
            std::string cur;
            for (char c : line) {
                if (c == ' ' || c == '\t') {
                    if (!cur.empty()) { args.push_back(cur); cur.clear(); }
                }
                else cur += c;
            }
            if (!cur.empty()) args.push_back(cur);

            bool hasMode = false;
            for (size_t i = 0; i < args.size(); i++) {
                std::string ls = lower(args[i]);
                if (ls == "--auto" || ls == "--manual" || ls == "--test" ||
                    ls == "--analyze") {
                    hasMode = true;
                }
                if (ls == "--strategy" || ls.find("--strategy=") == 0) {
                    hasMode = true;
                    g_menuStrategy = true;
                }
            }

            std::vector<char*> argv;
            for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
            parseArgs((int)argv.size(), argv.data(), st);

            if (hasMode) {
                return st.runMode;
            }
            else {
                printf("  %sSettings updated. Returning to menu...%s\n", C_GREEN, C_RESET);
                Sleep(800);
                continue;
            }
        }
        printf("  %sUnknown command. Please try again.%s\n", C_RED, C_RESET);
        Sleep(800);
    }
}

static void printHelp() {
    clearScreen();
    printf("\n  %s%sDPI Hunter v5.1 -- Help%s\n\n", C_BOLD, C_CYAN, C_RESET);
    printf("  %sUSAGE%s\n", C_BOLD C_WHITE, C_RESET);
    printf("    dpi_hunter.exe                  # menu\n");
    printf("    dpi_hunter.exe --auto           # auto mode\n");
    printf("    dpi_hunter.exe --manual         # manual mode\n");
    printf("    dpi_hunter.exe --test           # DNS latency test\n");
    printf("    dpi_hunter.exe --analyze        # test all strategies\n");
    printf("    dpi_hunter.exe --help           # this screen\n\n");
    printf("  %sOPTIONS%s\n", C_BOLD C_WHITE, C_RESET);
    printf("    --strategy=NAME      Pick a strategy\n");
    printf("    --dns=fast|full|off  DNS handling mode\n");
    printf("    --doh=NAME           Force provider\n");
    printf("    --ttl=N              Fake packet TTL (1-20)\n");
    printf("    --ports=443,80       Ports to protect\n");
    printf("    --no-dns             Disable DoH\n");
    printf("    --no-http            Disable HTTP fragmentation\n");
    printf("    --no-log             Disable log file\n");
    printf("    --log                Enable log file\n");
    printf("    --block-passive      Drop fake RST packets\n");
    printf("    --keep-quic          Do not block UDP/443 QUIC\n\n");
    printf("  %sPress any key to return...%s", C_DIM, C_RESET);
    fflush(stdout);
    _getch();
}

static int manualStrategyMenu() {
    clearScreen();
    printf("\n  %s%sSELECT A STRATEGY%s\n\n", C_BOLD, C_WHITE, C_RESET);
    for (int i = 0; i < STRAT_BYPASS_COUNT; i++)
        printf("  %s%2d%s  %s%-18s%s %s%s%s\n",
            C_YELLOW, i + 1, C_RESET, C_GREEN, STRAT_NAMES[i], C_RESET, C_DIM, STRAT_DESC[i], C_RESET);
    printf("\n  %s0%s   Back\n\n  %s> %s", C_YELLOW, C_RESET, C_YELLOW C_BOLD, C_RESET);
    fflush(stdout);
    int choice = 0, digits = 0;
    while (true) {
        int ch = _getch();
        if (ch == 27) { printf("\n"); return -1; }
        if (ch == 13) {
            if (digits > 0) {
                printf("%d\n", choice);
                if (choice == 0) return -1;
                if (choice >= 1 && choice <= STRAT_BYPASS_COUNT) return choice - 1;
            }
            choice = 0; digits = 0; continue;
        }
        if (ch >= '0' && ch <= '9' && digits < 2) {
            printf("%c", ch); choice = choice * 10 + (ch - '0'); digits++;
        }
        if (ch == 8 && digits > 0) { printf("\b \b"); choice /= 10; digits--; }
    }
}

static void loadBlacklist(const std::string& fn) {
    std::ifstream f(fn);
    if (!f.is_open()) return;
    std::string line; bool first = true;
    while (std::getline(f, line)) {
        if (first) { stripBom(line); first = false; }
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        g_blacklist.insert(lower(line));
    }
}
static bool isBlacklisted(const std::string& h) {
    if (g_blacklist.empty()) return true;
    size_t p = 0;
    while (true) {
        if (g_blacklist.count(h.substr(p))) return true;
        p = h.find('.', p);
        if (p == std::string::npos) return false;
        ++p;
    }
}
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

static bool extractSni(const char* d, unsigned int len, char** out, unsigned int* outLen) {
    if (len < 10) return false;
    uint32_t p = 0;
    while (p + 9 < len) {
        if (d[p] == 0 && d[p + 1] == 0 && d[p + 2] == 0 && d[p + 4] == 0 && d[p + 6] == 0 && d[p + 7] == 0 &&
            (unsigned char)d[p + 3] - (unsigned char)d[p + 5] == 2 && (unsigned char)d[p + 5] - (unsigned char)d[p + 8] == 3) {
            unsigned int hl = (unsigned char)d[p + 8];
            if (hl < 2 || hl > 254) return false;
            if (p + 9 + hl > len) return false;
            const char* hn = &d[p + 9];
            for (unsigned int i = 0; i < hl; i++) {
                char c = hn[i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
            }
            *out = (char*)hn; *outLen = hl; return true;
        }
        p++;
    }
    return false;
}
static bool isHttpRequest(const UINT8* p, UINT len) {
    if (len < 4 || p[0] < 'A' || p[0] > 'Z') return false;
    static const char* m[] = { "GET ","POST ","HEAD ","PUT ","DELETE ","OPTIONS ","CONNECT ","PATCH ","TRACE " };
    for (int i = 0; i < 9; i++) {
        size_t ml = strlen(m[i]);
        if (len >= ml && memcmp(p, m[i], ml) == 0) return true;
    }
    return false;
}
static bool extractHttpHost(const char* d, unsigned int len, char** out, unsigned int* outLen, unsigned int* outOff) {
    if (len < 12) return false;
    unsigned int hdrEnd = len;
    for (unsigned int i = 0; i + 3 < len; i++)
        if (d[i] == '\r' && d[i + 1] == '\n' && d[i + 2] == '\r' && d[i + 3] == '\n') { hdrEnd = i + 2; break; }
    for (unsigned int i = 0; i + 5 < hdrEnd; i++) {
        bool ls = (i == 0) || (d[i - 1] == '\n');
        if (!ls) continue;
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
            *out = (char*)(d + start); *outLen = end - start; *outOff = start; return true;
        }
    }
    return false;
}

struct Stats {
    volatile LONG total = 0, fragmented = 0, fakeSent = 0, quicBlocked = 0;
    volatile LONG passed = 0, rstDetected = 0, dnsDoh = 0, dnsFallback = 0;
    volatile LONG passiveDropped = 0;
};
static Stats g_stats;

struct IpKey { UINT32 a[4]; };
static IpKey keyV4(UINT32 v) { IpKey k; k.a[0] = v; k.a[1] = 0; k.a[2] = 0; k.a[3] = 0; return k; }
static IpKey keyV6(const UINT32* v) { IpKey k; memcpy(k.a, v, 16); return k; }
static bool keyEq(const IpKey& x, const IpKey& y) { return memcmp(x.a, y.a, 16) == 0; }

struct RecentFrag { IpKey key; USHORT port; DWORD tick; char host[128]; };
static RecentFrag g_recent[RECENT_MAX];
static int g_recentIdx = 0;

static void rememberFrag(const IpKey& k, USHORT p, const char* h) {
    g_recentIdx = (g_recentIdx + 1) % RECENT_MAX;
    RecentFrag& r = g_recent[g_recentIdx];
    r.key = k; r.port = p; r.tick = GetTickCount();
    strncpy_s(r.host, sizeof(r.host), h, _TRUNCATE);
}
static std::string matchRecent(const IpKey& k, USHORT p) {
    DWORD n = GetTickCount();
    for (int i = 0; i < RECENT_MAX; i++)
        if (keyEq(g_recent[i].key, k) && g_recent[i].port == p && (n - g_recent[i].tick) < RECENT_TTL && g_recent[i].host[0] != 0) {
            std::string r = g_recent[i].host; g_recent[i].host[0] = 0; return r;
        }
    return "";
}
static bool isLocalDst(PWINDIVERT_IPHDR ip, PWINDIVERT_IPV6HDR ip6) {
    if (ip) {
        const UINT8* b = (const UINT8*)&ip->DstAddr;
        return b[0] == 127 || b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    }
    if (ip6) {
        const UINT8* b = (const UINT8*)ip6->DstAddr;
        return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) || (ip6->DstAddr[0] == 0 && ip6->DstAddr[1] == 0 && ip6->DstAddr[2] == 0 && ip6->DstAddr[3] == htonl(1));
    }
    return false;
}

struct HopEntry { IpKey key; BYTE hops; };
static HopEntry g_hops[256];
static unsigned hopHash(const IpKey& k) { return (unsigned)((k.a[0] ^ k.a[1] ^ k.a[2] ^ k.a[3]) * 2654435761u) >> 24; }
static BYTE autoTtl(const unsigned char* pkt, BYTE def) {
    IpKey k = ((pkt[0] >> 4) == 6) ? keyV6(((const PWINDIVERT_IPV6HDR)pkt)->DstAddr) : keyV4(((const PWINDIVERT_IPHDR)pkt)->DstAddr);
    const HopEntry& e = g_hops[hopHash(k)];
    if (e.hops > 1 && keyEq(e.key, k)) { BYTE t = (BYTE)(e.hops - 1); return t < def ? t : def; }
    return def;
}
static BYTE fakeTtlFor(Strategy s) {
    int t = g_fakeTtl;
    if (s == STRAT_FAKE_TTL_LO) t = (t > 3) ? (t - 3) : 1;
    if (t < 1) t = 1; if (t > 20) t = 20;
    return (BYTE)t;
}
static void makeFakeHost(char* dst, unsigned int len) {
    const char* base = "www.google.com";
    const unsigned int bl = 14;
    if (len >= bl) { unsigned int pad = len - bl; for (unsigned int i = 0; i < pad; i++) dst[i] = 'w'; memcpy(dst + pad, base, bl); }
    else memcpy(dst, base + (bl - len), len);
}
static void sendFakePacket(const unsigned char* orig, UINT origLen, const WINDIVERT_ADDRESS* addr, PWINDIVERT_TCPHDR tcp, PVOID payload, UINT offset, UINT sniLen, BYTE ttl, bool wrongSeq, bool badChecksum) {
    if (origLen > MAXBUF) return;
    UINT tcpOff = (UINT)((const UINT8*)tcp - orig);
    UINT hdrLen = (UINT)((const UINT8*)payload - orig);
    if (hdrLen + offset + sniLen > origLen) return;
    static unsigned char fake[MAXBUF];
    memcpy(fake, orig, origLen);
    PWINDIVERT_TCPHDR ft = (PWINDIVERT_TCPHDR)(fake + tcpOff);
    makeFakeHost((char*)fake + hdrLen + offset, sniLen);
    WINDIVERT_ADDRESS fa = *addr;
    if (ttl != 0) {
        ttl = autoTtl(orig, ttl);
        if (ttl > 20) ttl = 20; if (ttl < 1) ttl = 1;
        if ((fake[0] >> 4) == 6) ((PWINDIVERT_IPV6HDR)fake)->HopLimit = ttl; else ((PWINDIVERT_IPHDR)fake)->TTL = ttl;
    }
    if (wrongSeq) { ft->AckNum = htonl(ntohl(ft->AckNum) - 66000); ft->SeqNum = htonl(ntohl(ft->SeqNum) - 10000); }
    WinDivertHelperCalcChecksums(fake, origLen, &fa, 0);
    if (badChecksum) ft->Checksum = htons((UINT16)(ntohs(ft->Checksum) - 1));
    WinDivertSend(g_handle, fake, origLen, NULL, &fa);
}
static bool sendOneFrag(const unsigned char* packet, UINT hdrLen, UINT tcpOff, UINT start, UINT len, LONG seqDelta, const WINDIVERT_ADDRESS* addr) {
    if (len == 0) return true;
    UINT total = hdrLen + len;
    if (total > MAXBUF) return false;
    static unsigned char buf[MAXBUF];
    memcpy(buf, packet, hdrLen);
    memcpy(buf + hdrLen, packet + hdrLen + start, len);
    PWINDIVERT_TCPHDR t = (PWINDIVERT_TCPHDR)(buf + tcpOff);
    t->SeqNum = htonl((LONG)(ntohl(t->SeqNum) + seqDelta));
    if ((packet[0] >> 4) == 6) ((PWINDIVERT_IPV6HDR)buf)->Length = htons((UINT16)(total - 40));
    else ((PWINDIVERT_IPHDR)buf)->Length = htons((UINT16)total);
    WINDIVERT_ADDRESS a = *addr;
    WinDivertHelperCalcChecksums(buf, total, &a, 0);
    return WinDivertSend(g_handle, buf, total, NULL, &a) != FALSE;
}
static bool sendFragments(unsigned char* packet, UINT packetLen, const WINDIVERT_ADDRESS* addr, PWINDIVERT_TCPHDR tcp, PVOID payload, UINT payloadLen, UINT splitOff) {
    if (splitOff == 0 || splitOff >= payloadLen) return false;
    UINT tcpOff = (UINT)((UINT8*)tcp - packet);
    UINT hdrLen = (UINT)((UINT8*)payload - packet);
    if (hdrLen + payloadLen > packetLen) return false;
    if (!sendOneFrag(packet, hdrLen, tcpOff, 0, splitOff, 0, addr)) return false;
    return sendOneFrag(packet, hdrLen, tcpOff, splitOff, payloadLen - splitOff, (LONG)splitOff, addr);
}
static bool sendMultiFrag(unsigned char* packet, UINT packetLen, const WINDIVERT_ADDRESS* addr, PWINDIVERT_TCPHDR tcp, PVOID payload, UINT payloadLen, const UINT* splits, int n) {
    UINT tcpOff = (UINT)((UINT8*)tcp - packet);
    UINT hdrLen = (UINT)((UINT8*)payload - packet);
    if (hdrLen + payloadLen > packetLen) return false;
    UINT prev = 0;
    for (int i = 0; i < n; i++) { if (splits[i] == 0 || splits[i] >= payloadLen || splits[i] <= prev) return false; prev = splits[i]; }
    UINT start = 0;
    for (int i = 0; i <= n; i++) {
        UINT end = (i < n) ? splits[i] : payloadLen;
        if (end <= start) break;
        if (!sendOneFrag(packet, hdrLen, tcpOff, start, end - start, (LONG)start, addr)) return false;
        start = end;
    }
    return true;
}
static bool sendRevFrag(unsigned char* packet, UINT packetLen, const WINDIVERT_ADDRESS* addr, PWINDIVERT_TCPHDR tcp, PVOID payload, UINT payloadLen, UINT splitOff) {
    UINT tcpOff = (UINT)((UINT8*)tcp - packet);
    UINT hdrLen = (UINT)((UINT8*)payload - packet);
    if (hdrLen + payloadLen > packetLen) return false;
    if (!sendOneFrag(packet, hdrLen, tcpOff, splitOff, payloadLen - splitOff, (LONG)splitOff, addr)) return false;
    return sendOneFrag(packet, hdrLen, tcpOff, 0, splitOff, 0, addr);
}
static bool isQuic(PVOID p, UINT l) { return p && l >= 1200 && (((UINT8*)p)[0] & 0xC0) == 0xC0; }

static void applyStrategy(unsigned char* packet, UINT packetLen, const WINDIVERT_ADDRESS* addr, PWINDIVERT_TCPHDR tcp, PVOID payload, UINT payloadLen, bool hasHost, UINT hostOffset, UINT hostLen, bool splitHello) {
    Strategy s = getStrategy();
    bool done = false;
    UINT tcpOff = (UINT)((UINT8*)tcp - packet);
    UINT hdrLen = (UINT)((UINT8*)payload - packet);
    (void)tcpOff; (void)hdrLen;

    switch (s) {
    case STRAT_SNI_FRAG_1: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, hasHost ? hostOffset + 1 : 2); break;
    case STRAT_SNI_FRAG_2: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, hasHost ? hostOffset + 2 : 2); break;
    case STRAT_SNI_FRAG_BEFORE: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, hasHost ? hostOffset : 2); break;
    case STRAT_FRAG_AT_2: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2); break;
    case STRAT_FRAG_AT_3: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 3); break;
    case STRAT_FAKE_TTL_HI:
    case STRAT_FAKE_TTL_LO:
    case STRAT_FAKE_WRONG_SEQ:
        if (hasHost) { bool ws = (s == STRAT_FAKE_WRONG_SEQ); sendFakePacket(packet, packetLen, addr, tcp, payload, hostOffset, hostLen, fakeTtlFor(s), ws, false); InterlockedIncrement(&g_stats.fakeSent); }
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_FAKE_BAD_CHKSUM:
        if (hasHost) { sendFakePacket(packet, packetLen, addr, tcp, payload, hostOffset, hostLen, 0, false, true); InterlockedIncrement(&g_stats.fakeSent); }
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_HOST_FAKE_SPLIT:
        if (hasHost) { sendFakePacket(packet, packetLen, addr, tcp, payload, hostOffset, hostLen, fakeTtlFor(STRAT_FAKE_TTL_HI), false, false); InterlockedIncrement(&g_stats.fakeSent); done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, hostOffset); }
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_FAKE_LO_BAD_CHK:
        if (hasHost && hostLen > 0) { sendFakePacket(packet, packetLen, addr, tcp, payload, hostOffset, hostLen, fakeTtlFor(STRAT_FAKE_TTL_LO), false, true); InterlockedIncrement(&g_stats.fakeSent); }
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_MULTISPLIT_4:
        if (hasHost && hostOffset > 4 && hostOffset + 4 < payloadLen) { UINT q = hostOffset / 4; UINT sp[4] = { q, 2 * q, 3 * q, hostOffset }; done = sendMultiFrag(packet, packetLen, addr, tcp, payload, payloadLen, sp, 4); }
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_REVERSE_FRAG:
        if (hasHost && hostOffset > 0 && hostOffset < payloadLen) done = sendRevFrag(packet, packetLen, addr, tcp, payload, payloadLen, hostOffset);
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_RECORD_FRAG: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 5); break;
    case STRAT_DESYNC:
        if (hasHost && hostOffset > 0 && hostOffset < payloadLen) { if (sendOneFrag(packet, hdrLen, tcpOff, 0, hostOffset, 0, addr)) done = sendOneFrag(packet, hdrLen, tcpOff, hostOffset, payloadLen - hostOffset, (LONG)hostOffset, addr); }
        else if (splitHello) done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2);
        break;
    case STRAT_QUIC_FAKE: done = sendFragments(packet, packetLen, addr, tcp, payload, payloadLen, 2); break;
    default: break;
    }
    if (done) { InterlockedIncrement(&g_stats.fragmented); return; }
    WinDivertSend(g_handle, packet, packetLen, NULL, addr);
    InterlockedIncrement(&g_stats.passed);
}

typedef std::vector<unsigned char> Bytes;
static void p8(Bytes& b, unsigned v) { b.push_back((unsigned char)(v & 0xFF)); }
static void p16(Bytes& b, unsigned v) { p8(b, v >> 8); p8(b, v); }
static void p24(Bytes& b, unsigned v) { p8(b, v >> 16); p16(b, v); }
static void pB(Bytes& b, const void* p, size_t n) { const unsigned char* c = (const unsigned char*)p; b.insert(b.end(), c, c + n); }
static void pExt(Bytes& o, unsigned t, const Bytes& d) { p16(o, t); p16(o, (unsigned)d.size()); o.insert(o.end(), d.begin(), d.end()); }
static unsigned char rb(unsigned& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return (unsigned char)(s & 0xFF); }

static void buildClientHello(const char* host, Bytes& out) {
    unsigned s = GetTickCount() ^ 0x9E3779B9u;
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
static TestResult testTls(const char* host) {
    size_t hl = strlen(host); if (hl == 0 || hl > 200) return TEST_NODNS;
    struct addrinfo* r = NULL; SOCKET s = connectTO(host, "443", &r);
    if (s == INVALID_SOCKET) { if (r) { freeaddrinfo(r); return TEST_NOCONN; } return TEST_NODNS; }
    Bytes hello; buildClientHello(host, hello);
    if (send(s, (const char*)&hello[0], (int)hello.size(), 0) != (int)hello.size()) { closesocket(s); freeaddrinfo(r); return TEST_BLOCKED; }
    unsigned char resp[8]; int n = recv(s, (char*)resp, sizeof(resp), 0);
    closesocket(s); freeaddrinfo(r);
    if (n > 0 && (resp[0] == 0x16 || resp[0] == 0x15)) return TEST_OK;
    return TEST_BLOCKED;
}
static TestResult testHttp(const char* host) {
    size_t hl = strlen(host); if (hl == 0 || hl > 200) return TEST_NODNS;
    struct addrinfo* r = NULL; SOCKET s = connectTO(host, "80", &r);
    if (s == INVALID_SOCKET) { if (r) { freeaddrinfo(r); return TEST_NOCONN; } return TEST_NODNS; }
    char req[512]; int rl = _snprintf_s(req, sizeof(req), _TRUNCATE, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: DPIHunter\r\nConnection: close\r\n\r\n", host);
    if (rl <= 0 || send(s, req, rl, 0) != rl) { closesocket(s); freeaddrinfo(r); return TEST_BLOCKED; }
    char resp[8]; int n = recv(s, resp, sizeof(resp) - 1, 0);
    closesocket(s); freeaddrinfo(r);
    if (n >= 5 && memcmp(resp, "HTTP/", 5) == 0) return TEST_OK;
    return TEST_BLOCKED;
}
static TestResult testHost(const char* host) {
    TestResult t = testTls(host);
    if (t == TEST_OK) return TEST_OK;
    if (t == TEST_BLOCKED && g_httpEnabled) { TestResult h = testHttp(host); if (h == TEST_OK) return TEST_OK; }
    return t;
}

static bool findWorkingStrategy(const std::vector<std::string>& hosts) {
    Strategy orig = getStrategy(); if (orig >= STRAT_BYPASS_COUNT) orig = (Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0);
    for (int step = 1; step <= STRAT_BYPASS_COUNT; step++) {
        if (!isRunning()) return false;
        Strategy cand = (Strategy)((orig + step) % STRAT_BYPASS_COUNT);
        if (cand == STRAT_QUIC_FAKE) continue;
        setStrategy(cand); updateStrategyRow(); if (sleepOrStop(300)) return false;
        int ok = 0, tested = 0;
        for (size_t i = 0; i < hosts.size(); i++) {
            TestResult r = testHost(hosts[i].c_str());
            if (r == TEST_OK) { ok++; tested++; }
            else if (r == TEST_BLOCKED) tested++;
        }
        EnterCriticalSection(&g_consoleLock);
        printf("    %stry%s %s%s%s ... ", C_DIM, C_RESET, C_CYAN, STRAT_NAMES[cand], C_RESET);
        if (tested > 0 && ok * 100 / tested >= SUCCESS_THRESHOLD) printf("%s%sOK%s\n", C_GREEN, C_BOLD, C_RESET);
        else printf("%sFAIL%s\n", C_RED, C_RESET);
        fflush(stdout); LeaveCriticalSection(&g_consoleLock);
        if (tested > 0 && ok * 100 / tested >= SUCCESS_THRESHOLD) { InterlockedExchange(&g_lastGood, (LONG)cand); logLine("FIX", C_GREEN C_BOLD, g_str.emergencyFound); return true; }
    }
    setStrategy(orig); updateStrategyRow(); return false;
}

static void emergencyRecovery(const char* host) {
    if (InterlockedCompareExchange(&g_emergencyRunning, 1, 0) != 0) return;
    DWORD now = GetTickCount(); DWORD last = (DWORD)InterlockedCompareExchange(&g_lastEmergencyTick, 0, 0);
    if (last != 0 && (now - last) < COOLDOWN_MS) { logLine("COOL", C_DIM, g_str.emergencyCooldown); InterlockedExchange(&g_emergencyRunning, 0); return; }
    InterlockedExchange(&g_lastEmergencyTick, (LONG)now);
    logLine("RST", C_RED C_BOLD, g_str.emergencyDetected);
    TestResult r = testHost(host);
    if (r == TEST_OK) logLine("RST", C_GREEN, g_str.rstBenign);
    else if (r == TEST_BLOCKED) { std::vector<std::string> h; h.push_back(host); if (!findWorkingStrategy(h)) logLine("FAIL", C_YELLOW, g_str.noFix); }
    InterlockedExchange(&g_emergencyRunning, 0);
}

static const char* DEFAULT_SITES[] = { "youtube.com", "discord.com", "twitter.com", "instagram.com", "reddit.com" };

static void pickTestSites(std::vector<std::string>& out) {
    out.clear(); static size_t cursor = 0;
    std::vector<std::string> base, pool;
    if (!g_blacklist.empty()) {
        for (std::set<std::string>::const_iterator it = g_blacklist.begin(); it != g_blacklist.end(); ++it)
            if (isPlainHost(*it)) base.push_back(*it);
    }
    else {
        for (size_t i = 0; i < sizeof(DEFAULT_SITES) / sizeof(DEFAULT_SITES[0]); i++) base.push_back(DEFAULT_SITES[i]);
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
    EnterCriticalSection(&g_consoleLock); printf("\n  "); printTs(); printf(" %sTEST%s %s\n", C_BLUE C_BOLD, C_RESET, STRAT_NAMES[cur]); fflush(stdout); LeaveCriticalSection(&g_consoleLock);
    int ok = 0; std::vector<std::string> blocked;
    for (size_t i = 0; i < sites.size(); i++) {
        if (!isRunning()) return PERIODIC_TEST;
        TestResult r = testHost(sites[i].c_str());
        EnterCriticalSection(&g_consoleLock);
        if (r == TEST_OK) { printf("    %sOK%s   %s\n", C_GREEN, C_RESET, sites[i].c_str()); ok++; }
        else if (r == TEST_BLOCKED) { printf("    %sFAIL%s %s\n", C_RED, C_RESET, sites[i].c_str()); blocked.push_back(sites[i]); }
        else printf("    %sSKIP%s %s\n", C_DIM, C_RESET, sites[i].c_str());
        fflush(stdout); LeaveCriticalSection(&g_consoleLock);
        EnterCriticalSection(&g_seenLock);
        if (r == TEST_BLOCKED) {
            if (g_failedHosts.size() < 100) g_failedHosts.insert(sites[i]);
        }
        else if (r == TEST_OK) {
            g_failedHosts.erase(sites[i]);
            g_unfixable.erase(sites[i]);
        }
        LeaveCriticalSection(&g_seenLock);
    }
    int tested = ok + (int)blocked.size(); if (tested == 0) return PERIODIC_TEST;
    int pct = (ok * 100) / tested;
    if (pct >= SUCCESS_THRESHOLD) { InterlockedExchange(&g_consecutiveFails, 0); InterlockedExchange(&g_lastGood, (LONG)cur); return PERIODIC_TEST; }
    logLine("SWAP", C_YELLOW C_BOLD, g_str.stratSwitch);
    if (findWorkingStrategy(blocked)) { InterlockedExchange(&g_consecutiveFails, 0); return PERIODIC_TEST; }

    EnterCriticalSection(&g_seenLock);
    for (size_t i = 0; i < blocked.size(); i++) {
        if (g_unfixable.size() > 100) g_unfixable.clear();
        g_unfixable.insert(blocked[i]);
    }
    LeaveCriticalSection(&g_seenLock);

    logLine("FAIL", C_YELLOW, g_str.noFix);
    LONG f = InterlockedIncrement(&g_consecutiveFails);
    if (f >= MAX_FAILS) { g_safeSince = GetTickCount(); setStrategy(STRAT_DISABLED); updateStrategyRow(); logLine("SAFE", C_YELLOW C_BOLD, g_str.safeEntered); InterlockedExchange(&g_consecutiveFails, 0); return PERIODIC_TEST; }
    return RETRY_SOON;
}

static DWORD WINAPI testThread(LPVOID) {
    if (!g_autoSwitch) { while (isRunning()) { if (sleepOrStop(1000)) break; } return 0; }
    if (sleepOrStop(FIRST_TEST_DELAY)) return 0;
    DWORD interval = PERIODIC_TEST; DWORD last = GetTickCount() - PERIODIC_TEST;
    while (isRunning()) {
        DWORD now = GetTickCount();
        if (getStrategy() == STRAT_DISABLED) {
            if ((now - g_safeSince) >= SAFE_RETRY_MS) {
                setStrategy((Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0));
                updateStrategyRow();
                logLine("SAFE", C_YELLOW, g_str.safeRetry);
                last = now - PERIODIC_TEST; interval = PERIODIC_TEST;
                EnterCriticalSection(&g_seenLock);
                g_unfixable.clear();
                LeaveCriticalSection(&g_seenLock);
            }
            if (sleepOrStop(1000)) break; continue;
        }
        if (InterlockedCompareExchange(&g_emergencyFlag, 0, 0)) {
            char h[256]; EnterCriticalSection(&g_emLock); strncpy_s(h, sizeof(h), g_emergencyHost, _TRUNCATE); InterlockedExchange(&g_emergencyFlag, 0); LeaveCriticalSection(&g_emLock);
            if (h[0]) emergencyRecovery(h); last = GetTickCount(); interval = PERIODIC_TEST; continue;
        }
        if ((now - last) >= interval) {
            last = now; InterlockedExchange(&g_emergencyRunning, 1); interval = periodicRound(); InterlockedExchange(&g_emergencyRunning, 0); last = GetTickCount();
        }
        if (sleepOrStop(250)) break;
    }
    return 0;
}

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
    static const char* skip[] = { ".local",".lan",".home",".internal",".localdomain",".arpa",".corp",".intranet",".private",".home.arpa" };
    for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++) if (endsWith(name, skip[i])) return false;
    return true;
}
static bool dohAvailable() {
    if (!InterlockedCompareExchange(&g_dohPaused, 0, 0)) return true;
    DWORD until = (DWORD)InterlockedCompareExchange(&g_dohPausedUntil, 0, 0);
    if ((int)(GetTickCount() - until) >= 0) { InterlockedExchange(&g_dohPaused, 0); InterlockedExchange(&g_dohFail, 0); logLine("DNS", C_GREEN, g_str.dnsBack); return true; }
    return false;
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
        if (dohQuery(c, prov, q, ql, resp) && (resp[2] & 0x80)) { ok = true; InterlockedExchange(&g_dohPref, prov); }
    }
    if (ok) {
        resp[0] = q[0]; resp[1] = q[1];
        size_t lim = (q[10] | q[11]) ? 1232 : 512;
        if (resp.size() > lim) makeTrunc(resp);
        if (sendDnsReply(j, &resp[0], (UINT)resp.size())) { InterlockedIncrement(&g_stats.dnsDoh); InterlockedExchange(&g_dohFail, 0); return; }
    }
    LONG f = InterlockedIncrement(&g_dohFail);
    if (f >= DNS_FAIL_LIMIT) {
        InterlockedExchange(&g_dohPausedUntil, (LONG)(GetTickCount() + DNS_PAUSE_MS));
        if (InterlockedCompareExchange(&g_dohPaused, 1, 0) == 0) logLine("DNS", C_YELLOW, g_str.dnsDown);
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

static DWORD WINAPI statsThread(LPVOID) {
    LONG last = -1;
    while (isRunning()) {
        if (sleepOrStop(30000)) break;
        LONG t = g_stats.total; if (t == last) continue; last = t;
        Strategy cur = getStrategy();
        EnterCriticalSection(&g_consoleLock);
        printf("  "); printTs();
        printf(" %sSTAT%s %spkts=%ld frag=%ld fake=%ld quic=%ld rst=%ld pdrop=%ld pass=%ld doh=%ld/%ld%s | %s%s%s\n",
            C_MAGENTA, C_RESET, C_DIM, (long)g_stats.total, (long)g_stats.fragmented, (long)g_stats.fakeSent,
            (long)g_stats.quicBlocked, (long)g_stats.rstDetected, (long)g_stats.passiveDropped,
            (long)g_stats.passed, (long)g_stats.dnsDoh, (long)g_stats.dnsFallback, C_RESET, C_CYAN, STRAT_NAMES[cur], C_RESET);
        fflush(stdout); LeaveCriticalSection(&g_consoleLock);
    }
    return 0;
}

static std::string buildFilter(const std::vector<int>& ports, bool dns) {
    std::string dst, src;
    for (size_t i = 0; i < ports.size(); i++) { if (i) { dst += " or "; src += " or "; } dst += "tcp.DstPort == " + std::to_string(ports[i]); src += "tcp.SrcPort == " + std::to_string(ports[i]); }
    std::string magic = "((tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01) or (tcp.Payload[0] >= 0x41 and tcp.Payload[0] <= 0x5A))";
    std::string f = "(outbound and tcp and tcp.PayloadLength >= 6 and (" + dst + ") and " + magic + ")";
    f += " or (outbound and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0)";
    f += " or (inbound and tcp and tcp.Rst and (" + src + "))";
    f += " or (inbound and tcp and tcp.Syn and tcp.Ack and (" + src + "))";
    if (dns) f += " or (outbound and udp and udp.DstPort == 53 and udp.PayloadLength > 0)";
    return f;
}

static const char* explainOpen(DWORD e) {
    switch (e) {
    case 2: return "WinDivert64.sys not found (keep next to .exe)";
    case 5: return "access denied (run as administrator)";
    case 87: return "invalid filter / WinDivert.dll vs .sys mismatch";
    case 577: return "driver signature rejected (WinDivert 2.2 signed)";
    case 654: return "incompatible driver version";
    case 1275: return "driver blocked (Defender / memory integrity)";
    default: return "check WinDivert.dll / WinDivert64.sys";
    }
}

static void askAnalyzeSites() {
    g_analyzeSites.clear();
    printf("\n  %sUse custom sites for analysis? (y/N): %s", C_YELLOW, C_RESET); fflush(stdout);
    char ans[16];
    if (fgets(ans, sizeof(ans), stdin)) {
        std::string a = lower(trim(ans));
        if (a == "y" || a == "yes") {
            printf("  %sSites, comma separated (e.g. discord.com,twitter.com): %s", C_YELLOW, C_RESET); fflush(stdout);
            char buf[512];
            if (fgets(buf, sizeof(buf), stdin)) {
                std::string s = trim(buf); size_t pos = 0;
                while (pos < s.size()) {
                    size_t next = s.find(',', pos);
                    std::string site = lower(trim(s.substr(pos, next == std::string::npos ? std::string::npos : next - pos)));
                    size_t p = site.find("://"); if (p != std::string::npos) site = site.substr(p + 3);
                    p = site.find('/');          if (p != std::string::npos) site = site.substr(0, p);
                    if (isPlainHost(site)) g_analyzeSites.push_back(site);
                    if (next == std::string::npos) break;
                    pos = next + 1;
                }
            }
        }
    }
}

static void runAnalyzeBody() {
    std::vector<std::string> testSites = g_analyzeSites;
    if (testSites.empty()) {
        static const char* def[] = { "youtube.com", "twitter.com", "discord.com", "wikipedia.org", "instagram.com", "reddit.com" };
        for (int i = 0; i < 6; i++) testSites.push_back(def[i]);
    }

    printf("\n  %s%sNETWORK ANALYSIS%s\n\n", C_BOLD, C_WHITE, C_RESET);
    const int nS = (int)testSites.size();
    printf("  %s%-20s", C_BOLD C_WHITE, "Strategy");
    for (int i = 0; i < nS; i++) printf(" %-14s", testSites[i].c_str());
    printf("%s\n  ", C_RESET);
    for (int i = 0; i < 20 + nS * 15; i++) putchar('-');
    printf("\n");

    Strategy orig = getStrategy();
    for (int s = 0; s < STRAT_BYPASS_COUNT; s++) {
        if (!isRunning()) break;
        setStrategy((Strategy)s); if (sleepOrStop(300)) break;
        printf("  %s%-20s%s", C_CYAN, STRAT_NAMES[s], C_RESET); fflush(stdout);
        int ok = 0;
        for (int i = 0; i < nS; i++) {
            TestResult r = testHost(testSites[i].c_str());
            if (r == TEST_OK) { printf(" %s%-14s%s", C_GREEN, "OK", C_RESET); ok++; }
            else if (r == TEST_BLOCKED) printf(" %s%-14s%s", C_RED, "FAIL", C_RESET);
            else printf(" %s%-14s%s", C_DIM, "SKIP", C_RESET);
            fflush(stdout);
        }
        int need = nS >= 3 ? nS - 2 : nS;
        if (ok > 0 && ok >= need) printf("  %s<-- works%s\n", C_GREEN C_BOLD, C_RESET);
        else if (ok > 0 && ok * 2 >= nS) printf("  %s<-- partial%s\n", C_YELLOW C_BOLD, C_RESET);
        else printf("\n");
    }
    setStrategy(orig);
    printf("\n  %sAnalysis complete.%s\n", C_GREEN, C_RESET);
    fflush(stdout);
}

static DWORD WINAPI analyzeThread(LPVOID) {
    if (sleepOrStop(1500)) return 0;
    runAnalyzeBody();
    requestStop();
    return 0;
}

static DWORD WINAPI dnsSelfTestThread(LPVOID) {
    if (sleepOrStop(2000)) return 0;
    std::string base = "example.com";
    for (std::set<std::string>::const_iterator it = g_blacklist.begin(); it != g_blacklist.end(); ++it)
        if (isPlainHost(*it)) { base = *it; break; }
    char name[300];
    sprintf_s(name, sizeof(name), "dpih%lu.%s", (unsigned long)GetTickCount(), base.c_str());
    LONG before = g_stats.dnsDoh;
    struct addrinfo hints; memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL; getaddrinfo(name, "80", &hints, &res); if (res) freeaddrinfo(res);
    Sleep(300);
    if (g_stats.dnsDoh > before) logLine("DNS", C_GREEN, "Self-test OK: queries are answered via DoH");
    else logLine("DNS", C_YELLOW, "Self-test: query NOT intercepted (VPN, browser DoH or custom DNS?)");
    return 0;
}

static int runTool(Settings& st) {
    InterlockedExchange(&g_running, TRUE);
    if (g_stopEvent) ResetEvent(g_stopEvent);
    if (g_doneEvent) ResetEvent(g_doneEvent);
    InterlockedExchange(&g_emergencyFlag, 0);
    InterlockedExchange(&g_emergencyRunning, 0);
    InterlockedExchange(&g_consecutiveFails, 0);
    InterlockedExchange(&g_dohPaused, 0);
    InterlockedExchange(&g_dohFail, 0);
    InterlockedExchange(&g_lastEmergencyTick, 0);
    g_rstCount = 0;
    g_rstWindowStart = 0;
    g_rstLastHost.clear();
    EnterCriticalSection(&g_seenLock);
    g_failedHosts.clear();
    g_unfixable.clear();
    LeaveCriticalSection(&g_seenLock);
    EnterCriticalSection(&g_dnsLock);
    while (!g_dnsQueue.empty()) { delete g_dnsQueue.front(); g_dnsQueue.pop_front(); }
    LeaveCriticalSection(&g_dnsLock);
    if (getStrategy() == STRAT_DISABLED)
        setStrategy((Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0));

    g_blacklist.clear();
    char bl[128]; strcpy_s(bl, sizeof(bl), g_str.blDisabled);
    {
        const char* names[] = { "blacklist.txt", "listem.txt", "list.txt" };
        for (int i = 0; i < 3; i++) { std::ifstream t(names[i]); if (t.is_open()) { t.close(); loadBlacklist(names[i]); break; } }
        if (!g_blacklist.empty()) sprintf_s(bl, sizeof(bl), "%d entries", (int)g_blacklist.size());
    }

    if (st.dnsMode != DNS_OFF) {
        if (st.dohAuto) {
            printf("\n  %sMeasuring DNS latency (%d providers)...%s\n", C_BOLD C_CYAN, DOH_COUNT, C_RESET); fflush(stdout);
            std::vector<DnsTestResult> results;
            int rec = runDnsTests(results, false);
            if (rec >= 0) {
                st.dohProvider = rec;
                printf("  %sAuto-selected:%s %s%s%s %s(%lums)%s\n\n",
                    C_BOLD, C_RESET, C_GREEN C_BOLD, DOH[rec].name.c_str(), C_RESET,
                    C_DIM, (long)results[rec].avgMs, C_RESET);
            }
            else {
                printf("  %sNo DNS reachable, disabling DoH.%s\n\n", C_YELLOW, C_RESET);
                st.dnsMode = DNS_OFF;
            }
        }
        else if (g_dohForced || !g_askDnsInteractive) {
            printf("\n  %sUsing DoH provider: %s%s\n\n", C_BOLD, DOH[st.dohProvider].name.c_str(), C_RESET);
        }
        else {
            printf("\n  %sMeasuring DNS latency (%d providers)...%s\n", C_BOLD C_CYAN, DOH_COUNT, C_RESET); fflush(stdout);
            doDnsTestInteractive(st);
        }
    }

    g_dnsEnabled = (st.dnsMode != DNS_OFF);
    InterlockedExchange(&g_dohPref, st.dohProvider);

    char dnsBuf[96];
    if (g_dnsEnabled) sprintf_s(dnsBuf, sizeof(dnsBuf), "%s - %s", g_str.dnsOn, DOH[st.dohProvider].name.c_str());
    else strcpy_s(dnsBuf, sizeof(dnsBuf), g_str.dnsOff);

    std::string ports;
    for (size_t i = 0; i < st.ports.size(); i++) { if (i) ports += ", "; ports += std::to_string(st.ports[i]); }
    printPanel(bl, dnsBuf, ports.c_str(), g_httpEnabled ? g_str.httpOn : g_str.httpOff, g_fakeTtl);

    std::string filter = buildFilter(st.ports, g_dnsEnabled);
    g_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_handle == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError(); printf("  %s%s%lu%s\n", C_RED, g_str.openFail, e, C_RESET);
        printf("  %s%s%s\n", C_YELLOW, explainOpen(e), C_RESET);
        printf("\n  %sTroubleshooting:%s\n    - Run as administrator\n    - Check WinDivert.dll + WinDivert64.sys are next to the .exe\n    - Disable Memory Integrity (Core Isolation) in Windows Security\n    - Add WinDivert files to your antivirus exclusions\n", C_BOLD, C_RESET);
        pauseAny(); return 1;
    }
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);

    printf("  %s%s:%s\n\n", C_DIM, g_str.logHeader, C_RESET); fflush(stdout);

    // Claude's Fix: Analyze runs in its own thread, main loop receives packets to keep internet alive
    HANDLE hTest = CreateThread(NULL, 0, InterlockedCompareExchange(&g_analyzeMode, 0, 0) ? analyzeThread : testThread, NULL, 0, NULL);
    HANDLE hStats = CreateThread(NULL, 0, statsThread, NULL, 0, NULL);
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
            if (++recvErr > 50) { char msg[96]; sprintf_s(msg, sizeof(msg), "WinDivertRecv keeps failing (error %lu), stopping", e); logLine("ERR", C_RED C_BOLD, msg); break; }
            Sleep(10); continue;
        }
        recvErr = 0;

        PWINDIVERT_IPHDR ip = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_TCPHDR tcp = NULL; PWINDIVERT_UDPHDR udp = NULL; PVOID payload = NULL; UINT payloadLen = 0;
        if (!WinDivertHelperParsePacket(g_packet, pl, &ip, &ip6, NULL, NULL, NULL, &tcp, &udp, &payload, &payloadLen, NULL, NULL)) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); continue; }
        if (!ip && !ip6) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); continue; }

        if (!addr.Outbound && tcp && tcp->Syn && tcp->Ack) {
            IpKey sk = ip ? keyV4(ip->SrcAddr) : keyV6(ip6->SrcAddr);
            int ttlSeen = ip ? (int)ip->TTL : (int)ip6->HopLimit; int initTtl = ttlSeen <= 64 ? 64 : (ttlSeen <= 128 ? 128 : 255); int hops = initTtl - ttlSeen;
            if (hops >= 1 && hops <= 40) { HopEntry& he = g_hops[hopHash(sk)]; he.key = sk; he.hops = (BYTE)hops; }
            WinDivertSend(g_handle, g_packet, pl, NULL, &addr); continue;
        }

        if (!addr.Outbound && tcp && tcp->Rst) {
            IpKey k = ip ? keyV4(ip->SrcAddr) : keyV6(ip6->SrcAddr); USHORT sp = ntohs(tcp->SrcPort); std::string h = matchRecent(k, sp);
            if (g_blockPassive && !h.empty() && ip && (ntohs(ip->Id) == 0 || ntohs(ip->Id) == 1)) { InterlockedIncrement(&g_stats.passiveDropped); continue; }
            if (!h.empty()) {
                InterlockedIncrement(&g_stats.rstDetected); DWORD now = GetTickCount();
                if (g_rstCount == 0 || (now - g_rstWindowStart) > RST_WINDOW_MS || h != g_rstLastHost) { g_rstWindowStart = now; g_rstCount = 0; g_rstLastHost = h; }
                g_rstCount++;
                if (g_rstCount >= RST_TRIGGER && !InterlockedCompareExchange(&g_emergencyRunning, 0, 0)) {
                    g_rstCount = 0; EnterCriticalSection(&g_emLock); strncpy_s(g_emergencyHost, sizeof(g_emergencyHost), h.c_str(), _TRUNCATE); InterlockedExchange(&g_emergencyFlag, 1); LeaveCriticalSection(&g_emLock);
                }
            }
            WinDivertSend(g_handle, g_packet, pl, NULL, &addr); continue;
        }

        InterlockedIncrement(&g_stats.total);

        if (udp) {
            USHORT dp = ntohs(udp->DstPort);
            if (dp == 53) { handleDns(pl, &addr, ip, ip6, payload, payloadLen); continue; }
            if (payload && dp == 443 && getStrategy() != STRAT_DISABLED && isQuic(payload, payloadLen)) {
                if (getStrategy() == STRAT_QUIC_FAKE) {
                    if (pl <= MAXBUF) {
                        static unsigned char qf[MAXBUF]; memcpy(qf, g_packet, pl); UINT qh = (UINT)((UINT8*)payload - g_packet);
                        if (payloadLen > 5 && qh + payloadLen <= pl) memset(qf + qh + 5, 0xA5, payloadLen - 5);
                        WINDIVERT_ADDRESS fa = addr; if ((qf[0] >> 4) == 6) ((PWINDIVERT_IPV6HDR)qf)->HopLimit = 2; else ((PWINDIVERT_IPHDR)qf)->TTL = 2;
                        WinDivertHelperCalcChecksums(qf, pl, &fa, 0); WinDivertSend(g_handle, qf, pl, NULL, &fa);
                    }
                }
                else if (g_dropQuic) { InterlockedIncrement(&g_stats.quicBlocked); continue; }
            }
            WinDivertSend(g_handle, g_packet, pl, NULL, &addr); InterlockedIncrement(&g_stats.passed); continue;
        }

        if (isLocalDst(ip, ip6)) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); InterlockedIncrement(&g_stats.passed); continue; }
        if (!tcp || !payload || payloadLen < 6) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); InterlockedIncrement(&g_stats.passed); continue; }

        UINT8* p8p = (UINT8*)payload; bool isTls = (p8p[0] == 0x16 && p8p[5] == 0x01); bool isHttp = false;
        if (!isTls && g_httpEnabled && payloadLen >= 8) isHttp = isHttpRequest(p8p, payloadLen);
        if (!isTls && !isHttp) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); InterlockedIncrement(&g_stats.passed); continue; }

        bool splitHello = false; if (isTls) { UINT recLen = ((UINT)p8p[3] << 8) | p8p[4]; if (recLen + 5 > payloadLen) splitHello = true; }

        char* hostPtr = NULL; unsigned int hostLen = 0; UINT hostOff = 0;
        if (isTls) { unsigned int hl = 0; if (extractSni((char*)p8p, payloadLen, &hostPtr, &hl)) { hostLen = hl; hostOff = (UINT)(hostPtr - (char*)p8p); } }
        else { if (!extractHttpHost((const char*)p8p, payloadLen, &hostPtr, &hostLen, &hostOff)) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); InterlockedIncrement(&g_stats.passed); continue; } }

        bool hasHost = (hostPtr != NULL);
        if (hasHost) {
            std::string host = lower(std::string(hostPtr, hostLen));
            if (!g_blacklist.empty() && !isBlacklisted(host)) { WinDivertSend(g_handle, g_packet, pl, NULL, &addr); InterlockedIncrement(&g_stats.passed); continue; }
            if (isTls) { IpKey k = ip ? keyV4(ip->DstAddr) : keyV6(ip6->DstAddr); rememberFrag(k, ntohs(tcp->DstPort), host.c_str()); }
        }

        applyStrategy(g_packet, pl, &addr, tcp, payload, payloadLen, hasHost, hostOff, (UINT)hostLen, splitHello);
    }

    InterlockedExchange(&g_running, FALSE); if (g_stopEvent) SetEvent(g_stopEvent);
    if (hTest) { WaitForSingleObject(hTest, INFINITE); CloseHandle(hTest); }
    if (hStats) { WaitForSingleObject(hStats, INFINITE); CloseHandle(hStats); }
    if (hSelf) { WaitForSingleObject(hSelf, INFINITE); CloseHandle(hSelf); }
    if (dnsThreads > 0) { WaitForMultipleObjects((DWORD)dnsThreads, hDns, TRUE, INFINITE); for (int i = 0; i < dnsThreads; i++) CloseHandle(hDns[i]); }
    EnterCriticalSection(&g_dnsLock); while (!g_dnsQueue.empty()) { delete g_dnsQueue.front(); g_dnsQueue.pop_front(); } LeaveCriticalSection(&g_dnsLock);
    if (g_dnsSem) { CloseHandle(g_dnsSem); g_dnsSem = NULL; }

    EnterCriticalSection(&g_handleLock); HANDLE h = g_handle; g_handle = INVALID_HANDLE_VALUE; WinDivertClose(h); LeaveCriticalSection(&g_handleLock);
    if (g_autoSwitch) saveLastStrategy();
    if (g_doneEvent) SetEvent(g_doneEvent);
    printf("\n  %s%s%s\n", C_YELLOW, g_str.stopped, C_RESET);
    return 0;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8); SetConsoleCP(CP_UTF8); setWorkingDir(); SetConsoleTitleA("DPI Hunter v5.1");
    enableAnsi(); disableQuickEdit();
    InitializeCriticalSection(&g_consoleLock); InitializeCriticalSection(&g_handleLock); InitializeCriticalSection(&g_emLock);
    InitializeCriticalSection(&g_seenLock); InitializeCriticalSection(&g_dnsLock); InitializeCriticalSection(&g_logLock);
    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL); g_doneEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    for (int i = 1; i < argc; i++) { std::string a = lower(argv[i]); if (a == "--help" || a == "-h" || a == "-?") { printHelp(); return 0; } }

    if (!isAdmin()) {
        if (relaunchAsAdmin(argc, argv)) ExitProcess(0);
        printf("  %sCould not get administrator rights.%s\n", C_RED, C_RESET);
        system("pause"); return 1;
    }

    Settings st; bool complete = false; configRead(st, complete); if (!complete) configWrite(st); parseArgs(argc, argv, st);

    bool forcedCLI = false;
    for (int i = 1; i < argc; i++) {
        std::string a = lower(argv[i]);
        if (a == "--auto" || a == "--manual" || a == "--test" || a == "--analyze" || a == "--strategy" || a.find("--strategy=") == 0) { forcedCLI = true; break; }
    }

    g_httpEnabled = st.httpEnabled; g_fakeTtl = st.fakeTtl; g_dnsMode = st.dnsMode; g_logEnabled = st.logEnabled;

    WSADATA wsa; if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("  %sWSAStartup failed%s\n", C_RED, C_RESET); system("pause"); return 1; }
    int exitCode = 0;

    while (true) {
        RunMode mode = st.runMode;
        if (!forcedCLI) {
            mode = mainMenu(st);
            if (mode == RUN_HELP) { continue; }
            if (mode == RUN_EXIT) break;

            g_httpEnabled = st.httpEnabled;
            g_fakeTtl = st.fakeTtl;
            g_dnsMode = st.dnsMode;
            g_logEnabled = st.logEnabled;
        }

        g_askDnsInteractive = (mode == RUN_MANUAL && !forcedCLI);

        if (mode == RUN_TEST) {
            printf("\n  %sMeasuring DNS latency (%d providers)...%s\n", C_BOLD C_CYAN, DOH_COUNT, C_RESET); fflush(stdout);
            Settings testSt = st;
            testSt.dohAuto = false;
            doDnsTestInteractive(testSt);
            pauseAny();
            if (forcedCLI) break;
            continue;
        }

        if (mode == RUN_ANALYZE) {
            askAnalyzeSites();
            g_analyzeMode = 1; g_autoSwitch = false;
            exitCode = runTool(st);
            g_analyzeMode = 0;
            pauseAny();
            if (forcedCLI) break;
            continue;
        }

        if (mode == RUN_MANUAL && !forcedCLI && !g_menuStrategy) {
            int strat = manualStrategyMenu();
            if (strat < 0) { if (forcedCLI) break; continue; }
            setStrategy((Strategy)strat); st.dohAuto = false;
            printf("\n  %sStrategy selected: %s%s\n\n", C_GREEN, STRAT_NAMES[strat], C_RESET);
        }
        else if (mode == RUN_MANUAL) {
            setStrategy((Strategy)st.manualStrategy);
            st.dohAuto = false;
        }
        g_menuStrategy = false;

        g_autoSwitch = (mode != RUN_MANUAL);
        if (mode == RUN_AUTO) {
            int ls = loadLastStrategy();
            if (ls >= 0) { setStrategy((Strategy)ls); InterlockedExchange(&g_lastGood, (LONG)ls); }
        }
        exitCode = runTool(st);

        if (exitCode != 0) pauseAny();
        if (forcedCLI) break;
        continue;
    }

    printf("\n  %sPress any key to exit...%s", C_DIM, C_RESET); fflush(stdout); _getch();
    WSACleanup(); return exitCode;
}
