/*
 * ============================================================================
 *  DPI Hunter v2.1 - Adaptive DPI Circumvention Tool (stability rewrite)
 *  by astegtam
 *
 *  What changed compared to v2.0 (short version):
 *    - Ctrl+C / closing the window now really stops the program (no hang)
 *    - WinDivert only captures what we need (TLS to port 443) -> far less load
 *    - Fake-packet strategies now send a REAL fake (harmless SNI), not a copy
 *    - Connection test uses a realistic TLS ClientHello (fewer false "FAIL")
 *    - A strategy is only switched when a site is really blocked
 *      (DNS errors / connect errors are NOT treated as DPI blocking)
 *    - Safe-Mode is temporary: the program retries after SAFE_RETRY_MS
 *    - Console "status line" update is thread-safe and checks its position
 *    - Working directory is fixed after the admin restart
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable: 28159)   // GetTickCount deprecated

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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
#include <fstream>

#include "windivert.h"

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "ws2_32.lib")

 // ---------------------------------------------------------------------------
 //  Constants (times are in milliseconds)
 // ---------------------------------------------------------------------------
#define MAXBUF                0xFFFF
#define AUTO_TEST_TIMEOUT     3000
#define FIRST_TEST_DELAY_MS   8000
#define PERIODIC_TEST_MS      300000     // 5 min between normal test rounds
#define RETRY_SOON_MS         60000      // after a failed round, test again in 1 min
#define EMERGENCY_DELAY_MS    300
#define TEST_SITES_MAX        3
#define SUCCESS_THRESHOLD     60         // % of sites that must work
#define RECENT_MAX            64
#define RECENT_TTL_MS         1500
#define SEEN_HOSTS_MAX        40
#define CONFIG_FILE           "dpi_hunter.cfg"
#define EMERGENCY_COOLDOWN_MS 60000      // at most one RST recovery per minute
#define MAX_CONSEC_FAILS      3          // failed rounds in a row -> Safe-Mode
#define SAFE_RETRY_MS         600000     // Safe-Mode lasts 10 min, then we retry
#define RST_TRIGGER_COUNT     3          // RSTs needed ...
#define RST_WINDOW_MS         15000      // ... inside this time window

// ---------------------------------------------------------------------------
//  ANSI colors
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
//  Strategies
// ---------------------------------------------------------------------------
enum Strategy {
    STRAT_SNI_FRAG_1 = 0,       // split the packet 1 byte after the SNI starts
    STRAT_SNI_FRAG_2,           // split 2 bytes after the SNI starts
    STRAT_SNI_FRAG_BEFORE,      // split right before the SNI
    STRAT_FRAG_AT_1,            // split at byte 1 of the TLS data
    STRAT_FRAG_AT_2,            // split at byte 2 (same idea as GoodbyeDPI -e 2)
    STRAT_FRAG_AT_3,            // split at byte 3
    STRAT_FAKE_TTL_3,           // fake ClientHello that dies after 3 hops
    STRAT_FAKE_TTL_6,           // fake ClientHello that dies after 6 hops
    STRAT_FAKE_TTL_3_WRONG_SEQ, // fake with TTL 3 and a wrong sequence number
    STRAT_FAKE_BAD_CHKSUM,      // fake with a broken TCP checksum
    STRAT_DISABLED,             // Safe-Mode (passthrough)
    STRAT_COUNT
};

#define STRAT_BYPASS_COUNT  STRAT_DISABLED   // number of real strategies

static const char* STRATEGY_NAMES[STRAT_COUNT] = {
    "SNI-Frag-1", "SNI-Frag-2", "SNI-Frag-Before",
    "Frag-At-1", "Frag-At-2", "Frag-At-3",
    "Fake-TTL-3", "Fake-TTL-6", "Fake-TTL-3-WrongSEQ", "Fake-BadChecksum",
    "Safe-Mode"
};

// ---------------------------------------------------------------------------
//  Language
// ---------------------------------------------------------------------------
enum Lang { LANG_TR, LANG_EN };

// ---------------------------------------------------------------------------
//  Global state
//  "volatile LONG" + Interlocked...() = a number that several threads can
//  read/write safely.
// ---------------------------------------------------------------------------
static volatile LONG g_running = TRUE;
static volatile LONG g_currentStrategy = STRAT_FRAG_AT_2;  // default (like GoodbyeDPI -e 2)
static volatile LONG g_lastGood = STRAT_FRAG_AT_2;         // last strategy that passed a test
static HANDLE        g_handle = INVALID_HANDLE_VALUE;      // WinDivert handle
static HANDLE        g_stopEvent = NULL;                   // "please stop" signal for threads
static HANDLE        g_doneEvent = NULL;                   // "main finished cleanup" signal

static unsigned char g_packet[MAXBUF];                     // only the main thread uses this

static SHORT             g_statusStrategyRow = -1;
static CRITICAL_SECTION  g_consoleLock;                    // one thread prints at a time

static volatile LONG     g_emergencyFlag = 0;
static volatile LONG     g_emergencyRunning = 0;
static volatile LONG     g_lastEmergencyTick = 0;
static volatile LONG     g_consecutiveFails = 0;
static char              g_emergencyHost[256] = { 0 };
static CRITICAL_SECTION  g_emLock;

// RST counting (main thread only)
static DWORD g_rstWindowStart = 0;
static int   g_rstCount = 0;

// Remember hosts we recently sent a ClientHello to (main thread only)
struct RecentFrag {
    DWORD   dstIP;
    USHORT  dstPort;
    DWORD   tick;
    char    host[128];
};
static RecentFrag        g_recent[RECENT_MAX];
static volatile LONG     g_recentIdx = 0;

static CRITICAL_SECTION  g_seenLock;
static std::set<std::string> g_seenHosts;

static inline bool isRunning() {
    return InterlockedCompareExchange(&g_running, 1, 1) != 0;
}
static inline Strategy getStrategy() {
    return (Strategy)InterlockedCompareExchange(&g_currentStrategy, 0, 0);
}
static inline void setStrategy(Strategy s) {
    InterlockedExchange(&g_currentStrategy, (LONG)s);
}

// Sleep that wakes up immediately when the program is stopping.
// Returns true  -> we are stopping, leave your loop
// Returns false -> time passed normally
static bool sleepOrStop(DWORD ms) {
    if (!g_stopEvent) { Sleep(ms); return !isRunning(); }
    return WaitForSingleObject(g_stopEvent, ms) == WAIT_OBJECT_0;
}

// ---------------------------------------------------------------------------
//  Ctrl+C / window close
//  FIX: the old version only set a flag, but the main loop sits inside
//  WinDivertRecv() and never looked at the flag until the next packet came.
//  WinDivertShutdown() makes WinDivertRecv() return immediately.
// ---------------------------------------------------------------------------
static void requestStop() {
    InterlockedExchange(&g_running, FALSE);
    if (g_stopEvent) SetEvent(g_stopEvent);
    HANDLE h = g_handle;
    if (h != INVALID_HANDLE_VALUE && h != NULL)
        WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
}

static BOOL WINAPI consoleHandler(DWORD sig) {
    switch (sig) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        requestStop();
        // For "close window" Windows kills us after a few seconds,
        // so give main() a moment to close WinDivert cleanly.
        if (sig != CTRL_C_EVENT && sig != CTRL_BREAK_EVENT && g_doneEvent)
            WaitForSingleObject(g_doneEvent, 4000);
        return TRUE;
    default:
        return FALSE;
    }
}

// ---------------------------------------------------------------------------
//  Console helpers
// ---------------------------------------------------------------------------
static void enableAnsi() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        mode |= 0x0004;   // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(hOut, mode);
    }
}

static void disableQuickEdit() {
    // Quick-edit freezes the program when you click in the window. Turn it off.
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hIn, &mode)) {
        mode &= ~ENABLE_QUICK_EDIT_MODE;
        mode &= ~ENABLE_MOUSE_INPUT;
        mode |= ENABLE_EXTENDED_FLAGS;
        SetConsoleMode(hIn, mode);
    }
}

static void printTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("%s[%02d:%02d:%02d]%s", C_DIM,
        st.wHour, st.wMinute, st.wSecond, C_RESET);
}

// FIX: after "Run as administrator" the working directory can be System32.
// Then dpi_hunter.cfg / blacklist.txt would be searched/written in the wrong
// folder. We move to the folder of the .exe first.
static void setWorkingDirToExe() {
    char p[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, p, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    char* slash = strrchr(p, '\\');
    if (slash) { *slash = 0; SetCurrentDirectoryA(p); }
}

// ---------------------------------------------------------------------------
//  Config
// ---------------------------------------------------------------------------
static bool configReadLang(Lang& out) {
    std::ifstream f(CONFIG_FILE);
    if (!f.is_open()) return false;

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
            line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t s = line.find_first_not_of(" \t");
        if (s == std::string::npos) continue;
        line = line.substr(s);
        if (line.empty() || line[0] == '#') continue;

        if (line.compare(0, 5, "lang=") == 0) {
            std::string v = line.substr(5);
            for (size_t i = 0; i < v.size(); i++)
                if (v[i] >= 'A' && v[i] <= 'Z') v[i] = (char)(v[i] - 'A' + 'a');
            if (v == "tr") { out = LANG_TR; return true; }
            if (v == "en") { out = LANG_EN; return true; }
        }
    }
    return false;
}

static void configWriteLang(Lang l) {
    std::ofstream f(CONFIG_FILE);
    if (!f.is_open()) return;
    f << "# DPI Hunter configuration\n";
    f << "# Delete this file to change language\n";
    f << "lang=" << ((l == LANG_TR) ? "tr" : "en") << "\n";
    f.close();
}

// ---------------------------------------------------------------------------
//  Language menu
// ---------------------------------------------------------------------------
static Lang languageMenu() {
    printf("\n");
    printf("  %sSelect Language / Dil Secin%s\n", C_BOLD C_CYAN, C_RESET);
    printf("\n");
    printf("    %s[1]%s  Turkce\n", C_GREEN C_BOLD, C_RESET);
    printf("    %s[2]%s  English\n", C_GREEN C_BOLD, C_RESET);
    printf("\n");
    printf("  %sYour choice [1-2]: %s", C_YELLOW C_BOLD, C_RESET);
    fflush(stdout);

    while (true) {
        int ch = _getch();
        if (ch == '1') { printf("1\n\n"); return LANG_TR; }
        if (ch == '2') { printf("2\n\n"); return LANG_EN; }
        if (ch == 27) { printf("\n");   ExitProcess(0); }
    }
}

// ---------------------------------------------------------------------------
//  Localized messages
//  NOTE: the order of the fields must match the order of the strings below.
// ---------------------------------------------------------------------------
struct Messages {
    const char* adminRestart;
    const char* adminFail;
    const char* openFail;
    const char* stopped;
    const char* strategyNow;
    const char* stratSwitch;
    const char* emergencyDetected;
    const char* emergencyFound;
    const char* emergencyFailed;
    const char* emergencyCooldown;
    const char* safeModeEntered;
    const char* safeModeStay;
    const char* lblStatus;
    const char* lblStrategy;
    const char* lblBlacklist;
    const char* statusActive;
    const char* blDisabled;
    const char* logHeader;
    const char* safeModeRetry;
    const char* noFix;
    const char* noValidTest;
    const char* rstBenign;
};

static const Messages MSG_TR = {
    "Yonetici izinleri gerekli. Yeniden baslatiliyor...\n",
    "Yonetici olarak baslatilamadi.\n",
    "WinDivert acilamadi! Hata: ",
    "Durduruldu",
    "Strateji",
    "Degistiriliyor",
    "Birden fazla DPI reset algilandi",
    "Sabitlendi",
    "Basarisiz",
    "Bekleme (spam onlendi)",
    "Guvenli moda gecildi (10 dk sonra tekrar denenecek)",
    "Guvenli mod aktif",
    "Durum",
    "Strateji",
    "Karaliste",
    "AKTIF",
    "Kapali (tum TLS korunuyor)",
    "Gunluk",
    "Guvenli mod suresi doldu, strateji tekrar deneniyor",
    "Hicbir strateji cozmedi (IP/DNS engeli olabilir)",
    "Gecerli test yapilamadi (DNS/baglanti hatasi), strateji degistirilmedi",
    "RST zararsiz cikti, site aciliyor"
};

static const Messages MSG_EN = {
    "Admin privileges required. Restarting...\n",
    "Could not restart as admin.\n",
    "WinDivert could not be opened! Error: ",
    "Stopped",
    "Strategy",
    "Switching",
    "Several DPI resets detected",
    "Locked in",
    "Failed",
    "Cooldown (spam prevented)",
    "Entered Safe-Mode (will retry in 10 min)",
    "Safe-Mode active",
    "Status",
    "Strategy",
    "Blacklist",
    "ACTIVE",
    "disabled (all TLS protected)",
    "Log",
    "Safe-Mode time is over, trying the strategy again",
    "No strategy fixed it (may be an IP/DNS block)",
    "No valid test (DNS/connect error), strategy not changed",
    "RST was harmless, site is reachable"
};

static const Messages& pickMessages(Lang l) {
    return (l == LANG_TR) ? MSG_TR : MSG_EN;
}

static bool parseLangArg(int argc, char** argv, Lang& out) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        std::string val;
        if (a == "-lang" || a == "--lang") {
            if (i + 1 < argc) val = argv[++i];
        }
        else if (a.compare(0, 7, "--lang=") == 0) val = a.substr(7);
        else if (a.compare(0, 6, "-lang=") == 0)  val = a.substr(6);
        else continue;

        for (size_t k = 0; k < val.size(); k++)
            if (val[k] >= 'A' && val[k] <= 'Z')
                val[k] = (char)(val[k] - 'A' + 'a');
        if (val == "tr" || val == "turkce") { out = LANG_TR; return true; }
        if (val == "en" || val == "english") { out = LANG_EN; return true; }
    }
    return false;
}

// ---------------------------------------------------------------------------
//  UI
// ---------------------------------------------------------------------------
static int consoleWidth() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    return 100;
}

static void printBanner() {
    int w = consoleWidth();
    if (w < 70)  w = 70;
    if (w > 110) w = 110;

    const char* art[] = {
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⢠⡾⠲⠶⣤⣀⣠⣤⣤⣤⡿⠛⠿⡴⠾⠛⢻⡆⠀⠀⠀",
        "⠀⠀⠀⣼⠁⠀⠀⠀⠉⠁⠀⢀⣿⠐⡿⣿⠿⣶⣤⣤⣷⡀⠀⠀",
        "⠀⠀⠀⢹⡶⠀⠀⠀⠀⠀⠀⠈⢯⣡⣿⣿⣀⣸⣿⣦⢓⡟⠀⠀",
        "⠀⠀⢀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠹⣍⣭⣾⠁⠀⠀",
        "⠀⣀⣸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣸⣷⣤⡀",
        "⠈⠉⠹⣏⡁⠀⢸⣿⠀⠀⠀⢀⡀⠀⠀⠀⣿⠆⠀⢀⣸⣇⣀⠀",
        "⠀⠐⠋⢻⣅⣄⢀⣀⣀⡀⠀⠯⠽⠂⢀⣀⣀⡀⠀⣤⣿⠀⠉⠀",
        "⠀⠀⠴⠛⠙⣳⠋⠉⠉⠙⣆⠀⠀⢰⡟⠉⠈⠙⢷⠟⠉⠙⠂⠀",
        "⠀⠀⠀⠀⠀⢻⣄⣠⣤⣴⠟⠛⠛⠛⢧⣤⣤⣀⡾⠁⠀⠀⠀⠀"
    };

    int artPad = (w - 40) / 2; if (artPad < 0) artPad = 0;

    printf("\n");
    for (int i = 0; i < 10; i++)
        printf("%*s%s%s%s\n", artPad, "", C_CYAN, art[i], C_RESET);
    printf("\n");

    const char* title = "D P I   H U N T E R   v2.1";
    int titleLen = (int)strlen(title);
    int tp = (w - titleLen) / 2; if (tp < 0) tp = 0;
    printf("%*s%s%s%s\n", tp, "", C_BOLD C_WHITE, title, C_RESET);

    const char* by = "by astegtam";
    int byLen = (int)strlen(by);
    int bp = (w - byLen) / 2; if (bp < 0) bp = 0;
    printf("%*s%s%s%s\n", bp, "", C_DIM, by, C_RESET);
    printf("\n");
}

static void printSeparator() {
    int w = consoleWidth();
    if (w > 100) w = 100;
    if (w < 40)  w = 40;

    printf("  %s", C_DIM);
    for (int i = 0; i < w - 4; i++) putchar('-');
    printf("%s\n", C_RESET);
}

static void printStatusPanel(const Messages& M, const char* blacklistStr) {
    Strategy cur = getStrategy();

    printf("  %s%-18s%s %s%s* %s%s\n",
        C_DIM, M.lblStatus, C_RESET,
        C_GREEN, C_BOLD, M.statusActive, C_RESET);

    // Remember on which console row the "Strategy" line is, so we can
    // rewrite just that line later.
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    fflush(stdout);
    if (GetConsoleScreenBufferInfo(hOut, &csbi))
        g_statusStrategyRow = csbi.dwCursorPosition.Y;
    else
        g_statusStrategyRow = -1;

    printf("  %s%-18s%s %s%s%s\n",
        C_DIM, M.lblStrategy, C_RESET,
        C_CYAN, STRATEGY_NAMES[cur], C_RESET);

    printf("  %s%-18s%s %s%s%s\n",
        C_DIM, M.lblBlacklist, C_RESET,
        C_YELLOW, blacklistStr, C_RESET);

    printf("\n");
    fflush(stdout);
}

// FIX 1: everything (reading the cursor, moving it, printing) now happens
//        INSIDE the lock. Before, the cursor could be read, then another
//        thread printed, then we restored a stale cursor position.
// FIX 2: we read the row back and only overwrite it if it still shows the
//        "Strategy" label. If the console scrolled, we skip instead of
//        writing over a random log line.
// Also the strategy name is shown in the window title (always safe).
static void updateStatusStrategy(const Messages& M) {
    Strategy cur = getStrategy();

    char title[96];
    sprintf_s(title, sizeof(title), "DPI Hunter v2.1 - %s", STRATEGY_NAMES[cur]);
    SetConsoleTitleA(title);

    if (g_statusStrategyRow < 0) return;

    EnterCriticalSection(&g_consoleLock);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        COORD saved = csbi.dwCursorPosition;
        COORD pos = { 0, g_statusStrategyRow };

        char rowText[48] = { 0 };
        DWORD got = 0;
        bool rowOk = false;
        if (ReadConsoleOutputCharacterA(hOut, rowText, 40, pos, &got) && got > 0) {
            rowText[got < 47 ? got : 47] = 0;
            rowOk = (strstr(rowText, M.lblStrategy) != NULL);
        }

        if (rowOk) {
            fflush(stdout);
            SetConsoleCursorPosition(hOut, pos);
            printf("  %s%-18s%s %s%s%s\x1b[K",
                C_DIM, M.lblStrategy, C_RESET,
                C_CYAN, STRATEGY_NAMES[cur], C_RESET);
            fflush(stdout);
            SetConsoleCursorPosition(hOut, saved);
        }
    }

    LeaveCriticalSection(&g_consoleLock);
}

static void logLine(const char* tag, const char* color, const char* text) {
    EnterCriticalSection(&g_consoleLock);
    printf("  ");
    printTimestamp();
    printf(" %s%s%s %s\n", color, tag, C_RESET, text);
    fflush(stdout);
    LeaveCriticalSection(&g_consoleLock);
}

static void logBlank() {
    EnterCriticalSection(&g_consoleLock);
    printf("\n");
    fflush(stdout);
    LeaveCriticalSection(&g_consoleLock);
}

// ---------------------------------------------------------------------------
//  Admin
// ---------------------------------------------------------------------------
static bool isAdmin() {
    BOOL a = FALSE; PSID g = NULL;
    SID_IDENTIFIER_AUTHORITY n = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&n, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) {
        CheckTokenMembership(NULL, g, &a);
        FreeSid(g);
    }
    return a != FALSE;
}

// FIX: the old version lost the command line arguments (like --lang=en)
// when it restarted itself as admin. Now we pass them on.
static bool relaunchAsAdmin(int argc, char** argv) {
    char p[MAX_PATH];
    if (!GetModuleFileNameA(NULL, p, MAX_PATH)) return false;

    std::string args;
    for (int i = 1; i < argc; i++) {
        if (!args.empty()) args += ' ';
        args += '"';
        args += argv[i];
        args += '"';
    }

    SHELLEXECUTEINFOA sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = p;
    sei.lpParameters = args.empty() ? NULL : args.c_str();
    sei.nShow = SW_NORMAL;
    return ShellExecuteExA(&sei) != FALSE;
}

// ---------------------------------------------------------------------------
//  Blacklist
// ---------------------------------------------------------------------------
static std::set<std::string> g_blacklist;

static void loadBlacklist(const std::string& fn) {
    std::ifstream f(fn);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
            line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t s = line.find_first_not_of(" \t");
        if (s == std::string::npos) continue;
        line = line.substr(s);
        if (line.empty() || line[0] == '#') continue;
        for (size_t i = 0; i < line.size(); i++) {
            char c = line[i];
            if (c >= 'A' && c <= 'Z') line[i] = (char)(c - 'A' + 'a');
        }
        g_blacklist.insert(line);
    }
}

static bool isBlacklisted(const std::string& host) {
    if (g_blacklist.empty()) return true;
    std::string h = host;
    for (size_t i = 0; i < h.size(); i++) {
        char c = h[i];
        if (c >= 'A' && c <= 'Z') h[i] = (char)(c - 'A' + 'a');
    }
    if (g_blacklist.count(h)) return true;
    // "cdn.discord.com" matches the entry "discord.com"
    for (std::set<std::string>::const_iterator it = g_blacklist.begin();
        it != g_blacklist.end(); ++it) {
        const std::string& e = *it;
        if (h.size() > e.size() &&
            h.compare(h.size() - e.size(), e.size(), e) == 0 &&
            h[h.size() - e.size() - 1] == '.')
            return true;
    }
    return false;
}

// A usable test host: letters, digits, dots, dashes, contains a dot.
static bool isPlainHost(const std::string& h) {
    if (h.size() < 3 || h.size() > 200) return false;
    if (h[0] == '.' || h.find('.') == std::string::npos) return false;
    for (size_t i = 0; i < h.size(); i++) {
        char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-'))
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  SNI extractor (finds the host name inside a TLS ClientHello)
// ---------------------------------------------------------------------------
static bool extractSni(const char* d, unsigned int len,
    char** outHost, unsigned int* outLen) {
    if (len < 10) return false;
    uint32_t ptr = 0;
    while (ptr + 9 < len) {
        // pattern of the "server_name" extension header
        if (d[ptr] == '\0' && d[ptr + 1] == '\0' && d[ptr + 2] == '\0' &&
            d[ptr + 4] == '\0' && d[ptr + 6] == '\0' && d[ptr + 7] == '\0' &&
            (unsigned char)d[ptr + 3] - (unsigned char)d[ptr + 5] == 2 &&
            (unsigned char)d[ptr + 5] - (unsigned char)d[ptr + 8] == 3) {
            unsigned int hl = (unsigned char)d[ptr + 8];
            if (hl < 2 || hl > 254) return false;
            if (ptr + 9 + hl > len) return false;
            const char* hn = &d[ptr + 9];
            for (unsigned int i = 0; i < hl; i++) {
                char c = hn[i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '-'))
                    return false;
            }
            *outHost = (char*)hn;
            *outLen = hl;
            return true;
        }
        ptr++;
    }
    return false;
}

// ---------------------------------------------------------------------------
//  Statistics
// ---------------------------------------------------------------------------
struct Stats {
    volatile LONG total = 0;
    volatile LONG fragmented = 0;
    volatile LONG fakeSent = 0;
    volatile LONG quicBlocked = 0;
    volatile LONG passed = 0;
    volatile LONG rstDetected = 0;
    volatile LONG emergencyTests = 0;
};
static Stats g_stats;

// ---------------------------------------------------------------------------
//  Recent ClientHello tracking (to connect an incoming RST to a host)
// ---------------------------------------------------------------------------
static void rememberFrag(DWORD dstIP, USHORT dstPort, const char* host) {
    LONG idx = InterlockedIncrement(&g_recentIdx) % RECENT_MAX;
    if (idx < 0) idx = 0;
    g_recent[idx].dstIP = dstIP;
    g_recent[idx].dstPort = dstPort;
    g_recent[idx].tick = GetTickCount();
    strncpy_s(g_recent[idx].host, sizeof(g_recent[idx].host), host, _TRUNCATE);
}

static std::string matchRecent(DWORD srcIP, USHORT srcPort) {
    DWORD now = GetTickCount();
    std::string result;
    for (int i = 0; i < RECENT_MAX; i++) {
        if (g_recent[i].dstIP == srcIP &&
            g_recent[i].dstPort == srcPort &&
            (now - g_recent[i].tick) < RECENT_TTL_MS &&
            g_recent[i].host[0] != 0) {
            result = g_recent[i].host;
            g_recent[i].host[0] = 0;
            break;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
//  Fake packet
//  FIX: the old version sent an exact COPY of the real ClientHello with a low
//  TTL. The DPI still saw the real (blocked) host name, so it did nothing.
//  A real "fake" must show the DPI a DIFFERENT, harmless host name.
//  Here we overwrite the SNI in the copy with a same-length name that ends
//  with "google.com". The fake dies before the server (low TTL / wrong
//  sequence / broken checksum), only the DPI reads it.
// ---------------------------------------------------------------------------
static void makeFakeHost(char* dst, unsigned int len) {
    const char* base = "www.google.com";     // 14 chars
    const unsigned int bl = 14;
    if (len >= bl) {
        unsigned int pad = len - bl;
        for (unsigned int i = 0; i < pad; i++) dst[i] = 'w';
        memcpy(dst + pad, base, bl);
    }
    else {
        memcpy(dst, base + (bl - len), len);  // last "len" chars of base
    }
}

static void sendFakePacket(const unsigned char* orig, UINT origLen,
    const WINDIVERT_ADDRESS* addr,
    PWINDIVERT_IPHDR ip, UINT sniOffset, UINT sniLen,
    BYTE ttl, bool wrongSeq, bool badChecksum) {
    if (origLen > MAXBUF) return;

    UINT ipHdrLen = (UINT)ip->HdrLength * 4;
    static unsigned char fake[MAXBUF];       // only the main thread calls this
    memcpy(fake, orig, origLen);

    PWINDIVERT_IPHDR  fip = (PWINDIVERT_IPHDR)fake;
    PWINDIVERT_TCPHDR ftcp = (PWINDIVERT_TCPHDR)(fake + ipHdrLen);
    UINT hdrLen = ipHdrLen + (UINT)ftcp->HdrLength * 4;

    // The SNI must really lie inside the packet
    if (hdrLen + sniOffset + sniLen > origLen) return;
    makeFakeHost((char*)fake + hdrLen + sniOffset, sniLen);

    WINDIVERT_ADDRESS fa = *addr;

    if (ttl != 0) {
        if (ttl > 10) ttl = 10;
        fip->TTL = ttl;
    }

    if (wrongSeq) {
        ftcp->AckNum = htonl(ntohl(ftcp->AckNum) - 66000);
        ftcp->SeqNum = htonl(ntohl(ftcp->SeqNum) - 10000);
    }

    WinDivertHelperCalcChecksums(fake, origLen, &fa, 0);

    if (badChecksum)   // break the checksum AFTER it was calculated
        ftcp->Checksum = htons((UINT16)(ntohs(ftcp->Checksum) - 1));

    WinDivertSend(g_handle, fake, origLen, NULL, &fa);
}

// ---------------------------------------------------------------------------
//  Fragment sending: cut the TCP payload in two packets
// ---------------------------------------------------------------------------
static bool sendFragments(unsigned char* packet, UINT packetLen,
    const WINDIVERT_ADDRESS* addr,
    PWINDIVERT_IPHDR ip, PWINDIVERT_TCPHDR tcp,
    PVOID payload, UINT payloadLen,
    UINT splitOffset) {
    if (splitOffset == 0 || splitOffset >= payloadLen) return false;

    UINT ipHdrLen = (UINT)ip->HdrLength * 4;
    UINT tcpHdrLen = (UINT)tcp->HdrLength * 4;
    UINT hdrLen = ipHdrLen + tcpHdrLen;

    if (hdrLen > packetLen) return false;
    if (hdrLen + payloadLen > packetLen) return false;

    UINT f1Len = hdrLen + splitOffset;
    UINT f2Len = hdrLen + (payloadLen - splitOffset);
    if (f2Len > MAXBUF) return false;

    // second packet = same headers + the rest of the data
    static unsigned char frag2[MAXBUF];
    memcpy(frag2, packet, hdrLen);
    memcpy(frag2 + hdrLen, (UINT8*)payload + splitOffset, payloadLen - splitOffset);

    PWINDIVERT_IPHDR  ip2 = (PWINDIVERT_IPHDR)frag2;
    PWINDIVERT_TCPHDR tcp2 = (PWINDIVERT_TCPHDR)(frag2 + ipHdrLen);

    // second packet continues where the first one ended
    tcp2->SeqNum = htonl(ntohl(tcp2->SeqNum) + splitOffset);
    ip->Length = htons((UINT16)f1Len);
    ip2->Length = htons((UINT16)f2Len);

    WinDivertHelperCalcChecksums(packet, f1Len, (WINDIVERT_ADDRESS*)addr, 0);
    WinDivertHelperCalcChecksums(frag2, f2Len, (WINDIVERT_ADDRESS*)addr, 0);

    WinDivertSend(g_handle, packet, f1Len, NULL, addr);
    WinDivertSend(g_handle, frag2, f2Len, NULL, addr);

    // FIX: from this point "packet" was modified (shorter IP length).
    // Returning false here would make the caller send the broken original.
    // If a send failed, TCP simply retransmits, so "true" is always right.
    return true;
}

// ---------------------------------------------------------------------------
//  Apply the current strategy to one ClientHello packet
// ---------------------------------------------------------------------------
static void applyStrategy(unsigned char* packet, UINT packetLen,
    const WINDIVERT_ADDRESS* addr,
    PWINDIVERT_IPHDR ip, PWINDIVERT_TCPHDR tcp,
    PVOID payload, UINT payloadLen,
    bool hasSni, UINT sniOffset, UINT sniLen) {
    Strategy s = getStrategy();
    bool handled = false;

    switch (s) {
    case STRAT_SNI_FRAG_1:
        // If we could not find the SNI (it can sit in the 2nd TCP segment),
        // fall back to a plain split at byte 2 instead of doing nothing.
        handled = sendFragments(packet, packetLen, addr, ip, tcp, payload, payloadLen,
            hasSni ? sniOffset + 1 : 2);
        break;
    case STRAT_SNI_FRAG_2:
        handled = sendFragments(packet, packetLen, addr, ip, tcp, payload, payloadLen,
            hasSni ? sniOffset + 2 : 2);
        break;
    case STRAT_SNI_FRAG_BEFORE:
        handled = sendFragments(packet, packetLen, addr, ip, tcp, payload, payloadLen,
            hasSni ? sniOffset : 2);
        break;
    case STRAT_FRAG_AT_1:
        handled = sendFragments(packet, packetLen, addr, ip, tcp, payload, payloadLen, 1);
        break;
    case STRAT_FRAG_AT_2:
        handled = sendFragments(packet, packetLen, addr, ip, tcp, payload, payloadLen, 2);
        break;
    case STRAT_FRAG_AT_3:
        handled = sendFragments(packet, packetLen, addr, ip, tcp, payload, payloadLen, 3);
        break;
    case STRAT_FAKE_TTL_3:
        if (hasSni) {
            sendFakePacket(packet, packetLen, addr, ip, sniOffset, sniLen, 3, false, false);
            InterlockedIncrement(&g_stats.fakeSent);
        }
        break;
    case STRAT_FAKE_TTL_6:
        if (hasSni) {
            sendFakePacket(packet, packetLen, addr, ip, sniOffset, sniLen, 6, false, false);
            InterlockedIncrement(&g_stats.fakeSent);
        }
        break;
    case STRAT_FAKE_TTL_3_WRONG_SEQ:
        if (hasSni) {
            sendFakePacket(packet, packetLen, addr, ip, sniOffset, sniLen, 3, true, false);
            InterlockedIncrement(&g_stats.fakeSent);
        }
        break;
    case STRAT_FAKE_BAD_CHKSUM:
        if (hasSni) {
            sendFakePacket(packet, packetLen, addr, ip, sniOffset, sniLen, 0, false, true);
            InterlockedIncrement(&g_stats.fakeSent);
        }
        break;
    case STRAT_DISABLED:
    default:
        break;
    }

    if (handled) {
        InterlockedIncrement(&g_stats.fragmented);
        return;
    }
    // Fake strategies end up here: the REAL packet goes out unchanged
    // right after the fake one.
    WinDivertSend(g_handle, packet, packetLen, NULL, addr);
    InterlockedIncrement(&g_stats.passed);
}

// ---------------------------------------------------------------------------
//  QUIC detection (a QUIC "long header" packet has the top bit set)
// ---------------------------------------------------------------------------
static bool isQuic(PVOID p, UINT l) {
    if (!p || l < 5) return false;
    return (((UINT8*)p)[0] & 0x80) != 0;
}

// ---------------------------------------------------------------------------
//  Small helpers to build a TLS ClientHello byte by byte
// ---------------------------------------------------------------------------
typedef std::vector<unsigned char> Bytes;

static void put8(Bytes& b, unsigned v) { b.push_back((unsigned char)(v & 0xFF)); }
static void put16(Bytes& b, unsigned v) { put8(b, v >> 8); put8(b, v); }
static void put24(Bytes& b, unsigned v) { put8(b, v >> 16); put16(b, v); }
static void putBytes(Bytes& b, const void* p, size_t n) {
    const unsigned char* c = (const unsigned char*)p;
    b.insert(b.end(), c, c + n);
}
static void putExt(Bytes& out, unsigned type, const Bytes& data) {
    put16(out, type);
    put16(out, (unsigned)data.size());
    out.insert(out.end(), data.begin(), data.end());
}
// tiny random generator (rand() has a separate state in every thread)
static unsigned char randByte(unsigned& st) {
    st ^= st << 13; st ^= st >> 17; st ^= st << 5;
    return (unsigned char)(st & 0xFF);
}

// A realistic, modern ClientHello (TLS 1.3 capable). Servers answer it with a
// proper ServerHello, so a missing answer really means "blocked".
static void buildClientHello(const char* host, Bytes& out) {
    unsigned st = GetTickCount() ^ 0x9E3779B9u;
    if (st == 0) st = 1;
    size_t hl = strlen(host);

    Bytes ext;

    { // server_name
        Bytes d;
        put16(d, (unsigned)(hl + 3));
        put8(d, 0);
        put16(d, (unsigned)hl);
        putBytes(d, host, hl);
        putExt(ext, 0x0000, d);
    }
    { // supported_groups: x25519, secp256r1, secp384r1
        Bytes d;
        put16(d, 6); put16(d, 0x001d); put16(d, 0x0017); put16(d, 0x0018);
        putExt(ext, 0x000a, d);
    }
    { // ec_point_formats
        Bytes d;
        put8(d, 1); put8(d, 0);
        putExt(ext, 0x000b, d);
    }
    { // signature_algorithms
        const unsigned sig[] = { 0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601 };
        Bytes d;
        put16(d, 2 * 8);
        for (int i = 0; i < 8; i++) put16(d, sig[i]);
        putExt(ext, 0x000d, d);
    }
    { // supported_versions: TLS 1.3, TLS 1.2
        Bytes d;
        put8(d, 4); put16(d, 0x0304); put16(d, 0x0303);
        putExt(ext, 0x002b, d);
    }
    { // psk_key_exchange_modes
        Bytes d;
        put8(d, 1); put8(d, 1);
        putExt(ext, 0x002d, d);
    }
    { // key_share: x25519 with 32 random bytes (any 32 bytes is a valid key)
        Bytes d;
        put16(d, 36); put16(d, 0x001d); put16(d, 32);
        for (int i = 0; i < 32; i++) put8(d, randByte(st));
        putExt(ext, 0x0033, d);
    }

    Bytes body;
    put16(body, 0x0303);                                   // client version
    for (int i = 0; i < 32; i++) put8(body, randByte(st)); // random
    put8(body, 32);                                        // session id length
    for (int i = 0; i < 32; i++) put8(body, randByte(st)); // session id
    const unsigned ciphers[] = { 0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,
                                 0xcca9,0xcca8,0x009c,0x009d,0x002f,0x0035 };
    put16(body, 2 * 13);
    for (int i = 0; i < 13; i++) put16(body, ciphers[i]);
    put8(body, 1); put8(body, 0);                          // compression: none
    put16(body, (unsigned)ext.size());
    body.insert(body.end(), ext.begin(), ext.end());

    Bytes hs;
    put8(hs, 0x01);                                        // ClientHello
    put24(hs, (unsigned)body.size());
    hs.insert(hs.end(), body.begin(), body.end());

    out.clear();
    put8(out, 0x16);                                       // TLS handshake record
    put16(out, 0x0301);
    put16(out, (unsigned)hs.size());
    out.insert(out.end(), hs.begin(), hs.end());
}

// ---------------------------------------------------------------------------
//  TLS handshake test
//  FIX: the old test returned only true/false, so a DNS error or a plain
//  "cannot connect" looked like a DPI block and made the program switch
//  strategies for nothing. Now there are four different results.
// ---------------------------------------------------------------------------
enum TestResult {
    TEST_OK,        // server answered our ClientHello -> not blocked
    TEST_BLOCKED,   // TCP connected, but the ClientHello got reset/ignored -> DPI
    TEST_NODNS,     // host name could not be resolved
    TEST_NOCONN     // TCP connection itself failed (network down / IP block)
};

static TestResult testTlsHandshake(const char* hostname) {
    size_t hnLen = strlen(hostname);
    if (hnLen == 0 || hnLen > 200) return TEST_NODNS;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    struct addrinfo* res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(hostname, "443", &hints, &res) != 0 || !res)
        return TEST_NODNS;

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return TEST_NOCONN; }

    // connect with a timeout: non-blocking connect + select()
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, res->ai_addr, (int)res->ai_addrlen);

    fd_set wset, eset;
    FD_ZERO(&wset); FD_SET(s, &wset);
    FD_ZERO(&eset); FD_SET(s, &eset);
    timeval tv;
    tv.tv_sec = AUTO_TEST_TIMEOUT / 1000;
    tv.tv_usec = (AUTO_TEST_TIMEOUT % 1000) * 1000;

    int sel = select(0, NULL, &wset, &eset, &tv);
    if (sel <= 0 || FD_ISSET(s, &eset)) {
        closesocket(s); freeaddrinfo(res); return TEST_NOCONN;
    }

    int err = 0, elen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
    if (err != 0) { closesocket(s); freeaddrinfo(res); return TEST_NOCONN; }

    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    DWORD rcvTimeout = AUTO_TEST_TIMEOUT;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&rcvTimeout, sizeof(rcvTimeout));

    Bytes hello;
    buildClientHello(hostname, hello);

    if (send(s, (const char*)&hello[0], (int)hello.size(), 0) != (int)hello.size()) {
        closesocket(s); freeaddrinfo(res); return TEST_BLOCKED;
    }

    // A healthy server answers with a TLS record: 0x16 (ServerHello)
    // or 0x15 (alert). Silence, FIN or RST means the hello was blocked.
    unsigned char resp[8];
    int n = recv(s, (char*)resp, sizeof(resp), 0);
    closesocket(s);
    freeaddrinfo(res);

    if (n > 0 && (resp[0] == 0x16 || resp[0] == 0x15)) return TEST_OK;
    return TEST_BLOCKED;
}

// ---------------------------------------------------------------------------
//  Strategy search
//  Tries the strategies one after another (starting after the current one)
//  and keeps the first one that opens most of the given hosts.
//  If nothing works, the old strategy is restored (no more random switching,
//  no more instant Safe-Mode).
// ---------------------------------------------------------------------------
static bool findWorkingStrategy(const Messages& M, const std::vector<std::string>& hosts) {
    Strategy original = getStrategy();
    if (original >= STRAT_BYPASS_COUNT) original = (Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0);

    for (int step = 1; step <= STRAT_BYPASS_COUNT; step++) {
        if (!isRunning()) return false;

        Strategy cand = (Strategy)((original + step) % STRAT_BYPASS_COUNT);
        setStrategy(cand);
        updateStatusStrategy(M);
        if (sleepOrStop(EMERGENCY_DELAY_MS)) return false;

        int ok = 0, tested = 0;
        for (size_t i = 0; i < hosts.size(); i++) {
            TestResult r = testTlsHandshake(hosts[i].c_str());
            if (r == TEST_OK) { ok++; tested++; }
            else if (r == TEST_BLOCKED) { tested++; }
        }

        EnterCriticalSection(&g_consoleLock);
        printf("    %stry%s %s%s%s ... ", C_DIM, C_RESET, C_CYAN, STRATEGY_NAMES[cand], C_RESET);
        if (tested > 0 && ok * 100 / tested >= SUCCESS_THRESHOLD)
            printf("%s%sOK%s\n", C_GREEN, C_BOLD, C_RESET);
        else
            printf("%sFAIL%s\n", C_RED, C_RESET);
        fflush(stdout);
        LeaveCriticalSection(&g_consoleLock);

        if (tested > 0 && ok * 100 / tested >= SUCCESS_THRESHOLD) {
            InterlockedExchange(&g_lastGood, (LONG)cand);
            logLine("FIX", C_GREEN C_BOLD, M.emergencyFound);
            return true;
        }
    }

    // nothing worked -> go back to what we had
    setStrategy(original);
    updateStatusStrategy(M);
    return false;
}

static void enterSafeMode(const Messages& M, DWORD& safeSince) {
    safeSince = GetTickCount();
    setStrategy(STRAT_DISABLED);
    updateStatusStrategy(M);
    logLine("SAFE", C_YELLOW C_BOLD, M.safeModeEntered);
    InterlockedExchange(&g_consecutiveFails, 0);
}

// ---------------------------------------------------------------------------
//  Emergency recovery (called after several RSTs in a short time)
// ---------------------------------------------------------------------------
static void emergencyRecovery(const Messages& M, const char* host) {
    if (InterlockedCompareExchange(&g_emergencyRunning, 1, 0) != 0) return;

    DWORD now = GetTickCount();
    DWORD last = (DWORD)InterlockedCompareExchange(&g_lastEmergencyTick, 0, 0);
    if (last != 0 && (now - last) < EMERGENCY_COOLDOWN_MS) {
        logLine("COOL", C_DIM, M.emergencyCooldown);
        InterlockedExchange(&g_emergencyRunning, 0);
        return;
    }
    InterlockedExchange(&g_lastEmergencyTick, (LONG)now);
    InterlockedIncrement(&g_stats.emergencyTests);

    logBlank();
    logLine("RST", C_RED C_BOLD, M.emergencyDetected);

    // First check with the CURRENT strategy: many RSTs are harmless.
    TestResult r = testTlsHandshake(host);
    if (r == TEST_OK) {
        logLine("RST", C_GREEN, M.rstBenign);
    }
    else if (r != TEST_BLOCKED) {
        logLine("RST", C_DIM, M.noValidTest);   // DNS / network problem, not DPI
    }
    else {
        std::vector<std::string> hosts;
        hosts.push_back(host);
        if (!findWorkingStrategy(M, hosts))
            logLine("FAIL", C_YELLOW, M.noFix);
    }

    InterlockedExchange(&g_emergencyRunning, 0);
}

// ---------------------------------------------------------------------------
//  Test sites
// ---------------------------------------------------------------------------
static const char* DEFAULT_TEST_SITES[] = {
    "youtube.com", "twitter.com", "discord.com"
};

// FIX: the old version always took the first 3 entries of the blacklist
// (alphabetical). One dead or odd entry could make every round "fail".
// Now we rotate through the blacklist and skip entries that are not plain
// host names.
static void pickTestSites(std::vector<std::string>& out) {
    out.clear();
    static size_t cursor = 0;     // only the test thread uses this

    std::vector<std::string> pool;
    for (std::set<std::string>::const_iterator it = g_blacklist.begin();
        it != g_blacklist.end(); ++it)
        if (isPlainHost(*it)) pool.push_back(*it);

    if (pool.empty()) {
        EnterCriticalSection(&g_seenLock);
        for (std::set<std::string>::const_iterator it = g_seenHosts.begin();
            it != g_seenHosts.end(); ++it)
            if (isPlainHost(*it)) pool.push_back(*it);
        LeaveCriticalSection(&g_seenLock);
    }

    if (pool.empty())
        for (int i = 0; i < TEST_SITES_MAX; i++)
            pool.push_back(DEFAULT_TEST_SITES[i]);

    size_t n = pool.size() < (size_t)TEST_SITES_MAX ? pool.size() : (size_t)TEST_SITES_MAX;
    for (size_t i = 0; i < n; i++)
        out.push_back(pool[(cursor + i) % pool.size()]);
    cursor += n;
}

// One normal test round. Returns the time (ms) until the next round.
static DWORD periodicRoundImpl(const Messages& M, DWORD& safeSince) {
    std::vector<std::string> sites;
    pickTestSites(sites);
    if (sites.empty()) return PERIODIC_TEST_MS;

    Strategy cur = getStrategy();

    logBlank();
    logLine("TEST", C_BLUE C_BOLD, STRATEGY_NAMES[cur]);

    int ok = 0;
    std::vector<std::string> blocked;

    for (size_t i = 0; i < sites.size(); i++) {
        if (!isRunning()) return PERIODIC_TEST_MS;
        TestResult r = testTlsHandshake(sites[i].c_str());

        EnterCriticalSection(&g_consoleLock);
        if (r == TEST_OK) {
            printf("    %sOK%s   %s\n", C_GREEN, C_RESET, sites[i].c_str());
            ok++;
        }
        else if (r == TEST_BLOCKED) {
            printf("    %sFAIL%s %s\n", C_RED, C_RESET, sites[i].c_str());
            blocked.push_back(sites[i]);
        }
        else {
            printf("    %sSKIP%s %s %s(%s)%s\n", C_DIM, C_RESET, sites[i].c_str(),
                C_DIM, (r == TEST_NODNS) ? "dns" : "connect", C_RESET);
        }
        fflush(stdout);
        LeaveCriticalSection(&g_consoleLock);
    }

    int tested = ok + (int)blocked.size();
    if (tested == 0) {                         // nothing valid -> change nothing
        logLine("TEST", C_DIM, M.noValidTest);
        return PERIODIC_TEST_MS;
    }

    int pct = (ok * 100) / tested;
    if (pct >= SUCCESS_THRESHOLD) {
        InterlockedExchange(&g_consecutiveFails, 0);
        InterlockedExchange(&g_lastGood, (LONG)cur);
        char buf[128];
        sprintf_s(buf, sizeof(buf), "%s (%d%%)", M.strategyNow, pct);
        logLine("KEEP", C_GREEN, buf);
        return PERIODIC_TEST_MS;
    }

    // round failed: look for a strategy that opens the blocked hosts
    logLine("SWAP", C_YELLOW C_BOLD, M.stratSwitch);
    if (findWorkingStrategy(M, blocked)) {
        InterlockedExchange(&g_consecutiveFails, 0);
        return PERIODIC_TEST_MS;
    }

    logLine("FAIL", C_YELLOW, M.noFix);
    LONG fails = InterlockedIncrement(&g_consecutiveFails);
    if (fails >= MAX_CONSEC_FAILS) {
        enterSafeMode(M, safeSince);
        return PERIODIC_TEST_MS;
    }
    return RETRY_SOON_MS;                      // look again soon
}

// While our own tests run, RSTs from test connections must not start another
// recovery. g_emergencyRunning doubles as the "tests are running" flag.
static DWORD periodicRound(const Messages& M, DWORD& safeSince) {
    InterlockedExchange(&g_emergencyRunning, 1);
    DWORD next = periodicRoundImpl(M, safeSince);
    InterlockedExchange(&g_emergencyRunning, 0);
    return next;
}

// ---------------------------------------------------------------------------
//  Test thread (runs next to the main packet loop)
// ---------------------------------------------------------------------------
static DWORD WINAPI testThread(LPVOID lpParam) {
    const Messages& M = *(const Messages*)lpParam;

    if (sleepOrStop(FIRST_TEST_DELAY_MS)) return 0;

    DWORD interval = PERIODIC_TEST_MS;
    DWORD lastRound = GetTickCount() - PERIODIC_TEST_MS;   // first round right away
    DWORD safeSince = 0;

    while (isRunning()) {
        DWORD now = GetTickCount();
        Strategy cur = getStrategy();

        // ---- Safe-Mode: wait, then try again ----
        if (cur == STRAT_DISABLED) {
            if ((now - safeSince) >= SAFE_RETRY_MS) {
                setStrategy((Strategy)InterlockedCompareExchange(&g_lastGood, 0, 0));
                updateStatusStrategy(M);
                logLine("SAFE", C_YELLOW, M.safeModeRetry);
                lastRound = now - PERIODIC_TEST_MS;
                interval = PERIODIC_TEST_MS;
            }
            if (sleepOrStop(1000)) break;
            continue;
        }

        // ---- RST storm detected by the main thread ----
        if (InterlockedCompareExchange(&g_emergencyFlag, 0, 0)) {
            char host[256];
            EnterCriticalSection(&g_emLock);
            strncpy_s(host, sizeof(host), g_emergencyHost, _TRUNCATE);
            InterlockedExchange(&g_emergencyFlag, 0);
            LeaveCriticalSection(&g_emLock);

            if (host[0] != 0) emergencyRecovery(M, host);
            lastRound = GetTickCount();
            interval = PERIODIC_TEST_MS;
            continue;
        }

        // ---- normal periodic test ----
        if ((now - lastRound) >= interval) {
            lastRound = now;
            interval = periodicRound(M, safeSince);
            lastRound = GetTickCount();
        }

        if (sleepOrStop(250)) break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
//  Statistics thread (prints a line every 30 s if something happened)
// ---------------------------------------------------------------------------
static DWORD WINAPI statsThread(LPVOID) {
    LONG lastTotal = -1;
    while (isRunning()) {
        if (sleepOrStop(30000)) break;

        LONG t = g_stats.total;
        if (t == lastTotal) continue;
        lastTotal = t;

        Strategy cur = getStrategy();

        EnterCriticalSection(&g_consoleLock);
        printf("  ");
        printTimestamp();
        printf(" %sSTAT%s %spkts=%ld frag=%ld fake=%ld quic=%ld rst=%ld pass=%ld%s | %s%s%s\n",
            C_MAGENTA, C_RESET, C_DIM,
            (long)g_stats.total,
            (long)g_stats.fragmented,
            (long)g_stats.fakeSent,
            (long)g_stats.quicBlocked,
            (long)g_stats.rstDetected,
            (long)g_stats.passed,
            C_RESET, C_CYAN, STRATEGY_NAMES[cur], C_RESET);
        fflush(stdout);
        LeaveCriticalSection(&g_consoleLock);
    }
    return 0;
}

// Human readable hint for the most common WinDivertOpen errors
static const char* explainOpenError(DWORD e) {
    switch (e) {
    case 2:    return "WinDivert64.sys not found (keep it next to the .exe)";
    case 5:    return "access denied (run as administrator)";
    case 87:   return "invalid filter / WinDivert.dll and .sys versions differ";
    case 577:  return "driver signature rejected (use the signed WinDivert 2.2 files)";
    case 654:  return "incompatible driver version (use matching dll + sys)";
    case 1275: return "driver blocked by Windows (Defender / memory integrity)";
    default:   return "check WinDivert.dll / WinDivert64.sys";
    }
}

// ===========================================================================
//  MAIN
// ===========================================================================
int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setWorkingDirToExe();                 // must be first: cfg/blacklist live next to the exe
    SetConsoleTitleA("DPI Hunter v2.1");
    enableAnsi();
    disableQuickEdit();

    InitializeCriticalSection(&g_seenLock);
    InitializeCriticalSection(&g_emLock);
    InitializeCriticalSection(&g_consoleLock);

    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);   // manual-reset event
    g_doneEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(consoleHandler, TRUE);

    printBanner();

    // ---- Admin ----
    if (!isAdmin()) {
        printf("%sAdmin privileges required. Restarting...%s\n", C_YELLOW, C_RESET);
        fflush(stdout);
        Sleep(1000);
        if (relaunchAsAdmin(argc, argv)) {
            FreeConsole();
            ExitProcess(0);
        }
        printf("%sCould not restart as admin.%s\n", C_RED, C_RESET);
        system("pause > nul");
        return 1;
    }

    // ---- Language ----
    Lang lang = LANG_EN;
    bool resolved = false;
    if (parseLangArg(argc, argv, lang))      resolved = true;
    if (!resolved && configReadLang(lang))   resolved = true;
    if (!resolved) {
        lang = languageMenu();
        configWriteLang(lang);
    }

    const Messages& M = pickMessages(lang);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("%sWSAStartup failed%s\n", C_RED, C_RESET);
        system("pause > nul");
        return 1;
    }
    srand(GetTickCount());

    // ---- Blacklist ----
    char blBuf[128];
    strcpy_s(blBuf, sizeof(blBuf), M.blDisabled);
    {
        const char* candidates[] = { "blacklist.txt", "listem.txt", "list.txt" };
        for (int i = 0; i < 3; i++) {
            std::ifstream t(candidates[i]);
            if (t.is_open()) {
                t.close();
                loadBlacklist(candidates[i]);
                break;
            }
        }
        if (!g_blacklist.empty())
            sprintf_s(blBuf, sizeof(blBuf), "%d entries", (int)g_blacklist.size());
    }

    printStatusPanel(M, blBuf);
    printSeparator();

    // ---- WinDivert ----
    // FIX: the old filter captured EVERY outbound TCP packet (games, downloads,
    // even empty ACKs) and pushed all of them through this program. Any short
    // pause here slowed down the whole internet. Now we only ask for:
    //   1. outbound TCP to port 443 that carries data (ClientHello is one)
    //   2. outbound UDP to port 443 with data (QUIC)
    //   3. inbound TCP RST coming from port 443
    // Everything else never touches this program.
    const char* filter =
        "(outbound and ip and tcp.DstPort == 443 and tcp.PayloadLength > 0) "
        "or (outbound and ip and udp.DstPort == 443 and udp.PayloadLength > 0) "
        "or (inbound and ip and tcp.SrcPort == 443 and tcp.Rst)";

    g_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_handle == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        printf("%s%s%lu%s\n", C_RED, M.openFail, e, C_RESET);
        printf("  %s\n", explainOpenError(e));
        system("pause > nul");
        return 1;
    }

    // Bigger packet queue = fewer dropped packets when the PC is busy.
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_SIZE, 16 * 1024 * 1024);

    printf("\n");
    printf("  %s%s:%s\n", C_DIM, M.logHeader, C_RESET);
    printf("\n");
    fflush(stdout);

    HANDLE hTest = CreateThread(NULL, 0, testThread, (LPVOID)&M, 0, NULL);
    HANDLE hStats = CreateThread(NULL, 0, statsThread, NULL, 0, NULL);

    int recvErrors = 0;

    // =============== MAIN PACKET LOOP ===============
    while (isRunning()) {
        UINT packetLen = 0;
        WINDIVERT_ADDRESS addr;

        if (!WinDivertRecv(g_handle, g_packet, sizeof(g_packet), &packetLen, &addr)) {
            // FIX: the old code just did "continue", which spins at 100% CPU
            // forever if WinDivertRecv keeps failing, and never ended on shutdown.
            DWORD e = GetLastError();
            if (e == ERROR_NO_DATA || !isRunning()) break;   // shutdown
            if (e == ERROR_INSUFFICIENT_BUFFER) continue;    // packet too big, skip it
            if (++recvErrors > 50) {
                char msg[96];
                sprintf_s(msg, sizeof(msg), "WinDivertRecv keeps failing (error %lu), stopping", e);
                logLine("ERR", C_RED C_BOLD, msg);
                break;
            }
            Sleep(10);
            continue;
        }
        recvErrors = 0;

        PWINDIVERT_IPHDR   ip = NULL;
        PWINDIVERT_IPV6HDR ipv6 = NULL;
        PWINDIVERT_TCPHDR  tcp = NULL;
        PWINDIVERT_UDPHDR  udp = NULL;
        PVOID              payload = NULL;
        UINT               payloadLen = 0;

        if (!WinDivertHelperParsePacket(g_packet, packetLen,
            &ip, &ipv6, NULL, NULL, NULL,
            &tcp, &udp, &payload, &payloadLen, NULL, NULL)) {
            WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
            continue;
        }

        // We only handle IPv4 (the filter has "ip"). Anything else goes through untouched.
        if (ip == NULL) {
            WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
            continue;
        }

        // ---- Inbound RST ----
        if (!addr.Outbound && tcp != NULL && tcp->Rst) {
            DWORD  srcIP = ip->SrcAddr;
            USHORT srcPort = ntohs(tcp->SrcPort);
            std::string host = matchRecent(srcIP, srcPort);
            if (!host.empty()) {
                InterlockedIncrement(&g_stats.rstDetected);

                // FIX: one single RST is NOT proof of DPI (servers send RSTs
                // for many normal reasons). Only start a recovery when several
                // RSTs arrive in a short time.
                DWORD now = GetTickCount();
                if (g_rstCount == 0 || (now - g_rstWindowStart) > RST_WINDOW_MS) {
                    g_rstWindowStart = now;
                    g_rstCount = 0;
                }
                g_rstCount++;

                if (g_rstCount >= RST_TRIGGER_COUNT &&
                    !InterlockedCompareExchange(&g_emergencyRunning, 0, 0)) {
                    g_rstCount = 0;
                    EnterCriticalSection(&g_emLock);
                    strncpy_s(g_emergencyHost, sizeof(g_emergencyHost),
                        host.c_str(), _TRUNCATE);
                    InterlockedExchange(&g_emergencyFlag, 1);
                    LeaveCriticalSection(&g_emLock);
                }
            }
            WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
            continue;
        }

        InterlockedIncrement(&g_stats.total);

        // ---- UDP (QUIC) ----
        if (udp != NULL) {
            if (payload != NULL && ntohs(udp->DstPort) == 443 &&
                getStrategy() != STRAT_DISABLED && isQuic(payload, payloadLen)) {
                // Drop QUIC so the browser falls back to TCP+TLS (which we can bypass)
                InterlockedIncrement(&g_stats.quicBlocked);
                continue;
            }
            WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
            InterlockedIncrement(&g_stats.passed);
            continue;
        }

        // ---- TCP: is it a TLS ClientHello? ----
        if (tcp == NULL || payload == NULL || payloadLen < 6) {
            WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
            InterlockedIncrement(&g_stats.passed);
            continue;
        }

        UINT8* pl = (UINT8*)payload;
        // FIX: byte 0 = 0x16 means "TLS handshake", but ONLY byte 5 = 0x01
        // means ClientHello. Other handshake records must not be touched.
        if (pl[0] != 0x16 || pl[5] != 0x01) {
            WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
            InterlockedIncrement(&g_stats.passed);
            continue;
        }

        char* sni = NULL;
        unsigned int sniLen = 0;
        bool hasSni = extractSni((char*)pl, payloadLen, &sni, &sniLen);
        UINT sniOffset = hasSni ? (UINT)(sni - (char*)pl) : 0;

        if (hasSni) {
            std::string host(sni, sniLen);
            for (size_t k = 0; k < host.size(); k++) {
                char c = host[k];
                if (c >= 'A' && c <= 'Z') host[k] = (char)(c - 'A' + 'a');
            }

            EnterCriticalSection(&g_seenLock);
            if (g_seenHosts.size() < SEEN_HOSTS_MAX &&
                g_seenHosts.find(host) == g_seenHosts.end())
                g_seenHosts.insert(host);
            LeaveCriticalSection(&g_seenLock);

            rememberFrag(ip->DstAddr, ntohs(tcp->DstPort), host.c_str());

            // Hosts that are not in the blacklist are left alone
            if (!g_blacklist.empty() && !isBlacklisted(host)) {
                WinDivertSend(g_handle, g_packet, packetLen, NULL, &addr);
                InterlockedIncrement(&g_stats.passed);
                continue;
            }
        }

        applyStrategy(g_packet, packetLen, &addr, ip, tcp,
            payload, payloadLen, hasSni, sniOffset, (UINT)sniLen);
    }

    // =============== SHUTDOWN ===============
    InterlockedExchange(&g_running, FALSE);
    if (g_stopEvent) SetEvent(g_stopEvent);    // wakes the helper threads
    if (hTest) { WaitForSingleObject(hTest, 3000);  CloseHandle(hTest); }
    if (hStats) { WaitForSingleObject(hStats, 3000); CloseHandle(hStats); }

    HANDLE h = g_handle;
    g_handle = INVALID_HANDLE_VALUE;
    WinDivertClose(h);
    WSACleanup();

    // NOTE: the old code deleted the critical sections here, but a helper
    // thread that was still busy (waiting for a network test) could use them
    // afterwards and crash. The OS frees everything when the process ends.

    printf("\n  %s%s%s\n", C_YELLOW, M.stopped, C_RESET);
    fflush(stdout);
    if (g_doneEvent) SetEvent(g_doneEvent);

    printf("\nPress any key to exit...");
    fflush(stdout);
    _getch();
    return 0;
}
