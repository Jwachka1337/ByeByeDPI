#include "protocol_headers.hpp"
#include "packet_engine.hpp"
#include "windivert_manager.hpp"
#include "windivert_deployer.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <uxtheme.h>

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <fstream>
#include <algorithm>
#include <memory>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

constexpr int IDC_BTN_START_STOP  = 1001;
constexpr int IDC_EDIT_DOMAIN     = 1002;
constexpr int IDC_BTN_ADD_DOMAIN  = 1003;
constexpr int IDC_BTN_DEL_DOMAIN  = 1004;
constexpr int IDC_LIST_DOMAINS    = 1005;
constexpr int IDC_CHK_ALL_DOMAINS = 1006;
constexpr int IDC_CHK_DISCORD     = 1007;
constexpr int IDC_CHK_TRAY        = 1008;
constexpr int IDC_LBL_ALL_DOMAINS = 1009;
constexpr int IDC_LBL_DISCORD     = 1010;
constexpr int IDC_LBL_TRAY        = 1011;

constexpr UINT IDM_FILE_START     = 2001;
constexpr UINT IDM_FILE_STOP      = 2002;
constexpr UINT IDM_FILE_IMPORT    = 2003;
constexpr UINT IDM_FILE_EXPORT    = 2004;
constexpr UINT IDM_FILE_TRAY      = 2005;
constexpr UINT IDM_FILE_EXIT      = 2006;

constexpr UINT IDM_MODE_ALL       = 2011;
constexpr UINT IDM_MODE_LIST      = 2012;
constexpr UINT IDM_MODE_DISCORD   = 2013;
constexpr UINT IDM_MODE_QUIC      = 2014;
constexpr UINT IDM_MODE_TS        = 2015;
constexpr UINT IDM_MODE_BADSUM    = 2016;

constexpr UINT IDM_TOOLS_RESET_STAT = 2021;
constexpr UINT IDM_TOOLS_RESET_DOMS = 2022;
constexpr UINT IDM_TOOLS_OPEN_DIR   = 2023;
constexpr UINT IDM_TOOLS_RESTART    = 2024;

constexpr UINT IDM_HELP_ABOUT     = 2031;
constexpr UINT IDM_HELP_DOCS      = 2032;

constexpr UINT WM_TRAY_ICON       = WM_USER + 101;
constexpr UINT ID_TRAY_SHOW       = 3001;
constexpr UINT ID_TRAY_TOGGLE     = 3002;
constexpr UINT ID_TRAY_EXIT       = 3003;
constexpr UINT_PTR IDT_STATS      = 1;

constexpr COLORREF CLR_BG         = RGB(20, 20, 24);
constexpr COLORREF CLR_PANEL      = RGB(28, 28, 36);
constexpr COLORREF CLR_CARD       = RGB(32, 33, 44);
constexpr COLORREF CLR_BORDER     = RGB(48, 50, 68);
constexpr COLORREF CLR_TEXT       = RGB(248, 249, 252);
constexpr COLORREF CLR_TEXT_MUTED = RGB(156, 163, 175);
constexpr COLORREF CLR_GREEN      = RGB(16, 185, 129);
constexpr COLORREF CLR_GREEN_HOV  = RGB(5, 150, 105);
constexpr COLORREF CLR_RED        = RGB(239, 68, 68);
constexpr COLORREF CLR_RED_HOV    = RGB(220, 38, 38);
constexpr COLORREF CLR_ACCENT     = RGB(79, 70, 229);
constexpr COLORREF CLR_ACCENT_HOV = RGB(67, 56, 202);

HBRUSH g_br_bg = nullptr;
HBRUSH g_br_panel = nullptr;
HBRUSH g_br_card = nullptr;
HBRUSH g_br_edit = nullptr;
HFONT g_font_main = nullptr;
HFONT g_font_title = nullptr;
HFONT g_font_bold = nullptr;
HFONT g_font_stat = nullptr;
HFONT g_font_stat_lbl = nullptr;
HWND g_hwnd = nullptr;
HMENU g_hmenu = nullptr;
NOTIFYICONDATAW g_nid{};
std::atomic<bool> g_engine_running{false};
std::unique_ptr<divert::WinDivertManager> g_divert_manager;
std::unique_ptr<engine::PacketEngine> g_engine;
std::vector<std::thread> g_workers;


bool g_opt_all_domains = true;
bool g_opt_discord_voice = true;
bool g_opt_quic_drop = true;
bool g_opt_tray_on_close = true;
engine::FakePacketMode g_opt_fake_mode = engine::FakePacketMode::TcpTimestamp;

HWND g_btn_start_stop = nullptr;
HWND g_edit_domain = nullptr;
HWND g_btn_add = nullptr;
HWND g_btn_del = nullptr;
HWND g_list_domains = nullptr;
HWND g_chk_all = nullptr;
HWND g_chk_discord = nullptr;
HWND g_chk_tray = nullptr;
HWND g_lbl_all = nullptr;
HWND g_lbl_discord = nullptr;
HWND g_lbl_tray = nullptr;

const std::vector<std::string> DEFAULT_PRESET_DOMAINS = {
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "youtu.be",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "discord.com",
    "discordapp.com",
    "discordapp.net",
    "gateway.discord.gg",
    "discord.gg",
    "discord.media",
    "status.discord.com",
    "instagram.com",
    "cdninstagram.com",
    "twitter.com",
    "x.com",
    "t.co",
    "twimg.com",
    "rutracker.org",
    "nnmclub.to",
    "ntc.party",
    "notion.so"
};

std::wstring get_domains_file_path() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring str(path);
    size_t pos = str.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        str = str.substr(0, pos + 1);
    }
    return str + L"domains.txt";
}

std::vector<std::string> load_domains_from_file() {
    std::vector<std::string> result;
    std::wstring path = get_domains_file_path();
    std::ifstream in(path);
    if (in.is_open()) {
        std::string line;
        while (std::getline(in, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) line.pop_back();
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(line.begin());
            if (!line.empty() && line[0] != '#') {
                result.push_back(line);
            }
        }
    }

    if (result.empty()) {
        result = DEFAULT_PRESET_DOMAINS;
    }
    return result;
}

void save_domains_to_file(const std::vector<std::string>& list) {
    std::wstring path = get_domains_file_path();
    std::ofstream out(path);
    if (out.is_open()) {
        out << "# Список доменов для обхода DPI\n";
        for (const auto& d : list) {
            out << d << "\n";
        }
    }
}

#ifndef DOMAIN_ALIAS_ADMINS
#define DOMAIN_ALIAS_ADMINS (0x00000220L)
#endif
#ifndef SECURITY_BUILTIN_DOMAIN_RID
#define SECURITY_BUILTIN_DOMAIN_RID (0x00000020L)
#endif

bool is_admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool run_as_admin() {
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) return false;

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) != FALSE;
}

// Поток фильтрации сетевых пакетов
void worker_thread_func(divert::WinDivertManager* mgr, engine::PacketEngine* eng) {
    std::vector<uint8_t> buffer(65535);
    WINDIVERT_ADDRESS addr{};
    uint32_t recv_len = 0;

    while (g_engine_running.load(std::memory_order_relaxed)) {
        if (!mgr->recv(buffer, addr, recv_len)) {
            if (!g_engine_running.load(std::memory_order_relaxed)) break;
            std::this_thread::yield();
            continue;
        }

        std::span<const uint8_t> packet_span(buffer.data(), recv_len);
        auto result = eng->process_packet(packet_span);

        switch (result.disposition) {
        case engine::ActionDisposition::PassUnmodified:
            mgr->send(packet_span, addr);
            break;
        case engine::ActionDisposition::Drop:
            break;
        case engine::ActionDisposition::EmitReplacement:
            for (auto& emitted : result.packets_to_emit) {
                WINDIVERT_ADDRESS send_addr = addr;
                if (emitted.recalc_checksum) {
                    mgr->send_recalc_checksums(emitted.data, send_addr);
                } else {
                    mgr->send(emitted.data, send_addr);
                }
            }
            break;
        }
    }
}

void stop_engine() {
    if (!g_engine_running.load(std::memory_order_relaxed)) return;

    g_engine_running.store(false, std::memory_order_release);

    if (g_divert_manager) {
        g_divert_manager->shutdown();
    }

    for (auto& t : g_workers) {
        if (t.joinable()) t.join();
    }
    g_workers.clear();

    if (g_divert_manager) {
        g_divert_manager->close();
    }

    if (g_hwnd) {
        InvalidateRect(g_hwnd, NULL, TRUE);
    }
}

bool start_engine() {
    if (g_engine_running.load(std::memory_order_relaxed)) return true;

    engine::EngineConfig cfg;
    cfg.tls_split_strategy = engine::TlsSplitStrategy::SplitPos1;
    cfg.reverse_segment_order = true;
    cfg.fake_mode = g_opt_fake_mode;
    cfg.fake_sni = "www.google.com";
    cfg.fake_repeats = 4;

    cfg.bypass_all_domains = g_opt_all_domains;
    cfg.udp_rtc_policy = g_opt_discord_voice ? engine::UdpRtcPolicy::FakePayload : engine::UdpRtcPolicy::None;
    cfg.udp_fake_cutoff = 4;
    cfg.udp_fake_repeats = 4;
    cfg.enable_udp_443_redirection = g_opt_quic_drop;

    int count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
    std::vector<std::string> domains;
    for (int i = 0; i < count; ++i) {
        wchar_t buf[256];
        SendMessageW(g_list_domains, LB_GETTEXT, i, (LPARAM)buf);
        char cbuf[256];
        WideCharToMultiByte(CP_UTF8, 0, buf, -1, cbuf, sizeof(cbuf), NULL, NULL);
        domains.push_back(cbuf);
    }
    cfg.custom_domains = domains;

    g_engine = std::make_unique<engine::PacketEngine>(cfg);
    g_divert_manager = std::make_unique<divert::WinDivertManager>();

    divert::DivertConfig div_cfg;
    if (!g_divert_manager->open(div_cfg)) {
        std::string err = divert::WinDivertManager::format_error(GetLastError());
        std::wstring werr(err.begin(), err.end());
        MessageBoxW(g_hwnd, werr.c_str(), L"Ошибка запуска WinDivert", MB_ICONERROR | MB_OK);
        return false;
    }

    g_engine_running.store(true, std::memory_order_release);

    uint32_t threads = std::clamp(std::thread::hardware_concurrency(), 1u, 4u);
    for (uint32_t i = 0; i < threads; ++i) {
        g_workers.emplace_back(worker_thread_func, g_divert_manager.get(), g_engine.get());
    }

    if (g_hwnd) {
        InvalidateRect(g_hwnd, NULL, TRUE);
    }
    return true;
}

void toggle_engine() {
    if (g_engine_running.load(std::memory_order_relaxed)) {
        stop_engine();
    } else {
        start_engine();
    }
}

void add_domain_from_edit() {
    wchar_t buf[256] = { 0 };
    GetWindowTextW(g_edit_domain, buf, 256);
    std::wstring wstr(buf);

    while (!wstr.empty() && (wstr.back() == L' ' || wstr.back() == L'\r' || wstr.back() == L'\n')) wstr.pop_back();
    while (!wstr.empty() && (wstr.front() == L' ' || wstr.front() == L'\t')) wstr.erase(wstr.begin());

    if (wstr.empty()) return;

    std::transform(wstr.begin(), wstr.end(), wstr.begin(), ::towlower);

    if (wstr.rfind(L"https://", 0) == 0) wstr = wstr.substr(8);
    if (wstr.rfind(L"http://", 0) == 0) wstr = wstr.substr(7);

    int count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; ++i) {
        wchar_t existing[256];
        SendMessageW(g_list_domains, LB_GETTEXT, i, (LPARAM)existing);
        if (_wcsicmp(existing, wstr.c_str()) == 0) {
            SetWindowTextW(g_edit_domain, L"");
            return;
        }
    }

    SendMessageW(g_list_domains, LB_ADDSTRING, 0, (LPARAM)wstr.c_str());
    SetWindowTextW(g_edit_domain, L"");

    char cbuf[256];
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, cbuf, sizeof(cbuf), NULL, NULL);
    if (g_engine) {
        g_engine->add_custom_domain(cbuf);
    }

    std::vector<std::string> list;
    count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; ++i) {
        wchar_t item[256];
        SendMessageW(g_list_domains, LB_GETTEXT, i, (LPARAM)item);
        char cibuf[256];
        WideCharToMultiByte(CP_UTF8, 0, item, -1, cibuf, sizeof(cibuf), NULL, NULL);
        list.push_back(cibuf);
    }
    save_domains_to_file(list);
}

void delete_selected_domain() {
    int sel = (int)SendMessageW(g_list_domains, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return;

    wchar_t item[256];
    SendMessageW(g_list_domains, LB_GETTEXT, sel, (LPARAM)item);
    SendMessageW(g_list_domains, LB_DELETESTRING, sel, 0);

    char cbuf[256];
    WideCharToMultiByte(CP_UTF8, 0, item, -1, cbuf, sizeof(cbuf), NULL, NULL);
    if (g_engine) {
        g_engine->remove_custom_domain(cbuf);
    }

    std::vector<std::string> list;
    int count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; ++i) {
        wchar_t it[256];
        SendMessageW(g_list_domains, LB_GETTEXT, i, (LPARAM)it);
        char cibuf[256];
        WideCharToMultiByte(CP_UTF8, 0, it, -1, cibuf, sizeof(cibuf), NULL, NULL);
        list.push_back(cibuf);
    }
    save_domains_to_file(list);
}

void import_domains_dialog(HWND hwnd) {
    wchar_t filename[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Текстовые файлы (*.txt)\0*.txt\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        std::ifstream in(filename);
        if (in.is_open()) {
            std::string line;
            while (std::getline(in, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) line.pop_back();
                while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(line.begin());
                if (!line.empty() && line[0] != '#') {
                    wchar_t wbuf[256];
                    MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, wbuf, 256);
                    SendMessageW(g_list_domains, LB_ADDSTRING, 0, (LPARAM)wbuf);
                }
            }
        }
        std::vector<std::string> list;
        int count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
        for (int i = 0; i < count; ++i) {
            wchar_t it[256];
            SendMessageW(g_list_domains, LB_GETTEXT, i, (LPARAM)it);
            char cibuf[256];
            WideCharToMultiByte(CP_UTF8, 0, it, -1, cibuf, sizeof(cibuf), NULL, NULL);
            list.push_back(cibuf);
        }
        save_domains_to_file(list);
        if (g_engine) g_engine->set_custom_domains(list);
    }
}

void export_domains_dialog(HWND hwnd) {
    wchar_t filename[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Текстовые файлы (*.txt)\0*.txt\0Все файлы (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn)) {
        std::ofstream out(filename);
        if (out.is_open()) {
            out << "# Экспортированный список доменов ByeByeDPI\n";
            int count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
            for (int i = 0; i < count; ++i) {
                wchar_t it[256];
                SendMessageW(g_list_domains, LB_GETTEXT, i, (LPARAM)it);
                char cibuf[256];
                WideCharToMultiByte(CP_UTF8, 0, it, -1, cibuf, sizeof(cibuf), NULL, NULL);
                out << cibuf << "\n";
            }
        }
    }
}

void reset_domains_to_default() {
    SendMessageW(g_list_domains, LB_RESETCONTENT, 0, 0);
    for (const auto& d : DEFAULT_PRESET_DOMAINS) {
        wchar_t wbuf[256];
        MultiByteToWideChar(CP_UTF8, 0, d.c_str(), -1, wbuf, 256);
        SendMessageW(g_list_domains, LB_ADDSTRING, 0, (LPARAM)wbuf);
    }
    save_domains_to_file(DEFAULT_PRESET_DOMAINS);
    if (g_engine) g_engine->set_custom_domains(DEFAULT_PRESET_DOMAINS);
}

void init_tray_icon(HWND hwnd) {
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY_ICON;
    g_nid.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_SHIELD);
    wcscpy_s(g_nid.szTip, L"ByeByeDPI - Обход DPI");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

void remove_tray_icon() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

void show_tray_menu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU hMenu = CreatePopupMenu();
    InsertMenuW(hMenu, 0, MF_BYPOSITION | MF_STRING, ID_TRAY_SHOW, L"Открыть окно ByeByeDPI");
    InsertMenuW(hMenu, 1, MF_BYPOSITION | MF_STRING, ID_TRAY_TOGGLE,
        g_engine_running.load(std::memory_order_relaxed) ? L"Остановить обход" : L"Включить обход");
    InsertMenuW(hMenu, 2, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
    InsertMenuW(hMenu, 3, MF_BYPOSITION | MF_STRING, ID_TRAY_EXIT, L"Выход из приложения");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

HMENU create_menu() {
    HMENU hMenuBar = CreateMenu();

    HMENU hFile = CreatePopupMenu();
    AppendMenuW(hFile, MF_STRING, IDM_FILE_START, L"Включить обход\tF5");
    AppendMenuW(hFile, MF_STRING, IDM_FILE_STOP, L"Остановить обход\tShift+F5");
    AppendMenuW(hFile, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hFile, MF_STRING, IDM_FILE_IMPORT, L"Импортировать домены...\tCtrl+O");
    AppendMenuW(hFile, MF_STRING, IDM_FILE_EXPORT, L"Экспортировать домены...\tCtrl+S");
    AppendMenuW(hFile, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hFile, MF_STRING, IDM_FILE_TRAY, L"Свернуть в трей\tCtrl+M");
    AppendMenuW(hFile, MF_STRING, IDM_FILE_EXIT, L"Выход\tAlt+F4");
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hFile, L"&Файл");

    HMENU hMode = CreatePopupMenu();
    AppendMenuW(hMode, MF_STRING | (g_opt_all_domains ? MF_CHECKED : MF_UNCHECKED), IDM_MODE_ALL, L"Универсальный режим (все сайты)");
    AppendMenuW(hMode, MF_STRING | (!g_opt_all_domains ? MF_CHECKED : MF_UNCHECKED), IDM_MODE_LIST, L"Только сайты из списка");
    AppendMenuW(hMode, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMode, MF_STRING | (g_opt_discord_voice ? MF_CHECKED : MF_UNCHECKED), IDM_MODE_DISCORD, L"Обход Discord Voice (UDP RTC)");
    AppendMenuW(hMode, MF_STRING | (g_opt_quic_drop ? MF_CHECKED : MF_UNCHECKED), IDM_MODE_QUIC, L"Форсировать TCP для YouTube (QUIC drop)");
    AppendMenuW(hMode, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMode, MF_STRING | (g_opt_fake_mode == engine::FakePacketMode::TcpTimestamp ? MF_CHECKED : MF_UNCHECKED), IDM_MODE_TS, L"Метод: TCP Timestamp (PAWS fooling)");
    AppendMenuW(hMode, MF_STRING | (g_opt_fake_mode == engine::FakePacketMode::BadChecksum ? MF_CHECKED : MF_UNCHECKED), IDM_MODE_BADSUM, L"Метод: Bad Checksum (0xDEAD)");
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hMode, L"&Режим обхода");

    HMENU hTools = CreatePopupMenu();
    AppendMenuW(hTools, MF_STRING, IDM_TOOLS_RESET_STAT, L"Сбросить статистику сессий");
    AppendMenuW(hTools, MF_STRING, IDM_TOOLS_RESET_DOMS, L"Восстановить домены по умолчанию");
    AppendMenuW(hTools, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hTools, MF_STRING, IDM_TOOLS_OPEN_DIR, L"Открыть папку с программой");
    AppendMenuW(hTools, MF_STRING, IDM_TOOLS_RESTART, L"Перезапустить с правами администратора");
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hTools, L"&Инструменты");

    HMENU hHelp = CreatePopupMenu();
    AppendMenuW(hHelp, MF_STRING, IDM_HELP_ABOUT, L"О программе ByeByeDPI");
    AppendMenuW(hHelp, MF_STRING, IDM_HELP_DOCS, L"Открыть репозиторий проекта");
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hHelp, L"&Справка");

    return hMenuBar;
}

void update_menu_state() {
    if (!g_hmenu) return;
    HMENU hMode = GetSubMenu(g_hmenu, 1);
    if (!hMode) return;

    CheckMenuItem(hMode, IDM_MODE_ALL, g_opt_all_domains ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hMode, IDM_MODE_LIST, !g_opt_all_domains ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hMode, IDM_MODE_DISCORD, g_opt_discord_voice ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hMode, IDM_MODE_QUIC, g_opt_quic_drop ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hMode, IDM_MODE_TS, (g_opt_fake_mode == engine::FakePacketMode::TcpTimestamp) ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hMode, IDM_MODE_BADSUM, (g_opt_fake_mode == engine::FakePacketMode::BadChecksum) ? MF_CHECKED : MF_UNCHECKED);
}

void paint_gui(HWND hwnd, HDC hdc) {
    RECT rc;
    GetClientRect(hwnd, &rc);

    FillRect(hdc, &rc, g_br_bg);
    SetBkMode(hdc, TRANSPARENT);

    RECT rc_header = { 20, 16, rc.right - 20, 70 };
    HBRUSH old_br = (HBRUSH)SelectObject(hdc, g_br_panel);
    HPEN pen_border = CreatePen(PS_SOLID, 1, CLR_BORDER);
    HPEN old_pen = (HPEN)SelectObject(hdc, pen_border);
    RoundRect(hdc, rc_header.left, rc_header.top, rc_header.right, rc_header.bottom, 12, 12);

    SelectObject(hdc, g_font_title);
    SetTextColor(hdc, CLR_TEXT);
    TextOutW(hdc, 36, 26, L"ByeByeDPI", 9);

    SelectObject(hdc, g_font_main);
    SetTextColor(hdc, CLR_TEXT_MUTED);
    TextOutW(hdc, 150, 33, L"Обход DPI", 9);

    bool running = g_engine_running.load(std::memory_order_relaxed);
    RECT rc_badge = { rc.right - 210, 26, rc.right - 36, 60 };
    HBRUSH br_badge = CreateSolidBrush(running ? RGB(20, 50, 36) : RGB(40, 40, 50));
    HPEN pen_badge = CreatePen(PS_SOLID, 1, running ? CLR_GREEN : RGB(70, 70, 85));
    SelectObject(hdc, br_badge);
    SelectObject(hdc, pen_badge);
    RoundRect(hdc, rc_badge.left, rc_badge.top, rc_badge.right, rc_badge.bottom, 8, 8);

    SelectObject(hdc, g_font_bold);
    SetTextColor(hdc, running ? CLR_GREEN : CLR_TEXT_MUTED);
    DrawTextW(hdc, running ? L"● ОБХОД ВКЛЮЧЕН" : L"○ ОБХОД ВЫКЛЮЧЕН", -1, &rc_badge, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    DeleteObject(br_badge);
    DeleteObject(pen_badge);

    RECT rc_stat = { 20, 146, rc.right - 20, 226 };
    SelectObject(hdc, g_br_card);
    SelectObject(hdc, pen_border);
    RoundRect(hdc, rc_stat.left, rc_stat.top, rc_stat.right, rc_stat.bottom, 12, 12);

    int col_w = (rc_stat.right - rc_stat.left) / 4;
    for (int i = 1; i < 4; ++i) {
        int x = rc_stat.left + col_w * i;
        MoveToEx(hdc, x, rc_stat.top + 10, NULL);
        LineTo(hdc, x, rc_stat.bottom - 10);
    }

    SelectObject(hdc, g_font_stat_lbl);
    SetTextColor(hdc, CLR_TEXT_MUTED);
    TextOutW(hdc, rc_stat.left + 20, rc_stat.top + 14, L"ПАКЕТОВ ВСЕГО", 13);
    TextOutW(hdc, rc_stat.left + col_w + 20, rc_stat.top + 14, L"TLS СЕССИЙ", 10);
    TextOutW(hdc, rc_stat.left + col_w * 2 + 20, rc_stat.top + 14, L"ОБОЙДЕНО DPI", 12);
    TextOutW(hdc, rc_stat.left + col_w * 3 + 20, rc_stat.top + 14, L"DISCORD RTC", 11);

    uint64_t total = 0, tls = 0, bypass = 0, udp = 0;
    if (g_engine) {
        const auto& m = g_engine->metrics();
        total = m.total_packets.load(std::memory_order_relaxed);
        tls = m.tls_client_hellos.load(std::memory_order_relaxed);
        bypass = m.tcp_segments_created.load(std::memory_order_relaxed);
        udp = m.udp_packets.load(std::memory_order_relaxed);
    }

    SelectObject(hdc, g_font_stat);
    SetTextColor(hdc, CLR_TEXT);

    wchar_t num_buf[32];
    swprintf_s(num_buf, L"%llu", total);
    TextOutW(hdc, rc_stat.left + 20, rc_stat.top + 38, num_buf, (int)wcslen(num_buf));

    swprintf_s(num_buf, L"%llu", tls);
    TextOutW(hdc, rc_stat.left + col_w + 20, rc_stat.top + 38, num_buf, (int)wcslen(num_buf));

    swprintf_s(num_buf, L"%llu", bypass);
    TextOutW(hdc, rc_stat.left + col_w * 2 + 20, rc_stat.top + 38, num_buf, (int)wcslen(num_buf));

    swprintf_s(num_buf, L"%llu", udp);
    TextOutW(hdc, rc_stat.left + col_w * 3 + 20, rc_stat.top + 38, num_buf, (int)wcslen(num_buf));

    SelectObject(hdc, g_font_bold);
    SetTextColor(hdc, CLR_TEXT);
    TextOutW(hdc, 20, 246, L"Целевые домены для обхода DPI:", 30);

    RECT rc_bar = { 0, rc.bottom - 26, rc.right, rc.bottom };
    HBRUSH br_bar = CreateSolidBrush(RGB(16, 16, 20));
    FillRect(hdc, &rc_bar, br_bar);
    DeleteObject(br_bar);

    SelectObject(hdc, g_font_stat_lbl);
    SetTextColor(hdc, CLR_TEXT_MUTED);
    int dom_count = (int)SendMessageW(g_list_domains, LB_GETCOUNT, 0, 0);
    wchar_t status_text[128];
    swprintf_s(status_text, L"  Служба WinDivert v2.2 | Режим ядра: NETWORK | Доменов в базе: %d | Метод: %s",
        dom_count,
        (g_opt_fake_mode == engine::FakePacketMode::TcpTimestamp) ? L"TCP Timestamp (ts)" : L"Bad Checksum");
    TextOutW(hdc, 10, rc.bottom - 20, status_text, (int)wcslen(status_text));

    SelectObject(hdc, old_br);
    SelectObject(hdc, old_pen);
    DeleteObject(pen_border);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;

        BOOL dark_mode = TRUE;
        DwmSetWindowAttribute(hwnd, 20, &dark_mode, sizeof(dark_mode));

      
        g_hmenu = create_menu();
        SetMenu(hwnd, g_hmenu);

        g_font_title = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_font_main = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_font_bold = CreateFontW(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_font_stat = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_font_stat_lbl = CreateFontW(12, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        g_br_bg = CreateSolidBrush(CLR_BG);
        g_br_panel = CreateSolidBrush(CLR_PANEL);
        g_br_card = CreateSolidBrush(CLR_CARD);
        g_br_edit = CreateSolidBrush(RGB(26, 27, 36));

        g_btn_start_stop = CreateWindowW(
            L"BUTTON", L"Включить обход",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            20, 80, 546, 52,
            hwnd, (HMENU)(UINT_PTR)IDC_BTN_START_STOP, NULL, NULL);

        g_edit_domain = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
            20, 276, 362, 34,
            hwnd, (HMENU)(UINT_PTR)IDC_EDIT_DOMAIN, NULL, NULL);
        SendMessageW(g_edit_domain, WM_SETFONT, (WPARAM)g_font_main, TRUE);
        SendMessageW(g_edit_domain, EM_SETCUEBANNER, TRUE, (LPARAM)L"Введите домен для обхода (например, example.com)");

        g_btn_add = CreateWindowW(
            L"BUTTON", L"+ Добавить",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            390, 276, 84, 34,
            hwnd, (HMENU)(UINT_PTR)IDC_BTN_ADD_DOMAIN, NULL, NULL);

        g_btn_del = CreateWindowW(
            L"BUTTON", L"Удалить",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            482, 276, 84, 34,
            hwnd, (HMENU)(UINT_PTR)IDC_BTN_DEL_DOMAIN, NULL, NULL);

        g_list_domains = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_VISIBLE | WS_CHILD | LBS_NOTIFY | WS_VSCROLL | WS_BORDER,
            20, 320, 546, 175,
            hwnd, (HMENU)(UINT_PTR)IDC_LIST_DOMAINS, NULL, NULL);
        SendMessageW(g_list_domains, WM_SETFONT, (WPARAM)g_font_main, TRUE);

        auto domains = load_domains_from_file();
        for (const auto& d : domains) {
            wchar_t wbuf[256];
            MultiByteToWideChar(CP_UTF8, 0, d.c_str(), -1, wbuf, 256);
            SendMessageW(g_list_domains, LB_ADDSTRING, 0, (LPARAM)wbuf);
        }

        g_chk_all = CreateWindowW(
            L"BUTTON", L"",
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            20, 510, 18, 18,
            hwnd, (HMENU)(UINT_PTR)IDC_CHK_ALL_DOMAINS, NULL, NULL);
        Button_SetCheck(g_chk_all, g_opt_all_domains ? BST_CHECKED : BST_UNCHECKED);
        SetWindowTheme(g_chk_all, L"DarkMode_Explorer", NULL);

        g_lbl_all = CreateWindowW(
            L"STATIC", L"Применять обход ко всем сайтам (универсальный режим)",
            WS_VISIBLE | WS_CHILD | SS_NOTIFY,
            44, 508, 520, 22,
            hwnd, (HMENU)(UINT_PTR)IDC_LBL_ALL_DOMAINS, NULL, NULL);
        SendMessageW(g_lbl_all, WM_SETFONT, (WPARAM)g_font_main, TRUE);

        g_chk_discord = CreateWindowW(
            L"BUTTON", L"",
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            20, 538, 18, 18,
            hwnd, (HMENU)(UINT_PTR)IDC_CHK_DISCORD, NULL, NULL);
        Button_SetCheck(g_chk_discord, g_opt_discord_voice ? BST_CHECKED : BST_UNCHECKED);
        SetWindowTheme(g_chk_discord, L"DarkMode_Explorer", NULL);

        g_lbl_discord = CreateWindowW(
            L"STATIC", L"Обход Discord Voice (голосовые каналы UDP / WebRTC)",
            WS_VISIBLE | WS_CHILD | SS_NOTIFY,
            44, 536, 520, 22,
            hwnd, (HMENU)(UINT_PTR)IDC_LBL_DISCORD, NULL, NULL);
        SendMessageW(g_lbl_discord, WM_SETFONT, (WPARAM)g_font_main, TRUE);

        g_chk_tray = CreateWindowW(
            L"BUTTON", L"",
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            20, 566, 18, 18,
            hwnd, (HMENU)(UINT_PTR)IDC_CHK_TRAY, NULL, NULL);
        Button_SetCheck(g_chk_tray, g_opt_tray_on_close ? BST_CHECKED : BST_UNCHECKED);
        SetWindowTheme(g_chk_tray, L"DarkMode_Explorer", NULL);

        g_lbl_tray = CreateWindowW(
            L"STATIC", L"Сворачивать в системный трей при закрытии окна",
            WS_VISIBLE | WS_CHILD | SS_NOTIFY,
            44, 564, 520, 22,
            hwnd, (HMENU)(UINT_PTR)IDC_LBL_TRAY, NULL, NULL);
        SendMessageW(g_lbl_tray, WM_SETFONT, (WPARAM)g_font_main, TRUE);

        init_tray_icon(hwnd);

        SetTimer(hwnd, IDT_STATS, 1000, NULL);
        return 0;
    }

    case WM_TIMER: {
        if (wParam == IDT_STATS) {
            RECT rc_stat = { 20, 146, 566, 226 };
            InvalidateRect(hwnd, &rc_stat, FALSE);
        }
        return 0;
    }

    case WM_DRAWITEM: {
        auto* pdis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (!pdis) break;

        HDC hdc = pdis->hDC;
        RECT rc = pdis->rcItem;
        bool pressed = (pdis->itemState & ODS_SELECTED);

        if (pdis->CtlID == IDC_BTN_START_STOP) {
            bool running = g_engine_running.load(std::memory_order_relaxed);
            COLORREF btn_clr = running ? (pressed ? CLR_RED_HOV : CLR_RED)
                                       : (pressed ? CLR_GREEN_HOV : CLR_GREEN);

            HBRUSH br = CreateSolidBrush(btn_clr);
            HPEN pen = CreatePen(PS_SOLID, 1, btn_clr);
            HBRUSH old_br = (HBRUSH)SelectObject(hdc, br);
            HPEN old_pen = (HPEN)SelectObject(hdc, pen);

            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 12, 12);

            SelectObject(hdc, g_font_bold);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255));

            const wchar_t* text = running ? L"Остановить обход" : L"Включить обход";
            DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(hdc, old_br);
            SelectObject(hdc, old_pen);
            DeleteObject(br);
            DeleteObject(pen);
            return TRUE;
        } else if (pdis->CtlID == IDC_BTN_ADD_DOMAIN || pdis->CtlID == IDC_BTN_DEL_DOMAIN) {
            COLORREF btn_clr = (pdis->CtlID == IDC_BTN_ADD_DOMAIN)
                ? (pressed ? CLR_ACCENT_HOV : CLR_ACCENT)
                : (pressed ? RGB(55, 55, 68) : RGB(42, 42, 54));

            HBRUSH br = CreateSolidBrush(btn_clr);
            HPEN pen = CreatePen(PS_SOLID, 1, CLR_BORDER);
            HBRUSH old_br = (HBRUSH)SelectObject(hdc, br);
            HPEN old_pen = (HPEN)SelectObject(hdc, pen);

            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 8, 8);

            SelectObject(hdc, g_font_bold);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255));

            wchar_t text[64];
            GetWindowTextW(pdis->hwndItem, text, 64);
            DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(hdc, old_br);
            SelectObject(hdc, old_pen);
            DeleteObject(br);
            DeleteObject(pen);
            return TRUE;
        }
        break;
    }

    
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, CLR_BG);
        return (INT_PTR)g_br_bg;
    }

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, RGB(26, 27, 36));
        return (INT_PTR)g_br_edit;
    }

    case WM_CTLCOLORBTN: {
        return (INT_PTR)g_br_bg;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);

        if (id == IDC_BTN_START_STOP || id == IDM_FILE_START || id == ID_TRAY_TOGGLE) {
            toggle_engine();
            InvalidateRect(g_btn_start_stop, NULL, TRUE);
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDM_FILE_STOP) {
            stop_engine();
            InvalidateRect(g_btn_start_stop, NULL, TRUE);
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_BTN_ADD_DOMAIN) {
            add_domain_from_edit();
        } else if (id == IDC_BTN_DEL_DOMAIN) {
            delete_selected_domain();
        } else if (id == IDC_CHK_ALL_DOMAINS || id == IDC_LBL_ALL_DOMAINS || id == IDM_MODE_ALL || id == IDM_MODE_LIST) {
            if (id == IDM_MODE_ALL) g_opt_all_domains = true;
            else if (id == IDM_MODE_LIST) g_opt_all_domains = false;
            else if (id == IDC_LBL_ALL_DOMAINS) g_opt_all_domains = !g_opt_all_domains;
            else g_opt_all_domains = (Button_GetCheck(g_chk_all) == BST_CHECKED);
            Button_SetCheck(g_chk_all, g_opt_all_domains ? BST_CHECKED : BST_UNCHECKED);
            update_menu_state();
            if (g_engine) g_engine->config().bypass_all_domains = g_opt_all_domains;
        } else if (id == IDC_CHK_DISCORD || id == IDC_LBL_DISCORD || id == IDM_MODE_DISCORD) {
            if (id == IDM_MODE_DISCORD || id == IDC_LBL_DISCORD) g_opt_discord_voice = !g_opt_discord_voice;
            else g_opt_discord_voice = (Button_GetCheck(g_chk_discord) == BST_CHECKED);
            Button_SetCheck(g_chk_discord, g_opt_discord_voice ? BST_CHECKED : BST_UNCHECKED);
            update_menu_state();
            if (g_engine) g_engine->config().udp_rtc_policy = g_opt_discord_voice ? engine::UdpRtcPolicy::FakePayload : engine::UdpRtcPolicy::None;
        } else if (id == IDC_CHK_TRAY || id == IDC_LBL_TRAY) {
            if (id == IDC_LBL_TRAY) g_opt_tray_on_close = !g_opt_tray_on_close;
            else g_opt_tray_on_close = (Button_GetCheck(g_chk_tray) == BST_CHECKED);
            Button_SetCheck(g_chk_tray, g_opt_tray_on_close ? BST_CHECKED : BST_UNCHECKED);
        } else if (id == IDM_MODE_QUIC) {
            g_opt_quic_drop = !g_opt_quic_drop;
            update_menu_state();
            if (g_engine) g_engine->config().enable_udp_443_redirection = g_opt_quic_drop;
        } else if (id == IDM_MODE_TS) {
            g_opt_fake_mode = engine::FakePacketMode::TcpTimestamp;
            update_menu_state();
            if (g_engine) g_engine->config().fake_mode = g_opt_fake_mode;
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDM_MODE_BADSUM) {
            g_opt_fake_mode = engine::FakePacketMode::BadChecksum;
            update_menu_state();
            if (g_engine) g_engine->config().fake_mode = g_opt_fake_mode;
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDM_FILE_IMPORT) {
            import_domains_dialog(hwnd);
        } else if (id == IDM_FILE_EXPORT) {
            export_domains_dialog(hwnd);
        } else if (id == IDM_FILE_TRAY) {
            ShowWindow(hwnd, SW_HIDE);
        } else if (id == IDM_FILE_EXIT) {
            stop_engine();
            remove_tray_icon();
            DestroyWindow(hwnd);
        } else if (id == IDM_TOOLS_RESET_STAT) {
            if (g_engine) g_engine->reset_metrics();
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDM_TOOLS_RESET_DOMS) {
            if (MessageBoxW(hwnd, L"Восстановить исходный список доменов по умолчанию?", L"Подтверждение", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                reset_domains_to_default();
            }
        } else if (id == IDM_TOOLS_OPEN_DIR) {
            wchar_t dir[MAX_PATH];
            GetModuleFileNameW(NULL, dir, MAX_PATH);
            wchar_t* last = wcsrchr(dir, L'\\');
            if (last) *last = L'\0';
            ShellExecuteW(hwnd, L"open", dir, NULL, NULL, SW_SHOW);
        } else if (id == IDM_TOOLS_RESTART) {
            run_as_admin();
            stop_engine();
            remove_tray_icon();
            DestroyWindow(hwnd);
        } else if (id == IDM_HELP_ABOUT) {
            MessageBoxW(hwnd,
                L"ByeByeDPI\n\n"
                L"Нативная утилита обхода сетевых систем DPI (YouTube, Discord, сайты).\n"
                L"Архитектура: WinDivert Kernel Network Layer (x64 C++20).\n\n"
                L"Особенности:\n"
                L"• HostFakeSplit / SeqOverlap для инфраструктуры YouTube CDN\n"
                L"• FakeSplit + TCP Timestamp PAWS для веб-ресурсов\n"
                L"• Пейлоад десинхронизации голосовых каналов Discord (RTC UDP)\n"
                L"• Полная автономность без внешних файлов",
                L"О программе ByeByeDPI", MB_ICONINFORMATION | MB_OK);
        } else if (id == IDM_HELP_DOCS) {
            ShellExecuteW(hwnd, L"open", L"https://github.com/Jwachka1337/ByeByeDPI/", NULL, NULL, SW_SHOW);
        } else if (id == ID_TRAY_SHOW) {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        } else if (id == ID_TRAY_EXIT) {
            stop_engine();
            remove_tray_icon();
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_TRAY_ICON: {
        if (lParam == WM_LBUTTONDBLCLK) {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        } else if (lParam == WM_RBUTTONUP) {
            show_tray_menu(hwnd);
        }
        return 0;
    }

    case WM_CLOSE: {
        if (g_opt_tray_on_close) {
            ShowWindow(hwnd, SW_HIDE);
        } else {
            stop_engine();
            remove_tray_icon();
            DestroyWindow(hwnd);
        }
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        paint_gui(hwnd, hdc);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY: {
        stop_engine();
        remove_tray_icon();
        KillTimer(hwnd, IDT_STATS);

        if (g_br_bg) DeleteObject(g_br_bg);
        if (g_br_panel) DeleteObject(g_br_panel);
        if (g_br_card) DeleteObject(g_br_card);
        if (g_br_edit) DeleteObject(g_br_edit);
        if (g_font_main) DeleteObject(g_font_main);
        if (g_font_title) DeleteObject(g_font_title);
        if (g_font_bold) DeleteObject(g_font_bold);
        if (g_font_stat) DeleteObject(g_font_stat);
        if (g_font_stat_lbl) DeleteObject(g_font_stat_lbl);

        PostQuitMessage(0);
        return 0;
    }

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

} 

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    if (!is_admin()) {
        if (run_as_admin()) {
            return 0;
        }
        MessageBoxW(NULL, L"Для работы фильтрации WinDivert требуются права администратора.", L"Ошибка прав доступа", MB_ICONERROR | MB_OK);
        return 1;
    }

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        MessageBoxW(NULL, L"Не удалось инициализировать Winsock API.", L"Ошибка", MB_ICONERROR | MB_OK);
        return 1;
    }

    auto deploy = deployer::initialize();
    if (!deploy.success) {
        std::wstring werr(deploy.error_message.begin(), deploy.error_message.end());
        MessageBoxW(NULL, werr.c_str(), L"Ошибка инициализации WinDivert", MB_ICONERROR | MB_OK);
        WSACleanup();
        return 1;
    }

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    const wchar_t CLASS_NAME[] = L"ByeByeDPI";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = CLASS_NAME;
    wc.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_SHIELD);

    RegisterClassExW(&wc);

    int width = 600;
    int height = 690;
    int screen_w = GetSystemMetrics(SM_CXSCREEN);
    int screen_h = GetSystemMetrics(SM_CYSCREEN);
    int pos_x = (screen_w - width) / 2;
    int pos_y = (screen_h - height) / 2;

    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"ByeByeDPI - Обход блокировок DPI",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        pos_x, pos_y, width, height,
        NULL, NULL, hInstance, NULL);

    if (!hwnd) {
        WSACleanup();
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    deployer::cleanup();
    WSACleanup();
    return (int)msg.wParam;
}
