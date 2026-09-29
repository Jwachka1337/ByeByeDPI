#include "windivert_deployer.hpp"
#include "resource_ids.h"

#include <shlobj.h>
#include <filesystem>
#include <sstream>
#include <cstdio>

#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

namespace deployer {


// Глобальные указатели на функции WinDivert

pfnWinDivertOpen             pWinDivertOpen = nullptr;
pfnWinDivertClose            pWinDivertClose = nullptr;
pfnWinDivertRecv             pWinDivertRecv = nullptr;
pfnWinDivertSend             pWinDivertSend = nullptr;
pfnWinDivertShutdown         pWinDivertShutdown = nullptr;
pfnWinDivertSetParam         pWinDivertSetParam = nullptr;
pfnWinDivertGetParam         pWinDivertGetParam = nullptr;
pfnWinDivertHelperCalcChecksums pWinDivertHelperCalcChecksums = nullptr;
pfnWinDivertHelperCompileFilter pWinDivertHelperCompileFilter = nullptr;


namespace {

std::atomic<bool> g_initialized{false};
HMODULE           g_windivert_dll = nullptr;
std::wstring      g_deploy_dir;

struct EmbeddedFile {
    int resource_id;
    const wchar_t* filename;
};

constexpr EmbeddedFile DEPLOY_FILES[] = {
    { IDR_WINDIVERT_DLL,    L"WinDivert.dll"   },
    { IDR_WINDIVERT64_SYS,  L"WinDivert64.sys" },
    { IDR_WINDIVERT_SYS,    L"WinDivert.sys"   },
};

bool extract_resource(int resource_id, const std::wstring& target_path, std::string& error) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(resource_id), RT_RCDATA);
    if (!hRes) {
        error = "FindResource не нашёл ресурс ID=" + std::to_string(resource_id);
        return false;
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        error = "LoadResource провалился для ID=" + std::to_string(resource_id);
        return false;
    }

    void* pData = LockResource(hData);
    DWORD dataSize = SizeofResource(NULL, hRes);
    if (!pData || dataSize == 0) {
        error = "LockResource/SizeofResource провалились для ID=" + std::to_string(resource_id);
        return false;
    }
    HANDLE hFile = CreateFileW(
        target_path.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "Не удалось создать файл: ошибка " << err;
        error = oss.str();
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, pData, dataSize, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != dataSize) {
        error = "Ошибка записи данных ресурса в файл";
        return false;
    }

    return true;
}

std::wstring make_deploy_directory() {
    wchar_t temp_path[MAX_PATH + 1];
    DWORD len = GetTempPathW(MAX_PATH, temp_path);
    if (len == 0 || len > MAX_PATH) {
        return L"";
    }

    DWORD pid = GetCurrentProcessId();
    std::wstring dir = std::wstring(temp_path) + L"ByeByeDPI_WinDivert_" + std::to_wstring(pid);
    return dir;
}

void remove_deploy_directory(const std::wstring& dir) {
    if (dir.empty()) return;

    std::error_code ec;
    fs::remove_all(dir, ec);
}

} 

DeployResult initialize() {
    DeployResult result;

    if (g_initialized.load(std::memory_order_acquire)) {
        result.success = true;
        result.deploy_directory = g_deploy_dir;
        return result;
    }

    g_deploy_dir = make_deploy_directory();
    if (g_deploy_dir.empty()) {
        result.error_message = "Не удалось определить путь временной папки (GetTempPathW)";
        return result;
    }

    std::error_code ec;
    fs::create_directories(g_deploy_dir, ec);
    if (ec) {
        result.error_message = "Не удалось создать временную папку: " + ec.message();
        return result;
    }

    for (const auto& ef : DEPLOY_FILES) {
        std::wstring target = g_deploy_dir + L"\\" + ef.filename;
        std::string err;
        if (!extract_resource(ef.resource_id, target, err)) {
            char fname_buf[64]{};
            WideCharToMultiByte(CP_UTF8, 0, ef.filename, -1, fname_buf, sizeof(fname_buf), NULL, NULL);
            result.error_message = "Ошибка извлечения " +
                std::string(fname_buf) + ": " + err;
            remove_deploy_directory(g_deploy_dir);
            return result;
        }
    }

    SetDllDirectoryW(g_deploy_dir.c_str());

    std::wstring dll_path = g_deploy_dir + L"\\WinDivert.dll";
    g_windivert_dll = LoadLibraryW(dll_path.c_str());
    if (!g_windivert_dll) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "Не удалось загрузить WinDivert.dll из временной папки (код ошибки: " << err << ")";
        result.error_message = oss.str();
        remove_deploy_directory(g_deploy_dir);
        return result;
    }

    #define LOAD_FUNC(name, type) \
        p##name = reinterpret_cast<type>(GetProcAddress(g_windivert_dll, #name)); \
        if (!p##name) { \
            result.error_message = "Не найдена функция " #name " в WinDivert.dll"; \
            FreeLibrary(g_windivert_dll); \
            g_windivert_dll = nullptr; \
            remove_deploy_directory(g_deploy_dir); \
            return result; \
        }

    LOAD_FUNC(WinDivertOpen,                 pfnWinDivertOpen)
    LOAD_FUNC(WinDivertClose,                pfnWinDivertClose)
    LOAD_FUNC(WinDivertRecv,                 pfnWinDivertRecv)
    LOAD_FUNC(WinDivertSend,                 pfnWinDivertSend)
    LOAD_FUNC(WinDivertShutdown,             pfnWinDivertShutdown)
    LOAD_FUNC(WinDivertSetParam,             pfnWinDivertSetParam)
    LOAD_FUNC(WinDivertGetParam,             pfnWinDivertGetParam)
    LOAD_FUNC(WinDivertHelperCalcChecksums,  pfnWinDivertHelperCalcChecksums)
    LOAD_FUNC(WinDivertHelperCompileFilter,  pfnWinDivertHelperCompileFilter)

    #undef LOAD_FUNC

    g_initialized.store(true, std::memory_order_release);

    result.success = true;
    result.deploy_directory = g_deploy_dir;
    return result;
}

void cleanup() {
    if (!g_initialized.load(std::memory_order_acquire)) return;

    pWinDivertOpen = nullptr;
    pWinDivertClose = nullptr;
    pWinDivertRecv = nullptr;
    pWinDivertSend = nullptr;
    pWinDivertShutdown = nullptr;
    pWinDivertSetParam = nullptr;
    pWinDivertGetParam = nullptr;
    pWinDivertHelperCalcChecksums = nullptr;
    pWinDivertHelperCompileFilter = nullptr;

    if (g_windivert_dll) {
        FreeLibrary(g_windivert_dll);
        g_windivert_dll = nullptr;
    }

    SetDllDirectoryW(NULL);

    g_initialized.store(false, std::memory_order_release);

    remove_deploy_directory(g_deploy_dir);
    g_deploy_dir.clear();
}

bool is_loaded() {
    return g_initialized.load(std::memory_order_acquire);
}

const std::wstring& deploy_path() {
    return g_deploy_dir;
}

} 
