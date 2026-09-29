#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windivert.h>

#include <string>
#include <atomic>

namespace deployer {

// Результат инициализации встроенного WinDivert
struct DeployResult {
    bool success{false};
    std::string error_message;
    std::wstring deploy_directory;  
};


DeployResult initialize();


void cleanup();

bool is_loaded();

const std::wstring& deploy_path();


// Указатели на функции WinDivert 


using pfnWinDivertOpen = HANDLE(WINAPI*)(
    const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);

using pfnWinDivertClose = BOOL(WINAPI*)(HANDLE handle);

using pfnWinDivertRecv = BOOL(WINAPI*)(
    HANDLE handle, VOID* pPacket, UINT packetLen,
    UINT* pRecvLen, WINDIVERT_ADDRESS* pAddr);

using pfnWinDivertSend = BOOL(WINAPI*)(
    HANDLE handle, const VOID* pPacket, UINT packetLen,
    UINT* pSendLen, const WINDIVERT_ADDRESS* pAddr);

using pfnWinDivertShutdown = BOOL(WINAPI*)(
    HANDLE handle, WINDIVERT_SHUTDOWN how);

using pfnWinDivertSetParam = BOOL(WINAPI*)(
    HANDLE handle, WINDIVERT_PARAM param, UINT64 value);

using pfnWinDivertGetParam = BOOL(WINAPI*)(
    HANDLE handle, WINDIVERT_PARAM param, UINT64* pValue);

using pfnWinDivertHelperCalcChecksums = BOOL(WINAPI*)(
    VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags);

using pfnWinDivertHelperCompileFilter = BOOL(WINAPI*)(
    const char* filter, WINDIVERT_LAYER layer,
    char* object, UINT objLen,
    const char** errorStr, UINT* errorPos);

extern pfnWinDivertOpen             pWinDivertOpen;
extern pfnWinDivertClose            pWinDivertClose;
extern pfnWinDivertRecv             pWinDivertRecv;
extern pfnWinDivertSend             pWinDivertSend;
extern pfnWinDivertShutdown         pWinDivertShutdown;
extern pfnWinDivertSetParam         pWinDivertSetParam;
extern pfnWinDivertGetParam         pWinDivertGetParam;
extern pfnWinDivertHelperCalcChecksums pWinDivertHelperCalcChecksums;
extern pfnWinDivertHelperCompileFilter pWinDivertHelperCompileFilter;

} 
