/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "../driver/ioctl.h"
#include "logger.h"
#include "adapter.h"
#include "ntdll.h"
#include <Windows.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <wchar.h>
#include <stdlib.h>

static BOOL CALLBACK
NopLogger(_In_ WIREGUARD_LOGGER_LEVEL Level, _In_z_ LPCWSTR LogLine)
{
    return TRUE;
}

WIREGUARD_LOGGER_CALLBACK Logger = NopLogger;

_Use_decl_annotations_
VOID WINAPI
WireGuardSetLogger(WIREGUARD_LOGGER_CALLBACK NewLogger)
{
    if (!NewLogger)
        NewLogger = NopLogger;
    Logger = NewLogger;
}

static VOID
StrTruncate(_Inout_count_(StrChars) LPWSTR Str, _In_ SIZE_T StrChars)
{
    Str[StrChars - 2] = L'\u2026'; /* Horizontal Ellipsis */
    Str[StrChars - 1] = 0;
}

_Use_decl_annotations_
DWORD
LoggerLog(WIREGUARD_LOGGER_LEVEL Level, LPCWSTR Function, LPCWSTR LogLine)
{
    DWORD LastError = GetLastError();
    if (Function)
    {
        WCHAR Combined[0x400];
        if (_snwprintf_s(Combined, _countof(Combined), _TRUNCATE, L"%s: %s", Function, LogLine) == -1)
            StrTruncate(Combined, _countof(Combined));
        Logger(Level, Combined);
    }
    else
        Logger(Level, LogLine);
    SetLastError(LastError);
    return LastError;
}

_Use_decl_annotations_
DWORD
LoggerLogV(WIREGUARD_LOGGER_LEVEL Level, LPCWSTR Function, LPCWSTR Format, va_list Args)
{
    DWORD LastError = GetLastError();
    WCHAR LogLine[0x400];
    if (_vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, Args) == -1)
        StrTruncate(LogLine, _countof(LogLine));
    if (Function)
        LoggerLog(Level, Function, LogLine);
    else
        Logger(Level, LogLine);
    SetLastError(LastError);
    return LastError;
}

_Use_decl_annotations_
DWORD
LoggerError(DWORD Error, LPCWSTR Function, LPCWSTR Prefix)
{
    LPWSTR SystemMessage = NULL, FormattedMessage = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        HRESULT_FROM_SETUPAPI(Error),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (VOID *)&SystemMessage,
        0,
        NULL);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_MAX_WIDTH_MASK,
        SystemMessage ? L"%4: %1: %3(Code 0x%2!08X!)" : L"%4: %1: Code 0x%2!08X!",
        0,
        0,
        (VOID *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage, (DWORD_PTR)Function });
    if (FormattedMessage)
        Logger(WIREGUARD_LOG_ERR, FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

_Use_decl_annotations_
DWORD
LoggerErrorV(DWORD Error, LPCWSTR Function, LPCWSTR Format, va_list Args)
{
    WCHAR Prefix[0x400];
    if (_vsnwprintf_s(Prefix, _countof(Prefix), _TRUNCATE, Format, Args) == -1)
        StrTruncate(Prefix, _countof(Prefix));
    return LoggerError(Error, Function, Prefix);
}

_Use_decl_annotations_
VOID
LoggerGetRegistryKeyPath(HKEY Key, LPWSTR Path)
{
    DWORD LastError = GetLastError();
    if (Key == NULL)
    {
        wcsncpy_s(Path, MAX_REG_PATH, L"<null>", _TRUNCATE);
        goto out;
    }
    if (_snwprintf_s(Path, MAX_REG_PATH, _TRUNCATE, L"0x%p", Key) == -1)
        StrTruncate(Path, MAX_REG_PATH);
    union
    {
        KEY_NAME_INFORMATION KeyNameInfo;
        WCHAR Data[offsetof(KEY_NAME_INFORMATION, Name) + MAX_REG_PATH];
    } Buffer;
    DWORD Size;
    if (!NT_SUCCESS(NtQueryKey(Key, 3, &Buffer, sizeof(Buffer), &Size)) ||
        Size < offsetof(KEY_NAME_INFORMATION, Name) || Buffer.KeyNameInfo.NameLength >= MAX_REG_PATH * sizeof(WCHAR))
        goto out;
    Buffer.KeyNameInfo.NameLength /= sizeof(WCHAR);
    wmemcpy_s(Path, MAX_REG_PATH, Buffer.KeyNameInfo.Name, Buffer.KeyNameInfo.NameLength);
    Path[Buffer.KeyNameInfo.NameLength] = L'\0';
out:
    SetLastError(LastError);
}

static DWORD WINAPI
LogReaderThread(_In_ LPVOID Parameter)
{
    WIREGUARD_ADAPTER *Adapter = Parameter;
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Unable to enable logging");
        WriteULongNoFence(&Adapter->LogState, WIREGUARD_ADAPTER_LOG_OFF);
        return 0;
    }
    while (ReadULongNoFence(&Adapter->LogState) != WIREGUARD_ADAPTER_LOG_OFF)
    {
        WCHAR WideLine[WG_MAX_LOG_LINE_LEN + 32] = { 0 };
        CHAR Line[WG_MAX_LOG_LINE_LEN] = { 0 };
        DWORD Bytes = sizeof(Line);
        if (!DeviceIoControl(ControlFile, WG_IOCTL_READ_LOG_LINE, NULL, 0, Line, Bytes, &Bytes, NULL))
        {
            BOOL IsAbort = GetLastError() == ERROR_OPERATION_ABORTED;
            CloseHandle(ControlFile);
            if (ReadULongNoFence(&Adapter->LogState) == WIREGUARD_ADAPTER_LOG_OFF)
                return 0;
            if (IsAbort)
                Sleep(5000);
            for (DWORD i = 0;; ++i)
            {
                ControlFile = AdapterOpenDeviceObject(Adapter);
                if (ControlFile == INVALID_HANDLE_VALUE)
                {
                    if (i < 10 && ReadULongNoFence(&Adapter->LogState) != WIREGUARD_ADAPTER_LOG_OFF)
                    {
                        Sleep(1000);
                        continue;
                    }
                    LOG_LAST_ERROR(L"Failed to reopen handle for logging after adapter disappeared");
                    WriteULongNoFence(&Adapter->LogState, WIREGUARD_ADAPTER_LOG_OFF);
                    return 0;
                }
                else
                    break;
            }
            continue;
        }
        WIREGUARD_LOGGER_LEVEL Level;
        if (Line[0] == '1')
            Level = WIREGUARD_LOG_ERR;
        else if (Line[0] == '2')
            Level = WIREGUARD_LOG_WARN;
        else if (Line[0] == '3')
            Level = WIREGUARD_LOG_INFO;
        else
            continue;
        DWORD Offset = 0;
        if (ReadULongNoFence(&Adapter->LogState) == WIREGUARD_ADAPTER_LOG_ON_WITH_PREFIX)
        {
            if (!Adapter->IfIndex)
            {
                NET_LUID Luid;
                WireGuardGetAdapterLUID(Adapter, &Luid);
                ConvertInterfaceLuidToIndex(&Luid, &Adapter->IfIndex);
            }
            Offset = swprintf_s(WideLine, _countof(WideLine), L"%u: ", Adapter->IfIndex);
        }
        if (!MultiByteToWideChar(CP_UTF8, 0, &Line[1], -1, WideLine + Offset, _countof(WideLine) - Offset))
            continue;
        Logger(Level, WideLine);
    }
    CloseHandle(ControlFile);
    return 0;
}

_Use_decl_annotations_
BOOL WINAPI
WireGuardSetAdapterLogging(WIREGUARD_ADAPTER *Adapter, WIREGUARD_ADAPTER_LOG_STATE LogState)
{
    DWORD CurrentState = ReadULongNoFence(&Adapter->LogState);
    if (CurrentState == (DWORD)LogState)
        return TRUE;
    WriteULongNoFence(&Adapter->LogState, LogState);
    if (CurrentState != WIREGUARD_ADAPTER_LOG_OFF && LogState == WIREGUARD_ADAPTER_LOG_OFF && Adapter->LogThread)
    {
        CancelSynchronousIo(Adapter->LogThread);
        BOOL Ret = WaitForSingleObject(Adapter->LogThread, INFINITE);
        CloseHandle(Adapter->LogThread);
        Adapter->LogThread = NULL;
        return Ret;
    }
    if (CurrentState == WIREGUARD_ADAPTER_LOG_OFF && LogState != WIREGUARD_ADAPTER_LOG_OFF && !Adapter->LogThread)
    {
        Adapter->LogThread = CreateThread(NULL, 0, LogReaderThread, Adapter, 0, NULL);
        return Adapter->LogThread != NULL;
    }
    return TRUE;
}
