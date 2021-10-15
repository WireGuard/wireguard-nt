/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sysinfoapi.h>
#include <winternl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "wireguard.h"

static WIREGUARD_CREATE_ADAPTER_FUNC *WireGuardCreateAdapter;
static WIREGUARD_OPEN_ADAPTER_FUNC *WireGuardOpenAdapter;
static WIREGUARD_CLOSE_ADAPTER_FUNC *WireGuardCloseAdapter;
static WIREGUARD_GET_ADAPTER_LUID_FUNC *WireGuardGetAdapterLUID;
static WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *WireGuardGetRunningDriverVersion;
static WIREGUARD_DELETE_DRIVER_FUNC *WireGuardDeleteDriver;
static WIREGUARD_SET_LOGGER_FUNC *WireGuardSetLogger;
static WIREGUARD_SET_ADAPTER_LOGGING_FUNC *WireGuardSetAdapterLogging;
static WIREGUARD_GET_ADAPTER_STATE_FUNC *WireGuardGetAdapterState;
static WIREGUARD_SET_ADAPTER_STATE_FUNC *WireGuardSetAdapterState;
static WIREGUARD_GET_CONFIGURATION_FUNC *WireGuardGetConfiguration;
static WIREGUARD_SET_CONFIGURATION_FUNC *WireGuardSetConfiguration;

static HMODULE
InitializeWireGuardNT(void)
{
    HMODULE WireGuardDll =
        LoadLibraryExW(L"wireguard.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!WireGuardDll)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(WireGuardDll, #Name)) == NULL)
    if (X(WireGuardCreateAdapter) || X(WireGuardOpenAdapter) || X(WireGuardCloseAdapter) ||
        X(WireGuardGetAdapterLUID) || X(WireGuardGetRunningDriverVersion) || X(WireGuardDeleteDriver) ||
        X(WireGuardSetLogger) || X(WireGuardSetAdapterLogging) || X(WireGuardGetAdapterState) ||
        X(WireGuardSetAdapterState) || X(WireGuardGetConfiguration) || X(WireGuardSetConfiguration))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(WireGuardDll);
        SetLastError(LastError);
        return NULL;
    }
    return WireGuardDll;
}

static void CALLBACK
ConsoleLogger(_In_ WIREGUARD_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR *LogLine)
{
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime((FILETIME *)&Timestamp, &SystemTime);
    WCHAR LevelMarker;
    switch (Level)
    {
    case WIREGUARD_LOG_INFO:
        LevelMarker = L'+';
        break;
    case WIREGUARD_LOG_WARN:
        LevelMarker = L'-';
        break;
    case WIREGUARD_LOG_ERR:
        LevelMarker = L'!';
        break;
    default:
        return;
    }
    fwprintf(
        stderr,
        L"%04u-%02u-%02u %02u:%02u:%02u.%04u [%c] %s\n",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond,
        SystemTime.wMilliseconds,
        LevelMarker,
        LogLine);
}

static DWORD64 Now(VOID)
{
    LARGE_INTEGER Timestamp;
    NtQuerySystemTime(&Timestamp);
    return Timestamp.QuadPart;
}

static DWORD
LogError(_In_z_ const WCHAR *Prefix, _In_ DWORD Error)
{
    WCHAR *SystemMessage = NULL, *FormattedMessage = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        HRESULT_FROM_SETUPAPI(Error),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (void *)&SystemMessage,
        0,
        NULL);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_MAX_WIDTH_MASK,
        SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
        0,
        0,
        (void *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage });
    if (FormattedMessage)
        ConsoleLogger(WIREGUARD_LOG_ERR, Now(), FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

static DWORD
LogLastError(_In_z_ const WCHAR *Prefix)
{
    DWORD LastError = GetLastError();
    LogError(Prefix, LastError);
    SetLastError(LastError);
    return LastError;
}

static void
Log(_In_ WIREGUARD_LOGGER_LEVEL Level, _In_z_ const WCHAR *Format, ...)
{
    WCHAR LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(Level, Now(), LogLine);
}

_Must_inspect_result_
_Return_type_success_(return != FALSE)
static BOOL
GenerateKeyPair(
    _Out_writes_bytes_all_(WIREGUARD_KEY_LENGTH) BYTE PublicKey[WIREGUARD_KEY_LENGTH],
    _Out_writes_bytes_all_(WIREGUARD_KEY_LENGTH) BYTE PrivateKey[WIREGUARD_KEY_LENGTH])
{
    BCRYPT_ALG_HANDLE Algorithm;
    BCRYPT_KEY_HANDLE Key;
    NTSTATUS Status;
    struct
    {
        BCRYPT_ECCKEY_BLOB Header;
        BYTE Public[32];
        BYTE Unused[32];
        BYTE Private[32];
    } ExportedKey;
    ULONG Bytes;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_ECDH_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = BCryptSetProperty(
        Algorithm, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
    if (!NT_SUCCESS(Status))
        goto cleanupProvider;

    Status = BCryptGenerateKeyPair(Algorithm, &Key, 255, 0);
    if (!NT_SUCCESS(Status))
        goto cleanupProvider;

    Status = BCryptFinalizeKeyPair(Key, 0);
    if (!NT_SUCCESS(Status))
        goto cleanupKey;

    Status = BCryptExportKey(Key, NULL, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)&ExportedKey, sizeof(ExportedKey), &Bytes, 0);
    if (!NT_SUCCESS(Status))
        goto cleanupKey;

    memcpy(PublicKey, ExportedKey.Public, WIREGUARD_KEY_LENGTH);
    memcpy(PrivateKey, ExportedKey.Private, WIREGUARD_KEY_LENGTH);
    SecureZeroMemory(&ExportedKey, sizeof(ExportedKey));

cleanupKey:
    BCryptDestroyKey(Key);
cleanupProvider:
    BCryptCloseAlgorithmProvider(Algorithm, 0);
out:
    SetLastError(RtlNtStatusToDosError(Status));
    return NT_SUCCESS(Status);
}

static HANDLE QuitEvent;

static BOOL WINAPI
CtrlHandler(_In_ DWORD CtrlType)
{
    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        Log(WIREGUARD_LOG_INFO, L"Cleaning up and shutting down");
        SetEvent(QuitEvent);
        return TRUE;
    }
    return FALSE;
}

_Return_type_success_(return != FALSE)
static BOOL
TalkToDemoServer(
    _In_reads_bytes_(InputLength) const CHAR *Input,
    _In_ DWORD InputLength,
    _Out_writes_bytes_(*OutputLength) CHAR *Output,
    _Inout_ DWORD *OutputLength,
    _Out_ SOCKADDR_INET *ResolvedDemoServer)
{
    SOCKET Socket = INVALID_SOCKET;
    ADDRINFOW Hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP }, *Resolution;
    BOOL Ret = FALSE;

    if (GetAddrInfoW(L"demo.wireguard.com", L"42912", &Hints, &Resolution))
        return FALSE;
    for (ADDRINFOW *Candidate = Resolution; Candidate; Candidate = Candidate->ai_next)
    {
        if (Candidate->ai_family != AF_INET && Candidate->ai_family != AF_INET6)
            continue;
        Socket = socket(Candidate->ai_family, Candidate->ai_socktype, Candidate->ai_protocol);
        if (Socket == INVALID_SOCKET)
            goto cleanupResolution;
        if (connect(Socket, Candidate->ai_addr, (int)Candidate->ai_addrlen) == SOCKET_ERROR)
        {
            closesocket(Socket);
            Socket = INVALID_SOCKET;
        }
        memcpy(ResolvedDemoServer, Candidate->ai_addr, Candidate->ai_addrlen);
        break;
    }
    if (Socket == INVALID_SOCKET)
        goto cleanupResolution;
    if (send(Socket, Input, InputLength, 0) == SOCKET_ERROR)
        goto cleanupSocket;
    if ((*OutputLength = recv(Socket, Output, *OutputLength, 0)) == SOCKET_ERROR)
        goto cleanupSocket;
    Ret = TRUE;
cleanupSocket:
    closesocket(Socket);
cleanupResolution:
    FreeAddrInfoW(Resolution);
    return Ret;
}

int __cdecl main(void)
{
    DWORD LastError;
    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData))
        return LogError(L"Failed to initialize Winsock", GetLastError());
    HMODULE WireGuard = InitializeWireGuardNT();
    if (!WireGuard)
    {
        LastError = LogError(L"Failed to initialize WireGuardNT", GetLastError());
        goto cleanupWinsock;
    }
    WireGuardSetLogger(ConsoleLogger);
    Log(WIREGUARD_LOG_INFO, L"WireGuardNT library loaded");

    struct
    {
        WIREGUARD_INTERFACE Interface;
        WIREGUARD_PEER DemoServer;
        WIREGUARD_ALLOWED_IP AllV4;
    } Config = { .Interface = { .Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY, .PeersCount = 1 },
                 .DemoServer = { .Flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_HAS_ENDPOINT,
                                 .AllowedIPsCount = 1 },
                 .AllV4 = { .AddressFamily = AF_INET } };

    Log(WIREGUARD_LOG_INFO, L"Generating keypair");
    BYTE PublicKey[WIREGUARD_KEY_LENGTH];
    if (!GenerateKeyPair(PublicKey, Config.Interface.PrivateKey))
    {
        LastError = LogError(L"Failed to generate keypair", GetLastError());
        goto cleanupWireGuard;
    }
    CHAR PublicKeyString[46] = { 0 };
    DWORD Bytes = sizeof(PublicKeyString);
    CryptBinaryToStringA(
        PublicKey, sizeof(PublicKey), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, PublicKeyString, &Bytes);
    CHAR ServerResponse[256] = { 0 };
    Log(WIREGUARD_LOG_INFO, L"Talking to demo server");
    Bytes = sizeof(ServerResponse) - 1;
    if (!TalkToDemoServer(
            PublicKeyString, (DWORD)strlen(PublicKeyString), ServerResponse, &Bytes, &Config.DemoServer.Endpoint))
    {
        LastError = LogError(L"Failed to talk to demo server", GetLastError());
        goto cleanupWireGuard;
    }

    CHAR *Colon1 = strchr(ServerResponse, ':');
    CHAR *Colon2 = Colon1 ? strchr(Colon1 + 1, ':') : NULL;
    CHAR *Colon3 = Colon2 ? strchr(Colon2 + 1, ':') : NULL;
    if (!Colon1 || !Colon2 || !Colon3)
    {
        LastError = LogError(L"Failed to parse demo server response", ERROR_UNDEFINED_CHARACTER);
        goto cleanupWireGuard;
    }
    if (Bytes && ServerResponse[--Bytes] == '\n')
        ServerResponse[Bytes] = '\0';
    *Colon1 = *Colon2 = *Colon3 = '\0';

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
    AddressRow.DadState = IpDadStatePreferred;
    Bytes = sizeof(Config.DemoServer.PublicKey);
    if (strcmp(ServerResponse, "OK") || InetPtonA(AF_INET, Colon3 + 1, &AddressRow.Address.Ipv4.sin_addr) != 1 ||
        !CryptStringToBinaryA(Colon1 + 1, 0, CRYPT_STRING_BASE64, Config.DemoServer.PublicKey, &Bytes, NULL, NULL))
    {
        LastError = LogError(L"Failed to parse demo server response", ERROR_UNDEFINED_CHARACTER);
        goto cleanupWireGuard;
    }
    if (Config.DemoServer.Endpoint.si_family == AF_INET)
        Config.DemoServer.Endpoint.Ipv4.sin_port = htons((u_short)atoi(Colon2 + 1));
    else if (Config.DemoServer.Endpoint.si_family == AF_INET6)
        Config.DemoServer.Endpoint.Ipv6.sin6_port = htons((u_short)atoi(Colon2 + 1));

    QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!QuitEvent)
    {
        LastError = LogError(L"Failed to create event", GetLastError());
        goto cleanupWireGuard;
    }
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        LastError = LogError(L"Failed to set console handler", GetLastError());
        goto cleanupQuit;
    }

    GUID ExampleGuid = { 0xdeadc001, 0xbeef, 0xbabe, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(L"Demo", L"Example", &ExampleGuid);
    if (!Adapter)
    {
        LastError = GetLastError();
        LogError(L"Failed to create adapter", LastError);
        goto cleanupQuit;
    }

    if (!WireGuardSetAdapterLogging(Adapter, WIREGUARD_ADAPTER_LOG_ON))
        LogError(L"Failed to enable adapter logging", GetLastError());

    DWORD Version = WireGuardGetRunningDriverVersion();
    Log(WIREGUARD_LOG_INFO, L"WireGuardNT v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    WireGuardGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    MIB_IPFORWARD_ROW2 DefaultRoute = { 0 };
    InitializeIpForwardEntry(&DefaultRoute);
    DefaultRoute.InterfaceLuid = AddressRow.InterfaceLuid;
    DefaultRoute.DestinationPrefix.Prefix.si_family = AF_INET;
    DefaultRoute.NextHop.si_family = AF_INET;
    DefaultRoute.Metric = 0;
    LastError = CreateIpForwardEntry2(&DefaultRoute);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set default route", LastError);
        goto cleanupAdapter;
    }
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set IP address", LastError);
        goto cleanupAdapter;
    }
    MIB_IPINTERFACE_ROW IpInterface = { 0 };
    InitializeIpInterfaceEntry(&IpInterface);
    IpInterface.InterfaceLuid = AddressRow.InterfaceLuid;
    IpInterface.Family = AF_INET;
    LastError = GetIpInterfaceEntry(&IpInterface);
    if (LastError != ERROR_SUCCESS)
    {
        LogError(L"Failed to get IP interface", LastError);
        goto cleanupAdapter;
    }
    IpInterface.UseAutomaticMetric = FALSE;
    IpInterface.Metric = 0;
    IpInterface.NlMtu = 1420;
    IpInterface.SitePrefixLength = 0;
    LastError = SetIpInterfaceEntry(&IpInterface);
    if (LastError != ERROR_SUCCESS)
    {
        LogError(L"Failed to set metric and MTU", LastError);
        goto cleanupAdapter;
    }

    Log(WIREGUARD_LOG_INFO, L"Setting configuration and adapter up");
    if (!WireGuardSetConfiguration(Adapter, &Config.Interface, sizeof(Config)) ||
        !WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE_UP))
    {
        LastError = LogError(L"Failed to set configuration and adapter up", GetLastError());
        goto cleanupAdapter;
    }

    do
    {
        Bytes = sizeof(Config);
        if (!WireGuardGetConfiguration(Adapter, &Config.Interface, &Bytes) || !Config.Interface.PeersCount)
        {
            LastError = LogError(L"Failed to get configuration", GetLastError());
            goto cleanupAdapter;
        }
        DWORD64 Timestamp = Now();
        SYSTEMTIME SystemTime;
        FileTimeToSystemTime((FILETIME *)&Timestamp, &SystemTime);
        fwprintf(
            stderr,
            L"%04u-%02u-%02u %02u:%02u:%02u.%04u [#] RX: %llu, TX: %llu\r",
            SystemTime.wYear,
            SystemTime.wMonth,
            SystemTime.wDay,
            SystemTime.wHour,
            SystemTime.wMinute,
            SystemTime.wSecond,
            SystemTime.wMilliseconds,
            Config.DemoServer.RxBytes,
            Config.DemoServer.TxBytes);
    } while (WaitForSingleObject(QuitEvent, 1000) == WAIT_TIMEOUT);

cleanupAdapter:
    WireGuardCloseAdapter(Adapter);
cleanupQuit:
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    CloseHandle(QuitEvent);
cleanupWireGuard:
    FreeLibrary(WireGuard);
cleanupWinsock:
    WSACleanup();
    return LastError;
}
