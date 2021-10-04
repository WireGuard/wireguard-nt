/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <WinSock2.h>
#include <Windows.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ndisguid.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <wchar.h>
#include <initguid.h> /* Keep these two at bottom in this order, so that we only generate extra GUIDs for devpkey. The other keys we'll get from uuid.lib like usual. */
#include <devpkey.h>

/* We pretend we're Windows 8, and then hack around the limitation in Windows 7 below. */
#if NTDDI_VERSION == NTDDI_WIN7
#    undef NTDDI_VERSION
#    define NTDDI_VERSION NTDDI_WIN8
#    include <devquery.h>
#    undef NTDDI_VERSION
#    define NTDDI_VERSION NTDDI_WIN7
#endif

#include "../driver/ioctl.h"
#include "adapter.h"
#include "logger.h"
#include "main.h"
#include "namespace.h"
#include "nci.h"
#include "ntdll.h"
#include "registry.h"
#include "resource.h"
#include "rundll32.h"
#include "wireguard-inf.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

#define MAX_POOL_DEVICE_TYPE (WIREGUARD_MAX_POOL + 8) /* Should accommodate a pool name with " Tunnel" appended */

static const DEVPROPKEY DEVPKEY_WireGuard_Pool = {
    { 0x65726957, 0x7547, 0x7261, { 0x64, 0x50, 0x6f, 0x6f, 0x6c, 0x4b, 0x65, 0x79 } },
    DEVPROPID_FIRST_USABLE + 0
};

static const DEVPROPKEY DEVPKEY_WireGuard_Name = {
    { 0x65726957, 0x7547, 0x7261, { 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x4b, 0x65, 0x79 } },
    DEVPROPID_FIRST_USABLE + 1
};

typedef struct _SP_DEVINFO_DATA_LIST
{
    SP_DEVINFO_DATA Data;
    VOID *Configuration;
    DWORD ConfigurationBytes;
    WIREGUARD_ADAPTER_STATE AdapterState;
    struct _SP_DEVINFO_DATA_LIST *Next;
} SP_DEVINFO_DATA_LIST;

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
SP_DRVINFO_DETAIL_DATA_W *
GetAdapterDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData)
{
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    for (;;)
    {
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = Alloc(Size);
        if (!DrvInfoDetailData)
            return NULL;
        DrvInfoDetailData->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, DrvInfoDetailData, Size, &Size))
            return DrvInfoDetailData;
        DWORD LastError = GetLastError();
        Free(DrvInfoDetailData);
        if (LastError != ERROR_INSUFFICIENT_BUFFER)
        {
            if (DevInfoData)
                LOG_ERROR(LastError, L"Failed for adapter %u", DevInfoData->DevInst);
            else
                LOG_ERROR(LastError, L"Failed");
            SetLastError(LastError);
            return NULL;
        }
    }
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(*BufLen)
VOID *
GetDeviceRegistryProperty(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_opt_ DWORD *ValueType,
    _Inout_ DWORD *BufLen)
{
    for (;;)
    {
        BYTE *Data = Alloc(*BufLen);
        if (!Data)
            return NULL;
        if (SetupDiGetDeviceRegistryPropertyW(DevInfo, DevInfoData, Property, ValueType, Data, *BufLen, BufLen))
            return Data;
        DWORD LastError = GetLastError();
        Free(Data);
        if (LastError != ERROR_INSUFFICIENT_BUFFER)
        {
            SetLastError(
                LOG_ERROR(LastError, L"Failed to query adapter %u property 0x%x", DevInfoData->DevInst, Property));
            return NULL;
        }
    }
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
GetDeviceRegistryString(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _In_ DWORD Property)
{
    DWORD LastError, ValueType, Size = 256 * sizeof(WCHAR);
    LPWSTR Buf = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, &Size);
    if (!Buf)
        return NULL;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        if (RegistryGetString(&Buf, Size / sizeof(*Buf), ValueType))
            return Buf;
        LastError = GetLastError();
        break;
    default:
        LOG(WIREGUARD_LOG_ERR,
            L"Adapter %u property 0x%x is not a string (type: %u)",
            DevInfoData->DevInst,
            Property,
            ValueType);
        LastError = ERROR_INVALID_DATATYPE;
    }
    Free(Buf);
    SetLastError(LastError);
    return NULL;
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
PZZWSTR
GetDeviceRegistryMultiString(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _In_ DWORD Property)
{
    DWORD LastError, ValueType, Size = 256 * sizeof(WCHAR);
    PZZWSTR Buf = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, &Size);
    if (!Buf)
        return NULL;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        if (RegistryGetMultiString(&Buf, Size / sizeof(*Buf), ValueType))
            return Buf;
        LastError = GetLastError();
        break;
    default:
        LOG(WIREGUARD_LOG_ERR,
            L"Adapter %u property 0x%x is not a string (type: %u)",
            DevInfoData->DevInst,
            Property,
            ValueType);
        LastError = ERROR_INVALID_DATATYPE;
    }
    Free(Buf);
    SetLastError(LastError);
    return NULL;
}

static BOOL
IsOurHardwareID(_In_z_ PCZZWSTR Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WIREGUARD_HWID))
            return TRUE;
    return FALSE;
}

static BOOL
IsOurAdapter(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    PZZWSTR Hwids = GetDeviceRegistryMultiString(DevInfo, DevInfoData, SPDRP_HARDWAREID);
    if (!Hwids)
    {
        LOG_LAST_ERROR(L"Failed to get adapter %u hardware ID", DevInfoData->DevInst);
        return FALSE;
    }
    BOOL IsOurs = IsOurHardwareID(Hwids);
    Free(Hwids);
    return IsOurs;
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
GetDeviceObjectFileName(_In_z_ LPCWSTR InstanceId)
{
    ULONG InterfacesLen;
    DWORD LastError = CM_MapCrToWin32Err(
        CM_Get_Device_Interface_List_SizeW(
            &InterfacesLen,
            (GUID *)&GUID_DEVINTERFACE_NET,
            (DEVINSTID_W)InstanceId,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT),
        ERROR_GEN_FAILURE);
    if (LastError != ERROR_SUCCESS)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed to query adapter %s associated instances size", InstanceId));
        return NULL;
    }
    LPWSTR Interfaces = AllocArray(InterfacesLen, sizeof(*Interfaces));
    if (!Interfaces)
        return NULL;
    LastError = CM_MapCrToWin32Err(
        CM_Get_Device_Interface_ListW(
            (GUID *)&GUID_DEVINTERFACE_NET,
            (DEVINSTID_W)InstanceId,
            Interfaces,
            InterfacesLen,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT),
        ERROR_GEN_FAILURE);
    if (LastError != ERROR_SUCCESS)
    {
        LOG_ERROR(LastError, L"Failed to get adapter %s associated instances", InstanceId);
        Free(Interfaces);
        SetLastError(LastError);
        return NULL;
    }
    if (!Interfaces[0])
    {
        Free(Interfaces);
        SetLastError(ERROR_DEVICE_NOT_AVAILABLE);
        return NULL;
    }
    return Interfaces;
}

_Must_inspect_result_
static _Return_type_success_(return != INVALID_HANDLE_VALUE)
HANDLE
OpenDeviceObject(_In_z_ LPCWSTR InstanceId)
{
    LPWSTR Filename = GetDeviceObjectFileName(InstanceId);
    if (!Filename)
        return INVALID_HANDLE_VALUE;
    HANDLE Handle = CreateFileW(
        Filename,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (Handle == INVALID_HANDLE_VALUE)
        LOG_LAST_ERROR(L"Failed to connect to adapter %s associated instance %s", InstanceId, Filename);
    Free(Filename);
    return Handle;
}

static BOOL
EnsureDeviceObject(_In_z_ LPCWSTR InstanceId)
{
    LPWSTR Filename = GetDeviceObjectFileName(InstanceId);
    if (!Filename)
    {
        LOG_LAST_ERROR(L"Failed to determine adapter %s device object", InstanceId);
        return FALSE;
    }
    BOOL Exists = TRUE;
    const int Attempts = 100;
    for (int i = 0; i < Attempts; ++i)
    {
        HANDLE Handle = CreateFileW(Filename, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (Handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(Handle);
            goto out;
        }
        if (i != Attempts - 1)
            Sleep(50);
    }
    Exists = FALSE;
    LOG_LAST_ERROR(L"Failed to connect to adapter %s associated instance %s", InstanceId, Filename);
out:
    Free(Filename);
    return Exists;
}

static _Return_type_success_(return != FALSE)
BOOL
SnapshotConfigurationAndState(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ VOID **Configuration,
    _Out_ DWORD *ConfigurationBytes,
    _Out_ WIREGUARD_ADAPTER_STATE *State)
{
    DWORD LastError = ERROR_SUCCESS;
    DWORD RequiredBytes;
    if (SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, NULL, 0, &RequiredBytes) ||
        (LastError = GetLastError()) != ERROR_INSUFFICIENT_BUFFER)
    {
        LOG_ERROR(LastError, L"Failed to query adapter %u instance ID size", DevInfoData->DevInst);
        return FALSE;
    }
    LastError = ERROR_SUCCESS;
    LPWSTR InstanceId = ZallocArray(RequiredBytes, sizeof(*InstanceId));
    if (!InstanceId)
        return FALSE;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u instance ID", DevInfoData->DevInst);
        goto cleanupInstanceId;
    }
    HANDLE NdisHandle = OpenDeviceObject(InstanceId);
    if (NdisHandle == INVALID_HANDLE_VALUE)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to get adapter %u object", DevInfoData->DevInst);
        goto cleanupInstanceId;
    }
    WG_IOCTL_ADAPTER_STATE Op = WG_IOCTL_ADAPTER_STATE_QUERY;
    if (!DeviceIoControl(
            NdisHandle, WG_IOCTL_SET_ADAPTER_STATE, &Op, sizeof(Op), State, sizeof(*State), &RequiredBytes, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to query adapter state on adapter %u", DevInfoData->DevInst);
        goto cleanupHandle;
    }
    for (RequiredBytes = 512;; RequiredBytes = *ConfigurationBytes)
    {
        *Configuration = Alloc(RequiredBytes);
        if (!*Configuration)
        {
            LastError = LOG_LAST_ERROR(
                L"Failed to allocate %u bytes for configuration on adapter %u", RequiredBytes, DevInfoData->DevInst);
            goto cleanupHandle;
        }
        if (DeviceIoControl(NdisHandle, WG_IOCTL_GET, NULL, 0, *Configuration, RequiredBytes, ConfigurationBytes, NULL))
            break;
        Free(*Configuration);
        *Configuration = NULL;
        if (GetLastError() != ERROR_MORE_DATA)
        {
            LastError = LOG_LAST_ERROR(L"Failed to query configuration on adapter %u", DevInfoData->DevInst);
            goto cleanupHandle;
        }
    }
cleanupHandle:
    CloseHandle(NdisHandle);
cleanupInstanceId:
    Free(InstanceId);
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
RestoreConfigurationAndState(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ VOID *Configuration,
    _In_ DWORD ConfigurationBytes,
    _In_ WIREGUARD_ADAPTER_STATE State)
{
    DWORD LastError = ERROR_SUCCESS;
    DWORD RequiredBytes;
    if (SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, NULL, 0, &RequiredBytes) ||
        (LastError = GetLastError()) != ERROR_INSUFFICIENT_BUFFER)
    {
        LOG_ERROR(LastError, L"Failed to query adapter %u instance ID size", DevInfoData->DevInst);
        return FALSE;
    }
    LastError = ERROR_SUCCESS;
    LPWSTR InstanceId = ZallocArray(RequiredBytes, sizeof(*InstanceId));
    if (!InstanceId)
        return FALSE;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u instance ID", DevInfoData->DevInst);
        goto cleanupInstanceId;
    }
    HANDLE NdisHandle = OpenDeviceObject(InstanceId);
    if (NdisHandle == INVALID_HANDLE_VALUE)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to get adapter %u object", DevInfoData->DevInst);
        goto cleanupInstanceId;
    }
    if (!DeviceIoControl(NdisHandle, WG_IOCTL_SET, NULL, 0, Configuration, ConfigurationBytes, &RequiredBytes, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set configuration on adapter %u", DevInfoData->DevInst);
        goto cleanupHandle;
    }
    if (!DeviceIoControl(NdisHandle, WG_IOCTL_SET_ADAPTER_STATE, &State, sizeof(State), NULL, 0, &RequiredBytes, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter state on adapter %u", DevInfoData->DevInst);
        goto cleanupHandle;
    }
cleanupHandle:
    CloseHandle(NdisHandle);
cleanupInstanceId:
    Free(InstanceId);
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
DisableAllOurAdapters(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD LastError = ERROR_SUCCESS;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA_LIST *DeviceNode = Zalloc(sizeof(*DeviceNode));
        if (!DeviceNode)
            return FALSE;
        DeviceNode->Data.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DeviceNode->Data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                Free(DeviceNode);
                break;
            }
            goto cleanupDeviceNode;
        }
        if (!IsOurAdapter(DevInfo, &DeviceNode->Data))
            goto cleanupDeviceNode;

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceNode;

        LOG(WIREGUARD_LOG_INFO, L"Snapshotting configuration of adapter %u", DeviceNode->Data.DevInst);
        if (!SnapshotConfigurationAndState(
                DevInfo,
                &DeviceNode->Data,
                &DeviceNode->Configuration,
                &DeviceNode->ConfigurationBytes,
                &DeviceNode->AdapterState))
            LOG(WIREGUARD_LOG_WARN, L"Failed to snapshot configuration of adapter %u", DeviceNode->Data.DevInst);

        LOG(WIREGUARD_LOG_INFO, L"Disabling adapter %u", DeviceNode->Data.DevInst);
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to disable adapter %u", DeviceNode->Data.DevInst);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
            goto cleanupDeviceNode;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceNode:
        Free(DeviceNode);
    }
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
EnableAllOurAdapters(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD LastError = ERROR_SUCCESS;
    for (SP_DEVINFO_DATA_LIST *DeviceNode = AdaptersToEnable; DeviceNode; DeviceNode = DeviceNode->Next)
    {
        LOG(WIREGUARD_LOG_INFO, L"Enabling adapter %u", DeviceNode->Data.DevInst);
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to enable adapter %u", DeviceNode->Data.DevInst);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
        }
        LOG(WIREGUARD_LOG_INFO, L"Restoring configuration of adapter %u", DeviceNode->Data.DevInst);
        if (!RestoreConfigurationAndState(
                DevInfo,
                &DeviceNode->Data,
                DeviceNode->Configuration,
                DeviceNode->ConfigurationBytes,
                DeviceNode->AdapterState))
            LOG(WIREGUARD_LOG_WARN, L"Failed to restore configuration of adapter %u", DeviceNode->Data.DevInst);
    }
    return RET_ERROR(TRUE, LastError);
}

static BOOL
CheckReboot(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
    {
        LOG_LAST_ERROR(L"Failed to retrieve adapter %u device installation parameters", DevInfoData->DevInst);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return (DevInstallParams.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
GetPoolDeviceTypeName(_In_z_ LPCWSTR Pool, _Out_writes_z_(MAX_POOL_DEVICE_TYPE) LPWSTR Name)
{
    if (_snwprintf_s(Name, MAX_POOL_DEVICE_TYPE, _TRUNCATE, L"%s Tunnel", Pool) == -1)
    {
        LOG(WIREGUARD_LOG_ERR, L"Pool name too long: %s", Pool);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

static BOOL
IsPoolMember(_In_z_ LPCWSTR Pool, _In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    WCHAR PoolProp[MAX_POOL_DEVICE_TYPE];
    DEVPROPTYPE PropType;
    if (!SetupDiGetDevicePropertyW(
            DevInfo, DevInfoData, &DEVPKEY_WireGuard_Pool, &PropType, (PBYTE)PoolProp, sizeof(PoolProp), NULL, 0))
        return FALSE;
    if (PropType != DEVPROP_TYPE_STRING)
    {
        SetLastError(ERROR_BAD_DEVICE);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return !_wcsicmp(PoolProp, Pool);
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
PopulateAdapterData(_Inout_ WIREGUARD_ADAPTER *Adapter, _In_z_ LPCWSTR Pool)
{
    DWORD LastError = ERROR_SUCCESS;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key =
        SetupDiOpenDevRegKey(Adapter->DevInfo, &Adapter->DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Failed to open adapter %u device registry key", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    LPWSTR ValueStr = RegistryQueryString(Key, L"NetCfgInstanceId", TRUE);
    if (!ValueStr)
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to get %.*s\\NetCfgInstanceId", MAX_REG_PATH, RegPath);
        goto cleanupKey;
    }
    if (FAILED(CLSIDFromString(ValueStr, &Adapter->CfgInstanceID)))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError =
            LOG(WIREGUARD_LOG_ERR, L"%.*s\\NetCfgInstanceId is not a GUID: %s", MAX_REG_PATH, RegPath, ValueStr);
        Free(ValueStr);
        goto cleanupKey;
    }
    Free(ValueStr);

    if (!RegistryQueryDWORD(Key, L"NetLuidIndex", &Adapter->LuidIndex, TRUE))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to get %.*s\\NetLuidIndex", MAX_REG_PATH, RegPath);
        goto cleanupKey;
    }

    if (!RegistryQueryDWORD(Key, L"*IfType", &Adapter->IfType, TRUE))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to get %.*s\\*IfType", MAX_REG_PATH, RegPath);
        goto cleanupKey;
    }

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(
            Adapter->DevInfo, &Adapter->DevInfoData, Adapter->DevInstanceID, _countof(Adapter->DevInstanceID), &Size))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u instance ID", Adapter->DevInfoData.DevInst);
        goto cleanupKey;
    }

    if (wcsncpy_s(Adapter->Pool, _countof(Adapter->Pool), Pool, _TRUNCATE) == STRUNCATE)
    {
        LOG(WIREGUARD_LOG_ERR, L"Pool name too long: %s", Pool);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupKey;
    }

cleanupKey:
    RegCloseKey(Key);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
VOID WINAPI
WireGuardFreeAdapter(WIREGUARD_ADAPTER *Adapter)
{
    if (!Adapter)
        return;
    WireGuardSetAdapterLogging(Adapter, WIREGUARD_ADAPTER_LOG_OFF);
    if (Adapter->DevInfo)
        SetupDiDestroyDeviceInfoList(Adapter->DevInfo);
    Free(Adapter);
}

_Use_decl_annotations_
BOOL WINAPI
WireGuardGetAdapterName(WIREGUARD_ADAPTER *Adapter, LPWSTR Name)
{
    DEVPROPTYPE PropType;
    if (!SetupDiGetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_WireGuard_Name,
            &PropType,
            (PBYTE)Name,
            MAX_ADAPTER_NAME * sizeof(*Name),
            NULL,
            0))
        return FALSE;
    if (PropType != DEVPROP_TYPE_STRING || !*Name)
    {
        SetLastError(ERROR_BAD_DEVICE);
        return FALSE;
    }
    return TRUE;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
ConvertInterfaceAliasToGuid(_In_z_ LPCWSTR Name, _Out_ GUID *Guid)
{
    NET_LUID Luid;
    DWORD LastError = ConvertInterfaceAliasToLuid(Name, &Luid);
    if (LastError != NO_ERROR)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed convert interface %s name to the locally unique identifier", Name));
        return FALSE;
    }
    LastError = ConvertInterfaceLuidToGuid(&Luid, Guid);
    if (LastError != NO_ERROR)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed to convert interface %s LUID (%I64u) to GUID", Name, Luid.Value));
        return FALSE;
    }
    return TRUE;
}

_Use_decl_annotations_
BOOL WINAPI
WireGuardSetAdapterName(WIREGUARD_ADAPTER *Adapter, LPCWSTR Name)
{
    const int MaxSuffix = 1000;
    WCHAR AvailableName[MAX_ADAPTER_NAME];
    if (wcsncpy_s(AvailableName, _countof(AvailableName), Name, _TRUNCATE) == STRUNCATE)
    {
        LOG(WIREGUARD_LOG_ERR, L"Adapter name too long: %s", Name);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!SetupDiSetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_WireGuard_Name,
            DEVPROP_TYPE_STRING,
#pragma warning(suppress : 4090)
            (const BYTE *)Name,
            (DWORD)((wcslen(Name) + 1) * sizeof(*Name)),
            0))
    {
        LOG_LAST_ERROR(L"Failed to set adapter %u name", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    for (int i = 0;; ++i)
    {
        DWORD LastError = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
        if (LastError == ERROR_DUP_NAME)
        {
            GUID Guid2;
            if (ConvertInterfaceAliasToGuid(AvailableName, &Guid2))
            {
                for (int j = 0; j < MaxSuffix; ++j)
                {
                    WCHAR Proposal[MAX_ADAPTER_NAME];
                    if (_snwprintf_s(Proposal, _countof(Proposal), _TRUNCATE, L"%s %d", Name, j + 1) == -1)
                    {
                        LOG(WIREGUARD_LOG_ERR, L"Adapter name too long: %s %d", Name, j + 1);
                        SetLastError(ERROR_INVALID_PARAMETER);
                        return FALSE;
                    }
                    if (_wcsnicmp(Proposal, AvailableName, MAX_ADAPTER_NAME) == 0)
                        continue;
                    DWORD LastError2 = NciSetConnectionName(&Guid2, Proposal);
                    if (LastError2 == ERROR_DUP_NAME)
                        continue;
                    if (LastError2 == ERROR_SUCCESS)
                    {
                        LastError = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
                        if (LastError == ERROR_SUCCESS)
                            break;
                    }
                    break;
                }
            }
        }
        if (LastError == ERROR_SUCCESS)
            break;
        if (i >= MaxSuffix || LastError != ERROR_DUP_NAME)
        {
            SetLastError(LOG_ERROR(LastError, L"Failed to set adapter name"));
            return FALSE;
        }
        if (_snwprintf_s(AvailableName, _countof(AvailableName), _TRUNCATE, L"%s %d", Name, i + 1) == -1)
        {
            LOG(WIREGUARD_LOG_ERR, L"Adapter name too long: %s %d", Name, i + 1);
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    if (!SetupDiSetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_WireGuard_Pool,
            DEVPROP_TYPE_STRING,
#pragma warning(suppress : 4090)
            (const BYTE *)Adapter->Pool,
            (DWORD)((wcslen(Adapter->Pool) + 1) * sizeof(*Adapter->Pool)),
            0))
    {
        LOG_LAST_ERROR(L"Failed to set adapter %u pool", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    if (!GetPoolDeviceTypeName(Adapter->Pool, PoolDeviceTypeName))
        return FALSE;
    if (!SetupDiSetDeviceRegistryPropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            SPDRP_FRIENDLYNAME,
            (const BYTE *)PoolDeviceTypeName,
            (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(*PoolDeviceTypeName))))
    {
        LOG_LAST_ERROR(L"Failed to set adapter %u friendly name", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
WIREGUARD_ADAPTER_HANDLE WINAPI
WireGuardOpenAdapter(LPCWSTR Pool, LPCWSTR Name)
{
    WIREGUARD_ADAPTER *Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        return FALSE;

    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanup;
    }

    Adapter->DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }

    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(Adapter->DevInfo, EnumIndex, &Adapter->DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        WCHAR Name2[MAX_ADAPTER_NAME];
        if (!WireGuardGetAdapterName(Adapter, Name2))
            continue;
        if (_wcsicmp(Name, Name2))
            continue;

        /* Check the Hardware ID to make sure it's a real WireGuard device. */
        if (!IsOurAdapter(Adapter->DevInfo, &Adapter->DevInfoData))
        {
            LOG(WIREGUARD_LOG_ERR, L"Foreign adapter %u named %s exists", Adapter->DevInfoData.DevInst, Name);
            LastError = ERROR_ALREADY_EXISTS;
            goto cleanupMutex;
        }

        if (!IsPoolMember(Pool, Adapter->DevInfo, &Adapter->DevInfoData))
        {
            if ((LastError = GetLastError()) == ERROR_SUCCESS)
            {
                LOG(WIREGUARD_LOG_ERR,
                    L"Adapter %u named %s is not a member of %s pool",
                    Adapter->DevInfoData.DevInst,
                    Name,
                    Pool);
                LastError = ERROR_ALREADY_EXISTS;
                goto cleanupMutex;
            }
            else
            {
                LOG(WIREGUARD_LOG_ERR, L"Failed to get adapter %u pool membership", Adapter->DevInfoData.DevInst);
                goto cleanupMutex;
            }
        }

        if (!PopulateAdapterData(Adapter, Pool))
        {
            LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to populate adapter %u data", Adapter->DevInfoData.DevInst);
            goto cleanupMutex;
        }

        if (!EnsureDeviceObject(Adapter->DevInstanceID))
        {
            LastError = GetLastError();
            goto cleanupMutex;
        }

        /* Our comparison was case-insensitive, and we also might want to reenforce the NCI connection. */
        WireGuardSetAdapterName(Adapter, Name);

        LastError = ERROR_SUCCESS;
        goto cleanupMutex;
    }
    LastError = ERROR_FILE_NOT_FOUND;
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    if (LastError != ERROR_SUCCESS)
        WireGuardFreeAdapter(Adapter);
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
VOID WINAPI
WireGuardGetAdapterLUID(WIREGUARD_ADAPTER *Adapter, NET_LUID *Luid)
{
    Luid->Info.Reserved = 0;
    Luid->Info.NetLuidIndex = Adapter->LuidIndex;
    Luid->Info.IfType = Adapter->IfType;
}

_Use_decl_annotations_
HANDLE WINAPI
AdapterOpenDeviceObject(const WIREGUARD_ADAPTER *Adapter)
{
    return OpenDeviceObject(Adapter->DevInstanceID);
}

static BOOL
IsOurDrvInfoDetail(_In_ const SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData)
{
    if (DrvInfoDetailData->CompatIDsOffset > 1 && !_wcsicmp(DrvInfoDetailData->HardwareID, WIREGUARD_HWID))
        return TRUE;
    if (DrvInfoDetailData->CompatIDsLength &&
        IsOurHardwareID(DrvInfoDetailData->HardwareID + DrvInfoDetailData->CompatIDsOffset))
        return TRUE;
    return FALSE;
}

static BOOL
IsNewer(
    _In_ const FILETIME *DriverDate1,
    _In_ DWORDLONG DriverVersion1,
    _In_ const FILETIME *DriverDate2,
    _In_ DWORDLONG DriverVersion2)
{
    if (DriverDate1->dwHighDateTime > DriverDate2->dwHighDateTime)
        return TRUE;
    if (DriverDate1->dwHighDateTime < DriverDate2->dwHighDateTime)
        return FALSE;

    if (DriverDate1->dwLowDateTime > DriverDate2->dwLowDateTime)
        return TRUE;
    if (DriverDate1->dwLowDateTime < DriverDate2->dwLowDateTime)
        return FALSE;

    if (DriverVersion1 > DriverVersion2)
        return TRUE;
    if (DriverVersion1 < DriverVersion2)
        return FALSE;

    return FALSE;
}

static _Return_type_success_(return != 0)
DWORD
VersionOfFile(_In_z_ LPCWSTR Filename)
{
    DWORD Zero;
    DWORD Len = GetFileVersionInfoSizeW(Filename, &Zero);
    if (!Len)
    {
        LOG_LAST_ERROR(L"Failed to query %s version info size", Filename);
        return 0;
    }
    VOID *VersionInfo = Alloc(Len);
    if (!VersionInfo)
        return 0;
    DWORD LastError = ERROR_SUCCESS, Version = 0;
    VS_FIXEDFILEINFO *FixedInfo;
    UINT FixedInfoLen = sizeof(*FixedInfo);
    if (!GetFileVersionInfoW(Filename, 0, Len, VersionInfo))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get %s version info", Filename);
        goto out;
    }
    if (!VerQueryValueW(VersionInfo, L"\\", &FixedInfo, &FixedInfoLen))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get %s version info root", Filename);
        goto out;
    }
    Version = FixedInfo->dwFileVersionMS;
    if (!Version)
    {
        LOG(WIREGUARD_LOG_WARN, L"Determined version of %s, but was v0.0, so returning failure", Filename);
        LastError = ERROR_VERSION_PARSE_ERROR;
    }
out:
    Free(VersionInfo);
    return RET_ERROR(Version, LastError);
}

static DWORD WINAPI
MaybeGetRunningDriverVersion(BOOL ReturnOneIfRunningInsteadOfVersion)
{
    PRTL_PROCESS_MODULES Modules;
    ULONG BufferSize = 128 * 1024;
    for (;;)
    {
        Modules = Alloc(BufferSize);
        if (!Modules)
            return 0;
        NTSTATUS Status = NtQuerySystemInformation(SystemModuleInformation, Modules, BufferSize, &BufferSize);
        if (NT_SUCCESS(Status))
            break;
        Free(Modules);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
            continue;
        LOG(WIREGUARD_LOG_ERR, L"Failed to enumerate drivers (status: 0x%x)", Status);
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }
    DWORD LastError = ERROR_SUCCESS, Version = 0;
    for (ULONG i = Modules->NumberOfModules; i-- > 0;)
    {
        LPCSTR NtPath = (LPCSTR)Modules->Modules[i].FullPathName;
        if (!_stricmp(&NtPath[Modules->Modules[i].OffsetToFileName], "wireguard.sys"))
        {
            if (ReturnOneIfRunningInsteadOfVersion)
            {
                Version = 1;
                goto cleanupModules;
            }
            WCHAR FilePath[MAX_PATH * 3 + 15];
            if (_snwprintf_s(FilePath, _countof(FilePath), _TRUNCATE, L"\\\\?\\GLOBALROOT%S", NtPath) == -1)
                continue;
            Version = VersionOfFile(FilePath);
            if (!Version)
                LastError = GetLastError();
            goto cleanupModules;
        }
    }
    LastError = ERROR_FILE_NOT_FOUND;
cleanupModules:
    Free(Modules);
    return RET_ERROR(Version, LastError);
}

_Use_decl_annotations_
DWORD WINAPI WireGuardGetRunningDriverVersion(VOID)
{
    return MaybeGetRunningDriverVersion(FALSE);
}

static BOOL EnsureWireGuardUnloaded(VOID)
{
    BOOL Loaded;
    for (int i = 0; (Loaded = MaybeGetRunningDriverVersion(TRUE) != 0) != FALSE && i < 300; ++i)
        Sleep(50);
    return !Loaded;
}

static VOID
SelectDriverDeferredCleanup(_In_ HDEVINFO DevInfoExistingAdapters, _In_opt_ SP_DEVINFO_DATA_LIST *ExistingAdapters)
{
    if (ExistingAdapters)
    {
        EnableAllOurAdapters(DevInfoExistingAdapters, ExistingAdapters);
        while (ExistingAdapters)
        {
            SP_DEVINFO_DATA_LIST *Next = ExistingAdapters->Next;
            Free(ExistingAdapters->Configuration);
            Free(ExistingAdapters);
            ExistingAdapters = Next;
        }
    }
    if (DevInfoExistingAdapters != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(DevInfoExistingAdapters);
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
SelectDriver(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Inout_ SP_DEVINSTALL_PARAMS_W *DevInstallParams,
    _Out_ HDEVINFO *DevInfoExistingAdaptersForCleanup,
    _Out_ SP_DEVINFO_DATA_LIST **ExistingAdaptersForCleanup)
{
    static const FILETIME OurDriverDate = WIREGUARD_INF_FILETIME;
    static const DWORDLONG OurDriverVersion = WIREGUARD_INF_VERSION;
    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        LOG(WIREGUARD_LOG_ERR, L"Failed to take driver installation mutex");
        return FALSE;
    }
    DWORD LastError;
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building adapter %u driver info list", DevInfoData->DevInst);
        goto cleanupDriverInstallationLock;
    }
    BOOL DestroyDriverInfoListOnCleanup = TRUE;
    FILETIME DriverDate = { 0 };
    DWORDLONG DriverVersion = 0;
    HDEVINFO DevInfoExistingAdapters = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA_LIST *ExistingAdapters = NULL;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = GetAdapterDrvInfoDetail(DevInfo, DevInfoData, &DrvInfoData);
        if (!DrvInfoDetailData)
        {
            LOG(WIREGUARD_LOG_WARN, L"Failed getting adapter %u driver info detail", DevInfoData->DevInst);
            continue;
        }
        if (!IsOurDrvInfoDetail(DrvInfoDetailData))
            goto next;
        if (IsNewer(&OurDriverDate, OurDriverVersion, &DrvInfoData.DriverDate, DrvInfoData.DriverVersion))
        {
            if (DevInfoExistingAdapters == INVALID_HANDLE_VALUE)
            {
                DevInfoExistingAdapters =
                    SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
                if (DevInfoExistingAdapters == INVALID_HANDLE_VALUE)
                {
                    LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
                    Free(DrvInfoDetailData);
                    goto cleanupExistingAdapters;
                }
                _Analysis_assume_(DevInfoExistingAdapters != NULL);
                DisableAllOurAdapters(DevInfoExistingAdapters, &ExistingAdapters);
                LOG(WIREGUARD_LOG_INFO, L"Waiting for existing driver to unload from kernel");
                if (!EnsureWireGuardUnloaded())
                    LOG(WIREGUARD_LOG_WARN,
                        L"Failed to unload existing driver, which means a reboot will likely be required");
            }
            LOG(WIREGUARD_LOG_INFO,
                L"Removing existing driver %u.%u",
                (DWORD)((DrvInfoData.DriverVersion & 0xffff000000000000) >> 48),
                (DWORD)((DrvInfoData.DriverVersion & 0x0000ffff00000000) >> 32));
            LPWSTR InfFileName = PathFindFileNameW(DrvInfoDetailData->InfFileName);
            if (!SetupUninstallOEMInfW(InfFileName, SUOI_FORCEDELETE, NULL))
                LOG_LAST_ERROR(L"Unable to remove existing driver %s", InfFileName);
            goto next;
        }
        if (!IsNewer(&DrvInfoData.DriverDate, DrvInfoData.DriverVersion, &DriverDate, DriverVersion))
            goto next;
        if (!SetupDiSetSelectedDriverW(DevInfo, DevInfoData, &DrvInfoData))
        {
            LOG_LAST_ERROR(
                L"Failed to select driver %s for adapter %u", DrvInfoDetailData->InfFileName, DevInfoData->DevInst);
            goto next;
        }
        DriverDate = DrvInfoData.DriverDate;
        DriverVersion = DrvInfoData.DriverVersion;
    next:
        Free(DrvInfoDetailData);
    }

    if (DriverVersion)
    {
        LOG(WIREGUARD_LOG_INFO,
            L"Using existing driver %u.%u",
            (DWORD)((DriverVersion & 0xffff000000000000) >> 48),
            (DWORD)((DriverVersion & 0x0000ffff00000000) >> 32));
        LastError = ERROR_SUCCESS;
        DestroyDriverInfoListOnCleanup = FALSE;
        goto cleanupExistingAdapters;
    }

    LOG(WIREGUARD_LOG_INFO,
        L"Installing driver %u.%u",
        (DWORD)((OurDriverVersion & 0xffff000000000000) >> 48),
        (DWORD)((OurDriverVersion & 0x0000ffff00000000) >> 32));
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!ResourceCreateTemporaryDirectory(RandomTempSubDirectory))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create temporary folder %s", RandomTempSubDirectory);
        goto cleanupExistingAdapters;
    }

    WCHAR CatPath[MAX_PATH] = { 0 };
    WCHAR SysPath[MAX_PATH] = { 0 };
    WCHAR InfPath[MAX_PATH] = { 0 };
    WCHAR DownlevelShimPath[MAX_PATH] = { 0 };
    if (!PathCombineW(CatPath, RandomTempSubDirectory, L"wireguard.cat") ||
        !PathCombineW(SysPath, RandomTempSubDirectory, L"wireguard.sys") ||
        !PathCombineW(InfPath, RandomTempSubDirectory, L"wireguard.inf"))
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }

    LOG(WIREGUARD_LOG_INFO, L"Extracting driver");
    if (!ResourceCopyToFile(CatPath, L"wireguard.cat") || !ResourceCopyToFile(SysPath, L"wireguard.sys") ||
        !ResourceCopyToFile(InfPath, L"wireguard.inf"))
    {
        LastError = LOG_LAST_ERROR(L"Failed to extract driver");
        goto cleanupDelete;
    }

    WCHAR *WintrustKeyOriginalValue = NULL;
    HKEY WintrustKey = NULL;
    if (!IsWindows10)
    {
        LOG(WIREGUARD_LOG_INFO, L"Shimming downlevel driver loader");
        if (!PathCombineW(DownlevelShimPath, RandomTempSubDirectory, L"downlevelshim.dll"))
        {
            DownlevelShimPath[0] = L'\0';
            LastError = ERROR_BUFFER_OVERFLOW;
            goto cleanupDelete;
        }
        if (!ResourceCopyToFile(DownlevelShimPath, L"downlevelshim.dll"))
        {
            LastError = LOG_LAST_ERROR(L"Failed to extract downlevel shim");
            goto cleanupDelete;
        }
        LastError = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &WintrustKey);
        if (LastError != ERROR_SUCCESS)
        {
            LOG_ERROR(LastError, L"Failed to open Wintrust FinalPolicy key");
            goto cleanupDelete;
        }
        WintrustKeyOriginalValue = RegistryQueryString(WintrustKey, L"$DLL", TRUE);
        if (!WintrustKeyOriginalValue)
        {
            LastError = LOG_LAST_ERROR(L"Failed to read current Wintrust FinalPolicy key");
            goto cleanupWintrustKey;
        }
        LastError = RegSetValueExW(
            WintrustKey,
            L"$DLL",
            0,
            REG_SZ,
            (BYTE *)DownlevelShimPath,
            (DWORD)((wcslen(DownlevelShimPath) + 1) * sizeof(DownlevelShimPath[0])));
        if (LastError != ERROR_SUCCESS)
        {
            LOG_ERROR(LastError, L"Failed to set Wintrust FinalPolicy key");
            goto cleanupWintrustChangedKey;
        }
    }

    LOG(WIREGUARD_LOG_INFO, L"Installing driver");
    WCHAR InfStorePath[MAX_PATH];
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_NONE, 0, InfStorePath, MAX_PATH, NULL, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Could not install driver %s to store", InfPath);
        goto cleanupWintrustChangedKey;
    }
    _Analysis_assume_nullterminated_(InfStorePath);

    SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
    DestroyDriverInfoListOnCleanup = FALSE;
    DevInstallParams->Flags |= DI_ENUMSINGLEINF;
    if (wcsncpy_s(DevInstallParams->DriverPath, _countof(DevInstallParams->DriverPath), InfStorePath, _TRUNCATE) ==
        STRUNCATE)
    {
        LOG(WIREGUARD_LOG_ERR, L"Inf path too long: %s", InfStorePath);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupWintrustChangedKey;
    }
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, DevInfoData, DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u device installation parameters", DevInfoData->DevInst);
        goto cleanupWintrustChangedKey;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed rebuilding adapter %u driver info list", DevInfoData->DevInst);
        goto cleanupWintrustChangedKey;
    }
    DestroyDriverInfoListOnCleanup = TRUE;
    SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
    if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, 0, &DrvInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u driver", DevInfoData->DevInst);
        goto cleanupWintrustChangedKey;
    }
    if (!SetupDiSetSelectedDriverW(DevInfo, DevInfoData, &DrvInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u driver", DevInfoData->DevInst);
        goto cleanupWintrustChangedKey;
    }
    LastError = ERROR_SUCCESS;
    DestroyDriverInfoListOnCleanup = FALSE;

cleanupWintrustChangedKey:
    if (WintrustKeyOriginalValue)
        RegSetValueExW(
            WintrustKey,
            L"$DLL",
            0,
            REG_SZ,
            (BYTE *)WintrustKeyOriginalValue,
            (DWORD)((wcslen(WintrustKeyOriginalValue) + 1) * sizeof(WintrustKeyOriginalValue[0])));
cleanupWintrustKey:
    if (WintrustKey)
        RegCloseKey(WintrustKey);
    if (WintrustKeyOriginalValue)
        Free(WintrustKeyOriginalValue);
cleanupDelete:
    DeleteFileW(CatPath);
    DeleteFileW(SysPath);
    DeleteFileW(InfPath);
    if (DownlevelShimPath[0])
        DeleteFileW(DownlevelShimPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
cleanupExistingAdapters:
    if (LastError == ERROR_SUCCESS)
    {
        *DevInfoExistingAdaptersForCleanup = DevInfoExistingAdapters;
        *ExistingAdaptersForCleanup = ExistingAdapters;
    }
    else
        SelectDriverDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
    if (DestroyDriverInfoListOnCleanup)
        SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
WIREGUARD_ADAPTER *
AdapterOpenFromDevInstanceId(LPCWSTR Pool, LPCWSTR DevInstanceID)
{
    WIREGUARD_ADAPTER *Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        return FALSE;

    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanup;
    }
    Adapter->DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    if (!SetupDiOpenDeviceInfoW(Adapter->DevInfo, DevInstanceID, NULL, 0, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to open device instance ID %s", DevInstanceID);
        goto cleanupMutex;
    }
    if (!PopulateAdapterData(Adapter, Pool))
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to populate adapter %u data", Adapter->DevInfoData.DevInst);
        goto cleanupMutex;
    }
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    if (LastError != ERROR_SUCCESS)
        WireGuardFreeAdapter(Adapter);
    return RET_ERROR(Adapter, LastError);
}

typedef struct _WAIT_FOR_INTERFACE_CTX
{
    HANDLE Event;
    DWORD LastError;
} WAIT_FOR_INTERFACE_CTX;

static VOID WINAPI
WaitForInterfaceCallback(
    _In_ HDEVQUERY DevQuery,
    _Inout_ PVOID Context,
    _In_ const DEV_QUERY_RESULT_ACTION_DATA *ActionData)
{
    WAIT_FOR_INTERFACE_CTX *Ctx = Context;
    Ctx->LastError = ERROR_SUCCESS;
    if (ActionData->Action == DevQueryResultStateChange)
    {
        if (ActionData->Data.State != DevQueryStateAborted)
            return;
        Ctx->LastError = ERROR_DEVICE_NOT_AVAILABLE;
    }
    else if (ActionData->Action == DevQueryResultRemove)
        return;
    SetEvent(Ctx->Event);
}

#if NTDDI_VERSION == NTDDI_WIN7
_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
WaitForInterfaceWin7(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    ULONG Status, Number;
    DWORD ValType, Zero;
    HKEY Key = INVALID_HANDLE_VALUE;
    BOOLEAN Ret = FALSE;
    for (int i = 0; i < 1500; ++i)
    {
        if (i)
            Sleep(10);
        if (Key == INVALID_HANDLE_VALUE)
        {
            Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
            if (Key == INVALID_HANDLE_VALUE)
                continue;
        }
        _Analysis_assume_(Key);
        Zero = 0;
        if (RegQueryValueExW(Key, L"NetCfgInstanceId", NULL, &ValType, NULL, &Zero) != ERROR_MORE_DATA &&
            CM_Get_DevNode_Status(&Status, &Number, DevInfoData->DevInst, 0) == CR_SUCCESS &&
            !(Status & DN_HAS_PROBLEM) && !Number)
        {
            Ret = TRUE;
            break;
        }
    }
    if (Key != INVALID_HANDLE_VALUE)
        RegCloseKey(Key);
    return Ret;
}
#endif

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
WaitForInterface(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
#if NTDDI_VERSION == NTDDI_WIN7
    if (IsWindows7)
        return WaitForInterfaceWin7(DevInfo, DevInfoData);
#endif

    DWORD LastError = ERROR_SUCCESS, Size;
    WCHAR InstanceId[MAX_INSTANCE_ID];
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, _countof(InstanceId), &Size))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u instance ID", DevInfoData->DevInst);
        goto cleanup;
    }

    static const DEVPROP_BOOLEAN DevPropTrue = DEVPROP_TRUE;
    const DEVPROP_FILTER_EXPRESSION Filters[] = { { .Operator = DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
                                                    .Property.CompKey.Key = DEVPKEY_Device_InstanceId,
                                                    .Property.CompKey.Store = DEVPROP_STORE_SYSTEM,
                                                    .Property.Type = DEVPROP_TYPE_STRING,
                                                    .Property.Buffer = InstanceId,
                                                    .Property.BufferSize =
                                                        (ULONG)((wcslen(InstanceId) + 1) * sizeof(InstanceId[0])) },
                                                  { .Operator = DEVPROP_OPERATOR_EQUALS,
                                                    .Property.CompKey.Key = DEVPKEY_DeviceInterface_Enabled,
                                                    .Property.CompKey.Store = DEVPROP_STORE_SYSTEM,
                                                    .Property.Type = DEVPROP_TYPE_BOOLEAN,
                                                    .Property.Buffer = (PVOID)&DevPropTrue,
                                                    .Property.BufferSize = sizeof(DevPropTrue) },
                                                  { .Operator = DEVPROP_OPERATOR_EQUALS,
                                                    .Property.CompKey.Key = DEVPKEY_DeviceInterface_ClassGuid,
                                                    .Property.CompKey.Store = DEVPROP_STORE_SYSTEM,
                                                    .Property.Type = DEVPROP_TYPE_GUID,
                                                    .Property.Buffer = (PVOID)&GUID_DEVINTERFACE_NET,
                                                    .Property.BufferSize = sizeof(GUID_DEVINTERFACE_NET) } };
    WAIT_FOR_INTERFACE_CTX Ctx = { .Event = CreateEventW(NULL, FALSE, FALSE, NULL) };
    if (!Ctx.Event)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create event");
        goto cleanup;
    }
    HDEVQUERY Query;
    HRESULT HRet = DevCreateObjectQuery(
        DevObjectTypeDeviceInterface,
        DevQueryFlagUpdateResults,
        0,
        NULL,
        _countof(Filters),
        Filters,
        WaitForInterfaceCallback,
        &Ctx,
        &Query);
    if (HRet < 0)
    {
        LastError = LOG_ERROR(HRet, L"Failed to create device query");
        goto cleanupEvent;
    }
    LastError = WaitForSingleObject(Ctx.Event, 15000);
    if (LastError != WAIT_OBJECT_0)
    {
        if (LastError == WAIT_FAILED)
            LastError = LOG_LAST_ERROR(L"Failed to wait for device query");
        else
            LastError = LOG_ERROR(LastError, L"Timed out waiting for device query");
        goto cleanupQuery;
    }
    LastError = Ctx.LastError;
    if (LastError != ERROR_SUCCESS)
        LastError = LOG_ERROR(LastError, L"Failed to get enabled device");
cleanupQuery:
    DevCloseObjectQuery(Query);
cleanupEvent:
    CloseHandle(Ctx.Event);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
WIREGUARD_ADAPTER_HANDLE WINAPI
WireGuardCreateAdapter(LPCWSTR Pool, LPCWSTR Name, const GUID *RequestedGUID)
{
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return CreateAdapterViaRundll32(Pool, Name, RequestedGUID);
#endif

    DWORD LastError = ERROR_SUCCESS;
    LOG(WIREGUARD_LOG_INFO, L"Creating adapter");

    WIREGUARD_ADAPTER *Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        return NULL;

    WCHAR InstanceIdInf[MAX_PATH];
    if (!GetWindowsDirectoryW(InstanceIdInf, _countof(InstanceIdInf)) ||
        !PathAppend(InstanceIdInf, L"INF\\wireguard-instanceid.inf"))
    {
        LastError = LOG_ERROR(ERROR_BUFFER_OVERFLOW, L"Failed to construct INF path");
        goto cleanupAdapter;
    }
    HANDLE InstanceIdMutex = NamespaceTakeInstanceIdMutex();
    if (!InstanceIdMutex)
    {
        LastError = LOG_LAST_ERROR(L"Failed to take instance ID mutex");
        goto cleanupAdapter;
    }
    if (RequestedGUID && IsWindows10)
    {
        HANDLE InstanceIdFile = CreateFileW(
            InstanceIdInf,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (InstanceIdFile == INVALID_HANDLE_VALUE)
        {
            LastError = LOG_LAST_ERROR(L"Failed to open %s for writing", InstanceIdInf);
            goto cleanupInstanceIdMutex;
        }
        static const WCHAR InfTemplate[] =
            L"[Version]\r\n"
            L"Signature = \"$Windows NT$\"\r\n"
            L"[WireGuard.NetSetup]\r\n"
            L"AddReg = WireGuard.SuggestedInstanceId\r\n"
            L"[WireGuard.SuggestedInstanceId]\r\n"
            L"HKR,,SuggestedInstanceId,1,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X\r\n";
        WCHAR InfContents[_countof(InfTemplate)];
        BYTE *P = (BYTE *)RequestedGUID;
        _snwprintf_s(
            InfContents,
            _countof(InfContents),
            _TRUNCATE,
            InfTemplate,
            P[0],
            P[1],
            P[2],
            P[3],
            P[4],
            P[5],
            P[6],
            P[7],
            P[8],
            P[9],
            P[10],
            P[11],
            P[12],
            P[13],
            P[14],
            P[15]);
        DWORD BytesWritten;
        if (!WriteFile(
                InstanceIdFile,
                InfContents,
                (DWORD)(wcslen(InfContents) * sizeof(InfContents[0])),
                &BytesWritten,
                NULL))
        {
            LastError = LOG_LAST_ERROR(L"Failed to write bytes to %s", InstanceIdInf);
            CloseHandle(InstanceIdFile);
            goto cleanupInstanceIdFile;
        }
        CloseHandle(InstanceIdFile);
    }
    else if (IsWindows10)
        DeleteFileW(InstanceIdInf);

    Adapter->DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create empty device information set");
        goto cleanupAdapter;
    }
    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    if (!SetupDiClassNameFromGuidExW(&GUID_DEVCLASS_NET, ClassName, _countof(ClassName), NULL, NULL, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to retrieve class name associated with class GUID");
        goto cleanupAdapter;
    }

    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    if (!GetPoolDeviceTypeName(Pool, PoolDeviceTypeName))
    {
        LastError = GetLastError();
        goto cleanupAdapter;
    }
    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    if (!SetupDiCreateDeviceInfoW(
            Adapter->DevInfo,
            ClassName,
            &GUID_DEVCLASS_NET,
            PoolDeviceTypeName,
            NULL,
            DICD_GENERATE_ID,
            &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create new device information element");
        goto cleanupAdapter;
    }
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(DevInstallParams) };
    if (!SetupDiGetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(
            L"Failed to retrieve adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError =
            LOG_LAST_ERROR(L"Failed to set adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }
    if (!SetupDiSetSelectedDevice(Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to select adapter %u device", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }
    static const WCHAR Hwids[_countof(WIREGUARD_HWID) + 1 /*Multi-string terminator*/] = WIREGUARD_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(
            Adapter->DevInfo, &Adapter->DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u hardware ID", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }

    HDEVINFO DevInfoExistingAdapters;
    SP_DEVINFO_DATA_LIST *ExistingAdapters;
    if (!SelectDriver(
            Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams, &DevInfoExistingAdapters, &ExistingAdapters))
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to select adapter %u driver", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }

    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanupDriverInfoList;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to register adapter %u device", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, Adapter->DevInfo, &Adapter->DevInfoData))
        LOG_LAST_ERROR(L"Failed to register adapter %u coinstallers", Adapter->DevInfoData.DevInst);
    if (!SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, Adapter->DevInfo, &Adapter->DevInfoData))
        LOG_LAST_ERROR(L"Failed to install adapter %u interfaces", Adapter->DevInfoData.DevInst);
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to install adapter %u device", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }

    if (CheckReboot(Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = ERROR_PNP_REBOOT_REQUIRED;
        goto cleanupDevice;
    }

    if (!SetupDiSetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_WireGuard_Pool,
            DEVPROP_TYPE_STRING,
#pragma warning(suppress : 4090)
            (const BYTE *)Pool,
            (DWORD)((wcslen(Pool) + 1) * sizeof(*Pool)),
            0))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u pool", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }
    if (!SetupDiSetDeviceRegistryPropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            SPDRP_DEVICEDESC,
            (const BYTE *)PoolDeviceTypeName,
            (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(*PoolDeviceTypeName))))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u description", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }

    if (!WaitForInterface(Adapter->DevInfo, &Adapter->DevInfoData))
    {
        DEVPROPTYPE PropertyType = 0;
        NTSTATUS NtStatus = 0;
        INT32 ProblemCode = 0;
        if (!SetupDiGetDevicePropertyW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &DEVPKEY_Device_ProblemStatus,
                &PropertyType,
                (PBYTE)&NtStatus,
                sizeof(NtStatus),
                NULL,
                0) ||
            PropertyType != DEVPROP_TYPE_NTSTATUS)
            NtStatus = 0;
        if (!SetupDiGetDevicePropertyW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &DEVPKEY_Device_ProblemCode,
                &PropertyType,
                (PBYTE)&ProblemCode,
                sizeof(ProblemCode),
                NULL,
                0) ||
            (PropertyType != DEVPROP_TYPE_INT32 && PropertyType != DEVPROP_TYPE_UINT32))
            ProblemCode = 0;
        LastError = RtlNtStatusToDosError(NtStatus);
        if (LastError == ERROR_SUCCESS)
            LastError = ERROR_DEVICE_NOT_AVAILABLE;
        LOG_ERROR(LastError, L"Failed to setup adapter (problem code: 0x%x, ntstatus: 0x%x)", ProblemCode, NtStatus);
        goto cleanupDevice;
    }

    if (!PopulateAdapterData(Adapter, Pool))
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to populate adapter %u data", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }

    if (!WireGuardSetAdapterName(Adapter, Name))
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to set adapter name %s", Name);
        goto cleanupDevice;
    }

    if (!EnsureDeviceObject(Adapter->DevInstanceID))
    {
        LastError = LOG_LAST_ERROR(L"Device object file did not appear");
        goto cleanupDevice;
    }
    LastError = ERROR_SUCCESS;

cleanupDevice:
    if (LastError != ERROR_SUCCESS)
    {
        SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                              .InstallFunction = DIF_REMOVE },
                                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
        if (SetupDiSetClassInstallParamsW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &RemoveDeviceParams.ClassInstallHeader,
                sizeof(RemoveDeviceParams)))
            SetupDiCallClassInstaller(DIF_REMOVE, Adapter->DevInfo, &Adapter->DevInfoData);
    }
    NamespaceReleaseMutex(Mutex);
cleanupDriverInfoList:
    SelectDriverDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
    SetupDiDestroyDriverInfoList(Adapter->DevInfo, &Adapter->DevInfoData, SPDIT_COMPATDRIVER);
cleanupInstanceIdFile:
    DeleteFileW(InstanceIdInf);
cleanupInstanceIdMutex:
    NamespaceReleaseMutex(InstanceIdMutex);
cleanupAdapter:
    if (LastError != ERROR_SUCCESS)
        WireGuardFreeAdapter(Adapter);
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
BOOL WINAPI
WireGuardDeleteAdapter(WIREGUARD_ADAPTER *Adapter)
{
    WireGuardSetAdapterLogging(Adapter, WIREGUARD_ADAPTER_LOG_OFF);

#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return DeleteAdapterViaRundll32(Adapter);
#endif

    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Adapter->Pool);
    if (!Mutex)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to take %s pool mutex", Adapter->Pool);
        goto cleanup;
    }

    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(DevInstallParams) };
    if (!SetupDiGetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(
            L"Failed to retrieve adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupMutex;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError =
            LOG_LAST_ERROR(L"Failed to set adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupMutex;
    }

    SP_REMOVEDEVICE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                              .InstallFunction = DIF_REMOVE },
                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
    if ((!SetupDiSetClassInstallParamsW(
             Adapter->DevInfo, &Adapter->DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
         !SetupDiCallClassInstaller(DIF_REMOVE, Adapter->DevInfo, &Adapter->DevInfoData)) &&
        GetLastError() != ERROR_NO_SUCH_DEVINST)
        LastError = LOG_LAST_ERROR(L"Failed to remove adapter %u", Adapter->DevInfoData.DevInst);

    if (CheckReboot(Adapter->DevInfo, &Adapter->DevInfoData))
        LastError = LastError == ERROR_SUCCESS ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_FAIL_REBOOT_REQUIRED;

cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
DeleteAllOurAdapters(_In_z_ LPCWSTR Pool, _Inout_ BOOL *RebootRequired)
{
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LOG(WIREGUARD_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        return FALSE;
    }
    DWORD LastError = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    SP_REMOVEDEVICE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                              .InstallFunction = DIF_REMOVE },
                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        if (!IsOurAdapter(DevInfo, &DevInfoData) || !IsPoolMember(Pool, DevInfo, &DevInfoData))
            continue;

        LOG(WIREGUARD_LOG_INFO, L"Removing adapter %u", DevInfoData.DevInst);
        if ((!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
             !SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData)) &&
            GetLastError() != ERROR_NO_SUCH_DEVINST)
        {
            LOG_LAST_ERROR(L"Failed to remove adapter %u", DevInfoData.DevInst);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
        }
        *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
BOOL WINAPI
WireGuardDeletePoolDriver(LPCWSTR Pool)
{
    DWORD LastError = ERROR_SUCCESS;
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
    {
        LastError = DeletePoolDriverViaRundll32(Pool) ? ERROR_SUCCESS : GetLastError();
        goto cleanup;
    }
#endif

    BOOL RebootRequired = FALSE;
    if (!DeleteAllOurAdapters(Pool, &RebootRequired))
    {
        LastError = GetLastError();
        goto cleanup;
    }

    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to take driver installation mutex");
        goto cleanup;
    }
    HDEVINFO DeviceInfoSet = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, 0);
    if (!DeviceInfoSet)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter information");
        goto cleanupDriverInstallationLock;
    }
    if (!SetupDiBuildDriverInfoList(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building driver info list");
        goto cleanupDeviceInfoSet;
    }
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DriverInfo = { .cbSize = sizeof(DriverInfo) };
        if (!SetupDiEnumDriverInfoW(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER, EnumIndex, &DriverInfo))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DriverDetail = GetAdapterDrvInfoDetail(DeviceInfoSet, NULL, &DriverInfo);
        if (!DriverDetail)
            continue;
        if (!_wcsicmp(DriverDetail->HardwareID, WIREGUARD_HWID))
        {
            LPCWSTR Path = PathFindFileNameW(DriverDetail->InfFileName);
            LOG(WIREGUARD_LOG_INFO, L"Removing driver %s", Path);
            if (!SetupUninstallOEMInfW(Path, 0, NULL))
            {
                LOG_LAST_ERROR(L"Unable to remove driver %s", Path);
                LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
            }
        }
        Free(DriverDetail);
    }
    if (RebootRequired)
        LastError = LastError == ERROR_SUCCESS ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_FAIL_REBOOT_REQUIRED;
    SetupDiDestroyDriverInfoList(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(DeviceInfoSet);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
BOOL WINAPI
WireGuardEnumAdapters(LPCWSTR Pool, WIREGUARD_ENUM_CALLBACK Func, LPARAM Param)
{
    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanup;
    }
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    BOOL Continue = TRUE;
    for (DWORD EnumIndex = 0; Continue; ++EnumIndex)
    {
        WIREGUARD_ADAPTER Adapter = { .DevInfo = DevInfo, .DevInfoData.cbSize = sizeof(Adapter.DevInfoData) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &Adapter.DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        if (!IsOurAdapter(DevInfo, &Adapter.DevInfoData) || !IsPoolMember(Pool, DevInfo, &Adapter.DevInfoData))
            continue;

        if (!PopulateAdapterData(&Adapter, Pool))
        {
            LastError = LOG(WIREGUARD_LOG_ERR, L"Failed to populate adapter %u data", Adapter.DevInfoData.DevInst);
            break;
        }
        Continue = Func(&Adapter, Param);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    return RET_ERROR(TRUE, LastError);
}
