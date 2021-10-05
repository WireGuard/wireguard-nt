/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wireguard.h"
#include <IPExport.h>
#include <SetupAPI.h>
#include <Windows.h>

#define MAX_INSTANCE_ID MAX_PATH /* TODO: Is MAX_PATH always enough? */
#define WIREGUARD_HWID L"WireGuard"
#define WIREGUARD_ENUMERATOR (IsWindows7 ? L"ROOT\\" WIREGUARD_HWID : L"SWD\\" WIREGUARD_HWID)

extern const DEVPROPKEY DEVPKEY_WireGuard_Name;

typedef struct HSWDEVICE__ *HSWDEVICE;

/**
 * WireGuard adapter descriptor.
 */
typedef struct _WIREGUARD_ADAPTER
{
    HSWDEVICE SwDevice;
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    WCHAR *InterfaceFilename;
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    DWORD IfIndex;
    HANDLE LogThread;
    DWORD LogState;
} WIREGUARD_ADAPTER;
/**
 * @copydoc WIREGUARD_CREATE_ADAPTER_FUNC
 */
WIREGUARD_CREATE_ADAPTER_FUNC WireGuardCreateAdapter;

/**
 * @copydoc WIREGUARD_OPEN_ADAPTER_FUNC
 */
WIREGUARD_OPEN_ADAPTER_FUNC WireGuardOpenAdapter;

/**
 * @copydoc WIREGUARD_CLOSE_ADAPTER_FUNC
 */
WIREGUARD_CLOSE_ADAPTER_FUNC WireGuardCloseAdapter;

/**
 * @copydoc WIREGUARD_GET_ADAPTER_LUID_FUNC
 */
WIREGUARD_GET_ADAPTER_LUID_FUNC WireGuardGetAdapterLUID;

/**
 * Returns a handle to the adapter device object.
 *
 * @param Adapter       Adapter handle obtained with WireGuardOpenAdapter or WireGuardCreateAdapter.
 *
 * @return If the function succeeds, the return value is adapter device object handle.
 *         If the function fails, the return value is INVALID_HANDLE_VALUE. To get extended error
 *         information, call GetLastError.
 */
_Return_type_success_(return != INVALID_HANDLE_VALUE)
HANDLE WINAPI
AdapterOpenDeviceObject(_In_ const WIREGUARD_ADAPTER *Adapter);

/**
 * Returns the device object file name for an adapter instance ID.
 *
 * @param InstanceID       The device instance ID of the adapter.
 *
 * @return If the function succeeds, the return value is the filename of the device object, which
 *         must be freed with Free(). If the function fails, the return value is INVALID_HANDLE_VALUE.
 *         To get extended error information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
AdapterGetDeviceObjectFileName(_In_z_ LPCWSTR InstanceId);

/**
 * Cleans up adapters with no attached process.
 */
VOID AdapterCleanupOrphanedDevices(VOID);

/**
 * Removes the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterRemoveInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/**
 * Enables the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterEnableInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/**
 * Disables the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterDisableInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);
