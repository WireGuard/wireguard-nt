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

/**
 * WireGuard adapter descriptor.
 */
typedef struct _WIREGUARD_ADAPTER
{
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    DWORD IfIndex;
    WCHAR Pool[WIREGUARD_MAX_POOL];
    HANDLE LogThread;
    DWORD LogState;
} WIREGUARD_ADAPTER;

/**
 * @copydoc WIREGUARD_FREE_ADAPTER_FUNC
 */
WIREGUARD_FREE_ADAPTER_FUNC WireGuardFreeAdapter;

/**
 * @copydoc WIREGUARD_CREATE_ADAPTER_FUNC
 */
WIREGUARD_CREATE_ADAPTER_FUNC WireGuardCreateAdapter;

/**
 * @copydoc WIREGUARD_OPEN_ADAPTER_FUNC
 */
WIREGUARD_OPEN_ADAPTER_FUNC WireGuardOpenAdapter;

/**
 * @copydoc WIREGUARD_DELETE_ADAPTER_FUNC
 */
WIREGUARD_DELETE_ADAPTER_FUNC WireGuardDeleteAdapter;

/**
 * @copydoc WIREGUARD_ENUM_ADAPTERS_FUNC
 */
WIREGUARD_ENUM_ADAPTERS_FUNC WireGuardEnumAdapters;

/**
 * @copydoc WIREGUARD_DELETE_POOL_DRIVER_FUNC
 */
WIREGUARD_DELETE_POOL_DRIVER_FUNC WireGuardDeletePoolDriver;

/**
 * @copydoc WIREGUARD_GET_ADAPTER_LUID_FUNC
 */
WIREGUARD_GET_ADAPTER_LUID_FUNC WireGuardGetAdapterLUID;

/**
 * @copydoc WIREGUARD_GET_ADAPTER_NAME_FUNC
 */
WIREGUARD_GET_ADAPTER_NAME_FUNC WireGuardGetAdapterName;

/**
 * @copydoc WIREGUARD_SET_ADAPTER_NAME_FUNC
 */
WIREGUARD_SET_ADAPTER_NAME_FUNC WireGuardSetAdapterName;

/**
 * @copydoc WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC
 */
WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC WireGuardGetRunningDriverVersion;

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
 * Returns an adapter object based on a devnode instance ID.
 *
 * @param Pool          Pool name of adapter object to be opened.
 *
 * @param DevInstanceID Instance ID of devnode for opening adapter.
 *
 * @return If the function succeeds, the return value is adapter object..
 *         If the function fails, the return value is NULL. To get extended error
 *         information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WIREGUARD_ADAPTER *
AdapterOpenFromDevInstanceId(_In_z_ LPCWSTR Pool, _In_z_ LPCWSTR DevInstanceID);
