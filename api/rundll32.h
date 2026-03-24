/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <SetupAPI.h>
#include "adapter.h"

_Return_type_success_(return != FALSE)
BOOL
RemoveInstanceViaRundll32(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

_Return_type_success_(return != FALSE)
BOOL
EnableInstanceViaRundll32(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

_Return_type_success_(return != FALSE)
BOOL
DisableInstanceViaRundll32(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);
