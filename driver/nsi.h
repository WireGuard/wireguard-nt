/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2026 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>

typedef struct _WG_DEVICE WG_DEVICE;

_IRQL_requires_max_(APC_LEVEL)
VOID NsiDriverEntry(_In_ DRIVER_OBJECT *DriverObject);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS NsiActivate(_Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID NsiDeactivate(_Inout_ WG_DEVICE *Wg);
