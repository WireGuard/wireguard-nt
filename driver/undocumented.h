/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>

NTSYSAPI
NTSTATUS NTAPI ZwYieldExecution(VOID);

NTSYSAPI
BOOLEAN NTAPI
SystemPrng(_Out_writes_bytes_all_(Len) PVOID RandomData, _In_ SIZE_T Len);
