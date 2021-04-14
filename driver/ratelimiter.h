/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RatelimiterAllow(_In_ CONST SOCKADDR *Src);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
RatelimiterDriverEntry(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID RatelimiterUnload(VOID);

#ifdef DBG
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
RatelimiterSelftest(VOID);
#endif
