/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#define SYS_TIME_UNITS_PER_SEC 10000000 /* System time unit is 100 ns. */
#define SEC_TO_SYS_TIME_UNITS(Sec) ((LONG64)(Sec)*SYS_TIME_UNITS_PER_SEC)

typedef struct _TIMER
{
    KTIMER Timer;
    KDPC Dpc;
    BOOLEAN Pending;
} TIMER;

typedef struct _WG_PEER WG_PEER;

_IRQL_requires_max_(APC_LEVEL)
VOID
TimersDataSent(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersDataReceived(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersAnyAuthenticatedPacketSent(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersAnyAuthenticatedPacketReceived(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
VOID
TimersHandshakeInitiated(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersHandshakeComplete(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersSessionDerived(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersAnyAuthenticatedPacketTraversal(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
TimersInit(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
VOID
TimersStop(_Inout_ WG_PEER *Peer);

static inline BOOLEAN
BirthdateHasExpired(_In_ CONST UINT64 BirthdaySysTimeUnits, _In_ CONST UINT64 ExpirationSeconds)
{
    return (INT64)(BirthdaySysTimeUnits + SEC_TO_SYS_TIME_UNITS(ExpirationSeconds)) <= (INT64)KeQueryInterruptTime();
}
