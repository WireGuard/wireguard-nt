/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include <ndis.h>
#include <wsk.h>

#define LOG_DRIVER_PREFIX "wireguard: "
#define LOG_DEVICE_PREFIX "%u: "

#if DBG
#    define LogErr(Device, Fmt, ...) \
        do \
        { \
            DbgPrintEx( \
                DPFLTR_IHVNETWORK_ID, \
                1, \
                LOG_DRIVER_PREFIX LOG_DEVICE_PREFIX Fmt "\n", \
                (Device)->InterfaceIndex, \
                ##__VA_ARGS__); \
            LogRingWrite(&(Device)->Log, "1" Fmt, ##__VA_ARGS__); \
        } while (0)
#    define LogWarn(Device, Fmt, ...) \
        do \
        { \
            DbgPrintEx( \
                DPFLTR_IHVNETWORK_ID, \
                2, \
                LOG_DRIVER_PREFIX LOG_DEVICE_PREFIX Fmt "\n", \
                (Device)->InterfaceIndex, \
                ##__VA_ARGS__); \
            LogRingWrite(&(Device)->Log, "2" Fmt, ##__VA_ARGS__); \
        } while (0)
#    define LogInfo(Device, Fmt, ...) \
        do \
        { \
            DbgPrintEx( \
                DPFLTR_IHVNETWORK_ID, \
                3, \
                LOG_DRIVER_PREFIX LOG_DEVICE_PREFIX Fmt "\n", \
                (Device)->InterfaceIndex, \
                ##__VA_ARGS__); \
            LogRingWrite(&(Device)->Log, "3" Fmt, ##__VA_ARGS__); \
        } while (0)
#    define LogDebug(Fmt, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, 4, LOG_DRIVER_PREFIX Fmt "\n", ##__VA_ARGS__)
#else
#    define LogErr(Device, Fmt, ...) LogRingWrite(&(Device)->Log, "1" Fmt, ##__VA_ARGS__)
#    define LogWarn(Device, Fmt, ...) LogRingWrite(&(Device)->Log, "2" Fmt, ##__VA_ARGS__)
#    define LogInfo(Device, Fmt, ...) LogRingWrite(&(Device)->Log, "3" Fmt, ##__VA_ARGS__)
#    define LogDebug(Fmt, ...)
#endif

#define LogInfoRatelimited(Device, Fmt, ...) \
    do \
    { \
        if (!LogRingIsRatelimited(&(Device)->Log)) \
            LogInfo(Device, Fmt, ##__VA_ARGS__); \
    } while (0)

#define LogInfoNblRatelimited(Device, Fmt, Nbl, ...) \
    do \
    { \
        ENDPOINT __Endpoint; \
        CHAR __EndpointStr[SOCKADDR_STR_MAX_LEN]; \
        SocketEndpointFromNbl(&__Endpoint, Nbl); \
        SockaddrToString(__EndpointStr, &__Endpoint.Addr); \
        LogInfoRatelimited(Device, Fmt, __EndpointStr, ##__VA_ARGS__); \
    } while (0)

enum
{
    MAX_LOG_LINE_LEN = 128,
    BUFFERED_LOG_ENTRIES = 32,
    BUFFERED_LOG_ENTRIES_MASK = BUFFERED_LOG_ENTRIES - 1,
};

typedef struct _LOG_RING
{
    CHAR Entries[BUFFERED_LOG_ENTRIES][MAX_LOG_LINE_LEN];
    LONG FirstAndLength;
    LONG CurrentWriters;
    KEVENT NewEntry;
    LONG RatelimitChecking;
    ULONG RatelimitPrinted, RatelimitMissed;
    ULONG64 RatelimitStart;
} LOG_RING;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
LogRingWrite(_Inout_ LOG_RING *Log, _In_z_ _Printf_format_string_ PCSTR Format, ...);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
LogRingInit(_Inout_ LOG_RING *Log);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
LogRingRead(
    _Inout_ LOG_RING *Log,
    _Out_writes_bytes_all_(MAX_LOG_LINE_LEN) CHAR Line[MAX_LOG_LINE_LEN],
    _In_ BOOLEAN *WhileFalse);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
LogRingIsRatelimited(_Inout_ LOG_RING *Log);

#define SOCKADDR_STR_MAX_LEN max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)
VOID
SockaddrToString(_Out_z_cap_c_(SOCKADDR_STR_MAX_LEN) PSTR Buffer, _In_ CONST SOCKADDR_INET *Addr);

#if DBG
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DumpNetBuffer(_In_ NET_BUFFER *Nb, _In_z_ CHAR *Prefix);
#endif
