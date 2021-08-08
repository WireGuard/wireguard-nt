/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "logging.h"
#include "ioctl.h"
#include "device.h"
#include <ntstrsafe.h>

_Use_decl_annotations_
VOID
LogRingInit(LOG_RING *Log)
{
    Log->CurrentWriters = Log->FirstAndLength = 0;
    KeInitializeEvent(&Log->NewEntry, SynchronizationEvent, FALSE);
}

typedef struct _FIRST_AND_LENGTH
{
    USHORT First, Length;
} FIRST_AND_LENGTH;
static_assert(sizeof(FIRST_AND_LENGTH) == sizeof(((LOG_RING *)0)->FirstAndLength), "First and length size mismatch");

_Use_decl_annotations_
VOID
LogRingWrite(LOG_RING *Log, PCSTR Format, ...)
{
    LARGE_INTEGER Timestamp;
    KeQuerySystemTime(&Timestamp);

    if (InterlockedIncrement(&Log->CurrentWriters) >= BUFFERED_LOG_ENTRIES - 1)
        goto out; /* Drop log entries if there's contention, rather than block. */

    USHORT Index;
    for (LONG OldFal = ReadNoFence(&Log->FirstAndLength);;)
    {
        LONG NewFal = OldFal;
        FIRST_AND_LENGTH *Fal = (FIRST_AND_LENGTH *)&NewFal;
        if (Fal->Length == BUFFERED_LOG_ENTRIES)
            Fal->First = (Fal->First + 1) & BUFFERED_LOG_ENTRIES_MASK;
        else
            ++Fal->Length;
        Index = (Fal->First + Fal->Length - 1) & BUFFERED_LOG_ENTRIES_MASK;
        LONG CurFal = InterlockedCompareExchange(&Log->FirstAndLength, NewFal, OldFal);
        if (CurFal == OldFal)
            break;
        OldFal = CurFal;
    }

    Log->Entries[Index].Timestamp = Timestamp.QuadPart;
    va_list Args;
    va_start(Args, Format);
    RtlStringCbVPrintfA(Log->Entries[Index].Msg, sizeof(Log->Entries[Index].Msg), Format, Args);
    va_end(Args);
    KeSetEvent(&Log->NewEntry, IO_NO_INCREMENT, FALSE);
out:
    InterlockedDecrement(&Log->CurrentWriters);
}

_Use_decl_annotations_
NTSTATUS
LogRingRead(LOG_RING *Log, WG_IOCTL_LOG_ENTRY *Entry, BOOLEAN *WhileFalse)
{
    NTSTATUS Status;

    while (!ReadBooleanNoFence(WhileFalse))
    {
        USHORT Index;
        for (LONG OldFal = ReadNoFence(&Log->FirstAndLength);;)
        {
            LONG NewFal = OldFal;
            FIRST_AND_LENGTH *Fal = (FIRST_AND_LENGTH *)&NewFal;
            if (!Fal->Length)
                goto wait;
            Index = Fal->First & BUFFERED_LOG_ENTRIES_MASK;
            Fal->First = (Fal->First + 1) & BUFFERED_LOG_ENTRIES_MASK;
            --Fal->Length;
            LONG CurFal = InterlockedCompareExchange(&Log->FirstAndLength, NewFal, OldFal);
            if (CurFal == OldFal)
                break;
            OldFal = CurFal;
        }
        RtlCopyMemory(Entry, &Log->Entries[Index], sizeof(*Entry));
        return STATUS_SUCCESS;

    wait:
        Status = KeWaitForSingleObject(&Log->NewEntry, UserRequest, UserMode, TRUE, NULL);
        if (Status != STATUS_SUCCESS) /* Intentionally not using NT_SUCCESS */
            break;
    }
    return STATUS_CANCELLED;
}

enum
{
    RATELIMIT_INTERVAL = 5 * SYS_TIME_UNITS_PER_SEC,
    RATELIMIT_BURST = 10,
};

_Use_decl_annotations_
BOOLEAN
LogRingIsRatelimited(_Inout_ LOG_RING *Log)
{
    BOOLEAN Ret = TRUE;
    if (InterlockedCompareExchange(&Log->RatelimitChecking, 1, 0) != 0)
        return Ret;
    ULONG64 Now = KeQueryInterruptTime();
    if (!Log->RatelimitStart)
        Log->RatelimitStart = Now;
    if ((LONG64)(Log->RatelimitStart + RATELIMIT_INTERVAL) - (LONG64)Now < 0)
    {
        if (Log->RatelimitMissed)
        {
            LogWarn(
                CONTAINING_RECORD(Log, WG_DEVICE, Log),
                "%u log lines swallowed by rate limiting",
                Log->RatelimitMissed);
            Log->RatelimitMissed = 0;
        }
        Log->RatelimitStart = Now;
        Log->RatelimitPrinted = 0;
    }
    if (Log->RatelimitPrinted <= RATELIMIT_BURST)
    {
        ++Log->RatelimitPrinted;
        Ret = FALSE;
    }
    else
        ++Log->RatelimitMissed;
    WriteNoFence(&Log->RatelimitChecking, 0);
    return Ret;
}

_Use_decl_annotations_
VOID
SockaddrToString(PSTR Buffer, CONST SOCKADDR_INET *Addr)
{
    if (Addr->si_family == AF_INET)
    {
        ULONG Length = SOCKADDR_STR_MAX_LEN;
        if (NT_SUCCESS(RtlIpv4AddressToStringExA(&Addr->Ipv4.sin_addr, Addr->Ipv4.sin_port, Buffer, &Length)))
            return;
    }
    else if (Addr->si_family == AF_INET6)
    {
        ULONG Length = SOCKADDR_STR_MAX_LEN;
        if (NT_SUCCESS(RtlIpv6AddressToStringExA(
                &Addr->Ipv6.sin6_addr, Addr->Ipv6.sin6_scope_id, Addr->Ipv6.sin6_port, Buffer, &Length)))
            return;
    }
    RtlStringCbCopyA(Buffer, SOCKADDR_STR_MAX_LEN, "no address");
}

#if DBG
_Use_decl_annotations_
VOID
DumpNetBuffer(NET_BUFFER *Nb, CHAR *Prefix)
{
    ULONG Len = NET_BUFFER_DATA_LENGTH(Nb);
    CHAR Format[128];
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, 1, LOG_DRIVER_PREFIX "%s (%u):\n", Prefix, Len);
    ULONG MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(Nb), i = 0, k = 0;
    for (MDL *Mdl = NET_BUFFER_CURRENT_MDL(Nb); Mdl; Mdl = Mdl->Next)
    {
        if (!Len)
            break;
        ULONG MdlLen = min(MmGetMdlByteCount(Mdl) - MdlOffset, Len);
        UCHAR *Data = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
        for (ULONG j = 0; j < MdlLen; ++j, ++k)
        {
            i += Data ? _snprintf_s(
                            Format + i,
                            sizeof(Format) - i,
                            _TRUNCATE,
                            "%02x%c",
                            Data[j + MdlOffset],
                            (k % 16 == 15) ? '\n' : ' ')
                      : _snprintf_s(Format + i, sizeof(Format) - i, _TRUNCATE, "..%c", (k % 16 == 15) ? '\n' : ' ');
            if (k % 16 == 15)
            {
                DbgPrintEx(DPFLTR_IHVNETWORK_ID, 1, "%s", Format);
                i = 0;
                Format[0] = 0;
            }
        }
        Len -= MdlLen;
        MdlOffset = 0;
    }
    if (i)
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, 1, "%s\n", Format);
}
#endif
