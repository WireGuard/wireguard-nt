/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "containers.h"
#include "ratelimiter.h"
#include "crypto.h"
#include "logging.h"
#include "timers.h"

#define TABLE_SIZE 8192
#define MAX_ENTRIES (TABLE_SIZE * 8)

static LOOKASIDE_ALIGN LOOKASIDE_LIST_EX EntryCache;
static HSIPHASH_KEY Key;
static KSPIN_LOCK TableLock;
static LONG TotalEntries = 0;
static struct
{
    KEVENT Terminate;
    PKTHREAD Thread;
} RatelimiterGcEntriesThread;
static HLIST_HEAD TableV4[TABLE_SIZE] = { 0 }, TableV6[TABLE_SIZE] = { 0 };

typedef struct _RATELIMITER_ENTRY
{
    UINT64 LastTime, Tokens, Ip;
    KSPIN_LOCK Lock;
    HLIST_NODE Hash;
    RCU_CALLBACK Rcu;
} RATELIMITER_ENTRY;

enum
{
    PACKETS_PER_SECOND = 20,
    PACKETS_BURSTABLE = 5,
    PACKET_COST = SYS_TIME_UNITS_PER_SEC / PACKETS_PER_SECOND,
    TOKEN_MAX = PACKET_COST * PACKETS_BURSTABLE
};

static RCU_CALLBACK_FN EntryFree;
_Use_decl_annotations_
static VOID
EntryFree(RCU_CALLBACK *Rcu)
{
    ExFreeToLookasideListEx(&EntryCache, CONTAINING_RECORD(Rcu, RATELIMITER_ENTRY, Rcu));
    InterlockedDecrement(&TotalEntries);
}

static VOID
EntryUninit(_Inout_ RATELIMITER_ENTRY *Entry)
{
    HlistDelRcu(&Entry->Hash);
    RcuCall(&Entry->Rcu, EntryFree);
}

/* Calling this function with a NULL work uninits all entries. */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(KSTART_ROUTINE)
static VOID
RatelimiterGcEntries(_In_opt_ PVOID StartContext)
{
    for (;;)
    {
        CONST UINT64 Now = KeQueryInterruptTime();
        RATELIMITER_ENTRY *Entry;
        HLIST_NODE *Temp;
        ULONG i;
        KIRQL Irql;

        for (i = 0; i < TABLE_SIZE; ++i)
        {
            KeAcquireSpinLock(&TableLock, &Irql);
            HLIST_FOR_EACH_ENTRY_SAFE (Entry, Temp, &TableV4[i], RATELIMITER_ENTRY, Hash)
            {
                if (!StartContext || Now - Entry->LastTime > SYS_TIME_UNITS_PER_SEC)
                    EntryUninit(Entry);
            }
            HLIST_FOR_EACH_ENTRY_SAFE (Entry, Temp, &TableV6[i], RATELIMITER_ENTRY, Hash)
            {
                if (!StartContext || Now - Entry->LastTime > SYS_TIME_UNITS_PER_SEC)
                    EntryUninit(Entry);
            }
            KeReleaseSpinLock(&TableLock, Irql);
        }
        if (!StartContext)
            break;
        if (KeWaitForSingleObject(
                &RatelimiterGcEntriesThread.Terminate,
                Executive,
                KernelMode,
                FALSE,
                &(LARGE_INTEGER){ .QuadPart = -SYS_TIME_UNITS_PER_SEC }) == STATUS_SUCCESS)
            break;
    }
}

_Use_decl_annotations_
BOOLEAN
RatelimiterAllow(CONST SOCKADDR *Src)
{
    RATELIMITER_ENTRY *Entry;
    HLIST_HEAD *Bucket;
    UINT64 Ip;
    KIRQL Irql;

    if (Src->sa_family == AF_INET)
    {
        Ip = (UINT64)((SOCKADDR_IN *)Src)->sin_addr.s_addr;
        Bucket = &TableV4[Hsiphash1u32((UINT32)Ip, &Key) & (TABLE_SIZE - 1)];
    }
    else if (Src->sa_family == AF_INET6)
    {
        /* Only use 64 bits, so as to ratelimit the whole /64. */
        RtlCopyMemory(&Ip, &((SOCKADDR_IN6 *)Src)->sin6_addr, sizeof(Ip));
        Bucket = &TableV6[Hsiphash2u32((UINT32)(Ip >> 32), (UINT32)Ip, &Key) & (TABLE_SIZE - 1)];
    }
    else
        return FALSE;
    Irql = RcuReadLock();
    HLIST_FOR_EACH_ENTRY_RCU (Entry, Bucket, RATELIMITER_ENTRY, Hash)
    {
        if (Entry->Ip == Ip)
        {
            UINT64 Now, Tokens;
            BOOLEAN Ret;
            /* Quasi-inspired by nft_limit.c, but this is actually a
             * slightly different algorithm. Namely, we incorporate
             * the burst as part of the maximum tokens, rather than
             * as part of the rate.
             */
            KeAcquireSpinLockAtDpcLevel(&Entry->Lock);
            Now = KeQueryInterruptTime();
            Tokens = min(TOKEN_MAX, Entry->Tokens + Now - Entry->LastTime);
            Entry->LastTime = Now;
            Ret = Tokens >= PACKET_COST;
            Entry->Tokens = Ret ? Tokens - PACKET_COST : Tokens;
            KeReleaseSpinLockFromDpcLevel(&Entry->Lock);
            RcuReadUnlock(Irql);
            return Ret;
        }
    }
    RcuReadUnlock(Irql);

    if ((ULONG)InterlockedIncrement(&TotalEntries) > MAX_ENTRIES)
        goto cleanupOom;

    Entry = ExAllocateFromLookasideListEx(&EntryCache);
    if (!Entry)
        goto cleanupOom;

    Entry->Ip = Ip;
    HlistInit(&Entry->Hash);
    KeInitializeSpinLock(&Entry->Lock);
    Entry->LastTime = KeQueryInterruptTime();
    Entry->Tokens = TOKEN_MAX - PACKET_COST;
    KeAcquireSpinLock(&TableLock, &Irql);
    HlistAddHeadRcu(&Entry->Hash, Bucket);
    KeReleaseSpinLock(&TableLock, Irql);
    return TRUE;

cleanupOom:
    InterlockedDecrement(&TotalEntries);
    return FALSE;
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, RatelimiterDriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
RatelimiterDriverEntry(VOID)
{
    NTSTATUS Status =
        ExInitializeLookasideListEx(&EntryCache, NULL, NULL, NonPagedPool, 0, sizeof(RATELIMITER_ENTRY), MEMORY_TAG, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    KeInitializeSpinLock(&TableLock);
    KeInitializeEvent(&RatelimiterGcEntriesThread.Terminate, NotificationEvent, FALSE);
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE Handle;
    Status = PsCreateSystemThread(
        &Handle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, RatelimiterGcEntries, (PVOID)TRUE);
    if (!NT_SUCCESS(Status))
        goto cleanupEntryCache;
    ObReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, &RatelimiterGcEntriesThread.Thread, NULL);
    ZwClose(Handle);
    CryptoRandom(&Key, sizeof(Key));
    return STATUS_SUCCESS;
cleanupEntryCache:
    ExDeleteLookasideListEx(&EntryCache);
    return Status;
}

_Use_decl_annotations_
VOID RatelimiterUnload(VOID)
{
#pragma warning(suppress : 28160) /* Acknowledge caution about Wait parameter. */
    KeSetEvent(&RatelimiterGcEntriesThread.Terminate, IO_NO_INCREMENT, TRUE);
    KeWaitForSingleObject(RatelimiterGcEntriesThread.Thread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(RatelimiterGcEntriesThread.Thread);
    RatelimiterGcEntries(NULL);
    RcuBarrier();
    ExDeleteLookasideListEx(&EntryCache);
}

#ifdef DBG
#    include "selftest/ratelimiter.c"
#endif
