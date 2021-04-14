/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "memory.h"
#include "rcu.h"

static struct
{
    KDPC *PerCpuDpcs;
    EX_PUSH_LOCK Lock;
} SyncState;

static KDEFERRED_ROUTINE ProcessorTick;
_Use_decl_annotations_
static VOID
ProcessorTick(KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    _Analysis_assume_(SystemArgument1 != NULL);
    _Analysis_assume_(SystemArgument2 != NULL);
    KEVENT *Event = SystemArgument1;
    LONG *Refs = SystemArgument2;
    if (!InterlockedDecrement(Refs))
        KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

/* `Refs`, although on stack, is shared between processors, and does require interlocked access. */
#pragma warning(push)
#pragma warning(disable : 28112)
#pragma warning(disable : 28113)

_Use_decl_annotations_
VOID RcuSynchronize(VOID)
{
    MuAcquirePushLockExclusive(&SyncState.Lock);
    KEVENT Event;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    LONG Refs = 1;
    ULONG NumProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG Processor = 0; Processor < NumProcessors; ++Processor)
    {
        PROCESSOR_NUMBER ProcessorNumber;
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(Processor, &ProcessorNumber)))
            continue;
        if (!NT_SUCCESS(KeSetTargetProcessorDpcEx(&SyncState.PerCpuDpcs[Processor], &ProcessorNumber)))
            continue;
        InterlockedIncrement(&Refs);
        if (!KeInsertQueueDpc(&SyncState.PerCpuDpcs[Processor], &Event, &Refs))
            InterlockedDecrement(&Refs);
    }
    if (!InterlockedDecrement(&Refs))
        goto out;
    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
out:
    MuReleasePushLockExclusive(&SyncState.Lock);
}

#pragma warning(pop)

static struct
{
    PKTHREAD Thread;
    KEVENT WorkPending;
    BOOLEAN Terminate;
    RCU_CALLBACK *Head, *Tail;
    KSPIN_LOCK Lock;
} Cleanup;

static KSTART_ROUTINE CallerThread;
_Use_decl_annotations_
static VOID
CallerThread(PVOID StartContext)
{
    for (;;)
    {
        KeWaitForSingleObject(&Cleanup.WorkPending, Executive, KernelMode, FALSE, NULL);
        KLOCK_QUEUE_HANDLE LockHandle;
        KeAcquireInStackQueuedSpinLock(&Cleanup.Lock, &LockHandle);
        RCU_CALLBACK *Head = Cleanup.Head;
        Cleanup.Head = NULL;
        Cleanup.Tail = NULL;
        KeClearEvent(&Cleanup.WorkPending);
        KeReleaseInStackQueuedSpinLock(&LockHandle);
        RcuSynchronize();
        while (Head)
        {
            RCU_CALLBACK *Next = Head->Next;
            switch (Head->Type)
            {
            case RCU_CALLBACK_CALL:
                Head->Func(Head);
                break;
            case RCU_CALLBACK_FREE:
                MemFree((UCHAR *)Head - Head->Offset);
                break;
            case RCU_CALLBACK_SYNC:
                KeSetEvent(&Head->Done, IO_NETWORK_INCREMENT, FALSE);
                break;
            }
            Head = Next;
        }
        if (ReadBooleanNoFence(&Cleanup.Terminate))
            break;
    }
}

_Use_decl_annotations_
VOID
__RcuCall(_Inout_ RCU_CALLBACK *Head)
{
    Head->Next = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;
    KeAcquireInStackQueuedSpinLock(&Cleanup.Lock, &LockHandle);
    *(Cleanup.Tail ? &Cleanup.Tail->Next : &Cleanup.Head) = Head;
    Cleanup.Tail = Head;
    KeSetEvent(&Cleanup.WorkPending, IO_NO_INCREMENT, FALSE);
    KeReleaseInStackQueuedSpinLock(&LockHandle);
}

_Use_decl_annotations_
VOID RcuBarrier(VOID)
{
    RCU_CALLBACK Work;
    Work.Type = RCU_CALLBACK_SYNC;
    KeInitializeEvent(&Work.Done, SynchronizationEvent, FALSE);
    __RcuCall(&Work);
    KeWaitForSingleObject(&Work.Done, Executive, KernelMode, FALSE, NULL);
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, RcuDriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
RcuDriverEntry(VOID)
{
    ULONG NumProcessors = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    SyncState.PerCpuDpcs = MemAllocateArray(NumProcessors, sizeof(*SyncState.PerCpuDpcs));
    if (!SyncState.PerCpuDpcs)
        return STATUS_INSUFFICIENT_RESOURCES;
    MuInitializePushLock(&SyncState.Lock);
    for (ULONG Processor = 0; Processor < NumProcessors; ++Processor)
    {
        KeInitializeDpc(&SyncState.PerCpuDpcs[Processor], ProcessorTick, NULL);
        KeSetImportanceDpc(&SyncState.PerCpuDpcs[Processor], LowImportance);
    }

    KeInitializeEvent(&Cleanup.WorkPending, NotificationEvent, FALSE);
    KeInitializeSpinLock(&Cleanup.Lock);
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE Handle;
    NTSTATUS Status =
        PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, CallerThread, (PVOID)TRUE);
    if (!NT_SUCCESS(Status))
        goto cleanupDpcs;
    ObReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, &Cleanup.Thread, NULL);
    ZwClose(Handle);
    return STATUS_SUCCESS;

cleanupDpcs:
    MemFree(SyncState.PerCpuDpcs);
    return Status;
}

_Use_decl_annotations_
VOID RcuUnload(VOID)
{
    RcuBarrier();
    WriteBooleanNoFence(&Cleanup.Terminate, TRUE);
    KeSetEvent(&Cleanup.WorkPending, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(Cleanup.Thread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(Cleanup.Thread);
    MemFree(SyncState.PerCpuDpcs);
}
