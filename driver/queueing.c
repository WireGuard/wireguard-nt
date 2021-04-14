/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "queueing.h"

static KSTART_ROUTINE WorkerThread;
_Use_decl_annotations_
static VOID
WorkerThread(PVOID StartContext)
{
    MULTICORE_WORKTHREAD *WorkThread = StartContext;
    MULTICORE_WORKQUEUE *WorkQueue = WorkThread->WorkQueue;
    PMULTICORE_WORKQUEUE_ROUTINE Func = WorkQueue->Func;
    GROUP_AFFINITY Affinity = { .Mask = (KAFFINITY)1 << WorkThread->Processor.Number,
                                .Group = WorkThread->Processor.Group };
    KeSetSystemGroupAffinityThread(&Affinity, NULL);
    PVOID Handles[] = { &WorkQueue->NewWork, &WorkQueue->Dead };
    for (;;)
    {
        if (KeWaitForMultipleObjects(ARRAYSIZE(Handles), Handles, WaitAny, Executive, KernelMode, FALSE, NULL, NULL) !=
            STATUS_WAIT_0)
            break;
        Func(WorkQueue);
    }
}

static KSTART_ROUTINE NewThreadSpawner;
_Use_decl_annotations_
static VOID
NewThreadSpawner(PVOID StartContext)
{
    MULTICORE_WORKQUEUE *WorkQueue = StartContext;
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    PVOID Handles[] = { &WorkQueue->NewCpus, &WorkQueue->Dead };
    for (;;)
    {
        if (KeWaitForMultipleObjects(ARRAYSIZE(Handles), Handles, WaitAny, Executive, KernelMode, FALSE, NULL, NULL) !=
            STATUS_WAIT_0)
            break;
        for (MULTICORE_WORKTHREAD *Thread = ReadPointerAcquire(&WorkQueue->FirstThread); Thread && !Thread->Thread;
             Thread = Thread->NextThread)
        {
            HANDLE Handle;
            if (!NT_SUCCESS(PsCreateSystemThread(
                    &Handle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, WorkerThread, Thread)))
                break;
            ObReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, &Thread->Thread, NULL);
            ZwClose(Handle);
        }
    }
}

static PROCESSOR_CALLBACK_FUNCTION NewCpuArrival;
_Use_decl_annotations_
static VOID
NewCpuArrival(PVOID CallbackContext, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT ChangeContext, PNTSTATUS OperationStatus)
{
    if (ChangeContext->State != KeProcessorAddCompleteNotify)
        return;
    MULTICORE_WORKQUEUE *WorkQueue = CallbackContext;
    MULTICORE_WORKTHREAD *WorkThread = MemAllocateAndZero(sizeof(*WorkThread));
    if (!WorkThread)
        return;
    WorkThread->Processor = ChangeContext->ProcNumber;
    WorkThread->NextThread = WorkQueue->FirstThread;
    WorkThread->WorkQueue = WorkQueue;
    WritePointerRelease(&WorkQueue->FirstThread, WorkThread);
    KeSetEvent(&WorkQueue->NewCpus, IO_NETWORK_INCREMENT, FALSE);
}

_Use_decl_annotations_
NTSTATUS
MulticoreWorkQueueInit(MULTICORE_WORKQUEUE *WorkQueue, PMULTICORE_WORKQUEUE_ROUTINE Func)
{
    KeInitializeEvent(&WorkQueue->NewWork, SynchronizationEvent, FALSE);
    KeInitializeEvent(&WorkQueue->NewCpus, SynchronizationEvent, FALSE);
    KeInitializeEvent(&WorkQueue->Dead, NotificationEvent, FALSE);
    WorkQueue->FirstThread = NULL;
    WorkQueue->Func = Func;
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE Handle;
    NTSTATUS Status =
        PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, NewThreadSpawner, WorkQueue);
    if (!NT_SUCCESS(Status))
        return Status;
    ObReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, &WorkQueue->WorkerSpawnerThread, NULL);
    ZwClose(Handle);
    WorkQueue->NewCpuNotifier =
        KeRegisterProcessorChangeCallback(NewCpuArrival, WorkQueue, KE_PROCESSOR_CHANGE_ADD_EXISTING);
    Status = WorkQueue->NewCpuNotifier ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    if (!NT_SUCCESS(Status))
        MulticoreWorkQueueDestroy(WorkQueue);
    return Status;
}

_Use_decl_annotations_
BOOLEAN
MulticoreWorkQueueBump(MULTICORE_WORKQUEUE *WorkQueue)
{
    return KeSetEvent(&WorkQueue->NewWork, IO_NETWORK_INCREMENT, FALSE) == 0;
}

_Use_decl_annotations_
VOID
MulticoreWorkQueueDestroy(MULTICORE_WORKQUEUE *WorkQueue)
{
    if (WorkQueue->NewCpuNotifier)
        KeDeregisterProcessorChangeCallback(WorkQueue->NewCpuNotifier);
    KeSetEvent(&WorkQueue->Dead, IO_NETWORK_INCREMENT, FALSE);
    KeWaitForSingleObject(WorkQueue->WorkerSpawnerThread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(WorkQueue->WorkerSpawnerThread);

    ULONG ThreadCount = 0;
    for (MULTICORE_WORKTHREAD *Thread = WorkQueue->FirstThread; Thread; Thread = Thread->NextThread)
    {
        if (Thread->Thread)
            ++ThreadCount;
    }
    if (!ThreadCount)
        return;
    PKTHREAD *Threads = MemAllocateArray(ThreadCount, sizeof(*Threads) + sizeof(KWAIT_BLOCK));
    if (Threads)
    {
        PKWAIT_BLOCK WaitBlock = (PKWAIT_BLOCK)((ULONG_PTR)Threads + (ThreadCount * sizeof(*Threads)));
        ThreadCount = 0;
        for (MULTICORE_WORKTHREAD *Thread = WorkQueue->FirstThread; Thread; Thread = Thread->NextThread)
        {
            if (Thread->Thread)
                Threads[ThreadCount++] = Thread->Thread;
        }
        KeWaitForMultipleObjects(ThreadCount, Threads, WaitAll, Executive, KernelMode, FALSE, NULL, WaitBlock);
        for (MULTICORE_WORKTHREAD *Thread = WorkQueue->FirstThread, *Next; Thread; Thread = Next)
        {
            Next = Thread->NextThread;
            if (Thread->Thread)
                ObDereferenceObject(Thread->Thread);
            MemFree(Thread);
        }
        MemFree(Threads);
    }
    else
    {
        for (MULTICORE_WORKTHREAD *Thread = WorkQueue->FirstThread, *Next; Thread; Thread = Next)
        {
            Next = Thread->NextThread;
            if (Thread->Thread)
            {
                KeWaitForSingleObject(Thread->Thread, Executive, KernelMode, FALSE, NULL);
                ObDereferenceObject(Thread->Thread);
            }
            MemFree(Thread);
        }
    }
}

#define NEXT(Nbl) NET_BUFFER_LIST_PER_PEER_LIST_LINK(Nbl)
#define STUB(Queue) (&(Queue)->Empty)

_Use_decl_annotations_
VOID
PrevQueueInit(PREV_QUEUE *Queue)
{
    NEXT(STUB(Queue)) = NULL;
    Queue->Head = Queue->Tail = STUB(Queue);
    Queue->Peeked = NULL;
    WriteRaw(&Queue->Count, 0);
}

static VOID
__PrevQueueEnqueue(_Inout_ PREV_QUEUE *Queue, _In_ __drv_aliasesMem NET_BUFFER_LIST *Nbl)
{
    WritePointerNoFence(&NEXT(Nbl), NULL);
    WritePointerNoFence(&NEXT((NET_BUFFER_LIST *)InterlockedExchangePointerRelease(&Queue->Head, Nbl)), Nbl);
}

_Use_decl_annotations_
BOOLEAN
PrevQueueEnqueue(PREV_QUEUE *Queue, NET_BUFFER_LIST *Nbl)
{
    if (!InterlockedIncrementUnless(&Queue->Count, MAX_QUEUED_PACKETS))
        return FALSE;
    __PrevQueueEnqueue(Queue, Nbl);
    return TRUE;
}

_Use_decl_annotations_
NET_BUFFER_LIST *
PrevQueueDequeue(PREV_QUEUE *Queue)
{
    NET_BUFFER_LIST *Tail = Queue->Tail, *Next = ReadPointerAcquire(&NEXT(Tail));

    if (Tail == STUB(Queue))
    {
        if (!Next)
            return NULL;
        Queue->Tail = Next;
        Tail = Next;
        Next = ReadPointerAcquire(&NEXT(Next));
    }
    if (Next)
    {
        Queue->Tail = Next;
        InterlockedDecrement(&Queue->Count);
        return Tail;
    }
    if (Tail != ReadPointerNoFence(&Queue->Head))
        return NULL;
    __PrevQueueEnqueue(Queue, STUB(Queue));
    Next = ReadPointerAcquire(&NEXT(Tail));
    if (Next)
    {
        Queue->Tail = Next;
        InterlockedDecrement(&Queue->Count);
        return Tail;
    }
    return NULL;
}

#undef NEXT
#undef STUB
