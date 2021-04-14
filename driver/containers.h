/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "interlocked.h"
#include "memory.h"
#include "rcu.h"
#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include <ndis.h>

#define LIST_FOR_EACH_ENTRY(Pos, Head, Type, Member) \
    for (Pos = CONTAINING_RECORD((Head)->Flink, Type, Member); &Pos->Member != (Head); \
         Pos = CONTAINING_RECORD((Pos)->Member.Flink, Type, Member))
#define LIST_FOR_EACH_ENTRY_SAFE(Pos, Tmp, Head, Type, Member) \
    for (Pos = CONTAINING_RECORD((Head)->Flink, Type, Member), \
        Tmp = CONTAINING_RECORD((Pos)->Member.Flink, Type, Member); \
         &Pos->Member != (Head); \
         Pos = Tmp, Tmp = CONTAINING_RECORD((Tmp)->Member.Flink, Type, Member))

typedef struct _HLIST_NODE HLIST_NODE;
struct _HLIST_NODE
{
    HLIST_NODE *Next, **Pprev;
};
typedef struct _HLIST_HEAD
{
    HLIST_NODE *First;
} HLIST_HEAD;

static inline VOID
HlistHeadInit(_Out_ HLIST_HEAD *H)
{
    H->First = NULL;
}

static inline VOID
HlistInit(_Out_ HLIST_NODE *H)
{
    H->Next = NULL;
    H->Pprev = NULL;
}

_Must_inspect_result_
static inline BOOLEAN
HlistUnhashed(_In_ CONST HLIST_NODE *Head)
{
    return !Head->Pprev;
}

static inline VOID
__HlistDel(_Inout_ HLIST_NODE *Node)
{
    HLIST_NODE *Next = Node->Next;
    HLIST_NODE **Pprev = Node->Pprev;

    WritePointerNoFence(Pprev, Next);
    if (Next)
        WritePointerNoFence(&Next->Pprev, Pprev);
}

static inline VOID
HlistDelInitRcu(_Inout_ HLIST_NODE *Node)
{
    if (!HlistUnhashed(Node))
    {
        __HlistDel(Node);
        WritePointerNoFence(&Node->Pprev, NULL);
    }
}

static inline VOID
HlistDelRcu(_Inout_ HLIST_NODE *Node)
{
    __HlistDel(Node);
    WritePointerNoFence(&Node->Pprev, NULL);
}

static inline VOID
HlistReplaceRcu(_Inout_ HLIST_NODE *Old, _Out_ HLIST_NODE *New)
{
    HLIST_NODE *Next = Old->Next;

    New->Next = Next;
    WritePointerNoFence(&New->Pprev, Old->Pprev);
    RcuAssignPointer(*(HLIST_NODE __rcu **)New->Pprev, New);
    if (Next)
        WritePointerNoFence(&New->Next->Pprev, &New->Next);
    WritePointerNoFence(&Old->Pprev, NULL);
}

#define HlistFirstRcu(Head) (*((HLIST_NODE __rcu **)(&(Head)->First)))
#define HlistNextRcu(Node) (*((HLIST_NODE __rcu **)(&(Node)->Next)))

static inline VOID
HlistAddHeadRcu(_Inout_ __drv_aliasesMem HLIST_NODE *Node, _Inout_ HLIST_HEAD *Head)
{
    HLIST_NODE *First = Head->First;

    Node->Next = First;
    WritePointerNoFence(&Node->Pprev, &Head->First);
    RcuAssignPointer(HlistFirstRcu(Head), Node);
    if (First)
        WritePointerNoFence(&First->Pprev, &Node->Next);
}

#define HlistEntry(Ptr, Type, Member) CONTAINING_RECORD(Ptr, Type, Member)
#define HlistEntrySafe(Ptr, Type, Member) ((Ptr) ? HlistEntry(Ptr, Type, Member) : NULL)
#define HLIST_FOR_EACH_ENTRY_SAFE(Pos, Tmp, Head, Type, Member) \
    for (Pos = HlistEntrySafe((Head)->First, Type, Member); Pos && (Tmp = Pos->Member.Next, 1); \
         Pos = HlistEntrySafe(Tmp, Type, Member))

#define HLIST_FOR_EACH_ENTRY_RCU(Pos, Head, Type, Member) \
    for (Pos = HlistEntrySafe(RcuDereference(Type, HlistFirstRcu(Head)), Type, Member); Pos; \
         Pos = HlistEntrySafe(RcuDereference(Type, HlistNextRcu(&(Pos)->Member)), Type, Member))

#define DECLARE_HASHTABLE(Name, Bits) HLIST_HEAD Name[1 << (Bits)]
#define HASH_SIZE(Name) (ARRAYSIZE(Name))

static inline VOID
__HashInit(_Out_writes_bytes_all_(Sz) HLIST_HEAD *Ht, _In_ SIZE_T Sz)
{
    for (SIZE_T i = 0; i < Sz; ++i)
        HlistHeadInit(&Ht[i]);
}

#define HashInit(Hashtable) __HashInit(Hashtable, HASH_SIZE(Hashtable))

typedef struct _PTR_RING
{
    DECLSPEC_CACHEALIGN LONG Producer;
    KSPIN_LOCK ProducerLock;
    DECLSPEC_CACHEALIGN LONG ConsumerHead;
    LONG ConsumerTail;
    KSPIN_LOCK ConsumerLock;
    DECLSPEC_CACHEALIGN LONG Size;
    LONG Batch;
    VOID **Queue;
} PTR_RING;

_Requires_lock_held_(Ring->ProducerLock)
_Must_inspect_result_
static inline NTSTATUS
__PtrRingProduce(_Inout_ PTR_RING *Ring, _In_ __drv_aliasesMem VOID *Ptr)
{
    if (!Ring->Size || Ring->Queue[Ring->Producer])
        return STATUS_BUFFER_TOO_SMALL;

    WriteMemoryBarrier();

    WritePointerNoFence(&Ring->Queue[Ring->Producer++], Ptr);
    if (Ring->Producer >= Ring->Size)
        Ring->Producer = 0;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Ring->ProducerLock)
_Must_inspect_result_
static inline NTSTATUS
PtrRingProduce(_Inout_ PTR_RING *Ring, _In_ __drv_aliasesMem VOID *Ptr)
{
    KIRQL Irql;
    NTSTATUS Ret;

    KeAcquireSpinLock(&Ring->ProducerLock, &Irql);
    Ret = __PtrRingProduce(Ring, Ptr);
    KeReleaseSpinLock(&Ring->ProducerLock, Irql);

    return Ret;
}

_Requires_lock_held_(Ring->ConsumerLock)
_Must_inspect_result_
_Post_maybenull_
static inline VOID *
__PtrRingPeek(_In_ CONST PTR_RING *Ring)
{
    if (Ring->Size)
        return ReadPointerNoFence(&Ring->Queue[Ring->ConsumerHead]);
    return NULL;
}

_Requires_lock_held_(Ring->ConsumerLock)
static inline VOID
__PtrRingDiscardOne(_Inout_ PTR_RING *Ring)
{
    LONG ConsumerHead = Ring->ConsumerHead;
    LONG Head = ConsumerHead++;

    if (ConsumerHead - Ring->ConsumerTail >= Ring->Batch || ConsumerHead >= Ring->Size)
    {
        while (Head >= Ring->ConsumerTail)
            Ring->Queue[Head--] = NULL;
        Ring->ConsumerTail = ConsumerHead;
    }
    if (ConsumerHead >= Ring->Size)
    {
        ConsumerHead = 0;
        Ring->ConsumerTail = 0;
    }
    WriteNoFence(&Ring->ConsumerHead, ConsumerHead);
}

_Requires_lock_held_(Ring->ConsumerLock)
_Must_inspect_result_
_Post_maybenull_
static inline VOID *
__PtrRingConsume(_Inout_ PTR_RING *Ring)
{
    VOID *Ptr;

    Ptr = __PtrRingPeek(Ring);
    if (Ptr)
        __PtrRingDiscardOne(Ring);

    return Ptr;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Ring->ConsumerLock)
_Must_inspect_result_
_Post_maybenull_
static inline VOID *
PtrRingConsume(_Inout_ PTR_RING *Ring)
{
    KIRQL Irql;
    VOID *Ptr;

    KeAcquireSpinLock(&Ring->ConsumerLock, &Irql);
    Ptr = __PtrRingConsume(Ring);
    KeReleaseSpinLock(&Ring->ConsumerLock, Irql);

    return Ptr;
}

static inline VOID
__PtrRingSetSize(_Inout_ PTR_RING *Ring, _In_ LONG Size)
{
    Ring->Size = Size;
    Ring->Batch = SYSTEM_CACHE_ALIGNMENT_SIZE * 2 / sizeof(*(Ring->Queue));
    if (Ring->Batch > Ring->Size / 2 || !Ring->Batch)
        Ring->Batch = 1;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static inline NTSTATUS
PtrRingInit(_Inout_ PTR_RING *Ring, _In_ LONG Size)
{
    Ring->Queue = MemAllocateArrayAndZero(Size, sizeof(VOID *));
    if (!Ring->Queue)
        return STATUS_INSUFFICIENT_RESOURCES;

    __PtrRingSetSize(Ring, Size);
    Ring->Producer = Ring->ConsumerHead = Ring->ConsumerTail = 0;
    KeInitializeSpinLock(&Ring->ProducerLock);
    KeInitializeSpinLock(&Ring->ConsumerLock);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(Destroy != 0, _Requires_lock_not_held_(Ring->ConsumerLock))
static inline VOID
PtrRingCleanup(_In_ PTR_RING *Ring, _In_opt_ VOID (*Destroy)(VOID *))
{
    VOID *Ptr;

    if (Destroy)
        while ((Ptr = PtrRingConsume(Ring)) != NULL)
            Destroy(Ptr);
    MemFree(Ring->Queue);
}

typedef struct _NET_BUFFER_LIST_QUEUE
{
    PNET_BUFFER_LIST Head, Tail;
    ULONG Length;
    KSPIN_LOCK Lock;
} NET_BUFFER_LIST_QUEUE;

static inline VOID
NetBufferListInitQueue(_Out_ NET_BUFFER_LIST_QUEUE *NblQueue)
{
    NblQueue->Head = NblQueue->Tail = NULL;
    NblQueue->Length = 0;
    KeInitializeSpinLock(&NblQueue->Lock);
}

_Must_inspect_result_
static inline BOOLEAN
NetBufferListIsQueueEmpty(_In_ CONST NET_BUFFER_LIST_QUEUE *NblQueue)
{
    return !NblQueue->Head;
}

static inline ULONG
NetBufferListQueueLength(_In_ CONST NET_BUFFER_LIST_QUEUE *NblQueue)
{
    return NblQueue->Length;
}

_Requires_lock_held_(NblQueue->Lock)
_Requires_lock_held_(Head->Lock)
static inline VOID
NetBufferListSpliceAndReinitQueue(_Inout_ NET_BUFFER_LIST_QUEUE *NblQueue, _Inout_ NET_BUFFER_LIST_QUEUE *Head)
{
    if (!NetBufferListIsQueueEmpty(NblQueue))
    {
        if (!Head->Tail)
            Head->Tail = NblQueue->Tail;
        NET_BUFFER_LIST_NEXT_NBL(NblQueue->Tail) = Head->Head;
        Head->Head = NblQueue->Head;
        Head->Length += NblQueue->Length;
        NblQueue->Head = NblQueue->Tail = NULL;
        NblQueue->Length = 0;
    }
}

_Requires_lock_held_(Head->Lock)
static inline VOID
NetBufferListSpliceTail(_In_ CONST NET_BUFFER_LIST_QUEUE *NblQueue, _Inout_ NET_BUFFER_LIST_QUEUE *Head)
{
    if (!NetBufferListIsQueueEmpty(NblQueue))
    {
        *(Head->Tail ? &NET_BUFFER_LIST_NEXT_NBL(Head->Tail) : &Head->Head) = NblQueue->Head;
        Head->Tail = NblQueue->Tail;
        Head->Length += NblQueue->Length;
    }
}

_Requires_lock_held_(NblQueue->Lock)
static inline VOID
NetBufferListEnqueue(_Inout_ NET_BUFFER_LIST_QUEUE *NblQueue, __drv_aliasesMem _In_ PNET_BUFFER_LIST Nbl)
{
    NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
    *(NblQueue->Tail ? &NET_BUFFER_LIST_NEXT_NBL(NblQueue->Tail) : &NblQueue->Head) = Nbl;
    NblQueue->Tail = Nbl;
    ++NblQueue->Length;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(NblQueue->Lock)
static inline VOID
NetBufferListInterlockedEnqueue(_Inout_ NET_BUFFER_LIST_QUEUE *NblQueue, __drv_aliasesMem _In_ PNET_BUFFER_LIST Nbl)
{
    KIRQL Irql;
    KeAcquireSpinLock(&NblQueue->Lock, &Irql);
    NetBufferListEnqueue(NblQueue, Nbl);
    KeReleaseSpinLock(&NblQueue->Lock, Irql);
}

_Requires_lock_held_(NblQueue->Lock)
_Must_inspect_result_
_Post_maybenull_
static inline PNET_BUFFER_LIST
NetBufferListDequeue(_Inout_ NET_BUFFER_LIST_QUEUE *NblQueue)
{
    PNET_BUFFER_LIST Nbl = NblQueue->Head;
    if (!Nbl)
        return NULL;
    NblQueue->Head = NET_BUFFER_LIST_NEXT_NBL(Nbl);
    NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
    if (!NblQueue->Head)
        NblQueue->Tail = NULL;
    NblQueue->Length--;
    return Nbl;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(NblQueue->Lock)
_Must_inspect_result_
_Post_maybenull_
static inline PNET_BUFFER_LIST
NetBufferListInterlockedDequeue(NET_BUFFER_LIST_QUEUE *NblQueue)
{
    KIRQL Irql;
    KeAcquireSpinLock(&NblQueue->Lock, &Irql);
    PNET_BUFFER_LIST Nbl = NetBufferListDequeue(NblQueue);
    KeReleaseSpinLock(&NblQueue->Lock, Irql);
    return Nbl;
}
