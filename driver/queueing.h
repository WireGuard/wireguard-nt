/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "peer.h"

#define MAX_QUEUED_INCOMING_HANDSHAKES 4096
#define MAX_STAGED_PACKETS 128
#define MAX_QUEUED_PACKETS 1024
#define PEER_XMIT_PACKETS_PER_ROUND 256

typedef struct _WG_DEVICE WG_DEVICE;
typedef struct _WG_PEER WG_PEER;
typedef struct _PREV_QUEUE PREV_QUEUE;

/* queueing.c APIs: */

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MulticoreWorkQueueInit(_Out_ MULTICORE_WORKQUEUE *WorkQueue, _In_ PMULTICORE_WORKQUEUE_ROUTINE Func);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MulticoreWorkQueueBump(_Inout_ MULTICORE_WORKQUEUE *WorkQueue);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MulticoreWorkQueueDestroy(_Inout_ MULTICORE_WORKQUEUE *WorkQueue);

#define BUSY_LINK ((PEER_SERIAL_ENTRY *)~(ULONG_PTR)0)

static inline VOID
PeerSerialInit(_Out_ PEER_SERIAL *Serial)
{
    Serial->Last = &Serial->First;
    Serial->First = BUSY_LINK;
    KeInitializeSpinLock(&Serial->Lock);
}

_Requires_lock_not_held_(Serial->Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static inline BOOLEAN
PeerSerialEnqueueIfNotBusy(_Inout_ PEER_SERIAL *Serial, _Inout_ PEER_SERIAL_ENTRY *Item, _In_ BOOLEAN MaybeRequeue)
{
    BOOLEAN Added = FALSE;
    KIRQL Irql;
    KeAcquireSpinLock(&Serial->Lock, &Irql);
    if (ReadPointerNoFence(&Item->Next))
    {
        if (MaybeRequeue)
            WriteNoFence16(&Item->Requeue, TRUE);
        goto out;
    }
    WritePointerNoFence(&Item->Next, BUSY_LINK);
    *Serial->Last = Item;
    Serial->Last = &Item->Next;
    Added = TRUE;
out:
    KeReleaseSpinLock(&Serial->Lock, Irql);
    return Added;
}

_Requires_lock_not_held_(Serial->Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static inline BOOLEAN
PeerSerialMaybeRetire(_Inout_ PEER_SERIAL *Serial, _Inout_ PEER_SERIAL_ENTRY *Item, _In_ BOOLEAN ForceMore)
{
    BOOLEAN Ret = FALSE;
    KIRQL Irql;
    KeAcquireSpinLock(&Serial->Lock, &Irql);
    WritePointerNoFence(&Item->Next, NULL);
    if (InterlockedCompareExchange16(&Item->Requeue, FALSE, TRUE) || ForceMore)
    {
        WritePointerNoFence(&Item->Next, BUSY_LINK);
        *Serial->Last = Item;
        Serial->Last = &Item->Next;
        Ret = TRUE;
    }
    KeReleaseSpinLock(&Serial->Lock, Irql);
    return Ret;
}

_Requires_lock_not_held_(Serial->Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Post_maybenull_
static inline PEER_SERIAL_ENTRY *
PeerSerialDequeue(_Inout_ PEER_SERIAL *Serial)
{
    if (ReadPointerNoFence(&Serial->First) == BUSY_LINK)
        return NULL;
    PEER_SERIAL_ENTRY *First = NULL;
    KIRQL Irql;
    KeAcquireSpinLock(&Serial->Lock, &Irql);
    First = Serial->First;
    if (First != BUSY_LINK && (Serial->First = First->Next) == BUSY_LINK)
        Serial->Last = &Serial->First;
    KeReleaseSpinLock(&Serial->Lock, Irql);
    return First == BUSY_LINK ? NULL : First;
}

#undef BUSY_LINK

/*
 * NBL[0] = crypt state
 * NBL[1] = prev queue link
 * NB[0-1] = nonce
 * NB[2] = keypair
 * NB[3] = wsk datagram indication (rx only)
 */
#define NET_BUFFER_NONCE(Nb) (*(UINT64 *)&NET_BUFFER_MINIPORT_RESERVED(Nb)[0])
#define NET_BUFFER_LIST_KEYPAIR(Nbl) \
    (*(NOISE_KEYPAIR **)&NET_BUFFER_MINIPORT_RESERVED(NET_BUFFER_LIST_FIRST_NB(Nbl))[2])
#define NET_BUFFER_LIST_PEER(Nbl) (NET_BUFFER_LIST_KEYPAIR(Nbl)->Entry.Peer)
#define NET_BUFFER_LIST_CRYPT_STATE(Nbl) ((LONG *)&NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[0])
#define NET_BUFFER_LIST_PER_PEER_LIST_LINK(Nbl) (*(NET_BUFFER_LIST **)&NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[1])
#define NET_BUFFER_LIST_PROTOCOL(Nbl) ((UINT16_BE)(ULONG_PTR)NET_BUFFER_LIST_INFO(Nbl, NetBufferListProtocolId))
#define NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl) (*(WSK_DATAGRAM_INDICATION **)&NET_BUFFER_MINIPORT_RESERVED(NET_BUFFER_LIST_FIRST_NB(Nbl))[3])

/* receive.c APIs: */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PacketReceive(_Inout_ WG_DEVICE *Wg, _In_ __drv_aliasesMem NET_BUFFER_LIST *First);

MINIPORT_RETURN_NET_BUFFER_LISTS ReturnNetBufferLists;

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
FreeReceiveNetBufferList(_In_ NET_BUFFER_LIST *First)
{
    if (First)
        ReturnNetBufferLists(First->SourceHandle, First, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FreeIncomingHandshakes(_Inout_ WG_DEVICE *Wg);

/* send.c APIs: */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PacketSendQueuedHandshakeInitiation(_Inout_ WG_PEER *Peer, _In_ BOOLEAN IsRetry);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Peer->Handshake.StaticIdentity->Lock)
_Requires_lock_not_held_(Peer->Handshake.Lock)
VOID
PacketSendHandshakeResponse(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
VOID
PacketSendHandshakeCookie(_Inout_ WG_DEVICE *Wg, _In_ CONST NET_BUFFER_LIST *InitiatingNbl, _In_ UINT32_LE SenderIndex);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
PacketSendKeepalive(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Peer->StagedPacketQueue.Lock)
VOID
PacketPurgeStagedPackets(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Peer->StagedPacketQueue.Lock)
VOID
PacketSendStagedPackets(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FreeSendNetBufferList(_In_ WG_DEVICE *Wg, __drv_freesMem(Mem) _In_ NET_BUFFER_LIST *Nbl, _In_ ULONG SendCompleteFlags);

MULTICORE_WORKQUEUE_ROUTINE PacketEncryptWorker, PacketDecryptWorker;
MULTICORE_WORKQUEUE_ROUTINE PacketHandshakeTxWorker, PacketHandshakeRxWorker;

typedef enum _PACKET_STATE
{
    PACKET_STATE_UNCRYPTED,
    PACKET_STATE_CRYPTED,
    PACKET_STATE_DEAD
} PACKET_STATE;

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline UINT16_BE
IpTunnelParseProtocol(_In_ CONST NET_BUFFER_LIST *Nbl)
{
    NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    NT_ASSERT(Nb);
    UCHAR *FirstByteOfHeader = NdisGetDataBuffer(Nb, sizeof(*FirstByteOfHeader), NULL, 1, 0);
    if (!FirstByteOfHeader)
        return 0;
    if (NET_BUFFER_DATA_LENGTH(Nb) >= sizeof(IPV4HDR) && (*FirstByteOfHeader >> 4) == 4)
        return Htons(NDIS_ETH_TYPE_IPV4);
    if (NET_BUFFER_DATA_LENGTH(Nb) >= sizeof(IPV6HDR) && (*FirstByteOfHeader >> 4) == 6)
        return Htons(NDIS_ETH_TYPE_IPV6);
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline BOOLEAN
CheckPacketProtocol(_In_ CONST NET_BUFFER_LIST *Nbl)
{
    UINT16_BE RealProtocol = IpTunnelParseProtocol(Nbl);
    return RealProtocol && NET_BUFFER_LIST_PROTOCOL(Nbl) == RealProtocol;
}

VOID
PrevQueueInit(_Out_ PREV_QUEUE *Queue);

/* Multi producer */
_Return_type_success_(return != FALSE)
BOOLEAN
PrevQueueEnqueue(_Inout_ PREV_QUEUE *Queue, _In_ __drv_aliasesMem NET_BUFFER_LIST *Nbl);

/* Single consumer */
_Must_inspect_result_
_Post_maybenull_
NET_BUFFER_LIST *
PrevQueueDequeue(_Inout_ PREV_QUEUE *Queue);

/* Single consumer */
_Must_inspect_result_
_Post_maybenull_
static inline NET_BUFFER_LIST *
PrevQueuePeek(_Inout_ PREV_QUEUE *Queue)
{
    if (Queue->Peeked)
        return Queue->Peeked;
    Queue->Peeked = PrevQueueDequeue(Queue);
    return Queue->Peeked;
}

/* Single consumer */
static inline VOID
PrevQueueDropPeeked(_Out_ PREV_QUEUE *Queue)
{
    Queue->Peeked = NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline BOOLEAN
QueueEnqueuePerDevice(
    _Inout_ PTR_RING *DeviceQueue,
    _Inout_ MULTICORE_WORKQUEUE *DeviceThreads,
    _Inout_ NET_BUFFER_LIST *Nbl)
{
    if (!NT_SUCCESS(PtrRingProduce(DeviceQueue, Nbl)))
        return FALSE;
    MulticoreWorkQueueBump(DeviceThreads);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline BOOLEAN
QueueInsertPerPeer(_Inout_ PREV_QUEUE *PeerQueue, _Inout_ NET_BUFFER_LIST *Nbl)
{
    WriteRelease(NET_BUFFER_LIST_CRYPT_STATE(Nbl), PACKET_STATE_UNCRYPTED);
    /* We first queue this up for the peer ingestion, but the consumer
     * will wait for the state to change to CRYPTED or DEAD before.
     */
    return PrevQueueEnqueue(PeerQueue, Nbl);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline NTSTATUS
QueueEnqueuePerDeviceAndPeer(
    _Inout_ PTR_RING *DeviceQueue,
    _Inout_ PREV_QUEUE *PeerQueue,
    _Inout_ MULTICORE_WORKQUEUE *DeviceThreads,
    _Inout_ NET_BUFFER_LIST *Nbl)
{
    if (!QueueInsertPerPeer(PeerQueue, Nbl))
        return STATUS_BUFFER_TOO_SMALL;

    /* Then we queue it up in the device queue, which consumes the
     * packet as soon as it can.
     */
    if (!QueueEnqueuePerDevice(DeviceQueue, DeviceThreads, Nbl))
        return STATUS_PIPE_BROKEN;
    return STATUS_SUCCESS;
}

_Requires_lock_not_held_(PeerQueue->Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
QueueEnqueuePerPeer(
    _Inout_ PEER_SERIAL *PeerQueue,
    _Inout_ PEER_SERIAL_ENTRY *PeerSerialEntry,
    _Inout_ __drv_aliasesMem NET_BUFFER_LIST *Nbl,
    _In_ PACKET_STATE State)
{
    /* We take a reference, because as soon as we call WriteRelease, the
     * peer can be freed from below us.
     */
    WG_PEER *Peer = PeerGet(NET_BUFFER_LIST_PEER(Nbl));
    WriteRelease(NET_BUFFER_LIST_CRYPT_STATE(Nbl), State);
    PeerSerialEnqueueIfNotBusy(PeerQueue, PeerSerialEntry, TRUE);
    PeerPut(Peer);
}

#ifdef DBG
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
PacketCounterSelftest(VOID);
#endif
