/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "queueing.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "rcu.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"
#include "logging.h"

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Peer->Handshake.StaticIdentity->Lock)
_Requires_lock_not_held_(Peer->Handshake.Lock)
static VOID
PacketSendHandshakeInitiation(_Inout_ WG_PEER *Peer)
{
    MESSAGE_HANDSHAKE_INITIATION Packet;

    if (!BirthdateHasExpired(ReadNoFence64(&Peer->LastSentHandshake), REKEY_TIMEOUT))
        return; /* This function is rate limited. */

    WriteNoFence64(&Peer->LastSentHandshake, KeQueryInterruptTime());
    CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    LogInfoRatelimited(Peer->Device, "Sending handshake initiation to peer %llu (%s)", Peer->InternalId, EndpointName);

    if (NoiseHandshakeCreateInitiation(&Packet, &Peer->Handshake))
    {
        CookieAddMacToPacket(&Packet, sizeof(Packet), Peer);
        TimersAnyAuthenticatedPacketTraversal(Peer);
        TimersAnyAuthenticatedPacketSent(Peer);
        WriteNoFence64(&Peer->LastSentHandshake, KeQueryInterruptTime());
        SocketSendBufferToPeer(Peer, &Packet, sizeof(Packet));
        TimersHandshakeInitiated(Peer);
    }
}

_Use_decl_annotations_
VOID
PacketHandshakeTxWorker(MULTICORE_WORKQUEUE *WorkQueue)
{
    WG_DEVICE *Wg = CONTAINING_RECORD(WorkQueue, WG_DEVICE, HandshakeTxThreads);
    PEER_SERIAL_ENTRY *Entry;

    while ((Entry = PeerSerialDequeue(&Wg->HandshakeTxQueue)) != NULL)
    {
        WG_PEER *Peer = CONTAINING_RECORD(Entry, WG_PEER, HandshakeTxSerialEntry);
        HANDSHAKE_TX_ACTION Action = InterlockedExchange16(&Peer->HandshakeTxAction, HANDSHAKE_TX_NONE);

        if (Action == HANDSHAKE_TX_SEND)
            PacketSendHandshakeInitiation(Peer);
        else if (Action == HANDSHAKE_TX_CLEAR)
        {
            NoiseHandshakeClear(&Peer->Handshake);
            NoiseKeypairsClear(&Peer->Keypairs);
        }

        if (!PeerSerialMaybeRetire(&Wg->HandshakeTxQueue, Entry, FALSE))
        {
            ExReleaseRundownProtection(&Peer->InUse);
            PeerPut(Peer);
        }
    }
}

_Use_decl_annotations_
VOID
PacketSendQueuedHandshakeInitiation(WG_PEER *Peer, BOOLEAN IsRetry)
{
    if (!IsRetry)
        Peer->TimerHandshakeAttempts = 0;

    /* We check LastSentHandshake here in addition to the actual function
     * we're queueing up, so that we don't queue things if not strictly
     * necessary:
     */
    if (!BirthdateHasExpired(ReadNoFence64(&Peer->LastSentHandshake), REKEY_TIMEOUT))
        return;

    if (!ExAcquireRundownProtection(&Peer->InUse))
        return;
    PeerGet(Peer);
    WriteNoFence16(&Peer->HandshakeTxAction, HANDSHAKE_TX_SEND);

    if (PeerSerialEnqueueIfNotBusy(&Peer->Device->HandshakeTxQueue, &Peer->HandshakeTxSerialEntry, TRUE))
        MulticoreWorkQueueBump(&Peer->Device->HandshakeTxThreads);
    else
    {
        /* If the work was already on the queue, we want to drop the extra reference. */
        ExReleaseRundownProtection(&Peer->InUse);
        PeerPut(Peer);
    }
}

_Use_decl_annotations_
VOID
PacketSendHandshakeResponse(WG_PEER *Peer)
{
    MESSAGE_HANDSHAKE_RESPONSE Packet;

    WriteNoFence64(&Peer->LastSentHandshake, KeQueryInterruptTime());
    CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    LogInfoRatelimited(Peer->Device, "Sending handshake response to peer %llu (%s)", Peer->InternalId, EndpointName);

    if (NoiseHandshakeCreateResponse(&Packet, &Peer->Handshake))
    {
        CookieAddMacToPacket(&Packet, sizeof(Packet), Peer);
        if (NoiseHandshakeBeginSession(&Peer->Handshake, &Peer->Keypairs))
        {
            TimersSessionDerived(Peer);
            TimersAnyAuthenticatedPacketTraversal(Peer);
            TimersAnyAuthenticatedPacketSent(Peer);
            WriteNoFence64(&Peer->LastSentHandshake, KeQueryInterruptTime());
            SocketSendBufferToPeer(Peer, &Packet, sizeof(Packet));
        }
    }
}

_Use_decl_annotations_
VOID
PacketSendHandshakeCookie(WG_DEVICE *Wg, CONST NET_BUFFER_LIST *InitiatingNbl, UINT32_LE SenderIndex)
{
    MESSAGE_HANDSHAKE_COOKIE Packet;

    LogInfoNblRatelimited(Wg, "Sending cookie response for denied handshake message for %s", InitiatingNbl);
    CookieMessageCreate(&Packet, InitiatingNbl, SenderIndex, &Wg->CookieChecker);
    SocketSendBufferAsReplyToNbl(Wg, InitiatingNbl, &Packet, sizeof(Packet));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
KeepKeyFresh(_Inout_ WG_PEER *Peer)
{
    KIRQL Irql;
    NOISE_KEYPAIR *Keypair;
    BOOLEAN Send;

    Irql = RcuReadLock();
    Keypair = RcuDereference(NOISE_KEYPAIR, Peer->Keypairs.CurrentKeypair);
    Send = Keypair && ReadBooleanNoFence(&Keypair->Sending.IsValid) &&
           (ReadNoFence64(&Keypair->SendingCounter) > REKEY_AFTER_MESSAGES ||
            (Keypair->IAmTheInitiator && BirthdateHasExpired(Keypair->Sending.Birthdate, REKEY_AFTER_TIME)));
    RcuReadUnlock(Irql);

    if (Send)
        PacketSendQueuedHandshakeInitiation(Peer, FALSE);
}

static ULONG
CalculateNblPadding(_In_ CONST NET_BUFFER *Nb, _In_ UINT32 Mtu)
{
    ULONG PaddedSize, LastUnit = NET_BUFFER_DATA_LENGTH(Nb);

    if (!Mtu)
        return ALIGN_UP_BY_T(ULONG, LastUnit, MESSAGE_PADDING_MULTIPLE) - LastUnit;

    /* We do this modulo business with the MTU, just in case NDIS gives us
     * a NB that's bigger than the MTU. In that case, we wouldn't want the
     * final subtraction to overflow in the case of the PaddedSize being
     * clamped.
     */
    if (LastUnit > Mtu)
        LastUnit %= Mtu;

    PaddedSize = min(Mtu, ALIGN_UP_BY_T(ULONG, LastUnit, MESSAGE_PADDING_MULTIPLE));
    return PaddedSize - LastUnit;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static BOOLEAN
EncryptPacket(
    _In_ CONST SIMD_STATE *Simd,
    _Inout_ NET_BUFFER *NbOut,
    _Inout_ NET_BUFFER *NbIn,
    _In_ CONST NOISE_KEYPAIR *Keypair,
    _In_ UINT32 Mtu)
{
    ULONG PaddingLen = CalculateNblPadding(NbIn, Mtu);
    UCHAR *OutBuffer = MemGetValidatedNetBufferData(NbOut);
    *(MESSAGE_DATA *)OutBuffer = (MESSAGE_DATA){ .Header.Type = CpuToLe32(MESSAGE_TYPE_DATA),
                                                 .KeyIdx = Keypair->RemoteIndex,
                                                 .Counter = CpuToLe64(NET_BUFFER_NONCE(NbOut)) };
    OutBuffer += sizeof(MESSAGE_DATA);

    MDL *LastMdl = NULL, *OriginalNextMdl = NULL, PaddingMdl = { 0 };
    ULONG OriginalMdlLen = 0;
    if (PaddingLen)
    {
        ULONG MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NbIn), Remaining = NET_BUFFER_DATA_LENGTH(NbIn), NeededLen = 0;
        for (LastMdl = NET_BUFFER_CURRENT_MDL(NbIn);; LastMdl = LastMdl->Next)
        {
            NeededLen = Remaining + MdlOffset;
            Remaining -= min(MmGetMdlByteCount(LastMdl) - MdlOffset, Remaining);
            if (!Remaining)
                break;
            MdlOffset = 0;
            if (!LastMdl->Next)
                return FALSE;
        }
        OriginalMdlLen = MmGetMdlByteCount(LastMdl);
        OriginalNextMdl = LastMdl->Next;
        /* This MDL is completely bogus, but hopefully is sufficient for just returning MappedSystemVa. */
        static CONST UCHAR Padding[MESSAGE_PADDING_MULTIPLE - 1] = { 0 };
        PaddingMdl.MappedSystemVa = (PVOID)Padding;
        PaddingMdl.ByteCount = PaddingLen;
#pragma warning(suppress : 28145) /*  We're modifying MdlFlags manually, but that's the whole point of this hack */
        PaddingMdl.MdlFlags = MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL;
        LastMdl->Next = &PaddingMdl;
        LastMdl->ByteCount = NeededLen;
        NET_BUFFER_DATA_LENGTH(NbIn) += PaddingLen;
    }
    BOOLEAN Ret = ChaCha20Poly1305EncryptMdl(
        OutBuffer,
        NET_BUFFER_CURRENT_MDL(NbIn),
        NET_BUFFER_DATA_LENGTH(NbIn),
        NET_BUFFER_CURRENT_MDL_OFFSET(NbIn),
        NULL,
        0,
        NET_BUFFER_NONCE(NbOut),
        Keypair->Sending.Key,
        Simd);
    NET_BUFFER_DATA_LENGTH(NbOut) = MessageDataLen(NET_BUFFER_DATA_LENGTH(NbIn));
    NET_BUFFER_DATA_OFFSET(NbOut) = NET_BUFFER_CURRENT_MDL_OFFSET(NbOut) = 0;
    if (PaddingLen)
    {
        if (NbIn != NbOut)
            NET_BUFFER_DATA_LENGTH(NbIn) -= PaddingLen;
        LastMdl->Next = OriginalNextMdl;
        LastMdl->ByteCount = OriginalMdlLen;
    }
    return Ret;
}

_Use_decl_annotations_
VOID
PacketSendKeepalive(WG_PEER *Peer)
{
    NET_BUFFER_LIST *Nbl;

    if (NetBufferListIsQueueEmpty(&Peer->StagedPacketQueue))
    {
        Nbl = MemAllocateNetBufferList(
            Peer->Device->NblPool, Peer->Device->NbPool, 0, 0, sizeof(MESSAGE_DATA) + NoiseEncryptedLen(0));
        if (!Nbl)
            return;
        Nbl->ParentNetBufferList = Nbl;
        NetBufferListInterlockedEnqueue(&Peer->StagedPacketQueue, Nbl);
        CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
        SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
        LogInfoRatelimited(Peer->Device, "Sending keepalive packet to peer %llu (%s)", Peer->InternalId, EndpointName);
    }

    PacketSendStagedPackets(Peer);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PacketCreateDataDone(_Inout_ WG_PEER *Peer, _Inout_ NET_BUFFER_LIST *First)
{
    BOOLEAN IsKeepalive;

    TimersAnyAuthenticatedPacketTraversal(Peer);
    TimersAnyAuthenticatedPacketSent(Peer);

    if (NT_SUCCESS(SocketSendNblsToPeer(Peer, First, &IsKeepalive)) && !IsKeepalive)
        TimersDataSent(Peer);

    KeepKeyFresh(Peer);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
PacketPeerTxWork(_Inout_ WG_PEER *Peer, _In_ ULONG Budget)
{
    NOISE_KEYPAIR *Keypair;
    PACKET_STATE State;
    NET_BUFFER_LIST *First;

    while ((First = PrevQueuePeek(&Peer->TxQueue)) != NULL &&
           (State = ReadAcquire(NET_BUFFER_LIST_CRYPT_STATE(First))) != PACKET_STATE_UNCRYPTED)
    {
        if (!Budget--)
            return TRUE;
        PrevQueueDropPeeked(&Peer->TxQueue);
        Keypair = NET_BUFFER_LIST_KEYPAIR(First);

        if (State == PACKET_STATE_CRYPTED)
            PacketCreateDataDone(Peer, First);
        else
            FreeSendNetBufferList(Peer->Device, First, 0);

        NoiseKeypairPut(Keypair, FALSE);
        ExReleaseRundownProtection(&Peer->InUse);
        PeerPut(Peer);
    }
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
ProcessPerPeerWork(PEER_SERIAL *WorkQueue)
{
    PEER_SERIAL_ENTRY *Entry;
    while ((Entry = PeerSerialDequeue(WorkQueue)) != NULL)
        PeerSerialMaybeRetire(
            WorkQueue,
            Entry,
            PacketPeerTxWork(CONTAINING_RECORD(Entry, WG_PEER, TxSerialEntry), PEER_XMIT_PACKETS_PER_ROUND));
}

_Use_decl_annotations_
VOID
PacketEncryptWorker(MULTICORE_WORKQUEUE *WorkQueue)
{
    WG_DEVICE *Wg = CONTAINING_RECORD(WorkQueue, WG_DEVICE, EncryptThreads);
    PTR_RING *Ring = &Wg->EncryptQueue;
    NET_BUFFER_LIST *First;
    SIMD_STATE Simd;

    SimdGet(&Simd);
    while ((First = PtrRingConsume(Ring)) != NULL)
    {
        PACKET_STATE State = PACKET_STATE_CRYPTED;
        NOISE_KEYPAIR *Keypair = NET_BUFFER_LIST_KEYPAIR(First);
        WG_PEER *Peer = NET_BUFFER_LIST_PEER(First);
        ULONG Mtu = ReadULongNoFence(&Wg->Mtu);

        for (NET_BUFFER_LIST *Nbl = First; Nbl; Nbl = NET_BUFFER_LIST_NEXT_NBL(Nbl))
        {
            for (NET_BUFFER *NbIn = NET_BUFFER_LIST_FIRST_NB(Nbl->ParentNetBufferList),
                            *NbOut = NET_BUFFER_LIST_FIRST_NB(Nbl);
                 NbIn && NbOut;
                 NbIn = NET_BUFFER_NEXT_NB(NbIn), NbOut = NET_BUFFER_NEXT_NB(NbOut))
            {
                if (!EncryptPacket(&Simd, NbOut, NbIn, Keypair, Mtu))
                {
                    State = PACKET_STATE_DEAD;
                    goto enqueue;
                }
            }
            if (Nbl != Nbl->ParentNetBufferList)
            {
                FreeSendNetBufferList(Wg, Nbl->ParentNetBufferList, 0);
                Nbl->ParentNetBufferList = Nbl;
            }
        }
    enqueue:
        _Analysis_assume_(First != NULL);
        QueueEnqueuePerPeer(&Peer->Device->TxQueue, &Peer->TxSerialEntry, First, State);
        ProcessPerPeerWork(&Wg->TxQueue);
    }
    SimdPut(&Simd);
    ProcessPerPeerWork(&Wg->TxQueue);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PacketCreateData(_Inout_ WG_PEER *Peer, _In_ NET_BUFFER_LIST *First)
{
    WG_DEVICE *Wg = Peer->Device;
    NTSTATUS Ret = STATUS_INVALID_PARAMETER;

    if (!ExAcquireRundownProtection(&Peer->InUse))
        goto cleanup;

    Ret = QueueEnqueuePerDeviceAndPeer(&Wg->EncryptQueue, &Peer->TxQueue, &Wg->EncryptThreads, First);
    if (Ret == STATUS_PIPE_BROKEN)
    {
        QueueEnqueuePerPeer(&Peer->Device->TxQueue, &Peer->TxSerialEntry, First, PACKET_STATE_DEAD);
        MulticoreWorkQueueBump(&Wg->EncryptThreads);
    }
    if (NT_SUCCESS(Ret) || Ret == STATUS_PIPE_BROKEN)
        return;
    ExReleaseRundownProtection(&Peer->InUse);

cleanup:
    NoiseKeypairPut(NET_BUFFER_LIST_KEYPAIR(First), FALSE);
    FreeSendNetBufferList(Peer->Device, First, 0);
    PeerPut(Peer);
}

_Use_decl_annotations_
VOID
PacketPurgeStagedPackets(WG_PEER *Peer)
{
    KIRQL Irql;

    KeAcquireSpinLock(&Peer->StagedPacketQueue.Lock, &Irql);
    Peer->Device->Statistics.ifOutDiscards += NetBufferListQueueLength(&Peer->StagedPacketQueue);
    if (Peer->StagedPacketQueue.Head)
        FreeSendNetBufferList(Peer->Device, Peer->StagedPacketQueue.Head, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
    Peer->StagedPacketQueue.Head = Peer->StagedPacketQueue.Tail = NULL;
    Peer->StagedPacketQueue.Length = 0;
    KeReleaseSpinLock(&Peer->StagedPacketQueue.Lock, Irql);
}

_Use_decl_annotations_
VOID
PacketSendStagedPackets(WG_PEER *Peer)
{
    NOISE_KEYPAIR *Keypair;
    NET_BUFFER_LIST_QUEUE Packets;
    PNET_BUFFER_LIST Nbl;
    KIRQL Irql;

    /* Steal the current queue into our local one. */
    NetBufferListInitQueue(&Packets);
    KeAcquireSpinLock(&Peer->StagedPacketQueue.Lock, &Irql);
    _Analysis_suppress_lock_checking_(Packets.Lock); /* `Packets` is private, lock is not required. */
    NetBufferListSpliceAndReinitQueue(&Peer->StagedPacketQueue, &Packets);
    KeReleaseSpinLock(&Peer->StagedPacketQueue.Lock, Irql);
    if (NetBufferListIsQueueEmpty(&Packets))
        return;
    _Analysis_assume_(Packets.Head != NULL);

    /* First we make sure we have a valid reference to a valid key. */
    Irql = RcuReadLock();
    Keypair = NoiseKeypairGet(RcuDereference(NOISE_KEYPAIR, Peer->Keypairs.CurrentKeypair));
    RcuReadUnlock(Irql);
    if (!Keypair)
        goto outNokey;
    if (!ReadBooleanNoFence(&Keypair->Sending.IsValid))
        goto outNokey;
    if (BirthdateHasExpired(Keypair->Sending.Birthdate, REJECT_AFTER_TIME))
        goto outInvalid;

    /* After we know we have a somewhat valid key, we now try to assign
     * nonces to all of the packets in the queue. If we can't assign nonces
     * for all of them, we just consider it a failure and wait for the next
     * handshake.
     */
    for (Nbl = Packets.Head; Nbl; Nbl = NET_BUFFER_LIST_NEXT_NBL(Nbl))
    {
        for (NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl); Nb; Nb = NET_BUFFER_NEXT_NB(Nb))
        {
            NET_BUFFER_NONCE(Nb) = InterlockedIncrement64(&Keypair->SendingCounter) - 1;
            if (NET_BUFFER_NONCE(Nb) >= REJECT_AFTER_MESSAGES)
                goto outInvalid;
        }
    }

    PeerGet(Keypair->Entry.Peer);
    _Analysis_assume_(NET_BUFFER_LIST_FIRST_NB(Packets.Head)); /* Checked in SendNetBufferLists(). */
    NET_BUFFER_LIST_KEYPAIR(Packets.Head) = Keypair;
    PacketCreateData(Peer, Packets.Head);
    return;

outInvalid:
    WriteBooleanNoFence(&Keypair->Sending.IsValid, FALSE);
outNokey:
    NoiseKeypairPut(Keypair, FALSE);

    /* We orphan the packets if we're waiting on a handshake, so that they
     * don't block the pool of an upper layer. Then we put them back on the
     * end of the queue. We're not too concerned about accidentally getting
     * things a little out of order if packets are being added really fast,
     * because this queue is for before packets can even be sent and it's
     * small anyway.
     */
    _Analysis_suppress_lock_checking_(Packets.Lock); /* `Packets` is private, lock is not required. */
    while ((Nbl = NetBufferListDequeue(&Packets)) != NULL)
    {
        NT_ASSERT(Nbl->ParentNetBufferList);
        if (Nbl->ParentNetBufferList == Nbl)
            goto requeueOrphan;

        for (NET_BUFFER *NbIn = NET_BUFFER_LIST_FIRST_NB(Nbl->ParentNetBufferList),
                        *NbOut = NET_BUFFER_LIST_FIRST_NB(Nbl);
             NbIn && NbOut;
             NbIn = NET_BUFFER_NEXT_NB(NbIn), NbOut = NET_BUFFER_NEXT_NB(NbOut))
        {
            VOID *Dst = (UCHAR *)MemGetValidatedNetBufferData(NbOut) + sizeof(MESSAGE_DATA);
            VOID *Src = NdisGetDataBuffer(NbIn, NET_BUFFER_DATA_LENGTH(NbIn), Dst, 1, 0);
            if (Src != Dst)
                RtlCopyMemory(Dst, Src, NET_BUFFER_DATA_LENGTH(NbIn));
            NET_BUFFER_DATA_LENGTH(NbOut) = NET_BUFFER_DATA_LENGTH(NbIn);
            NET_BUFFER_DATA_OFFSET(NbOut) = NET_BUFFER_CURRENT_MDL_OFFSET(NbOut) = sizeof(MESSAGE_DATA);
        }
        FreeSendNetBufferList(Peer->Device, Nbl->ParentNetBufferList, 0);
        Nbl->ParentNetBufferList = Nbl;
    requeueOrphan:
        NetBufferListInterlockedEnqueue(&Peer->StagedPacketQueue, Nbl);
    }

    /* If we're exiting because there's something wrong with the key, it
     * means we should initiate a new handshake.
     */
    PacketSendQueuedHandshakeInitiation(Peer, FALSE);
}

#pragma warning( \
    suppress : 6014) /* `Nbl` is returned in NdisMSendNetBufferListsComplete or freed in MemFreeNetBufferList. */
_Use_decl_annotations_
VOID
FreeSendNetBufferList(WG_DEVICE *Wg, NET_BUFFER_LIST *FirstNbl, ULONG SendCompleteFlags)
{
    for (NET_BUFFER_LIST *Nbl = FirstNbl, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
        if (Nbl->NdisPoolHandle == Wg->NblPool)
        {
            if (Nbl->ParentNetBufferList != Nbl)
            {
                NET_BUFFER_LIST_STATUS(Nbl->ParentNetBufferList) = NET_BUFFER_LIST_STATUS(Nbl);
                NdisMSendNetBufferListsComplete(Wg->MiniportAdapterHandle, Nbl->ParentNetBufferList, SendCompleteFlags);
                ExReleaseRundownProtection(&Wg->ItemsInFlight);
                Nbl->ParentNetBufferList = NULL;
            }
            MemFreeNetBufferList(Nbl);
        }
        else
        {
            NdisMSendNetBufferListsComplete(Wg->MiniportAdapterHandle, Nbl, SendCompleteFlags);
            ExReleaseRundownProtection(&Wg->ItemsInFlight);
        }
    }
}
