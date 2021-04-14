/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "cookie.h"
#include "device.h"
#include "messages.h"
#include "peer.h"
#include "queueing.h"
#include "rcu.h"
#include "socket.h"
#include "timers.h"
#include "logging.h"

static VOID
UpdateRxStats(_Inout_ WG_PEER *Peer, _In_ CONST ULONG Len)
{
    Peer->RxBytes += Len;
    Peer->Device->Statistics.ifHCInOctets += Len;
    Peer->Device->Statistics.ifHCInUcastOctets += Len;
    ++Peer->Device->Statistics.ifHCInUcastPkts;
}

#define NBL_TYPE_LE32(Nbl) (((MESSAGE_HEADER *)MemGetValidatedNetBufferListData(Nbl))->Type)

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ReceiveHandshakePacket(_Inout_ WG_DEVICE *Wg, _In_ NET_BUFFER_LIST *Nbl)
{
    COOKIE_MAC_STATE MacState;
    WG_PEER *Peer = NULL;
    /* This is global, so that our load calculation applies to the whole
     * system. We don't care about races with it at all.
     */
    static UINT64 LastUnderLoad;
    BOOLEAN PacketNeedsCookie;
    BOOLEAN UnderLoad;
    UINT32_LE NblType = NBL_TYPE_LE32(Nbl);
    NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    CHAR EndpointName[SOCKADDR_STR_MAX_LEN];

    if (NblType == CpuToLe32(MESSAGE_TYPE_HANDSHAKE_COOKIE))
    {
        LogInfoNblRatelimited(Wg, "Receiving cookie response from %s", Nbl);
        CookieMessageConsume(MemGetValidatedNetBufferListData(Nbl), Wg);
        return;
    }

    UnderLoad = NetBufferListQueueLength(&Wg->HandshakeRxQueue) >= MAX_QUEUED_INCOMING_HANDSHAKES / 8;
    if (UnderLoad)
    {
        LastUnderLoad = KeQueryInterruptTime();
    }
    else if (LastUnderLoad)
    {
        UnderLoad = !BirthdateHasExpired(LastUnderLoad, 1);
        if (!UnderLoad)
            LastUnderLoad = 0;
    }
    MacState = CookieValidatePacket(&Wg->CookieChecker, Nbl, UnderLoad);
    if ((UnderLoad && MacState == VALID_MAC_WITH_COOKIE) || (!UnderLoad && MacState == VALID_MAC_BUT_NO_COOKIE))
    {
        PacketNeedsCookie = FALSE;
    }
    else if (UnderLoad && MacState == VALID_MAC_BUT_NO_COOKIE)
    {
        PacketNeedsCookie = TRUE;
    }
    else
    {
        LogInfoNblRatelimited(Wg, "Invalid MAC of handshake, dropping packet from %s", Nbl);
        return;
    }

    switch (NblType)
    {
    case CpuToLe32(MESSAGE_TYPE_HANDSHAKE_INITIATION): {
        MESSAGE_HANDSHAKE_INITIATION *Message = MemGetValidatedNetBufferListData(Nbl);

        if (PacketNeedsCookie)
        {
            PacketSendHandshakeCookie(Wg, Nbl, Message->SenderIndex);
            return;
        }
        Peer = NoiseHandshakeConsumeInitiation(Message, Wg);
        if (!Peer)
        {
            LogInfoNblRatelimited(Wg, "Invalid handshake initiation from %s", Nbl);
            return;
        }
        SocketSetPeerEndpointFromNbl(Peer, Nbl);
        SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
        LogInfoRatelimited(Wg, "Receiving handshake initiation from peer %llu (%s)", Peer->InternalId, EndpointName);
        PacketSendHandshakeResponse(Peer);
        break;
    }
    case CpuToLe32(MESSAGE_TYPE_HANDSHAKE_RESPONSE): {
        MESSAGE_HANDSHAKE_RESPONSE *Message = MemGetValidatedNetBufferListData(Nbl);

        if (PacketNeedsCookie)
        {
            PacketSendHandshakeCookie(Wg, Nbl, Message->SenderIndex);
            return;
        }
        Peer = NoiseHandshakeConsumeResponse(Message, Wg);
        if (!Peer)
        {
            LogInfoNblRatelimited(Wg, "Invalid handshake response from %s", Nbl);
            return;
        }
        SocketSetPeerEndpointFromNbl(Peer, Nbl);
        SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
        LogInfoRatelimited(Wg, "Receiving handshake response from peer %llu (%s)", Peer->InternalId, EndpointName);
        if (NoiseHandshakeBeginSession(&Peer->Handshake, &Peer->Keypairs))
        {
            TimersSessionDerived(Peer);
            TimersHandshakeComplete(Peer);
            /* Calling this function will either send any existing
             * packets in the queue and not send a keepalive, which
             * is the best case, Or, if there's nothing in the
             * queue, it will send a keepalive, in order to give
             * immediate confirmation of the session.
             */
            PacketSendKeepalive(Peer);
        }
        break;
    }
    }

    if (!Peer)
    {
        NT_ASSERTMSG("Somehow a wrong type of packet wound up in the handshake queue!", 0);
        return;
    }

    UpdateRxStats(Peer, NET_BUFFER_DATA_LENGTH(Nb));

    TimersAnyAuthenticatedPacketReceived(Peer);
    TimersAnyAuthenticatedPacketTraversal(Peer);
    PeerPut(Peer);
}

_Use_decl_annotations_
VOID
PacketHandshakeRxWorker(MULTICORE_WORKQUEUE *WorkQueue)
{
    WG_DEVICE *Wg = CONTAINING_RECORD(WorkQueue, WG_DEVICE, HandshakeRxThreads);
    NET_BUFFER_LIST *Nbl;

    while ((Nbl = NetBufferListInterlockedDequeue(&Wg->HandshakeRxQueue)) != NULL)
    {
        ReceiveHandshakePacket(Wg, Nbl);
        FreeReceiveNetBufferList(Wg, Nbl);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
KeepKeyFresh(_Inout_ WG_PEER *Peer)
{
    NOISE_KEYPAIR *Keypair;
    BOOLEAN Send;
    KIRQL Irql;

    if (Peer->SentLastminuteHandshake)
        return;

    Irql = RcuReadLock();
    Keypair = RcuDereference(NOISE_KEYPAIR, Peer->Keypairs.CurrentKeypair);
    Send = Keypair && ReadBooleanNoFence(&Keypair->Sending.IsValid) && Keypair->IAmTheInitiator &&
           BirthdateHasExpired(Keypair->Sending.Birthdate, REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT);
    RcuReadUnlock(Irql);

    if (Send)
    {
        Peer->SentLastminuteHandshake = TRUE;
        PacketSendQueuedHandshakeInitiation(Peer, FALSE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Return_type_success_(return != FALSE)
static BOOLEAN
DecryptPacket(_In_ CONST SIMD_STATE *Simd, _Inout_ NET_BUFFER_LIST *Nbl, _Inout_opt_ NOISE_KEYPAIR *Keypair)
{
    if (!Keypair)
        return FALSE;

    if (!ReadBooleanNoFence(&Keypair->Receiving.IsValid) ||
        BirthdateHasExpired(Keypair->Receiving.Birthdate, REJECT_AFTER_TIME) ||
        Keypair->ReceivingCounter.Counter >= REJECT_AFTER_MESSAGES)
    {
        WriteBooleanNoFence(&Keypair->Receiving.IsValid, FALSE);
        return FALSE;
    }

    NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    WSK_BUF *Buffer = &NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->Buffer;
    MESSAGE_DATA *Message = MemGetValidatedNetBufferListData(Nbl);
    UINT64 Nonce = Le64ToCpu(Message->Counter);
    NET_BUFFER_NONCE(Nb) = Nonce;
    NET_BUFFER_DATA_LENGTH(Nb) = (ULONG)Buffer->Length - MessageDataLen(0);
    return ChaCha20Poly1305DecryptMdl(
        MemGetValidatedNetBufferListData(Nbl),
        Buffer->Mdl,
        (ULONG)Buffer->Length - sizeof(*Message),
        Buffer->Offset + sizeof(*Message),
        NULL,
        0,
        Nonce,
        Keypair->Receiving.Key,
        Simd);
}

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Counter->Lock)
_Must_inspect_result_
_Return_type_success_(return != FALSE)
static BOOLEAN
CounterValidate(_Inout_ NOISE_REPLAY_COUNTER *Counter, _In_ UINT64 TheirCounter)
{
    ULONG_PTR Index, IndexCurrent, Top, i;
    KIRQL Irql;
    BOOLEAN Ret = FALSE;

    KeAcquireSpinLock(&Counter->Lock, &Irql);

    if (Counter->Counter >= REJECT_AFTER_MESSAGES + 1 || TheirCounter >= REJECT_AFTER_MESSAGES)
        goto out;

    ++TheirCounter;

    if ((COUNTER_WINDOW_SIZE + TheirCounter) < Counter->Counter)
        goto out;

    Index = (ULONG_PTR)(TheirCounter >> BITS_PER_POINTER_SHIFT);

    if (TheirCounter > Counter->Counter)
    {
        IndexCurrent = (ULONG_PTR)(Counter->Counter >> BITS_PER_POINTER_SHIFT);
        Top = min(Index - IndexCurrent, COUNTER_BITS_TOTAL / BITS_PER_POINTER);
        for (i = 1; i <= Top; ++i)
            Counter->Backtrack[(i + IndexCurrent) & ((COUNTER_BITS_TOTAL / BITS_PER_POINTER) - 1)] = 0;
        Counter->Counter = TheirCounter;
    }

    Index &= (COUNTER_BITS_TOTAL / BITS_PER_POINTER) - 1;
    Ret = !InterlockedBitTestAndSetPtr((LONG_PTR *)&Counter->Backtrack[Index], TheirCounter & (BITS_PER_POINTER - 1));

out:
    KeReleaseSpinLock(&Counter->Lock, Irql);
    return Ret;
}

#ifdef DBG
#    include "selftest/counter.c"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PacketConsumeDataDone(_Inout_ WG_PEER *Peer, _Inout_ NET_BUFFER_LIST *Nbl, _In_ CONST ENDPOINT *Endpoint)
{
    ULONG Len, LenBeforeTrim;
    WG_PEER *RoutedPeer;
    NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    UINT16_BE Proto;
    VOID *Hdr;
    CHAR EndpointName[SOCKADDR_STR_MAX_LEN], SrcStr[46] = "";

    SocketSetPeerEndpoint(Peer, Endpoint);

    if (NoiseReceivedWithKeypair(&Peer->Keypairs, NET_BUFFER_LIST_KEYPAIR(Nbl)))
    {
        TimersHandshakeComplete(Peer);
        PacketSendStagedPackets(Peer);
    }

    KeepKeyFresh(Peer);

    TimersAnyAuthenticatedPacketReceived(Peer);
    TimersAnyAuthenticatedPacketTraversal(Peer);

    /* A packet with length 0 is a keepalive packet */
    if (!NET_BUFFER_DATA_LENGTH(Nb))
    {
        UpdateRxStats(Peer, MessageDataLen(0));
        SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
        LogInfoRatelimited(
            Peer->Device, "Receiving keepalive packet from peer %llu (%s)", Peer->InternalId, EndpointName);
        goto packetProcessed;
    }

    TimersDataReceived(Peer);

    Nbl->SourceHandle = Peer->Device->MiniportAdapterHandle;
    /* We've already verified the Poly1305 auth tag, which means this packet
     * was not modified in transit. We can therefore tell the networking
     * stack that all checksums of every layer of encapsulation have already
     * been checked "by the hardware" and therefore is unnecessary to check
     * again in software.
     */
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO *TcpIpChecksumNblInfo =
        (NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO *)&NET_BUFFER_LIST_INFO(Nbl, TcpIpChecksumNetBufferListInfo);
    TcpIpChecksumNblInfo->Receive.TcpChecksumFailed = 0;
    TcpIpChecksumNblInfo->Receive.TcpChecksumValueInvalid = 0;
    TcpIpChecksumNblInfo->Receive.TcpChecksumSucceeded = 1;
    TcpIpChecksumNblInfo->Receive.UdpChecksumFailed = 0;
    TcpIpChecksumNblInfo->Receive.UdpChecksumSucceeded = 1;
    TcpIpChecksumNblInfo->Receive.IpChecksumFailed = 0;
    TcpIpChecksumNblInfo->Receive.IpChecksumValueInvalid = 0;
    TcpIpChecksumNblInfo->Receive.IpChecksumSucceeded = 1;
    Proto = IpTunnelParseProtocol(Nbl);
    if (Proto == Htons(NDIS_ETH_TYPE_IPV4) && (Hdr = NdisGetDataBuffer(Nb, sizeof(IPV4HDR), NULL, 1, 0)) != NULL)
    {
        Len = Ntohs(((IPV4HDR *)Hdr)->TotLen);
        if (Len < sizeof(IPV4HDR))
            goto dishonestPacketSize;
        NdisSetNblFlag(Nbl, NDIS_NBL_FLAGS_IS_IPV4);
    }
    else if (Proto == Htons(NDIS_ETH_TYPE_IPV6) && (Hdr = NdisGetDataBuffer(Nb, sizeof(IPV6HDR), NULL, 1, 0)) != NULL)
    {
        Len = Ntohs(((IPV6HDR *)Hdr)->PayloadLen) + sizeof(IPV6HDR);
        NdisSetNblFlag(Nbl, NDIS_NBL_FLAGS_IS_IPV6);
    }
    else
        goto dishonestPacketType;
    NET_BUFFER_LIST_INFO(Nbl, NetBufferListProtocolId) = (VOID *)Proto;

    if (Len > NET_BUFFER_DATA_LENGTH(Nb))
        goto dishonestPacketSize;
    LenBeforeTrim = NET_BUFFER_DATA_LENGTH(Nb);
    NET_BUFFER_DATA_LENGTH(Nb) = Len;

    RoutedPeer = AllowedIpsLookupSrc(&Peer->Device->PeerAllowedIps, Proto, Hdr);
    PeerPut(RoutedPeer); /* We don't need the extra reference. */

    if (RoutedPeer != Peer)
        goto dishonestPacketPeer;

    NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_SUCCESS;
    UpdateRxStats(Peer, MessageDataLen(LenBeforeTrim));
    return TRUE;

dishonestPacketPeer:
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    if (Proto == Htons(NDIS_ETH_TYPE_IPV4))
        RtlIpv4AddressToStringA((IN_ADDR *)&((IPV4HDR *)Hdr)->Saddr, SrcStr);
    else if (Proto == Htons(NDIS_ETH_TYPE_IPV6))
        RtlIpv6AddressToStringA(&((IPV6HDR *)Hdr)->Saddr, SrcStr);
    LogInfoRatelimited(
        Peer->Device, "Packet has unallowed src IP (%s) from peer %llu (%s)", SrcStr, Peer->InternalId, EndpointName);
    goto falsePacket;
dishonestPacketType:
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    LogInfoRatelimited(
        Peer->Device, "Packet is neither ipv4 nor ipv6 from peer %llu (%s)", Peer->InternalId, EndpointName);
    goto falsePacket;
dishonestPacketSize:
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    LogInfoRatelimited(Peer->Device, "Packet has incorrect size from peer %llu (%s)", Peer->InternalId, EndpointName);
    goto falsePacket;
falsePacket:
    ++Peer->Device->Statistics.ifInErrors;
    ++Peer->Device->Statistics.ifInDiscards;
packetProcessed:
    FreeReceiveNetBufferList(Peer->Device, Nbl);
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
PacketPeerRxWork(_Inout_ WG_PEER *Peer, _In_ ULONG Budget)
{
    NOISE_KEYPAIR *Keypair;
    ENDPOINT Endpoint;
    PACKET_STATE State;
    NET_BUFFER_LIST *Nbl, *First = NULL, **Next = &First;
    BOOLEAN Free, MoreProcessing = FALSE;
    ULONG NumNbls = 0;

    while ((Nbl = PrevQueuePeek(&Peer->RxQueue)) != NULL &&
           (State = ReadAcquire(NET_BUFFER_LIST_CRYPT_STATE(Nbl))) != PACKET_STATE_UNCRYPTED)
    {
        if (!Budget--)
        {
            MoreProcessing = TRUE;
            break;
        }
        PrevQueueDropPeeked(&Peer->RxQueue);
        Keypair = NET_BUFFER_LIST_KEYPAIR(Nbl);
        Free = TRUE;

        if (State != PACKET_STATE_CRYPTED)
            goto next;

        UINT64 Nonce = NET_BUFFER_NONCE(NET_BUFFER_LIST_FIRST_NB(Nbl));
        if (!CounterValidate(&Keypair->ReceivingCounter, Nonce))
        {
            LogInfoRatelimited(
                Peer->Device, "Packet has invalid nonce %llu (max %llu)", Nonce, Keypair->ReceivingCounter.Counter);
            goto next;
        }

        if (!NT_SUCCESS(SocketEndpointFromNbl(&Endpoint, Nbl)))
            goto next;

        if (PacketConsumeDataDone(Peer, Nbl, &Endpoint))
        {
            *Next = Nbl;
            Next = &NET_BUFFER_LIST_NEXT_NBL(Nbl);
            ++NumNbls;
        }
        Free = FALSE;

    next:
        NoiseKeypairPut(Keypair, FALSE);
        if (Free)
            FreeReceiveNetBufferList(Peer->Device, Nbl);
        ExReleaseRundownProtection(&Peer->InUse);
        PeerPut(Peer);
    }
    if (First)
        NdisMIndicateReceiveNetBufferLists(First->SourceHandle, First, NDIS_DEFAULT_PORT_NUMBER, NumNbls, 0);
    return MoreProcessing;
}

_Use_decl_annotations_
VOID
PacketRxWorker(MULTICORE_WORKQUEUE *WorkQueue)
{
    WG_DEVICE *Wg = CONTAINING_RECORD(WorkQueue, WG_DEVICE, RxThreads);
    PEER_SERIAL_ENTRY *Entry;
    while ((Entry = PeerSerialDequeue(&Wg->RxQueue)) != NULL)
        PeerSerialMaybeRetire(
            &Wg->RxQueue,
            Entry,
            PacketPeerRxWork(CONTAINING_RECORD(Entry, WG_PEER, RxSerialEntry), PEER_XMIT_PACKETS_PER_ROUND));
}

_Use_decl_annotations_
VOID
PacketDecryptWorker(MULTICORE_WORKQUEUE *WorkQueue)
{
    WG_DEVICE *Wg = CONTAINING_RECORD(WorkQueue, WG_DEVICE, DecryptThreads);
    PTR_RING *Ring = &Wg->DecryptQueue;
    NET_BUFFER_LIST *First;
    SIMD_STATE Simd;

    SimdGet(&Simd);
    while ((First = PtrRingConsume(Ring)) != NULL)
    {
        for (NET_BUFFER_LIST *Nbl = First, *NextNbl; Nbl; Nbl = NextNbl)
        {
            WG_PEER *Peer = NET_BUFFER_LIST_PEER(Nbl);
            NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
            NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
            PACKET_STATE State =
                DecryptPacket(&Simd, Nbl, NET_BUFFER_LIST_KEYPAIR(Nbl)) ? PACKET_STATE_CRYPTED : PACKET_STATE_DEAD;
            QueueEnqueuePerPeer(&Peer->Device->RxQueue, &Peer->RxSerialEntry, &Peer->Device->RxThreads, Nbl, State);
        }
    }
    SimdPut(&Simd);
}

#pragma warning(suppress : 28194) /* `Nbl` is aliased in QueueEnqueuePerDeviceAndPeer, or QueueEnqueuePerPeer or freed \
                                     in FreeReceiveNetBufferList. */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PacketConsumeData(_Inout_ WG_DEVICE *Wg, _Inout_ __drv_aliasesMem NET_BUFFER_LIST *First)
{
    NET_BUFFER_LIST *FirstForDevice = NULL, **Link = &FirstForDevice;
    for (NET_BUFFER_LIST *Nbl = First, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;

        MESSAGE_DATA *Message = MemGetValidatedNetBufferListData(Nbl);
        WG_PEER *Peer = NULL;
        NOISE_KEYPAIR *Keypair;

        KIRQL Irql = RcuReadLock();
        NET_BUFFER_LIST_KEYPAIR(Nbl) = Keypair = NoiseKeypairGet(
            (NOISE_KEYPAIR *)IndexHashtableLookup(Wg->IndexHashtable, INDEX_HASHTABLE_KEYPAIR, Message->KeyIdx, &Peer));
        RcuReadUnlock(Irql);
        if (!Keypair)
            goto cleanupNbl;

        if (!ExAcquireRundownProtection(&Peer->InUse))
            goto cleanupKeypair;
        if (!QueueInsertPerPeer(&Peer->RxQueue, Nbl))
            goto cleanupInUse;
        *Link = Nbl;
        Link = &NET_BUFFER_LIST_NEXT_NBL(Nbl);
        continue;

    cleanupInUse:
        ExReleaseRundownProtection(&Peer->InUse);
    cleanupKeypair:
        NoiseKeypairPut(Keypair, FALSE);
    cleanupNbl:
        FreeReceiveNetBufferList(Wg, Nbl);
        PeerPut(Peer);
    }
    if (FirstForDevice && !QueueEnqueuePerDevice(&Wg->DecryptQueue, &Wg->DecryptThreads, FirstForDevice))
    {
        for (NET_BUFFER_LIST *Nbl = FirstForDevice, *NextNbl; Nbl; Nbl = NextNbl)
        {
            WG_PEER *Peer = NET_BUFFER_LIST_PEER(Nbl);
            NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
            NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
            QueueEnqueuePerPeer(
                &Peer->Device->RxQueue, &Peer->RxSerialEntry, &Peer->Device->RxThreads, Nbl, PACKET_STATE_DEAD);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Return_type_success_(return == TRUE)
_Must_inspect_result_
static BOOLEAN
PrepareNetBufferListHeader(_Inout_ NET_BUFFER_LIST *Nbl)
{
    WSK_BUF *Buffer = &NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->Buffer;
    if (Buffer->Length < sizeof(MESSAGE_HEADER))
        return FALSE;
    ULONG MdlLen = MmGetMdlByteCount(Buffer->Mdl);
    if (Buffer->Offset > MdlLen)
        return FALSE;
    MdlLen -= Buffer->Offset;
    /* We lazily require that the full header is in the first MDL.
     * Later we can switch to something more complex if this turns
     * out to be an actual problem with real indications.
     */
    if (MdlLen < sizeof(MESSAGE_HEADER))
        return FALSE;
    UCHAR *Src =
        MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
    if (!Src)
        return FALSE;
    Src += Buffer->Offset;
    MESSAGE_HEADER *Header = MemGetValidatedNetBufferListData(Nbl);
    RtlCopyMemory(Header, Src, sizeof(*Header));
    ULONG HeaderLen, RequiredLen;
    if (Header->Type == CpuToLe32(MESSAGE_TYPE_DATA))
        HeaderLen = sizeof(MESSAGE_DATA), RequiredLen = MESSAGE_MINIMUM_LENGTH;
    else if (Header->Type == CpuToLe32(MESSAGE_TYPE_HANDSHAKE_INITIATION))
        RequiredLen = HeaderLen = sizeof(MESSAGE_HANDSHAKE_INITIATION);
    else if (Header->Type == CpuToLe32(MESSAGE_TYPE_HANDSHAKE_RESPONSE))
        RequiredLen = HeaderLen = sizeof(MESSAGE_HANDSHAKE_RESPONSE);
    else if (Header->Type == CpuToLe32(MESSAGE_TYPE_HANDSHAKE_COOKIE))
        RequiredLen = HeaderLen = sizeof(MESSAGE_HANDSHAKE_COOKIE);
    else
        return FALSE;
    if (Buffer->Length < RequiredLen || MdlLen < HeaderLen)
        return FALSE;
    RtlCopyMemory(Header + 1, Src + sizeof(*Header), HeaderLen - sizeof(*Header));
    return TRUE;
}

#pragma warning(suppress : 28194) /* `Nbl` is aliased in NetBufferListInterlockedEnqueue, or PacketConsumeData, \
                                     or freed in FreeReceiveNetBufferList. */
_Use_decl_annotations_
VOID
PacketReceive(WG_DEVICE *Wg, NET_BUFFER_LIST *First)
{
    NET_BUFFER_LIST *FirstData = NULL, **Link = &FirstData;
    for (NET_BUFFER_LIST *Nbl = First, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;

        if (!PrepareNetBufferListHeader(Nbl))
            goto cleanup;
        switch (NBL_TYPE_LE32(Nbl))
        {
        case CpuToLe32(MESSAGE_TYPE_HANDSHAKE_INITIATION):
        case CpuToLe32(MESSAGE_TYPE_HANDSHAKE_RESPONSE):
        case CpuToLe32(MESSAGE_TYPE_HANDSHAKE_COOKIE): {
            if (NetBufferListQueueLength(&Wg->HandshakeRxQueue) > MAX_QUEUED_INCOMING_HANDSHAKES)
            {
                LogInfoNblRatelimited(Wg, "Dropping handshake packet from %s", Nbl);
                goto cleanup;
            }
            NetBufferListInterlockedEnqueue(&Wg->HandshakeRxQueue, Nbl);
            MulticoreWorkQueueBump(&Wg->HandshakeRxThreads);
            break;
        }
        case CpuToLe32(MESSAGE_TYPE_DATA):
            *Link = Nbl;
            Link = &NET_BUFFER_LIST_NEXT_NBL(Nbl);
            break;
        default:
            goto cleanup;
        }
        continue;

    cleanup:
        FreeReceiveNetBufferList(Wg, Nbl);
    }

    if (FirstData)
        PacketConsumeData(Wg, FirstData);
}

_Use_decl_annotations_
VOID
FreeReceiveNetBufferList(WG_DEVICE *Wg, NET_BUFFER_LIST *First)
{
    for (NET_BUFFER_LIST *Nbl = First, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
        WSK_DATAGRAM_INDICATION *DatagramIndication = NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl);
        NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl) = NULL;
        SOCKET *Socket = (SOCKET *)DatagramIndication->Next;
        DatagramIndication->Next = NULL;
        ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Sock->Dispatch)->WskRelease(Socket->Sock, DatagramIndication);
        MemFreeNetBufferList(Nbl);
        ExReleaseRundownProtection(&Socket->ItemsInFlight);
    }
}

_Use_decl_annotations_
VOID
FreeIncomingHandshakes(WG_DEVICE *Wg)
{
    NET_BUFFER_LIST *Nbl;
    while ((Nbl = NetBufferListInterlockedDequeue(&Wg->HandshakeRxQueue)) != NULL)
        FreeReceiveNetBufferList(Wg, Nbl);
}
