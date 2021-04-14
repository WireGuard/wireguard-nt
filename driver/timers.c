/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "device.h"
#include "peer.h"
#include "queueing.h"
#include "rcu.h"
#include "socket.h"
#include "timers.h"
#include "logging.h"

typedef _Function_class_(TIMER_CALLBACK)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
TIMER_CALLBACK(_In_ TIMER *);
typedef TIMER_CALLBACK *PTIMER_CALLBACK;

static KDEFERRED_ROUTINE TimerDpcCallback;
_Use_decl_annotations_
static VOID
TimerDpcCallback(KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    TIMER *Timer = CONTAINING_RECORD(Dpc, TIMER, Dpc);
    _Analysis_assume_(DeferredContext != NULL);
    ((PTIMER_CALLBACK)DeferredContext)(Timer);
    WriteBooleanNoFence(&Timer->Pending, FALSE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TimerInit(_Out_ TIMER *Timer, _In_ PTIMER_CALLBACK Callback)
{
    KeInitializeDpc(&Timer->Dpc, TimerDpcCallback, (PVOID)Callback);
    KeInitializeTimer(&Timer->Timer);
    Timer->Pending = FALSE;
}

static BOOLEAN
TimerIsPending(_In_ CONST TIMER *Timer)
{
    return ReadBooleanNoFence(&Timer->Pending);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TimerMod(_Inout_ TIMER *Timer, _In_ LONG64 Expires)
{
    WriteBooleanNoFence(&Timer->Pending, TRUE);
    KeSetCoalescableTimer(&Timer->Timer, (LARGE_INTEGER){ .QuadPart = Expires }, 0, 320, &Timer->Dpc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TimerDelete(_In_ TIMER *Timer)
{
    if (!KeCancelTimer(&Timer->Timer))
        KeRemoveQueueDpc(&Timer->Dpc);
    WriteBooleanNoFence(&Timer->Pending, FALSE);
}

static ULONG JitterSeed;

_IRQL_requires_max_(APC_LEVEL)
_Ret_range_(0, Range - 1)
static ULONG
GenerateJitter(_In_ ULONG Range)
{
    return (ULONG)(((UINT64)RtlRandomEx(&JitterSeed) * Range) >> 32);
}

/*
 * - Timer for retransmitting the handshake if we don't hear back after
 * `REKEY_TIMEOUT + jitter` ms.
 *
 * - Timer for sending empty packet if we have received a packet but after have
 * not sent one for `KEEPALIVE_TIMEOUT` ms.
 *
 * - Timer for initiating new handshake if we have sent a packet but after have
 * not received one (even empty) for `(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) +
 * jitter` ms.
 *
 * - Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms
 * if no new keys have been received.
 *
 * - Timer for, if enabled, sending an empty authenticated packet every user-
 * specified seconds.
 */

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
ModPeerTimer(_In_ WG_PEER *Peer, _Inout_ TIMER *Timer, _In_ LONG64 Expires)
{
    if (!ReadBooleanNoFence(&Peer->Device->IsUp) || !ExAcquireRundownProtection(&Peer->InUse))
        return;
    TimerMod(Timer, Expires);
    ExReleaseRundownProtection(&Peer->InUse);
}

static TIMER_CALLBACK ExpiredRetransmitHandshake;
_Use_decl_annotations_
static VOID
ExpiredRetransmitHandshake(TIMER *Timer)
{
    WG_PEER *Peer = CONTAINING_RECORD(Timer, WG_PEER, TimerRetransmitHandshake);

    if (Peer->TimerHandshakeAttempts > MAX_TIMER_HANDSHAKES)
    {
        CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
        SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
        LogInfo(
            Peer->Device,
            "Handshake for peer %llu (%s) did not complete after %d attempts, giving up",
            Peer->InternalId,
            EndpointName,
            MAX_TIMER_HANDSHAKES + 2);

        TimerDelete(&Peer->TimerSendKeepalive);
        /* We drop all packets without a keypair and don't try again,
         * if we try unsuccessfully for too long to make a handshake.
         */
        PacketPurgeStagedPackets(Peer);

        /* We set a timer for destroying any residue that might be left
         * of a partial exchange.
         */
        if (!TimerIsPending(&Peer->TimerZeroKeyMaterial))
            ModPeerTimer(Peer, &Peer->TimerZeroKeyMaterial, -SEC_TO_SYS_TIME_UNITS(REJECT_AFTER_TIME * 3));
    }
    else
    {
        ++Peer->TimerHandshakeAttempts;
        CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
        SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
        LogInfo(
            Peer->Device,
            "Handshake for peer %llu (%s) did not complete after %d seconds, retrying (try %u)",
            Peer->InternalId,
            EndpointName,
            REKEY_TIMEOUT,
            Peer->TimerHandshakeAttempts + 1);

        /* We clear the endpoint address src address, in case this is
         * the cause of trouble.
         */
        SocketClearPeerEndpointSrc(Peer);

        PacketSendQueuedHandshakeInitiation(Peer, TRUE);
    }
}

static TIMER_CALLBACK ExpiredSendKeepalive;
_Use_decl_annotations_
static VOID
ExpiredSendKeepalive(TIMER *Timer)
{
    WG_PEER *Peer = CONTAINING_RECORD(Timer, WG_PEER, TimerSendKeepalive);

    PacketSendKeepalive(Peer);
    if (Peer->TimerNeedAnotherKeepalive)
    {
        Peer->TimerNeedAnotherKeepalive = FALSE;
        ModPeerTimer(Peer, &Peer->TimerSendKeepalive, -SEC_TO_SYS_TIME_UNITS(KEEPALIVE_TIMEOUT));
    }
}

static TIMER_CALLBACK ExpiredNewHandshake;
_Use_decl_annotations_
static VOID
ExpiredNewHandshake(TIMER *Timer)
{
    WG_PEER *Peer = CONTAINING_RECORD(Timer, WG_PEER, TimerNewHandshake);

    CHAR EndpointStr[SOCKADDR_STR_MAX_LEN];
    SockaddrToString(EndpointStr, &Peer->Endpoint.Addr);
    LogInfo(
        Peer->Device,
        "Retrying handshake with peer %llu (%s) because we stopped hearing back after %d seconds",
        Peer->InternalId,
        EndpointStr,
        KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
    /* We clear the endpoint address src address, in case this is the cause
     * of trouble.
     */
    SocketClearPeerEndpointSrc(Peer);
    PacketSendQueuedHandshakeInitiation(Peer, FALSE);
}

static TIMER_CALLBACK ExpiredZeroKeyMaterial;
_Use_decl_annotations_
static VOID
ExpiredZeroKeyMaterial(TIMER *Timer)
{
    WG_PEER *Peer = CONTAINING_RECORD(Timer, WG_PEER, TimerZeroKeyMaterial);

    if (!ExAcquireRundownProtection(&Peer->InUse))
        return;

    CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    LogInfo(
        Peer->Device,
        "Zeroing out all keys for peer %llu (%s), since we haven't received a new one in %d seconds",
        Peer->InternalId,
        EndpointName,
        REJECT_AFTER_TIME * 3);

    PeerGet(Peer);
    WriteNoFence16(&Peer->HandshakeTxAction, HANDSHAKE_TX_CLEAR);

    if (PeerSerialEnqueueIfNotBusy(&Peer->Device->HandshakeTxQueue, &Peer->HandshakeTxSerialEntry, TRUE))
        MulticoreWorkQueueBump(&Peer->Device->HandshakeTxThreads);
    else
    {
        /* If the work was already on the queue, we want to drop the extra reference. */
        ExReleaseRundownProtection(&Peer->InUse);
        PeerPut(Peer);
    }
}

static TIMER_CALLBACK ExpiredSendPersistentKeepalive;
_Use_decl_annotations_
static VOID
ExpiredSendPersistentKeepalive(TIMER *Timer)
{
    WG_PEER *Peer = CONTAINING_RECORD(Timer, WG_PEER, TimerPersistentKeepalive);

    if (Peer->PersistentKeepaliveInterval)
        PacketSendKeepalive(Peer);
}

/* Should be called after an authenticated data packet is sent. */
_Use_decl_annotations_
VOID
TimersDataSent(WG_PEER *Peer)
{
    if (!TimerIsPending(&Peer->TimerNewHandshake))
        ModPeerTimer(
            Peer,
            &Peer->TimerNewHandshake,
            -(SEC_TO_SYS_TIME_UNITS(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) +
              GenerateJitter(REKEY_TIMEOUT_JITTER_MAX_SYS_TIME_UNITS)));
}

/* Should be called after an authenticated data packet is received. */
_Use_decl_annotations_
VOID
TimersDataReceived(WG_PEER *Peer)
{
    if (ReadBooleanNoFence(&Peer->Device->IsUp))
    {
        if (!TimerIsPending(&Peer->TimerSendKeepalive))
            ModPeerTimer(Peer, &Peer->TimerSendKeepalive, -SEC_TO_SYS_TIME_UNITS(KEEPALIVE_TIMEOUT));
        else
            Peer->TimerNeedAnotherKeepalive = TRUE;
    }
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
_Use_decl_annotations_
VOID
TimersAnyAuthenticatedPacketSent(WG_PEER *Peer)
{
    TimerDelete(&Peer->TimerSendKeepalive);
}

/* Should be called after any type of authenticated packet is received, whether
 * keepalive, data, or handshake.
 */
_Use_decl_annotations_
VOID
TimersAnyAuthenticatedPacketReceived(WG_PEER *Peer)
{
    TimerDelete(&Peer->TimerNewHandshake);
}

/* Should be called after a handshake initiation message is sent. */
_Use_decl_annotations_
VOID
TimersHandshakeInitiated(WG_PEER *Peer)
{
    ModPeerTimer(
        Peer,
        &Peer->TimerRetransmitHandshake,
        -(SEC_TO_SYS_TIME_UNITS(REKEY_TIMEOUT) + GenerateJitter(REKEY_TIMEOUT_JITTER_MAX_SYS_TIME_UNITS)));
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
_Use_decl_annotations_
VOID
TimersHandshakeComplete(WG_PEER *Peer)
{
    TimerDelete(&Peer->TimerRetransmitHandshake);
    Peer->TimerHandshakeAttempts = 0;
    Peer->SentLastminuteHandshake = FALSE;
    KeQuerySystemTime(&Peer->WalltimeLastHandshake);
}

/* Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
_Use_decl_annotations_
VOID
TimersSessionDerived(WG_PEER *Peer)
{
    ModPeerTimer(Peer, &Peer->TimerZeroKeyMaterial, -SEC_TO_SYS_TIME_UNITS(REJECT_AFTER_TIME * 3));
}

/* Should be called before a packet with authentication, whether
 * keepalive, data, or handshakem is sent, or after one is received.
 */
_Use_decl_annotations_
VOID
TimersAnyAuthenticatedPacketTraversal(WG_PEER *Peer)
{
    if (Peer->PersistentKeepaliveInterval)
        ModPeerTimer(Peer, &Peer->TimerPersistentKeepalive, -SEC_TO_SYS_TIME_UNITS(Peer->PersistentKeepaliveInterval));
}

_Use_decl_annotations_
VOID
TimersInit(WG_PEER *Peer)
{
    TimerInit(&Peer->TimerRetransmitHandshake, ExpiredRetransmitHandshake);
    TimerInit(&Peer->TimerSendKeepalive, ExpiredSendKeepalive);
    TimerInit(&Peer->TimerNewHandshake, ExpiredNewHandshake);
    TimerInit(&Peer->TimerZeroKeyMaterial, ExpiredZeroKeyMaterial);
    TimerInit(&Peer->TimerPersistentKeepalive, ExpiredSendPersistentKeepalive);
    Peer->TimerHandshakeAttempts = 0;
    Peer->SentLastminuteHandshake = FALSE;
    Peer->TimerNeedAnotherKeepalive = FALSE;
    CryptoRandom((UCHAR *)&JitterSeed, sizeof(JitterSeed));
}

_Use_decl_annotations_
VOID
TimersStop(WG_PEER *Peer)
{
    TimerDelete(&Peer->TimerRetransmitHandshake);
    TimerDelete(&Peer->TimerSendKeepalive);
    TimerDelete(&Peer->TimerNewHandshake);
    TimerDelete(&Peer->TimerZeroKeyMaterial);
    TimerDelete(&Peer->TimerPersistentKeepalive);
    KeFlushQueuedDpcs();
}
