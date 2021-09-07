/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "interlocked.h"
#include "cookie.h"
#include "device.h"
#include "noise.h"
#include "rcu.h"
#include "timers.h"

typedef struct _ENDPOINT
{
    SOCKADDR_INET Addr;
    struct
    {
        WSACMSGHDR Cmsg;
        union
        {
            IN_PKTINFO Src4;
            IN6_PKTINFO Src6;
        };
        UCHAR CmsgHackBuf[WSA_CMSGHDR_ALIGN(sizeof(WSACMSGHDR))];
    };
    UINT32 RoutingGeneration;
    UINT32 UpdateGeneration;
} ENDPOINT;

typedef enum _HANDSHAKE_TX_ACTION
{
    HANDSHAKE_TX_NONE = 0,
    HANDSHAKE_TX_CLEAR,
    HANDSHAKE_TX_SEND
} HANDSHAKE_TX_ACTION;

typedef struct _WG_PEER
{
    WG_DEVICE *Device;
    PREV_QUEUE TxQueue, RxQueue;
    PEER_SERIAL_ENTRY TxSerialEntry, RxSerialEntry, HandshakeTxSerialEntry;
    NET_BUFFER_LIST_QUEUE StagedPacketQueue;
    EX_RUNDOWN_REF InUse;
    NOISE_KEYPAIRS Keypairs;
    ENDPOINT Endpoint;
    EX_SPIN_LOCK EndpointLock;
    NOISE_HANDSHAKE Handshake;
    LONG64 LastSentHandshake;
    COOKIE LatestCookie;
    HLIST_NODE PubkeyHash;
    UINT64 RxBytes, TxBytes;
    TIMER TimerRetransmitHandshake, TimerSendKeepalive;
    TIMER TimerNewHandshake, TimerZeroKeyMaterial;
    TIMER TimerPersistentKeepalive;
    ULONG TimerHandshakeAttempts;
    UINT16 PersistentKeepaliveInterval;
    SHORT HandshakeTxAction;
    BOOLEAN TimerNeedAnotherKeepalive;
    BOOLEAN SentLastminuteHandshake;
    LARGE_INTEGER WalltimeLastHandshake;
    KREF Refcount;
    RCU_CALLBACK Rcu;
    LIST_ENTRY PeerList;
    LIST_ENTRY AllowedIpsList;
    UINT64 InternalId;
} WG_PEER;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_held_(Wg->DeviceUpdateLock)
_Must_inspect_result_
NTSTATUS
PeerCreate(
    _In_ WG_DEVICE *Wg,
    _In_ CONST UINT8 PublicKey[NOISE_PUBLIC_KEY_LEN],
    _In_ CONST UINT8 PresharedKey[NOISE_SYMMETRIC_KEY_LEN],
    _Out_ WG_PEER **Peer);

_Must_inspect_result_
_Post_maybenull_
WG_PEER *
PeerGetMaybeZero(_In_opt_ WG_PEER *Peer);

_Post_notnull_
static inline WG_PEER *
PeerGet(_In_ WG_PEER *Peer)
{
    KrefGet(&Peer->Refcount);
    return Peer;
}

VOID
PeerPut(_In_opt_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(Peer->Device->DeviceUpdateLock)
VOID
PeerRemove(_In_opt_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(Wg->DeviceUpdateLock)
VOID
PeerRemoveAll(_Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PeerDriverEntry(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID PeerUnload(VOID);
