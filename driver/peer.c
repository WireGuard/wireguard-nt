/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "containers.h"
#include "device.h"
#include "noise.h"
#include "peer.h"
#include "peerlookup.h"
#include "queueing.h"
#include "timers.h"
#include "logging.h"

static LOOKASIDE_ALIGN LOOKASIDE_LIST_EX PeerCache;
static LONG64 PeerCounter = 0;

_Use_decl_annotations_
NTSTATUS
PeerCreate(
    WG_DEVICE *Wg,
    CONST UINT8 PublicKey[NOISE_PUBLIC_KEY_LEN],
    CONST UINT8 PresharedKey[NOISE_SYMMETRIC_KEY_LEN],
    WG_PEER **Peer)
{
    if (Wg->NumPeers >= MAX_PEERS_PER_DEVICE)
        return STATUS_TOO_MANY_NODES;

    *Peer = ExAllocateFromLookasideListEx(&PeerCache);
    if (!*Peer)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(*Peer, sizeof(**Peer));

    (*Peer)->Device = Wg;
    NoiseHandshakeInit(&(*Peer)->Handshake, &Wg->StaticIdentity, PublicKey, PresharedKey, *Peer);
    (*Peer)->InternalId = InterlockedIncrement64(&PeerCounter);
    CookieInit(&(*Peer)->LatestCookie);
    TimersInit(*Peer);
    CookieCheckerPrecomputePeerKeys(*Peer);
    KeInitializeSpinLock(&(*Peer)->Keypairs.KeypairUpdateLock);
    PrevQueueInit(&(*Peer)->TxQueue);
    PrevQueueInit(&(*Peer)->RxQueue);
    KrefInit(&(*Peer)->Refcount);
    NetBufferListInitQueue(&(*Peer)->StagedPacketQueue);
    ExInitializeRundownProtection(&(*Peer)->InUse);
    NoiseResetLastSentHandshake(&(*Peer)->LastSentHandshake);
    InsertTailList(&Wg->PeerList, &(*Peer)->PeerList);
    InitializeListHead(&(*Peer)->AllowedIpsList);
    PubkeyHashtableAdd(Wg->PeerHashtable, *Peer);
    ++Wg->NumPeers;
    LogInfo(Wg, "Peer %llu created", (*Peer)->InternalId);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
WG_PEER *
PeerGetMaybeZero(WG_PEER *Peer)
{
    if (!Peer || !KrefGetUnlessZero(&Peer->Refcount))
        return NULL;
    return Peer;
}

/* We have a separate "remove" function make sure that all active places where
 * a peer is currently operating will eventually come to an end and not pass
 * their reference onto another context.
 */
_Use_decl_annotations_
VOID
PeerRemove(WG_PEER *Peer)
{
    if (!Peer)
        return;

    /* Remove from configuration-time lookup structures. */
    RemoveEntryList(&Peer->PeerList);
    InitializeListHead(&Peer->PeerList);
    AllowedIpsRemoveByPeer(&Peer->Device->PeerAllowedIps, Peer, &Peer->Device->DeviceUpdateLock);
    PubkeyHashtableRemove(Peer->Device->PeerHashtable, Peer);
    NoiseKeypairsClear(&Peer->Keypairs);
    /* Disable creation of new references and wait for old ones to go away. */
    ExWaitForRundownProtectionRelease(&Peer->InUse);
    /* Destroy all ongoing timers that were in-flight at the beginning of this function. */
    TimersStop(Peer);

    --Peer->Device->NumPeers;
    PeerPut(Peer);
}

_Use_decl_annotations_
VOID
PeerRemoveAll(WG_DEVICE *Wg)
{
    WG_PEER *Peer, *Temp;

    /* Avoid having to traverse individually for each one. */
    AllowedIpsFree(&Wg->PeerAllowedIps, &Wg->DeviceUpdateLock);

    LIST_FOR_EACH_ENTRY_SAFE (Peer, Temp, &Wg->PeerList, WG_PEER, PeerList)
    {
        _Analysis_assume_same_lock_(Peer->Device->DeviceUpdateLock, Wg->DeviceUpdateLock);
        PeerRemove(Peer);
    }
    RcuSynchronize();
}

static RCU_CALLBACK_FN RcuRelease;
_Use_decl_annotations_
static VOID
RcuRelease(RCU_CALLBACK *Rcu)
{
    WG_PEER *Peer = CONTAINING_RECORD(Rcu, WG_PEER, Rcu);

    NT_ASSERT(!PrevQueuePeek(&Peer->TxQueue) && !PrevQueuePeek(&Peer->RxQueue));

    /* The final zeroing takes care of clearing any remaining handshake key
     * material and other potentially sensitive information.
     */
    RtlSecureZeroMemory(Peer, sizeof(*Peer));
    ExFreeToLookasideListEx(&PeerCache, Peer);
}

static VOID
KrefRelease(_In_ KREF *Refcount)
{
    WG_PEER *Peer = CONTAINING_RECORD(Refcount, WG_PEER, Refcount);

    CHAR EndpointName[SOCKADDR_STR_MAX_LEN];
    SockaddrToString(EndpointName, &Peer->Endpoint.Addr);
    LogInfo(Peer->Device, "Peer %llu (%s) destroyed", Peer->InternalId, EndpointName);

    /* Remove ourself from dynamic runtime lookup structures, now that the
     * last reference is gone.
     */
    IndexHashtableRemove(Peer->Device->IndexHashtable, &Peer->Handshake.Entry);

    /* Remove any lingering packets that didn't have a chance to be
     * transmitted.
     */
    PacketPurgeStagedPackets(Peer);

    /* Free the memory used. */
    RcuCall(&Peer->Rcu, RcuRelease);
}

_Use_decl_annotations_
VOID
PeerPut(WG_PEER *Peer)
{
    if (!Peer)
        return;
    KrefPut(&Peer->Refcount, KrefRelease);
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, PeerDriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
PeerDriverEntry(VOID)
{
    return ExInitializeLookasideListEx(&PeerCache, NULL, NULL, NonPagedPool, 0, sizeof(WG_PEER), MEMORY_TAG, 0);
}

_Use_decl_annotations_
VOID PeerUnload(VOID)
{
    ExDeleteLookasideListEx(&PeerCache);
}
