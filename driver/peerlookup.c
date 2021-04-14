/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "containers.h"
#include "noise.h"
#include "peer.h"
#include "peerlookup.h"

_Post_notnull_
static HLIST_HEAD *
PubkeyBucket(_In_ PUBKEY_HASHTABLE *Table, _In_ CONST UINT8 Pubkey[NOISE_PUBLIC_KEY_LEN])
{
    /* siphash gives us a secure 64bit number based on a random key. Since
     * the bits are uniformly distributed, we can then mask off to get the
     * bits we need.
     */
    CONST UINT64 Hash = Siphash(Pubkey, NOISE_PUBLIC_KEY_LEN, &Table->Key);

    return &Table->Hashtable[Hash & (HASH_SIZE(Table->Hashtable) - 1)];
}

_Use_decl_annotations_
PUBKEY_HASHTABLE *PubkeyHashtableAlloc(VOID)
{
    PUBKEY_HASHTABLE *Table = MemAllocate(sizeof(*Table));
    if (!Table)
        return NULL;

    CryptoRandom(&Table->Key, sizeof(Table->Key));
    HashInit(Table->Hashtable);
    MuInitializePushLock(&Table->Lock);
    return Table;
}

_Use_decl_annotations_
VOID
PubkeyHashtableAdd(PUBKEY_HASHTABLE *Table, WG_PEER *Peer)
{
    MuAcquirePushLockExclusive(&Table->Lock);
    HlistAddHeadRcu(&Peer->PubkeyHash, PubkeyBucket(Table, Peer->Handshake.RemoteStatic));
    MuReleasePushLockExclusive(&Table->Lock);
}

_Use_decl_annotations_
VOID
PubkeyHashtableRemove(PUBKEY_HASHTABLE *Table, WG_PEER *Peer)
{
    MuAcquirePushLockExclusive(&Table->Lock);
    HlistDelInitRcu(&Peer->PubkeyHash);
    MuReleasePushLockExclusive(&Table->Lock);
}

_Use_decl_annotations_
WG_PEER *
PubkeyHashtableLookup(PUBKEY_HASHTABLE *Table, CONST UINT8 Pubkey[NOISE_PUBLIC_KEY_LEN])
{
    WG_PEER *IterPeer, *Peer = NULL;
    KIRQL Irql;

    Irql = RcuReadLock();
    HLIST_FOR_EACH_ENTRY_RCU (IterPeer, PubkeyBucket(Table, Pubkey), WG_PEER, PubkeyHash)
    {
        if (RtlEqualMemory(Pubkey, IterPeer->Handshake.RemoteStatic, NOISE_PUBLIC_KEY_LEN))
        {
            Peer = IterPeer;
            break;
        }
    }
    Peer = PeerGetMaybeZero(Peer);
    RcuReadUnlock(Irql);
    return Peer;
}

_Post_notnull_
static HLIST_HEAD *
IndexBucket(_In_ INDEX_HASHTABLE *Table, _In_ CONST UINT32_LE Index)
{
    /* Since the indices are random and thus all bits are uniformly
     * distributed, we can find its bucket simply by masking.
     */
    return &Table->Hashtable[(UINT32)Index & (HASH_SIZE(Table->Hashtable) - 1)];
}

_Use_decl_annotations_
INDEX_HASHTABLE *IndexHashtableAlloc(VOID)
{
    INDEX_HASHTABLE *Table = MemAllocate(sizeof(*Table));
    if (!Table)
        return NULL;

    HashInit(Table->Hashtable);
    KeInitializeSpinLock(&Table->Lock);
    return Table;
}

/* At the moment, we limit ourselves to 2^20 total peers, which generally might
 * amount to 2^20*3 items in this hashtable. The algorithm below works by
 * picking a random number and testing it. We can see that these limits mean we
 * usually succeed pretty quickly:
 *
 * >>> def calculation(tries, size):
 * ...     return (size / 2**32)**(tries - 1) *  (1 - (size / 2**32))
 * ...
 * >>> calculation(1, 2**20 * 3)
 * 0.999267578125
 * >>> calculation(2, 2**20 * 3)
 * 0.0007318854331970215
 * >>> calculation(3, 2**20 * 3)
 * 5.360489012673497e-07
 * >>> calculation(4, 2**20 * 3)
 * 3.9261394135792216e-10
 *
 * At the moment, we don't do any masking, so this algorithm isn't exactly
 * constant time in either the random guessing or in the hash list lookup. We
 * could require a minimum of 3 tries, which would successfully mask the
 * guessing. this would not, however, help with the growing hash lengths, which
 * is another thing to consider moving forward.
 */

_Use_decl_annotations_
UINT32_LE
IndexHashtableInsert(INDEX_HASHTABLE *Table, INDEX_HASHTABLE_ENTRY *Entry)
{
    INDEX_HASHTABLE_ENTRY *ExistingEntry;
    KIRQL Irql;

    KeAcquireSpinLock(&Table->Lock, &Irql);
    HlistDelInitRcu(&Entry->IndexHash);
    KeReleaseSpinLock(&Table->Lock, Irql);

    Irql = RcuReadLock();

searchUnusedSlot:
    /* First we try to find an unused slot, randomly, while unlocked. */
    CryptoRandom(&Entry->Index, sizeof(Entry->Index));
    HLIST_FOR_EACH_ENTRY_RCU (ExistingEntry, IndexBucket(Table, Entry->Index), INDEX_HASHTABLE_ENTRY, IndexHash)
    {
        if (ExistingEntry->Index == Entry->Index)
            /* If it's already in use, we continue searching. */
            goto searchUnusedSlot;
    }

    /* Once we've found an unused slot, we lock it, and then double-check
     * that nobody else stole it from us.
     */
    KeAcquireSpinLockAtDpcLevel(&Table->Lock);
    HLIST_FOR_EACH_ENTRY_RCU (ExistingEntry, IndexBucket(Table, Entry->Index), INDEX_HASHTABLE_ENTRY, IndexHash)
    {
        if (ExistingEntry->Index == Entry->Index)
        {
            KeReleaseSpinLockFromDpcLevel(&Table->Lock);
            /* If it was stolen, we start over. */
            goto searchUnusedSlot;
        }
    }
    /* Otherwise, we know we have it exclusively (since we're locked),
     * so we insert.
     */
    HlistAddHeadRcu(&Entry->IndexHash, IndexBucket(Table, Entry->Index));
    KeReleaseSpinLockFromDpcLevel(&Table->Lock);

    RcuReadUnlock(Irql);

    return Entry->Index;
}

_Use_decl_annotations_
BOOLEAN
IndexHashtableReplace(INDEX_HASHTABLE *Table, INDEX_HASHTABLE_ENTRY *Old, INDEX_HASHTABLE_ENTRY *New)
{
    BOOLEAN Ret;
    KIRQL Irql;

    KeAcquireSpinLock(&Table->Lock, &Irql);
    Ret = !HlistUnhashed(&Old->IndexHash);
    if (!Ret)
        goto out;

    New->Index = Old->Index;
    HlistReplaceRcu(&Old->IndexHash, &New->IndexHash);

    /* Calling init here NULLs out IndexHash, and in fact after this
     * function returns, it's theoretically possible for this to get
     * reinserted elsewhere. That means the RCU lookup below might either
     * terminate early or jump between buckets, in which case the packet
     * simply gets dropped, which isn't terrible.
     */
    HlistInit(&Old->IndexHash);
out:
    KeReleaseSpinLock(&Table->Lock, Irql);
    return Ret;
}

_Use_decl_annotations_
VOID
IndexHashtableRemove(INDEX_HASHTABLE *Table, INDEX_HASHTABLE_ENTRY *Entry)
{
    KIRQL Irql;

    KeAcquireSpinLock(&Table->Lock, &Irql);
    HlistDelInitRcu(&Entry->IndexHash);
    KeReleaseSpinLock(&Table->Lock, Irql);
}

/* Returns a strong reference to a entry->peer */
_Use_decl_annotations_
INDEX_HASHTABLE_ENTRY *
IndexHashtableLookup(INDEX_HASHTABLE *Table, CONST INDEX_HASHTABLE_TYPE TypeMask, CONST UINT32_LE Index, WG_PEER **Peer)
{
    INDEX_HASHTABLE_ENTRY *IterEntry, *Entry = NULL;
    KIRQL Irql;

    Irql = RcuReadLock();
    HLIST_FOR_EACH_ENTRY_RCU (IterEntry, IndexBucket(Table, Index), INDEX_HASHTABLE_ENTRY, IndexHash)
    {
        if (IterEntry->Index == Index)
        {
            if (IterEntry->Type & TypeMask)
                Entry = IterEntry;
            break;
        }
    }
    if (Entry)
    {
        Entry->Peer = PeerGetMaybeZero(Entry->Peer);
        if (Entry->Peer)
            *Peer = Entry->Peer;
        else
            Entry = NULL;
    }
    RcuReadUnlock(Irql);
    return Entry;
}
