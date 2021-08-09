/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "crypto.h"
#include "device.h"
#include "messages.h"
#include "noise.h"
#include "peer.h"
#include "peerlookup.h"
#include "queueing.h"
#include "logging.h"

#pragma warning(disable : 4295) /* array is too small to include a terminating null character */

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static CONST UINT8 HandshakeName[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static CONST UINT8 IdentifierName[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static UINT8 HandshakeInitHash[NOISE_HASH_LEN];
static UINT8 HandshakeInitChainingKey[NOISE_HASH_LEN];
static LONG64 KeypairCounter = 0;

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, NoiseDriverEntry)
#endif
VOID NoiseDriverEntry(VOID)
{
    BLAKE2S_STATE Blake;

    Blake2s(HandshakeInitChainingKey, HandshakeName, NULL, NOISE_HASH_LEN, sizeof(HandshakeName), 0);
    Blake2sInit(&Blake, NOISE_HASH_LEN);
    Blake2sUpdate(&Blake, HandshakeInitChainingKey, NOISE_HASH_LEN);
    Blake2sUpdate(&Blake, IdentifierName, sizeof(IdentifierName));
    Blake2sFinal(&Blake, HandshakeInitHash);
}

_Use_decl_annotations_
VOID
NoisePrecomputeStaticStatic(WG_PEER *Peer)
{
    MuAcquirePushLockExclusive(&Peer->Handshake.Lock);
    if (!Peer->Handshake.StaticIdentity->HasIdentity || !Curve25519(
                                                            Peer->Handshake.PrecomputedStaticStatic,
                                                            Peer->Handshake.StaticIdentity->StaticPrivate,
                                                            Peer->Handshake.RemoteStatic))
        RtlZeroMemory(Peer->Handshake.PrecomputedStaticStatic, NOISE_PUBLIC_KEY_LEN);
    MuReleasePushLockExclusive(&Peer->Handshake.Lock);
}

_Use_decl_annotations_
VOID
NoiseHandshakeInit(
    NOISE_HANDSHAKE *Handshake,
    NOISE_STATIC_IDENTITY *StaticIdentity,
    CONST UINT8 PeerPublicKey[NOISE_PUBLIC_KEY_LEN],
    CONST UINT8 PeerPresharedKey[NOISE_SYMMETRIC_KEY_LEN],
    WG_PEER *Peer)
{
    RtlZeroMemory(Handshake, sizeof(*Handshake));
    MuInitializePushLock(&Handshake->Lock);
    Handshake->Entry.Type = INDEX_HASHTABLE_HANDSHAKE;
    Handshake->Entry.Peer = Peer;
    RtlCopyMemory(Handshake->RemoteStatic, PeerPublicKey, NOISE_PUBLIC_KEY_LEN);
    if (PeerPresharedKey)
        RtlCopyMemory(Handshake->PresharedKey, PeerPresharedKey, NOISE_SYMMETRIC_KEY_LEN);
    Handshake->StaticIdentity = StaticIdentity;
    Handshake->State = HANDSHAKE_ZEROED;
    NoisePrecomputeStaticStatic(Peer);
}

static VOID
HandshakeZero(_Out_ NOISE_HANDSHAKE *Handshake)
{
    RtlZeroMemory(&Handshake->EphemeralPrivate, NOISE_PUBLIC_KEY_LEN);
    RtlZeroMemory(&Handshake->RemoteEphemeral, NOISE_PUBLIC_KEY_LEN);
    RtlZeroMemory(&Handshake->Hash, NOISE_HASH_LEN);
    RtlZeroMemory(&Handshake->ChainingKey, NOISE_HASH_LEN);
    Handshake->RemoteIndex = 0;
    Handshake->State = HANDSHAKE_ZEROED;
}

_Use_decl_annotations_
VOID
NoiseHandshakeClear(NOISE_HANDSHAKE *Handshake)
{
    MuAcquirePushLockExclusive(&Handshake->Lock);
    IndexHashtableRemove(Handshake->Entry.Peer->Device->IndexHashtable, &Handshake->Entry);
    HandshakeZero(Handshake);
    MuReleasePushLockExclusive(&Handshake->Lock);
}

_Must_inspect_result_
_Post_maybenull_
_Return_type_success_(return != NULL)
static __drv_allocatesMem(Mem) NOISE_KEYPAIR *
KeypairCreate(_In_ WG_PEER *Peer)
{
    NOISE_KEYPAIR *Keypair = MemAllocateAndZero(sizeof(*Keypair));

    if (!Keypair)
        return NULL;
    KeInitializeSpinLock(&Keypair->ReceivingCounter.Lock);
    Keypair->InternalId = InterlockedIncrement64(&KeypairCounter);
    Keypair->Entry.Type = INDEX_HASHTABLE_KEYPAIR;
    Keypair->Entry.Peer = Peer;
    KrefInit(&Keypair->Refcount);
    return Keypair;
}

static RCU_CALLBACK_FN KeypairFreeRcu;
_Use_decl_annotations_
static VOID
KeypairFreeRcu(RCU_CALLBACK *Rcu)
{
    MemFreeSensitive(CONTAINING_RECORD(Rcu, NOISE_KEYPAIR, Rcu), sizeof(NOISE_KEYPAIR));
}

static VOID
KeypairFreeKref(_In_ KREF *Kref)
{
    NOISE_KEYPAIR *Keypair = CONTAINING_RECORD(Kref, NOISE_KEYPAIR, Refcount);

    LogInfoRatelimited(
        Keypair->Entry.Peer->Device,
        "Keypair %llu destroyed for peer %llu",
        Keypair->InternalId,
        Keypair->Entry.Peer->InternalId);
    IndexHashtableRemove(Keypair->Entry.Peer->Device->IndexHashtable, &Keypair->Entry);
    RcuCall(&Keypair->Rcu, KeypairFreeRcu);
}

_Use_decl_annotations_
VOID
NoiseKeypairPut(NOISE_KEYPAIR *Keypair, BOOLEAN UnreferenceNow)
{
    if (!Keypair)
        return;
    if (UnreferenceNow)
        IndexHashtableRemove(Keypair->Entry.Peer->Device->IndexHashtable, &Keypair->Entry);
    KrefPut(&Keypair->Refcount, KeypairFreeKref);
}

_Use_decl_annotations_
NOISE_KEYPAIR *
NoiseKeypairGet(NOISE_KEYPAIR *Keypair)
{
    if (!Keypair || !KrefGetUnlessZero(&Keypair->Refcount))
        return NULL;
    return Keypair;
}

_Use_decl_annotations_
VOID
NoiseKeypairsClear(NOISE_KEYPAIRS *Keypairs)
{
    NOISE_KEYPAIR *Old;
    KIRQL Irql;

    KeAcquireSpinLock(&Keypairs->KeypairUpdateLock, &Irql);

    /* We zero the next_keypair before zeroing the others, so that
     * wg_noise_received_with_keypair returns early before subsequent ones
     * are zeroed.
     */
    Old = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->NextKeypair, &Keypairs->KeypairUpdateLock);
    RcuInitPointer(Keypairs->NextKeypair, NULL);
    NoiseKeypairPut(Old, TRUE);

    Old = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->PreviousKeypair, &Keypairs->KeypairUpdateLock);
    RcuInitPointer(Keypairs->PreviousKeypair, NULL);
    NoiseKeypairPut(Old, TRUE);

    Old = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->CurrentKeypair, &Keypairs->KeypairUpdateLock);
    RcuInitPointer(Keypairs->CurrentKeypair, NULL);
    NoiseKeypairPut(Old, TRUE);

    KeReleaseSpinLock(&Keypairs->KeypairUpdateLock, Irql);
}

_Use_decl_annotations_
VOID
NoiseExpireCurrentPeerKeypairs(WG_PEER *Peer)
{
    NOISE_KEYPAIR *Keypair;
    KIRQL Irql;

    NoiseHandshakeClear(&Peer->Handshake);
    NoiseResetLastSentHandshake(&Peer->LastSentHandshake);

    KeAcquireSpinLock(&Peer->Keypairs.KeypairUpdateLock, &Irql);
    Keypair = RcuDereferenceProtected(NOISE_KEYPAIR, Peer->Keypairs.NextKeypair, &Peer->Keypairs.KeypairUpdateLock);
    if (Keypair)
        Keypair->Sending.IsValid = FALSE;
    Keypair = RcuDereferenceProtected(NOISE_KEYPAIR, Peer->Keypairs.CurrentKeypair, &Peer->Keypairs.KeypairUpdateLock);
    if (Keypair)
        Keypair->Sending.IsValid = FALSE;
    KeReleaseSpinLock(&Peer->Keypairs.KeypairUpdateLock, Irql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Keypairs->KeypairUpdateLock)
static VOID
AddNewKeypair(_Inout_ NOISE_KEYPAIRS *Keypairs, _In_ __drv_aliasesMem NOISE_KEYPAIR *NewKeypair)
{
    NOISE_KEYPAIR *PreviousKeypair, *NextKeypair, *CurrentKeypair;
    KIRQL Irql;

    KeAcquireSpinLock(&Keypairs->KeypairUpdateLock, &Irql);
    PreviousKeypair = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->PreviousKeypair, &Keypairs->KeypairUpdateLock);
    NextKeypair = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->NextKeypair, &Keypairs->KeypairUpdateLock);
    CurrentKeypair = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->CurrentKeypair, &Keypairs->KeypairUpdateLock);
    if (NewKeypair->IAmTheInitiator)
    {
        /* If we're the initiator, it means we've sent a handshake, and
         * received a confirmation response, which means this new
         * keypair can now be used.
         */
        if (NextKeypair)
        {
            /* If there already was a next keypair pending, we
             * demote it to be the previous keypair, and free the
             * existing current. Note that this means KCI can result
             * in this transition. It would perhaps be more sound to
             * always just get rid of the unused next keypair
             * instead of putting it in the previous slot, but this
             * might be a bit less robust. Something to think about
             * for the future.
             */
            RcuInitPointer(Keypairs->NextKeypair, NULL);
            RcuAssignPointer(Keypairs->PreviousKeypair, NextKeypair);
            NoiseKeypairPut(CurrentKeypair, TRUE);
        }
        else /* If there wasn't an existing next keypair, we replace
              * the previous with the current one.
              */
            RcuAssignPointer(Keypairs->PreviousKeypair, CurrentKeypair);
        /* At this point we can get rid of the old previous keypair, and
         * set up the new keypair.
         */
        NoiseKeypairPut(PreviousKeypair, TRUE);
        RcuAssignPointer(Keypairs->CurrentKeypair, NewKeypair);
    }
    else
    {
        /* If we're the responder, it means we can't use the new keypair
         * until we receive confirmation via the first data packet, so
         * we get rid of the existing previous one, the possibly
         * existing next one, and slide in the new next one.
         */
        RcuAssignPointer(Keypairs->NextKeypair, NewKeypair);
        NoiseKeypairPut(NextKeypair, TRUE);
        RcuInitPointer(Keypairs->PreviousKeypair, NULL);
        NoiseKeypairPut(PreviousKeypair, TRUE);
    }
    KeReleaseSpinLock(&Keypairs->KeypairUpdateLock, Irql);
}

_Use_decl_annotations_
BOOLEAN
NoiseReceivedWithKeypair(NOISE_KEYPAIRS *Keypairs, NOISE_KEYPAIR *ReceivedKeypair)
{
    NOISE_KEYPAIR *OldKeypair;
    BOOLEAN KeyIsNew;
    KIRQL Irql;

    /* We first check without taking the spinlock. */
    KeyIsNew = ReceivedKeypair == RcuAccessPointer(Keypairs->NextKeypair);
    if (!KeyIsNew)
        return FALSE;

    KeAcquireSpinLock(&Keypairs->KeypairUpdateLock, &Irql);
    /* After locking, we double check that things didn't change from
     * beneath us.
     */
    if (ReceivedKeypair != RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->NextKeypair, &Keypairs->KeypairUpdateLock))
    {
        KeReleaseSpinLock(&Keypairs->KeypairUpdateLock, Irql);
        return FALSE;
    }

    /* When we've finally received the confirmation, we slide the next
     * into the current, the current into the previous, and get rid of
     * the old previous.
     */
    OldKeypair = RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->PreviousKeypair, &Keypairs->KeypairUpdateLock);
    RcuAssignPointer(
        Keypairs->PreviousKeypair,
        RcuDereferenceProtected(NOISE_KEYPAIR, Keypairs->CurrentKeypair, &Keypairs->KeypairUpdateLock));
    NoiseKeypairPut(OldKeypair, TRUE);
    RcuAssignPointer(Keypairs->CurrentKeypair, ReceivedKeypair);
    RcuInitPointer(Keypairs->NextKeypair, NULL);

    KeReleaseSpinLock(&Keypairs->KeypairUpdateLock, Irql);
    return TRUE;
}

_Use_decl_annotations_
VOID
NoiseSetStaticIdentityPrivateKey(NOISE_STATIC_IDENTITY *StaticIdentity, CONST UINT8 PrivateKey[NOISE_PUBLIC_KEY_LEN])
{
    RtlCopyMemory(StaticIdentity->StaticPrivate, PrivateKey, NOISE_PUBLIC_KEY_LEN);
    Curve25519ClampSecret(StaticIdentity->StaticPrivate);
    StaticIdentity->HasIdentity = Curve25519GeneratePublic(StaticIdentity->StaticPublic, PrivateKey);
}

_Use_decl_annotations_
VOID
NoiseStaticIdentityClear(NOISE_STATIC_IDENTITY *StaticIdentity)
{
    MuAcquirePushLockExclusive(&StaticIdentity->Lock);
    RtlSecureZeroMemory(&StaticIdentity->StaticPublic, NOISE_PUBLIC_KEY_LEN);
    RtlSecureZeroMemory(&StaticIdentity->StaticPrivate, NOISE_PUBLIC_KEY_LEN);
    StaticIdentity->HasIdentity = FALSE;
    MuReleasePushLockExclusive(&StaticIdentity->Lock);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static VOID
Kdf(_Out_writes_bytes_all_opt_(FirstLen) UINT8 *FirstDst,
    _Out_writes_bytes_all_opt_(SecondLen) UINT8 *SecondDst,
    _Out_writes_bytes_all_opt_(ThirdLen) UINT8 *ThirdDst,
    _In_reads_bytes_(DataLen) CONST UINT8 *Data,
    _In_ CONST SIZE_T FirstLen,
    _In_ CONST SIZE_T SecondLen,
    _In_ CONST SIZE_T ThirdLen,
    _In_ CONST SIZE_T DataLen,
    _In_ CONST UINT8 ChainingKey[NOISE_HASH_LEN])
{
    UINT8 Output[BLAKE2S_HASH_SIZE + 1];
    UINT8 Secret[BLAKE2S_HASH_SIZE];
    NT_ASSERT(
        !(FirstLen > BLAKE2S_HASH_SIZE || SecondLen > BLAKE2S_HASH_SIZE || ThirdLen > BLAKE2S_HASH_SIZE ||
          ((SecondLen || SecondDst || ThirdLen || ThirdDst) && (!FirstLen || !FirstDst)) ||
          ((ThirdLen || ThirdDst) && (!SecondLen || !SecondDst))));
    _Analysis_assume_(RtlFillMemory(Output, sizeof(Output), 'A'));

    /* Extract entropy from data into secret */
    Blake2s256Hmac(Secret, Data, ChainingKey, DataLen, NOISE_HASH_LEN);

    if (!FirstDst || !FirstLen)
        goto out;

    /* Expand first key: key = secret, data = 0x1 */
    Output[0] = 1;
    Blake2s256Hmac(Output, Output, Secret, 1, BLAKE2S_HASH_SIZE);
    RtlCopyMemory(FirstDst, Output, FirstLen);

    if (!SecondDst || !SecondLen)
        goto out;

    /* Expand second key: key = secret, data = first-key || 0x2 */
    Output[BLAKE2S_HASH_SIZE] = 2;
    Blake2s256Hmac(Output, Output, Secret, BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
    RtlCopyMemory(SecondDst, Output, SecondLen);

    if (!ThirdDst || !ThirdLen)
        goto out;

    /* Expand third key: key = secret, data = second-key || 0x3 */
    Output[BLAKE2S_HASH_SIZE] = 3;
    Blake2s256Hmac(Output, Output, Secret, BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
    RtlCopyMemory(ThirdDst, Output, ThirdLen);

out:
    /* Clear sensitive data from stack */
    RtlSecureZeroMemory(Secret, BLAKE2S_HASH_SIZE);
    RtlSecureZeroMemory(Output, BLAKE2S_HASH_SIZE + 1);
}

static VOID
DeriveKeys(
    _Out_ NOISE_SYMMETRIC_KEY *FirstDst,
    _Out_ NOISE_SYMMETRIC_KEY *SecondDst,
    _In_ CONST UINT8 ChainingKey[NOISE_HASH_LEN])
{
    UINT64 Birthdate = KeQueryInterruptTime();
    Kdf(FirstDst->Key, SecondDst->Key, NULL, NULL, NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0, ChainingKey);
    FirstDst->Birthdate = SecondDst->Birthdate = Birthdate;
    FirstDst->IsValid = SecondDst->IsValid = TRUE;
}

_Must_inspect_result_
_Return_type_success_(return != FALSE)
static BOOLEAN
MixDh(
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 ChainingKey[NOISE_HASH_LEN],
    _Out_writes_bytes_all_opt_(NOISE_SYMMETRIC_KEY_LEN) UINT8 Key[NOISE_SYMMETRIC_KEY_LEN],
    _In_count_(NOISE_PUBLIC_KEY_LEN) CONST UINT8 Private[NOISE_PUBLIC_KEY_LEN],
    _In_count_(NOISE_PUBLIC_KEY_LEN) CONST UINT8 Public[NOISE_PUBLIC_KEY_LEN])
{
    UINT8 DhCalculation[NOISE_PUBLIC_KEY_LEN];

    if (!Curve25519(DhCalculation, Private, Public))
        return FALSE;
    Kdf(ChainingKey,
        Key,
        NULL,
        DhCalculation,
        NOISE_HASH_LEN,
        NOISE_SYMMETRIC_KEY_LEN,
        0,
        NOISE_PUBLIC_KEY_LEN,
        ChainingKey);
    RtlSecureZeroMemory(DhCalculation, NOISE_PUBLIC_KEY_LEN);
    return TRUE;
}

_Must_inspect_result_
_Return_type_success_(return != FALSE)
static BOOLEAN
MixPrecomputedDh(
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 ChainingKey[NOISE_HASH_LEN],
    _Out_writes_bytes_all_opt_(NOISE_SYMMETRIC_KEY_LEN) UINT8 Key[NOISE_SYMMETRIC_KEY_LEN],
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) CONST UINT8 Precomputed[NOISE_PUBLIC_KEY_LEN])
{
    if (CryptoIsZero32(Precomputed))
        return FALSE;
    Kdf(ChainingKey,
        Key,
        NULL,
        Precomputed,
        NOISE_HASH_LEN,
        NOISE_SYMMETRIC_KEY_LEN,
        0,
        NOISE_PUBLIC_KEY_LEN,
        ChainingKey);
    return TRUE;
}

static VOID
MixHash(
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 Hash[NOISE_HASH_LEN],
    _In_reads_bytes_(SrcLen) CONST UINT8 *Src,
    _In_ SIZE_T SrcLen)
{
    BLAKE2S_STATE Blake;

    Blake2sInit(&Blake, NOISE_HASH_LEN);
    Blake2sUpdate(&Blake, Hash, NOISE_HASH_LEN);
    Blake2sUpdate(&Blake, Src, SrcLen);
    Blake2sFinal(&Blake, Hash);
}

static VOID
MixPsk(
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 ChainingKey[NOISE_HASH_LEN],
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 Hash[NOISE_HASH_LEN],
    _Out_writes_bytes_all_opt_(NOISE_SYMMETRIC_KEY_LEN) UINT8 Key[NOISE_SYMMETRIC_KEY_LEN],
    _In_reads_bytes_(NOISE_SYMMETRIC_KEY_LEN) CONST UINT8 Psk[NOISE_SYMMETRIC_KEY_LEN])
{
    UINT8 TempHash[NOISE_HASH_LEN];

    Kdf(ChainingKey,
        TempHash,
        Key,
        Psk,
        NOISE_HASH_LEN,
        NOISE_HASH_LEN,
        NOISE_SYMMETRIC_KEY_LEN,
        NOISE_SYMMETRIC_KEY_LEN,
        ChainingKey);
    MixHash(Hash, TempHash, NOISE_HASH_LEN);
    RtlSecureZeroMemory(TempHash, NOISE_HASH_LEN);
}

static VOID
HandshakeInit(
    _Out_writes_bytes_all_(NOISE_HASH_LEN) UINT8 ChainingKey[NOISE_HASH_LEN],
    _Out_writes_bytes_all_(NOISE_HASH_LEN) UINT8 Hash[NOISE_HASH_LEN],
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) CONST UINT8 RemoteStatic[NOISE_PUBLIC_KEY_LEN])
{
    RtlCopyMemory(Hash, HandshakeInitHash, NOISE_HASH_LEN);
    RtlCopyMemory(ChainingKey, HandshakeInitChainingKey, NOISE_HASH_LEN);
    MixHash(Hash, RemoteStatic, NOISE_PUBLIC_KEY_LEN);
}

static VOID
MessageEncrypt(
    _Out_writes_bytes_all_(SrcLen + CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *DstCiphertext,
    _In_reads_bytes_(SrcLen) CONST UINT8 *SrcPlaintext,
    _In_ SIZE_T SrcLen,
    _In_ CONST UINT8 Key[NOISE_SYMMETRIC_KEY_LEN],
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 Hash[NOISE_HASH_LEN])
{
    ChaCha20Poly1305Encrypt(
        DstCiphertext, SrcPlaintext, SrcLen, Hash, NOISE_HASH_LEN, 0 /* Always zero for Noise_IK */, Key);
    MixHash(Hash, DstCiphertext, NoiseEncryptedLen(SrcLen));
}

_Must_inspect_result_
_Return_type_success_(return != FALSE)
static BOOLEAN
MessageDecrypt(
    _Out_writes_bytes_all_(SrcLen - CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *DstPlaintext,
    _In_reads_bytes_(SrcLen) CONST UINT8 *SrcCiphertext,
    _In_ SIZE_T SrcLen,
    _In_ CONST UINT8 Key[NOISE_SYMMETRIC_KEY_LEN],
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 Hash[NOISE_HASH_LEN])
{
    if (!ChaCha20Poly1305Decrypt(
            DstPlaintext, SrcCiphertext, SrcLen, Hash, NOISE_HASH_LEN, 0 /* Always zero for Noise_IK */, Key))
        return FALSE;
    MixHash(Hash, SrcCiphertext, SrcLen);
    return TRUE;
}

static VOID
MessageEphemeral(
    _Out_writes_bytes_all_(NOISE_PUBLIC_KEY_LEN) UINT8 EphemeralDst[NOISE_PUBLIC_KEY_LEN],
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) CONST UINT8 EphemeralSrc[NOISE_PUBLIC_KEY_LEN],
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 ChainingKey[NOISE_HASH_LEN],
    _Inout_updates_all_(NOISE_HASH_LEN) UINT8 Hash[NOISE_HASH_LEN])
{
    if (EphemeralDst != EphemeralSrc)
        RtlCopyMemory(EphemeralDst, EphemeralSrc, NOISE_PUBLIC_KEY_LEN);
    else
        _Analysis_assume_((RtlCopyMemory(EphemeralDst, EphemeralSrc, NOISE_PUBLIC_KEY_LEN), TRUE));
    MixHash(Hash, EphemeralSrc, NOISE_PUBLIC_KEY_LEN);
    Kdf(ChainingKey, NULL, NULL, EphemeralSrc, NOISE_HASH_LEN, 0, 0, NOISE_PUBLIC_KEY_LEN, ChainingKey);
}

static VOID
Tai64nNow(_Out_writes_bytes_all_(NOISE_TIMESTAMP_LEN) UINT8 Output[NOISE_TIMESTAMP_LEN])
{
    LARGE_INTEGER Now;
    INT64 Sec;
    LONG Nsec;

    KeQuerySystemTime(&Now);
    Now.QuadPart -= 11644473600LL * SYS_TIME_UNITS_PER_SEC;

    /* In order to prevent some sort of infoleak from precise timers, we
     * round down the time to the closest rounded-down power of
     * two to the maximum initiations per second allowed anyway by the
     * implementation.
     */
    Now.QuadPart =
        ALIGN_DOWN_BY_T(INT64, Now.QuadPart, RounddownPowOfTwo(SYS_TIME_UNITS_PER_SEC / INITIATIONS_PER_SECOND));
    Sec = Now.QuadPart / SYS_TIME_UNITS_PER_SEC;
    Nsec = (LONG)(Now.QuadPart % SYS_TIME_UNITS_PER_SEC) * (1000000000 / SYS_TIME_UNITS_PER_SEC);

    /* https://cr.yp.to/libtai/tai64.html */
    *(UINT64_BE *)Output = CpuToBe64(0x400000000000000aULL + Sec);
    *(UINT32_BE *)(Output + sizeof(UINT64_BE)) = CpuToBe32(Nsec);
}

_Use_decl_annotations_
BOOLEAN
NoiseHandshakeCreateInitiation(MESSAGE_HANDSHAKE_INITIATION *Dst, NOISE_HANDSHAKE *Handshake)
{
    UINT8 Timestamp[NOISE_TIMESTAMP_LEN];
    UINT8 Key[NOISE_SYMMETRIC_KEY_LEN];
    BOOLEAN Ret = FALSE;

    MuAcquirePushLockShared(&Handshake->StaticIdentity->Lock);
    MuAcquirePushLockExclusive(&Handshake->Lock);

    if (!Handshake->StaticIdentity->HasIdentity)
        goto out;

    Dst->Header.Type = CpuToLe32(MESSAGE_TYPE_HANDSHAKE_INITIATION);

    HandshakeInit(Handshake->ChainingKey, Handshake->Hash, Handshake->RemoteStatic);

    /* e */
    Curve25519GenerateSecret(Handshake->EphemeralPrivate);
    if (!Curve25519GeneratePublic(Dst->UnencryptedEphemeral, Handshake->EphemeralPrivate))
        goto out;
    MessageEphemeral(Dst->UnencryptedEphemeral, Dst->UnencryptedEphemeral, Handshake->ChainingKey, Handshake->Hash);

    /* es */
    if (!MixDh(Handshake->ChainingKey, Key, Handshake->EphemeralPrivate, Handshake->RemoteStatic))
        goto out;

    /* s */
    MessageEncrypt(
        Dst->EncryptedStatic, Handshake->StaticIdentity->StaticPublic, NOISE_PUBLIC_KEY_LEN, Key, Handshake->Hash);

    /* ss */
    if (!MixPrecomputedDh(Handshake->ChainingKey, Key, Handshake->PrecomputedStaticStatic))
        goto out;

    /* {t} */
    Tai64nNow(Timestamp);
    MessageEncrypt(Dst->EncryptedTimestamp, Timestamp, NOISE_TIMESTAMP_LEN, Key, Handshake->Hash);

    Dst->SenderIndex = IndexHashtableInsert(Handshake->Entry.Peer->Device->IndexHashtable, &Handshake->Entry);

    Handshake->State = HANDSHAKE_CREATED_INITIATION;
    Ret = TRUE;

out:
    MuReleasePushLockExclusive(&Handshake->Lock);
    MuReleasePushLockShared(&Handshake->StaticIdentity->Lock);
    RtlSecureZeroMemory(Key, NOISE_SYMMETRIC_KEY_LEN);
    return Ret;
}

_Use_decl_annotations_
WG_PEER *
NoiseHandshakeConsumeInitiation(CONST MESSAGE_HANDSHAKE_INITIATION *Src, WG_DEVICE *Wg)
{
    WG_PEER *Peer = NULL, *RetPeer = NULL;
    NOISE_HANDSHAKE *Handshake;
    BOOLEAN ReplayAttack, FloodAttack;
    UINT8 Key[NOISE_SYMMETRIC_KEY_LEN];
    UINT8 ChainingKey[NOISE_HASH_LEN];
    UINT8 Hash[NOISE_HASH_LEN];
    UINT8 S[NOISE_PUBLIC_KEY_LEN];
    UINT8 E[NOISE_PUBLIC_KEY_LEN];
    UINT8 T[NOISE_TIMESTAMP_LEN];
    UINT64 InitiationConsumption;

    MuAcquirePushLockShared(&Wg->StaticIdentity.Lock);
    if (!Wg->StaticIdentity.HasIdentity)
        goto out;

    HandshakeInit(ChainingKey, Hash, Wg->StaticIdentity.StaticPublic);

    /* e */
    MessageEphemeral(E, Src->UnencryptedEphemeral, ChainingKey, Hash);

    /* es */
    if (!MixDh(ChainingKey, Key, Wg->StaticIdentity.StaticPrivate, E))
        goto out;

    /* s */
    if (!MessageDecrypt(S, Src->EncryptedStatic, sizeof(Src->EncryptedStatic), Key, Hash))
        goto out;

    /* Lookup which peer we're actually talking to */
    Peer = PubkeyHashtableLookup(Wg->PeerHashtable, S);
    if (!Peer)
        goto out;
    Handshake = &Peer->Handshake;

    /* ss */
    if (!MixPrecomputedDh(ChainingKey, Key, Handshake->PrecomputedStaticStatic))
        goto out;

    /* {t} */
    if (!MessageDecrypt(T, Src->EncryptedTimestamp, sizeof(Src->EncryptedTimestamp), Key, Hash))
        goto out;

    MuAcquirePushLockShared(&Handshake->Lock);
    ReplayAttack = memcmp(T, Handshake->LatestTimestamp, NOISE_TIMESTAMP_LEN) <= 0;
    FloodAttack = (INT64)Handshake->LastInitiationConsumption + SYS_TIME_UNITS_PER_SEC / INITIATIONS_PER_SECOND >
                  (INT64)KeQueryInterruptTime();
    MuReleasePushLockShared(&Handshake->Lock);
    if (ReplayAttack || FloodAttack)
        goto out;

    /* Success! Copy everything to peer */
    MuAcquirePushLockExclusive(&Handshake->Lock);
    RtlCopyMemory(Handshake->RemoteEphemeral, E, NOISE_PUBLIC_KEY_LEN);
    if (memcmp(T, Handshake->LatestTimestamp, NOISE_TIMESTAMP_LEN) > 0)
        RtlCopyMemory(Handshake->LatestTimestamp, T, NOISE_TIMESTAMP_LEN);
    RtlCopyMemory(Handshake->Hash, Hash, NOISE_HASH_LEN);
    RtlCopyMemory(Handshake->ChainingKey, ChainingKey, NOISE_HASH_LEN);
    Handshake->RemoteIndex = Src->SenderIndex;
    InitiationConsumption = KeQueryInterruptTime();
    if ((INT64)(Handshake->LastInitiationConsumption - InitiationConsumption) < 0)
        Handshake->LastInitiationConsumption = InitiationConsumption;
    Handshake->State = HANDSHAKE_CONSUMED_INITIATION;
    MuReleasePushLockExclusive(&Handshake->Lock);
    RetPeer = Peer;

out:
    RtlSecureZeroMemory(Key, NOISE_SYMMETRIC_KEY_LEN);
    RtlSecureZeroMemory(Hash, NOISE_HASH_LEN);
    RtlSecureZeroMemory(ChainingKey, NOISE_HASH_LEN);
    MuReleasePushLockShared(&Wg->StaticIdentity.Lock);
    if (!RetPeer)
        PeerPut(Peer);
    return RetPeer;
}

_Use_decl_annotations_
BOOLEAN
NoiseHandshakeCreateResponse(MESSAGE_HANDSHAKE_RESPONSE *Dst, NOISE_HANDSHAKE *Handshake)
{
    UINT8 Key[NOISE_SYMMETRIC_KEY_LEN];
    BOOLEAN Ret = FALSE;

    MuAcquirePushLockShared(&Handshake->StaticIdentity->Lock);
    MuAcquirePushLockExclusive(&Handshake->Lock);

    if (Handshake->State != HANDSHAKE_CONSUMED_INITIATION)
        goto out;

    Dst->Header.Type = CpuToLe32(MESSAGE_TYPE_HANDSHAKE_RESPONSE);
    Dst->ReceiverIndex = Handshake->RemoteIndex;

    /* e */
    Curve25519GenerateSecret(Handshake->EphemeralPrivate);
    if (!Curve25519GeneratePublic(Dst->UnencryptedEphemeral, Handshake->EphemeralPrivate))
        goto out;
    MessageEphemeral(Dst->UnencryptedEphemeral, Dst->UnencryptedEphemeral, Handshake->ChainingKey, Handshake->Hash);

    /* ee */
    if (!MixDh(Handshake->ChainingKey, NULL, Handshake->EphemeralPrivate, Handshake->RemoteEphemeral))
        goto out;

    /* se */
    if (!MixDh(Handshake->ChainingKey, NULL, Handshake->EphemeralPrivate, Handshake->RemoteStatic))
        goto out;

    /* psk */
    MixPsk(Handshake->ChainingKey, Handshake->Hash, Key, Handshake->PresharedKey);

    /* {} */
    MessageEncrypt(Dst->EncryptedNothing, NULL, 0, Key, Handshake->Hash);

    Dst->SenderIndex = IndexHashtableInsert(Handshake->Entry.Peer->Device->IndexHashtable, &Handshake->Entry);

    Handshake->State = HANDSHAKE_CREATED_RESPONSE;
    Ret = TRUE;

out:
    MuReleasePushLockExclusive(&Handshake->Lock);
    MuReleasePushLockShared(&Handshake->StaticIdentity->Lock);
    RtlSecureZeroMemory(Key, NOISE_SYMMETRIC_KEY_LEN);
    return Ret;
}

_Use_decl_annotations_
WG_PEER *
NoiseHandshakeConsumeResponse(CONST MESSAGE_HANDSHAKE_RESPONSE *Src, WG_DEVICE *Wg)
{
    NOISE_HANDSHAKE_STATE State = HANDSHAKE_ZEROED;
    WG_PEER *Peer = NULL, *RetPeer = NULL;
    NOISE_HANDSHAKE *Handshake;
    UINT8 Key[NOISE_SYMMETRIC_KEY_LEN];
    UINT8 Hash[NOISE_HASH_LEN];
    UINT8 ChainingKey[NOISE_HASH_LEN];
    UINT8 E[NOISE_PUBLIC_KEY_LEN];
    UINT8 EphemeralPrivate[NOISE_PUBLIC_KEY_LEN];
    UINT8 StaticPrivate[NOISE_PUBLIC_KEY_LEN];
    UINT8 PresharedKey[NOISE_SYMMETRIC_KEY_LEN];

    MuAcquirePushLockShared(&Wg->StaticIdentity.Lock);

    if (!Wg->StaticIdentity.HasIdentity)
        goto out;

    Handshake = (NOISE_HANDSHAKE *)IndexHashtableLookup(
        Wg->IndexHashtable, INDEX_HASHTABLE_HANDSHAKE, Src->ReceiverIndex, &Peer);
    if (!Handshake)
        goto out;

    MuAcquirePushLockShared(&Handshake->Lock);
    State = Handshake->State;
    RtlCopyMemory(Hash, Handshake->Hash, NOISE_HASH_LEN);
    RtlCopyMemory(ChainingKey, Handshake->ChainingKey, NOISE_HASH_LEN);
    RtlCopyMemory(EphemeralPrivate, Handshake->EphemeralPrivate, NOISE_PUBLIC_KEY_LEN);
    RtlCopyMemory(PresharedKey, Handshake->PresharedKey, NOISE_SYMMETRIC_KEY_LEN);
    MuReleasePushLockShared(&Handshake->Lock);

    if (State != HANDSHAKE_CREATED_INITIATION)
        goto fail;

    /* e */
    MessageEphemeral(E, Src->UnencryptedEphemeral, ChainingKey, Hash);

    /* ee */
    if (!MixDh(ChainingKey, NULL, EphemeralPrivate, E))
        goto fail;

    /* se */
    if (!MixDh(ChainingKey, NULL, Wg->StaticIdentity.StaticPrivate, E))
        goto fail;

    /* psk */
    MixPsk(ChainingKey, Hash, Key, PresharedKey);

    /* {} */
    if (!MessageDecrypt(NULL, Src->EncryptedNothing, sizeof(Src->EncryptedNothing), Key, Hash))
        goto fail;

    /* Success! Copy everything to peer */
    MuAcquirePushLockExclusive(&Handshake->Lock);
    /* It's important to check that the state is still the same, while we
     * have an exclusive lock.
     */
    if (Handshake->State != State)
    {
        MuReleasePushLockExclusive(&Handshake->Lock);
        goto fail;
    }
    RtlCopyMemory(Handshake->RemoteEphemeral, E, NOISE_PUBLIC_KEY_LEN);
    RtlCopyMemory(Handshake->Hash, Hash, NOISE_HASH_LEN);
    RtlCopyMemory(Handshake->ChainingKey, ChainingKey, NOISE_HASH_LEN);
    Handshake->RemoteIndex = Src->SenderIndex;
    Handshake->State = HANDSHAKE_CONSUMED_RESPONSE;
    MuReleasePushLockExclusive(&Handshake->Lock);
    RetPeer = Peer;
    goto out;

fail:
    PeerPut(Peer);
out:
    RtlSecureZeroMemory(Key, NOISE_SYMMETRIC_KEY_LEN);
    RtlSecureZeroMemory(Hash, NOISE_HASH_LEN);
    RtlSecureZeroMemory(ChainingKey, NOISE_HASH_LEN);
    RtlSecureZeroMemory(EphemeralPrivate, NOISE_PUBLIC_KEY_LEN);
    RtlSecureZeroMemory(StaticPrivate, NOISE_PUBLIC_KEY_LEN);
    RtlSecureZeroMemory(PresharedKey, NOISE_SYMMETRIC_KEY_LEN);
    MuReleasePushLockShared(&Wg->StaticIdentity.Lock);
    return RetPeer;
}

_Use_decl_annotations_
BOOLEAN
NoiseHandshakeBeginSession(NOISE_HANDSHAKE *Handshake, NOISE_KEYPAIRS *Keypairs)
{
    NOISE_KEYPAIR *NewKeypair;
    BOOLEAN Ret = FALSE;

    MuAcquirePushLockExclusive(&Handshake->Lock);
    if (Handshake->State != HANDSHAKE_CREATED_RESPONSE && Handshake->State != HANDSHAKE_CONSUMED_RESPONSE)
        goto out;

    NewKeypair = KeypairCreate(Handshake->Entry.Peer);
    if (!NewKeypair)
        goto out;
    NewKeypair->IAmTheInitiator = Handshake->State == HANDSHAKE_CONSUMED_RESPONSE;
    NewKeypair->RemoteIndex = Handshake->RemoteIndex;

    if (NewKeypair->IAmTheInitiator)
        DeriveKeys(&NewKeypair->Sending, &NewKeypair->Receiving, Handshake->ChainingKey);
    else
        DeriveKeys(&NewKeypair->Receiving, &NewKeypair->Sending, Handshake->ChainingKey);

    HandshakeZero(Handshake);
    if (ExAcquireRundownProtection(&CONTAINING_RECORD(Handshake, WG_PEER, Handshake)->InUse))
    {
        AddNewKeypair(Keypairs, NewKeypair);
        LogInfoRatelimited(
            Handshake->Entry.Peer->Device,
            "Keypair %llu created for peer %llu",
            NewKeypair->InternalId,
            Handshake->Entry.Peer->InternalId);
        Ret =
            IndexHashtableReplace(Handshake->Entry.Peer->Device->IndexHashtable, &Handshake->Entry, &NewKeypair->Entry);
        ExReleaseRundownProtection(&CONTAINING_RECORD(Handshake, WG_PEER, Handshake)->InUse);
    }
    else
        MemFreeSensitive(NewKeypair, sizeof(NOISE_KEYPAIR));

out:
    MuReleasePushLockExclusive(&Handshake->Lock);
    return Ret;
}
