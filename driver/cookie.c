/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "cookie.h"
#include "peer.h"
#include "device.h"
#include "messages.h"
#include "ratelimiter.h"
#include "timers.h"
#include "crypto.h"
#include "queueing.h"
#include "logging.h"

#pragma warning(disable : 4295) /* array is too small to include a terminating null character */

_Use_decl_annotations_
VOID
CookieCheckerInit(COOKIE_CHECKER *Checker, WG_DEVICE *Wg)
{
    MuInitializePushLock(&Checker->SecretLock);
    Checker->SecretBirthdate = KeQueryInterruptTime();
    CryptoRandom(Checker->Secret, NOISE_HASH_LEN);
    Checker->Device = Wg;
}

enum
{
    COOKIE_KEY_LABEL_LEN = 8
};
static CONST UINT8 Mac1KeyLabel[COOKIE_KEY_LABEL_LEN] = "mac1----";
static CONST UINT8 CookieKeyLabel[COOKIE_KEY_LABEL_LEN] = "cookie--";

static VOID
PrecomputeKey(
    _Out_writes_bytes_all_(NOISE_SYMMETRIC_KEY_LEN) UINT8 Key[NOISE_SYMMETRIC_KEY_LEN],
    _In_reads_bytes_(NOISE_PUBLIC_KEY_LEN) CONST UINT8 Pubkey[NOISE_PUBLIC_KEY_LEN],
    _In_reads_bytes_(COOKIE_KEY_LABEL_LEN) CONST UINT8 Label[COOKIE_KEY_LABEL_LEN])
{
    BLAKE2S_STATE Blake;

    Blake2sInit(&Blake, NOISE_SYMMETRIC_KEY_LEN);
    Blake2sUpdate(&Blake, Label, COOKIE_KEY_LABEL_LEN);
    Blake2sUpdate(&Blake, Pubkey, NOISE_PUBLIC_KEY_LEN);
    Blake2sFinal(&Blake, Key);
}

_Use_decl_annotations_
VOID
CookieCheckerPrecomputeDeviceKeys(COOKIE_CHECKER *Checker)
{
    if (Checker->Device->StaticIdentity.HasIdentity)
    {
        PrecomputeKey(Checker->CookieEncryptionKey, Checker->Device->StaticIdentity.StaticPublic, CookieKeyLabel);
        PrecomputeKey(Checker->MessageMac1Key, Checker->Device->StaticIdentity.StaticPublic, Mac1KeyLabel);
    }
    else
    {
        RtlZeroMemory(Checker->CookieEncryptionKey, NOISE_SYMMETRIC_KEY_LEN);
        RtlZeroMemory(Checker->MessageMac1Key, NOISE_SYMMETRIC_KEY_LEN);
    }
}

_Use_decl_annotations_
VOID
CookieCheckerPrecomputePeerKeys(WG_PEER *Peer)
{
    PrecomputeKey(Peer->LatestCookie.CookieDecryptionKey, Peer->Handshake.RemoteStatic, CookieKeyLabel);
    PrecomputeKey(Peer->LatestCookie.MessageMac1Key, Peer->Handshake.RemoteStatic, Mac1KeyLabel);
}

_Use_decl_annotations_
VOID
CookieInit(COOKIE *Cookie)
{
    RtlZeroMemory(Cookie, sizeof(*Cookie));
    MuInitializePushLock(&Cookie->Lock);
}

static VOID
ComputeMac1(
    _Out_writes_bytes_all_(COOKIE_LEN) UINT8 Mac1[COOKIE_LEN],
    _In_reads_bytes_(Len - sizeof(MESSAGE_MACS)) CONST VOID *Message,
    _In_ SIZE_T Len,
    _In_ CONST UINT8 Key[NOISE_SYMMETRIC_KEY_LEN])
{
    Len = Len - sizeof(MESSAGE_MACS) + FIELD_OFFSET(MESSAGE_MACS, Mac1);
    Blake2s(Mac1, Message, Key, COOKIE_LEN, Len, NOISE_SYMMETRIC_KEY_LEN);
}

static VOID
ComputeMac2(
    _Out_writes_bytes_all_(COOKIE_LEN) UINT8 Mac2[COOKIE_LEN],
    _In_reads_bytes_(Len - COOKIE_LEN) CONST VOID *Message,
    _In_ SIZE_T Len,
    _In_ CONST UINT8 Cookie[COOKIE_LEN])
{
    Len = Len - sizeof(MESSAGE_MACS) + FIELD_OFFSET(MESSAGE_MACS, Mac2);
    Blake2s(Mac2, Message, Cookie, COOKIE_LEN, Len, COOKIE_LEN);
}

_Requires_lock_not_held_(Checker->SecretLock)
_IRQL_requires_max_(APC_LEVEL)
static VOID
MakeCookie(
    _Out_writes_bytes_all_(COOKIE_LEN) UINT8 Cookie[COOKIE_LEN],
    _In_ CONST SOCKADDR *Src,
    _Inout_ COOKIE_CHECKER *Checker)
{
    BLAKE2S_STATE State;

    if (BirthdateHasExpired(Checker->SecretBirthdate, COOKIE_SECRET_MAX_AGE))
    {
        MuAcquirePushLockExclusive(&Checker->SecretLock);
        Checker->SecretBirthdate = KeQueryInterruptTime();
        CryptoRandom(Checker->Secret, NOISE_HASH_LEN);
        MuReleasePushLockExclusive(&Checker->SecretLock);
    }

    MuAcquirePushLockShared(&Checker->SecretLock);

    Blake2sInitKey(&State, COOKIE_LEN, Checker->Secret, NOISE_HASH_LEN);
    if (Src->sa_family == AF_INET)
    {
        CONST SOCKADDR_IN *Src4 = (CONST SOCKADDR_IN *)Src;
        Blake2sUpdate(&State, (UINT8 *)&Src4->sin_addr, sizeof(Src4->sin_addr));
        Blake2sUpdate(&State, (UINT8 *)&Src4->sin_port, sizeof(Src4->sin_port));
    }
    else if (Src->sa_family == AF_INET6)
    {
        CONST SOCKADDR_IN6 *Src6 = (CONST SOCKADDR_IN6 *)Src;
        Blake2sUpdate(&State, (UINT8 *)&Src6->sin6_addr, sizeof(Src6->sin6_addr));
        Blake2sUpdate(&State, (UINT8 *)&Src6->sin6_port, sizeof(Src6->sin6_port));
    }
    Blake2sFinal(&State, Cookie);

    MuReleasePushLockShared(&Checker->SecretLock);
}

_Use_decl_annotations_
COOKIE_MAC_STATE
CookieValidatePacket(COOKIE_CHECKER *Checker, NET_BUFFER_LIST *Nbl, BOOLEAN CheckCookie)
{
    CONST ULONG NblLen = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(Nbl));
    UCHAR *NblData = MemGetValidatedNetBufferListData(Nbl);
    MESSAGE_MACS *Macs = (MESSAGE_MACS *)(NblData + NblLen - sizeof(*Macs));
    COOKIE_MAC_STATE Ret;
    UINT8 ComputedMac[COOKIE_LEN];
    UINT8 Cookie[COOKIE_LEN];

    Ret = INVALID_MAC;
    ComputeMac1(ComputedMac, NblData, NblLen, Checker->MessageMac1Key);
    if (!CryptoEqualMemory16(ComputedMac, Macs->Mac1))
        goto out;

    Ret = VALID_MAC_BUT_NO_COOKIE;

    if (!CheckCookie)
        goto out;

    MakeCookie(Cookie, NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->RemoteAddress, Checker);

    ComputeMac2(ComputedMac, NblData, NblLen, Cookie);
    if (!CryptoEqualMemory16(ComputedMac, Macs->Mac2))
        goto out;

    Ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
    if (!RatelimiterAllow(NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->RemoteAddress))
        goto out;

    Ret = VALID_MAC_WITH_COOKIE;

out:
    return Ret;
}

_Use_decl_annotations_
VOID
CookieAddMacToPacket(VOID *Message, SIZE_T Len, WG_PEER *Peer)
{
    MESSAGE_MACS *Macs = (MESSAGE_MACS *)((UINT8 *)Message + Len - sizeof(*Macs));

    MuAcquirePushLockExclusive(&Peer->LatestCookie.Lock);
    ComputeMac1(Macs->Mac1, Message, Len, Peer->LatestCookie.MessageMac1Key);
    RtlCopyMemory(Peer->LatestCookie.LastMac1Sent, Macs->Mac1, COOKIE_LEN);
    Peer->LatestCookie.HaveSentMac1 = TRUE;
    MuReleasePushLockExclusive(&Peer->LatestCookie.Lock);

    MuAcquirePushLockShared(&Peer->LatestCookie.Lock);
    if (Peer->LatestCookie.IsValid &&
        !BirthdateHasExpired(Peer->LatestCookie.Birthdate, COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
        ComputeMac2(Macs->Mac2, Message, Len, Peer->LatestCookie.Cookie);
    else
        RtlZeroMemory(Macs->Mac2, COOKIE_LEN);
    MuReleasePushLockShared(&Peer->LatestCookie.Lock);
}

_Use_decl_annotations_
VOID
CookieMessageCreate(MESSAGE_HANDSHAKE_COOKIE *Dst, CONST NET_BUFFER_LIST *Nbl, UINT32_LE Index, COOKIE_CHECKER *Checker)
{
    CONST ULONG NblLen = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(Nbl));
    UCHAR *NblData = MemGetValidatedNetBufferListData(Nbl);
    MESSAGE_MACS *Macs = (MESSAGE_MACS *)(NblData + NblLen - sizeof(*Macs));
    UINT8 Cookie[COOKIE_LEN];

    Dst->Header.Type = CpuToLe32(MESSAGE_TYPE_HANDSHAKE_COOKIE);
    Dst->ReceiverIndex = Index;
    CryptoRandom(Dst->Nonce, COOKIE_NONCE_LEN);

    MakeCookie(Cookie, NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->RemoteAddress, Checker);
    XChaCha20Poly1305Encrypt(
        Dst->EncryptedCookie, Cookie, COOKIE_LEN, Macs->Mac1, COOKIE_LEN, Dst->Nonce, Checker->CookieEncryptionKey);
}

_Use_decl_annotations_
VOID
CookieMessageConsume(MESSAGE_HANDSHAKE_COOKIE *Src, WG_DEVICE *Wg)
{
    WG_PEER *Peer = NULL;
    UINT8 Cookie[COOKIE_LEN];
    BOOLEAN Ret;

    if (!IndexHashtableLookup(
            Wg->IndexHashtable, INDEX_HASHTABLE_HANDSHAKE | INDEX_HASHTABLE_KEYPAIR, Src->ReceiverIndex, &Peer))
        return;

    MuAcquirePushLockShared(&Peer->LatestCookie.Lock);
    if (!Peer->LatestCookie.HaveSentMac1)
    {
        MuReleasePushLockShared(&Peer->LatestCookie.Lock);
        goto out;
    }
    Ret = XChaCha20Poly1305Decrypt(
        Cookie,
        Src->EncryptedCookie,
        sizeof(Src->EncryptedCookie),
        Peer->LatestCookie.LastMac1Sent,
        COOKIE_LEN,
        Src->Nonce,
        Peer->LatestCookie.CookieDecryptionKey);
    MuReleasePushLockShared(&Peer->LatestCookie.Lock);

    if (Ret)
    {
        MuAcquirePushLockExclusive(&Peer->LatestCookie.Lock);
        RtlCopyMemory(Peer->LatestCookie.Cookie, Cookie, COOKIE_LEN);
        Peer->LatestCookie.Birthdate = KeQueryInterruptTime();
        Peer->LatestCookie.IsValid = TRUE;
        Peer->LatestCookie.HaveSentMac1 = FALSE;
        MuReleasePushLockExclusive(&Peer->LatestCookie.Lock);
    }
    else
        LogInfoRatelimited(Wg, "Could not decrypt invalid cookie response");

out:
    PeerPut(Peer);
}
