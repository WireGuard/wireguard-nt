/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "interlocked.h"
#include "messages.h"
#include "peerlookup.h"
#include "timers.h"
#include "rcu.h"

typedef struct _NOISE_REPLAY_COUNTER
{
    UINT64 Counter;
    KSPIN_LOCK Lock;
    ULONG_PTR Backtrack[COUNTER_BITS_TOTAL / BITS_PER_POINTER];
} NOISE_REPLAY_COUNTER;

typedef struct _NOISE_SYMMETRIC_KEY
{
    UINT8 Key[NOISE_SYMMETRIC_KEY_LEN];
    UINT64 Birthdate;
    BOOLEAN IsValid;
} NOISE_SYMMETRIC_KEY;

typedef struct _NOISE_KEYPAIR
{
    INDEX_HASHTABLE_ENTRY Entry;
    NOISE_SYMMETRIC_KEY Sending;
    LONG64 SendingCounter;
    NOISE_SYMMETRIC_KEY Receiving;
    NOISE_REPLAY_COUNTER ReceivingCounter;
    UINT32_LE RemoteIndex;
    BOOLEAN IAmTheInitiator;
    KREF Refcount;
    RCU_CALLBACK Rcu;
    UINT64 InternalId;
} NOISE_KEYPAIR;

typedef struct _NOISE_KEYPAIRS
{
    NOISE_KEYPAIR __rcu *CurrentKeypair;
    NOISE_KEYPAIR __rcu *PreviousKeypair;
    NOISE_KEYPAIR __rcu *NextKeypair;
    KSPIN_LOCK KeypairUpdateLock;
} NOISE_KEYPAIRS;

typedef struct _NOISE_STATIC_IDENTITY
{
    UINT8 StaticPublic[NOISE_PUBLIC_KEY_LEN];
    UINT8 StaticPrivate[NOISE_PUBLIC_KEY_LEN];
    EX_PUSH_LOCK Lock;
    BOOLEAN HasIdentity;
} NOISE_STATIC_IDENTITY;

typedef enum _NOISE_HANDSHAKE_STATE
{
    HANDSHAKE_ZEROED,
    HANDSHAKE_CREATED_INITIATION,
    HANDSHAKE_CONSUMED_INITIATION,
    HANDSHAKE_CREATED_RESPONSE,
    HANDSHAKE_CONSUMED_RESPONSE
} NOISE_HANDSHAKE_STATE;

typedef struct _NOISE_HANDSHAKE
{
    INDEX_HASHTABLE_ENTRY Entry;

    NOISE_HANDSHAKE_STATE State;
    UINT64 LastInitiationConsumption;

    NOISE_STATIC_IDENTITY *StaticIdentity;

    UINT8 EphemeralPrivate[NOISE_PUBLIC_KEY_LEN];
    UINT8 RemoteStatic[NOISE_PUBLIC_KEY_LEN];
    UINT8 RemoteEphemeral[NOISE_PUBLIC_KEY_LEN];
    UINT8 PrecomputedStaticStatic[NOISE_PUBLIC_KEY_LEN];

    UINT8 PresharedKey[NOISE_SYMMETRIC_KEY_LEN];

    UINT8 Hash[NOISE_HASH_LEN];
    UINT8 ChainingKey[NOISE_HASH_LEN];

    UINT8 LatestTimestamp[NOISE_TIMESTAMP_LEN];
    UINT32_LE RemoteIndex;

    /* Protects all members except the immutable (after noise_handshake_
     * init): remote_static, precomputed_static_static, static_identity.
     */
    EX_PUSH_LOCK Lock;
} NOISE_HANDSHAKE;

typedef struct _WG_DEVICE WG_DEVICE;

VOID NoiseDriverEntry(VOID);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(Peer->Device->DeviceUpdateLock)
VOID
NoiseHandshakeInit(
    _Out_ NOISE_HANDSHAKE *Handshake,
    _In_ NOISE_STATIC_IDENTITY *StaticIdentity,
    _In_ CONST UINT8 PeerPublicKey[NOISE_PUBLIC_KEY_LEN],
    _In_ CONST UINT8 PeerPresharedKey[NOISE_SYMMETRIC_KEY_LEN],
    _In_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Handshake->Lock)
VOID
NoiseHandshakeClear(_Inout_ NOISE_HANDSHAKE *Handshake);

static inline VOID
NoiseResetLastSentHandshake(_Out_ _Interlocked_operand_ LONG64 *HandshakeSysTimeUnits)
{
    WriteNoFence64(
        HandshakeSysTimeUnits, KeQueryInterruptTime() - (UINT64)(REKEY_TIMEOUT + 1) * SYS_TIME_UNITS_PER_SEC);
}

VOID
NoiseKeypairPut(_In_opt_ NOISE_KEYPAIR *Keypair, _In_ BOOLEAN UnreferenceNow);

_Must_inspect_result_
_Post_maybenull_
NOISE_KEYPAIR *
NoiseKeypairGet(_Inout_opt_ NOISE_KEYPAIR *Keypair);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Keypairs->KeypairUpdateLock)
VOID
NoiseKeypairsClear(_Inout_ NOISE_KEYPAIRS *Keypairs);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Keypairs->KeypairUpdateLock)
BOOLEAN
NoiseReceivedWithKeypair(_Inout_ NOISE_KEYPAIRS *Keypairs, _In_ NOISE_KEYPAIR *ReceivedKeypair);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Peer->Keypairs.KeypairUpdateLock)
VOID
NoiseExpireCurrentPeerKeypairs(_Inout_ WG_PEER *Peer);

_Requires_exclusive_lock_held_(StaticIdentity->Lock)
VOID
NoiseSetStaticIdentityPrivateKey(
    _Inout_ NOISE_STATIC_IDENTITY *StaticIdentity,
    _In_ CONST UINT8 PrivateKey[NOISE_PUBLIC_KEY_LEN]);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(StaticIdentity->Lock)
VOID
NoiseStaticIdentityClear(_Inout_ NOISE_STATIC_IDENTITY *StaticIdentity);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(Peer->Device->DeviceUpdateLock)
_Requires_lock_not_held_(Peer->Handshake.Lock)
VOID
NoisePrecomputeStaticStatic(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Handshake->StaticIdentity->Lock)
_Requires_lock_not_held_(Handshake->Lock)
_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOLEAN
NoiseHandshakeCreateInitiation(_Out_ MESSAGE_HANDSHAKE_INITIATION *Dst, _Inout_ NOISE_HANDSHAKE *Handshake);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Wg->StaticIdentity.Lock)
_Must_inspect_result_
_Return_type_success_(return != NULL)
WG_PEER *
NoiseHandshakeConsumeInitiation(_In_ CONST MESSAGE_HANDSHAKE_INITIATION *Src, _Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Handshake->StaticIdentity->Lock)
_Requires_lock_not_held_(Handshake->Lock)
_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOLEAN
NoiseHandshakeCreateResponse(_Out_ MESSAGE_HANDSHAKE_RESPONSE *Dst, _Inout_ NOISE_HANDSHAKE *Handshake);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Wg->StaticIdentity.Lock)
_Must_inspect_result_
_Return_type_success_(return != NULL)
WG_PEER *
NoiseHandshakeConsumeResponse(_In_ CONST MESSAGE_HANDSHAKE_RESPONSE *Src, _Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Handshake->Lock)
_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOLEAN
NoiseHandshakeBeginSession(_Inout_ NOISE_HANDSHAKE *Handshake, _Inout_ NOISE_KEYPAIRS *Keypairs);
