/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "messages.h"

typedef struct _WG_PEER WG_PEER;
typedef struct _WG_DEVICE WG_DEVICE;

typedef struct _COOKIE_CHECKER
{
    UINT8 Secret[NOISE_HASH_LEN];
    UINT8 CookieEncryptionKey[NOISE_SYMMETRIC_KEY_LEN];
    UINT8 MessageMac1Key[NOISE_SYMMETRIC_KEY_LEN];
    UINT64 SecretBirthdate;
    EX_PUSH_LOCK SecretLock;
    WG_DEVICE *Device;
} COOKIE_CHECKER;

typedef struct _COOKIE
{
    UINT64 Birthdate;
    BOOLEAN IsValid;
    UINT8 Cookie[COOKIE_LEN];
    BOOLEAN HaveSentMac1;
    UINT8 LastMac1Sent[COOKIE_LEN];
    UINT8 CookieDecryptionKey[NOISE_SYMMETRIC_KEY_LEN];
    UINT8 MessageMac1Key[NOISE_SYMMETRIC_KEY_LEN];
    EX_PUSH_LOCK Lock;
} COOKIE;

typedef enum _COOKIE_MAC_STATE
{
    INVALID_MAC,
    VALID_MAC_BUT_NO_COOKIE,
    VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
    VALID_MAC_WITH_COOKIE
} COOKIE_MAC_STATE;

_IRQL_requires_max_(APC_LEVEL)
VOID
CookieCheckerInit(_Out_ COOKIE_CHECKER *Checker, _In_ WG_DEVICE *Wg);

_Requires_lock_held_(Checker->Device->DeviceUpdateLock)
VOID
CookieCheckerPrecomputeDeviceKeys(_Inout_ COOKIE_CHECKER *Checker);

VOID
CookieCheckerPrecomputePeerKeys(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
VOID
CookieInit(_Out_ COOKIE *Cookie);

_Must_inspect_result_
COOKIE_MAC_STATE
CookieValidatePacket(_Inout_ COOKIE_CHECKER *Checker, _In_ NET_BUFFER_LIST *Nbl, _In_ BOOLEAN CheckCookie);

_IRQL_requires_max_(APC_LEVEL)
VOID
CookieAddMacToPacket(_Inout_updates_bytes_(Len) VOID *Message, _In_ SIZE_T Len, _Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
VOID
CookieMessageCreate(
    _Out_ MESSAGE_HANDSHAKE_COOKIE *Src,
    _In_ CONST NET_BUFFER_LIST *Nbl,
    _In_ UINT32_LE Index,
    _Inout_ COOKIE_CHECKER *Checker);

_IRQL_requires_max_(APC_LEVEL)
VOID
CookieMessageConsume(_In_ MESSAGE_HANDSHAKE_COOKIE *Src, _Inout_ WG_DEVICE *Wg);
