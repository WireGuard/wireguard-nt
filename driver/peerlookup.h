/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "containers.h"
#include "messages.h"
#include "crypto.h"

typedef struct _WG_PEER WG_PEER;

typedef struct _PUBKEY_HASHTABLE
{
    DECLARE_HASHTABLE(Hashtable, 11);
    SIPHASH_KEY Key;
    EX_PUSH_LOCK Lock;
} PUBKEY_HASHTABLE;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Post_maybenull_
_Return_type_success_(return != NULL)
__drv_allocatesMem(Mem)
PUBKEY_HASHTABLE *PubkeyHashtableAlloc(VOID);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Table->Lock)
VOID
PubkeyHashtableAdd(_Inout_ PUBKEY_HASHTABLE *Table, _Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Table->Lock)
VOID
PubkeyHashtableRemove(_Inout_ PUBKEY_HASHTABLE *Table, _Inout_ WG_PEER *Peer);

/* Returns a strong reference to a peer */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Post_maybenull_
WG_PEER *
PubkeyHashtableLookup(_In_ PUBKEY_HASHTABLE *Table, _In_ CONST UINT8 Pubkey[NOISE_PUBLIC_KEY_LEN]);

typedef struct _INDEX_HASHTABLE
{
    DECLARE_HASHTABLE(Hashtable, 13);
    KSPIN_LOCK Lock;
} INDEX_HASHTABLE;

typedef enum _INDEX_HASHTABLE_TYPE
{
    INDEX_HASHTABLE_HANDSHAKE = 1U << 0,
    INDEX_HASHTABLE_KEYPAIR = 1U << 1
} INDEX_HASHTABLE_TYPE;

typedef struct _INDEX_HASHTABLE_ENTRY
{
    WG_PEER *Peer;
    HLIST_NODE IndexHash;
    INDEX_HASHTABLE_TYPE Type;
    UINT32_LE Index;
} INDEX_HASHTABLE_ENTRY;

_Must_inspect_result_
_Post_maybenull_
_Return_type_success_(return != NULL)
__drv_allocatesMem(Mem)
INDEX_HASHTABLE *IndexHashtableAlloc(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Table->Lock)
UINT32_LE
IndexHashtableInsert(_Inout_ INDEX_HASHTABLE *Table, _Inout_ INDEX_HASHTABLE_ENTRY *Entry);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Table->Lock)
BOOLEAN
IndexHashtableReplace(
    _Inout_ INDEX_HASHTABLE *Table,
    _Inout_ INDEX_HASHTABLE_ENTRY *Old,
    _Inout_ INDEX_HASHTABLE_ENTRY *New);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(Table->Lock)
VOID
IndexHashtableRemove(_Inout_ INDEX_HASHTABLE *Table, _In_ INDEX_HASHTABLE_ENTRY *Entry);

_Must_inspect_result_
_Return_type_success_(return != NULL)
INDEX_HASHTABLE_ENTRY *
IndexHashtableLookup(
    _In_ INDEX_HASHTABLE *Table,
    _In_ CONST INDEX_HASHTABLE_TYPE TypeMask,
    _In_ CONST UINT32_LE Index,
    _Out_ WG_PEER **Peer);
