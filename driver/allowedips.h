/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "rcu.h"
#include "arithmetic.h"
#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include <wsk.h>

typedef struct _WG_PEER WG_PEER;

typedef struct _ALLOWEDIPS_NODE ALLOWEDIPS_NODE;
struct _ALLOWEDIPS_NODE
{
    WG_PEER __rcu *Peer;
    ALLOWEDIPS_NODE __rcu *Bit[2];
    UINT8 Cidr, BitAtA, BitAtB, Bitlen;
    __declspec(align(8)) UINT8 Bits[16];

    /* Keep rarely used members at bottom to be beyond cache line. */
    ULONG_PTR ParentBitPacked;
    union
    {
        LIST_ENTRY PeerList;
        RCU_CALLBACK Rcu;
    };
};

typedef __declspec(align(4)) struct _ALLOWEDIPS_TABLE
{
    ALLOWEDIPS_NODE __rcu *Root4;
    ALLOWEDIPS_NODE __rcu *Root6;
    UINT64 Seq;
} ALLOWEDIPS_TABLE;

VOID
AllowedIpsInit(_Out_ ALLOWEDIPS_TABLE *Table);

_Requires_lock_held_(Lock)
VOID
AllowedIpsFree(_Inout_ ALLOWEDIPS_TABLE *Table, _In_ EX_PUSH_LOCK *Lock);

_Requires_lock_held_(Lock)
NTSTATUS
AllowedIpsInsertV4(
    _Inout_ ALLOWEDIPS_TABLE *Table,
    _In_ CONST IN_ADDR *Ip,
    _In_ UINT8 Cidr,
    _In_ WG_PEER *Peer,
    _In_ EX_PUSH_LOCK *Lock);

_Requires_lock_held_(Lock)
NTSTATUS
AllowedIpsInsertV6(
    _Inout_ ALLOWEDIPS_TABLE *Table,
    _In_ CONST IN6_ADDR *Ip,
    _In_ UINT8 Cidr,
    _In_ WG_PEER *Peer,
    _In_ EX_PUSH_LOCK *Lock);

_Requires_lock_held_(Lock)
VOID
AllowedIpsRemoveByPeer(_Inout_ ALLOWEDIPS_TABLE *Table, _In_ WG_PEER *Peer, _In_ EX_PUSH_LOCK *Lock);

/* The Ip pointer should be 8 byte aligned */
ADDRESS_FAMILY
AllowedIpsReadNode(_In_ CONST ALLOWEDIPS_NODE *Node, _Out_ UINT8 Ip[16], _Out_ UINT8 *Cidr);

/* These return a strong reference to a peer: */
_Must_inspect_result_
_Post_maybenull_
WG_PEER *
AllowedIpsLookupDst(_In_ ALLOWEDIPS_TABLE *Table, _In_ UINT16_BE Proto, _In_ CONST VOID *IpHdr);

_Must_inspect_result_
_Post_maybenull_
WG_PEER *
AllowedIpsLookupSrc(_In_ ALLOWEDIPS_TABLE *Table, _In_ UINT16_BE Proto, _In_ CONST VOID *IpHdr);

#ifdef DBG
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
AllowedIpsSelftest(VOID);
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
AllowedIpsDriverEntry(VOID);

_IRQL_requires_max_(APC_LEVEL)
VOID AllowedIpsUnload(VOID);
