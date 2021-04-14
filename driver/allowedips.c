/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "allowedips.h"
#include "containers.h"
#include "peer.h"
#include "logging.h"

#define STACK_ENTRIES 128

static LOOKASIDE_ALIGN LOOKASIDE_LIST_EX NodeCache;

static VOID
SwapEndian(_Out_writes_bytes_all_(Bits / 8) UINT8 *Dst, _In_reads_bytes_(Bits / 8) CONST UINT8 *Src, _In_ UINT8 Bits)
{
    if (Bits == 32)
    {
        *(UINT32 *)Dst = Be32ToCpu(*(CONST UINT32_BE *)Src);
    }
    else if (Bits == 128)
    {
        ((UINT64 *)Dst)[0] = Be64ToCpu(((CONST UINT64_BE *)Src)[0]);
        ((UINT64 *)Dst)[1] = Be64ToCpu(((CONST UINT64_BE *)Src)[1]);
    }
}

static VOID
CopyAndAssignCidr(
    _Out_ ALLOWEDIPS_NODE *Node,
    _In_reads_bytes_(Bits / 8) CONST UINT8 *Src,
    _In_ UINT8 Cidr,
    _In_ UINT8 Bits)
{
    Node->Cidr = Cidr;
    Node->BitAtA = Cidr / 8U;
#if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
    Node->BitAtA ^= (Bits / 8U - 1U) % 8U;
#endif
    Node->BitAtB = 7U - (Cidr % 8U);
    Node->Bitlen = Bits;
    RtlCopyMemory(Node->Bits, Src, Bits / 8U);
}

static inline UINT8
Choose(_In_ CONST ALLOWEDIPS_NODE *Node, _In_ CONST UINT8 *Key)
{
    return (Key[Node->BitAtA] >> Node->BitAtB) & 1;
}

static VOID
PushRcu(_Inout_ ALLOWEDIPS_NODE *Stack[STACK_ENTRIES], _In_ ALLOWEDIPS_NODE __rcu *P, _In_ ULONG *Len)
{
    /* This lets us use it from mutex-protected or cleanup functions too. */
    _Analysis_assume_rcu_held_;
    if (RcuAccessPointer(P))
    {
        NT_ASSERT(*Len < STACK_ENTRIES);
        Stack[(*Len)++] = RcuDereference(ALLOWEDIPS_NODE, P);
    }
    _Analysis_assume_rcu_not_held_;
}

static RCU_CALLBACK_FN NodeFreeRcu;
_Use_decl_annotations_
static VOID
NodeFreeRcu(RCU_CALLBACK *Rcu)
{
    ExFreeToLookasideListEx(&NodeCache, CONTAINING_RECORD(Rcu, ALLOWEDIPS_NODE, Rcu));
}

static RCU_CALLBACK_FN RootFreeRcu;
#pragma warning(suppress : 6262) /* Using 1044 bytes of stack is still below 1280. */
_Use_decl_annotations_
static VOID
RootFreeRcu(RCU_CALLBACK *Rcu)
{
    ALLOWEDIPS_NODE *Node, *Stack[STACK_ENTRIES] = { CONTAINING_RECORD(Rcu, ALLOWEDIPS_NODE, Rcu) };
    ULONG Len = 1;

    while (Len > 0 && (Node = Stack[--Len]) != NULL)
    {
        PushRcu(Stack, Node->Bit[0], &Len);
        PushRcu(Stack, Node->Bit[1], &Len);
        ExFreeToLookasideListEx(&NodeCache, Node);
    }
}

#pragma warning(suppress : 6262) /* Using 1044 bytes of stack is still below 1280. */
static VOID
RootRemovePeerLists(_In_ ALLOWEDIPS_NODE *Root)
{
    ALLOWEDIPS_NODE *Node, *Stack[STACK_ENTRIES] = { Root };
    ULONG Len = 1;
    while (Len > 0 && (Node = Stack[--Len]) != NULL)
    {
        PushRcu(Stack, Node->Bit[0], &Len);
        PushRcu(Stack, Node->Bit[1], &Len);
        if (RcuAccessPointer(Node->Peer))
            RemoveEntryList(&Node->PeerList);
    }
}

static UINT8
CommonBits(_In_ CONST ALLOWEDIPS_NODE *Node, _In_reads_bytes_(Bits / 8) CONST UINT8 *Key, _In_ UINT8 Bits)
{
    if (Bits == 32)
        return 32 - (UINT8)FindLastSet32(*(CONST UINT32 *)Node->Bits ^ *(CONST UINT32 *)Key);
    else if (Bits == 128)
        return 128 - (UINT8)FindLastSet128(
                         *(CONST UINT64 *)&Node->Bits[0] ^ *(CONST UINT64 *)&Key[0],
                         *(CONST UINT64 *)&Node->Bits[8] ^ *(CONST UINT64 *)&Key[8]);
    return 0;
}

static BOOLEAN
PrefixMatches(_In_ CONST ALLOWEDIPS_NODE *Node, _In_reads_bytes_(Bits / 8) CONST UINT8 *Key, _In_ UINT8 Bits)
{
    /* This could be much faster if it actually just compared the common
     * bits properly, by precomputing a mask bswap(~0 << (32 - cidr)), and
     * the rest, but it turns out that common_bits is already super fast on
     * modern processors, even taking into account the unfortunate bswap.
     * So, we just inline it like this instead.
     */
    return CommonBits(Node, Key, Bits) >= Node->Cidr;
}

_Requires_rcu_held_
_Must_inspect_result_
_Post_maybenull_
static ALLOWEDIPS_NODE *
FindNode(_In_ ALLOWEDIPS_NODE *Trie, _In_ UINT8 Bits, _In_reads_bytes_(Bits / 8) CONST UINT8 *Key)
{
    ALLOWEDIPS_NODE *Node = Trie, *Found = NULL;

    while (Node && PrefixMatches(Node, Key, Bits))
    {
        if (RcuAccessPointer(Node->Peer))
            Found = Node;
        if (Node->Cidr == Bits)
            break;
        Node = RcuDereference(ALLOWEDIPS_NODE, Node->Bit[Choose(Node, Key)]);
    }
    return Found;
}

/* Returns a strong reference to a peer */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Post_maybenull_
static WG_PEER *
Lookup(_In_ ALLOWEDIPS_NODE __rcu *Root, _In_ UINT8 Bits, _In_reads_bytes_(Bits / 8) CONST VOID *BeIp)
{
    /* Aligned so it can be passed to FindLastSet/FindLastSet64 */
    __declspec(align(8)) UINT8 Ip[16];
    ALLOWEDIPS_NODE *Node;
    WG_PEER *Peer = NULL;
    KIRQL Irql;

    SwapEndian(Ip, BeIp, Bits);

    Irql = RcuReadLock();
retry:
    Node = FindNode(RcuDereference(ALLOWEDIPS_NODE, Root), Bits, Ip);
    if (Node)
    {
        Peer = PeerGetMaybeZero(RcuDereference(WG_PEER, Node->Peer));
        if (!Peer)
            goto retry;
    }
    RcuReadUnlock(Irql);
    return Peer;
}

_Requires_lock_held_(Lock)
static BOOLEAN
NodePlacement(
    _In_ ALLOWEDIPS_NODE __rcu *Trie,
    _In_reads_bytes_(Bits / 8) CONST UINT8 *Key,
    _In_ UINT8 Cidr,
    _In_ UINT8 Bits,
    _Out_ ALLOWEDIPS_NODE **Rnode,
    _In_ EX_PUSH_LOCK *Lock)
{
    ALLOWEDIPS_NODE *Node = RcuDereferenceProtected(ALLOWEDIPS_NODE, Trie, Lock);
    ALLOWEDIPS_NODE *Parent = NULL;
    BOOLEAN Exact = FALSE;

    while (Node && Node->Cidr <= Cidr && PrefixMatches(Node, Key, Bits))
    {
        Parent = Node;
        if (Parent->Cidr == Cidr)
        {
            Exact = TRUE;
            break;
        }
        Node = RcuDereferenceProtected(ALLOWEDIPS_NODE, Parent->Bit[Choose(Parent, Key)], Lock);
    }
    *Rnode = Parent;
    return Exact;
}

static inline VOID
ConnectNode(_Inout_ ALLOWEDIPS_NODE __rcu **Parent, _In_ UINT8 Bit, _In_ __drv_aliasesMem ALLOWEDIPS_NODE *Node)
{
    Node->ParentBitPacked = (ULONG_PTR)Parent | Bit;
    RcuAssignPointer(*Parent, Node);
}

static inline VOID
ChooseAndConnectNode(_Inout_ ALLOWEDIPS_NODE *Parent, _In_ __drv_aliasesMem ALLOWEDIPS_NODE *Node)
{
    UINT8 Bit = Choose(Parent, Node->Bits);
    ConnectNode(&Parent->Bit[Bit], Bit, Node);
}

_Requires_lock_held_(Lock)
static NTSTATUS
Add(_Inout_ ALLOWEDIPS_NODE __rcu **Trie,
    _In_ UINT8 Bits,
    _In_ CONST UINT8 *Key,
    _In_ UINT8 Cidr,
    _In_ WG_PEER *Peer,
    _In_ EX_PUSH_LOCK *Lock)
{
    ALLOWEDIPS_NODE *Node, *Parent, *Down, *Newnode;

    if (Cidr > Bits || !Peer)
        return STATUS_INVALID_PARAMETER;

    if (!RcuAccessPointer(*Trie))
    {
        Node = ExAllocateFromLookasideListEx(&NodeCache);
        if (!Node)
            return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(Node, sizeof(*Node));
        RcuInitPointer(Node->Peer, Peer);
        InsertTailList(&Peer->AllowedIpsList, &Node->PeerList);
        CopyAndAssignCidr(Node, Key, Cidr, Bits);
        ConnectNode(Trie, 2, Node);
        return STATUS_SUCCESS;
    }
    if (NodePlacement(*Trie, Key, Cidr, Bits, &Node, Lock))
    {
        RcuAssignPointer(Node->Peer, Peer);
        RemoveEntryList(&Node->PeerList);
        InsertTailList(&Peer->AllowedIpsList, &Node->PeerList);
        return STATUS_SUCCESS;
    }

    Newnode = ExAllocateFromLookasideListEx(&NodeCache);
    if (!Newnode)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Newnode, sizeof(*Newnode));
    RcuInitPointer(Newnode->Peer, Peer);
    InsertTailList(&Peer->AllowedIpsList, &Newnode->PeerList);
    CopyAndAssignCidr(Newnode, Key, Cidr, Bits);

    if (!Node)
    {
        Down = RcuDereferenceProtected(ALLOWEDIPS_NODE, *Trie, Lock);
    }
    else
    {
        CONST UINT8 Bit = Choose(Node, Key);
        Down = RcuDereferenceProtected(ALLOWEDIPS_NODE, Node->Bit[Bit], Lock);
        if (!Down)
        {
            ConnectNode(&Node->Bit[Bit], Bit, Newnode);
            return STATUS_SUCCESS;
        }
    }
    Cidr = min(Cidr, CommonBits(Down, Key, Bits));
    Parent = Node;

    if (Newnode->Cidr == Cidr)
    {
        ChooseAndConnectNode(Newnode, Down);
        if (!Parent)
            ConnectNode(Trie, 2, Newnode);
        else
            ChooseAndConnectNode(Parent, Newnode);
        return 0;
    }

    Node = ExAllocateFromLookasideListEx(&NodeCache);
    if (!Node)
    {
        RemoveEntryList(&Newnode->PeerList);
        ExFreeToLookasideListEx(&NodeCache, Newnode);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Node, sizeof(*Node));
    InitializeListHead(&Node->PeerList);
    CopyAndAssignCidr(Node, Newnode->Bits, Cidr, Bits);

    ChooseAndConnectNode(Node, Down);
    ChooseAndConnectNode(Node, Newnode);
    if (!Parent)
        ConnectNode(Trie, 2, Node);
    else
        ChooseAndConnectNode(Parent, Node);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
AllowedIpsInit(ALLOWEDIPS_TABLE *Table)
{
    Table->Root4 = Table->Root6 = NULL;
    Table->Seq = 1;
}

_Use_decl_annotations_
VOID
AllowedIpsFree(ALLOWEDIPS_TABLE *Table, EX_PUSH_LOCK *Lock)
{
    ALLOWEDIPS_NODE *Old4 = RcuDereferenceProtected(ALLOWEDIPS_NODE, Table->Root4, Lock);
    ALLOWEDIPS_NODE *Old6 = RcuDereferenceProtected(ALLOWEDIPS_NODE, Table->Root6, Lock);

    ++Table->Seq;
    RcuInitPointer(Table->Root4, NULL);
    RcuInitPointer(Table->Root6, NULL);
    if (Old4)
    {
        RootRemovePeerLists(Old4);
        RcuCall(&Old4->Rcu, RootFreeRcu);
    }
    if (Old6)
    {
        RootRemovePeerLists(Old6);
        RcuCall(&Old6->Rcu, RootFreeRcu);
    }
}

_Use_decl_annotations_
NTSTATUS
AllowedIpsInsertV4(ALLOWEDIPS_TABLE *Table, CONST IN_ADDR *Ip, UINT8 Cidr, WG_PEER *Peer, EX_PUSH_LOCK *Lock)
{
    /* Aligned so it can be passed to FindLastSet */
    __declspec(align(4)) UINT8 Key[4];

    ++Table->Seq;
    SwapEndian(Key, (CONST UINT8 *)Ip, 32);
    return Add(&Table->Root4, 32, Key, Cidr, Peer, Lock);
}

_Use_decl_annotations_
NTSTATUS
AllowedIpsInsertV6(ALLOWEDIPS_TABLE *Table, CONST IN6_ADDR *Ip, UINT8 Cidr, WG_PEER *Peer, EX_PUSH_LOCK *Lock)
{
    /* Aligned so it can be passed to FindLastSet64 */
    __declspec(align(8)) UINT8 Key[16];

    ++Table->Seq;
    SwapEndian(Key, (CONST UINT8 *)Ip, 128);
    return Add(&Table->Root6, 128, Key, Cidr, Peer, Lock);
}

_Use_decl_annotations_
VOID
AllowedIpsRemoveByPeer(ALLOWEDIPS_TABLE *Table, WG_PEER *Peer, EX_PUSH_LOCK *Lock)
{
    ALLOWEDIPS_NODE *Node, *Child, **ParentBit, *Parent, *Tmp;
    BOOLEAN FreeParent;

    if (IsListEmpty(&Peer->AllowedIpsList))
        return;
    ++Table->Seq;
    LIST_FOR_EACH_ENTRY_SAFE (Node, Tmp, &Peer->AllowedIpsList, ALLOWEDIPS_NODE, PeerList)
    {
        RemoveEntryList(&Node->PeerList);
        InitializeListHead(&Node->PeerList);
        RcuInitPointer(Node->Peer, NULL);
        if (Node->Bit[0] && Node->Bit[1])
            continue;
        Child = RcuDereferenceProtected(ALLOWEDIPS_NODE, Node->Bit[!RcuAccessPointer(Node->Bit[0])], Lock);
        if (Child)
            Child->ParentBitPacked = Node->ParentBitPacked;
        ParentBit = (ALLOWEDIPS_NODE **)(Node->ParentBitPacked & ~(ULONG_PTR)3);
        *ParentBit = Child;
        Parent =
            (ALLOWEDIPS_NODE *)((UCHAR *)ParentBit - FIELD_OFFSET(ALLOWEDIPS_NODE, Bit[Node->ParentBitPacked & 1]));
        FreeParent = !RcuAccessPointer(Node->Bit[0]) && !RcuAccessPointer(Node->Bit[1]) &&
                     (Node->ParentBitPacked & 3) <= 1 && !RcuAccessPointer(Parent->Peer);
        if (FreeParent)
            Child = RcuDereferenceProtected(ALLOWEDIPS_NODE, Parent->Bit[!(Node->ParentBitPacked & 1)], Lock);
        RcuCall(&Node->Rcu, NodeFreeRcu);
        if (!FreeParent)
            continue;
        if (Child)
            Child->ParentBitPacked = Parent->ParentBitPacked;
        *(ALLOWEDIPS_NODE **)(Parent->ParentBitPacked & ~(ULONG_PTR)3) = Child;
        RcuCall(&Parent->Rcu, NodeFreeRcu);
    }
}

_Use_decl_annotations_
ADDRESS_FAMILY
AllowedIpsReadNode(CONST ALLOWEDIPS_NODE *Node, UINT8 Ip[16], UINT8 *Cidr)
{
    CONST ULONG CidrBytes = DIV_ROUND_UP(Node->Cidr, 8U);
    SwapEndian(Ip, Node->Bits, Node->Bitlen);
    RtlZeroMemory(Ip + CidrBytes, Node->Bitlen / 8U - CidrBytes);
    if (Node->Cidr)
        Ip[CidrBytes - 1U] &= ~0U << (-Node->Cidr % 8U);

    *Cidr = Node->Cidr;
    return Node->Bitlen == 32 ? AF_INET : AF_INET6;
}

/* Returns a strong reference to a peer */
_Use_decl_annotations_
WG_PEER *
AllowedIpsLookupDst(ALLOWEDIPS_TABLE *Table, UINT16_BE Proto, CONST VOID *IpHdr)
{
    if (Proto == Htons(NDIS_ETH_TYPE_IPV4))
        return Lookup(Table->Root4, 32, &((IPV4HDR *)IpHdr)->Daddr);
    else if (Proto == Htons(NDIS_ETH_TYPE_IPV6))
        return Lookup(Table->Root6, 128, &((IPV6HDR *)IpHdr)->Daddr);
    return NULL;
}

/* Returns a strong reference to a peer */
_Use_decl_annotations_
WG_PEER *
AllowedIpsLookupSrc(ALLOWEDIPS_TABLE *Table, UINT16_BE Proto, CONST VOID *IpHdr)
{
    if (Proto == Htons(NDIS_ETH_TYPE_IPV4))
        return Lookup(Table->Root4, 32, &((IPV4HDR *)IpHdr)->Saddr);
    else if (Proto == Htons(NDIS_ETH_TYPE_IPV6))
        return Lookup(Table->Root6, 128, &((IPV6HDR *)IpHdr)->Saddr);
    return NULL;
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, AllowedIpsDriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
AllowedIpsDriverEntry(VOID)
{
    return ExInitializeLookasideListEx(&NodeCache, NULL, NULL, NonPagedPool, 0, sizeof(ALLOWEDIPS_NODE), MEMORY_TAG, 0);
}

_Use_decl_annotations_
VOID AllowedIpsUnload(VOID)
{
    RcuBarrier();
    ExDeleteLookasideListEx(&NodeCache);
}

#ifdef DBG
#    include "selftest/allowedips.c"
#endif
