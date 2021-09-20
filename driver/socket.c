/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/* We pretend we're Windows 8, and then hack around the limitation in Windows 7 below. */
#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#if NTDDI_VERSION == NTDDI_WIN7
#    undef NTDDI_VERSION
#    define NTDDI_VERSION NTDDI_WIN8
#    include <wsk.h>
#    undef NTDDI_VERSION
#    define NTDDI_VERSION NTDDI_WIN7
#endif

#include "device.h"
#include "messages.h"
#include "peer.h"
#include "queueing.h"
#include "rcu.h"
#include "socket.h"
#include "logging.h"
#include <wsk.h>
#include <netioapi.h>

static LONG RoutingGenerationV4 = 1, RoutingGenerationV6 = 1;
static HANDLE RouteNotifierV4, RouteNotifierV6;
static CONST WSK_CLIENT_DISPATCH WskAppDispatchV1 = { .Version = MAKE_WSK_VERSION(1, 0) };
static WSK_REGISTRATION WskRegistration;
static WSK_PROVIDER_NPI WskProviderNpi;
static BOOLEAN WskHasIpv4Transport, WskHasIpv6Transport;
static NTSTATUS WskInitStatus = STATUS_RETRY;
static EX_PUSH_LOCK WskIsIniting;
static LOOKASIDE_ALIGN LOOKASIDE_LIST_EX SocketSendCtxCache;

#define NET_BUFFER_WSK_BUF(Nb) ((WSK_BUF_LIST *)&NET_BUFFER_MINIPORT_RESERVED(Nb)[0])
static_assert(
    sizeof(NET_BUFFER_MINIPORT_RESERVED((NET_BUFFER *)0)) >= sizeof(WSK_BUF_LIST),
    "WSK_BUF_LIST is too large for NB");

typedef union _WSK_IRP
{
    IRP Irp;
    UCHAR IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
} WSK_IRP;

typedef struct _SOCKET_SEND_CTX
{
    WSK_IRP;
    WG_DEVICE *Wg;
    union
    {
        NET_BUFFER_LIST *FirstNbl;
        WSK_BUF Buffer;
    };
} SOCKET_SEND_CTX;

static IO_COMPLETION_ROUTINE NblSendComplete;
_Use_decl_annotations_
static NTSTATUS
NblSendComplete(DEVICE_OBJECT *DeviceObject, IRP *Irp, VOID *VoidCtx)
{
    SOCKET_SEND_CTX *Ctx = VoidCtx;
    _Analysis_assume_(Ctx);
    FreeSendNetBufferList(Ctx->Wg, Ctx->FirstNbl, 0);
    ExFreeToLookasideListEx(&SocketSendCtxCache, Ctx);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static IO_COMPLETION_ROUTINE BufferSendComplete;
_Use_decl_annotations_
static NTSTATUS
BufferSendComplete(DEVICE_OBJECT *DeviceObject, IRP *Irp, VOID *VoidCtx)
{
    SOCKET_SEND_CTX *Ctx = VoidCtx;
    _Analysis_assume_(Ctx);
    MemFreeDataAndMdlChain(Ctx->Buffer.Mdl);
    ExFreeToLookasideListEx(&SocketSendCtxCache, Ctx);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

#if NTDDI_VERSION == NTDDI_WIN7
static BOOLEAN NoWskSendMessages;

typedef struct _POLYFILLED_SOCKET_SEND_CTX
{
    WSK_IRP;
    IRP *OriginalIrp;
    LONG *RefCount;
} POLYFILLED_SOCKET_SEND_CTX;

static IO_COMPLETION_ROUTINE PolyfilledSendComplete;
_Use_decl_annotations_
static NTSTATUS
PolyfilledSendComplete(DEVICE_OBJECT *DeviceObject, IRP *Irp, VOID *VoidCtx)
{
    POLYFILLED_SOCKET_SEND_CTX *Ctx = VoidCtx;
    _Analysis_assume_(Ctx);
    if (!InterlockedDecrement(Ctx->RefCount))
    {
        IO_STACK_LOCATION *Stack = IoGetNextIrpStackLocation(Ctx->OriginalIrp);
        if (Stack && Stack->CompletionRoutine)
            Stack->CompletionRoutine(DeviceObject, Ctx->OriginalIrp, Stack->Context);
        MemFree(Ctx->RefCount);
    }
    MemFree(Ctx);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
PolyfilledWskSendMessages(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF_LIST BufferList,
    _Reserved_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp)
{
#    pragma warning(suppress : 6014) /* `RefCount` is freed in PolyfilledSendComplete. */
    LONG *RefCount = MemAllocate(sizeof(*RefCount));
    if (!RefCount)
        return STATUS_INSUFFICIENT_RESOURCES;
    WriteNoFence(RefCount, 1);
    for (WSK_BUF_LIST *Buf = BufferList; Buf; Buf = Buf->Next)
    {
        POLYFILLED_SOCKET_SEND_CTX *Ctx = MemAllocate(sizeof(*Ctx));
        if (!Ctx)
            continue;
        Ctx->RefCount = RefCount;
        Ctx->OriginalIrp = Irp;
        IoInitializeIrp(&Ctx->Irp, sizeof(Ctx->IrpBuffer), 1);
        IoSetCompletionRoutine(&Ctx->Irp, PolyfilledSendComplete, Ctx, TRUE, TRUE, TRUE);
        InterlockedIncrement(RefCount);
        ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Dispatch)
            ->WskSendTo(Socket, &Buf->Buffer, Flags, RemoteAddress, ControlInfoLength, ControlInfo, &Ctx->Irp);
    }
    if (!InterlockedDecrement(RefCount))
    {
        IO_STACK_LOCATION *Stack = IoGetNextIrpStackLocation(Irp);
        if (Stack && Stack->CompletionRoutine)
            Stack->CompletionRoutine((DEVICE_OBJECT *)Socket, Irp, Stack->Context);
        MemFree(RefCount);
    }
    return STATUS_SUCCESS;
}
#endif

static BOOLEAN
CidrMaskMatchV4(_In_ CONST IN_ADDR *Addr, _In_ CONST IP_ADDRESS_PREFIX *Prefix)
{
    return Prefix->PrefixLength == 0 ||
           (Addr->s_addr & (Htonl(~0U << (32 - Prefix->PrefixLength)))) == Prefix->Prefix.Ipv4.sin_addr.s_addr;
}

static BOOLEAN
CidrMaskMatchV6(_In_ CONST IN6_ADDR *Addr, _In_ CONST IP_ADDRESS_PREFIX *Prefix)
{
    if (Prefix->PrefixLength == 0)
        return TRUE;
    ULONG WholeParts = Prefix->PrefixLength / 32;
    ULONG LeftoverBits = Prefix->PrefixLength % 32;
    if (!RtlEqualMemory(&Prefix->Prefix.Ipv6.sin6_addr, Addr, WholeParts * sizeof(UINT32)))
        return FALSE;
    if (WholeParts == 4 || LeftoverBits == 0)
        return TRUE;
    return (((UINT32 *)Addr)[WholeParts] & Htonl(~0U << (32 - LeftoverBits))) ==
           ((UINT32 *)&Prefix->Prefix.Ipv6.sin6_addr)[WholeParts];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_shared_lock_(Peer->EndpointLock)
_Requires_lock_not_held_(Peer->EndpointLock)
static NTSTATUS
SocketResolvePeerEndpoint(_Inout_ WG_PEER *Peer, _Out_ _At_(*Irql, _IRQL_saves_) KIRQL *Irql)
{
    *Irql = ExAcquireSpinLockShared(&Peer->EndpointLock);
retryWhileHoldingSharedLock:
    if ((Peer->Endpoint.Addr.si_family == AF_INET &&
         Peer->Endpoint.RoutingGeneration == (UINT32)ReadNoFence(&RoutingGenerationV4) &&
         Peer->Endpoint.Src4.ipi_ifindex && Peer->Endpoint.Src4.ipi_ifindex != Peer->Device->InterfaceIndex) ||
        (Peer->Endpoint.Addr.si_family == AF_INET6 &&
         Peer->Endpoint.RoutingGeneration == (UINT32)ReadNoFence(&RoutingGenerationV6) &&
         Peer->Endpoint.Src6.ipi6_ifindex && Peer->Endpoint.Src6.ipi6_ifindex != Peer->Device->InterfaceIndex))
        return STATUS_SUCCESS;

    SOCKADDR_INET Addr;
    UINT32 UpdateGeneration = Peer->Endpoint.UpdateGeneration;
    RtlCopyMemory(&Addr, &Peer->Endpoint.Addr, sizeof(Addr));
    ExReleaseSpinLockShared(&Peer->EndpointLock, *Irql);
    SOCKADDR_INET SrcAddr = { 0 };
    ULONG BestIndex = 0, BestCidr = 0, BestMetric = ~0UL;
    NET_LUID BestLuid = { 0 };
    MIB_IPFORWARD_TABLE2 *Table;
    NTSTATUS Status = GetIpForwardTable2(Addr.si_family, &Table);
    if (!NT_SUCCESS(Status))
        return Status;
    union
    {
        MIB_IF_ROW2 Interface;
        MIB_IPINTERFACE_ROW IpInterface;
    } *If = MemAllocate(sizeof(*If));
    if (!If)
        return STATUS_INSUFFICIENT_RESOURCES;
    for (ULONG i = 0; i < Table->NumEntries; ++i)
    {
        if (Table->Table[i].InterfaceLuid.Value == Peer->Device->InterfaceLuid.Value)
            continue;
        if (Table->Table[i].DestinationPrefix.PrefixLength < BestCidr)
            continue;
        if (Addr.si_family == AF_INET && !CidrMaskMatchV4(&Addr.Ipv4.sin_addr, &Table->Table[i].DestinationPrefix))
            continue;
        if (Addr.si_family == AF_INET6 && !CidrMaskMatchV6(&Addr.Ipv6.sin6_addr, &Table->Table[i].DestinationPrefix))
            continue;
        If->Interface = (MIB_IF_ROW2){ .InterfaceLuid = Table->Table[i].InterfaceLuid };
        if (!NT_SUCCESS(GetIfEntry2(&If->Interface)) || If->Interface.OperStatus != IfOperStatusUp)
            continue;
        If->IpInterface =
            (MIB_IPINTERFACE_ROW){ .Family = Addr.si_family, .InterfaceLuid = Table->Table[i].InterfaceLuid };
        if (!NT_SUCCESS(GetIpInterfaceEntry(&If->IpInterface)))
            continue;
        ULONG Metric = Table->Table[i].Metric + If->IpInterface.Metric;
        if (Table->Table[i].DestinationPrefix.PrefixLength == BestCidr && Metric > BestMetric)
            continue;
        BestCidr = Table->Table[i].DestinationPrefix.PrefixLength;
        BestMetric = Metric;
        BestIndex = Table->Table[i].InterfaceIndex;
        BestLuid = Table->Table[i].InterfaceLuid;
    }
    MemFree(If);
    if (Table->NumEntries && BestIndex)
        Status = GetBestRoute2(&BestLuid, 0, NULL, &Addr, 0, &Table->Table[0], &SrcAddr);
    FreeMibTable(Table);
    if (!BestIndex)
        return STATUS_BAD_NETWORK_PATH;
    if (!NT_SUCCESS(Status))
        return Status;

    *Irql = ExAcquireSpinLockExclusive(&Peer->EndpointLock);
    if (UpdateGeneration != Peer->Endpoint.UpdateGeneration)
    {
        ExReleaseSpinLockExclusiveFromDpcLevel(&Peer->EndpointLock);
        ExAcquireSpinLockSharedAtDpcLevel(&Peer->EndpointLock);
        goto retryWhileHoldingSharedLock;
    }
    if (Peer->Endpoint.Addr.si_family == AF_INET)
    {
        Peer->Endpoint.Cmsg.cmsg_len = WSA_CMSG_LEN(sizeof(Peer->Endpoint.Src4));
        Peer->Endpoint.Cmsg.cmsg_level = IPPROTO_IP;
        Peer->Endpoint.Cmsg.cmsg_type = IP_PKTINFO;
        Peer->Endpoint.Src4.ipi_addr = SrcAddr.Ipv4.sin_addr;
        Peer->Endpoint.Src4.ipi_ifindex = BestIndex;
        Peer->Endpoint.CmsgHack4.cmsg_len = WSA_CMSG_LEN(0);
        Peer->Endpoint.CmsgHack4.cmsg_level = IPPROTO_IP;
        Peer->Endpoint.CmsgHack4.cmsg_type = IP_OPTIONS;
        Peer->Endpoint.RoutingGeneration = ReadNoFence(&RoutingGenerationV4);
    }
    else if (Peer->Endpoint.Addr.si_family == AF_INET6)
    {
        Peer->Endpoint.Cmsg.cmsg_len = WSA_CMSG_LEN(sizeof(Peer->Endpoint.Src6));
        Peer->Endpoint.Cmsg.cmsg_level = IPPROTO_IPV6;
        Peer->Endpoint.Cmsg.cmsg_type = IPV6_PKTINFO;
        Peer->Endpoint.Src6.ipi6_addr = SrcAddr.Ipv6.sin6_addr;
        Peer->Endpoint.Src6.ipi6_ifindex = BestIndex;
        Peer->Endpoint.CmsgHack6.cmsg_len = WSA_CMSG_LEN(0);
        Peer->Endpoint.CmsgHack6.cmsg_level = IPPROTO_IPV6;
        Peer->Endpoint.CmsgHack6.cmsg_type = IPV6_RTHDR;
        Peer->Endpoint.RoutingGeneration = ReadNoFence(&RoutingGenerationV6);
    }
    ++Peer->Endpoint.UpdateGeneration, ++UpdateGeneration;
    ExReleaseSpinLockExclusiveFromDpcLevel(&Peer->EndpointLock);
    ExAcquireSpinLockSharedAtDpcLevel(&Peer->EndpointLock);
    if (Peer->Endpoint.UpdateGeneration != UpdateGeneration)
        goto retryWhileHoldingSharedLock;
    return STATUS_SUCCESS;
}

#pragma warning(suppress : 28194) /* `Nbl` is aliased in Ctx->Nbl or freed on failure. */
#pragma warning(suppress : 28167) /* IRQL is either not raised on SocketResolvePeerEndpoint failure, or \
                                     restored by ExReleaseSpinLockShared */
_Use_decl_annotations_
NTSTATUS
SocketSendNblsToPeer(WG_PEER *Peer, NET_BUFFER_LIST *First, BOOLEAN *AllKeepalive)
{
    if (!First)
        return STATUS_ALREADY_COMPLETE;

    *AllKeepalive = TRUE;
    WSK_BUF_LIST *FirstWskBuf = NULL, *LastWskBuf = NULL;
    ULONG64 DataLength = 0, Packets = 0;
    for (NET_BUFFER_LIST *Nbl = First; Nbl; Nbl = NET_BUFFER_LIST_NEXT_NBL(Nbl))
    {
        for (NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl); Nb; Nb = NET_BUFFER_NEXT_NB(Nb))
        {
            NET_BUFFER_WSK_BUF(Nb)->Buffer.Mdl = NET_BUFFER_CURRENT_MDL(Nb);
            NET_BUFFER_WSK_BUF(Nb)->Buffer.Length = NET_BUFFER_DATA_LENGTH(Nb);
            NET_BUFFER_WSK_BUF(Nb)->Buffer.Offset = NET_BUFFER_CURRENT_MDL_OFFSET(Nb);
            NET_BUFFER_WSK_BUF(Nb)->Next = NULL;
            *(LastWskBuf ? &LastWskBuf->Next : &FirstWskBuf) = NET_BUFFER_WSK_BUF(Nb);
            LastWskBuf = NET_BUFFER_WSK_BUF(Nb);
            DataLength += NET_BUFFER_DATA_LENGTH(Nb);
            ++Packets;
            if (NET_BUFFER_DATA_LENGTH(Nb) != MessageDataLen(0))
                *AllKeepalive = FALSE;
        }
    }
    _Analysis_assume_(FirstWskBuf != NULL);

    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    SOCKET_SEND_CTX *Ctx = ExAllocateFromLookasideListEx(&SocketSendCtxCache);
    if (!Ctx)
        goto cleanupNbls;
    Ctx->FirstNbl = First;
    Ctx->Wg = Peer->Device;
    IoInitializeIrp(&Ctx->Irp, sizeof(Ctx->IrpBuffer), 1);
    IoSetCompletionRoutine(&Ctx->Irp, NblSendComplete, Ctx, TRUE, TRUE, TRUE);
    KIRQL Irql;
    Status = SocketResolvePeerEndpoint(Peer, &Irql);
    if (!NT_SUCCESS(Status))
        goto cleanupCtx;
    SOCKET *Socket = NULL;
    RcuReadLockAtDpcLevel();
    if (Peer->Endpoint.Addr.si_family == AF_INET)
        Socket = RcuDereference(SOCKET, Peer->Device->Sock4);
    else if (Peer->Endpoint.Addr.si_family == AF_INET6)
        Socket = RcuDereference(SOCKET, Peer->Device->Sock6);
    if (!Socket)
    {
        Status = STATUS_NETWORK_UNREACHABLE;
        goto cleanupRcuLock;
    }
    PFN_WSK_SEND_MESSAGES WskSendMessages = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Sock->Dispatch)->WskSendMessages;
#if NTDDI_VERSION == NTDDI_WIN7
    if (NoWskSendMessages)
        WskSendMessages = PolyfilledWskSendMessages;
#endif
    Status = WskSendMessages(
        Socket->Sock,
        FirstWskBuf,
        0,
        (PSOCKADDR)&Peer->Endpoint.Addr,
        (ULONG)WSA_CMSGDATA_ALIGN(Peer->Endpoint.Cmsg.cmsg_len) + WSA_CMSG_SPACE(0),
        &Peer->Endpoint.Cmsg,
        &Ctx->Irp);
    RcuReadUnlockFromDpcLevel();
    ExReleaseSpinLockShared(&Peer->EndpointLock, Irql);
    if (NT_SUCCESS(Status))
    {
        Peer->TxBytes += DataLength;
        Peer->Device->Statistics.ifHCOutOctets += DataLength;
        Peer->Device->Statistics.ifHCOutUcastOctets += DataLength;
        Peer->Device->Statistics.ifHCOutUcastPkts += Packets;
    }
    else
        Peer->Device->Statistics.ifOutErrors += Packets;
    return Status;

cleanupRcuLock:
    RcuReadUnlockFromDpcLevel();
    ExReleaseSpinLockShared(&Peer->EndpointLock, Irql);
cleanupCtx:
    ExFreeToLookasideListEx(&SocketSendCtxCache, Ctx);
cleanupNbls:
    FreeSendNetBufferList(Peer->Device, First, 0);
    return Status;
}

#pragma warning(suppress : 28167) /* IRQL is either not raised on SocketResolvePeerEndpoint failure, or \
                                     restored by ExReleaseSpinLockShared */
_Use_decl_annotations_
NTSTATUS
SocketSendBufferToPeer(WG_PEER *Peer, CONST VOID *Buffer, ULONG Len)
{
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    SOCKET_SEND_CTX *Ctx = ExAllocateFromLookasideListEx(&SocketSendCtxCache);
    if (!Ctx)
        return Status;
    Ctx->Buffer.Length = Len;
    Ctx->Buffer.Offset = 0;
    Ctx->Buffer.Mdl = MemAllocateDataAndMdlChain(Len);
    if (!Ctx->Buffer.Mdl)
        goto cleanupCtx;
    RtlCopyMemory(MmGetMdlVirtualAddress(Ctx->Buffer.Mdl), Buffer, Len);
    Ctx->Wg = Peer->Device;
    IoInitializeIrp(&Ctx->Irp, sizeof(Ctx->IrpBuffer), 1);
    IoSetCompletionRoutine(&Ctx->Irp, BufferSendComplete, Ctx, TRUE, TRUE, TRUE);
    KIRQL Irql;
    Status = SocketResolvePeerEndpoint(Peer, &Irql);
    if (!NT_SUCCESS(Status))
        goto cleanupMdl;
    SOCKET *Socket = NULL;
    RcuReadLockAtDpcLevel();
    if (Peer->Endpoint.Addr.si_family == AF_INET)
        Socket = RcuDereference(SOCKET, Peer->Device->Sock4);
    else if (Peer->Endpoint.Addr.si_family == AF_INET6)
        Socket = RcuDereference(SOCKET, Peer->Device->Sock6);
    if (!Socket)
    {
        Status = STATUS_NETWORK_UNREACHABLE;
        goto cleanupRcuLock;
    }
    Status = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Sock->Dispatch)
                 ->WskSendTo(
                     Socket->Sock,
                     &Ctx->Buffer,
                     0,
                     (PSOCKADDR)&Peer->Endpoint.Addr,
                     (ULONG)WSA_CMSGDATA_ALIGN(Peer->Endpoint.Cmsg.cmsg_len) + WSA_CMSG_SPACE(0),
                     &Peer->Endpoint.Cmsg,
                     &Ctx->Irp);
    RcuReadUnlockFromDpcLevel();
    ExReleaseSpinLockShared(&Peer->EndpointLock, Irql);
    if (NT_SUCCESS(Status))
        Peer->TxBytes += Len;
    return Status;

cleanupRcuLock:
    RcuReadUnlockFromDpcLevel();
    ExReleaseSpinLockShared(&Peer->EndpointLock, Irql);
cleanupMdl:
    MemFreeDataAndMdlChain(Ctx->Buffer.Mdl);
cleanupCtx:
    ExFreeToLookasideListEx(&SocketSendCtxCache, Ctx);
    return Status;
}

_Use_decl_annotations_
NTSTATUS
SocketSendBufferAsReplyToNbl(WG_DEVICE *Wg, CONST NET_BUFFER_LIST *InNbl, CONST VOID *Buffer, ULONG Len)
{
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    SOCKET_SEND_CTX *Ctx = ExAllocateFromLookasideListEx(&SocketSendCtxCache);
    if (!Ctx)
        return Status;
    Ctx->Buffer.Length = Len;
    Ctx->Buffer.Offset = 0;
    Ctx->Buffer.Mdl = MemAllocateDataAndMdlChain(Len);
    if (!Ctx->Buffer.Mdl)
        goto cleanupCtx;
    RtlCopyMemory(MmGetMdlVirtualAddress(Ctx->Buffer.Mdl), Buffer, Len);
    Ctx->Wg = Wg;
    IoInitializeIrp(&Ctx->Irp, sizeof(Ctx->IrpBuffer), 1);
    IoSetCompletionRoutine(&Ctx->Irp, BufferSendComplete, Ctx, TRUE, TRUE, TRUE);
    ENDPOINT Endpoint;
    Status = SocketEndpointFromNbl(&Endpoint, InNbl);
    if (!NT_SUCCESS(Status))
        goto cleanupMdl;
    Status = STATUS_BAD_NETWORK_PATH;
    if ((Endpoint.Addr.si_family == AF_INET && Endpoint.Src4.ipi_ifindex == Wg->InterfaceIndex) ||
        (Endpoint.Addr.si_family == AF_INET6 && Endpoint.Src6.ipi6_ifindex == Wg->InterfaceIndex))
        goto cleanupMdl;
    KIRQL Irql = RcuReadLock();
    SOCKET *Socket = NULL;
    if (Endpoint.Addr.si_family == AF_INET)
        Socket = RcuDereference(SOCKET, Wg->Sock4);
    else if (Endpoint.Addr.si_family == AF_INET6)
        Socket = RcuDereference(SOCKET, Wg->Sock6);
    if (!Socket)
    {
        Status = STATUS_NETWORK_UNREACHABLE;
        goto cleanupRcuLock;
    }
    Status = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Sock->Dispatch)
                 ->WskSendTo(
                     Socket->Sock,
                     &Ctx->Buffer,
                     0,
                     (PSOCKADDR)&Endpoint.Addr,
                     (ULONG)WSA_CMSGDATA_ALIGN(Endpoint.Cmsg.cmsg_len) + WSA_CMSG_SPACE(0),
                     &Endpoint.Cmsg,
                     &Ctx->Irp);
    RcuReadUnlock(Irql);
    return Status;

cleanupRcuLock:
    RcuReadUnlock(Irql);
cleanupMdl:
    MemFreeDataAndMdlChain(Ctx->Buffer.Mdl);
cleanupCtx:
    ExFreeToLookasideListEx(&SocketSendCtxCache, Ctx);
    return Status;
}

static_assert(
    WSA_CMSGDATA_ALIGN(WSA_CMSG_LEN(RTL_FIELD_SIZE(ENDPOINT, Src4))) == WSA_CMSG_SPACE(RTL_FIELD_SIZE(ENDPOINT, Src4)),
    "cmsg calculation mismatch");
static_assert(
    WSA_CMSGDATA_ALIGN(WSA_CMSG_LEN(RTL_FIELD_SIZE(ENDPOINT, Src6))) == WSA_CMSG_SPACE(RTL_FIELD_SIZE(ENDPOINT, Src6)),
    "cmsg calculation mismatch");
static_assert(
    WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR)) + FIELD_OFFSET(ENDPOINT, Cmsg) == FIELD_OFFSET(ENDPOINT, Src4),
    "cmsg calculation mismatch");
static_assert(
    WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR)) + FIELD_OFFSET(ENDPOINT, Cmsg) == FIELD_OFFSET(ENDPOINT, Src6),
    "cmsg calculation mismatch");
static_assert(
    FIELD_OFFSET(ENDPOINT, Cmsg) + WSA_CMSG_SPACE(RTL_FIELD_SIZE(ENDPOINT, Src4)) <= sizeof(ENDPOINT),
    "cmsg calculation mismatch");
static_assert(
    FIELD_OFFSET(ENDPOINT, Cmsg) + WSA_CMSG_SPACE(RTL_FIELD_SIZE(ENDPOINT, Src6)) <= sizeof(ENDPOINT),
    "cmsg calculation mismatch");
static_assert(WSA_CMSG_SPACE(0) == sizeof(WSACMSGHDR), "cmsg calculation mismatch");

_Post_maybenull_
static VOID *
FindInCmsgHdr(_In_ WSK_DATAGRAM_INDICATION *Data, _In_ CONST INT Level, _In_ CONST INT Type)
{
    SIZE_T Len = Data->ControlInfoLength;
    WSACMSGHDR *Hdr = Data->ControlInfo;

    while (Len > 0 && Hdr)
    {
        if (Hdr->cmsg_level == Level && Hdr->cmsg_type == Type)
            return (VOID *)WSA_CMSG_DATA(Hdr);
        Len -= WSA_CMSGHDR_ALIGN(Hdr->cmsg_len);
        Hdr = (WSACMSGHDR *)((UCHAR *)Hdr + WSA_CMSGHDR_ALIGN(Hdr->cmsg_len));
    }
    return NULL;
}

_Use_decl_annotations_
NTSTATUS
SocketEndpointFromNbl(ENDPOINT *Endpoint, CONST NET_BUFFER_LIST *Nbl)
{
    WSK_DATAGRAM_INDICATION *Data = NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl);
    SOCKADDR *Addr = Data->RemoteAddress;
    VOID *Pktinfo;
    RtlZeroMemory(Endpoint, sizeof(*Endpoint));
    if (Addr->sa_family == AF_INET && (Pktinfo = FindInCmsgHdr(Data, IPPROTO_IP, IP_PKTINFO)) != NULL)
    {
        Endpoint->Addr.Ipv4 = *(SOCKADDR_IN *)Addr;
        Endpoint->Cmsg.cmsg_len = WSA_CMSG_LEN(sizeof(Endpoint->Src4));
        Endpoint->Cmsg.cmsg_level = IPPROTO_IP;
        Endpoint->Cmsg.cmsg_type = IP_PKTINFO;
        Endpoint->Src4 = *(IN_PKTINFO *)Pktinfo;
        Endpoint->CmsgHack4.cmsg_len = WSA_CMSG_LEN(0);
        Endpoint->CmsgHack4.cmsg_level = IPPROTO_IP;
        Endpoint->CmsgHack4.cmsg_type = IP_OPTIONS;
        Endpoint->RoutingGeneration = ReadNoFence(&RoutingGenerationV4);
    }
    else if (Addr->sa_family == AF_INET6 && (Pktinfo = FindInCmsgHdr(Data, IPPROTO_IPV6, IPV6_PKTINFO)) != NULL)
    {
        Endpoint->Addr.Ipv6 = *(SOCKADDR_IN6 *)Addr;
        Endpoint->Cmsg.cmsg_len = WSA_CMSG_LEN(sizeof(Endpoint->Src6));
        Endpoint->Cmsg.cmsg_level = IPPROTO_IPV6;
        Endpoint->Cmsg.cmsg_type = IPV6_PKTINFO;
        Endpoint->Src6 = *(IN6_PKTINFO *)Pktinfo;
        Endpoint->CmsgHack6.cmsg_len = WSA_CMSG_LEN(0);
        Endpoint->CmsgHack6.cmsg_level = IPPROTO_IPV6;
        Endpoint->CmsgHack6.cmsg_type = IPV6_RTHDR;
        Endpoint->RoutingGeneration = ReadNoFence(&RoutingGenerationV6);
    }
    else
        return STATUS_INVALID_ADDRESS;
    return STATUS_SUCCESS;
}

static inline BOOLEAN
Ipv6AddrEq(_In_ CONST IN6_ADDR *A1, _In_ CONST IN6_ADDR *A2)
{
    UINT64 *B1 = (UINT64 *)A1, *B2 = (UINT64 *)A2;
    return ((B1[0] ^ B2[0]) | (B1[1] ^ B2[1])) == 0;
}

static BOOLEAN
EndpointEq(_In_ CONST ENDPOINT *A, _In_ CONST ENDPOINT *B)
{
    return (A->Addr.si_family == AF_INET && B->Addr.si_family == AF_INET &&
            A->Addr.Ipv4.sin_port == B->Addr.Ipv4.sin_port &&
            A->Addr.Ipv4.sin_addr.s_addr == B->Addr.Ipv4.sin_addr.s_addr &&
            A->Src4.ipi_addr.s_addr == B->Src4.ipi_addr.s_addr && A->Src4.ipi_ifindex == B->Src4.ipi_ifindex) ||
           (A->Addr.si_family == AF_INET6 && B->Addr.si_family == AF_INET6 &&
            A->Addr.Ipv6.sin6_port == B->Addr.Ipv6.sin6_port &&
            Ipv6AddrEq(&A->Addr.Ipv6.sin6_addr, &B->Addr.Ipv6.sin6_addr) &&
            A->Addr.Ipv6.sin6_scope_id == B->Addr.Ipv6.sin6_scope_id &&
            Ipv6AddrEq(&A->Src6.ipi6_addr, &B->Src6.ipi6_addr) && A->Src6.ipi6_ifindex == B->Src6.ipi6_ifindex) ||
           !A->Addr.si_family && !B->Addr.si_family;
}

_Use_decl_annotations_
VOID
SocketSetPeerEndpoint(WG_PEER *Peer, CONST ENDPOINT *Endpoint)
{
    KIRQL Irql;

    /* First we check unlocked, in order to optimize, since it's pretty rare
     * that an endpoint will change. If we happen to be mid-write, and two
     * CPUs wind up writing the same thing or something slightly different,
     * it doesn't really matter much either.
     */
    if (EndpointEq(Endpoint, &Peer->Endpoint))
        return;
    Irql = ExAcquireSpinLockExclusive(&Peer->EndpointLock);
    if (Endpoint->Addr.si_family == AF_INET)
    {
        Peer->Endpoint.Addr.Ipv4 = Endpoint->Addr.Ipv4;
        if (Endpoint->Src4.ipi_ifindex != Peer->Device->InterfaceIndex)
        {
            Peer->Endpoint.Cmsg = Endpoint->Cmsg;
            Peer->Endpoint.Src4 = Endpoint->Src4;
            Peer->Endpoint.CmsgHack4 = Endpoint->CmsgHack4;
        }
    }
    else if (Endpoint->Addr.si_family == AF_INET6)
    {
        Peer->Endpoint.Addr.Ipv6 = Endpoint->Addr.Ipv6;
        if (Endpoint->Src6.ipi6_ifindex != Peer->Device->InterfaceIndex)
        {
            Peer->Endpoint.Cmsg = Endpoint->Cmsg;
            Peer->Endpoint.Src6 = Endpoint->Src6;
            Peer->Endpoint.CmsgHack6 = Endpoint->CmsgHack6;
        }
    }
    else
        goto out;
    Peer->Endpoint.RoutingGeneration = Endpoint->RoutingGeneration;
    ++Peer->Endpoint.UpdateGeneration;
out:
    ExReleaseSpinLockExclusive(&Peer->EndpointLock, Irql);
}

_Use_decl_annotations_
VOID
SocketSetPeerEndpointFromNbl(WG_PEER *Peer, CONST NET_BUFFER_LIST *Nbl)
{
    ENDPOINT Endpoint;

    if (NT_SUCCESS(SocketEndpointFromNbl(&Endpoint, Nbl)))
        SocketSetPeerEndpoint(Peer, &Endpoint);
}

_Use_decl_annotations_
VOID
SocketClearPeerEndpointSrc(WG_PEER *Peer)
{
    KIRQL Irql;

    Irql = ExAcquireSpinLockExclusive(&Peer->EndpointLock);
    Peer->Endpoint.RoutingGeneration = 0;
    ++Peer->Endpoint.UpdateGeneration;
    RtlZeroMemory(&Peer->Endpoint.Src6, sizeof(Peer->Endpoint.Src6));
    ExReleaseSpinLockExclusive(&Peer->EndpointLock, Irql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static NTSTATUS WSKAPI
Receive(_In_opt_ PVOID SocketContext, _In_ ULONG Flags, _In_opt_ WSK_DATAGRAM_INDICATION *DataIndication)
{
    SOCKET *Socket = SocketContext;
    if (!Socket || !Socket->Sock || !DataIndication)
        return STATUS_SUCCESS;
    WG_DEVICE *Wg = Socket->Device;
    NET_BUFFER_LIST *First = NULL, **Link = &First;
    for (WSK_DATAGRAM_INDICATION *DataIndicationNext; DataIndication; DataIndication = DataIndicationNext)
    {
        DataIndicationNext = DataIndication->Next;
        DataIndication->Next = NULL;
        NET_BUFFER_LIST *Nbl = NULL;
        ULONG Length;
        if (!NT_SUCCESS(RtlSIZETToULong(DataIndication->Buffer.Length, &Length)))
            goto skipDatagramIndication;
        Nbl = MemAllocateNetBufferList(0, Length, 0);
        if (!Nbl || !ReadBooleanNoFence(&Wg->IsUp) || !ExAcquireRundownProtection(&Socket->ItemsInFlight))
            goto skipDatagramIndication;
        NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl) = DataIndication;
        DataIndication->Next = (VOID *)Socket;
        *Link = Nbl;
        Link = &NET_BUFFER_LIST_NEXT_NBL(Nbl);
        continue;

    skipDatagramIndication:
        ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Sock->Dispatch)->WskRelease(Socket->Sock, DataIndication);
        if (Nbl)
            MemFreeNetBufferList(Nbl);
        ++Wg->Statistics.ifInDiscards;
    }
    if (First)
        PacketReceive(Wg, First);
    return STATUS_PENDING;
}

static IO_COMPLETION_ROUTINE RaiseEventOnComplete;
_Use_decl_annotations_
static NTSTATUS
RaiseEventOnComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    _Analysis_assume_(Context);
    KeSetEvent((KEVENT *)Context, IO_NETWORK_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_max_(APC_LEVEL)
static VOID
CloseSocket(_Frees_ptr_opt_ SOCKET *Socket)
{
    if (!Socket)
        return;
    ExWaitForRundownProtectionRelease(&Socket->ItemsInFlight);
    if (!Socket->Sock)
        goto freeIt;
    KEVENT Done;
    WSK_IRP I;
    KeInitializeEvent(&Done, SynchronizationEvent, FALSE);
    IoInitializeIrp(&I.Irp, sizeof(I.IrpBuffer), 1);
    IoSetCompletionRoutine(&I.Irp, RaiseEventOnComplete, &Done, TRUE, TRUE, TRUE);
    NTSTATUS Status = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Socket->Sock->Dispatch)->WskCloseSocket(Socket->Sock, &I.Irp);
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Done, Executive, KernelMode, FALSE, NULL);
freeIt:
    MemFree(Socket);
}

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
SetSockOpt(
    _In_ WSK_SOCKET *Sock,
    _In_ ULONG Level,
    _In_ ULONG Option,
    _In_reads_bytes_(Len) VOID *Input,
    _In_ ULONG Len)
{
    KEVENT Done;
    WSK_IRP I;
    KeInitializeEvent(&Done, SynchronizationEvent, FALSE);
    IoInitializeIrp(&I.Irp, sizeof(I.IrpBuffer), 1);
    IoSetCompletionRoutine(&I.Irp, RaiseEventOnComplete, &Done, TRUE, TRUE, TRUE);
    NTSTATUS Status = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Sock->Dispatch)
                          ->WskControlSocket(Sock, WskSetOption, Option, Level, Len, Input, 0, NULL, NULL, &I.Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Done, Executive, KernelMode, FALSE, NULL);
        Status = I.Irp.IoStatus.Status;
    }
    return Status;
}

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
CreateAndBindSocket(_In_ WG_DEVICE *Wg, _Inout_ SOCKADDR *Sa, _Out_ SOCKET **RetSocket)
{
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    SOCKET *Socket = MemAllocate(sizeof(*Socket));
    if (!Socket)
        return Status;
    Socket->Device = Wg;
    Socket->Sock = NULL;
    ExInitializeRundownProtection(&Socket->ItemsInFlight);
    KEVENT Done;
    WSK_IRP I;
    KeInitializeEvent(&Done, SynchronizationEvent, FALSE);
    IoInitializeIrp(&I.Irp, sizeof(I.IrpBuffer), 1);
    IoSetCompletionRoutine(&I.Irp, RaiseEventOnComplete, &Done, TRUE, TRUE, TRUE);
    static CONST WSK_CLIENT_DATAGRAM_DISPATCH WskClientDatagramDispatch = { .WskReceiveFromEvent = Receive };
    Status = WskProviderNpi.Dispatch->WskSocket(
        WskProviderNpi.Client,
        Sa->sa_family,
        SOCK_DGRAM,
        IPPROTO_UDP,
        WSK_FLAG_DATAGRAM_SOCKET,
        Socket,
        &WskClientDatagramDispatch,
        Wg->SocketOwnerProcess,
        NULL,
        NULL,
        &I.Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Done, Executive, KernelMode, FALSE, NULL);
        Status = I.Irp.IoStatus.Status;
    }
    if (!NT_SUCCESS(Status))
        goto cleanupSocket;
    WSK_SOCKET *Sock = (WSK_SOCKET *)I.Irp.IoStatus.Information;
    WritePointerNoFence(&Socket->Sock, Sock);

    ULONG True = TRUE;
    if (Sa->sa_family == AF_INET)
    {
        Status = SetSockOpt(Sock, IPPROTO_IP, IP_PKTINFO, &True, sizeof(True));
        if (!NT_SUCCESS(Status))
            goto cleanupSocket;
    }
    else if (Sa->sa_family == AF_INET6)
    {
        Status = SetSockOpt(Sock, IPPROTO_IPV6, IPV6_V6ONLY, &True, sizeof(True));
        if (!NT_SUCCESS(Status))
            goto cleanupSocket;
        Status = SetSockOpt(Sock, IPPROTO_IPV6, IPV6_PKTINFO, &True, sizeof(True));
        if (!NT_SUCCESS(Status))
            goto cleanupSocket;
    }

    IoInitializeIrp(&I.Irp, sizeof(I.IrpBuffer), 1);
    IoSetCompletionRoutine(&I.Irp, RaiseEventOnComplete, &Done, TRUE, TRUE, TRUE);
    Status = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Sock->Dispatch)->WskBind(Sock, Sa, 0, &I.Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Done, Executive, KernelMode, FALSE, NULL);
        Status = I.Irp.IoStatus.Status;
    }
    if (!NT_SUCCESS(Status))
    {
        CHAR Address[SOCKADDR_STR_MAX_LEN];
        SockaddrToString(Address, (SOCKADDR_INET *)Sa);
        LogErr(Wg, "Could not bind socket to %s (%#x)", Address, Status);
        goto cleanupSocket;
    }

    IoInitializeIrp(&I.Irp, sizeof(I.IrpBuffer), 1);
    IoSetCompletionRoutine(&I.Irp, RaiseEventOnComplete, &Done, TRUE, TRUE, TRUE);
    Status = ((WSK_PROVIDER_DATAGRAM_DISPATCH *)Sock->Dispatch)->WskGetLocalAddress(Sock, Sa, &I.Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Done, Executive, KernelMode, FALSE, NULL);
        Status = I.Irp.IoStatus.Status;
    }
    if (!NT_SUCCESS(Status))
        goto cleanupSocket;

    *RetSocket = Socket;
    return STATUS_SUCCESS;

cleanupSocket:
    CloseSocket(Socket);
    return Status;
}

_Use_decl_annotations_
NTSTATUS
SocketInit(WG_DEVICE *Wg, UINT16 Port)
{
    NTSTATUS Status;
    SOCKADDR_IN Sa4 = { .sin_family = AF_INET, .sin_addr.s_addr = Htonl(INADDR_ANY), .sin_port = Htons(Port) };
    SOCKADDR_IN6 Sa6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT };
    SOCKET *New4 = NULL, *New6 = NULL;
    LONG Retries = 0;

retry:
    if (WskHasIpv4Transport)
    {
        Status = CreateAndBindSocket(Wg, (SOCKADDR *)&Sa4, &New4);
        if (!NT_SUCCESS(Status))
            goto out;
    }

    if (WskHasIpv6Transport)
    {
        Sa6.sin6_port = Sa4.sin_port;
        Status = CreateAndBindSocket(Wg, (SOCKADDR *)&Sa6, &New6);
        if (!NT_SUCCESS(Status))
        {
            CloseSocket(New4);
            New4 = NULL;
            if (Status == STATUS_ADDRESS_ALREADY_EXISTS && !Port && Retries++ < 100)
                goto retry;
            goto out;
        }
    }

    SocketReinit(
        Wg,
        New4,
        New6,
        WskHasIpv4Transport   ? Ntohs(Sa4.sin_port)
        : WskHasIpv6Transport ? Ntohs(Sa6.sin6_port)
                              : Port);
    Status = STATUS_SUCCESS;
out:
    return Status;
}

_Use_decl_annotations_
VOID
SocketReinit(WG_DEVICE *Wg, SOCKET *New4, SOCKET *New6, UINT16 Port)
{
    MuAcquirePushLockExclusive(&Wg->SocketUpdateLock);
    SOCKET *Old4 = RcuDereferenceProtected(SOCKET, Wg->Sock4, &Wg->SocketUpdateLock);
    SOCKET *Old6 = RcuDereferenceProtected(SOCKET, Wg->Sock6, &Wg->SocketUpdateLock);
    RcuAssignPointer(Wg->Sock4, New4);
    RcuAssignPointer(Wg->Sock6, New6);
    if (New4 || New6)
        Wg->IncomingPort = Port;
    MuReleasePushLockExclusive(&Wg->SocketUpdateLock);
    RcuSynchronize();
    CloseSocket(Old4);
    CloseSocket(Old6);
}

static VOID
RouteNotification(
    _In_ VOID *CallerContext,
    _In_opt_ MIB_IPFORWARD_ROW2 *Row,
    _In_ MIB_NOTIFICATION_TYPE NotificationType)
{
    InterlockedAdd((LONG *)CallerContext, 2);
}

_Use_decl_annotations_
NTSTATUS
WskInit(VOID)
{
    NTSTATUS Status = ReadNoFence(&WskInitStatus);
    if (Status != STATUS_RETRY)
        return Status;
    MuAcquirePushLockExclusive(&WskIsIniting);
    Status = ReadNoFence(&WskInitStatus);
    if (Status != STATUS_RETRY)
        goto cleanupIniting;

#if NTDDI_VERSION == NTDDI_WIN7
    RTL_OSVERSIONINFOW OsVersionInfo = { .dwOSVersionInfoSize = sizeof(OsVersionInfo) };
    NoWskSendMessages =
        NT_SUCCESS(RtlGetVersion(&OsVersionInfo)) &&
        (OsVersionInfo.dwMajorVersion < 6 || (OsVersionInfo.dwMajorVersion == 6 && OsVersionInfo.dwMinorVersion < 2));
#endif

    Status = ExInitializeLookasideListEx(
        &SocketSendCtxCache, NULL, NULL, NonPagedPool, 0, sizeof(SOCKET_SEND_CTX), MEMORY_TAG, 0);
    if (!NT_SUCCESS(Status))
        goto cleanupIniting;
    WSK_CLIENT_NPI WskClientNpi = { .Dispatch = &WskAppDispatchV1 };
    Status = WskRegister(&WskClientNpi, &WskRegistration);
    if (!NT_SUCCESS(Status))
        goto cleanupLookaside;
    Status = WskCaptureProviderNPI(&WskRegistration, WSK_INFINITE_WAIT, &WskProviderNpi);
    if (!NT_SUCCESS(Status))
        goto cleanupWskRegister;
    SIZE_T WskTransportsSize = 0x10 * sizeof(WSK_TRANSPORT);
    for (;;)
    {
        WSK_TRANSPORT *WskTransports = MemAllocate(WskTransportsSize);
        if (!WskTransports)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanupWskProviderNPI;
        }
        Status = WskProviderNpi.Dispatch->WskControlClient(
            WskProviderNpi.Client,
            WSK_TRANSPORT_LIST_QUERY,
            0,
            NULL,
            WskTransportsSize,
            WskTransports,
            &WskTransportsSize,
            NULL);
        if (NT_SUCCESS(Status))
        {
            for (SIZE_T i = 0, n = WskTransportsSize / sizeof(*WskTransports); i < n; ++i)
            {
                if (WskTransports[i].SocketType == SOCK_DGRAM && WskTransports[i].Protocol == IPPROTO_UDP)
                {
                    if (WskTransports[i].AddressFamily == AF_UNSPEC)
                    {
                        WskHasIpv4Transport = TRUE;
                        WskHasIpv6Transport = TRUE;
                    }
                    else if (WskTransports[i].AddressFamily == AF_INET)
                        WskHasIpv4Transport = TRUE;
                    else if (WskTransports[i].AddressFamily == AF_INET6)
                        WskHasIpv6Transport = TRUE;
                }
            }
            MemFree(WskTransports);
            break;
        }
        MemFree(WskTransports);
        if (Status != STATUS_BUFFER_OVERFLOW)
            goto cleanupWskProviderNPI;
    }
    WSK_EVENT_CALLBACK_CONTROL WskEventCallbackControl = { .NpiId = &NPI_WSK_INTERFACE_ID,
                                                           .EventMask = WSK_EVENT_RECEIVE_FROM };
    Status = WskProviderNpi.Dispatch->WskControlClient(
        WskProviderNpi.Client,
        WSK_SET_STATIC_EVENT_CALLBACKS,
        sizeof(WskEventCallbackControl),
        &WskEventCallbackControl,
        0,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(Status))
        goto cleanupWskProviderNPI;

    /* Ignore return value, as MSDN says eventually this will be removed. */
    ULONG NoTdi = WSK_TDI_BEHAVIOR_BYPASS_TDI;
    WskProviderNpi.Dispatch->WskControlClient(
        WskProviderNpi.Client,
        WSK_TDI_BEHAVIOR,
        sizeof(NoTdi),
        &NoTdi,
        0,
        NULL,
        NULL,
        NULL);

    Status = NotifyRouteChange2(AF_INET, RouteNotification, &RoutingGenerationV4, FALSE, &RouteNotifierV4);
    if (!NT_SUCCESS(Status))
        goto cleanupWskProviderNPI;
    Status = NotifyRouteChange2(AF_INET6, RouteNotification, &RoutingGenerationV6, FALSE, &RouteNotifierV6);
    if (!NT_SUCCESS(Status))
        goto cleanupRouteNotifierV4;

    WriteNoFence(&WskInitStatus, STATUS_SUCCESS);
    MuReleasePushLockExclusive(&WskIsIniting);
    return STATUS_SUCCESS;

cleanupRouteNotifierV4:
    CancelMibChangeNotify2(RouteNotifierV4);
cleanupWskProviderNPI:
    WskReleaseProviderNPI(&WskRegistration);
cleanupWskRegister:
    WskDeregister(&WskRegistration);
cleanupLookaside:
    ExDeleteLookasideListEx(&SocketSendCtxCache);
cleanupIniting:
    WriteNoFence(&WskInitStatus, Status);
    MuReleasePushLockExclusive(&WskIsIniting);
    return Status;
}

_Use_decl_annotations_
VOID WskUnload(VOID)
{
    MuAcquirePushLockExclusive(&WskIsIniting);
    if (ReadNoFence(&WskInitStatus) != STATUS_SUCCESS)
        goto out;
    CancelMibChangeNotify2(RouteNotifierV6);
    CancelMibChangeNotify2(RouteNotifierV4);
    WskReleaseProviderNPI(&WskRegistration);
    WskDeregister(&WskRegistration);
    ExDeleteLookasideListEx(&SocketSendCtxCache);
out:
    MuReleasePushLockExclusive(&WskIsIniting);
}
