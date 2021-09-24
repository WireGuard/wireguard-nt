/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "containers.h"
#include "device.h"
#include "ioctl.h"
#include "messages.h"
#include "peer.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "socket.h"
#include "timers.h"
#include "logging.h"
#include <ntstrsafe.h>
#include <netioapi.h>

#pragma warning(disable : 28175) /* undocumented: the member of struct should not be accessed by a driver */

#define NDIS_MINIPORT_VERSION_MIN ((NDIS_MINIPORT_MINIMUM_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINIMUM_MINOR_VERSION)
#define NDIS_MINIPORT_VERSION_MAX ((NDIS_MINIPORT_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINOR_VERSION)

#define VENDOR_NAME "WireGuard Tunnel"
#define VENDOR_ID 0xFFFFFF00
#define LINK_SPEED 100000000000ULL /* 100gbps */
#define BUFFER_SPACE 0x4000000     /* 64MiB */

static UINT NdisVersion;
static NDIS_HANDLE NdisMiniportDriverHandle;
static HANDLE IpInterfaceNotifier;
static PKTHREAD IpInterfaceNotifierBugWorkaroundThread;
static KEVENT IpInterfaceNotifierBugWorkaroundTerminate;
static LIST_ENTRY DeviceList;
static EX_PUSH_LOCK DeviceListLock;

MINIPORT_UNLOAD Unload;

_Use_decl_annotations_
VOID
DeviceStart(WG_DEVICE *Wg)
{
    WG_PEER *Peer;

    LIST_FOR_EACH_ENTRY (Peer, &Wg->PeerList, WG_PEER, PeerList)
    {
        PacketSendStagedPackets(Peer);
        if (Peer->PersistentKeepaliveInterval)
            PacketSendKeepalive(Peer);
    }
}

static MINIPORT_RESTART Restart;
_Use_decl_annotations_
static NDIS_STATUS
Restart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
    WG_DEVICE *Wg = (WG_DEVICE *)MiniportAdapterContext;

    MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);
    ExReInitializeRundownProtection(&Wg->ItemsInFlight);
    if (ReadBooleanNoFence(&Wg->IsUp))
        DeviceStart(Wg);
    MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DeviceStop(WG_DEVICE *Wg)
{
    WG_PEER *Peer;

    LIST_FOR_EACH_ENTRY (Peer, &Wg->PeerList, WG_PEER, PeerList)
    {
        PacketPurgeStagedPackets(Peer);
        TimersStop(Peer);
        NoiseHandshakeClear(&Peer->Handshake);
        NoiseKeypairsClear(&Peer->Keypairs);
        NoiseResetLastSentHandshake(&Peer->LastSentHandshake);
    }
    FreeIncomingHandshakes(Wg);
}

static MINIPORT_PAUSE Pause;
_Use_decl_annotations_
static NDIS_STATUS
Pause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
    WG_DEVICE *Wg = (WG_DEVICE *)MiniportAdapterContext;

    MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);
    ExWaitForRundownProtectionRelease(&Wg->ItemsInFlight);
    if (ReadBooleanNoFence(&Wg->IsUp))
        DeviceStop(Wg);
    MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DeviceIndicateConnectionStatus(NDIS_HANDLE MiniportAdapterHandle, NDIS_MEDIA_CONNECT_STATE MediaConnectState)
{
    NDIS_LINK_STATE State = { .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                                          .Revision = NDIS_LINK_STATE_REVISION_1,
                                          .Size = NDIS_SIZEOF_LINK_STATE_REVISION_1 },
                              .MediaConnectState = MediaConnectState,
                              .MediaDuplexState = MediaDuplexStateFull,
                              .XmitLinkSpeed = LINK_SPEED,
                              .RcvLinkSpeed = LINK_SPEED,
                              .PauseFunctions = NdisPauseFunctionsUnsupported };

    NDIS_STATUS_INDICATION Indication = { .Header = { .Type = NDIS_OBJECT_TYPE_STATUS_INDICATION,
                                                      .Revision = NDIS_STATUS_INDICATION_REVISION_1,
                                                      .Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1 },
                                          .SourceHandle = MiniportAdapterHandle,
                                          .StatusCode = NDIS_STATUS_LINK_STATE,
                                          .StatusBuffer = &State,
                                          .StatusBufferSize = sizeof(State) };

    NdisMIndicateStatusEx(MiniportAdapterHandle, &Indication);
}

static MINIPORT_SEND_NET_BUFFER_LISTS SendNetBufferLists;
_Use_decl_annotations_
static VOID
SendNetBufferLists(
    NDIS_HANDLE MiniportAdapterContext,
    NET_BUFFER_LIST *NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags)
{
    WG_DEVICE *Wg = (WG_DEVICE *)MiniportAdapterContext;
    ULONG CompleteFlags = 0;
    if (SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL)
        CompleteFlags |= NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    for (NET_BUFFER_LIST *Nbl = NetBufferLists, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;

        if (!ExAcquireRundownProtection(&Wg->ItemsInFlight))
        {
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_PAUSED;
            NdisMSendNetBufferListsComplete(Wg->MiniportAdapterHandle, Nbl, CompleteFlags);
            ++Wg->Statistics.ifOutDiscards;
            continue;
        }
        if (!ReadBooleanNoFence(&Wg->IsUp))
        {
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_MEDIA_DISCONNECTED;
            goto returnNbl;
        }

        NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
        if (!Nb)
        {
            LogInfoRatelimited(Wg, "Missing NET_BUFFER");
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_FAILURE;
            ++Wg->Statistics.ifOutErrors;
            goto returnNbl;
        }

        NET_BUFFER_LIST *CloneNbl = MemAllocateNetBufferListWithClonedGeometry(
            Nbl, sizeof(MESSAGE_DATA) + NoiseEncryptedLen(0) + MESSAGE_PADDING_MULTIPLE - 1);
        if (!CloneNbl)
        {
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_RESOURCES;
            goto returnNbl;
        }
        Nbl = CloneNbl;

        CONST UINT16_BE Protocol = NET_BUFFER_LIST_PROTOCOL(Nbl);
        IPV4HDR *Header4 = NULL;
        IPV6HDR *Header6 = NULL;
        VOID *Header = NULL;
        /* Potential TOCTOU? Generally NDIS considers headers fair game for R/W, but raw sockets
         * and hyper-v devices make me fear that a physically local user might be able to modify
         * Header4/6 while we're reading it.
         */
        if (Protocol == Htons(NDIS_ETH_TYPE_IPV4))
            Header4 = Header = NdisGetDataBuffer(Nb, sizeof(IPV4HDR), NULL, 1, 0);
        else if (Protocol == Htons(NDIS_ETH_TYPE_IPV6))
            Header6 = Header = NdisGetDataBuffer(Nb, sizeof(IPV6HDR), NULL, 1, 0);
        else
        {
            LogInfoRatelimited(Wg, "Unsupported NBL protocol");
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_FAILURE;
            ++Wg->Statistics.ifOutErrors;
            goto returnNbl;
        }
        if ((!Header4 || Header4->Version != 4 || Ntohs(Header4->TotLen) != NET_BUFFER_DATA_LENGTH(Nb)) &&
            (!Header6 || Header6->Version != 6 ||
             Ntohs(Header6->PayloadLen) + sizeof(IPV6HDR) != NET_BUFFER_DATA_LENGTH(Nb)))
        {
            LogInfoRatelimited(Wg, "Invalid IP packet");
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_FAILURE;
            ++Wg->Statistics.ifOutErrors;
            goto returnNbl;
        }

        WG_PEER *Peer = AllowedIpsLookupDst(&Wg->PeerAllowedIps, Protocol, Header);
        if (!Peer)
        {
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_FAILURE;
            ++Wg->Statistics.ifOutErrors;
            goto returnNbl;
        }
        ADDRESS_FAMILY Family = ReadUShortNoFence(&Peer->Endpoint.Addr.si_family);
        if (Family != AF_INET && Family != AF_INET6)
        {
            LogInfoRatelimited(
                Wg, "No valid endpoint has been configured or discovered for peer %llu", Peer->InternalId);
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_FAILURE;
            ++Wg->Statistics.ifOutErrors;
            goto cleanupPeer;
        }

        KIRQL Irql;
        KeAcquireSpinLock(&Peer->StagedPacketQueue.Lock, &Irql);
        /* If the queue is getting too big, we start removing the oldest packets
         * until it's small again. We do this before adding the new packet, so
         * we don't remove GSO segments that are in excess.
         */
        while (NetBufferListQueueLength(&Peer->StagedPacketQueue) > MAX_STAGED_PACKETS)
        {
            NET_BUFFER_LIST *NblToDiscard = NetBufferListDequeue(&Peer->StagedPacketQueue);
            _Analysis_assume_(NblToDiscard); /* NetBufferListQueueLength() > MAX_STAGED_PACKETS implies
                                                NetBufferListDequeue() returns a NBL. */
            NET_BUFFER_LIST_STATUS(NblToDiscard) = NDIS_STATUS_FAILURE;
            ++Wg->Statistics.ifOutDiscards;
            FreeSendNetBufferList(Wg, NblToDiscard, CompleteFlags | NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }
        NetBufferListEnqueue(&Peer->StagedPacketQueue, Nbl);
        KeReleaseSpinLock(&Peer->StagedPacketQueue.Lock, Irql);

        PacketSendStagedPackets(Peer);
        PeerPut(Peer);
        continue;

    cleanupPeer:
        PeerPut(Peer);
    returnNbl:
        FreeSendNetBufferList(Wg, Nbl, CompleteFlags);
        ++Wg->Statistics.ifOutDiscards;
    }
}

static MINIPORT_CANCEL_SEND CancelSend;
_Use_decl_annotations_
static VOID
CancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
}

static VOID
IpInterfaceChangeNotification(
    _In_ PVOID CallerContext,
    _In_opt_ PMIB_IPINTERFACE_ROW Row,
    _In_ MIB_NOTIFICATION_TYPE NotificationType)
{
    if ((NotificationType != MibAddInstance && NotificationType != MibParameterNotification) || !Row ||
        (NotificationType == MibParameterNotification && (!Row->NlMtu || Row->NlMtu == ~0U)))
        return;
    MuAcquirePushLockShared(&DeviceListLock);
    WG_DEVICE *IterWg, *Wg = NULL;
    LIST_FOR_EACH_ENTRY (IterWg, &DeviceList, WG_DEVICE, DeviceList)
    {
        if (IterWg->InterfaceLuid.Value == Row->InterfaceLuid.Value)
        {
            Wg = IterWg;
            break;
        }
    }
    if (!Wg)
        goto cleanupDeviceListLock;
    ULONG *Mtu;
    if (Row->Family == AF_INET)
        Mtu = &Wg->Mtu4;
    else if (Row->Family == AF_INET6)
        Mtu = &Wg->Mtu6;
    else
        goto cleanupDeviceListLock;
    if (NotificationType == MibAddInstance && !*Mtu)
    {
        if ((!Row->NlMtu || Row->NlMtu == ~0U) && !NT_SUCCESS(GetIpInterfaceEntry(Row)))
            goto cleanupDeviceListLock;
        *Mtu = Row->NlMtu;
        Row->SitePrefixLength = 0;
        Row->NlMtu = 1500 - DATA_PACKET_MINIMUM_LENGTH;
        if (*Mtu == MTU_MAX || !*Mtu || *Mtu == ~0U)
        {
            *Mtu = Row->NlMtu = 1500 - DATA_PACKET_MINIMUM_LENGTH;
            SetIpInterfaceEntry(Row);
        }
    }
    else if (NotificationType == MibParameterNotification)
        *Mtu = Row->NlMtu;
cleanupDeviceListLock:
    MuReleasePushLockShared(&DeviceListLock);
}

static KSTART_ROUTINE IpInterfaceNotifierBugWorkaroundRoutine;
_Use_decl_annotations_
static VOID
IpInterfaceNotifierBugWorkaroundRoutine(PVOID StartContext)
{
    while (KeWaitForSingleObject(
               &IpInterfaceNotifierBugWorkaroundTerminate,
               Executive,
               KernelMode,
               FALSE,
               &(LARGE_INTEGER){ .QuadPart = -SEC_TO_SYS_TIME_UNITS(3) }) == STATUS_TIMEOUT)
    {
        MuAcquirePushLockShared(&DeviceListLock);
        WG_DEVICE *Wg;
        LIST_FOR_EACH_ENTRY (Wg, &DeviceList, WG_DEVICE, DeviceList)
        {
            if (Wg->Mtu4)
            {
                MIB_IPINTERFACE_ROW Row = { .InterfaceLuid = Wg->InterfaceLuid, .Family = AF_INET };
                if (NT_SUCCESS(GetIpInterfaceEntry(&Row)) && Row.NlMtu && Row.NlMtu != ~0U)
                    Wg->Mtu4 = Row.NlMtu;
            }
            if (Wg->Mtu6)
            {
                MIB_IPINTERFACE_ROW Row = { .InterfaceLuid = Wg->InterfaceLuid, .Family = AF_INET6 };
                if (NT_SUCCESS(GetIpInterfaceEntry(&Row)) && Row.NlMtu && Row.NlMtu != ~0U)
                    Wg->Mtu6 = Row.NlMtu;
            }
        }
        MuReleasePushLockShared(&DeviceListLock);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS InitIpInterfaceNotifierBugWorkaround(VOID)
{
    RTL_OSVERSIONINFOW OsVersionInfo = { .dwOSVersionInfoSize = sizeof(OsVersionInfo) };
    if (NT_SUCCESS(RtlGetVersion(&OsVersionInfo)) &&
        (OsVersionInfo.dwMajorVersion > 10 ||
         /* TODO: Update the 999999 here once we know which builds this is fixed on. */
         (OsVersionInfo.dwMajorVersion == 10 && OsVersionInfo.dwBuildNumber >= 999999)))
        return STATUS_SUCCESS;

    KeInitializeEvent(&IpInterfaceNotifierBugWorkaroundTerminate, NotificationEvent, FALSE);
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE Handle;
    NTSTATUS Status = PsCreateSystemThread(
        &Handle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, IpInterfaceNotifierBugWorkaroundRoutine, NULL);
    if (!NT_SUCCESS(Status))
        return Status;
    ObReferenceObjectByHandle(Handle, SYNCHRONIZE, NULL, KernelMode, &IpInterfaceNotifierBugWorkaroundThread, NULL);
    ZwClose(Handle);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID UninitIpInterfaceNotifierBugWorkaround(VOID)
{
    if (!IpInterfaceNotifierBugWorkaroundThread)
        return;
    KeSetEvent(&IpInterfaceNotifierBugWorkaroundTerminate, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(IpInterfaceNotifierBugWorkaroundThread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(IpInterfaceNotifierBugWorkaroundThread);
}

static MINIPORT_HALT HaltEx;
_Use_decl_annotations_
static VOID
HaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
    WG_DEVICE *Wg = (WG_DEVICE *)MiniportAdapterContext;
    IoctlHalt(Wg);
    MuAcquirePushLockExclusive(&DeviceListLock);
    RemoveEntryList(&Wg->DeviceList);
    MuReleasePushLockExclusive(&DeviceListLock);
    MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);
    Wg->IncomingPort = 0;
    SocketReinit(Wg, NULL, NULL, 0);
    if (Wg->SocketOwnerProcess)
    {
        ObDereferenceObject(Wg->SocketOwnerProcess);
        Wg->SocketOwnerProcess = NULL;
    }
    PeerRemoveAll(Wg);
    MulticoreWorkQueueDestroy(&Wg->DecryptThreads);
    MulticoreWorkQueueDestroy(&Wg->EncryptThreads);
    MulticoreWorkQueueDestroy(&Wg->HandshakeRxThreads);
    MulticoreWorkQueueDestroy(&Wg->HandshakeTxThreads);
    PtrRingFree(&Wg->DecryptQueue);
    PtrRingFree(&Wg->EncryptQueue);
    RcuBarrier();
    NoiseStaticIdentityClear(&Wg->StaticIdentity);
    FreeIncomingHandshakes(Wg);
    PtrRingFree(&Wg->HandshakeRxQueue);
    MemFree(Wg->IndexHashtable);
    MemFree(Wg->PeerHashtable);
    MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);

    WritePointerNoFence(&Wg->MiniportAdapterHandle, NULL);
    LogInfo(Wg, "Interface destroyed");
    MemFree(Wg);
}

#pragma warning(suppress : 28194) /* `Wg` is aliased in NdisMSetMiniportAttributes. */
_IRQL_requires_max_(PASSIVE_LEVEL)
static NDIS_STATUS
RegisterAdapter(_In_ NDIS_HANDLE MiniportAdapterHandle, _In_ __drv_aliasesMem WG_DEVICE *Wg)
{
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES AdapterRegistrationAttributes = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630
                                    ? NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
                                    : NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630
                                ? NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
                                : NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2 },
        .AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND | NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK,
        .InterfaceType = NdisInterfaceInternal,
        .MiniportAdapterContext = Wg
    };
    NDIS_STATUS Status = NdisMSetMiniportAttributes(
        MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterRegistrationAttributes);
    if (!NT_SUCCESS(Status))
        return Status;

    NDIS_PM_CAPABILITIES PmCapabilities = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_PM_CAPABILITIES_REVISION_1
                                                                       : NDIS_PM_CAPABILITIES_REVISION_2,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1
                                                                   : NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2 },
        .MinMagicPacketWakeUp = NdisDeviceStateUnspecified,
        .MinPatternWakeUp = NdisDeviceStateUnspecified,
        .MinLinkChangeWakeUp = NdisDeviceStateUnspecified
    };
    static NDIS_OID SupportedOids[] = { OID_GEN_MAXIMUM_TOTAL_SIZE,
                                        OID_GEN_CURRENT_LOOKAHEAD,
                                        OID_GEN_TRANSMIT_BUFFER_SPACE,
                                        OID_GEN_RECEIVE_BUFFER_SPACE,
                                        OID_GEN_TRANSMIT_BLOCK_SIZE,
                                        OID_GEN_RECEIVE_BLOCK_SIZE,
                                        OID_GEN_VENDOR_DESCRIPTION,
                                        OID_GEN_VENDOR_ID,
                                        OID_GEN_VENDOR_DRIVER_VERSION,
                                        OID_GEN_XMIT_OK,
                                        OID_GEN_RCV_OK,
                                        OID_GEN_CURRENT_PACKET_FILTER,
                                        OID_GEN_STATISTICS,
                                        OID_GEN_INTERRUPT_MODERATION,
                                        OID_GEN_LINK_PARAMETERS,
                                        OID_PNP_SET_POWER,
                                        OID_PNP_QUERY_POWER };
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES AdapterGeneralAttributes = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES,
                    .Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2,
                    .Size = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2 },
        .MediaType = NdisMediumIP,
        .PhysicalMediumType = NdisPhysicalMediumUnspecified,
        .MtuSize = MTU_MAX,
        .MaxXmitLinkSpeed = LINK_SPEED,
        .MaxRcvLinkSpeed = LINK_SPEED,
        .RcvLinkSpeed = LINK_SPEED,
        .XmitLinkSpeed = LINK_SPEED,
        .MediaConnectState = MediaConnectStateDisconnected,
        .MediaDuplexState = MediaDuplexStateFull,
        .LookaheadSize = MTU_MAX,
        .MacOptions =
            NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | NDIS_MAC_OPTION_NO_LOOPBACK,
        .SupportedPacketFilters = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_ALL_MULTICAST |
                                  NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_ALL_LOCAL |
                                  NDIS_PACKET_TYPE_ALL_FUNCTIONAL,
        .AccessType = NET_IF_ACCESS_BROADCAST,
        .DirectionType = NET_IF_DIRECTION_SENDRECEIVE,
        .ConnectionType = NET_IF_CONNECTION_DEDICATED,
        .IfType = IF_TYPE_PROP_VIRTUAL,
        .IfConnectorPresent = FALSE,
        .SupportedStatistics = Wg->Statistics.SupportedStatistics,
        .SupportedPauseFunctions = NdisPauseFunctionsUnsupported,
        .SupportedOidList = SupportedOids,
        .SupportedOidListLength = sizeof(SupportedOids),
        .AutoNegotiationFlags =
            NDIS_LINK_STATE_XMIT_LINK_SPEED_AUTO_NEGOTIATED | NDIS_LINK_STATE_RCV_LINK_SPEED_AUTO_NEGOTIATED |
            NDIS_LINK_STATE_DUPLEX_AUTO_NEGOTIATED | NDIS_LINK_STATE_PAUSE_FUNCTIONS_AUTO_NEGOTIATED,
        .PowerManagementCapabilitiesEx = &PmCapabilities
    };
    Status =
        NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterGeneralAttributes);
    if (!NT_SUCCESS(Status))
        return Status;

    NDIS_OFFLOAD Offload = {
        .Header = { .Type = NDIS_OBJECT_TYPE_OFFLOAD,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630   ? NDIS_OFFLOAD_REVISION_2
                                : NdisVersion < NDIS_RUNTIME_VERSION_650 ? NDIS_OFFLOAD_REVISION_3
                                : NdisVersion < NDIS_RUNTIME_VERSION_670 ? NDIS_OFFLOAD_REVISION_4
                                : NdisVersion < NDIS_RUNTIME_VERSION_683 ? NDIS_OFFLOAD_REVISION_5
                                                                         : NDIS_OFFLOAD_REVISION_6,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630   ? NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_2
                            : NdisVersion < NDIS_RUNTIME_VERSION_650 ? NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_3
                            : NdisVersion < NDIS_RUNTIME_VERSION_670 ? NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_4
                            : NdisVersion < NDIS_RUNTIME_VERSION_683 ? NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_5
                                                                     : NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_6 },
        .Checksum = { .IPv4Receive = { .IpOptionsSupported = NDIS_OFFLOAD_SUPPORTED,
                                       .TcpOptionsSupported = NDIS_OFFLOAD_SUPPORTED,
                                       .TcpChecksum = NDIS_OFFLOAD_SUPPORTED,
                                       .UdpChecksum = NDIS_OFFLOAD_SUPPORTED,
                                       .IpChecksum = NDIS_OFFLOAD_SUPPORTED },
                      .IPv6Receive = { .IpExtensionHeadersSupported = NDIS_OFFLOAD_SUPPORTED,
                                       .TcpOptionsSupported = NDIS_OFFLOAD_SUPPORTED,
                                       .TcpChecksum = NDIS_OFFLOAD_SUPPORTED,
                                       .UdpChecksum = NDIS_OFFLOAD_SUPPORTED } },
    };
    NDIS_TCP_CONNECTION_OFFLOAD ConnectionOffload = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NDIS_TCP_CONNECTION_OFFLOAD_REVISION_1,
                    .Size = NDIS_SIZEOF_TCP_CONNECTION_OFFLOAD_REVISION_1 },
    };
    NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES AdapterOffloadAttributes = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES,
                    .Revision = NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1,
                    .Size = NDIS_SIZEOF_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1 },
        .DefaultOffloadConfiguration = &Offload,
        .HardwareOffloadCapabilities = &Offload,
        .DefaultTcpConnectionOffloadConfiguration = &ConnectionOffload,
        .TcpConnectionOffloadHardwareCapabilities = &ConnectionOffload,
    };
    Status =
        NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterOffloadAttributes);
    if (!NT_SUCCESS(Status))
        return Status;

    return NDIS_STATUS_SUCCESS;
}

static MINIPORT_INITIALIZE InitializeEx;
_Use_decl_annotations_
static NDIS_STATUS
InitializeEx(
    NDIS_HANDLE MiniportAdapterHandle,
    NDIS_HANDLE MiniportDriverContext,
    PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
    NTSTATUS Status;
    WG_DEVICE *Wg = MemAllocateAndZero(sizeof(*Wg));
    if (!Wg)
        return NDIS_STATUS_RESOURCES;
    Wg->MiniportAdapterHandle = MiniportAdapterHandle;
    Wg->InterfaceIndex = MiniportInitParameters->IfIndex;
    Wg->InterfaceLuid = MiniportInitParameters->NetLuid;
    LogRingInit(&Wg->Log);
    KeInitializeEvent(&Wg->DeviceRemoved, NotificationEvent, FALSE);

    NdisMGetDeviceProperty(MiniportAdapterHandle, NULL, &Wg->FunctionalDeviceObject, NULL, NULL, NULL);
    if (!Wg->FunctionalDeviceObject)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanupWg;
    }
    NT_ASSERT(!Wg->FunctionalDeviceObject->Reserved);
    /* Reverse engineering indicates that we'd be better off calling
     * NdisWdfGetAdapterContextFromAdapterHandle(functional_device), which points to our WG_DEVICE object
     * directly, but this isn't available before Windows 10, so for now we just stick it into this reserved field.
     * Revisit this when we drop support for old Windows versions. */
    Wg->FunctionalDeviceObject->Reserved = Wg;

    ExInitializeRundownProtection(&Wg->ItemsInFlight);
    ExRundownCompleted(&Wg->ItemsInFlight); /* Wait until Restart is called to mark this active. */

    MuInitializePushLock(&Wg->StaticIdentity.Lock);
    MuInitializePushLock(&Wg->SocketUpdateLock);
    MuInitializePushLock(&Wg->DeviceUpdateLock);
    PeerSerialInit(&Wg->TxQueue);
    PeerSerialInit(&Wg->RxQueue);
    PeerSerialInit(&Wg->HandshakeTxQueue);
    AllowedIpsInit(&Wg->PeerAllowedIps);
    CookieCheckerInit(&Wg->CookieChecker, Wg);
    InitializeListHead(&Wg->PeerList);

    Status = STATUS_INSUFFICIENT_RESOURCES;

    Wg->PeerHashtable = PubkeyHashtableAlloc();
    if (!Wg->PeerHashtable)
        goto cleanupWg;

    Wg->IndexHashtable = IndexHashtableAlloc();
    if (!Wg->IndexHashtable)
        goto cleanupPeerHashtable;

    Wg->Statistics.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Wg->Statistics.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
    Wg->Statistics.Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
    Wg->Statistics.SupportedStatistics =
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV | NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS | NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT | NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR | NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV | NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT | NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;

    Status = PtrRingInit(&Wg->EncryptQueue, MAX_QUEUED_PACKETS);
    if (!NT_SUCCESS(Status))
        goto cleanupIndexHashtable;

    Status = PtrRingInit(&Wg->DecryptQueue, MAX_QUEUED_PACKETS);
    if (!NT_SUCCESS(Status))
        goto cleanupEncryptQueue;

    Status = PtrRingInit(&Wg->HandshakeRxQueue, MAX_QUEUED_INCOMING_HANDSHAKES);
    if (!NT_SUCCESS(Status))
        goto cleanupDecryptQueue;

    Status = MulticoreWorkQueueInit(&Wg->EncryptThreads, PacketEncryptWorker);
    if (!NT_SUCCESS(Status))
        goto cleanupHandshakeRxQueue;

    Status = MulticoreWorkQueueInit(&Wg->DecryptThreads, PacketDecryptWorker);
    if (!NT_SUCCESS(Status))
        goto cleanupEncryptThreads;

    Status = MulticoreWorkQueueInit(&Wg->HandshakeTxThreads, PacketHandshakeTxWorker);
    if (!NT_SUCCESS(Status))
        goto cleanupDecryptThreads;

    Status = MulticoreWorkQueueInit(&Wg->HandshakeRxThreads, PacketHandshakeRxWorker);
    if (!NT_SUCCESS(Status))
        goto cleanupHandshakeTxThreads;

    Status = RegisterAdapter(MiniportAdapterHandle, Wg);
    if (!NT_SUCCESS(Status))
        goto cleanupHandshakeRxThreads;

    MuAcquirePushLockExclusive(&DeviceListLock);
    InsertHeadList(&DeviceList, &Wg->DeviceList);
    MuReleasePushLockExclusive(&DeviceListLock);

    LogInfo(Wg, "Interface created");

    return NDIS_STATUS_SUCCESS;

cleanupHandshakeRxThreads:
    MulticoreWorkQueueDestroy(&Wg->HandshakeRxThreads);
cleanupHandshakeTxThreads:
    MulticoreWorkQueueDestroy(&Wg->HandshakeTxThreads);
cleanupDecryptThreads:
    MulticoreWorkQueueDestroy(&Wg->DecryptThreads);
cleanupEncryptThreads:
    MulticoreWorkQueueDestroy(&Wg->EncryptThreads);
cleanupHandshakeRxQueue:
    PtrRingFree(&Wg->HandshakeRxQueue);
cleanupDecryptQueue:
    PtrRingFree(&Wg->DecryptQueue);
cleanupEncryptQueue:
    PtrRingFree(&Wg->EncryptQueue);
cleanupIndexHashtable:
    MemFree(Wg->IndexHashtable);
cleanupPeerHashtable:
    MemFree(Wg->PeerHashtable);
cleanupWg:
    MemFree(Wg);
    if (Status == STATUS_INSUFFICIENT_RESOURCES)
        return NDIS_STATUS_RESOURCES;
    NdisWriteErrorLogEntry(MiniportAdapterHandle, NDIS_ERROR_CODE_DRIVER_FAILURE, 1, Status);
    return NDIS_STATUS_FAILURE;
}

static MINIPORT_DEVICE_PNP_EVENT_NOTIFY DevicePnPEventNotify;
_Use_decl_annotations_
static VOID
DevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext, PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
}

static MINIPORT_SHUTDOWN ShutdownEx;
_Use_decl_annotations_
static VOID
ShutdownEx(NDIS_HANDLE MiniportAdapterContext, NDIS_SHUTDOWN_ACTION ShutdownAction)
{
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
OidQueryWrite(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_ ULONG Value)
{
    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(Value))
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(Value);
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(Value);
    RtlCopyMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, &Value, sizeof(Value));
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
OidQueryWrite32or64(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_ ULONG64 Value)
{
    ULONG Truncated;

    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(Truncated))
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(Value);
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(Value))
    {
        if (!NT_SUCCESS(RtlULong64ToULong(Value, &Truncated)))
        {
            OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(Value);
            OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten =
            sizeof(Truncated);
        RtlCopyMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, &Truncated, sizeof(Truncated));
        return NDIS_STATUS_SUCCESS;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(Value);
    RtlCopyMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, &Value, sizeof(Value));
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
OidQueryWriteBuf(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_reads_bytes_(Size) CONST VOID *Buf, _In_ ULONG Size)
{
    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < Size)
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = Size;
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = Size;
    RtlCopyMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, Buf, Size);
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
OidQuery(_Inout_ WG_DEVICE *Wg, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
    NT_ASSERT(
        OidRequest->RequestType == NdisRequestQueryInformation ||
        OidRequest->RequestType == NdisRequestQueryStatistics);

    switch (OidRequest->DATA.QUERY_INFORMATION.Oid)
    {
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        return OidQueryWrite(OidRequest, MTU_MAX);

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
        return OidQueryWrite(OidRequest, BUFFER_SPACE);

    case OID_GEN_RECEIVE_BUFFER_SPACE:
        return OidQueryWrite(OidRequest, BUFFER_SPACE);

    case OID_GEN_VENDOR_ID:
        return OidQueryWrite(OidRequest, Htonl(VENDOR_ID));

    case OID_GEN_VENDOR_DESCRIPTION:
        return OidQueryWriteBuf(OidRequest, VENDOR_NAME, sizeof(VENDOR_NAME));

    case OID_GEN_VENDOR_DRIVER_VERSION:
        return OidQueryWrite(OidRequest, (WIREGUARD_VERSION_MAJ << 16) | WIREGUARD_VERSION_MIN);

    case OID_GEN_XMIT_OK:
        return OidQueryWrite32or64(
            OidRequest,
            Wg->Statistics.ifHCOutUcastPkts + Wg->Statistics.ifHCOutMulticastPkts +
                Wg->Statistics.ifHCOutBroadcastPkts);

    case OID_GEN_RCV_OK:
        return OidQueryWrite32or64(
            OidRequest,
            Wg->Statistics.ifHCInUcastPkts + Wg->Statistics.ifHCInMulticastPkts + Wg->Statistics.ifHCInBroadcastPkts);

    case OID_GEN_STATISTICS:
        return OidQueryWriteBuf(OidRequest, &Wg->Statistics, sizeof(Wg->Statistics));

    case OID_GEN_INTERRUPT_MODERATION: {
        static CONST NDIS_INTERRUPT_MODERATION_PARAMETERS InterruptParameters = {
            .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                        .Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1,
                        .Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 },
            .InterruptModeration = NdisInterruptModerationNotSupported
        };
        return OidQueryWriteBuf(OidRequest, &InterruptParameters, sizeof(InterruptParameters));
    }

    case OID_PNP_QUERY_POWER:
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_SUCCESS;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
    return NDIS_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NDIS_STATUS
OidSet(_Inout_ WG_DEVICE *Wg, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
    NT_ASSERT(OidRequest->RequestType == NdisRequestSetInformation);

    OidRequest->DATA.SET_INFORMATION.BytesNeeded = OidRequest->DATA.SET_INFORMATION.BytesRead = 0;

    switch (OidRequest->DATA.SET_INFORMATION.Oid)
    {
    case OID_GEN_CURRENT_PACKET_FILTER:
    case OID_GEN_CURRENT_LOOKAHEAD:
        if (OidRequest->DATA.SET_INFORMATION.InformationBufferLength != 4)
        {
            OidRequest->DATA.SET_INFORMATION.BytesNeeded = 4;
            return NDIS_STATUS_INVALID_LENGTH;
        }
        OidRequest->DATA.SET_INFORMATION.BytesRead = 4;
        return NDIS_STATUS_SUCCESS;

    case OID_GEN_LINK_PARAMETERS:
        OidRequest->DATA.SET_INFORMATION.BytesRead = OidRequest->DATA.SET_INFORMATION.InformationBufferLength;
        return NDIS_STATUS_SUCCESS;

    case OID_GEN_INTERRUPT_MODERATION:
        return NDIS_STATUS_INVALID_DATA;

    case OID_PNP_SET_POWER:
        if (OidRequest->DATA.SET_INFORMATION.InformationBufferLength != sizeof(NDIS_DEVICE_POWER_STATE))
        {
            OidRequest->DATA.SET_INFORMATION.BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
            return NDIS_STATUS_INVALID_LENGTH;
        }
        OidRequest->DATA.SET_INFORMATION.BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
        NDIS_DEVICE_POWER_STATE PowerState;
        RtlCopyMemory(&PowerState, OidRequest->DATA.SET_INFORMATION.InformationBuffer, sizeof(PowerState));
        if (PowerState >= NdisDeviceStateD1)
            RcuBarrier();
        return NDIS_STATUS_SUCCESS;
    }

    return NDIS_STATUS_NOT_SUPPORTED;
}

static MINIPORT_OID_REQUEST OidRequest;
_Use_decl_annotations_
static NDIS_STATUS
OidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
        return OidQuery(MiniportAdapterContext, OidRequest);

    case NdisRequestSetInformation:
        return OidSet(MiniportAdapterContext, OidRequest);

    default:
        return NDIS_STATUS_INVALID_OID;
    }
}

static MINIPORT_CANCEL_OID_REQUEST CancelOidRequest;
_Use_decl_annotations_
static VOID
CancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_DIRECT_OID_REQUEST DirectOidRequest;
_Use_decl_annotations_
static NDIS_STATUS
DirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    case NdisRequestSetInformation:
        return NDIS_STATUS_NOT_SUPPORTED;

    default:
        return NDIS_STATUS_INVALID_OID;
    }
}

static MINIPORT_CANCEL_DIRECT_OID_REQUEST CancelDirectOidRequest;
_Use_decl_annotations_
static VOID
CancelDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_SYNCHRONOUS_OID_REQUEST SynchronousOidRequest;
_Use_decl_annotations_
static NDIS_STATUS
SynchronousOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    case NdisRequestSetInformation:
        return NDIS_STATUS_NOT_SUPPORTED;

    default:
        return NDIS_STATUS_INVALID_OID;
    }
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DeviceDriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
DeviceDriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
    NTSTATUS Status;

    MuInitializePushLock(&DeviceListLock);
    InitializeListHead(&DeviceList);

    Status = NotifyIpInterfaceChange(AF_UNSPEC, IpInterfaceChangeNotification, NULL, FALSE, &IpInterfaceNotifier);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = InitIpInterfaceNotifierBugWorkaround();
    if (!NT_SUCCESS(Status))
        goto cleanupIpInterfaceNotifier;

    NdisVersion = NdisGetVersion();
    if (NdisVersion < NDIS_MINIPORT_VERSION_MIN)
        return NDIS_STATUS_UNSUPPORTED_REVISION;
    if (NdisVersion > NDIS_MINIPORT_VERSION_MAX)
        NdisVersion = NDIS_MINIPORT_VERSION_MAX;

    NDIS_MINIPORT_DRIVER_CHARACTERISTICS Miniport = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_680
                                    ? NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2
                                    : NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_680
                                ? NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2
                                : NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3 },

        .MajorNdisVersion = (UCHAR)((NdisVersion & 0x00ff0000) >> 16),
        .MinorNdisVersion = (UCHAR)(NdisVersion & 0x000000ff),

        .MajorDriverVersion = WIREGUARD_VERSION_MAJ,
        .MinorDriverVersion = WIREGUARD_VERSION_MIN,

        .InitializeHandlerEx = InitializeEx,
        .HaltHandlerEx = HaltEx,
        .UnloadHandler = Unload,
        .PauseHandler = Pause,
        .RestartHandler = Restart,
        .OidRequestHandler = OidRequest,
        .SendNetBufferListsHandler = SendNetBufferLists,
        .ReturnNetBufferListsHandler = ReturnNetBufferLists,
        .CancelSendHandler = CancelSend,
        .DevicePnPEventNotifyHandler = DevicePnPEventNotify,
        .ShutdownHandlerEx = ShutdownEx,
        .CancelOidRequestHandler = CancelOidRequest,
        .DirectOidRequestHandler = DirectOidRequest,
        .CancelDirectOidRequestHandler = CancelDirectOidRequest,
        .SynchronousOidRequestHandler = SynchronousOidRequest
    };
    Status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &Miniport, &NdisMiniportDriverHandle);
    if (!NT_SUCCESS(Status))
        goto cleanupIpInterfaceNotifierBugWorkaround;
    IoctlDriverEntry(DriverObject);
    return STATUS_SUCCESS;

cleanupIpInterfaceNotifierBugWorkaround:
    UninitIpInterfaceNotifierBugWorkaround();
cleanupIpInterfaceNotifier:
    CancelMibChangeNotify2(IpInterfaceNotifier);
    return Status;
}

VOID DeviceUnload(VOID)
{
    NdisMDeregisterMiniportDriver(NdisMiniportDriverHandle);
    UninitIpInterfaceNotifierBugWorkaround();
    CancelMibChangeNotify2(IpInterfaceNotifier);
    RcuBarrier();
}
