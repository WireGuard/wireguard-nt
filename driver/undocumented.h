/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2026 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>

NTSYSAPI
NTSTATUS NTAPI ZwYieldExecution(VOID);

NTSYSAPI
BOOLEAN NTAPI
SystemPrng(_Out_writes_bytes_all_(Len) PVOID RandomData, _In_ SIZE_T Len);

NTSYSAPI
PVOID NTAPI
NdisWdfGetAdapterContextFromAdapterHandle(_In_ PVOID DeviceExtension);

#define IOCTL_NSI_SET_ALL_PARAMETERS CTL_CODE(0x12, 4, METHOD_NEITHER, 0)

typedef enum _NL_OBJECT_TYPE
{
    NlInterfaceObject = 0x7,
    NlSubInterfaceObject = 0x12
} NL_OBJECT_TYPE;

typedef struct _NSI_IP_INTERFACE_RW
{
    BOOLEAN AdvertisingEnabled;
    BOOLEAN ForwardingEnabled;
    BOOLEAN MulticastForwardingEnabled;
    BOOLEAN WeakHostSend;
    BOOLEAN WeakHostReceive;
    BOOLEAN UseNeighborUnreachabilityDetection;
    BOOLEAN UseAutomaticMetric;
    BOOLEAN UseZeroBroadcastAddress;
    BOOLEAN UseBroadcastForRouterDiscovery;
    BOOLEAN DhcpRouterDiscoveryEnabled;
    BOOLEAN ManagedAddressConfigurationSupported;
    BOOLEAN OtherStatefulConfigurationSupported;
    BOOLEAN AdvertiseDefaultRoute;
    UCHAR Padding1[3];
    ULONG NetworkCategory;
    ULONG RouterDiscoveryBehavior;
    ULONG TypeOfInterface;
    ULONG Metric;
    ULONG BaseReachableTime;
    ULONG RetransmitTime;
    ULONG PathMtuDiscoveryTimeout;
    ULONG DadTransmits;
    ULONG LinkLocalAddressBehavior;
    ULONG LinkLocalAddressTimeout;
    ULONG ZoneIndices[16];
    ULONG NlMtu;
    ULONG SitePrefixLength;
    ULONG MulticastForwardingHopLimit;
    ULONG CurrentHopLimit;
    UCHAR LinkLocalAddress[16];
    BOOLEAN DisableDefaultRoutes;
    UCHAR Padding2[3];
    ULONG AdvertisedRouterLifetime;
    BOOLEAN SendUnsolicitedNeighborAdvertisementOnDad;
    BOOLEAN LimitedLinkConnectivity;
    BOOLEAN ForceARPNDPattern;
    BOOLEAN EnableDirectMACPattern;
    BOOLEAN EnableWol;
    BOOLEAN ForceTunneling;
    UCHAR Padding3[2];
    ULONG DomainNetworkLocation;
    ULONGLONG RandomizedEpoch;
    ULONG EcnCapability;
    ULONG DomainType;
    UCHAR NetworkSignature[16];
    ULONG InternetConnectivityDetected;
    BOOLEAN ProxyDetected;
    UCHAR Padding4[3];
    ULONG DadRetransmitTime;
    BOOLEAN PrefixSharing;
    BOOLEAN DisableUnconstrainedRouteLookup;
    UCHAR Padding5[2];
    ULONG NetworkContext;
    BOOLEAN ResetAutoconfigurationOnOperStatusDown;
    BOOLEAN ClampMssEnabled;
    UCHAR Reserved[10];
} NSI_IP_INTERFACE_RW;

typedef struct _NSI_IP_SUBINTERFACE_RW
{
    ULONG NlMtu;
} NSI_IP_SUBINTERFACE_RW;

typedef struct _NSI_SET_ALL_PARAMETERS
{
    PVOID ClientContext;
    PVOID ProviderHandle;
    PVOID ModuleId;
    ULONG_PTR ObjectIndex;
    ULONG StoreType;
    ULONG Action;
    PVOID KeyStruct;
    ULONG KeyStructLength;
    PVOID RwParameterStruct;
    ULONG RwParameterStructLength;
} NSI_SET_ALL_PARAMETERS;

#ifdef _WIN64
typedef struct _NSI_SET_ALL_PARAMETERS_32
{
    ULONG ClientContext;
    ULONG ProviderHandle;
    ULONG ModuleId;
    ULONG ObjectIndex;
    ULONG StoreType;
    ULONG Action;
    ULONG KeyStruct;
    ULONG KeyStructLength;
    ULONG RwParameterStruct;
    ULONG RwParameterStructLength;
} NSI_SET_ALL_PARAMETERS_32;
#endif
