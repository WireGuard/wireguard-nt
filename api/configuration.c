/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "../driver/ioctl.h"
#include "wireguard.h"
#include "adapter.h"
#include "logger.h"
#include <Windows.h>
#include <stdlib.h>

static_assert(sizeof(WG_IOCTL_INTERFACE) == sizeof(WIREGUARD_INTERFACE), "Interface struct mismatch");
static_assert(
    offsetof(WG_IOCTL_INTERFACE, Flags) == offsetof(WIREGUARD_INTERFACE, Flags),
    "Interface->Flags struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_INTERFACE, Flags) == RTL_FIELD_SIZE(WIREGUARD_INTERFACE, Flags),
    "Interface->Flags struct mismatch");
static_assert(
    offsetof(WG_IOCTL_INTERFACE, ListenPort) == offsetof(WIREGUARD_INTERFACE, ListenPort),
    "Interface->ListenPort struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_INTERFACE, ListenPort) == RTL_FIELD_SIZE(WIREGUARD_INTERFACE, ListenPort),
    "Interface->ListenPort struct mismatch");
static_assert(
    offsetof(WG_IOCTL_INTERFACE, PrivateKey) == offsetof(WIREGUARD_INTERFACE, PrivateKey),
    "Interface->PrivateKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_INTERFACE, PrivateKey) == RTL_FIELD_SIZE(WIREGUARD_INTERFACE, PrivateKey),
    "Interface->PrivateKey struct mismatch");
static_assert(
    offsetof(WG_IOCTL_INTERFACE, PublicKey) == offsetof(WIREGUARD_INTERFACE, PublicKey),
    "Interface->PublicKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_INTERFACE, PublicKey) == RTL_FIELD_SIZE(WIREGUARD_INTERFACE, PublicKey),
    "Interface->PublicKey struct mismatch");
static_assert(
    offsetof(WG_IOCTL_INTERFACE, PeersCount) == offsetof(WIREGUARD_INTERFACE, PeersCount),
    "Interface->PeersCount struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_INTERFACE, PeersCount) == RTL_FIELD_SIZE(WIREGUARD_INTERFACE, PeersCount),
    "Interface->PeersCount struct mismatch");
static_assert(
    WG_IOCTL_INTERFACE_HAS_PUBLIC_KEY == WIREGUARD_INTERFACE_HAS_PUBLIC_KEY,
    "INTERFACE_HAS_PUBLIC_KEY flag mismatch");
static_assert(
    WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY == WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
    "INTERFACE_HAS_PRIVATE_KEY flag mismatch");
static_assert(
    WG_IOCTL_INTERFACE_HAS_LISTEN_PORT == WIREGUARD_INTERFACE_HAS_LISTEN_PORT,
    "INTERFACE_HAS_LISTEN_PORT flag mismatch");
static_assert(
    WG_IOCTL_INTERFACE_REPLACE_PEERS == WIREGUARD_INTERFACE_REPLACE_PEERS,
    "INTERFACE_REPLACE_PEERS flag mismatch");
static_assert(sizeof(WG_IOCTL_PEER) == sizeof(WIREGUARD_PEER), "Peer struct mismatch");
static_assert(offsetof(WG_IOCTL_PEER, Flags) == offsetof(WIREGUARD_PEER, Flags), "Peer->Flags struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, Flags) == RTL_FIELD_SIZE(WIREGUARD_PEER, Flags),
    "Peer->Flags struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, ProtocolVersion) == offsetof(WIREGUARD_PEER, Reserved),
    "Peer->Reserved struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, ProtocolVersion) == RTL_FIELD_SIZE(WIREGUARD_PEER, Reserved),
    "Peer->Reserved struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, PublicKey) == offsetof(WIREGUARD_PEER, PublicKey),
    "Peer->PublicKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, PublicKey) == RTL_FIELD_SIZE(WIREGUARD_PEER, PublicKey),
    "Peer->PublicKey struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, PresharedKey) == offsetof(WIREGUARD_PEER, PresharedKey),
    "Peer->PresharedKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, PresharedKey) == RTL_FIELD_SIZE(WIREGUARD_PEER, PresharedKey),
    "Peer->PresharedKey struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, PersistentKeepalive) == offsetof(WIREGUARD_PEER, PersistentKeepalive),
    "Peer->PersistentKeepalive struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, PersistentKeepalive) == RTL_FIELD_SIZE(WIREGUARD_PEER, PersistentKeepalive),
    "Peer->PersistentKeepalive struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, Endpoint) == offsetof(WIREGUARD_PEER, Endpoint),
    "Peer->Endpoint struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, Endpoint) == RTL_FIELD_SIZE(WIREGUARD_PEER, Endpoint),
    "Peer->Endpoint struct mismatch");
static_assert(offsetof(WG_IOCTL_PEER, TxBytes) == offsetof(WIREGUARD_PEER, TxBytes), "Peer->TxBytes struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, TxBytes) == RTL_FIELD_SIZE(WIREGUARD_PEER, TxBytes),
    "Peer->TxBytes struct mismatch");
static_assert(offsetof(WG_IOCTL_PEER, RxBytes) == offsetof(WIREGUARD_PEER, RxBytes), "Peer->RxBytes struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, RxBytes) == RTL_FIELD_SIZE(WIREGUARD_PEER, RxBytes),
    "Peer->RxBytes struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, LastHandshake) == offsetof(WIREGUARD_PEER, LastHandshake),
    "Peer->LastHandshake struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, LastHandshake) == RTL_FIELD_SIZE(WIREGUARD_PEER, LastHandshake),
    "Peer->LastHandshake struct mismatch");
static_assert(
    offsetof(WG_IOCTL_PEER, AllowedIPsCount) == offsetof(WIREGUARD_PEER, AllowedIPsCount),
    "Peer->AllowedIPsCount struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_PEER, AllowedIPsCount) == RTL_FIELD_SIZE(WIREGUARD_PEER, AllowedIPsCount),
    "Peer->AllowedIPsCount struct mismatch");
static_assert(WG_IOCTL_PEER_HAS_PUBLIC_KEY == WIREGUARD_PEER_HAS_PUBLIC_KEY, "PEER_HAS_PUBLIC_KEY flag mismatch");
static_assert(
    WG_IOCTL_PEER_HAS_PRESHARED_KEY == WIREGUARD_PEER_HAS_PRESHARED_KEY,
    "PEER_HAS_PRESHARED_KEY flag mismatch");
static_assert(
    WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE == WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE,
    "PEER_HAS_PERSISTENT_KEEPALIVE flag mismatch");
static_assert(WG_IOCTL_PEER_HAS_ENDPOINT == WIREGUARD_PEER_HAS_ENDPOINT, "PEER_HAS_ENDPOINT flag mismatch");
static_assert(
    WG_IOCTL_PEER_REPLACE_ALLOWED_IPS == WIREGUARD_PEER_REPLACE_ALLOWED_IPS,
    "PEER_REPLACE_ALLOWED_IPS flag mismatch");
static_assert(WG_IOCTL_PEER_REMOVE == WIREGUARD_PEER_REMOVE, "PEER_REMOVE flag mismatch");
static_assert(WG_IOCTL_PEER_UPDATE_ONLY == WIREGUARD_PEER_UPDATE_ONLY, "PEER_UPDATE_ONLY flag mismatch");
static_assert(sizeof(WG_IOCTL_ALLOWED_IP) == sizeof(WIREGUARD_ALLOWED_IP), "Allowed IP struct mismatch");
static_assert(
    offsetof(WG_IOCTL_ALLOWED_IP, AddressFamily) == offsetof(WIREGUARD_ALLOWED_IP, AddressFamily),
    "AllowedIp->AddressFamily struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_ALLOWED_IP, AddressFamily) == RTL_FIELD_SIZE(WIREGUARD_ALLOWED_IP, AddressFamily),
    "AllowedIp->AddressFamily struct mismatch");
static_assert(
    offsetof(WG_IOCTL_ALLOWED_IP, Cidr) == offsetof(WIREGUARD_ALLOWED_IP, Cidr),
    "AllowedIp->cidr struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_ALLOWED_IP, Cidr) == RTL_FIELD_SIZE(WIREGUARD_ALLOWED_IP, Cidr),
    "AllowedIp->cidr struct mismatch");
static_assert(
    offsetof(WG_IOCTL_ALLOWED_IP, Address.V4) == offsetof(WIREGUARD_ALLOWED_IP, Address.V4),
    "AllowedIp->Address.V4 struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_ALLOWED_IP, Address.V4) == RTL_FIELD_SIZE(WIREGUARD_ALLOWED_IP, Address.V4),
    "AllowedIp->Address.V4 struct mismatch");
static_assert(
    offsetof(WG_IOCTL_ALLOWED_IP, Address.V6) == offsetof(WIREGUARD_ALLOWED_IP, Address.V6),
    "AllowedIp->Address.V6 struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_ALLOWED_IP, Address.V6) == RTL_FIELD_SIZE(WIREGUARD_ALLOWED_IP, Address.V6),
    "AllowedIp->Address.V6 struct mismatch");
static_assert(
    offsetof(WG_IOCTL_ALLOWED_IP, Address) == offsetof(WIREGUARD_ALLOWED_IP, Address),
    "AllowedIp->Address struct mismatch");
static_assert(
    RTL_FIELD_SIZE(WG_IOCTL_ALLOWED_IP, Address) == RTL_FIELD_SIZE(WIREGUARD_ALLOWED_IP, Address),
    "AllowedIp->Address struct mismatch");
static_assert(sizeof(WG_IOCTL_ADAPTER_STATE) == sizeof(WIREGUARD_ADAPTER_STATE), "Adapter state mismatch");
static_assert(WG_IOCTL_ADAPTER_STATE_DOWN == WIREGUARD_ADAPTER_STATE_DOWN, "Adapter state down mismatch");
static_assert(WG_IOCTL_ADAPTER_STATE_UP == WIREGUARD_ADAPTER_STATE_UP, "Adapter state up mismatch");

WIREGUARD_SET_ADAPTER_STATE_FUNC WireGuardSetAdapterState;
_Use_decl_annotations_
BOOL WINAPI
WireGuardSetAdapterState(WIREGUARD_ADAPTER *Adapter, WIREGUARD_ADAPTER_STATE State)
{
    switch (State)
    {
    case WIREGUARD_ADAPTER_STATE_UP:
    case WIREGUARD_ADAPTER_STATE_DOWN:
        break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD BytesReturned;
    if (!DeviceIoControl(ControlFile, WG_IOCTL_SET_ADAPTER_STATE, &State, sizeof(State), NULL, 0, &BytesReturned, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

WIREGUARD_GET_ADAPTER_STATE_FUNC WireGuardGetAdapterState;
_Use_decl_annotations_
BOOL WINAPI
WireGuardGetAdapterState(WIREGUARD_ADAPTER *Adapter, WIREGUARD_ADAPTER_STATE *State)
{
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD BytesReturned;
    WG_IOCTL_ADAPTER_STATE Op = WG_IOCTL_ADAPTER_STATE_QUERY;
    if (!DeviceIoControl(
            ControlFile, WG_IOCTL_SET_ADAPTER_STATE, &Op, sizeof(Op), State, sizeof(*State), &BytesReturned, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

WIREGUARD_SET_CONFIGURATION_FUNC WireGuardSetConfiguration;
_Use_decl_annotations_
BOOL WINAPI
WireGuardSetConfiguration(WIREGUARD_ADAPTER *Adapter, const WIREGUARD_INTERFACE *Config, DWORD Bytes)
{
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!DeviceIoControl(ControlFile, WG_IOCTL_SET, NULL, 0, (VOID *)Config, Bytes, &Bytes, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

WIREGUARD_GET_CONFIGURATION_FUNC WireGuardGetConfiguration;
_Use_decl_annotations_
BOOL WINAPI
WireGuardGetConfiguration(WIREGUARD_ADAPTER *Adapter, WIREGUARD_INTERFACE *Config, DWORD *Bytes)
{
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!DeviceIoControl(ControlFile, WG_IOCTL_GET, NULL, 0, Config, *Bytes, Bytes, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}
