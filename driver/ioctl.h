/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#ifdef _KERNEL_MODE
#    include <ntifs.h> /* Must be included before <wdm.h> */
#    include <wdm.h>
#    include <ndis.h>
#else
#    include <winsock2.h>
#    include <Windows.h>
#    include <ws2def.h>
#    include <ws2ipdef.h>
#    include <devioctl.h>
#endif

#pragma warning(push)
#pragma warning(disable : 4324) /* structure was padded due to alignment specifier */

#define WG_KEY_LEN 32

typedef __declspec(align(8)) struct _WG_IOCTL_ALLOWED_IP
{
    union
    {
        IN_ADDR V4;
        IN6_ADDR V6;
    } Address;
    ADDRESS_FAMILY AddressFamily;
    UCHAR Cidr;
} WG_IOCTL_ALLOWED_IP;

typedef enum
{
    WG_IOCTL_PEER_HAS_PUBLIC_KEY = 1 << 0,
    WG_IOCTL_PEER_HAS_PRESHARED_KEY = 1 << 1,
    WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2,
    WG_IOCTL_PEER_HAS_ENDPOINT = 1 << 3,
    WG_IOCTL_PEER_HAS_PROTOCOL_VERSION = 1 << 4,
    WG_IOCTL_PEER_REPLACE_ALLOWED_IPS = 1 << 5,
    WG_IOCTL_PEER_REMOVE = 1 << 6,
    WG_IOCTL_PEER_UPDATE_ONLY = 1 << 7
} WG_IOCTL_PEER_FLAG;

typedef __declspec(align(8)) struct _WG_IOCTL_PEER
{
    WG_IOCTL_PEER_FLAG Flags;
    ULONG ProtocolVersion; /* 0 = latest protocol, 1 = this protocol. */
    UCHAR PublicKey[WG_KEY_LEN];
    UCHAR PresharedKey[WG_KEY_LEN];
    USHORT PersistentKeepalive;
    SOCKADDR_INET Endpoint;
    ULONG64 TxBytes;
    ULONG64 RxBytes;
    ULONG64 LastHandshake;
    ULONG AllowedIPsCount;
} WG_IOCTL_PEER;

typedef enum
{
    WG_IOCTL_INTERFACE_HAS_PUBLIC_KEY = 1 << 0,
    WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY = 1 << 1,
    WG_IOCTL_INTERFACE_HAS_LISTEN_PORT = 1 << 2,
    WG_IOCTL_INTERFACE_REPLACE_PEERS = 1 << 3
} WG_IOCTL_INTERFACE_FLAG;

typedef __declspec(align(8)) struct _WG_IOCTL_INTERFACE
{
    WG_IOCTL_INTERFACE_FLAG Flags;
    USHORT ListenPort;
    UCHAR PrivateKey[WG_KEY_LEN];
    UCHAR PublicKey[WG_KEY_LEN];
    ULONG PeersCount;
} WG_IOCTL_INTERFACE;

typedef enum
{
    WG_IOCTL_ADAPTER_STATE_DOWN = 0,
    WG_IOCTL_ADAPTER_STATE_UP = 1,
    WG_IOCTL_ADAPTER_STATE_QUERY = 2
} WG_IOCTL_ADAPTER_STATE;

typedef __declspec(align(8)) struct _WG_IOCTL_LOG_ENTRY
{
    ULONG64 Timestamp;
    CHAR Msg[120];
} WG_IOCTL_LOG_ENTRY;

/* Get adapter properties.
 *
 * The lpOutBuffer and nOutBufferSize parameters of DeviceIoControl() must describe an user allocated buffer
 * and its size in bytes. The buffer will be filled with a WG_IOCTL_INTERFACE struct followed by zero or more
 * WG_IOCTL_PEER structs. Should all data not fit into the buffer, ERROR_MORE_DATA is returned with the required
 * size of the buffer.
 */
#define WG_IOCTL_GET CTL_CODE(45208U, 321, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

/* Set adapter properties.
 *
 * The lpInBuffer and nInBufferSize parameters of DeviceIoControl() must describe a WG_IOCTL_INTERFACE struct followed
 * by PeersCount times WG_IOCTL_PEER struct.
 */
#define WG_IOCTL_SET CTL_CODE(45208U, 322, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

/* Bring adapter up, down, or query existing adapter state. Input is verb. Output is current state after operation. */
#define WG_IOCTL_SET_ADAPTER_STATE CTL_CODE(45208U, 323, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/* Read the next line in the adapter log. */
#define WG_IOCTL_READ_LOG_LINE CTL_CODE(45208U, 324, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#ifdef _KERNEL_MODE

typedef struct _WG_DEVICE WG_DEVICE;

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(_Global_critical_region_)
VOID
IoctlHalt(_Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(APC_LEVEL)
VOID
IoctlDriverEntry(_In_ DRIVER_OBJECT *DriverObject);

#endif

#pragma warning(pop)
