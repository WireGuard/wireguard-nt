/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <wsk.h>

typedef struct _SOCKET
{
    WSK_SOCKET *Sock;
    WG_DEVICE *Device;
    EX_RUNDOWN_REF ItemsInFlight;
} SOCKET;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SocketSendNblsToPeer(_Inout_ WG_PEER *Peer, _In_ __drv_aliasesMem NET_BUFFER_LIST *First, _Out_ BOOLEAN *AllKeepalive);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SocketSendBufferToPeer(_Inout_ WG_PEER *Peer, _In_reads_bytes_(Len) CONST VOID *Data, _In_ ULONG Len);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SocketSendBufferAsReplyToNbl(
    _Inout_ WG_DEVICE *Wg,
    _In_ CONST NET_BUFFER_LIST *InNbl,
    _In_reads_bytes_(Len) CONST VOID *Buffer,
    _In_ ULONG Len);

NTSTATUS
SocketEndpointFromNbl(_Out_ ENDPOINT *Endpoint, _In_ CONST NET_BUFFER_LIST *Nbl);

_Requires_lock_not_held_(Peer->EndpointLock)
VOID
SocketSetPeerEndpoint(_Inout_ WG_PEER *Peer, _In_ CONST ENDPOINT *Endpoint);

_Requires_lock_not_held_(Peer->EndpointLock)
VOID
SocketSetPeerEndpointFromNbl(_Inout_ WG_PEER *Peer, _In_ CONST NET_BUFFER_LIST *Nbl);

_Requires_lock_not_held_(Peer->EndpointLock)
VOID
SocketClearPeerEndpointSrc(_Inout_ WG_PEER *Peer);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Wg->SocketUpdateLock)
NTSTATUS
SocketInit(_Inout_ WG_DEVICE *Wg, _In_ UINT16 Port);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_not_held_(Wg->SocketUpdateLock)
VOID
SocketReinit(
    _Inout_ WG_DEVICE *Wg,
    _In_opt_ __drv_aliasesMem SOCKET *New4,
    _In_opt_ __drv_aliasesMem SOCKET *New6,
    _In_ UINT16 Port);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WskInit(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID WskUnload(VOID);
