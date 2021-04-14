/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "allowedips.h"
#include "containers.h"
#include "cookie.h"
#include "noise.h"
#include "peerlookup.h"
#include "rcu.h"
#include "logging.h"
#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>

extern LIST_ENTRY DeviceList;
extern EX_PUSH_LOCK DeviceListLock;

typedef struct _PREV_QUEUE
{
    NET_BUFFER_LIST *Head, *Tail, *Peeked;
    NET_BUFFER_LIST Empty;
    LONG Count;
} PREV_QUEUE;

// Would be nice to have the MULTICORE_* stuff in queueing.h where it belongs.
typedef struct _MULTICORE_WORKTHREAD MULTICORE_WORKTHREAD;
typedef struct _MULTICORE_WORKQUEUE MULTICORE_WORKQUEUE;

typedef _Function_class_(MULTICORE_WORKQUEUE_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MULTICORE_WORKQUEUE_ROUTINE(_In_ MULTICORE_WORKQUEUE *);
typedef MULTICORE_WORKQUEUE_ROUTINE *PMULTICORE_WORKQUEUE_ROUTINE;

struct _MULTICORE_WORKTHREAD
{
    SLIST_ENTRY Entry;
    PKTHREAD Thread;
    PROCESSOR_NUMBER Processor;
    MULTICORE_WORKTHREAD *NextThread;
    MULTICORE_WORKQUEUE *WorkQueue;
};

struct _MULTICORE_WORKQUEUE
{
    MULTICORE_WORKTHREAD *FirstThread;
    KEVENT NewWork, NewCpus, Dead;
    PMULTICORE_WORKQUEUE_ROUTINE Func;
    PVOID NewCpuNotifier;
    PKTHREAD WorkerSpawnerThread;
};

typedef struct _SOCKET SOCKET;

typedef struct _PEER_SERIAL_ENTRY PEER_SERIAL_ENTRY;
struct _PEER_SERIAL_ENTRY
{
    PEER_SERIAL_ENTRY *Next;
    SHORT Requeue;
};

typedef struct _PEER_SERIAL
{
    PEER_SERIAL_ENTRY *First, **Last;
    KSPIN_LOCK Lock;
} PEER_SERIAL;

typedef struct _WG_DEVICE
{
    NDIS_HANDLE MiniportAdapterHandle; /* This is actually a pointer to NDIS_MINIPORT_BLOCK struct. */
    DEVICE_OBJECT *FunctionalDeviceObject;
    NDIS_STATISTICS_INFO Statistics;
    NDIS_HANDLE NblPool, NbPool;
    EX_RUNDOWN_REF ItemsInFlight;
    PTR_RING EncryptQueue, DecryptQueue;
    PEER_SERIAL TxQueue, RxQueue, HandshakeTxQueue;
    NET_BUFFER_LIST_QUEUE HandshakeRxQueue;
    MULTICORE_WORKQUEUE EncryptThreads, DecryptThreads;
    MULTICORE_WORKQUEUE TxThreads, RxThreads;
    MULTICORE_WORKQUEUE HandshakeTxThreads, HandshakeRxThreads;
    SOCKET __rcu *Sock4, *Sock6;
    NOISE_STATIC_IDENTITY StaticIdentity;
    COOKIE_CHECKER CookieChecker;
    PUBKEY_HASHTABLE *PeerHashtable;
    INDEX_HASHTABLE *IndexHashtable;
    ALLOWEDIPS_TABLE PeerAllowedIps;
    EX_PUSH_LOCK DeviceUpdateLock, SocketUpdateLock;
    LIST_ENTRY PeerList;
    ULONG NumPeers, DeviceUpdateGen;
    NET_IFINDEX InterfaceIndex;
    NET_LUID InterfaceLuid;
    PEPROCESS SocketOwnerProcess;
    UINT16 IncomingPort;
    BOOLEAN IsUp, IsDeviceRemoving;
    PVOID MtuRegistryKeyObject;
    LARGE_INTEGER MtuRegistryNotifier;
    ULONG Mtu;
    LOG_RING Log;
    LIST_ENTRY DeviceList;
    KEVENT DeviceRemoved;
    PKTHREAD HandleForceCloseThread;
} WG_DEVICE;

_Requires_lock_held_(Wg->DeviceUpdateLock)
VOID
DeviceStart(_Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(Wg->DeviceUpdateLock)
VOID
DeviceStop(_Inout_ WG_DEVICE *Wg);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DeviceIndicateConnectionStatus(_In_ NDIS_HANDLE MiniportAdapterHandle, _In_ NDIS_MEDIA_CONNECT_STATE MediaConnectState);

DRIVER_INITIALIZE DeviceDriverEntry;

VOID DeviceUnload(VOID);
