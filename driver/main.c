/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "device.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "rcu.h"
#include "socket.h"
#include "logging.h"
#include "crypto.h"
#include <wsk.h>
#include <ndis.h>

DRIVER_INITIALIZE DriverEntry;
#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
    NTSTATUS Ret;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    CryptoDriverEntry();
    NoiseDriverEntry();

    Ret = MemDriverEntry();
    if (!NT_SUCCESS(Ret))
        return Ret;

    Ret = RcuDriverEntry();
    if (!NT_SUCCESS(Ret))
        goto cleanupMem;

    Ret = AllowedIpsDriverEntry();
    if (!NT_SUCCESS(Ret))
        goto cleanupRcu;

    Ret = RatelimiterDriverEntry();
    if (!NT_SUCCESS(Ret))
        goto cleanupAllowedIps;

    Ret = PeerDriverEntry();
    if (!NT_SUCCESS(Ret))
        goto cleanupRatelimiter;

    Ret = DeviceDriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(Ret))
        goto cleanupPeer;

#ifdef DBG
    if (!CryptoSelftest() || !AllowedIpsSelftest() || !PacketCounterSelftest() || !RatelimiterSelftest())
    {
        Ret = STATUS_INTERNAL_ERROR;
        goto cleanupDevice;
    }
#endif
    return 0;

#ifdef DBG
cleanupDevice:
    DeviceUnload();
#endif
cleanupPeer:
    PeerUnload();
cleanupRatelimiter:
    RatelimiterUnload();
cleanupAllowedIps:
    AllowedIpsUnload();
cleanupRcu:
    RcuUnload();
cleanupMem:
    MemUnload();
    return Ret;
}

MINIPORT_UNLOAD Unload;
_Use_decl_annotations_
VOID
Unload(PDRIVER_OBJECT DriverObject)
{
    DeviceUnload();
    WskUnload();
    PeerUnload();
    RatelimiterUnload();
    AllowedIpsUnload();
    RcuUnload();
    MemUnload();
}
