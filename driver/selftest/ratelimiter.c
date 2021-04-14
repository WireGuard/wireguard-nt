/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "messages.h"

#define IS_BEFORE_UNBIASED_INTERRUPT_TIME(A) ((LONG64)(A) < (LONG64)KeQueryUnbiasedInterruptTime())

static UINT64
MaximumSysTimeUnitsAtIndex(LONG Index);
static NTSTATUS
TimingsTest(IPV4HDR *Hdr4, IPV6HDR *Hdr6, LONG *Test);
static NTSTATUS
CapacityTest(IPV4HDR *Hdr4, LONG *Test);

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, MaximumSysTimeUnitsAtIndex)
#    pragma alloc_text(INIT, TimingsTest)
#    pragma alloc_text(INIT, CapacityTest)
#    pragma alloc_text(INIT, RatelimiterSelftest)
#endif

#pragma data_seg("INITDATA")
#pragma bss_seg("INITBSS")
static CONST struct
{
    BOOLEAN Failure;
    ULONG64 SysTimeUnitsToSleepBefore;
} ExpectedResults[] = { [PACKETS_BURSTABLE] = { TRUE, 0 },
                        [PACKETS_BURSTABLE + 1] = { FALSE, SYS_TIME_UNITS_PER_SEC / PACKETS_PER_SECOND },
                        [PACKETS_BURSTABLE + 2] = { TRUE, 0 },
                        [PACKETS_BURSTABLE + 3] = { FALSE, 2 * SYS_TIME_UNITS_PER_SEC / PACKETS_PER_SECOND },
                        [PACKETS_BURSTABLE + 4] = { FALSE, 0 },
                        [PACKETS_BURSTABLE + 5] = { TRUE, 0 } };
#pragma data_seg()
#pragma bss_seg()

static UINT64
MaximumSysTimeUnitsAtIndex(LONG Index)
{
    ULONG64 Total = 2 * SYS_TIME_UNITS_PER_SEC / PACKETS_PER_SECOND / 3;
    LONG i;

    for (i = 0; i <= Index; ++i)
        Total += ExpectedResults[i].SysTimeUnitsToSleepBefore;
    return Total;
}

#define IN6_NIBBLE(A, i) (((ULONG *)(A))[i])

static NTSTATUS
TimingsTest(IPV4HDR *Hdr4, IPV6HDR *Hdr6, LONG *Test)
{
    ULONG64 LoopStartTime;
    LONG i;
    SOCKADDR_IN Src4 = { .sin_family = AF_INET, .sin_addr.S_un.S_addr = Hdr4->Saddr };
    SOCKADDR_IN6 Src6 = { .sin6_family = AF_INET6, .sin6_addr = Hdr6->Saddr };

    RatelimiterGcEntries(NULL);
    RcuBarrier();
    LoopStartTime = KeQueryUnbiasedInterruptTime();

    for (i = 0; i < ARRAYSIZE(ExpectedResults); ++i)
    {
        if (ExpectedResults[i].SysTimeUnitsToSleepBefore)
            KeDelayExecutionThread(
                KernelMode,
                FALSE,
                &(LARGE_INTEGER){ .QuadPart = -(LONG64)ExpectedResults[i].SysTimeUnitsToSleepBefore });

        if (IS_BEFORE_UNBIASED_INTERRUPT_TIME(LoopStartTime + MaximumSysTimeUnitsAtIndex(i)))
            return STATUS_TIMEOUT;
        if (RatelimiterAllow((SOCKADDR *)&Src4) == ExpectedResults[i].Failure)
            return STATUS_DISK_FULL;
        ++(*Test);

        Src4.sin_addr.s_addr = Hdr4->Saddr = Htonl(Ntohl(Hdr4->Saddr) + i + 1);
        if (IS_BEFORE_UNBIASED_INTERRUPT_TIME(LoopStartTime + MaximumSysTimeUnitsAtIndex(i)))
            return STATUS_TIMEOUT;
        if (!RatelimiterAllow((SOCKADDR *)&Src4))
            return STATUS_DISK_FULL;
        ++(*Test);

        Src4.sin_addr.s_addr = Hdr4->Saddr = Htonl(Ntohl(Hdr4->Saddr) - i - 1);

        IN6_NIBBLE(&Src6.sin6_addr, 2) = IN6_NIBBLE(&Hdr6->Saddr, 2) = Htonl(i);
        IN6_NIBBLE(&Src6.sin6_addr, 3) = IN6_NIBBLE(&Hdr6->Saddr, 3) = Htonl(i);
        if (IS_BEFORE_UNBIASED_INTERRUPT_TIME(LoopStartTime + MaximumSysTimeUnitsAtIndex(i)))
            return STATUS_TIMEOUT;
        if (RatelimiterAllow((SOCKADDR *)&Src6) == ExpectedResults[i].Failure)
            return STATUS_DISK_FULL;
        ++(*Test);

        IN6_NIBBLE(&Src6.sin6_addr, 0) = IN6_NIBBLE(&Hdr6->Saddr, 0) =
            Htonl(Ntohl(IN6_NIBBLE(&Hdr6->Saddr, 0)) + i + 1);
        if (IS_BEFORE_UNBIASED_INTERRUPT_TIME(LoopStartTime + MaximumSysTimeUnitsAtIndex(i)))
            return STATUS_TIMEOUT;
        if (!RatelimiterAllow((SOCKADDR *)&Src6))
            return STATUS_DISK_FULL;
        ++(*Test);

        IN6_NIBBLE(&Src6.sin6_addr, 0) = IN6_NIBBLE(&Hdr6->Saddr, 0) =
            Htonl(Ntohl(IN6_NIBBLE(&Hdr6->Saddr, 0)) - i - 1);

        if (IS_BEFORE_UNBIASED_INTERRUPT_TIME(LoopStartTime + MaximumSysTimeUnitsAtIndex(i)))
            return STATUS_TIMEOUT;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
CapacityTest(IPV4HDR *Hdr4, LONG *Test)
{
    ULONG i;
    SOCKADDR_IN Src4 = { .sin_family = AF_INET, .sin_addr.S_un.S_addr = Hdr4->Saddr };

    RatelimiterGcEntries(NULL);
    RcuBarrier();

    if (ReadNoFence(&TotalEntries))
        return STATUS_DISK_FULL;
    ++(*Test);

    for (i = 0; i <= MAX_ENTRIES; ++i)
    {
        Src4.sin_addr.s_addr = Hdr4->Saddr = Htonl(i);
        if (RatelimiterAllow((SOCKADDR *)&Src4) != (i != MAX_ENTRIES))
            return STATUS_DISK_FULL;
        ++(*Test);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
RatelimiterSelftest(VOID)
{
    enum
    {
        TRIALS_BEFORE_GIVING_UP = 5000
    };
    BOOLEAN Success = FALSE;
    LONG Test = 0, Trials;
    NET_BUFFER_LIST *Nbl4, *Nbl6 = NULL;
    IPV4HDR *Hdr4;
    IPV6HDR *Hdr6 = NULL;

    NET_BUFFER_LIST_POOL_PARAMETERS NblPoolParameters = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
        .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
        .PoolTag = MEMORY_TAG
    };
    NDIS_HANDLE NblPool = NdisAllocateNetBufferListPool(NULL, &NblPoolParameters);
    if (!NblPool)
        goto out;
    NET_BUFFER_POOL_PARAMETERS NbPoolParameters = { .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                                                                .Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1,
                                                                .Size =
                                                                    NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1 },
                                                    .PoolTag = MEMORY_TAG };
    NDIS_HANDLE NbPool = NdisAllocateNetBufferPool(NULL, &NbPoolParameters);
    if (!NbPool)
        goto cleanupNblPool;
    ++Test;
    ++Test;
    ++Test;

    Nbl4 = MemAllocateNetBufferList(NblPool, NbPool, 0, sizeof(*Hdr4), 0);
    if (!Nbl4)
        goto cleanupNofree;
    NdisSetNblFlag(Nbl4, NDIS_NBL_FLAGS_IS_IPV4);
    NET_BUFFER_LIST_INFO(Nbl4, NetBufferListProtocolId) = (VOID *)Htons(NDIS_ETH_TYPE_IPV4);
    Hdr4 = MemGetValidatedNetBufferListData(Nbl4);
    Hdr4->Saddr = Htonl(8182);
    ++Test;

    Nbl6 = MemAllocateNetBufferList(NblPool, NbPool, 0, sizeof(*Hdr6), 0);
    if (!Nbl6)
    {
        MemFreeNetBufferList(Nbl4);
        goto cleanupNofree;
    }
    NdisSetNblFlag(Nbl6, NDIS_NBL_FLAGS_IS_IPV6);
    NET_BUFFER_LIST_INFO(Nbl6, NetBufferListProtocolId) = (VOID *)Htons(NDIS_ETH_TYPE_IPV6);
    Hdr6 = MemGetValidatedNetBufferListData(Nbl6);
    IN6_NIBBLE(&Hdr6->Saddr, 0) = Htonl(1212);
    IN6_NIBBLE(&Hdr6->Saddr, 1) = Htonl(289188);
    ++Test;

    for (Trials = TRIALS_BEFORE_GIVING_UP;;)
    {
        LONG TestCount = 0;
        NTSTATUS Ret;

        Ret = TimingsTest(Hdr4, Hdr6, &TestCount);
        if (Ret == STATUS_TIMEOUT)
        {
            if (!Trials--)
            {
                Test += TestCount;
                goto cleanup;
            }
            KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){ .QuadPart = -SYS_TIME_UNITS_PER_SEC / 2 });
            continue;
        }
        else if (!NT_SUCCESS(Ret))
        {
            Test += TestCount;
            goto cleanup;
        }
        else
        {
            Test += TestCount;
            break;
        }
    }

    for (Trials = TRIALS_BEFORE_GIVING_UP;;)
    {
        LONG TestCount = 0;

        if (!NT_SUCCESS(CapacityTest(Hdr4, &TestCount)))
        {
            if (!Trials--)
            {
                Test += TestCount;
                goto cleanup;
            }
            KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){ .QuadPart = -SYS_TIME_UNITS_PER_SEC / 20 });
            continue;
        }
        Test += TestCount;
        break;
    }

    Success = TRUE;

cleanup:
    MemFreeNetBufferList(Nbl4);
    MemFreeNetBufferList(Nbl6);
cleanupNofree:
    NdisFreeNetBufferPool(NbPool);
cleanupNblPool:
    NdisFreeNetBufferListPool(NblPool);
out:
    if (Success)
        LogDebug("ratelimiter self-tests: pass");
    else
        LogDebug("ratelimiter self-test %d: FAIL", Test);

    return Success;
}
