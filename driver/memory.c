/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "memory.h"
#include "messages.h"

static CONST ULONG PacketCacheSizes[] = { 192, 512, 1024, 1500, 9000 };
static NDIS_HANDLE LooseNbPool, LooseNblPool;
static NDIS_HANDLE NbDataPools[ARRAYSIZE(PacketCacheSizes)], NblDataPools[ARRAYSIZE(PacketCacheSizes)];

#pragma warning(suppress : 28195) /* IoAllocateMdl allocates, even if missing the SAL annotation. */
_Use_decl_annotations_
MDL *
MemAllocateDataAndMdlChain(ULONG BufferSize)
{
    NT_ASSERT(BufferSize <= (MAXULONG - PAGE_SIZE));
    VOID *Memory = MemAllocate(BufferSize);
    if (!Memory)
        return NULL;
    MDL *Mdl = IoAllocateMdl(Memory, BufferSize, FALSE, FALSE, NULL);
    if (!Mdl)
    {
        MemFree(Memory);
        return NULL;
    }
    MmBuildMdlForNonPagedPool(Mdl);
    return Mdl;
}

#pragma warning(suppress : 6014) /* IoFreeMdl frees, even if missing the SAL annotation. */
_Use_decl_annotations_
VOID
MemFreeDataAndMdlChain(MDL *Mdl)
{
    while (Mdl)
    {
        MDL *Next = Mdl->Next;
        VOID *Memory = MmGetMdlVirtualAddress(Mdl);
        IoFreeMdl(Mdl);
        MemFree(Memory);
        Mdl = Next;
    }
}

_Use_decl_annotations_
NET_BUFFER_LIST *
MemAllocateNetBufferList(ULONG SpaceBefore, ULONG Size, ULONG SpaceAfter)
{
    ULONG Sum = Size;
    if (!NT_SUCCESS(RtlULongAdd(Sum, SpaceBefore, &Sum) || !NT_SUCCESS(RtlULongAdd(Sum, SpaceAfter, &Sum))) ||
        Sum > MTU_MAX)
        return NULL;
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        if (PacketCacheSizes[i] >= Sum)
        {
            NET_BUFFER_LIST *Nbl = NdisAllocateNetBufferList(NblDataPools[i], 0, 0);
            if (!Nbl)
                return NULL;
            NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(Nbl)) = Size;
            NET_BUFFER_DATA_OFFSET(NET_BUFFER_LIST_FIRST_NB(Nbl)) =
                NET_BUFFER_CURRENT_MDL_OFFSET(NET_BUFFER_LIST_FIRST_NB(Nbl)) = SpaceBefore;
            return Nbl;
        }
    }

#pragma warning(suppress : 6014) /* MDL is aliased in Nbl or freed on failure. */
    MDL *Mdl = MemAllocateDataAndMdlChain(Sum);
    if (!Mdl)
        return NULL;
    NET_BUFFER *Nb = NdisAllocateNetBuffer(LooseNbPool, Mdl, SpaceBefore, Size);
    if (!Nb)
        goto cleanupMdl;
    NET_BUFFER_LIST *Nbl = NdisAllocateNetBufferList(LooseNblPool, 0, 0);
    if (!Nbl)
        goto cleanupNb;
    NET_BUFFER_LIST_FIRST_NB(Nbl) = Nb;
    return Nbl;

cleanupNb:
    NdisFreeNetBuffer(Nb);
cleanupMdl:
    MemFreeDataAndMdlChain(Mdl);
    return NULL;
}

_Use_decl_annotations_
VOID
MemFreeNetBufferList(NET_BUFFER_LIST *Nbl)
{
    if (Nbl->NdisPoolHandle == LooseNblPool)
    {
        while (NET_BUFFER_LIST_FIRST_NB(Nbl))
        {
            NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
            NET_BUFFER_LIST_FIRST_NB(Nbl) = NET_BUFFER_NEXT_NB(NET_BUFFER_LIST_FIRST_NB(Nbl));
            if (Nb->NdisPoolHandle == LooseNbPool)
                MemFreeDataAndMdlChain(NET_BUFFER_FIRST_MDL(Nb));
            NdisFreeNetBuffer(Nb);
        }
    }
    NdisFreeNetBufferList(Nbl);
}

#pragma warning(suppress : 28195) /* NdisAllocateNetBufferList & co allocate. */
_Use_decl_annotations_
NET_BUFFER_LIST *
MemAllocateNetBufferListWithClonedGeometry(NET_BUFFER_LIST *Original, ULONG AdditionalBytesPerNb)
{
    NET_BUFFER_LIST *Clone = NdisAllocateNetBufferList(LooseNblPool, 0, 0);
    if (!Clone)
        return NULL;
    NET_BUFFER_LIST_INFO(Clone, NetBufferListProtocolId) = NET_BUFFER_LIST_INFO(Original, NetBufferListProtocolId);
    NET_BUFFER **CloneNb = &NET_BUFFER_LIST_FIRST_NB(Clone);
    for (NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Original); Nb; Nb = NET_BUFFER_NEXT_NB(Nb))
    {
        ULONG Length;
        if (NET_BUFFER_DATA_LENGTH(Nb) > MTU_MAX ||
            !NT_SUCCESS(RtlULongAdd(NET_BUFFER_DATA_LENGTH(Nb), AdditionalBytesPerNb, &Length)))
            goto cleanupClone;
        for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
        {
            if (PacketCacheSizes[i] >= Length)
            {
                *CloneNb = NdisAllocateNetBufferMdlAndData(NbDataPools[i]);
                if (!*CloneNb)
                    goto cleanupClone;
                NET_BUFFER_DATA_LENGTH(*CloneNb) = Length;
                goto linkNb;
            }
        }
#pragma warning(suppress : 6014) /* `CloneMdl` is aliased in NdisAllocateNetBuffer or freed on failure. */
        MDL *CloneMdl = MemAllocateDataAndMdlChain(Length);
        if (!CloneMdl)
            goto cleanupClone;
#pragma warning(suppress : 6014) /* `*CloneNb` is aliased in Clone or freed on failure. */
        *CloneNb = NdisAllocateNetBuffer(LooseNbPool, CloneMdl, 0, 0);
        if (!*CloneNb)
        {
            MemFreeDataAndMdlChain(CloneMdl);
            goto cleanupClone;
        }
    linkNb:
        CloneNb = &NET_BUFFER_NEXT_NB(*CloneNb);
    }
    Clone->ParentNetBufferList = Original;
    return Clone;

cleanupClone:
    MemFreeNetBufferList(Clone);
    return NULL;
}

_Use_decl_annotations_
BOOLEAN
MemNetBufferListIsOurs(NET_BUFFER_LIST *Nbl)
{
    if (Nbl->NdisPoolHandle == LooseNblPool)
        return TRUE;
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        if (Nbl->NdisPoolHandle == NblDataPools[i])
            return TRUE;
    }
    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
MemCopyFromMdl(VOID *Dst, MDL *Src, ULONG Offset, ULONG Size)
{
    if (!Src)
        return STATUS_BUFFER_TOO_SMALL;
    UCHAR *DstBuf = Dst;
    while (Offset >= MmGetMdlByteCount(Src))
    {
        Offset -= MmGetMdlByteCount(Src);
        Src = Src->Next;
        if (!Src)
            return STATUS_BUFFER_TOO_SMALL;
    }
    for (ULONG CurSize; Size; Src = Src->Next, Size -= CurSize, DstBuf += CurSize)
    {
        if (!Src)
            return STATUS_BUFFER_TOO_SMALL;
        UCHAR *SrcBuf = MmGetSystemAddressForMdlSafe(Src, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
        if (!SrcBuf)
            return STATUS_INSUFFICIENT_RESOURCES;
        CurSize = min(MmGetMdlByteCount(Src) - Offset, Size);
        RtlCopyMemory(DstBuf, SrcBuf + Offset, CurSize);
        Offset = 0;
    }
    return STATUS_SUCCESS;
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, MemDriverEntry)
#endif
_Use_decl_annotations_
NTSTATUS
MemDriverEntry(VOID)
{
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        NET_BUFFER_LIST_POOL_PARAMETERS NblDataPoolParameters = {
            .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                        .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                        .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
            .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
            .PoolTag = MEMORY_TAG,
            .fAllocateNetBuffer = TRUE,
            .DataSize = PacketCacheSizes[i]
        };
        NblDataPools[i] = NdisAllocateNetBufferListPool(NULL, &NblDataPoolParameters);
        if (!NblDataPools[i])
        {
            for (ULONG j = 0; j < i; ++j)
                NdisFreeNetBufferListPool(NblDataPools[j]);
            goto cleanup;
        }
    }
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        NET_BUFFER_POOL_PARAMETERS NbDataPoolParameters = {
            .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                        .Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1,
                        .Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1 },
            .PoolTag = MEMORY_TAG,
            .DataSize = PacketCacheSizes[i]
        };
        NbDataPools[i] = NdisAllocateNetBufferPool(NULL, &NbDataPoolParameters);
        if (!NbDataPools[i])
        {
            for (ULONG j = 0; j < i; ++j)
                NdisFreeNetBufferPool(NbDataPools[j]);
            goto cleanupNblDataPools;
        }
    }
    NET_BUFFER_LIST_POOL_PARAMETERS LooseNblPoolParameters = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
        .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
        .PoolTag = MEMORY_TAG
    };
    LooseNblPool = NdisAllocateNetBufferListPool(NULL, &LooseNblPoolParameters);
    if (!LooseNblPool)
        goto cleanupNbDataPools;
    NET_BUFFER_POOL_PARAMETERS LooseNbPoolParameters = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1 },
        .PoolTag = MEMORY_TAG
    };
    LooseNbPool = NdisAllocateNetBufferPool(NULL, &LooseNbPoolParameters);
    if (!LooseNbPool)
        goto cleanupLooseNblPool;
    return STATUS_SUCCESS;

cleanupLooseNblPool:
    NdisFreeNetBufferListPool(LooseNblPool);
cleanupNbDataPools:
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
        NdisFreeNetBufferPool(NbDataPools[i]);
cleanupNblDataPools:
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
        NdisFreeNetBufferListPool(NblDataPools[i]);
cleanup:
    return STATUS_INSUFFICIENT_RESOURCES;
}

_Use_decl_annotations_
VOID MemUnload(VOID)
{
    NdisFreeNetBufferPool(LooseNbPool);
    NdisFreeNetBufferListPool(LooseNblPool);
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        NdisFreeNetBufferPool(NbDataPools[i]);
        NdisFreeNetBufferListPool(NblDataPools[i]);
    }
}
