/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "memory.h"
#include "messages.h"

static CONST ULONG PacketCacheSizes[] = { 192, 512, 1024, 1500, 9000 };
static LOOKASIDE_ALIGN LOOKASIDE_LIST_EX PacketCaches[ARRAYSIZE(PacketCacheSizes)];

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Return_type_success_(return != NULL)
static __drv_allocatesMem(Mem)
VOID *
MemAllocateFromPacketCaches(_In_ ULONG BufferSize)
{
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        if (PacketCacheSizes[i] >= BufferSize)
            return ExAllocateFromLookasideListEx(&PacketCaches[i]);
    }
    return MemAllocate(BufferSize);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
MemFreeToPacketCaches(_In_ ULONG BufferSize, _In_ __drv_freesMem(Mem) VOID *Memory)
{
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
    {
        if (PacketCacheSizes[i] >= BufferSize)
        {
            ExFreeToLookasideListEx(&PacketCaches[i], Memory);
            return;
        }
    }
    MemFree(Memory);
}

#pragma warning(suppress : 28195) /* IoAllocateMdl allocates, even if missing the SAL annotation. */
_Use_decl_annotations_
MDL *
MemAllocateDataAndMdlChain(ULONG BufferSize)
{
    NT_ASSERT(BufferSize <= (MAXULONG - PAGE_SIZE));
    VOID *Memory = MemAllocateFromPacketCaches(BufferSize);
    if (!Memory)
        return NULL;
    MDL *Mdl = IoAllocateMdl(Memory, BufferSize, FALSE, FALSE, NULL);
    if (!Mdl)
    {
        MemFreeToPacketCaches(BufferSize, Memory);
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
        ULONG BufferCount = MmGetMdlByteCount(Mdl);
        VOID *Memory = MmGetMdlVirtualAddress(Mdl);
        IoFreeMdl(Mdl);
        MemFreeToPacketCaches(BufferCount, Memory);
        Mdl = Next;
    }
}

_Use_decl_annotations_
NET_BUFFER_LIST *
MemAllocateNetBufferList(NDIS_HANDLE NblPool, NDIS_HANDLE NbPool, ULONG SpaceBefore, ULONG Size, ULONG SpaceAfter)
{
    ULONG Sum = Size;
    if (!NT_SUCCESS(RtlULongAdd(Sum, SpaceBefore, &Sum) || !NT_SUCCESS(RtlULongAdd(Sum, SpaceAfter, &Sum))) ||
        Sum > MTU_MAX)
        return NULL;
#pragma warning(suppress : 6014) /* MDL is aliased in Nbl or freed on failure. */
    MDL *Mdl = MemAllocateDataAndMdlChain(Sum);
    if (!Mdl)
        return NULL;
    NET_BUFFER *Nb = NdisAllocateNetBuffer(NbPool, Mdl, SpaceBefore, Size);
    if (!Nb)
        goto cleanupMdl;
    NET_BUFFER_LIST *Nbl = NdisAllocateNetBufferList(NblPool, 0, 0);
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
    while (NET_BUFFER_LIST_FIRST_NB(Nbl))
    {
        NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
        NET_BUFFER_LIST_FIRST_NB(Nbl) = NET_BUFFER_NEXT_NB(NET_BUFFER_LIST_FIRST_NB(Nbl));
        MemFreeDataAndMdlChain(NET_BUFFER_FIRST_MDL(Nb));
        NdisFreeNetBuffer(Nb);
    }
    NdisFreeNetBufferList(Nbl);
}

#pragma warning(suppress : 28195) /* NdisAllocateNetBufferList & co allocate. */
_Use_decl_annotations_
NET_BUFFER_LIST *
MemAllocateNetBufferListWithClonedGeometry(
    NDIS_HANDLE NblPool,
    NDIS_HANDLE NbPool,
    NET_BUFFER_LIST *Original,
    ULONG AdditionalBytesPerNb)
{
    NET_BUFFER_LIST *Clone = NdisAllocateNetBufferList(NblPool, 0, 0);
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
#pragma warning(suppress : 6014) /* `CloneMdl` is aliased in NdisAllocateNetBuffer or freed on failure. */
        MDL *CloneMdl = MemAllocateDataAndMdlChain(Length);
        if (!CloneMdl)
            goto cleanupClone;
        *CloneNb = NdisAllocateNetBuffer(NbPool, CloneMdl, 0, 0);
        if (!*CloneNb)
        {
            MemFreeDataAndMdlChain(CloneMdl);
            goto cleanupClone;
        }
        CloneNb = &NET_BUFFER_NEXT_NB(*CloneNb);
    }
    Clone->ParentNetBufferList = Original;
    return Clone;

cleanupClone:
    MemFreeNetBufferList(Clone);
    return NULL;
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
        NTSTATUS Status = ExInitializeLookasideListEx(
            &PacketCaches[i], NULL, NULL, NonPagedPool, 0, PacketCacheSizes[i], MEMORY_TAG, 0);
        if (!NT_SUCCESS(Status))
        {
            for (ULONG j = 0; j < i; ++j)
                ExDeleteLookasideListEx(&PacketCaches[j]);
            return Status;
        }
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID MemUnload(VOID)
{
    for (ULONG i = 0; i < ARRAYSIZE(PacketCacheSizes); ++i)
        ExDeleteLookasideListEx(&PacketCaches[i]);
}
