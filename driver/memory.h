/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "arithmetic.h"
#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include <ndis.h>

#define MEMORY_TAG Be32ToCpu('wgnt')

/* Source analysis has issues with ExAllocatePool... annotations raising false alerts. */
#pragma warning(push)
#pragma warning(disable : 28118)
#pragma warning(disable : 28160)

_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_maybenull_
_Must_inspect_result_
_Post_writable_byte_size_(NumberOfBytes)
_Return_type_success_(return != NULL)
static inline __drv_allocatesMem(Mem)
VOID *
MemAllocate(_In_ SIZE_T NumberOfBytes)
{
    return ExAllocatePoolUninitialized(NonPagedPool, NumberOfBytes, MEMORY_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_maybenull_
_Must_inspect_result_
_Post_writable_byte_size_(NumberOfBytes)
_Return_type_success_(return != NULL)
_At_buffer_((UCHAR *)return, _Iter_, NumberOfBytes, _Post_satisfies_(((UCHAR *)return )[_Iter_] == 0))
static inline __drv_allocatesMem(Mem)
VOID *
MemAllocateAndZero(_In_ SIZE_T NumberOfBytes)
{
    return ExAllocatePoolZero(NonPagedPool, NumberOfBytes, MEMORY_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_maybenull_
_Must_inspect_result_
_Post_writable_byte_size_((NumberOfElements) * (SizeOfOneElement))
_Return_type_success_(return != NULL)
static inline __drv_allocatesMem(Mem)
VOID *
MemAllocateArray(_In_ SIZE_T NumberOfElements, _In_ SIZE_T SizeOfOneElement)
{
    SIZE_T Size;
    if (!NT_SUCCESS(RtlSIZETMult(NumberOfElements, SizeOfOneElement, &Size)))
        return NULL;
    return ExAllocatePoolUninitialized(NonPagedPool, Size, MEMORY_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_maybenull_
_Must_inspect_result_
_Post_writable_byte_size_((NumberOfElements) * (SizeOfOneElement))
_Return_type_success_(return != NULL)
_At_buffer_(
    (UCHAR *)return,
    _Iter_,
    NumberOfElements *SizeOfOneElement,
    _Post_satisfies_(((UCHAR *)return )[_Iter_] == 0))
static inline __drv_allocatesMem(Mem)
VOID *
MemAllocateArrayAndZero(_In_ SIZE_T NumberOfElements, _In_ SIZE_T SizeOfOneElement)
{
    SIZE_T Size;
    if (!NT_SUCCESS(RtlSIZETMult(NumberOfElements, SizeOfOneElement, &Size)))
        return NULL;
    return ExAllocatePoolZero(NonPagedPool, Size, MEMORY_TAG);
}

#pragma warning(pop)

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
MemFree(_Pre_maybenull_ __drv_freesMem(Mem) VOID *Ptr)
{
    if (Ptr)
        ExFreePoolWithTag(Ptr, MEMORY_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
MemFreeSensitive(_Pre_maybenull_ __drv_freesMem(Mem) VOID *Ptr, _In_ SIZE_T Size)
{
    if (Ptr)
    {
        RtlSecureZeroMemory(Ptr, Size);
        ExFreePoolWithTag(Ptr, MEMORY_TAG);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MemFreeDataAndMdlChain(_In_opt_ __drv_freesMem(Mem) MDL *Mdl);

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Return_type_success_(return != NULL)
__drv_allocatesMem(Mem)
MDL *
MemAllocateDataAndMdlChain(_In_ ULONG Size);

_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_Return_type_success_(return != NULL)
__drv_allocatesMem(mem)
NET_BUFFER_LIST *
MemAllocateNetBufferList(
    _In_ ULONG SpaceBefore,
    _In_ ULONG Size,
    _In_ ULONG SpaceAfter);

_IRQL_requires_max_(DISPATCH_LEVEL)
__drv_allocatesMem(mem)
NET_BUFFER_LIST *
MemAllocateNetBufferListWithClonedGeometry(
    _In_ NET_BUFFER_LIST *Original,
    _In_ ULONG AdditionalBytesPerNb);

BOOLEAN
MemNetBufferListIsOurs(_In_ NET_BUFFER_LIST *Nbl);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MemFreeNetBufferList(__drv_freesMem(mem) _In_ NET_BUFFER_LIST *Nbl);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_notnull_
static inline VOID *
MemGetValidatedNetBufferData(_In_ CONST NET_BUFFER *Nb)
{
    /* We intentionally neglect to add NET_BUFFER_CURRENT_MDL_OFFSET(Nb) here, as this really
     * only applies to NBs that we create ourselves.
     */
    VOID *Addr = MmGetMdlVirtualAddress(NET_BUFFER_CURRENT_MDL(Nb));
    _Analysis_assume_(Addr != NULL);
    return Addr;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_notnull_
static inline VOID *
MemGetValidatedNetBufferListData(_In_ CONST NET_BUFFER_LIST *Nbl)
{
    return MemGetValidatedNetBufferData(NET_BUFFER_LIST_FIRST_NB(Nbl));
}

_Must_inspect_result_
NTSTATUS
MemCopyFromMdl(_Out_writes_bytes_all_(Size) VOID *Dst, _In_ MDL *Src, _In_ ULONG Offset, _In_ ULONG Size);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MemDriverEntry(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID MemUnload(VOID);
