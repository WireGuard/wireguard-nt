/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include <ndis.h>
#include <ntintsafe.h>

typedef _Strict_type_match_ UINT16 UINT16_BE;
typedef _Strict_type_match_ UINT16 UINT16_LE;
typedef _Strict_type_match_ UINT32 UINT32_BE;
typedef _Strict_type_match_ UINT32 UINT32_LE;
typedef _Strict_type_match_ UINT64 UINT64_BE;
typedef _Strict_type_match_ UINT64 UINT64_LE;

#if REG_DWORD == REG_DWORD_BIG_ENDIAN
#    define Le16ToCpu(X) ((UINT16)RtlUshortByteSwap(X))
#    define Le32ToCpu(X) ((UINT32)RtlUlongByteSwap(X))
#    define Le64ToCpu(X) ((UINT64)RtlUlonglongByteSwap(X))
#    define Be16ToCpu(X) ((UINT16)(X))
#    define Be32ToCpu(X) ((UINT32)(X))
#    define Be64ToCpu(X) ((UINT64)(X))
#    define CpuToLe16(X) ((UINT16_LE)RtlUshortByteSwap(X))
#    define CpuToLe32(X) ((UINT32_LE)RtlUlongByteSwap(X))
#    define CpuToLe64(X) ((UINT64_LE)RtlUlonglongByteSwap(X))
#    define CpuToBe16(X) ((UINT16_BE)(X))
#    define CpuToBe32(X) ((UINT32_BE)(X))
#    define CpuToBe64(X) ((UINT64_BE)(X))
#elif REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#    define Be16ToCpu(X) ((UINT16)RtlUshortByteSwap(X))
#    define Be32ToCpu(X) ((UINT32)RtlUlongByteSwap(X))
#    define Be64ToCpu(X) ((UINT64)RtlUlonglongByteSwap(X))
#    define Le16ToCpu(X) ((UINT16)(X))
#    define Le32ToCpu(X) ((UINT32)(X))
#    define Le64ToCpu(X) ((UINT64)(X))
#    define CpuToBe16(X) ((UINT16_BE)RtlUshortByteSwap(X))
#    define CpuToBe32(X) ((UINT32_BE)RtlUlongByteSwap(X))
#    define CpuToBe64(X) ((UINT64_BE)RtlUlonglongByteSwap(X))
#    define CpuToLe16(X) ((UINT16_LE)(X))
#    define CpuToLe32(X) ((UINT32_LE)(X))
#    define CpuToLe64(X) ((UINT64_LE)(X))
#else
#    error "Unable to determine endianess"
#endif

#define Ntohs(X) Be16ToCpu(X)
#define Ntohl(X) Be32ToCpu(X)
#define Htons(X) CpuToBe16(X)
#define Htonl(X) CpuToBe32(X)

#ifdef _WIN64
#    define BITS_PER_POINTER 64
#    define BITS_PER_POINTER_SHIFT 6
#else
#    define BITS_PER_POINTER 32
#    define BITS_PER_POINTER_SHIFT 5
#endif

static inline ULONG
FindLastSet32(_In_ UINT32 Word)
{
    ULONG Index;
    return BitScanReverse(&Index, Word) ? Index + 1 : 0;
}

static inline ULONG
FindLastSet64(_In_ UINT64 Word)
{
#ifndef BitScanReverse64
    UINT32 H = Word >> 32;
    return H ? FindLastSet32(H) + 32 : FindLastSet32((UINT32)Word);
#else
    ULONG Index;
    return BitScanReverse64(&Index, Word) ? Index + 1 : 0;
#endif
}

static inline ULONG
FindLastSet128(_In_ UINT64 A, _In_ UINT64 B)
{
    return A ? FindLastSet64(A) + 64U : FindLastSet64(B);
}

static inline ULONG_PTR
RounddownPowOfTwo(_In_ ULONG_PTR N)
{
    N = N | (N >> 1);
    N = N | (N >> 2);
    N = N | (N >> 4);
    N = N | (N >> 8);
    N = N | (N >> 16);
#ifdef _WIN64
    N = N | (N >> 32);
#endif
    return N - (N >> 1);
}

#define DIV_ROUND_UP(N, D) (((N) + (D)-1) / (D))
#define ALIGN_DOWN_BY_T(T, Length, Alignment) ((T)(Length) & ~((T)(Alignment)-1))
#define ALIGN_UP_BY_T(T, Length, Alignment) (ALIGN_DOWN_BY_T(T, ((T)(Length) + (Alignment)-1), Alignment))