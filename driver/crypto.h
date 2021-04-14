/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "undocumented.h"
#include <ndis.h>

#if defined(_M_AMD64)
typedef enum
{
    CPU_FEATURE_SSSE3 = 1 << 0,
    CPU_FEATURE_AVX = 1 << 1,
    CPU_FEATURE_AVX2 = 1 << 2,
    CPU_FEATURE_AVX512F = 1 << 3,
    CPU_FEATURE_AVX512VL = 1 << 4,
    CPU_FEATURE_AVX512IFMA = 1 << 5,
} CPU_FEATURE;

typedef struct _SIMD_STATE
{
    CPU_FEATURE CpuFeatures;
    XSTATE_SAVE XState;
    BOOLEAN HasSavedXState;
} SIMD_STATE;

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(State->HasSavedXState, _Kernel_float_saved_)
_At_(State->XState, _When_(State->HasSavedXState, _Kernel_acquires_resource_(FloatState)))
VOID
SimdGet(_Out_ SIMD_STATE *State);

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(State->HasSavedXState, _Kernel_float_restored_)
_At_(
    State->XState,
    _When_(State->HasSavedXState, _Kernel_requires_resource_held_(FloatState) _Kernel_releases_resource_(FloatState)))
VOID
SimdPut(_Inout_ SIMD_STATE *State);
#else
typedef struct _SIMD_STATE
{
    CHAR CpuFeatures;
} SIMD_STATE;

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
SimdGet(_Out_ SIMD_STATE *State)
{
    State->CpuFeatures = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
SimdPut(_Inout_ SIMD_STATE *State)
{
}
#endif

_Must_inspect_result_
static FORCEINLINE BOOLEAN
CryptoEqualMemory16(_In_reads_bytes_(16) CONST VOID *Data1, _In_reads_bytes_(16) CONST VOID *Data2)
{
#if _WIN64
    CONST volatile ULONG64 *D1 = Data1, *D2 = Data2;
    volatile ULONG64 NotEqual = (ReadULong64NoFence(&D1[0]) ^ ReadULong64NoFence(&D2[0])) |
                                (ReadULong64NoFence(&D1[1]) ^ ReadULong64NoFence(&D2[1]));
#else
    CONST volatile ULONG *D1 = Data1, *D2 = Data2;
    volatile ULONG NotEqual =
        (ReadULongNoFence(&D1[0]) ^ ReadULongNoFence(&D2[0])) | (ReadULongNoFence(&D1[1]) ^ ReadULongNoFence(&D2[1])) |
        (ReadULongNoFence(&D1[2]) ^ ReadULongNoFence(&D2[2])) | (ReadULongNoFence(&D1[3]) ^ ReadULongNoFence(&D2[3]));
#endif
    return !NotEqual;
}

_Must_inspect_result_
static FORCEINLINE BOOLEAN
CryptoEqualMemory32(_In_reads_bytes_(32) CONST VOID *Data1, _In_reads_bytes_(32) CONST VOID *Data2)
{
#if _WIN64
    CONST volatile ULONG64 *D1 = Data1, *D2 = Data2;
    volatile ULONG64 NotEqual = (ReadULong64NoFence(&D1[0]) ^ ReadULong64NoFence(&D2[0])) |
                                (ReadULong64NoFence(&D1[1]) ^ ReadULong64NoFence(&D2[1])) |
                                (ReadULong64NoFence(&D1[2]) ^ ReadULong64NoFence(&D2[2])) |
                                (ReadULong64NoFence(&D1[3]) ^ ReadULong64NoFence(&D2[3]));
#else
    CONST volatile ULONG *D1 = Data1, *D2 = Data2;
    volatile ULONG NotEqual =
        (ReadULongNoFence(&D1[0]) ^ ReadULongNoFence(&D2[0])) | (ReadULongNoFence(&D1[1]) ^ ReadULongNoFence(&D2[1])) |
        (ReadULongNoFence(&D1[2]) ^ ReadULongNoFence(&D2[2])) | (ReadULongNoFence(&D1[3]) ^ ReadULongNoFence(&D2[3])) |
        (ReadULongNoFence(&D1[4]) ^ ReadULongNoFence(&D2[4])) | (ReadULongNoFence(&D1[5]) ^ ReadULongNoFence(&D2[5])) |
        (ReadULongNoFence(&D1[6]) ^ ReadULongNoFence(&D2[6])) | (ReadULongNoFence(&D1[7]) ^ ReadULongNoFence(&D2[7]));
#endif
    return !NotEqual;
}

#pragma warning(disable : 28159) /* We're bug checking in case somebody's RNG is borked. */
static inline VOID
CryptoRandom(_Out_writes_bytes_all_(Len) PVOID RandomData, _In_ SIZE_T Len)
{
#ifdef SDV_HACKS
    /* SDV refuses to run if we link against cng.lib, so for SDV mode, we just insert a stub
     * function instead. Then, out of an abundance of caution, we make sure that this always
     * bug checks in case somebody's build system somehow winds up building this by accident.
     */
    if (Len)
        KeBugCheck(CRYPTO_LIBRARY_INTERNAL_ERROR);
    RtlFillMemory(RandomData, Len, 'A');
#else
    /* CryptoRandom is documented as "Always returns TRUE." We see from reverse engineering that
     * it returns FALSE if AesRNGState_generate fails, and that fails if a size addition overflows,
     * which presumably it won't given that we only ever pass small values of Len. So just assert
     * here that the documentation is correct.
     */
    if (!SystemPrng(RandomData, Len))
        KeBugCheck(CRYPTO_LIBRARY_INTERNAL_ERROR);
#endif
}

enum CHACHA20POLY1305_LENGTHS
{
    XCHACHA20POLY1305_NONCE_SIZE = 24,
    CHACHA20POLY1305_KEY_SIZE = 32,
    CHACHA20POLY1305_AUTHTAG_SIZE = 16
};

VOID
ChaCha20Poly1305Encrypt(
    _Out_writes_bytes_all_(SrcLen + CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *Dst,
    _In_reads_bytes_(SrcLen) CONST UINT8 *Src,
    _In_ CONST SIZE_T SrcLen,
    _In_reads_bytes_(AdLen) CONST UINT8 *Ad,
    _In_ CONST SIZE_T AdLen,
    _In_ CONST UINT64 Nonce,
    _In_ CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE]);

_Must_inspect_result_
BOOLEAN
ChaCha20Poly1305Decrypt(
    _Out_writes_bytes_all_(SrcLen - CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *Dst,
    _In_reads_bytes_(SrcLen) CONST UINT8 *Src,
    _In_ CONST SIZE_T SrcLen,
    _In_reads_bytes_(AdLen) CONST UINT8 *Ad,
    _In_ CONST SIZE_T AdLen,
    _In_ CONST UINT64 Nonce,
    _In_ CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE]);

_Must_inspect_result_
BOOLEAN
ChaCha20Poly1305EncryptMdl(
    _Out_writes_bytes_all_(SrcLen + CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *Dst,
    _In_ MDL *Src,
    _In_ CONST ULONG SrcLen,
    _In_ CONST ULONG SrcOffset,
    _In_reads_bytes_(AdLen) CONST UINT8 *Ad,
    _In_ CONST SIZE_T AdLen,
    _In_ CONST UINT64 Nonce,
    _In_ CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE],
    _In_opt_ CONST SIMD_STATE *Simd);

_Must_inspect_result_
BOOLEAN
ChaCha20Poly1305DecryptMdl(
    _Out_writes_bytes_all_(SrcLen - CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *Dst,
    _In_ MDL *Src,
    _In_ CONST ULONG SrcLen,
    _In_ CONST ULONG SrcOffset,
    _In_reads_bytes_(AdLen) CONST UINT8 *Ad,
    _In_ CONST SIZE_T AdLen,
    _In_ CONST UINT64 Nonce,
    _In_ CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE],
    _In_opt_ CONST SIMD_STATE *Simd);

VOID
XChaCha20Poly1305Encrypt(
    _Out_writes_bytes_all_(SrcLen + CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *Dst,
    _In_reads_bytes_(SrcLen) CONST UINT8 *Src,
    _In_ CONST SIZE_T SrcLen,
    _In_reads_bytes_(AdLen) CONST UINT8 *Ad,
    _In_ CONST SIZE_T AdLen,
    _In_ CONST UINT8 Nonce[XCHACHA20POLY1305_NONCE_SIZE],
    _In_ CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE]);

_Must_inspect_result_
BOOLEAN
XChaCha20Poly1305Decrypt(
    _Out_writes_bytes_all_(SrcLen - CHACHA20POLY1305_AUTHTAG_SIZE) UINT8 *Dst,
    _In_reads_bytes_(SrcLen) CONST UINT8 *Src,
    _In_ CONST SIZE_T SrcLen,
    _In_reads_bytes_(AdLen) CONST UINT8 *Ad,
    _In_ CONST SIZE_T AdLen,
    _In_ CONST UINT8 Nonce[XCHACHA20POLY1305_NONCE_SIZE],
    _In_ CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE]);

enum BLAKE2S_LENGTHS
{
    BLAKE2S_BLOCK_SIZE = 64,
    BLAKE2S_HASH_SIZE = 32,
    BLAKE2S_KEY_SIZE = 32
};

typedef struct _BLAKE2S_STATE
{
    UINT32 H[8];
    UINT32 T[2];
    UINT32 F[2];
    UINT8 Buf[BLAKE2S_BLOCK_SIZE];
    ULONG BufLen;
    ULONG OutLen;
} BLAKE2S_STATE;

VOID
Blake2sInit(_Out_ BLAKE2S_STATE *State, _In_ CONST SIZE_T OutLen);

VOID
Blake2sInitKey(
    _Out_ BLAKE2S_STATE *State,
    _In_ CONST SIZE_T OutLen,
    _In_reads_bytes_(KeyLen) CONST UINT8 *Key,
    _In_ CONST SIZE_T KeyLen);

VOID
Blake2sUpdate(_Inout_ BLAKE2S_STATE *State, _In_reads_bytes_(InLen) CONST UINT8 *In, _In_ SIZE_T InLen);

VOID
Blake2sFinal(_Inout_ BLAKE2S_STATE *State, _Out_writes_bytes_all_(State->OutLen) UINT8 *Out);

VOID
Blake2s(
    _Out_writes_bytes_all_(OutLen) UINT8 *Out,
    _In_reads_bytes_(InLen) CONST UINT8 *In,
    _In_reads_bytes_(KeyLen) CONST UINT8 *Key,
    _In_ CONST SIZE_T OutLen,
    _In_ CONST SIZE_T InLen,
    _In_ CONST SIZE_T KeyLen);

VOID
Blake2s256Hmac(
    _Out_writes_bytes_all_(BLAKE2S_HASH_SIZE) UINT8 *Out,
    _In_reads_bytes_(InLen) CONST UINT8 *In,
    _In_reads_bytes_(KeyLen) CONST UINT8 *Key,
    _In_ CONST SIZE_T InLen,
    _In_ CONST SIZE_T KeyLen);

typedef struct _SIPHASH_KEY
{
    UINT64 Key[2];
} SIPHASH_KEY;

UINT64
Siphash(_In_reads_bytes_(Len) CONST VOID *Data, _In_ SIZE_T Len, _In_ CONST SIPHASH_KEY *Key);
UINT64
Siphash1u64(_In_ CONST UINT64 A, _In_ CONST SIPHASH_KEY *Key);
UINT64
Siphash2u64(_In_ CONST UINT64 A, _In_ CONST UINT64 B, _In_ CONST SIPHASH_KEY *Key);
UINT64
Siphash3u64(_In_ CONST UINT64 A, _In_ CONST UINT64 B, _In_ CONST UINT64 C, _In_ CONST SIPHASH_KEY *Key);
UINT64
Siphash4u64(
    _In_ CONST UINT64 A,
    _In_ CONST UINT64 B,
    _In_ CONST UINT64 C,
    _In_ CONST UINT64 D,
    _In_ CONST SIPHASH_KEY *Key);
UINT64
Siphash1u32(_In_ CONST UINT32 A, _In_ CONST SIPHASH_KEY *Key);
UINT64
Siphash3u32(_In_ CONST UINT32 A, _In_ CONST UINT32 B, _In_ CONST UINT32 C, _In_ CONST SIPHASH_KEY *Key);

static inline UINT64
Siphash2u32(_In_ CONST UINT32 A, _In_ CONST UINT32 B, _In_ CONST SIPHASH_KEY *Key)
{
    return Siphash1u64((UINT64)B << 32 | A, Key);
}
static inline UINT64
Siphash4u32(
    _In_ CONST UINT32 A,
    _In_ CONST UINT32 B,
    _In_ CONST UINT32 C,
    _In_ CONST UINT32 D,
    _In_ CONST SIPHASH_KEY *Key)
{
    return Siphash2u64((UINT64)B << 32 | A, (UINT64)D << 32 | C, Key);
}

typedef struct _HSIPHASH_KEY
{
    ULONG_PTR Key[2];
} HSIPHASH_KEY;

UINT32
Hsiphash(_In_reads_bytes_(Len) CONST VOID *Data, _In_ SIZE_T Len, _In_ CONST HSIPHASH_KEY *Key);
UINT32
Hsiphash1u32(_In_ CONST UINT32 A, _In_ CONST HSIPHASH_KEY *Key);
UINT32
Hsiphash2u32(_In_ CONST UINT32 A, _In_ CONST UINT32 B, _In_ CONST HSIPHASH_KEY *Key);
UINT32
Hsiphash3u32(_In_ CONST UINT32 A, _In_ CONST UINT32 B, _In_ CONST UINT32 C, _In_ CONST HSIPHASH_KEY *Key);
UINT32
Hsiphash4u32(
    _In_ CONST UINT32 A,
    _In_ CONST UINT32 B,
    _In_ CONST UINT32 C,
    _In_ CONST UINT32 D,
    _In_ CONST HSIPHASH_KEY *Key);

enum CURVE25519_LENGTHS
{
    CURVE25519_KEY_SIZE = 32
};

_Must_inspect_result_
BOOLEAN
Curve25519(
    _Out_writes_bytes_all_(CURVE25519_KEY_SIZE) UINT8 Out[CURVE25519_KEY_SIZE],
    _In_reads_bytes_(CURVE25519_KEY_SIZE) CONST UINT8 Scalar[CURVE25519_KEY_SIZE],
    _In_reads_bytes_(CURVE25519_KEY_SIZE) CONST UINT8 Point[CURVE25519_KEY_SIZE]);

_Must_inspect_result_
static inline BOOLEAN
Curve25519GeneratePublic(
    _Out_writes_bytes_all_(CURVE25519_KEY_SIZE) UINT8 Pub[CURVE25519_KEY_SIZE],
    _In_reads_bytes_(CURVE25519_KEY_SIZE) CONST UINT8 Secret[CURVE25519_KEY_SIZE])
{
    static CONST UINT8 Basepoint[CURVE25519_KEY_SIZE] = { 9 };
    return Curve25519(Pub, Secret, Basepoint);
}

static inline VOID
Curve25519ClampSecret(_Inout_updates_bytes_(CURVE25519_KEY_SIZE) UINT8 Secret[CURVE25519_KEY_SIZE])
{
    Secret[0] &= 248;
    Secret[31] = (Secret[31] & 127) | 64;
}

static inline VOID
Curve25519GenerateSecret(_Out_writes_bytes_all_(CURVE25519_KEY_SIZE) UINT8 Secret[CURVE25519_KEY_SIZE])
{
    CryptoRandom(Secret, CURVE25519_KEY_SIZE);
    Curve25519ClampSecret(Secret);
}

_Must_inspect_result_
static FORCEINLINE BOOLEAN
Curve25519IsNull(_In_reads_bytes_(CURVE25519_KEY_SIZE) CONST UINT8 Pub[CURVE25519_KEY_SIZE])
{
#if _WIN64
    CONST volatile ULONG64 *P = (CONST volatile ULONG64 *)Pub;
    volatile ULONG64 NotZero =
        ReadULong64NoFence(&P[0]) | ReadULong64NoFence(&P[1]) | ReadULong64NoFence(&P[2]) | ReadULong64NoFence(&P[3]);
#else
    CONST volatile ULONG *P = (CONST volatile ULONG *)Pub;
    volatile ULONG NotZero = ReadULongNoFence(&P[0]) | ReadULongNoFence(&P[1]) | ReadULongNoFence(&P[2]) |
                             ReadULongNoFence(&P[3]) | ReadULongNoFence(&P[4]) | ReadULongNoFence(&P[5]) |
                             ReadULongNoFence(&P[6]) | ReadULongNoFence(&P[7]);
#endif
    return !NotZero;
}

VOID CryptoDriverEntry(VOID);

#ifdef DBG
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CryptoSelftest(VOID);
#endif
