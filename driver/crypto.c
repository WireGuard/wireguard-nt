/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "crypto.h"
#include "arithmetic.h"
#include "memory.h"

#pragma warning(disable : 4244)  /* '=': conversion from 'UINT32' to 'UINT8', possible loss of data */
#pragma warning(disable : 4267)  /* '=': conversion from 'SIZE_T' to 'ULONG', possible loss of data */
#pragma warning(disable : 4242)  /* '=': conversion from 'SIZE_T' to 'UINT32', possible loss of data */
#pragma warning(disable : 6385)  /* Reading invalid data from '<COMPLEX_EXPR>':  the readable size is '_Old_5`32' \
                                    bytes, but '56' bytes may be read. */
#pragma warning(disable : 26451) /* Arithmetic overflow: Using operator '*' on a 4 byte value and then casting the \
                                    result to a 8 byte value. Cast the value to the wider type before calling operator \
                                    '*' to avoid overflow (io.2). */

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, CryptoDriverEntry)
#endif
#if defined(_M_AMD64)
#    include <intrin.h>

static CPU_FEATURE CpuFeatures;

#    define CPUID_1_ECX_SSSE3_BIT 9
#    define CPUID_1_ECX_SSSE3_BIT 9
#    define CPUID_1_ECX_SSE3_BIT 0
#    define CPUID_1_EDX_SSE2_BIT 26
#    define CPUID_1_EDX_SSE_BIT 25
#    define CPUID_1_ECX_AVX_BIT 28
#    define CPUID_1_ECX_OSXSAVE_BIT 27
#    define CPUID_70_EBX_AVX2_BIT 5
#    define CPUID_70_EBX_AVX512F_BIT 16
#    define CPUID_70_EBX_AVX512IFMA_BIT 21
#    define CPUID_70_EBX_AVX512VL_BIT 31
#    define WORD_EAX 0
#    define WORD_EBX 1
#    define WORD_ECX 2
#    define WORD_EDX 3

typedef struct _CPUID_BIT_INFO
{
    BYTE Leaf;
    BYTE Word;
    BYTE Bitno;
    CPU_FEATURE RequiredBy;
} CPUID_BIT_INFO;

static CONST CPUID_BIT_INFO CpuidBitInfo[] = {
    { 1, WORD_EDX, CPUID_1_EDX_SSE_BIT, CPU_FEATURE_SSSE3 },
    { 1, WORD_EDX, CPUID_1_EDX_SSE2_BIT, CPU_FEATURE_SSSE3 },
    { 1, WORD_ECX, CPUID_1_ECX_SSE3_BIT, CPU_FEATURE_SSSE3 },
    { 1, WORD_ECX, CPUID_1_ECX_SSSE3_BIT, CPU_FEATURE_SSSE3 },
    { 1, WORD_ECX, CPUID_1_ECX_AVX_BIT, CPU_FEATURE_AVX },
    { 7, WORD_EBX, CPUID_70_EBX_AVX2_BIT, CPU_FEATURE_AVX2 },
    { 7, WORD_EBX, CPUID_70_EBX_AVX512F_BIT, CPU_FEATURE_AVX512F },
    { 7, WORD_EBX, CPUID_70_EBX_AVX512IFMA_BIT, CPU_FEATURE_AVX512IFMA },
    { 7, WORD_EBX, CPUID_70_EBX_AVX512VL_BIT, CPU_FEATURE_AVX512VL },
};

VOID CryptoDriverEntry(VOID)
{
    /* It's not like it's exactly hard or complicated to support Windows 7, 8, or 8.1 kernels here,
     * but it also means more testing, and given how poorly suited those old network stacks are for
     * high speed networking, it's simpler to just fall back to the slow implementations, and concern
     * ourselves with Windows 10 (and later, given the recent bout of Start Menu meddling).
     */
    RTL_OSVERSIONINFOW OsVersionInfo = { .dwOSVersionInfoSize = sizeof(OsVersionInfo) };
    if (!NT_SUCCESS(RtlGetVersion(&OsVersionInfo)) || OsVersionInfo.dwMajorVersion < 10)
        return;

    CPU_FEATURE DisabledCpuFeatures =
        ~(CPU_FEATURE_SSSE3 | CPU_FEATURE_AVX | CPU_FEATURE_AVX2 | CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512VL |
          CPU_FEATURE_AVX512IFMA);
    int CpuInfo[4], InfoType, MaxInfoType;
    BOOLEAN IsIntel, IsSkylakeX, HasOSXSAVE;

    __cpuid(CpuInfo, InfoType = 0);
    MaxInfoType = CpuInfo[WORD_EAX];
    IsIntel = CpuInfo[WORD_EBX] == 0x756e6547 && CpuInfo[WORD_EDX] == 0x49656e69 && CpuInfo[WORD_ECX] == 0x6c65746e;
    __cpuid(CpuInfo, InfoType = 1);
    IsSkylakeX = IsIntel && (CpuInfo[WORD_EAX] & 0xf0ff0) == 0x50650;
    HasOSXSAVE = !!(CpuInfo[WORD_ECX] & (1 << CPUID_1_ECX_OSXSAVE_BIT));

    for (ULONG i = 0; i < ARRAYSIZE(CpuidBitInfo); ++i)
    {
        if (CpuidBitInfo[i].Leaf != InfoType)
            __cpuid(CpuInfo, InfoType = CpuidBitInfo[i].Leaf);
        if (CpuidBitInfo[i].Leaf > MaxInfoType || !(CpuInfo[CpuidBitInfo[i].Word] & (1UL << CpuidBitInfo[i].Bitno)))
            DisabledCpuFeatures |= CpuidBitInfo[i].RequiredBy;
    }

    ULONG64 FeatureMask = RtlGetEnabledExtendedFeatures((ULONG64)(-1)) & (ULONG64)(HasOSXSAVE ? _xgetbv(0) : 0);
    if ((FeatureMask & (XSTATE_MASK_GSSE | XSTATE_MASK_AVX)) != (XSTATE_MASK_GSSE | XSTATE_MASK_AVX))
        DisabledCpuFeatures |= CPU_FEATURE_AVX | CPU_FEATURE_AVX2;
    if ((FeatureMask & (XSTATE_MASK_GSSE | XSTATE_MASK_AVX | XSTATE_MASK_AVX512)) !=
        (XSTATE_MASK_GSSE | XSTATE_MASK_AVX | XSTATE_MASK_AVX512))
        DisabledCpuFeatures |= CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA;

    if (DisabledCpuFeatures & CPU_FEATURE_SSSE3)
        DisabledCpuFeatures |= CPU_FEATURE_AVX;
    if (DisabledCpuFeatures & CPU_FEATURE_AVX)
        DisabledCpuFeatures |= CPU_FEATURE_AVX2;
    if (DisabledCpuFeatures & CPU_FEATURE_AVX2)
        DisabledCpuFeatures |= CPU_FEATURE_AVX512F;
    if (DisabledCpuFeatures & CPU_FEATURE_AVX512F)
        DisabledCpuFeatures |= CPU_FEATURE_AVX512VL;
    if (DisabledCpuFeatures & CPU_FEATURE_AVX512F)
        DisabledCpuFeatures |= CPU_FEATURE_AVX512IFMA;

    /* AVX512F downclocks too much on Skylake X, but VL is fine. */
    if (IsSkylakeX)
        DisabledCpuFeatures |= CPU_FEATURE_AVX512F;

    CpuFeatures = ~DisabledCpuFeatures;
}

_Use_decl_annotations_
VOID
SimdGet(SIMD_STATE *State)
{
    State->HasSavedXState = FALSE;
    State->CpuFeatures = CpuFeatures;
    if (CpuFeatures & (CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA))
    {
        State->HasSavedXState =
            NT_SUCCESS(KeSaveExtendedProcessorState(XSTATE_MASK_AVX | XSTATE_MASK_AVX512, &State->XState));
        if (State->HasSavedXState)
            return;
        State->CpuFeatures &= ~(CPU_FEATURE_AVX512F | CPU_FEATURE_AVX512VL | CPU_FEATURE_AVX512IFMA);
    }

    if (CpuFeatures & (CPU_FEATURE_AVX2 | CPU_FEATURE_AVX))
    {
        State->HasSavedXState = NT_SUCCESS(KeSaveExtendedProcessorState(XSTATE_MASK_AVX, &State->XState));
        if (State->HasSavedXState)
            return;
        State->CpuFeatures &= ~(CPU_FEATURE_AVX2 | CPU_FEATURE_AVX);
    }

    /* Sometimes State->XState isn't initialized, because of HaveSavedXState, but analysis doesn't know that. */
    _Analysis_assume_((RtlFillMemory(State, sizeof(*State), 'A'), TRUE));

    /* We don't need to save the state for SSSE3 on recent Windows. */
}

_Use_decl_annotations_
VOID
SimdPut(SIMD_STATE *State)
{
    if (!State->HasSavedXState)
    {
        State->CpuFeatures = 0;
        return;
    }
    KeRestoreExtendedProcessorState(&State->XState);
    RtlSecureZeroMemory(State, sizeof(*State));
}
#else
VOID CryptoDriverEntry(VOID) {}
#endif

static inline UINT32
Rol32(_In_ UINT32 Word, _In_ LONG Shift)
{
    return (Word << (Shift & 31)) | (Word >> ((-Shift) & 31));
}

static inline UINT32
Ror32(_In_ UINT32 Word, _In_ LONG Shift)
{
    return (Word >> (Shift & 31)) | (Word << ((-Shift) & 31));
}

static inline UINT64
Rol64(_In_ UINT64 Word, _In_ LONG Shift)
{
    return (Word << (Shift & 63)) | (Word >> ((-Shift) & 63));
}

#define Le16ToCpup(X) Le16ToCpu(*(X))
#define Le32ToCpup(X) Le32ToCpu(*(X))
#define Le64ToCpup(X) Le64ToCpu(*(X))

static inline UINT32
GetUnalignedLe32(_In_reads_bytes_(4) CONST UINT8 *A)
{
    UINT32 L;
    RtlCopyMemory(&L, A, sizeof(L));
    return Le32ToCpup(&L);
}

static inline UINT64
GetUnalignedLe64(_In_reads_bytes_(8) CONST UINT8 *A)
{
    UINT64 L;
    RtlCopyMemory(&L, A, sizeof(L));
    return Le64ToCpup(&L);
}

static inline VOID
PutUnalignedLe32(_In_ UINT32 S, _Out_writes_bytes_all_(4) UINT8 *D)
{
    UINT32 L = CpuToLe32(S);
    RtlCopyMemory(D, &L, sizeof(L));
}

static inline VOID
CpuToLe32Array(_Inout_updates_(Words) UINT32 *Buf, _In_ SIZE_T Words)
{
    while (Words--)
    {
        *Buf = CpuToLe32(*Buf);
        ++Buf;
    }
}

static inline VOID
Le32ToCpuArray(_Inout_updates_(Words) UINT32 *Buf, _In_ SIZE_T Words)
{
    while (Words--)
    {
        *Buf = Le32ToCpup(Buf);
        ++Buf;
    }
}

static VOID
XorCpy(
    _Out_writes_bytes_all_(Len) UINT8 *Dst,
    _In_reads_bytes_(Len) CONST UINT8 *Src1,
    _In_reads_bytes_(Len) CONST UINT8 *Src2,
    _In_ SIZE_T Len)
{
    SIZE_T i;

    for (i = 0; i < Len; ++i)
        Dst[i] = Src1[i] ^ Src2[i];
}

#define QUARTER_ROUND(X, A, B, C, D) \
    (X[A] += X[B], \
     X[D] = Rol32((X[D] ^ X[A]), 16), \
     X[C] += X[D], \
     X[B] = Rol32((X[B] ^ X[C]), 12), \
     X[A] += X[B], \
     X[D] = Rol32((X[D] ^ X[A]), 8), \
     X[C] += X[D], \
     X[B] = Rol32((X[B] ^ X[C]), 7))

#define C(i, j) (i * 4 + j)

#define DOUBLE_ROUND(X) \
    (/* Column Round */ \
     QUARTER_ROUND(X, C(0, 0), C(1, 0), C(2, 0), C(3, 0)), \
     QUARTER_ROUND(X, C(0, 1), C(1, 1), C(2, 1), C(3, 1)), \
     QUARTER_ROUND(X, C(0, 2), C(1, 2), C(2, 2), C(3, 2)), \
     QUARTER_ROUND(X, C(0, 3), C(1, 3), C(2, 3), C(3, 3)), /* Diagonal Round */ \
     QUARTER_ROUND(X, C(0, 0), C(1, 1), C(2, 2), C(3, 3)), \
     QUARTER_ROUND(X, C(0, 1), C(1, 2), C(2, 3), C(3, 0)), \
     QUARTER_ROUND(X, C(0, 2), C(1, 3), C(2, 0), C(3, 1)), \
     QUARTER_ROUND(X, C(0, 3), C(1, 0), C(2, 1), C(3, 2)))

#define TWENTY_ROUNDS(X) \
    (DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X), \
     DOUBLE_ROUND(X))

enum CHACHA20_LENGTHS
{
    CHACHA20_NONCE_SIZE = 16,
    CHACHA20_KEY_SIZE = 32,
    CHACHA20_KEY_WORDS = CHACHA20_KEY_SIZE / sizeof(UINT32),
    CHACHA20_BLOCK_SIZE = 64,
    CHACHA20_BLOCK_WORDS = CHACHA20_BLOCK_SIZE / sizeof(UINT32),
    HCHACHA20_NONCE_SIZE = CHACHA20_NONCE_SIZE,
    HCHACHA20_KEY_SIZE = CHACHA20_KEY_SIZE
};

enum CHACHA20_CONSTANTS
{
    /* expand 32-byte k */
    CHACHA20_CONSTANT_EXPA = 0x61707865U,
    CHACHA20_CONSTANT_ND_3 = 0x3320646eU,
    CHACHA20_CONSTANT_2_BY = 0x79622d32U,
    CHACHA20_CONSTANT_TE_K = 0x6b206574U
};

typedef struct _CHACHA20_CTX
{
    union
    {
        UINT32 State[16];
        struct
        {
            UINT32 Constant[4];
            UINT32 Key[8];
            UINT32 Counter[4];
        };
    };
} CHACHA20_CTX;

static VOID
ChaCha20Init(_Out_ CHACHA20_CTX *Ctx, _In_ CONST UINT8 Key[CHACHA20_KEY_SIZE], _In_ CONST UINT64 Nonce)
{
    Ctx->Constant[0] = CHACHA20_CONSTANT_EXPA;
    Ctx->Constant[1] = CHACHA20_CONSTANT_ND_3;
    Ctx->Constant[2] = CHACHA20_CONSTANT_2_BY;
    Ctx->Constant[3] = CHACHA20_CONSTANT_TE_K;
    Ctx->Key[0] = GetUnalignedLe32(Key + 0);
    Ctx->Key[1] = GetUnalignedLe32(Key + 4);
    Ctx->Key[2] = GetUnalignedLe32(Key + 8);
    Ctx->Key[3] = GetUnalignedLe32(Key + 12);
    Ctx->Key[4] = GetUnalignedLe32(Key + 16);
    Ctx->Key[5] = GetUnalignedLe32(Key + 20);
    Ctx->Key[6] = GetUnalignedLe32(Key + 24);
    Ctx->Key[7] = GetUnalignedLe32(Key + 28);
    Ctx->Counter[0] = 0;
    Ctx->Counter[1] = 0;
    Ctx->Counter[2] = Nonce & 0xffffffffU;
    Ctx->Counter[3] = Nonce >> 32;
}

#if defined(_M_AMD64)
VOID
ChaCha20ALU(
    _Out_writes_bytes_all_(Len) UINT8 *Dst,
    _In_reads_bytes_(Len) CONST UINT8 *Src,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 Key[8],
    _In_ CONST UINT32 Counter[4]);
VOID
ChaCha20SSSE3(
    _Out_writes_bytes_all_(Len) UINT8 *Dst,
    _In_reads_bytes_(Len) CONST UINT8 *Src,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 Key[8],
    _In_ CONST UINT32 Counter[4]);
VOID
ChaCha20AVX2(
    _Out_writes_bytes_all_(Len) UINT8 *Dst,
    _In_reads_bytes_(Len) CONST UINT8 *Src,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 Key[8],
    _In_ CONST UINT32 Counter[4]);
VOID
ChaCha20AVX512(
    _Out_writes_bytes_all_(Len) UINT8 *Dst,
    _In_reads_bytes_(Len) CONST UINT8 *Src,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 Key[8],
    _In_ CONST UINT32 Counter[4]);
VOID
ChaCha20AVX512VL(
    _Out_writes_bytes_all_(Len) UINT8 *Dst,
    _In_reads_bytes_(Len) CONST UINT8 *Src,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 Key[8],
    _In_ CONST UINT32 Counter[4]);

static VOID
ChaCha20(
    _Inout_ CHACHA20_CTX *Ctx,
    _Out_writes_bytes_all_(Len) UINT8 *Out,
    _In_reads_bytes_(Len) CONST UINT8 *In,
    _In_ UINT32 Len,
    _In_opt_ CONST SIMD_STATE *Simd)
{
    if (!Len)
        return;
    if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX512F))
        ChaCha20AVX512(Out, In, Len, Ctx->Key, Ctx->Counter);
    else if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX512VL))
        ChaCha20AVX512VL(Out, In, Len, Ctx->Key, Ctx->Counter);
    else if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX2))
        ChaCha20AVX2(Out, In, Len, Ctx->Key, Ctx->Counter);
    else if ((Simd && (Simd->CpuFeatures & CPU_FEATURE_SSSE3)) || (!Simd && (CpuFeatures & CPU_FEATURE_SSSE3)))
        ChaCha20SSSE3(Out, In, Len, Ctx->Key, Ctx->Counter);
    else
        ChaCha20ALU(Out, In, Len, Ctx->Key, Ctx->Counter);
    Ctx->Counter[0] += (Len + 63) / 64;
}

static VOID
ChaCha20Block(
    _Inout_ CHACHA20_CTX *Ctx,
    _Out_writes_all_(CHACHA20_BLOCK_WORDS) UINT32 Stream[CHACHA20_BLOCK_WORDS],
    _In_opt_ CONST SIMD_STATE *Simd)
{
    static CONST UINT32 ZeroInput[CHACHA20_BLOCK_WORDS] = { 0 };
    ChaCha20(Ctx, (UINT8 *)Stream, (CONST UINT8 *)ZeroInput, sizeof(ZeroInput), Simd);
}
#else
static VOID
ChaCha20Block(
    _Inout_ CHACHA20_CTX *Ctx,
    _Out_writes_all_(CHACHA20_BLOCK_WORDS) UINT32 Stream[CHACHA20_BLOCK_WORDS],
    _In_opt_ CONST SIMD_STATE *Simd)
{
    UINT32 X[CHACHA20_BLOCK_WORDS];
    LONG i;

    for (i = 0; i < ARRAYSIZE(X); ++i)
        X[i] = Ctx->State[i];

    TWENTY_ROUNDS(X);

    for (i = 0; i < ARRAYSIZE(X); ++i)
        Stream[i] = CpuToLe32(X[i] + Ctx->State[i]);

    Ctx->Counter[0] += 1;
}

static VOID
ChaCha20(
    _Inout_ CHACHA20_CTX *Ctx,
    _Out_writes_bytes_all_(Len) UINT8 *Out,
    _In_reads_bytes_(Len) CONST UINT8 *In,
    _In_ UINT32 Len,
    _In_opt_ CONST SIMD_STATE *Simd)
{
    UINT32 Buf[CHACHA20_BLOCK_WORDS];

    while (Len >= CHACHA20_BLOCK_SIZE)
    {
        ChaCha20Block(Ctx, Buf, Simd);
        XorCpy(Out, In, (UINT8 *)Buf, CHACHA20_BLOCK_SIZE);
        Len -= CHACHA20_BLOCK_SIZE;
        Out += CHACHA20_BLOCK_SIZE;
        In += CHACHA20_BLOCK_SIZE;
    }
    if (Len)
    {
        ChaCha20Block(Ctx, Buf, Simd);
        XorCpy(Out, In, (UINT8 *)Buf, Len);
    }
}
#endif

static VOID
HChaCha20(
    _Out_writes_all_(CHACHA20_KEY_WORDS) UINT32 DerivedKey[CHACHA20_KEY_WORDS],
    _In_ CONST UINT8 Nonce[HCHACHA20_NONCE_SIZE],
    _In_ CONST UINT8 Key[HCHACHA20_KEY_SIZE])
{
    UINT32 X[] = { CHACHA20_CONSTANT_EXPA,      CHACHA20_CONSTANT_ND_3,      CHACHA20_CONSTANT_2_BY,
                   CHACHA20_CONSTANT_TE_K,      GetUnalignedLe32(Key + 0),   GetUnalignedLe32(Key + 4),
                   GetUnalignedLe32(Key + 8),   GetUnalignedLe32(Key + 12),  GetUnalignedLe32(Key + 16),
                   GetUnalignedLe32(Key + 20),  GetUnalignedLe32(Key + 24),  GetUnalignedLe32(Key + 28),
                   GetUnalignedLe32(Nonce + 0), GetUnalignedLe32(Nonce + 4), GetUnalignedLe32(Nonce + 8),
                   GetUnalignedLe32(Nonce + 12) };

    TWENTY_ROUNDS(X);

    RtlCopyMemory(DerivedKey + 0, X + 0, sizeof(UINT32) * 4);
    RtlCopyMemory(DerivedKey + 4, X + 12, sizeof(UINT32) * 4);
}

enum POLY1305_LENGTHS
{
    POLY1305_BLOCK_SIZE = 16,
    POLY1305_KEY_SIZE = 32,
    POLY1305_MAC_SIZE = 16
};

#if defined(_M_AMD64)
typedef union _POLY1305_INTERNAL
{
    struct
    {
        UINT64 H[3];
        UINT64 R[2];
    } Base264;
    struct
    {
        UINT32 H[5];
        UINT32 IsBase226;
        UINT64 R[2];
        UINT64 Pad;
        struct
        {
            UINT32 R2, R1, R4, R3;
        } RP[9];
    } Base226;
    struct
    {
        UINT64 H[3];
        UINT64 S[2];
        UINT64 R[3];
        struct
        {
            UINT32 R1, R3, R2, R4;
        } RP[4];
    } Base244;
} POLY1305_INTERNAL;

VOID
Poly1305InitALU(_Out_ POLY1305_INTERNAL *Ctx, _In_ CONST UINT8 Key[POLY1305_BLOCK_SIZE]);
VOID
Poly1305InitAVX512IFMA(_Out_ POLY1305_INTERNAL *Ctx, _In_ CONST UINT8 Key[POLY1305_BLOCK_SIZE]);
VOID
Poly1305BlocksALU(
    _Inout_ POLY1305_INTERNAL *Ctx,
    _In_reads_bytes_(Len) CONST UINT8 *In,
    _In_ CONST SIZE_T Len,
    _In_ CONST UINT32 PadBit);
VOID
Poly1305BlocksAVX(
    _Inout_ POLY1305_INTERNAL *Ctx,
    _In_reads_bytes_(Len) CONST UINT8 *In,
    _In_ CONST SIZE_T Len,
    _In_ CONST UINT32 PadBit);
VOID
Poly1305BlocksAVX2(
    _Inout_ POLY1305_INTERNAL *Ctx,
    _In_reads_bytes_(Len) CONST UINT8 *In,
    _In_ CONST SIZE_T Len,
    _In_ CONST UINT32 PadBit);
VOID
Poly1305BlocksAVX512IFMA(
    _Inout_ POLY1305_INTERNAL *Ctx,
    _In_reads_bytes_(Len) CONST UINT8 *In,
    _In_ CONST SIZE_T Len,
    _In_ CONST UINT32 PadBit);
VOID
Poly1305EmitALU(
    _In_ CONST POLY1305_INTERNAL *Ctx,
    _Out_writes_bytes_all_(POLY1305_MAC_SIZE) UINT8 Mac[POLY1305_MAC_SIZE],
    _In_ CONST UINT32 Nonce[4]);
VOID
Poly1305EmitAVX512IFMA(
    _In_ CONST POLY1305_INTERNAL *Ctx,
    _Out_writes_bytes_all_(POLY1305_MAC_SIZE) UINT8 Mac[POLY1305_MAC_SIZE],
    _In_ CONST UINT32 Nonce[4]);

static VOID
Poly1305InitCore(_Out_ POLY1305_INTERNAL *St, _In_ CONST UINT8 Key[16], _In_opt_ CONST SIMD_STATE *Simd)
{
    if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX512IFMA))
        Poly1305InitAVX512IFMA(St, Key);
    else
        Poly1305InitALU(St, Key);
}

static VOID
Poly1305BlocksCore(
    _Inout_ POLY1305_INTERNAL *St,
    _In_reads_bytes_(Len) CONST UINT8 *Input,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 PadBit,
    _In_opt_ CONST SIMD_STATE *Simd)
{
    if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX512IFMA))
        Poly1305BlocksAVX512IFMA(St, Input, Len, PadBit);
    else if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX2))
        Poly1305BlocksAVX2(St, Input, Len, PadBit);
    else if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX))
        Poly1305BlocksAVX(St, Input, Len, PadBit);
    else
        Poly1305BlocksALU(St, Input, Len, PadBit);
}

static VOID
Poly1305EmitCore(
    _In_ CONST POLY1305_INTERNAL *St,
    _Out_writes_bytes_all_(16) UINT8 Mac[16],
    _In_ CONST UINT32 Nonce[4],
    _In_opt_ CONST SIMD_STATE *Simd)
{
    if (Simd && (Simd->CpuFeatures & CPU_FEATURE_AVX512IFMA))
        Poly1305EmitAVX512IFMA(St, Mac, Nonce);
    else
        Poly1305EmitALU(St, Mac, Nonce);
}
#else
typedef struct _POLY1305_INTERNAL
{
    UINT32 H[5];
    UINT32 R[5];
    UINT32 S[4];
} POLY1305_INTERNAL;

static VOID
Poly1305InitCore(_Out_ POLY1305_INTERNAL *St, _In_ CONST UINT8 Key[16], _In_opt_ CONST SIMD_STATE *Simd)
{
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    St->R[0] = (GetUnalignedLe32(&Key[0])) & 0x3ffffff;
    St->R[1] = (GetUnalignedLe32(&Key[3]) >> 2) & 0x3ffff03;
    St->R[2] = (GetUnalignedLe32(&Key[6]) >> 4) & 0x3ffc0ff;
    St->R[3] = (GetUnalignedLe32(&Key[9]) >> 6) & 0x3f03fff;
    St->R[4] = (GetUnalignedLe32(&Key[12]) >> 8) & 0x00fffff;

    /* s = 5*r */
    St->S[0] = St->R[1] * 5;
    St->S[1] = St->R[2] * 5;
    St->S[2] = St->R[3] * 5;
    St->S[3] = St->R[4] * 5;

    /* h = 0 */
    St->H[0] = 0;
    St->H[1] = 0;
    St->H[2] = 0;
    St->H[3] = 0;
    St->H[4] = 0;
}

static VOID
Poly1305BlocksCore(
    _Inout_ POLY1305_INTERNAL *St,
    _In_reads_bytes_(Len) CONST UINT8 *Input,
    _In_ SIZE_T Len,
    _In_ CONST UINT32 PadBit,
    _In_opt_ CONST SIMD_STATE *Simd)
{
    CONST UINT32 Hibit = PadBit << 24;
    UINT32 R0, R1, R2, R3, R4;
    UINT32 S1, S2, S3, S4;
    UINT32 H0, H1, H2, H3, H4;
    UINT64 D0, D1, D2, D3, D4;
    UINT32 C;

    R0 = St->R[0];
    R1 = St->R[1];
    R2 = St->R[2];
    R3 = St->R[3];
    R4 = St->R[4];

    S1 = St->S[0];
    S2 = St->S[1];
    S3 = St->S[2];
    S4 = St->S[3];

    H0 = St->H[0];
    H1 = St->H[1];
    H2 = St->H[2];
    H3 = St->H[3];
    H4 = St->H[4];

    while (Len >= POLY1305_BLOCK_SIZE)
    {
        /* h += m[i] */
        H0 += (GetUnalignedLe32(&Input[0])) & 0x3ffffff;
        H1 += (GetUnalignedLe32(&Input[3]) >> 2) & 0x3ffffff;
        H2 += (GetUnalignedLe32(&Input[6]) >> 4) & 0x3ffffff;
        H3 += (GetUnalignedLe32(&Input[9]) >> 6) & 0x3ffffff;
        H4 += (GetUnalignedLe32(&Input[12]) >> 8) | Hibit;

        /* h *= r */
        D0 = ((UINT64)H0 * R0) + ((UINT64)H1 * S4) + ((UINT64)H2 * S3) + ((UINT64)H3 * S2) + ((UINT64)H4 * S1);
        D1 = ((UINT64)H0 * R1) + ((UINT64)H1 * R0) + ((UINT64)H2 * S4) + ((UINT64)H3 * S3) + ((UINT64)H4 * S2);
        D2 = ((UINT64)H0 * R2) + ((UINT64)H1 * R1) + ((UINT64)H2 * R0) + ((UINT64)H3 * S4) + ((UINT64)H4 * S3);
        D3 = ((UINT64)H0 * R3) + ((UINT64)H1 * R2) + ((UINT64)H2 * R1) + ((UINT64)H3 * R0) + ((UINT64)H4 * S4);
        D4 = ((UINT64)H0 * R4) + ((UINT64)H1 * R3) + ((UINT64)H2 * R2) + ((UINT64)H3 * R1) + ((UINT64)H4 * R0);

        /* (partial) h %= p */
        C = (UINT32)(D0 >> 26);
        H0 = (UINT32)D0 & 0x3ffffff;
        D1 += C;
        C = (UINT32)(D1 >> 26);
        H1 = (UINT32)D1 & 0x3ffffff;
        D2 += C;
        C = (UINT32)(D2 >> 26);
        H2 = (UINT32)D2 & 0x3ffffff;
        D3 += C;
        C = (UINT32)(D3 >> 26);
        H3 = (UINT32)D3 & 0x3ffffff;
        D4 += C;
        C = (UINT32)(D4 >> 26);
        H4 = (UINT32)D4 & 0x3ffffff;
        H0 += C * 5;
        C = (H0 >> 26);
        H0 = H0 & 0x3ffffff;
        H1 += C;

        Input += POLY1305_BLOCK_SIZE;
        Len -= POLY1305_BLOCK_SIZE;
    }

    St->H[0] = H0;
    St->H[1] = H1;
    St->H[2] = H2;
    St->H[3] = H3;
    St->H[4] = H4;
}

static VOID
Poly1305EmitCore(
    _In_ CONST POLY1305_INTERNAL *St,
    _Out_writes_bytes_all_(16) UINT8 Mac[16],
    _In_ CONST UINT32 Nonce[4],
    _In_opt_ CONST SIMD_STATE *Simd)
{
    UINT32 H0, H1, H2, H3, H4, C;
    UINT32 G0, G1, G2, G3, G4;
    UINT64 F;
    UINT32 Mask;

    /* fully carry h */
    H0 = St->H[0];
    H1 = St->H[1];
    H2 = St->H[2];
    H3 = St->H[3];
    H4 = St->H[4];

    C = H1 >> 26;
    H1 = H1 & 0x3ffffff;
    H2 += C;
    C = H2 >> 26;
    H2 = H2 & 0x3ffffff;
    H3 += C;
    C = H3 >> 26;
    H3 = H3 & 0x3ffffff;
    H4 += C;
    C = H4 >> 26;
    H4 = H4 & 0x3ffffff;
    H0 += C * 5;
    C = H0 >> 26;
    H0 = H0 & 0x3ffffff;
    H1 += C;

    /* compute h + -p */
    G0 = H0 + 5;
    C = G0 >> 26;
    G0 &= 0x3ffffff;
    G1 = H1 + C;
    C = G1 >> 26;
    G1 &= 0x3ffffff;
    G2 = H2 + C;
    C = G2 >> 26;
    G2 &= 0x3ffffff;
    G3 = H3 + C;
    C = G3 >> 26;
    G3 &= 0x3ffffff;
    G4 = H4 + C - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    Mask = (G4 >> ((sizeof(UINT32) * 8) - 1)) - 1;
    G0 &= Mask;
    G1 &= Mask;
    G2 &= Mask;
    G3 &= Mask;
    G4 &= Mask;
    Mask = ~Mask;

    H0 = (H0 & Mask) | G0;
    H1 = (H1 & Mask) | G1;
    H2 = (H2 & Mask) | G2;
    H3 = (H3 & Mask) | G3;
    H4 = (H4 & Mask) | G4;

    /* h = h % (2^128) */
    H0 = ((H0) | (H1 << 26)) & 0xffffffff;
    H1 = ((H1 >> 6) | (H2 << 20)) & 0xffffffff;
    H2 = ((H2 >> 12) | (H3 << 14)) & 0xffffffff;
    H3 = ((H3 >> 18) | (H4 << 8)) & 0xffffffff;

    /* mac = (h + nonce) % (2^128) */
    F = (UINT64)H0 + Nonce[0];
    H0 = (UINT32)F;
    F = (UINT64)H1 + Nonce[1] + (F >> 32);
    H1 = (UINT32)F;
    F = (UINT64)H2 + Nonce[2] + (F >> 32);
    H2 = (UINT32)F;
    F = (UINT64)H3 + Nonce[3] + (F >> 32);
    H3 = (UINT32)F;

    PutUnalignedLe32(H0, &Mac[0]);
    PutUnalignedLe32(H1, &Mac[4]);
    PutUnalignedLe32(H2, &Mac[8]);
    PutUnalignedLe32(H3, &Mac[12]);
}
#endif

typedef struct _POLY1305_CTX
{
    POLY1305_INTERNAL State;
    UINT32 Nonce[4];
    UINT8 Data[POLY1305_BLOCK_SIZE];
    SIZE_T Num;
    CONST SIMD_STATE *Simd;
} POLY1305_CTX;

static VOID
Poly1305Init(_Out_ POLY1305_CTX *Ctx, _In_ CONST UINT8 Key[POLY1305_KEY_SIZE], _In_opt_ CONST SIMD_STATE *Simd)
{
    Ctx->Nonce[0] = GetUnalignedLe32(&Key[16]);
    Ctx->Nonce[1] = GetUnalignedLe32(&Key[20]);
    Ctx->Nonce[2] = GetUnalignedLe32(&Key[24]);
    Ctx->Nonce[3] = GetUnalignedLe32(&Key[28]);
    Ctx->Simd = Simd;

    Poly1305InitCore(&Ctx->State, Key, Ctx->Simd);

    Ctx->Num = 0;
}

static VOID
Poly1305Update(_Inout_ POLY1305_CTX *Ctx, _In_reads_bytes_(Len) CONST UINT8 *Input, _In_ SIZE_T Len)
{
    CONST SIZE_T Num = Ctx->Num;
    SIZE_T Rem;

    if (Num)
    {
        Rem = POLY1305_BLOCK_SIZE - Num;
        if (Len < Rem)
        {
            RtlCopyMemory(Ctx->Data + Num, Input, Len);
            Ctx->Num = Num + Len;
            return;
        }
        RtlCopyMemory(Ctx->Data + Num, Input, Rem);
        Poly1305BlocksCore(&Ctx->State, Ctx->Data, POLY1305_BLOCK_SIZE, 1, Ctx->Simd);
        Input += Rem;
        Len -= Rem;
    }

    Rem = Len % POLY1305_BLOCK_SIZE;
    Len -= Rem;

    if (Len >= POLY1305_BLOCK_SIZE)
    {
        Poly1305BlocksCore(&Ctx->State, Input, Len, 1, Ctx->Simd);
        Input += Len;
    }

    if (Rem)
        RtlCopyMemory(Ctx->Data, Input, Rem);

    Ctx->Num = Rem;
}

static VOID
Poly1305Final(_Inout_ POLY1305_CTX *Ctx, _Out_writes_bytes_all_(16) UINT8 Mac[POLY1305_MAC_SIZE])
{
    SIZE_T Num = Ctx->Num;

    if (Num)
    {
        Ctx->Data[Num++] = 1;
        while (Num < POLY1305_BLOCK_SIZE)
            Ctx->Data[Num++] = 0;
        Poly1305BlocksCore(&Ctx->State, Ctx->Data, POLY1305_BLOCK_SIZE, 0, Ctx->Simd);
    }

    Poly1305EmitCore(&Ctx->State, Mac, Ctx->Nonce, Ctx->Simd);

    RtlSecureZeroMemory(Ctx, sizeof(*Ctx));
}

static CONST UINT8 Pad0[16] = { 0 };

_Use_decl_annotations_
VOID
ChaCha20Poly1305Encrypt(
    UINT8 *Dst,
    CONST UINT8 *Src,
    CONST SIZE_T SrcLen,
    CONST UINT8 *Ad,
    CONST SIZE_T AdLen,
    CONST UINT64 Nonce,
    CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE])
{
    POLY1305_CTX Poly1305State;
    CHACHA20_CTX ChaCha20State;
    union
    {
        UINT8 Block0[POLY1305_KEY_SIZE];
        UINT64 Lens[2];
    } B = { { 0 } };

    ChaCha20Init(&ChaCha20State, Key, Nonce);
    ChaCha20(&ChaCha20State, B.Block0, B.Block0, sizeof(B.Block0), NULL);
    Poly1305Init(&Poly1305State, B.Block0, NULL);

    Poly1305Update(&Poly1305State, Ad, AdLen);
    Poly1305Update(&Poly1305State, Pad0, (0x10 - AdLen) & 0xf);

    ChaCha20(&ChaCha20State, Dst, Src, SrcLen, NULL);

    Poly1305Update(&Poly1305State, Dst, SrcLen);
    Poly1305Update(&Poly1305State, Pad0, (0x10 - SrcLen) & 0xf);

    B.Lens[0] = CpuToLe64(AdLen);
    B.Lens[1] = CpuToLe64(SrcLen);
    Poly1305Update(&Poly1305State, (UINT8 *)B.Lens, sizeof(B.Lens));

    Poly1305Final(&Poly1305State, Dst + SrcLen);

    RtlSecureZeroMemory(&ChaCha20State, sizeof(ChaCha20State));
    RtlSecureZeroMemory(&B, sizeof(B));
}

_Use_decl_annotations_
BOOLEAN
ChaCha20Poly1305Decrypt(
    UINT8 *Dst,
    CONST UINT8 *Src,
    CONST SIZE_T SrcLen,
    CONST UINT8 *Ad,
    CONST SIZE_T AdLen,
    CONST UINT64 Nonce,
    CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE])
{
    POLY1305_CTX Poly1305State;
    CHACHA20_CTX ChaCha20State;
    BOOLEAN Ret;
    SIZE_T DstLen;
    union
    {
        UINT8 Block0[POLY1305_KEY_SIZE];
        UINT8 Mac[POLY1305_MAC_SIZE];
        UINT64 Lens[2];
    } B = { { 0 } };

    if (SrcLen < POLY1305_MAC_SIZE)
        return FALSE;

    ChaCha20Init(&ChaCha20State, Key, Nonce);
    ChaCha20(&ChaCha20State, B.Block0, B.Block0, sizeof(B.Block0), NULL);
    Poly1305Init(&Poly1305State, B.Block0, NULL);

    Poly1305Update(&Poly1305State, Ad, AdLen);
    Poly1305Update(&Poly1305State, Pad0, (0x10 - AdLen) & 0xf);

    DstLen = SrcLen - POLY1305_MAC_SIZE;
    Poly1305Update(&Poly1305State, Src, DstLen);
    Poly1305Update(&Poly1305State, Pad0, (0x10 - DstLen) & 0xf);

    B.Lens[0] = CpuToLe64(AdLen);
    B.Lens[1] = CpuToLe64(DstLen);
    Poly1305Update(&Poly1305State, (UINT8 *)B.Lens, sizeof(B.Lens));

    Poly1305Final(&Poly1305State, B.Mac);

    Ret = CryptoEqualMemory16(B.Mac, Src + DstLen);
    if (Ret)
        ChaCha20(&ChaCha20State, Dst, Src, DstLen, NULL);

    RtlSecureZeroMemory(&ChaCha20State, sizeof(ChaCha20State));
    RtlSecureZeroMemory(&B, sizeof(B));

    return Ret;
}

_Use_decl_annotations_
BOOLEAN
ChaCha20Poly1305DecryptMdl(
    UINT8 *Dst,
    MDL *Src,
    CONST ULONG SrcLen,
    CONST ULONG SrcOffset,
    CONST UINT8 *Ad,
    CONST SIZE_T AdLen,
    CONST UINT64 Nonce,
    CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE],
    CONST SIMD_STATE *Simd)
{
    POLY1305_CTX Poly1305State;
    CHACHA20_CTX ChaCha20State;
    UINT8 *SrcBuf;
    ULONG Len, LenMdl, OffsetMdl = SrcOffset, Leftover = 0, Total = SrcLen - POLY1305_MAC_SIZE, Remaining = Total;
    MDL *Mdl = Src;
    BOOLEAN Ret = FALSE;
    union
    {
        UINT32 Stream[CHACHA20_BLOCK_WORDS];
        UINT8 Block0[POLY1305_KEY_SIZE];
        UINT8 Mac[POLY1305_MAC_SIZE * 2];
        UINT64 Lens[2];
    } B = { { 0 } };

    if (SrcLen < POLY1305_MAC_SIZE)
        return FALSE;

    ChaCha20Init(&ChaCha20State, Key, Nonce);
    ChaCha20(&ChaCha20State, B.Block0, B.Block0, sizeof(B.Block0), Simd);
    Poly1305Init(&Poly1305State, B.Block0, Simd);

    if (AdLen)
    {
        Poly1305Update(&Poly1305State, Ad, AdLen);
        if (AdLen & 0xf)
            Poly1305Update(&Poly1305State, Pad0, 0x10 - (AdLen & 0xf));
    }

    while (OffsetMdl >= MmGetMdlByteCount(Mdl))
    {
        OffsetMdl -= MmGetMdlByteCount(Mdl);
        Mdl = Mdl->Next;
    }
    for (;;)
    {
        if (!Mdl)
            goto out;
        Len = LenMdl = min(MmGetMdlByteCount(Mdl) - OffsetMdl, Remaining);
        SrcBuf = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
        if (!SrcBuf)
            goto out;
        SrcBuf += OffsetMdl;

        /* Potential TOCTOU? We read the bytes from SrcBuf for Poly1305 here, and later below
         * we decrypt those bytes with ChaCha20. If a user on the same physical machine can
         * access these pages, I fear it might be possible sneak in a buffer that isn't
         * actually authenticated.
         */
        Poly1305Update(&Poly1305State, SrcBuf, LenMdl);

        if (Leftover != 0)
        {
            ULONG l = min(Len, Leftover);
            XorCpy(Dst, SrcBuf, ((UINT8 *)B.Stream) + (CHACHA20_BLOCK_SIZE - Leftover), l);
            Leftover -= l;
            SrcBuf += l;
            Dst += l;
            Len -= l;
        }

        if (Len >= CHACHA20_BLOCK_SIZE)
        {
            ULONG l = ALIGN_DOWN_BY_T(ULONG, Len, CHACHA20_BLOCK_SIZE);
            ChaCha20(&ChaCha20State, Dst, SrcBuf, l, Simd);
            SrcBuf += l;
            Dst += l;
            Len -= l;
        }

        if (Len)
        {
            ChaCha20Block(&ChaCha20State, B.Stream, Simd);
            XorCpy(Dst, SrcBuf, (UINT8 *)B.Stream, Len);
            Leftover = CHACHA20_BLOCK_SIZE - Len;
            Dst += Len;
        }

        Remaining -= LenMdl;
        if (!Remaining)
        {
            OffsetMdl += LenMdl;
            break;
        }
        Mdl = Mdl->Next;
        OffsetMdl = 0;
    }
    Poly1305Update(&Poly1305State, Pad0, (0x10 - Total) & 0xf);
    B.Lens[0] = CpuToLe64(AdLen);
    B.Lens[1] = CpuToLe64(Total);
    Poly1305Update(&Poly1305State, (UINT8 *)B.Lens, sizeof(B.Lens));
    Poly1305Final(&Poly1305State, B.Mac);
    if (!NT_SUCCESS(MemCopyFromMdl(B.Mac + POLY1305_MAC_SIZE, Mdl, OffsetMdl, POLY1305_MAC_SIZE)))
        goto out;
    Ret = CryptoEqualMemory16(B.Mac, B.Mac + POLY1305_MAC_SIZE);
out:
    RtlSecureZeroMemory(&ChaCha20State, sizeof(ChaCha20State));
    RtlSecureZeroMemory(&B, sizeof(B));
    return Ret;
}

_Use_decl_annotations_
BOOLEAN
ChaCha20Poly1305EncryptMdl(
    UINT8 *Dst,
    MDL *Src,
    CONST ULONG SrcLen,
    CONST ULONG SrcOffset,
    CONST UINT8 *Ad,
    CONST SIZE_T AdLen,
    CONST UINT64 Nonce,
    CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE],
    CONST SIMD_STATE *Simd)
{
    POLY1305_CTX Poly1305State;
    CHACHA20_CTX ChaCha20State;
    UINT8 *SrcBuf;
    MDL *Mdl = Src;
    ULONG Len, LenMdl, OffsetMdl = SrcOffset, Leftover = 0;
    union
    {
        UINT32 Stream[CHACHA20_BLOCK_WORDS];
        UINT8 Block0[POLY1305_KEY_SIZE];
        UINT64 Lens[2];
    } B = { { 0 } };

    ChaCha20Init(&ChaCha20State, Key, Nonce);
    ChaCha20(&ChaCha20State, B.Block0, B.Block0, sizeof(B.Block0), Simd);
    Poly1305Init(&Poly1305State, B.Block0, Simd);

    if (AdLen)
    {
        Poly1305Update(&Poly1305State, Ad, AdLen);
        if (AdLen & 0xf)
            Poly1305Update(&Poly1305State, Pad0, 0x10 - (AdLen & 0xf));
    }

    while (OffsetMdl >= MmGetMdlByteCount(Mdl))
    {
        OffsetMdl -= MmGetMdlByteCount(Mdl);
        Mdl = Mdl->Next;
    }
    for (ULONG Remaining = SrcLen; Remaining; Remaining -= LenMdl)
    {
        if (!Mdl)
            return FALSE;
        Len = LenMdl = min(MmGetMdlByteCount(Mdl) - OffsetMdl, Remaining);
        SrcBuf = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
        if (!SrcBuf)
            return FALSE;
        SrcBuf += OffsetMdl;

        if (Leftover != 0)
        {
            ULONG l = min(Len, Leftover);
            XorCpy(Dst, SrcBuf, ((UINT8 *)B.Stream) + (CHACHA20_BLOCK_SIZE - Leftover), l);
            Leftover -= l;
            SrcBuf += l;
            Dst += l;
            Len -= l;
        }

        if (Len >= CHACHA20_BLOCK_SIZE)
        {
            ULONG l = ALIGN_DOWN_BY_T(ULONG, Len, CHACHA20_BLOCK_SIZE);
            ChaCha20(&ChaCha20State, Dst, SrcBuf, l, Simd);
            SrcBuf += l;
            Dst += l;
            Len -= l;
        }

        if (Len)
        {
            ChaCha20Block(&ChaCha20State, B.Stream, Simd);
            XorCpy(Dst, SrcBuf, (UINT8 *)B.Stream, Len);
            Leftover = CHACHA20_BLOCK_SIZE - Len;
            Dst += Len;
        }

        _Analysis_assume_((RtlFillMemory(Dst - LenMdl, LenMdl, 'A'), TRUE));
        Poly1305Update(&Poly1305State, Dst - LenMdl, LenMdl);

        Mdl = Mdl->Next;
        OffsetMdl = 0;
    }
    Poly1305Update(&Poly1305State, Pad0, (0x10 - SrcLen) & 0xf);
    B.Lens[0] = CpuToLe64(AdLen);
    B.Lens[1] = CpuToLe64(SrcLen);
    Poly1305Update(&Poly1305State, (UINT8 *)B.Lens, sizeof(B.Lens));
    Poly1305Final(&Poly1305State, Dst);

    RtlSecureZeroMemory(&ChaCha20State, sizeof(ChaCha20State));
    RtlSecureZeroMemory(&B, sizeof(B));

    return TRUE;
}

_Use_decl_annotations_
VOID
XChaCha20Poly1305Encrypt(
    UINT8 *Dst,
    CONST UINT8 *Src,
    CONST SIZE_T SrcLen,
    CONST UINT8 *Ad,
    CONST SIZE_T AdLen,
    CONST UINT8 Nonce[XCHACHA20POLY1305_NONCE_SIZE],
    CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE])
{
    UINT32 DerivedKey[CHACHA20_KEY_WORDS];

    HChaCha20(DerivedKey, Nonce, Key);
    CpuToLe32Array(DerivedKey, ARRAYSIZE(DerivedKey));
    ChaCha20Poly1305Encrypt(Dst, Src, SrcLen, Ad, AdLen, GetUnalignedLe64(Nonce + 16), (UINT8 *)DerivedKey);
    RtlSecureZeroMemory(DerivedKey, CHACHA20POLY1305_KEY_SIZE);
}

_Use_decl_annotations_
BOOLEAN
XChaCha20Poly1305Decrypt(
    UINT8 *Dst,
    CONST UINT8 *Src,
    CONST SIZE_T SrcLen,
    CONST UINT8 *Ad,
    CONST SIZE_T AdLen,
    CONST UINT8 Nonce[XCHACHA20POLY1305_NONCE_SIZE],
    CONST UINT8 Key[CHACHA20POLY1305_KEY_SIZE])
{
    BOOLEAN Ret;
    UINT32 DerivedKey[CHACHA20_KEY_WORDS];

    HChaCha20(DerivedKey, Nonce, Key);
    CpuToLe32Array(DerivedKey, ARRAYSIZE(DerivedKey));
    Ret = ChaCha20Poly1305Decrypt(Dst, Src, SrcLen, Ad, AdLen, GetUnalignedLe64(Nonce + 16), (UINT8 *)DerivedKey);
    RtlSecureZeroMemory(DerivedKey, CHACHA20POLY1305_KEY_SIZE);
    return Ret;
}

static CONST UINT32 Blake2sIv[8] = { 0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
                                     0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL };

static CONST UINT8 Blake2sSigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 }, { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 }, { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 }, { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 }, { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

static inline VOID
Blake2sSetLastblock(_Out_ BLAKE2S_STATE *State)
{
    State->F[0] = (UINT32)-1;
}

static inline VOID
Blake2sIncrementCounter(_Inout_ BLAKE2S_STATE *State, _In_ CONST UINT32 Inc)
{
    State->T[0] += Inc;
    State->T[1] += (State->T[0] < Inc);
}

static inline VOID
Blake2sInitParam(_Out_ BLAKE2S_STATE *State, _In_ CONST UINT32 Param)
{
    LONG i;

    RtlZeroMemory(State, sizeof(*State));
    for (i = 0; i < 8; ++i)
        State->H[i] = Blake2sIv[i];
    State->H[0] ^= Param;
}

_Use_decl_annotations_
VOID
Blake2sInit(BLAKE2S_STATE *State, CONST SIZE_T OutLen)
{
    Blake2sInitParam(State, 0x01010000 | OutLen);
    State->OutLen = OutLen;
}

_Use_decl_annotations_
VOID
Blake2sInitKey(BLAKE2S_STATE *State, CONST SIZE_T OutLen, CONST UINT8 *Key, CONST SIZE_T KeyLen)
{
    UINT8 Block[BLAKE2S_BLOCK_SIZE] = { 0 };

    Blake2sInitParam(State, 0x01010000 | KeyLen << 8 | OutLen);
    State->OutLen = OutLen;
    RtlCopyMemory(Block, Key, KeyLen);
    Blake2sUpdate(State, Block, BLAKE2S_BLOCK_SIZE);
    RtlSecureZeroMemory(Block, BLAKE2S_BLOCK_SIZE);
}

static inline VOID
Blake2sCompress(
    _Inout_ BLAKE2S_STATE *State,
    _In_reads_bytes_(BLAKE2S_BLOCK_SIZE *Nblocks) CONST UINT8 *Block,
    _In_ SIZE_T Nblocks,
    _In_ CONST UINT32 Inc)
{
    UINT32 M[16];
    UINT32 V[16];
    LONG i;

    while (Nblocks > 0)
    {
        Blake2sIncrementCounter(State, Inc);
        RtlCopyMemory(M, Block, BLAKE2S_BLOCK_SIZE);
        Le32ToCpuArray(M, ARRAYSIZE(M));
        RtlCopyMemory(V, State->H, 32);
        V[8] = Blake2sIv[0];
        V[9] = Blake2sIv[1];
        V[10] = Blake2sIv[2];
        V[11] = Blake2sIv[3];
        V[12] = Blake2sIv[4] ^ State->T[0];
        V[13] = Blake2sIv[5] ^ State->T[1];
        V[14] = Blake2sIv[6] ^ State->F[0];
        V[15] = Blake2sIv[7] ^ State->F[1];

#define G(R, i, A, B, C, D) \
    do \
    { \
        A += B + M[Blake2sSigma[R][2 * i + 0]]; \
        D = Ror32(D ^ A, 16); \
        C += D; \
        B = Ror32(B ^ C, 12); \
        A += B + M[Blake2sSigma[R][2 * i + 1]]; \
        D = Ror32(D ^ A, 8); \
        C += D; \
        B = Ror32(B ^ C, 7); \
    } while (0)

#define ROUND(R) \
    do \
    { \
        G(R, 0, V[0], V[4], V[8], V[12]); \
        G(R, 1, V[1], V[5], V[9], V[13]); \
        G(R, 2, V[2], V[6], V[10], V[14]); \
        G(R, 3, V[3], V[7], V[11], V[15]); \
        G(R, 4, V[0], V[5], V[10], V[15]); \
        G(R, 5, V[1], V[6], V[11], V[12]); \
        G(R, 6, V[2], V[7], V[8], V[13]); \
        G(R, 7, V[3], V[4], V[9], V[14]); \
    } while (0)
        ROUND(0);
        ROUND(1);
        ROUND(2);
        ROUND(3);
        ROUND(4);
        ROUND(5);
        ROUND(6);
        ROUND(7);
        ROUND(8);
        ROUND(9);

#undef G
#undef ROUND

        for (i = 0; i < 8; ++i)
            State->H[i] ^= V[i] ^ V[i + 8];

        Block += BLAKE2S_BLOCK_SIZE;
        --Nblocks;
    }
}

_Use_decl_annotations_
VOID
Blake2sUpdate(BLAKE2S_STATE *State, CONST UINT8 *In, SIZE_T InLen)
{
    CONST SIZE_T Fill = BLAKE2S_BLOCK_SIZE - State->BufLen;

    if (!InLen)
        return;
    if (InLen > Fill)
    {
        RtlCopyMemory(State->Buf + State->BufLen, In, Fill);
        Blake2sCompress(State, State->Buf, 1, BLAKE2S_BLOCK_SIZE);
        State->BufLen = 0;
        In += Fill;
        InLen -= Fill;
    }
    if (InLen > BLAKE2S_BLOCK_SIZE)
    {
        CONST SIZE_T Nblocks = DIV_ROUND_UP(InLen, BLAKE2S_BLOCK_SIZE);
        /* Hash one less (full) block than strictly possible */
        Blake2sCompress(State, In, Nblocks - 1, BLAKE2S_BLOCK_SIZE);
        In += BLAKE2S_BLOCK_SIZE * (Nblocks - 1);
        InLen -= BLAKE2S_BLOCK_SIZE * (Nblocks - 1);
    }
    RtlCopyMemory(State->Buf + State->BufLen, In, InLen);
    State->BufLen += InLen;
}

_Use_decl_annotations_
VOID
Blake2sFinal(BLAKE2S_STATE *State, UINT8 *Out)
{
    Blake2sSetLastblock(State);
    RtlZeroMemory(State->Buf + State->BufLen, BLAKE2S_BLOCK_SIZE - State->BufLen); /* Padding */
    Blake2sCompress(State, State->Buf, 1, State->BufLen);
    CpuToLe32Array(State->H, ARRAYSIZE(State->H));
    RtlCopyMemory(Out, State->H, State->OutLen);
    RtlSecureZeroMemory(State, sizeof(*State));
}

_Use_decl_annotations_
VOID
Blake2s(UINT8 *Out, CONST UINT8 *In, CONST UINT8 *Key, CONST SIZE_T OutLen, CONST SIZE_T InLen, CONST SIZE_T KeyLen)
{
    BLAKE2S_STATE State;

    if (KeyLen)
        Blake2sInitKey(&State, OutLen, Key, KeyLen);
    else
        Blake2sInit(&State, OutLen);

    Blake2sUpdate(&State, In, InLen);
    Blake2sFinal(&State, Out);
}

_Use_decl_annotations_
VOID
Blake2s256Hmac(UINT8 *Out, CONST UINT8 *In, CONST UINT8 *Key, CONST SIZE_T InLen, CONST SIZE_T KeyLen)
{
    BLAKE2S_STATE State;
    __declspec(align(4)) UINT8 XKey[BLAKE2S_BLOCK_SIZE] = { 0 };
    __declspec(align(4)) UINT8 IHash[BLAKE2S_HASH_SIZE];
    LONG i;

    if (KeyLen > BLAKE2S_BLOCK_SIZE)
    {
        Blake2sInit(&State, BLAKE2S_HASH_SIZE);
        Blake2sUpdate(&State, Key, KeyLen);
        Blake2sFinal(&State, XKey);
    }
    else
        RtlCopyMemory(XKey, Key, KeyLen);

    for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
        XKey[i] ^= 0x36;

    Blake2sInit(&State, BLAKE2S_HASH_SIZE);
    Blake2sUpdate(&State, XKey, BLAKE2S_BLOCK_SIZE);
    Blake2sUpdate(&State, In, InLen);
    Blake2sFinal(&State, IHash);

    for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
        XKey[i] ^= 0x5c ^ 0x36;

    Blake2sInit(&State, BLAKE2S_HASH_SIZE);
    Blake2sUpdate(&State, XKey, BLAKE2S_BLOCK_SIZE);
    Blake2sUpdate(&State, IHash, BLAKE2S_HASH_SIZE);
    Blake2sFinal(&State, IHash);

    RtlCopyMemory(Out, IHash, BLAKE2S_HASH_SIZE);
    RtlSecureZeroMemory(XKey, BLAKE2S_BLOCK_SIZE);
    RtlSecureZeroMemory(IHash, BLAKE2S_HASH_SIZE);
}

#define SIPROUND \
    do \
    { \
        V0 += V1; \
        V1 = Rol64(V1, 13); \
        V1 ^= V0; \
        V0 = Rol64(V0, 32); \
        V2 += V3; \
        V3 = Rol64(V3, 16); \
        V3 ^= V2; \
        V0 += V3; \
        V3 = Rol64(V3, 21); \
        V3 ^= V0; \
        V2 += V1; \
        V1 = Rol64(V1, 17); \
        V1 ^= V2; \
        V2 = Rol64(V2, 32); \
    } while (0)

#define PREAMBLE(Len) \
    UINT64 V0 = 0x736f6d6570736575ULL; \
    UINT64 V1 = 0x646f72616e646f6dULL; \
    UINT64 V2 = 0x6c7967656e657261ULL; \
    UINT64 V3 = 0x7465646279746573ULL; \
    UINT64 B = ((UINT64)(Len)) << 56; \
    V3 ^= Key->Key[1]; \
    V2 ^= Key->Key[0]; \
    V1 ^= Key->Key[1]; \
    V0 ^= Key->Key[0];

#define POSTAMBLE \
    V3 ^= B; \
    SIPROUND; \
    SIPROUND; \
    V0 ^= B; \
    V2 ^= 0xff; \
    SIPROUND; \
    SIPROUND; \
    SIPROUND; \
    SIPROUND; \
    return (V0 ^ V1) ^ (V2 ^ V3);

_Use_decl_annotations_
UINT64
Siphash(CONST VOID *Data, SIZE_T Len, CONST SIPHASH_KEY *Key)
{
    CONST UINT8 *End = (CONST UINT8 *)Data + Len - (Len % sizeof(UINT64));
    CONST UINT8 Left = Len & (sizeof(UINT64) - 1);
    UINT64 M;
    PREAMBLE(Len)
    for (; Data != End; Data = (CONST UINT8 *)Data + sizeof(UINT64))
    {
        M = Le64ToCpup((CONST UINT64_LE *)Data);
        V3 ^= M;
        SIPROUND;
        SIPROUND;
        V0 ^= M;
    }
    switch (Left)
    {
    case 7:
        B |= ((UINT64)End[6]) << 48;
        /* fallthrough */;
    case 6:
        B |= ((UINT64)End[5]) << 40;
        /* fallthrough */;
    case 5:
        B |= ((UINT64)End[4]) << 32;
        /* fallthrough */;
    case 4:
        B |= Le32ToCpup((CONST UINT32_LE *)Data);
        break;
    case 3:
        B |= ((UINT64)End[2]) << 16;
        /* fallthrough */;
    case 2:
        B |= Le16ToCpup((CONST UINT16_LE *)Data);
        break;
    case 1:
        B |= End[0];
    }
    POSTAMBLE
}

_Use_decl_annotations_
UINT64
Siphash1u64(CONST UINT64 First, CONST SIPHASH_KEY *Key)
{
    PREAMBLE(8)
    V3 ^= First;
    SIPROUND;
    SIPROUND;
    V0 ^= First;
    POSTAMBLE
}

_Use_decl_annotations_
UINT64
Siphash2u64(CONST UINT64 First, CONST UINT64 Second, CONST SIPHASH_KEY *Key)
{
    PREAMBLE(16)
    V3 ^= First;
    SIPROUND;
    SIPROUND;
    V0 ^= First;
    V3 ^= Second;
    SIPROUND;
    SIPROUND;
    V0 ^= Second;
    POSTAMBLE
}

_Use_decl_annotations_
UINT64
Siphash3u64(CONST UINT64 First, CONST UINT64 Second, CONST UINT64 Third, CONST SIPHASH_KEY *Key)
{
    PREAMBLE(24)
    V3 ^= First;
    SIPROUND;
    SIPROUND;
    V0 ^= First;
    V3 ^= Second;
    SIPROUND;
    SIPROUND;
    V0 ^= Second;
    V3 ^= Third;
    SIPROUND;
    SIPROUND;
    V0 ^= Third;
    POSTAMBLE
}

_Use_decl_annotations_
UINT64
Siphash4u64(CONST UINT64 First, CONST UINT64 Second, CONST UINT64 Third, CONST UINT64 Forth, CONST SIPHASH_KEY *Key)
{
    PREAMBLE(32)
    V3 ^= First;
    SIPROUND;
    SIPROUND;
    V0 ^= First;
    V3 ^= Second;
    SIPROUND;
    SIPROUND;
    V0 ^= Second;
    V3 ^= Third;
    SIPROUND;
    SIPROUND;
    V0 ^= Third;
    V3 ^= Forth;
    SIPROUND;
    SIPROUND;
    V0 ^= Forth;
    POSTAMBLE
}

_Use_decl_annotations_
UINT64
Siphash1u32(CONST UINT32 First, CONST SIPHASH_KEY *Key)
{
    PREAMBLE(4)
    B |= First;
    POSTAMBLE
}

_Use_decl_annotations_
UINT64
Siphash3u32(CONST UINT32 First, CONST UINT32 Second, CONST UINT32 Third, CONST SIPHASH_KEY *Key)
{
    UINT64 Combined = (UINT64)Second << 32 | First;
    PREAMBLE(12)
    V3 ^= Combined;
    SIPROUND;
    SIPROUND;
    V0 ^= Combined;
    B |= Third;
    POSTAMBLE
}

#if BITS_PER_POINTER == 64
/* Note that on 64-bit, we make HalfSiphash1-3 actually be Siphash1-3, for
 * performance reasons. On 32-bit, below, we actually implement HalfSiphash1-3.
 */

#    define HSIPROUND SIPROUND
#    define HPREAMBLE(Len) PREAMBLE(Len)
#    define HPOSTAMBLE \
        V3 ^= B; \
        HSIPROUND; \
        V0 ^= B; \
        V2 ^= 0xff; \
        HSIPROUND; \
        HSIPROUND; \
        HSIPROUND; \
        return (UINT32)((V0 ^ V1) ^ (V2 ^ V3));

_Use_decl_annotations_
UINT32
Hsiphash(CONST VOID *Data, SIZE_T Len, CONST HSIPHASH_KEY *Key)
{
    CONST UINT8 *End = (CONST UINT8 *)Data + Len - (Len % sizeof(UINT64));
    CONST UINT8 Left = Len & (sizeof(UINT64) - 1);
    UINT64 M;
    HPREAMBLE(Len)
    for (; Data != End; Data = (CONST UINT8 *)Data + sizeof(UINT64))
    {
        M = Le64ToCpup((CONST UINT64_LE *)Data);
        V3 ^= M;
        HSIPROUND;
        V0 ^= M;
    }
    switch (Left)
    {
    case 7:
        B |= ((UINT64)End[6]) << 48;
        /* fallthrough */;
    case 6:
        B |= ((UINT64)End[5]) << 40;
        /* fallthrough */;
    case 5:
        B |= ((UINT64)End[4]) << 32;
        /* fallthrough */;
    case 4:
        B |= Le32ToCpup((CONST UINT32_LE *)Data);
        break;
    case 3:
        B |= ((UINT64)End[2]) << 16;
        /* fallthrough */;
    case 2:
        B |= Le16ToCpup((CONST UINT16_LE *)Data);
        break;
    case 1:
        B |= End[0];
    }
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash1u32(CONST UINT32 First, CONST HSIPHASH_KEY *Key)
{
    HPREAMBLE(4)
    B |= First;
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash2u32(CONST UINT32 First, CONST UINT32 Second, CONST HSIPHASH_KEY *Key)
{
    UINT64 Combined = (UINT64)Second << 32 | First;
    HPREAMBLE(8)
    V3 ^= Combined;
    HSIPROUND;
    V0 ^= Combined;
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash3u32(CONST UINT32 First, CONST UINT32 Second, CONST UINT32 Third, CONST HSIPHASH_KEY *Key)
{
    UINT64 Combined = (UINT64)Second << 32 | First;
    HPREAMBLE(12)
    V3 ^= Combined;
    HSIPROUND;
    V0 ^= Combined;
    B |= Third;
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash4u32(CONST UINT32 First, CONST UINT32 Second, CONST UINT32 Third, CONST UINT32 Forth, CONST HSIPHASH_KEY *Key)
{
    UINT64 Combined = (UINT64)Second << 32 | First;
    HPREAMBLE(16)
    V3 ^= Combined;
    HSIPROUND;
    V0 ^= Combined;
    Combined = (UINT64)Forth << 32 | Third;
    V3 ^= Combined;
    HSIPROUND;
    V0 ^= Combined;
    HPOSTAMBLE
}
#else
#    define HSIPROUND \
        do \
        { \
            V0 += V1; \
            V1 = Rol32(V1, 5); \
            V1 ^= V0; \
            V0 = Rol32(V0, 16); \
            V2 += V3; \
            V3 = Rol32(V3, 8); \
            V3 ^= V2; \
            V0 += V3; \
            V3 = Rol32(V3, 7); \
            V3 ^= V0; \
            V2 += V1; \
            V1 = Rol32(V1, 13); \
            V1 ^= V2; \
            V2 = Rol32(V2, 16); \
        } while (0)

#    define HPREAMBLE(Len) \
        UINT32 V0 = 0; \
        UINT32 V1 = 0; \
        UINT32 V2 = 0x6c796765U; \
        UINT32 V3 = 0x74656462U; \
        UINT32 B = ((UINT32)(Len)) << 24; \
        V3 ^= Key->Key[1]; \
        V2 ^= Key->Key[0]; \
        V1 ^= Key->Key[1]; \
        V0 ^= Key->Key[0];

#    define HPOSTAMBLE \
        V3 ^= B; \
        HSIPROUND; \
        V0 ^= B; \
        V2 ^= 0xff; \
        HSIPROUND; \
        HSIPROUND; \
        HSIPROUND; \
        return V1 ^ V3;

_Use_decl_annotations_
UINT32
Hsiphash(CONST VOID *Data, SIZE_T Len, CONST HSIPHASH_KEY *Key)
{
    CONST UINT8 *End = (CONST UINT8 *)Data + Len - (Len % sizeof(UINT32));
    CONST UINT8 Left = Len & (sizeof(UINT32) - 1);
    UINT32 M;
    HPREAMBLE(Len)
    for (; Data != End; Data = (CONST UINT8 *)Data + sizeof(UINT32))
    {
        M = Le32ToCpup((CONST UINT32_LE *)Data);
        V3 ^= M;
        HSIPROUND;
        V0 ^= M;
    }
    switch (Left)
    {
    case 3:
        B |= ((UINT32)End[2]) << 16;
        /* fallthrough */;
    case 2:
        B |= Le16ToCpup((CONST UINT16_LE *)Data);
        break;
    case 1:
        B |= End[0];
    }
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash1u32(CONST UINT32 First, CONST HSIPHASH_KEY *Key)
{
    HPREAMBLE(4)
    V3 ^= First;
    HSIPROUND;
    V0 ^= First;
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash2u32(CONST UINT32 First, CONST UINT32 Second, CONST HSIPHASH_KEY *Key)
{
    HPREAMBLE(8)
    V3 ^= First;
    HSIPROUND;
    V0 ^= First;
    V3 ^= Second;
    HSIPROUND;
    V0 ^= Second;
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash3u32(CONST UINT32 First, CONST UINT32 Second, CONST UINT32 Third, CONST HSIPHASH_KEY *Key)
{
    HPREAMBLE(12)
    V3 ^= First;
    HSIPROUND;
    V0 ^= First;
    V3 ^= Second;
    HSIPROUND;
    V0 ^= Second;
    V3 ^= Third;
    HSIPROUND;
    V0 ^= Third;
    HPOSTAMBLE
}

_Use_decl_annotations_
UINT32
Hsiphash4u32(CONST UINT32 First, CONST UINT32 Second, CONST UINT32 Third, CONST UINT32 Forth, CONST HSIPHASH_KEY *Key)
{
    HPREAMBLE(16)
    V3 ^= First;
    HSIPROUND;
    V0 ^= First;
    V3 ^= Second;
    HSIPROUND;
    V0 ^= Second;
    V3 ^= Third;
    HSIPROUND;
    V0 ^= Third;
    V3 ^= Forth;
    HSIPROUND;
    V0 ^= Forth;
    HPOSTAMBLE
}
#endif

/* Below here is fiat's implementation of x25519.
 *
 * Copyright (C) 2015-2016 The fiat-crypto Authors.
 * Copyright (C) 2018-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is a machine-generated formally verified implementation of Curve25519
 * ECDH from: <https://github.com/mit-plv/fiat-crypto>. Though originally
 * machine generated, it has been tweaked to be suitable for use in the kernel.
 * It is optimized for 32-bit machines and machines that cannot work efficiently
 * with 128-bit integer types.
 */

/* Fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9].
 * Fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
 * Multiplication and carrying produce Fe from FeLoose.
 */
typedef struct Fe
{
    UINT32 V[10];
} Fe;

/* FeLoose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc
 * Addition and subtraction produce FeLoose from (Fe, Fe).
 */
typedef struct FeLoose
{
    UINT32 V[10];
} FeLoose;

static inline VOID
FeFrombytesImpl(_Out_writes_all_(10) UINT32 H[10], _In_reads_bytes_(32) CONST UINT8 *S)
{
    /* Ignores top bit of s. */
    UINT32 A0 = GetUnalignedLe32(S);
    UINT32 A1 = GetUnalignedLe32(S + 4);
    UINT32 A2 = GetUnalignedLe32(S + 8);
    UINT32 A3 = GetUnalignedLe32(S + 12);
    UINT32 A4 = GetUnalignedLe32(S + 16);
    UINT32 A5 = GetUnalignedLe32(S + 20);
    UINT32 A6 = GetUnalignedLe32(S + 24);
    UINT32 A7 = GetUnalignedLe32(S + 28);
    H[0] = A0 & ((1 << 26) - 1);                        /* 26 used, 32-26 left.   26 */
    H[1] = (A0 >> 26) | ((A1 & ((1 << 19) - 1)) << 6);  /* (32-26) + 19 =  6+19 = 25 */
    H[2] = (A1 >> 19) | ((A2 & ((1 << 13) - 1)) << 13); /* (32-19) + 13 = 13+13 = 26 */
    H[3] = (A2 >> 13) | ((A3 & ((1 << 6) - 1)) << 19);  /* (32-13) +  6 = 19+ 6 = 25 */
    H[4] = (A3 >> 6);                                   /* (32- 6)              = 26 */
    H[5] = A4 & ((1 << 25) - 1);                        /*                        25 */
    H[6] = (A4 >> 25) | ((A5 & ((1 << 19) - 1)) << 7);  /* (32-25) + 19 =  7+19 = 26 */
    H[7] = (A5 >> 19) | ((A6 & ((1 << 12) - 1)) << 13); /* (32-19) + 12 = 13+12 = 25 */
    H[8] = (A6 >> 12) | ((A7 & ((1 << 6) - 1)) << 20);  /* (32-12) +  6 = 20+ 6 = 26 */
    H[9] = (A7 >> 6) & ((1 << 25) - 1);                 /*                        25 */
}

static inline VOID
FeFrombytes(_Out_ Fe *H, _In_reads_bytes_(32) CONST UINT8 *S)
{
    FeFrombytesImpl(H->V, S);
}

static inline UINT8 /*bool*/
AddcarryxU25(_In_ CONST UINT8 /*bool*/ C, _In_ CONST UINT32 A, _In_ CONST UINT32 B, _Out_ UINT32 *Low)
{
    /* This function extracts 25 bits of result and 1 bit of carry
     * (26 total), so a 32-bit intermediate is sufficient.
     */
    UINT32 X = A + B + C;
    *Low = X & ((1 << 25) - 1);
    return (X >> 25) & 1;
}

static inline UINT8 /*bool*/
AddcarryxU26(_In_ CONST UINT8 /*bool*/ C, _In_ CONST UINT32 A, _In_ CONST UINT32 B, _Out_ UINT32 *Low)
{
    /* This function extracts 26 bits of result and 1 bit of carry
     * (27 total), so a 32-bit intermediate is sufficient.
     */
    UINT32 X = A + B + C;
    *Low = X & ((1 << 26) - 1);
    return (X >> 26) & 1;
}

static inline UINT8 /*bool*/
SubborrowU25(_In_ CONST UINT8 /*bool*/ C, _In_ CONST UINT32 A, _In_ CONST UINT32 B, _Out_ UINT32 *Low)
{
    /* This function extracts 25 bits of result and 1 bit of borrow
     * (26 total), so a 32-bit intermediate is sufficient.
     */
    UINT32 X = A - B - C;
    *Low = X & ((1 << 25) - 1);
    return X >> 31;
}

static inline UINT8 /*bool*/
SubborrowU26(_In_ CONST UINT8 /*bool*/ C, _In_ CONST UINT32 A, _In_ CONST UINT32 B, _Out_ UINT32 *Low)
{
    /* This function extracts 26 bits of result and 1 bit of borrow
     *(27 total), so a 32-bit intermediate is sufficient.
     */
    UINT32 X = A - B - C;
    *Low = X & ((1 << 26) - 1);
    return X >> 31;
}

static inline UINT32
Cmovznz32(_In_ UINT32 T, _In_ CONST UINT32 Z, _In_ CONST UINT32 Nz)
{
    T = -!!T; /* all set if nonzero, 0 if 0 */
    return (T & Nz) | ((~T) & Z);
}

static inline VOID
FeFreeze(_Out_writes_all_(10) UINT32 Out[10], _In_reads_(10) CONST UINT32 In1[10])
{
    CONST UINT32 X17 = In1[9];
    CONST UINT32 X18 = In1[8];
    CONST UINT32 X16 = In1[7];
    CONST UINT32 X14 = In1[6];
    CONST UINT32 X12 = In1[5];
    CONST UINT32 X10 = In1[4];
    CONST UINT32 X8 = In1[3];
    CONST UINT32 X6 = In1[2];
    CONST UINT32 X4 = In1[1];
    CONST UINT32 X2 = In1[0];
    UINT32 X20;
    UINT8 /*bool*/ X21 = SubborrowU26(0x0, X2, 0x3ffffed, &X20);
    UINT32 X23;
    UINT8 /*bool*/ X24 = SubborrowU25(X21, X4, 0x1ffffff, &X23);
    UINT32 X26;
    UINT8 /*bool*/ X27 = SubborrowU26(X24, X6, 0x3ffffff, &X26);
    UINT32 X29;
    UINT8 /*bool*/ X30 = SubborrowU25(X27, X8, 0x1ffffff, &X29);
    UINT32 X32;
    UINT8 /*bool*/ X33 = SubborrowU26(X30, X10, 0x3ffffff, &X32);
    UINT32 X35;
    UINT8 /*bool*/ X36 = SubborrowU25(X33, X12, 0x1ffffff, &X35);
    UINT32 X38;
    UINT8 /*bool*/ X39 = SubborrowU26(X36, X14, 0x3ffffff, &X38);
    UINT32 X41;
    UINT8 /*bool*/ X42 = SubborrowU25(X39, X16, 0x1ffffff, &X41);
    UINT32 X44;
    UINT8 /*bool*/ X45 = SubborrowU26(X42, X18, 0x3ffffff, &X44);
    UINT32 X47;
    UINT8 /*bool*/ X48 = SubborrowU25(X45, X17, 0x1ffffff, &X47);
    UINT32 X49 = Cmovznz32(X48, 0x0, 0xffffffff);
    UINT32 X50 = (X49 & 0x3ffffed);
    UINT32 X52;
    UINT8 /*bool*/ X53 = AddcarryxU26(0x0, X20, X50, &X52);
    UINT32 X54 = (X49 & 0x1ffffff);
    UINT32 X56;
    UINT8 /*bool*/ X57 = AddcarryxU25(X53, X23, X54, &X56);
    UINT32 X58 = (X49 & 0x3ffffff);
    UINT32 X60;
    UINT8 /*bool*/ X61 = AddcarryxU26(X57, X26, X58, &X60);
    UINT32 X62 = (X49 & 0x1ffffff);
    UINT32 X64;
    UINT8 /*bool*/ X65 = AddcarryxU25(X61, X29, X62, &X64);
    UINT32 X66 = (X49 & 0x3ffffff);
    UINT32 X68;
    UINT8 /*bool*/ X69 = AddcarryxU26(X65, X32, X66, &X68);
    UINT32 X70 = (X49 & 0x1ffffff);
    UINT32 X72;
    UINT8 /*bool*/ X73 = AddcarryxU25(X69, X35, X70, &X72);
    UINT32 X74 = (X49 & 0x3ffffff);
    UINT32 X76;
    UINT8 /*bool*/ X77 = AddcarryxU26(X73, X38, X74, &X76);
    UINT32 X78 = (X49 & 0x1ffffff);
    UINT32 X80;
    UINT8 /*bool*/ X81 = AddcarryxU25(X77, X41, X78, &X80);
    UINT32 X82 = (X49 & 0x3ffffff);
    UINT32 X84;
    UINT8 /*bool*/ X85 = AddcarryxU26(X81, X44, X82, &X84);
    UINT32 X86 = (X49 & 0x1ffffff);
    UINT32 X88;
    AddcarryxU25(X85, X47, X86, &X88);
    Out[0] = X52;
    Out[1] = X56;
    Out[2] = X60;
    Out[3] = X64;
    Out[4] = X68;
    Out[5] = X72;
    Out[6] = X76;
    Out[7] = X80;
    Out[8] = X84;
    Out[9] = X88;
}

static inline VOID
FeTobytes(_Out_writes_bytes_all_(32) UINT8 S[32], _In_ CONST Fe *F)
{
    UINT32 H[10];
    FeFreeze(H, F->V);
    S[0] = H[0] >> 0;
    S[1] = H[0] >> 8;
    S[2] = H[0] >> 16;
    S[3] = (H[0] >> 24) | (H[1] << 2);
    S[4] = H[1] >> 6;
    S[5] = H[1] >> 14;
    S[6] = (H[1] >> 22) | (H[2] << 3);
    S[7] = H[2] >> 5;
    S[8] = H[2] >> 13;
    S[9] = (H[2] >> 21) | (H[3] << 5);
    S[10] = H[3] >> 3;
    S[11] = H[3] >> 11;
    S[12] = (H[3] >> 19) | (H[4] << 6);
    S[13] = H[4] >> 2;
    S[14] = H[4] >> 10;
    S[15] = H[4] >> 18;
    S[16] = H[5] >> 0;
    S[17] = H[5] >> 8;
    S[18] = H[5] >> 16;
    S[19] = (H[5] >> 24) | (H[6] << 1);
    S[20] = H[6] >> 7;
    S[21] = H[6] >> 15;
    S[22] = (H[6] >> 23) | (H[7] << 3);
    S[23] = H[7] >> 5;
    S[24] = H[7] >> 13;
    S[25] = (H[7] >> 21) | (H[8] << 4);
    S[26] = H[8] >> 4;
    S[27] = H[8] >> 12;
    S[28] = (H[8] >> 20) | (H[9] << 6);
    S[29] = H[9] >> 2;
    S[30] = H[9] >> 10;
    S[31] = H[9] >> 18;
}

/* h = f */
static inline VOID
FeCopy(_Out_ Fe *H, _In_ CONST Fe *F)
{
    RtlMoveMemory(H, F, sizeof(UINT32) * 10);
}

static inline VOID
FeCopyLt(_Out_ FeLoose *H, _In_ CONST Fe *F)
{
    RtlMoveMemory(H, F, sizeof(UINT32) * 10);
}

/* h = 0 */
static inline VOID
Fe0(_Out_ Fe *H)
{
    RtlZeroMemory(H, sizeof(UINT32) * 10);
}

/* h = 1 */
static inline VOID
Fe1(_Out_ Fe *H)
{
    RtlZeroMemory(H, sizeof(UINT32) * 10);
    H->V[0] = 1;
}

static VOID
FeAddImpl(_Out_writes_all_(10) UINT32 Out[10], _In_reads_(10) CONST UINT32 In1[10], _In_reads_(10) CONST UINT32 In2[10])
{
    CONST UINT32 X20 = In1[9];
    CONST UINT32 X21 = In1[8];
    CONST UINT32 X19 = In1[7];
    CONST UINT32 X17 = In1[6];
    CONST UINT32 X15 = In1[5];
    CONST UINT32 X13 = In1[4];
    CONST UINT32 X11 = In1[3];
    CONST UINT32 X9 = In1[2];
    CONST UINT32 X7 = In1[1];
    CONST UINT32 X5 = In1[0];
    CONST UINT32 X38 = In2[9];
    CONST UINT32 X39 = In2[8];
    CONST UINT32 X37 = In2[7];
    CONST UINT32 X35 = In2[6];
    CONST UINT32 X33 = In2[5];
    CONST UINT32 X31 = In2[4];
    CONST UINT32 X29 = In2[3];
    CONST UINT32 X27 = In2[2];
    CONST UINT32 X25 = In2[1];
    CONST UINT32 X23 = In2[0];
    Out[0] = (X5 + X23);
    Out[1] = (X7 + X25);
    Out[2] = (X9 + X27);
    Out[3] = (X11 + X29);
    Out[4] = (X13 + X31);
    Out[5] = (X15 + X33);
    Out[6] = (X17 + X35);
    Out[7] = (X19 + X37);
    Out[8] = (X21 + X39);
    Out[9] = (X20 + X38);
}

/* h = f + g
 * Can overlap h with f or g.
 */
static inline VOID
FeAdd(_Out_ FeLoose *H, _In_ CONST Fe *F, _In_ CONST Fe *G)
{
    FeAddImpl(H->V, F->V, G->V);
}

static VOID
FeSubImpl(_Out_writes_all_(10) UINT32 Out[10], _In_reads_(10) CONST UINT32 In1[10], _In_reads_(10) CONST UINT32 In2[10])
{
    CONST UINT32 X20 = In1[9];
    CONST UINT32 X21 = In1[8];
    CONST UINT32 X19 = In1[7];
    CONST UINT32 X17 = In1[6];
    CONST UINT32 X15 = In1[5];
    CONST UINT32 X13 = In1[4];
    CONST UINT32 X11 = In1[3];
    CONST UINT32 X9 = In1[2];
    CONST UINT32 X7 = In1[1];
    CONST UINT32 X5 = In1[0];
    CONST UINT32 X38 = In2[9];
    CONST UINT32 X39 = In2[8];
    CONST UINT32 X37 = In2[7];
    CONST UINT32 X35 = In2[6];
    CONST UINT32 X33 = In2[5];
    CONST UINT32 X31 = In2[4];
    CONST UINT32 X29 = In2[3];
    CONST UINT32 X27 = In2[2];
    CONST UINT32 X25 = In2[1];
    CONST UINT32 X23 = In2[0];
    Out[0] = ((0x7ffffda + X5) - X23);
    Out[1] = ((0x3fffffe + X7) - X25);
    Out[2] = ((0x7fffffe + X9) - X27);
    Out[3] = ((0x3fffffe + X11) - X29);
    Out[4] = ((0x7fffffe + X13) - X31);
    Out[5] = ((0x3fffffe + X15) - X33);
    Out[6] = ((0x7fffffe + X17) - X35);
    Out[7] = ((0x3fffffe + X19) - X37);
    Out[8] = ((0x7fffffe + X21) - X39);
    Out[9] = ((0x3fffffe + X20) - X38);
}

/* h = f - g
 * Can overlap h with f or g.
 */
static inline VOID
FeSub(_Out_ FeLoose *H, _In_ CONST Fe *F, _In_ CONST Fe *G)
{
    FeSubImpl(H->V, F->V, G->V);
}

static VOID
FeMulImpl(_Out_writes_all_(10) UINT32 Out[10], _In_reads_(10) CONST UINT32 In1[10], _In_reads_(10) CONST UINT32 In2[10])
{
    CONST UINT32 X20 = In1[9];
    CONST UINT32 X21 = In1[8];
    CONST UINT32 X19 = In1[7];
    CONST UINT32 X17 = In1[6];
    CONST UINT32 X15 = In1[5];
    CONST UINT32 X13 = In1[4];
    CONST UINT32 X11 = In1[3];
    CONST UINT32 X9 = In1[2];
    CONST UINT32 X7 = In1[1];
    CONST UINT32 X5 = In1[0];
    CONST UINT32 X38 = In2[9];
    CONST UINT32 X39 = In2[8];
    CONST UINT32 X37 = In2[7];
    CONST UINT32 X35 = In2[6];
    CONST UINT32 X33 = In2[5];
    CONST UINT32 X31 = In2[4];
    CONST UINT32 X29 = In2[3];
    CONST UINT32 X27 = In2[2];
    CONST UINT32 X25 = In2[1];
    CONST UINT32 X23 = In2[0];
    UINT64 X40 = ((UINT64)X23 * X5);
    UINT64 X41 = (((UINT64)X23 * X7) + ((UINT64)X25 * X5));
    UINT64 X42 = ((((UINT64)(0x2 * X25) * X7) + ((UINT64)X23 * X9)) + ((UINT64)X27 * X5));
    UINT64 X43 = (((((UINT64)X25 * X9) + ((UINT64)X27 * X7)) + ((UINT64)X23 * X11)) + ((UINT64)X29 * X5));
    UINT64 X44 =
        (((((UINT64)X27 * X9) + (0x2 * (((UINT64)X25 * X11) + ((UINT64)X29 * X7)))) + ((UINT64)X23 * X13)) +
         ((UINT64)X31 * X5));
    UINT64 X45 =
        (((((((UINT64)X27 * X11) + ((UINT64)X29 * X9)) + ((UINT64)X25 * X13)) + ((UINT64)X31 * X7)) +
          ((UINT64)X23 * X15)) +
         ((UINT64)X33 * X5));
    UINT64 X46 =
        (((((0x2 * ((((UINT64)X29 * X11) + ((UINT64)X25 * X15)) + ((UINT64)X33 * X7))) + ((UINT64)X27 * X13)) +
           ((UINT64)X31 * X9)) +
          ((UINT64)X23 * X17)) +
         ((UINT64)X35 * X5));
    UINT64 X47 =
        (((((((((UINT64)X29 * X13) + ((UINT64)X31 * X11)) + ((UINT64)X27 * X15)) + ((UINT64)X33 * X9)) +
            ((UINT64)X25 * X17)) +
           ((UINT64)X35 * X7)) +
          ((UINT64)X23 * X19)) +
         ((UINT64)X37 * X5));
    UINT64 X48 =
        (((((((UINT64)X31 * X13) +
             (0x2 * (((((UINT64)X29 * X15) + ((UINT64)X33 * X11)) + ((UINT64)X25 * X19)) + ((UINT64)X37 * X7)))) +
            ((UINT64)X27 * X17)) +
           ((UINT64)X35 * X9)) +
          ((UINT64)X23 * X21)) +
         ((UINT64)X39 * X5));
    UINT64 X49 =
        (((((((((((UINT64)X31 * X15) + ((UINT64)X33 * X13)) + ((UINT64)X29 * X17)) + ((UINT64)X35 * X11)) +
              ((UINT64)X27 * X19)) +
             ((UINT64)X37 * X9)) +
            ((UINT64)X25 * X21)) +
           ((UINT64)X39 * X7)) +
          ((UINT64)X23 * X20)) +
         ((UINT64)X38 * X5));
    UINT64 X50 =
        (((((0x2 * ((((((UINT64)X33 * X15) + ((UINT64)X29 * X19)) + ((UINT64)X37 * X11)) + ((UINT64)X25 * X20)) +
                    ((UINT64)X38 * X7))) +
            ((UINT64)X31 * X17)) +
           ((UINT64)X35 * X13)) +
          ((UINT64)X27 * X21)) +
         ((UINT64)X39 * X9));
    UINT64 X51 =
        (((((((((UINT64)X33 * X17) + ((UINT64)X35 * X15)) + ((UINT64)X31 * X19)) + ((UINT64)X37 * X13)) +
            ((UINT64)X29 * X21)) +
           ((UINT64)X39 * X11)) +
          ((UINT64)X27 * X20)) +
         ((UINT64)X38 * X9));
    UINT64 X52 =
        (((((UINT64)X35 * X17) +
           (0x2 * (((((UINT64)X33 * X19) + ((UINT64)X37 * X15)) + ((UINT64)X29 * X20)) + ((UINT64)X38 * X11)))) +
          ((UINT64)X31 * X21)) +
         ((UINT64)X39 * X13));
    UINT64 X53 =
        (((((((UINT64)X35 * X19) + ((UINT64)X37 * X17)) + ((UINT64)X33 * X21)) + ((UINT64)X39 * X15)) +
          ((UINT64)X31 * X20)) +
         ((UINT64)X38 * X13));
    UINT64 X54 =
        (((0x2 * ((((UINT64)X37 * X19) + ((UINT64)X33 * X20)) + ((UINT64)X38 * X15))) + ((UINT64)X35 * X21)) +
         ((UINT64)X39 * X17));
    UINT64 X55 = (((((UINT64)X37 * X21) + ((UINT64)X39 * X19)) + ((UINT64)X35 * X20)) + ((UINT64)X38 * X17));
    UINT64 X56 = (((UINT64)X39 * X21) + (0x2 * (((UINT64)X37 * X20) + ((UINT64)X38 * X19))));
    UINT64 X57 = (((UINT64)X39 * X20) + ((UINT64)X38 * X21));
    UINT64 X58 = ((UINT64)(0x2 * X38) * X20);
    UINT64 X59 = (X48 + (X58 << 0x4));
    UINT64 X60 = (X59 + (X58 << 0x1));
    UINT64 X61 = (X60 + X58);
    UINT64 X62 = (X47 + (X57 << 0x4));
    UINT64 X63 = (X62 + (X57 << 0x1));
    UINT64 X64 = (X63 + X57);
    UINT64 X65 = (X46 + (X56 << 0x4));
    UINT64 X66 = (X65 + (X56 << 0x1));
    UINT64 X67 = (X66 + X56);
    UINT64 X68 = (X45 + (X55 << 0x4));
    UINT64 X69 = (X68 + (X55 << 0x1));
    UINT64 X70 = (X69 + X55);
    UINT64 X71 = (X44 + (X54 << 0x4));
    UINT64 X72 = (X71 + (X54 << 0x1));
    UINT64 X73 = (X72 + X54);
    UINT64 X74 = (X43 + (X53 << 0x4));
    UINT64 X75 = (X74 + (X53 << 0x1));
    UINT64 X76 = (X75 + X53);
    UINT64 X77 = (X42 + (X52 << 0x4));
    UINT64 X78 = (X77 + (X52 << 0x1));
    UINT64 X79 = (X78 + X52);
    UINT64 X80 = (X41 + (X51 << 0x4));
    UINT64 X81 = (X80 + (X51 << 0x1));
    UINT64 X82 = (X81 + X51);
    UINT64 X83 = (X40 + (X50 << 0x4));
    UINT64 X84 = (X83 + (X50 << 0x1));
    UINT64 X85 = (X84 + X50);
    UINT64 X86 = (X85 >> 0x1a);
    UINT32 X87 = ((UINT32)X85 & 0x3ffffff);
    UINT64 X88 = (X86 + X82);
    UINT64 X89 = (X88 >> 0x19);
    UINT32 X90 = ((UINT32)X88 & 0x1ffffff);
    UINT64 X91 = (X89 + X79);
    UINT64 X92 = (X91 >> 0x1a);
    UINT32 X93 = ((UINT32)X91 & 0x3ffffff);
    UINT64 X94 = (X92 + X76);
    UINT64 X95 = (X94 >> 0x19);
    UINT32 X96 = ((UINT32)X94 & 0x1ffffff);
    UINT64 X97 = (X95 + X73);
    UINT64 X98 = (X97 >> 0x1a);
    UINT32 X99 = ((UINT32)X97 & 0x3ffffff);
    UINT64 X100 = (X98 + X70);
    UINT64 X101 = (X100 >> 0x19);
    UINT32 X102 = ((UINT32)X100 & 0x1ffffff);
    UINT64 X103 = (X101 + X67);
    UINT64 X104 = (X103 >> 0x1a);
    UINT32 X105 = ((UINT32)X103 & 0x3ffffff);
    UINT64 X106 = (X104 + X64);
    UINT64 X107 = (X106 >> 0x19);
    UINT32 X108 = ((UINT32)X106 & 0x1ffffff);
    UINT64 X109 = (X107 + X61);
    UINT64 X110 = (X109 >> 0x1a);
    UINT32 X111 = ((UINT32)X109 & 0x3ffffff);
    UINT64 X112 = (X110 + X49);
    UINT64 X113 = (X112 >> 0x19);
    UINT32 X114 = ((UINT32)X112 & 0x1ffffff);
    UINT64 X115 = (X87 + (0x13 * X113));
    UINT32 X116 = (UINT32)(X115 >> 0x1a);
    UINT32 X117 = ((UINT32)X115 & 0x3ffffff);
    UINT32 X118 = (X116 + X90);
    UINT32 X119 = (X118 >> 0x19);
    UINT32 X120 = (X118 & 0x1ffffff);
    Out[0] = X117;
    Out[1] = X120;
    Out[2] = (X119 + X93);
    Out[3] = X96;
    Out[4] = X99;
    Out[5] = X102;
    Out[6] = X105;
    Out[7] = X108;
    Out[8] = X111;
    Out[9] = X114;
}

static inline VOID
FeMulTtt(_Out_ Fe *H, _In_ CONST Fe *F, _In_ CONST Fe *G)
{
    FeMulImpl(H->V, F->V, G->V);
}

static inline VOID
FeMulTlt(_Out_ Fe *H, _In_ CONST FeLoose *F, _In_ CONST Fe *G)
{
    FeMulImpl(H->V, F->V, G->V);
}

static inline VOID
FeMulTll(_Out_ Fe *H, _In_ CONST FeLoose *F, _In_ CONST FeLoose *G)
{
    FeMulImpl(H->V, F->V, G->V);
}

static VOID
FeSqrImpl(_Out_writes_all_(10) UINT32 Out[10], _In_reads_(10) CONST UINT32 In1[10])
{
    CONST UINT32 X17 = In1[9];
    CONST UINT32 X18 = In1[8];
    CONST UINT32 X16 = In1[7];
    CONST UINT32 X14 = In1[6];
    CONST UINT32 X12 = In1[5];
    CONST UINT32 X10 = In1[4];
    CONST UINT32 X8 = In1[3];
    CONST UINT32 X6 = In1[2];
    CONST UINT32 X4 = In1[1];
    CONST UINT32 X2 = In1[0];
    UINT64 X19 = ((UINT64)X2 * X2);
    UINT64 X20 = ((UINT64)(0x2 * X2) * X4);
    UINT64 X21 = (0x2 * (((UINT64)X4 * X4) + ((UINT64)X2 * X6)));
    UINT64 X22 = (0x2 * (((UINT64)X4 * X6) + ((UINT64)X2 * X8)));
    UINT64 X23 = ((((UINT64)X6 * X6) + ((UINT64)(0x4 * X4) * X8)) + ((UINT64)(0x2 * X2) * X10));
    UINT64 X24 = (0x2 * ((((UINT64)X6 * X8) + ((UINT64)X4 * X10)) + ((UINT64)X2 * X12)));
    UINT64 X25 = (0x2 * (((((UINT64)X8 * X8) + ((UINT64)X6 * X10)) + ((UINT64)X2 * X14)) + ((UINT64)(0x2 * X4) * X12)));
    UINT64 X26 = (0x2 * (((((UINT64)X8 * X10) + ((UINT64)X6 * X12)) + ((UINT64)X4 * X14)) + ((UINT64)X2 * X16)));
    UINT64 X27 =
        (((UINT64)X10 * X10) +
         (0x2 * ((((UINT64)X6 * X14) + ((UINT64)X2 * X18)) + (0x2 * (((UINT64)X4 * X16) + ((UINT64)X8 * X12))))));
    UINT64 X28 =
        (0x2 * ((((((UINT64)X10 * X12) + ((UINT64)X8 * X14)) + ((UINT64)X6 * X16)) + ((UINT64)X4 * X18)) +
                ((UINT64)X2 * X17)));
    UINT64 X29 =
        (0x2 * (((((UINT64)X12 * X12) + ((UINT64)X10 * X14)) + ((UINT64)X6 * X18)) +
                (0x2 * (((UINT64)X8 * X16) + ((UINT64)X4 * X17)))));
    UINT64 X30 = (0x2 * (((((UINT64)X12 * X14) + ((UINT64)X10 * X16)) + ((UINT64)X8 * X18)) + ((UINT64)X6 * X17)));
    UINT64 X31 =
        (((UINT64)X14 * X14) + (0x2 * (((UINT64)X10 * X18) + (0x2 * (((UINT64)X12 * X16) + ((UINT64)X8 * X17))))));
    UINT64 X32 = (0x2 * ((((UINT64)X14 * X16) + ((UINT64)X12 * X18)) + ((UINT64)X10 * X17)));
    UINT64 X33 = (0x2 * ((((UINT64)X16 * X16) + ((UINT64)X14 * X18)) + ((UINT64)(0x2 * X12) * X17)));
    UINT64 X34 = (0x2 * (((UINT64)X16 * X18) + ((UINT64)X14 * X17)));
    UINT64 X35 = (((UINT64)X18 * X18) + ((UINT64)(0x4 * X16) * X17));
    UINT64 X36 = ((UINT64)(0x2 * X18) * X17);
    UINT64 X37 = ((UINT64)(0x2 * X17) * X17);
    UINT64 X38 = (X27 + (X37 << 0x4));
    UINT64 X39 = (X38 + (X37 << 0x1));
    UINT64 X40 = (X39 + X37);
    UINT64 X41 = (X26 + (X36 << 0x4));
    UINT64 X42 = (X41 + (X36 << 0x1));
    UINT64 X43 = (X42 + X36);
    UINT64 X44 = (X25 + (X35 << 0x4));
    UINT64 X45 = (X44 + (X35 << 0x1));
    UINT64 X46 = (X45 + X35);
    UINT64 X47 = (X24 + (X34 << 0x4));
    UINT64 X48 = (X47 + (X34 << 0x1));
    UINT64 X49 = (X48 + X34);
    UINT64 X50 = (X23 + (X33 << 0x4));
    UINT64 X51 = (X50 + (X33 << 0x1));
    UINT64 X52 = (X51 + X33);
    UINT64 X53 = (X22 + (X32 << 0x4));
    UINT64 X54 = (X53 + (X32 << 0x1));
    UINT64 X55 = (X54 + X32);
    UINT64 X56 = (X21 + (X31 << 0x4));
    UINT64 X57 = (X56 + (X31 << 0x1));
    UINT64 X58 = (X57 + X31);
    UINT64 X59 = (X20 + (X30 << 0x4));
    UINT64 X60 = (X59 + (X30 << 0x1));
    UINT64 X61 = (X60 + X30);
    UINT64 X62 = (X19 + (X29 << 0x4));
    UINT64 X63 = (X62 + (X29 << 0x1));
    UINT64 X64 = (X63 + X29);
    UINT64 X65 = (X64 >> 0x1a);
    UINT32 X66 = ((UINT32)X64 & 0x3ffffff);
    UINT64 X67 = (X65 + X61);
    UINT64 X68 = (X67 >> 0x19);
    UINT32 X69 = ((UINT32)X67 & 0x1ffffff);
    UINT64 X70 = (X68 + X58);
    UINT64 X71 = (X70 >> 0x1a);
    UINT32 X72 = ((UINT32)X70 & 0x3ffffff);
    UINT64 X73 = (X71 + X55);
    UINT64 X74 = (X73 >> 0x19);
    UINT32 X75 = ((UINT32)X73 & 0x1ffffff);
    UINT64 X76 = (X74 + X52);
    UINT64 X77 = (X76 >> 0x1a);
    UINT32 X78 = ((UINT32)X76 & 0x3ffffff);
    UINT64 X79 = (X77 + X49);
    UINT64 X80 = (X79 >> 0x19);
    UINT32 X81 = ((UINT32)X79 & 0x1ffffff);
    UINT64 X82 = (X80 + X46);
    UINT64 X83 = (X82 >> 0x1a);
    UINT32 X84 = ((UINT32)X82 & 0x3ffffff);
    UINT64 X85 = (X83 + X43);
    UINT64 X86 = (X85 >> 0x19);
    UINT32 X87 = ((UINT32)X85 & 0x1ffffff);
    UINT64 X88 = (X86 + X40);
    UINT64 X89 = (X88 >> 0x1a);
    UINT32 X90 = ((UINT32)X88 & 0x3ffffff);
    UINT64 X91 = (X89 + X28);
    UINT64 X92 = (X91 >> 0x19);
    UINT32 X93 = ((UINT32)X91 & 0x1ffffff);
    UINT64 X94 = (X66 + (0x13 * X92));
    UINT32 X95 = (UINT32)(X94 >> 0x1a);
    UINT32 X96 = ((UINT32)X94 & 0x3ffffff);
    UINT32 X97 = (X95 + X69);
    UINT32 X98 = (X97 >> 0x19);
    UINT32 X99 = (X97 & 0x1ffffff);
    Out[0] = X96;
    Out[1] = X99;
    Out[2] = (X98 + X72);
    Out[3] = X75;
    Out[4] = X78;
    Out[5] = X81;
    Out[6] = X84;
    Out[7] = X87;
    Out[8] = X90;
    Out[9] = X93;
}

static inline VOID
FeSqTl(_Out_ Fe *H, _In_ CONST FeLoose *F)
{
    FeSqrImpl(H->V, F->V);
}

static inline VOID
FeSqTt(_Out_ Fe *H, _In_ CONST Fe *F)
{
    FeSqrImpl(H->V, F->V);
}

static inline VOID
FeLooseInvert(_Out_ Fe *Out, _In_ CONST FeLoose *Z)
{
    Fe T0;
    Fe T1;
    Fe T2;
    Fe T3;
    LONG i;

    FeSqTl(&T0, Z);
    FeSqTt(&T1, &T0);
    for (i = 1; i < 2; ++i)
        FeSqTt(&T1, &T1);
    FeMulTlt(&T1, Z, &T1);
    FeMulTtt(&T0, &T0, &T1);
    FeSqTt(&T2, &T0);
    FeMulTtt(&T1, &T1, &T2);
    FeSqTt(&T2, &T1);
    for (i = 1; i < 5; ++i)
        FeSqTt(&T2, &T2);
    FeMulTtt(&T1, &T2, &T1);
    FeSqTt(&T2, &T1);
    for (i = 1; i < 10; ++i)
        FeSqTt(&T2, &T2);
    FeMulTtt(&T2, &T2, &T1);
    FeSqTt(&T3, &T2);
    for (i = 1; i < 20; ++i)
        FeSqTt(&T3, &T3);
    FeMulTtt(&T2, &T3, &T2);
    FeSqTt(&T2, &T2);
    for (i = 1; i < 10; ++i)
        FeSqTt(&T2, &T2);
    FeMulTtt(&T1, &T2, &T1);
    FeSqTt(&T2, &T1);
    for (i = 1; i < 50; ++i)
        FeSqTt(&T2, &T2);
    FeMulTtt(&T2, &T2, &T1);
    FeSqTt(&T3, &T2);
    for (i = 1; i < 100; ++i)
        FeSqTt(&T3, &T3);
    FeMulTtt(&T2, &T3, &T2);
    FeSqTt(&T2, &T2);
    for (i = 1; i < 50; ++i)
        FeSqTt(&T2, &T2);
    FeMulTtt(&T1, &T2, &T1);
    FeSqTt(&T1, &T1);
    for (i = 1; i < 5; ++i)
        FeSqTt(&T1, &T1);
    FeMulTtt(Out, &T1, &T0);
}

static inline VOID
FeInvert(_Out_ Fe *Out, _In_ CONST Fe *Z)
{
    FeLoose l;
    FeCopyLt(&l, Z);
    FeLooseInvert(Out, &l);
}

/* Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}
 */
static inline VOID
FeCswap(_Inout_ Fe *F, _Inout_ Fe *G, _In_ UINT32 B)
{
    LONG i;
    B = 0 - B;
    for (i = 0; i < 10; ++i)
    {
        UINT32 X = F->V[i] ^ G->V[i];
        X &= B;
        F->V[i] ^= X;
        G->V[i] ^= X;
    }
}

/* NOTE: based on fiat-crypto fe_mul, edited for in2=121666, 0, 0.*/
static inline VOID
FeMul121666Impl(_Out_writes_all_(10) UINT32 Out[10], _In_reads_(10) CONST UINT32 In1[10])
{
    CONST UINT32 X20 = In1[9];
    CONST UINT32 X21 = In1[8];
    CONST UINT32 X19 = In1[7];
    CONST UINT32 X17 = In1[6];
    CONST UINT32 X15 = In1[5];
    CONST UINT32 X13 = In1[4];
    CONST UINT32 X11 = In1[3];
    CONST UINT32 X9 = In1[2];
    CONST UINT32 X7 = In1[1];
    CONST UINT32 X5 = In1[0];
    CONST UINT32 X38 = 0;
    CONST UINT32 X39 = 0;
    CONST UINT32 X37 = 0;
    CONST UINT32 X35 = 0;
    CONST UINT32 X33 = 0;
    CONST UINT32 X31 = 0;
    CONST UINT32 X29 = 0;
    CONST UINT32 X27 = 0;
    CONST UINT32 X25 = 0;
    CONST UINT32 X23 = 121666;
    UINT64 X40 = ((UINT64)X23 * X5);
    UINT64 X41 = (((UINT64)X23 * X7) + ((UINT64)X25 * X5));
    UINT64 X42 = ((((UINT64)(0x2 * X25) * X7) + ((UINT64)X23 * X9)) + ((UINT64)X27 * X5));
    UINT64 X43 = (((((UINT64)X25 * X9) + ((UINT64)X27 * X7)) + ((UINT64)X23 * X11)) + ((UINT64)X29 * X5));
    UINT64 X44 =
        (((((UINT64)X27 * X9) + (0x2 * (((UINT64)X25 * X11) + ((UINT64)X29 * X7)))) + ((UINT64)X23 * X13)) +
         ((UINT64)X31 * X5));
    UINT64 X45 =
        (((((((UINT64)X27 * X11) + ((UINT64)X29 * X9)) + ((UINT64)X25 * X13)) + ((UINT64)X31 * X7)) +
          ((UINT64)X23 * X15)) +
         ((UINT64)X33 * X5));
    UINT64 X46 =
        (((((0x2 * ((((UINT64)X29 * X11) + ((UINT64)X25 * X15)) + ((UINT64)X33 * X7))) + ((UINT64)X27 * X13)) +
           ((UINT64)X31 * X9)) +
          ((UINT64)X23 * X17)) +
         ((UINT64)X35 * X5));
    UINT64 X47 =
        (((((((((UINT64)X29 * X13) + ((UINT64)X31 * X11)) + ((UINT64)X27 * X15)) + ((UINT64)X33 * X9)) +
            ((UINT64)X25 * X17)) +
           ((UINT64)X35 * X7)) +
          ((UINT64)X23 * X19)) +
         ((UINT64)X37 * X5));
    UINT64 X48 =
        (((((((UINT64)X31 * X13) +
             (0x2 * (((((UINT64)X29 * X15) + ((UINT64)X33 * X11)) + ((UINT64)X25 * X19)) + ((UINT64)X37 * X7)))) +
            ((UINT64)X27 * X17)) +
           ((UINT64)X35 * X9)) +
          ((UINT64)X23 * X21)) +
         ((UINT64)X39 * X5));
    UINT64 X49 =
        (((((((((((UINT64)X31 * X15) + ((UINT64)X33 * X13)) + ((UINT64)X29 * X17)) + ((UINT64)X35 * X11)) +
              ((UINT64)X27 * X19)) +
             ((UINT64)X37 * X9)) +
            ((UINT64)X25 * X21)) +
           ((UINT64)X39 * X7)) +
          ((UINT64)X23 * X20)) +
         ((UINT64)X38 * X5));
    UINT64 X50 =
        (((((0x2 * ((((((UINT64)X33 * X15) + ((UINT64)X29 * X19)) + ((UINT64)X37 * X11)) + ((UINT64)X25 * X20)) +
                    ((UINT64)X38 * X7))) +
            ((UINT64)X31 * X17)) +
           ((UINT64)X35 * X13)) +
          ((UINT64)X27 * X21)) +
         ((UINT64)X39 * X9));
    UINT64 X51 =
        (((((((((UINT64)X33 * X17) + ((UINT64)X35 * X15)) + ((UINT64)X31 * X19)) + ((UINT64)X37 * X13)) +
            ((UINT64)X29 * X21)) +
           ((UINT64)X39 * X11)) +
          ((UINT64)X27 * X20)) +
         ((UINT64)X38 * X9));
    UINT64 X52 =
        (((((UINT64)X35 * X17) +
           (0x2 * (((((UINT64)X33 * X19) + ((UINT64)X37 * X15)) + ((UINT64)X29 * X20)) + ((UINT64)X38 * X11)))) +
          ((UINT64)X31 * X21)) +
         ((UINT64)X39 * X13));
    UINT64 X53 =
        (((((((UINT64)X35 * X19) + ((UINT64)X37 * X17)) + ((UINT64)X33 * X21)) + ((UINT64)X39 * X15)) +
          ((UINT64)X31 * X20)) +
         ((UINT64)X38 * X13));
    UINT64 X54 =
        (((0x2 * ((((UINT64)X37 * X19) + ((UINT64)X33 * X20)) + ((UINT64)X38 * X15))) + ((UINT64)X35 * X21)) +
         ((UINT64)X39 * X17));
    UINT64 X55 = (((((UINT64)X37 * X21) + ((UINT64)X39 * X19)) + ((UINT64)X35 * X20)) + ((UINT64)X38 * X17));
    UINT64 X56 = (((UINT64)X39 * X21) + (0x2 * (((UINT64)X37 * X20) + ((UINT64)X38 * X19))));
    UINT64 X57 = (((UINT64)X39 * X20) + ((UINT64)X38 * X21));
    UINT64 X58 = ((UINT64)(0x2 * X38) * X20);
    UINT64 X59 = (X48 + (X58 << 0x4));
    UINT64 X60 = (X59 + (X58 << 0x1));
    UINT64 X61 = (X60 + X58);
    UINT64 X62 = (X47 + (X57 << 0x4));
    UINT64 X63 = (X62 + (X57 << 0x1));
    UINT64 X64 = (X63 + X57);
    UINT64 X65 = (X46 + (X56 << 0x4));
    UINT64 X66 = (X65 + (X56 << 0x1));
    UINT64 X67 = (X66 + X56);
    UINT64 X68 = (X45 + (X55 << 0x4));
    UINT64 X69 = (X68 + (X55 << 0x1));
    UINT64 X70 = (X69 + X55);
    UINT64 X71 = (X44 + (X54 << 0x4));
    UINT64 X72 = (X71 + (X54 << 0x1));
    UINT64 X73 = (X72 + X54);
    UINT64 X74 = (X43 + (X53 << 0x4));
    UINT64 X75 = (X74 + (X53 << 0x1));
    UINT64 X76 = (X75 + X53);
    UINT64 X77 = (X42 + (X52 << 0x4));
    UINT64 X78 = (X77 + (X52 << 0x1));
    UINT64 X79 = (X78 + X52);
    UINT64 X80 = (X41 + (X51 << 0x4));
    UINT64 X81 = (X80 + (X51 << 0x1));
    UINT64 X82 = (X81 + X51);
    UINT64 X83 = (X40 + (X50 << 0x4));
    UINT64 X84 = (X83 + (X50 << 0x1));
    UINT64 X85 = (X84 + X50);
    UINT64 X86 = (X85 >> 0x1a);
    UINT32 X87 = ((UINT32)X85 & 0x3ffffff);
    UINT64 X88 = (X86 + X82);
    UINT64 X89 = (X88 >> 0x19);
    UINT32 X90 = ((UINT32)X88 & 0x1ffffff);
    UINT64 X91 = (X89 + X79);
    UINT64 X92 = (X91 >> 0x1a);
    UINT32 X93 = ((UINT32)X91 & 0x3ffffff);
    UINT64 X94 = (X92 + X76);
    UINT64 X95 = (X94 >> 0x19);
    UINT32 X96 = ((UINT32)X94 & 0x1ffffff);
    UINT64 X97 = (X95 + X73);
    UINT64 X98 = (X97 >> 0x1a);
    UINT32 X99 = ((UINT32)X97 & 0x3ffffff);
    UINT64 X100 = (X98 + X70);
    UINT64 X101 = (X100 >> 0x19);
    UINT32 X102 = ((UINT32)X100 & 0x1ffffff);
    UINT64 X103 = (X101 + X67);
    UINT64 X104 = (X103 >> 0x1a);
    UINT32 X105 = ((UINT32)X103 & 0x3ffffff);
    UINT64 X106 = (X104 + X64);
    UINT64 X107 = (X106 >> 0x19);
    UINT32 X108 = ((UINT32)X106 & 0x1ffffff);
    UINT64 X109 = (X107 + X61);
    UINT64 X110 = (X109 >> 0x1a);
    UINT32 X111 = ((UINT32)X109 & 0x3ffffff);
    UINT64 X112 = (X110 + X49);
    UINT64 X113 = (X112 >> 0x19);
    UINT32 X114 = ((UINT32)X112 & 0x1ffffff);
    UINT64 X115 = (X87 + (0x13 * X113));
    UINT32 X116 = (UINT32)(X115 >> 0x1a);
    UINT32 X117 = ((UINT32)X115 & 0x3ffffff);
    UINT32 X118 = (X116 + X90);
    UINT32 X119 = (X118 >> 0x19);
    UINT32 X120 = (X118 & 0x1ffffff);
    Out[0] = X117;
    Out[1] = X120;
    Out[2] = (X119 + X93);
    Out[3] = X96;
    Out[4] = X99;
    Out[5] = X102;
    Out[6] = X105;
    Out[7] = X108;
    Out[8] = X111;
    Out[9] = X114;
}

static inline VOID
FeMul121666(_Out_ Fe *H, _In_ CONST FeLoose *F)
{
    FeMul121666Impl(H->V, F->V);
}

_Use_decl_annotations_
BOOLEAN
Curve25519(
    UINT8 Out[CURVE25519_KEY_SIZE],
    CONST UINT8 Scalar[CURVE25519_KEY_SIZE],
    CONST UINT8 Point[CURVE25519_KEY_SIZE])
{
    Fe X1, X2, Z2, X3, Z3;
    FeLoose X2l, Z2l, X3l;
    UINT32 Swap = 0;
    LONG Pos;
    UINT8 E[32];

    RtlCopyMemory(E, Scalar, 32);
    Curve25519ClampSecret(E);

    /* The following implementation was transcribed to Coq and proven to
     * correspond to unary scalar multiplication in affine coordinates given
     * that x1 != 0 is the x coordinate of some point on the curve. It was
     * also checked in Coq that doing a ladderstep with x1 = x3 = 0 gives
     * z2' = z3' = 0, and z2 = z3 = 0 gives z2' = z3' = 0. The statement was
     * quantified over the underlying field, so it applies to Curve25519
     * itself and the quadratic twist of Curve25519. It was not proven in
     * Coq that prime-field arithmetic correctly simulates extension-field
     * arithmetic on prime-field values. The decoding of the byte array
     * representation of e was not considered.
     *
     * Specification of Montgomery curves in affine coordinates:
     * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Spec/MontgomeryCurve.v#L27>
     *
     * Proof that these form a group that is isomorphic to a Weierstrass
     * curve:
     * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/AffineProofs.v#L35>
     *
     * Coq transcription and correctness proof of the loop
     * (where scalarbits=255):
     * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L118>
     * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L278>
     * preconditions: 0 <= e < 2^255 (not necessarily e < order),
     * fe_invert(0) = 0
     */
    FeFrombytes(&X1, Point);
    Fe1(&X2);
    Fe0(&Z2);
    FeCopy(&X3, &X1);
    Fe1(&Z3);

    for (Pos = 254; Pos >= 0; --Pos)
    {
        Fe Tmp0, Tmp1;
        FeLoose Tmp0l, Tmp1l;
        /* loop invariant as of right before the test, for the case
         * where x1 != 0:
         *   pos >= -1; if z2 = 0 then x2 is nonzero; if z3 = 0 then x3
         *   is nonzero
         *   let r := e >> (pos+1) in the following equalities of
         *   projective points:
         *   to_xz (r*P)     === if swap then (x3, z3) else (x2, z2)
         *   to_xz ((r+1)*P) === if swap then (x2, z2) else (x3, z3)
         *   x1 is the nonzero x coordinate of the nonzero
         *   point (r*P-(r+1)*P)
         */
        UINT32 B = 1 & (E[Pos / 8] >> (Pos & 7));
        Swap ^= B;
        FeCswap(&X2, &X3, Swap);
        FeCswap(&Z2, &Z3, Swap);
        Swap = B;
        /* Coq transcription of ladderstep formula (called from
         * transcribed loop):
         * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L89>
         * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L131>
         * x1 != 0
         * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L217>
         * x1  = 0
         * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L147>
         */
        FeSub(&Tmp0l, &X3, &Z3);
        FeSub(&Tmp1l, &X2, &Z2);
        FeAdd(&X2l, &X2, &Z2);
        FeAdd(&Z2l, &X3, &Z3);
        FeMulTll(&Z3, &Tmp0l, &X2l);
        FeMulTll(&Z2, &Z2l, &Tmp1l);
        FeSqTl(&Tmp0, &Tmp1l);
        FeSqTl(&Tmp1, &X2l);
        FeAdd(&X3l, &Z3, &Z2);
        FeSub(&Z2l, &Z3, &Z2);
        FeMulTtt(&X2, &Tmp1, &Tmp0);
        FeSub(&Tmp1l, &Tmp1, &Tmp0);
        FeSqTl(&Z2, &Z2l);
        FeMul121666(&Z3, &Tmp1l);
        FeSqTl(&X3, &X3l);
        FeAdd(&Tmp0l, &Tmp0, &Z3);
        FeMulTtt(&Z3, &X1, &Z2);
        FeMulTll(&Z2, &Tmp1l, &Tmp0l);
    }
    /* here pos=-1, so r=e, so to_xz (e*P) === if swap then (x3, z3)
     * else (x2, z2)
     */
    FeCswap(&X2, &X3, Swap);
    FeCswap(&Z2, &Z3, Swap);

    FeInvert(&Z2, &Z2);
    FeMulTtt(&X2, &X2, &Z2);
    FeTobytes(Out, &X2);

    RtlSecureZeroMemory(&X1, sizeof(X1));
    RtlSecureZeroMemory(&X2, sizeof(X2));
    RtlSecureZeroMemory(&Z2, sizeof(Z2));
    RtlSecureZeroMemory(&X3, sizeof(X3));
    RtlSecureZeroMemory(&Z3, sizeof(Z3));
    RtlSecureZeroMemory(&X2l, sizeof(X2l));
    RtlSecureZeroMemory(&Z2l, sizeof(Z2l));
    RtlSecureZeroMemory(&X3l, sizeof(X3l));
    RtlSecureZeroMemory(&E, sizeof(E));

    return !CryptoIsZero32(Out);
}

#ifdef DBG
#    include "selftest/chacha20poly1305.c"
#    ifdef ALLOC_PRAGMA
#        pragma alloc_text(INIT, CryptoSelftest)
#    endif
_Use_decl_annotations_
BOOLEAN CryptoSelftest(VOID)
{
    BOOLEAN Success = TRUE;
    SIMD_STATE Simd;
    SimdGet(&Simd);
    ULONG FullSet = (ULONG)Simd.CpuFeatures;
    Simd.CpuFeatures = 0;
    do
    {
        if (!ChaCha20Poly1305Selftest(&Simd))
        {
            LogDebug("chacha20poly1305 self-test combination 0x%lx: FAIL", Simd.CpuFeatures);
            Success = FALSE;
        }
        Simd.CpuFeatures = ((ULONG)Simd.CpuFeatures - FullSet) & FullSet;
    } while (Simd.CpuFeatures);
    SimdPut(&Simd);
    if (Success)
        LogDebug("crypto self-tests: pass");
    return Success;
}
#endif
