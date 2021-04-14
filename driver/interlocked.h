/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include <fltkernel.h>

#pragma warning(suppress : 28194) /* `Value` is aliased in WritePointerNoFence. */
static inline VOID
__WritePointerNoFence(_Out_ _Interlocked_operand_ PVOID volatile *Destination, _In_opt_ __drv_aliasesMem PVOID Value)
{
    _Analysis_assume_(Value); /* The _In_ should be an _In_opt_. */
    WritePointerNoFence(Destination, Value);
}
/* Suppresses warning about strict type matches, which don't quite make sense in this context. */
#define WritePointerNoFence(P, V) __WritePointerNoFence((PVOID *)(P), V)

#pragma warning(suppress : 28194) /* `Value` is aliased in WritePointerRelease. */
static inline VOID
__WritePointerRelease(_Out_ _Interlocked_operand_ PVOID volatile *Destination, _In_opt_ __drv_aliasesMem PVOID Value)
{
    _Analysis_assume_(Value); /* The _In_ should be an _In_opt_. */
    WritePointerRelease(Destination, Value);
}
/* Suppresses warning about strict type matches, which don't quite make sense in this context. */
#define WritePointerRelease(P, V) __WritePointerRelease((PVOID *)(P), V)

static inline VOID WriteMemoryBarrier(VOID)
{
#if defined(_ARM64_)
    __dmb(_ARM64_BARRIER_ISHST);
#elif defined(_ARM_)
    __dmb(_ARM_BARRIER_ISHST);
#elif defined(_AMD64_) || defined(_X86_)
    /* Strong ordering on Intel */
#else
#    error "Unknown arch. Consult smp_wmb."
#endif
    _ReadWriteBarrier();
}

#ifdef _WIN64
#    define InterlockedBitTestAndSetPtr(Addr, Nr) InterlockedBitTestAndSet64(Addr, Nr)
#else
#    define InterlockedBitTestAndSetPtr(Addr, Nr) InterlockedBitTestAndSet(Addr, Nr)
#endif

#ifndef InterlockedExchangePointerRelease
_Ret_writes_(_Inexpressible_(Unknown)) static inline PVOID InterlockedExchangePointerRelease(
    _Inout_ _At_(
        *Target,
        _Pre_writable_byte_size_(_Inexpressible_(Unknown)) _Post_writable_byte_size_(_Inexpressible_(Unknown)))
        _Interlocked_operand_ PVOID volatile *Target,
    _In_opt_ PVOID Value)
{
#    if defined(_ARM64_)
    __dmb(_ARM64_BARRIER_ISH);
#    elif defined(_ARM_)
    __dmb(_ARM_BARRIER_ISH);
#    elif defined(_AMD64_) || defined(_X86_)
    /* Atomic instructions are already serializing on Intel */
#    else
#        error "Unknown arch. Consult __atomic_release_fence/smp_mb__before_atomic."
#    endif
    return InterlockedExchangePointer(Target, Value);
}
#endif

_Must_inspect_result_
static inline BOOLEAN
InterlockedIncrementUnless(_Inout_ _Interlocked_operand_ LONG volatile *Destination, _In_ LONG Unless)
{
    for (LONG C = ReadNoFence(Destination), X;; C = X)
    {
        if (C == Unless)
            return FALSE;
        X = InterlockedCompareExchange(Destination, C + 1, C);
        if (X == C)
            return TRUE;
    }
}

_Must_inspect_result_
static inline BOOLEAN
InterlockedIncrementUnless64(_Inout_ _Interlocked_operand_ LONG64 volatile *Destination, _In_ LONG64 Unless)
{
    for (LONG64 C = ReadNoFence64(Destination), X;; C = X)
    {
        if (C == Unless)
            return FALSE;
        X = InterlockedCompareExchange64(Destination, C + 1, C);
        if (X == C)
            return TRUE;
    }
}

typedef LONG64 KREF;

static inline VOID
KrefInit(_Out_ KREF *Kref)
{
    WriteRaw64(Kref, 1);
}

static inline VOID
KrefGet(_Inout_ KREF *Kref)
{
    InterlockedIncrement64(Kref);
}

_Must_inspect_result_
static inline BOOLEAN
KrefGetUnlessZero(_Inout_ KREF *Kref)
{
    return InterlockedIncrementUnless64(Kref, 0);
}

static inline BOOLEAN
KrefPut(_Inout_ KREF *Kref, _In_ VOID (*Release)(_In_ KREF *Kref))
{
    if (!InterlockedDecrement64(Kref))
    {
        Release(Kref);
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(APC_LEVEL)
static inline VOID
MuInitializePushLock(_Out_ PEX_PUSH_LOCK PushLock)
{
#ifdef EX_LEGACY_PUSH_LOCKS
    FltInitializePushLock(PushLock);
#else
    ExInitializePushLock(PushLock);
#endif
}

_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
static inline VOID
MuAcquirePushLockExclusive(_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_)
                               PEX_PUSH_LOCK PushLock)
{
#ifdef EX_LEGACY_PUSH_LOCKS
    FltAcquirePushLockExclusive(PushLock);
#else
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(PushLock);
#endif
}

_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
static inline VOID
MuAcquirePushLockShared(_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_)
                            PEX_PUSH_LOCK PushLock)
{
#ifdef EX_LEGACY_PUSH_LOCKS
    FltAcquirePushLockShared(PushLock);
#else
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(PushLock);
#endif
}

_Releases_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
static inline VOID
MuReleasePushLockExclusive(_Inout_ _Requires_exclusive_lock_held_(*_Curr_) _Releases_exclusive_lock_(*_Curr_)
                               PEX_PUSH_LOCK PushLock)
{
#ifdef EX_LEGACY_PUSH_LOCKS
    FltReleasePushLock(PushLock);
#else
    ExReleasePushLockExclusive(PushLock);
    KeLeaveCriticalRegion();
#endif
}

_Releases_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
static inline VOID
MuReleasePushLockShared(_Inout_ _Requires_shared_lock_held_(*_Curr_) _Releases_shared_lock_(*_Curr_)
                            PEX_PUSH_LOCK PushLock)
{
    _Analysis_suppress_lock_checking_(PushLock);
#ifdef EX_LEGACY_PUSH_LOCKS
    FltReleasePushLock(PushLock);
#else
    ExReleasePushLockShared(PushLock);
    KeLeaveCriticalRegion();
#endif
}
