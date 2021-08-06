/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>
#include "interlocked.h"

extern int _Global_rcu_read_lock_;
#define _Requires_rcu_held_ _Requires_lock_held_(_Global_rcu_read_lock_)
#define _Acquires_rcu_ _Acquires_lock_(_Global_rcu_read_lock_)
#define _Releases_rcu_ _Releases_lock_(_Global_rcu_read_lock_)
#define _Analysis_assume_rcu_held_ _Analysis_assume_lock_held_(_Global_rcu_read_lock_);
#define _Analysis_assume_rcu_not_held_ _Analysis_assume_lock_not_held_(_Global_rcu_read_lock_);
#define _Analysis_assume_rcu_acquired_ _Analysis_assume_lock_acquired_(_Global_rcu_read_lock_);
#define _Analysis_assume_rcu_released_ _Analysis_assume_lock_released_(_Global_rcu_read_lock_);

typedef enum _RCU_CALLBACK_TYPE
{
    RCU_CALLBACK_CALL = 1,
    RCU_CALLBACK_FREE,
    RCU_CALLBACK_SYNC,
} RCU_CALLBACK_TYPE;
typedef struct _RCU_CALLBACK RCU_CALLBACK;
typedef _Function_class_(RCU_CALLBACK_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
RCU_CALLBACK_FN(_In_ RCU_CALLBACK *);
typedef RCU_CALLBACK_FN *PRCU_CALLBACK_FN;

struct _RCU_CALLBACK
{
    RCU_CALLBACK *Next;
    RCU_CALLBACK_TYPE Type;
    union
    {
        PRCU_CALLBACK_FN Func;
        ULONG_PTR Offset;
        KEVENT Done;
    };
};

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_saves_
_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_rcu_
static inline KIRQL RcuReadLock(VOID)
{
    _Analysis_assume_rcu_acquired_;
    return KeRaiseIrqlToDpcLevel();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Releases_rcu_
static inline VOID
RcuReadUnlock(_In_ _Notliteral_ _IRQL_restores_ KIRQL Irql)
{
    _Analysis_assume_rcu_released_;
    KeLowerIrql(Irql);
}

_IRQL_requires_min_(DISPATCH_LEVEL)
_Acquires_rcu_
static inline VOID RcuReadLockAtDpcLevel(VOID)
{
    _Analysis_assume_rcu_acquired_;
}

_IRQL_requires_min_(DISPATCH_LEVEL)
_Releases_rcu_
static inline VOID
RcuReadUnlockFromDpcLevel(VOID)
{
    _Analysis_assume_rcu_released_;
}

// TODO: replace __rcu with proper SAL annotations perhaps?
#define __rcu

#define RcuInitPointer(P, V) WritePointerNoFence(&(P), V)
#define RcuAssignPointer(P, V) WritePointerRelease(&(P), V)
#define RcuAccessPointer(P) ReadPointerNoFence(&(P))

_Requires_rcu_held_
static inline PVOID
__RcuDereference(_In_ _Interlocked_operand_ PVOID CONST volatile *Source)
{
    return ReadPointerNoFence(Source);
}
#define RcuDereference(Type, P) ((Type *)__RcuDereference(&(P)))

_Requires_lock_held_(Lock)
static inline PVOID
__RcuDereferenceProtected(_In_ PVOID *Address, _In_ PVOID Lock)
{
    return *Address;
}
#define RcuDereferenceProtected(Type, P, Lock) ((Type *)__RcuDereferenceProtected(&(P), Lock))

_IRQL_requires_max_(APC_LEVEL)
VOID RcuSynchronize(VOID);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
__RcuCall(_Inout_ RCU_CALLBACK *Head);

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
RcuCall(_Out_ RCU_CALLBACK *Head, _In_ RCU_CALLBACK_FN Func)
{
    Head->Type = RCU_CALLBACK_CALL;
    Head->Func = Func;
    __RcuCall(Head);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static inline VOID
__RcuFree(_Out_ RCU_CALLBACK *Head, _In_ SIZE_T Offset)
{
    Head->Type = RCU_CALLBACK_FREE;
    Head->Offset = Offset;
    __RcuCall(Head);
}

#define RcuFree(Type, Head, Member) __RcuFree(&((Type *)(Head))->Member, FIELD_OFFSET(Type, Member))

_IRQL_requires_max_(APC_LEVEL)
VOID RcuBarrier(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RcuDriverEntry(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID RcuUnload(VOID);
