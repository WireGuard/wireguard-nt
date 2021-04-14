/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, PacketCounterSelftest)
#endif
_Use_decl_annotations_
BOOLEAN
PacketCounterSelftest(VOID)
{
    NOISE_REPLAY_COUNTER *Counter;
    ULONG TestNum = 0, i;
    BOOLEAN Success = TRUE;

    Counter = MemAllocate(sizeof(*Counter));
    if (!Counter)
    {
        LogDebug("nonce counter self-test malloc: FAIL");
        return FALSE;
    }

#define T_INIT \
    do \
    { \
        RtlZeroMemory(Counter, sizeof(*Counter)); \
        KeInitializeSpinLock(&Counter->Lock); \
    } while (0)
#define T_LIM (COUNTER_WINDOW_SIZE + 1)
#define T(n, V) \
    do \
    { \
        ++TestNum; \
        if (CounterValidate(Counter, n) != (V)) \
        { \
            LogDebug("nonce counter self-test %u: FAIL", TestNum); \
            Success = FALSE; \
        } \
    } while (0)

    T_INIT;
    /*  1 */ T(0, TRUE);
    /*  2 */ T(1, TRUE);
    /*  3 */ T(1, FALSE);
    /*  4 */ T(9, TRUE);
    /*  5 */ T(8, TRUE);
    /*  6 */ T(7, TRUE);
    /*  7 */ T(7, FALSE);
    /*  8 */ T(T_LIM, TRUE);
    /*  9 */ T(T_LIM - 1, TRUE);
    /* 10 */ T(T_LIM - 1, FALSE);
    /* 11 */ T(T_LIM - 2, TRUE);
    /* 12 */ T(2, TRUE);
    /* 13 */ T(2, FALSE);
    /* 14 */ T(T_LIM + 16, TRUE);
    /* 15 */ T(3, FALSE);
    /* 16 */ T(T_LIM + 16, FALSE);
    /* 17 */ T(T_LIM * 4, TRUE);
    /* 18 */ T(T_LIM * 4 - (T_LIM - 1), TRUE);
    /* 19 */ T(10, FALSE);
    /* 20 */ T(T_LIM * 4 - T_LIM, FALSE);
    /* 21 */ T(T_LIM * 4 - (T_LIM + 1), FALSE);
    /* 22 */ T(T_LIM * 4 - (T_LIM - 2), TRUE);
    /* 23 */ T(T_LIM * 4 + 1 - T_LIM, FALSE);
    /* 24 */ T(0, FALSE);
    /* 25 */ T(REJECT_AFTER_MESSAGES, FALSE);
    /* 26 */ T(REJECT_AFTER_MESSAGES - 1, TRUE);
    /* 27 */ T(REJECT_AFTER_MESSAGES, FALSE);
    /* 28 */ T(REJECT_AFTER_MESSAGES - 1, FALSE);
    /* 29 */ T(REJECT_AFTER_MESSAGES - 2, TRUE);
    /* 30 */ T(REJECT_AFTER_MESSAGES + 1, FALSE);
    /* 31 */ T(REJECT_AFTER_MESSAGES + 2, FALSE);
    /* 32 */ T(REJECT_AFTER_MESSAGES - 2, FALSE);
    /* 33 */ T(REJECT_AFTER_MESSAGES - 3, TRUE);
    /* 34 */ T(0, FALSE);

    T_INIT;
    for (i = 1; i <= COUNTER_WINDOW_SIZE; ++i)
        T(i, TRUE);
    T(0, TRUE);
    T(0, FALSE);

    T_INIT;
    for (i = 2; i <= COUNTER_WINDOW_SIZE + 1; ++i)
        T(i, TRUE);
    T(1, TRUE);
    T(0, FALSE);

    T_INIT;
    for (i = COUNTER_WINDOW_SIZE + 1; i-- > 0;)
        T(i, TRUE);

    T_INIT;
    for (i = COUNTER_WINDOW_SIZE + 2; i-- > 1;)
        T(i, TRUE);
    T(0, FALSE);

    T_INIT;
    for (i = COUNTER_WINDOW_SIZE + 1; i-- > 1;)
        T(i, TRUE);
    T(COUNTER_WINDOW_SIZE + 1, TRUE);
    T(0, FALSE);

    T_INIT;
    for (i = COUNTER_WINDOW_SIZE + 1; i-- > 1;)
        T(i, TRUE);
    T(0, TRUE);
    T(COUNTER_WINDOW_SIZE + 1, TRUE);

#undef T
#undef T_LIM
#undef T_INIT

    if (Success)
        LogDebug("nonce counter self-tests: pass");
    MemFree(Counter);
    return Success;
}
