/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

static inline IN_ADDR *
Ip4(UINT8 A, UINT8 B, UINT8 C, UINT8 D);
static inline IN6_ADDR *
Ip6(UINT32 A, UINT32 B, UINT32 C, UINT32 D);
static WG_PEER *InitPeer(VOID);

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, Ip4)
#    pragma alloc_text(INIT, Ip6)
#    pragma alloc_text(INIT, InitPeer)
#    pragma alloc_text(INIT, AllowedIpsSelftest)
#endif

static inline IN_ADDR *
Ip4(UINT8 A, UINT8 B, UINT8 C, UINT8 D)
{
    static IN_ADDR Ip;
    UINT8 *Split = (UINT8 *)&Ip;

    Split[0] = A;
    Split[1] = B;
    Split[2] = C;
    Split[3] = D;
    return &Ip;
}

static inline IN6_ADDR *
Ip6(UINT32 A, UINT32 B, UINT32 C, UINT32 D)
{
    static IN6_ADDR Ip;
    UINT32_BE *Split = (UINT32_BE *)&Ip;

    Split[0] = CpuToBe32(A);
    Split[1] = CpuToBe32(B);
    Split[2] = CpuToBe32(C);
    Split[3] = CpuToBe32(D);
    return &Ip;
}

static WG_PEER *InitPeer(VOID)
{
    WG_PEER *Peer = MemAllocateAndZero(sizeof(*Peer));

    if (!Peer)
        return NULL;
    KrefInit(&Peer->Refcount);
    InitializeListHead(&Peer->AllowedIpsList);
    return Peer;
}

#define Insert(Version, Mem, Ipa, Ipb, Ipc, Ipd, Cidr) \
    AllowedIpsInsertV##Version(&t, Ip##Version(Ipa, Ipb, Ipc, Ipd), Cidr, Mem, &Mutex)

#define MaybeFail() \
    do \
    { \
        ++i; \
        if (!_s) \
        { \
            LogDebug("allowedips self-test %zu: FAIL", i); \
            Success = FALSE; \
        } \
    } while (0)

#define Test(Version, Mem, Ipa, Ipb, Ipc, Ipd) \
    do \
    { \
        BOOLEAN _s = Lookup(t.Root##Version, (Version) == 4 ? 32 : 128, Ip##Version(Ipa, Ipb, Ipc, Ipd)) == (Mem); \
        MaybeFail(); \
    } while (0)

#define TestNegative(Version, Mem, Ipa, Ipb, Ipc, Ipd) \
    do \
    { \
        BOOLEAN _s = Lookup(t.Root##Version, (Version) == 4 ? 32 : 128, Ip##Version(Ipa, Ipb, Ipc, Ipd)) != (Mem); \
        MaybeFail(); \
    } while (0)

#define TestBoolean(Cond) \
    do \
    { \
        BOOLEAN _s = (Cond); \
        MaybeFail(); \
    } while (0)

_Use_decl_annotations_
BOOLEAN
AllowedIpsSelftest(VOID)
{
    BOOLEAN FoundA = FALSE, FoundB = FALSE, FoundC = FALSE, FoundD = FALSE, FoundE = FALSE, FoundOther = FALSE;
    WG_PEER *A = InitPeer(), *B = InitPeer(), *C = InitPeer(), *D = InitPeer(), *E = InitPeer(), *F = InitPeer(),
            *G = InitPeer(), *H = InitPeer();
    ALLOWEDIPS_NODE *IterNode;
    BOOLEAN Success = FALSE;
    ALLOWEDIPS_TABLE t;
    EX_PUSH_LOCK Mutex;
    SIZE_T i = 0, Count = 0;
    UINT64_BE Part;
    __declspec(align(8)) UINT8 Ip[16];

    MuInitializePushLock(&Mutex);
    MuAcquirePushLockExclusive(&Mutex);
    AllowedIpsInit(&t);

    if (!A || !B || !C || !D || !E || !F || !G || !H)
    {
        LogDebug("allowedips self-test malloc: FAIL");
        goto free;
    }

    Insert(4, A, 192, 168, 4, 0, 24);
    Insert(4, B, 192, 168, 4, 4, 32);
    Insert(4, C, 192, 168, 0, 0, 16);
    Insert(4, D, 192, 95, 5, 64, 27);
    /* replaces previous entry, and maskself is required */
    Insert(4, C, 192, 95, 5, 65, 27);
    Insert(6, D, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128);
    Insert(6, C, 0x26075300, 0x60006b00, 0, 0, 64);
    Insert(4, E, 0, 0, 0, 0, 0);
    Insert(6, E, 0, 0, 0, 0, 0);
    /* replaces previous entry */
    Insert(6, F, 0, 0, 0, 0, 0);
    Insert(6, G, 0x24046800, 0, 0, 0, 32);
    /* maskself is required */
    Insert(6, H, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 64);
    Insert(6, A, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 128);
    Insert(6, C, 0x24446800, 0x40e40800, 0xdeaebeef, 0xdefbeef, 128);
    Insert(6, B, 0x24446800, 0xf0e40800, 0xeeaebeef, 0, 98);
    Insert(4, G, 64, 15, 112, 0, 20);
    /* maskself is required */
    Insert(4, H, 64, 15, 123, 211, 25);
    Insert(4, A, 10, 0, 0, 0, 25);
    Insert(4, B, 10, 0, 0, 128, 25);
    Insert(4, A, 10, 1, 0, 0, 30);
    Insert(4, B, 10, 1, 0, 4, 30);
    Insert(4, C, 10, 1, 0, 8, 29);
    Insert(4, D, 10, 1, 0, 16, 29);

    Success = TRUE;

    Test(4, A, 192, 168, 4, 20);
    Test(4, A, 192, 168, 4, 0);
    Test(4, B, 192, 168, 4, 4);
    Test(4, C, 192, 168, 200, 182);
    Test(4, C, 192, 95, 5, 68);
    Test(4, E, 192, 95, 5, 96);
    Test(6, D, 0x26075300, 0x60006b00, 0, 0xc05f0543);
    Test(6, C, 0x26075300, 0x60006b00, 0, 0xc02e01ee);
    Test(6, F, 0x26075300, 0x60006b01, 0, 0);
    Test(6, G, 0x24046800, 0x40040806, 0, 0x1006);
    Test(6, G, 0x24046800, 0x40040806, 0x1234, 0x5678);
    Test(6, F, 0x240467ff, 0x40040806, 0x1234, 0x5678);
    Test(6, F, 0x24046801, 0x40040806, 0x1234, 0x5678);
    Test(6, H, 0x24046800, 0x40040800, 0x1234, 0x5678);
    Test(6, H, 0x24046800, 0x40040800, 0, 0);
    Test(6, H, 0x24046800, 0x40040800, 0x10101010, 0x10101010);
    Test(6, A, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef);
    Test(4, G, 64, 15, 116, 26);
    Test(4, G, 64, 15, 127, 3);
    Test(4, G, 64, 15, 123, 1);
    Test(4, H, 64, 15, 123, 128);
    Test(4, H, 64, 15, 123, 129);
    Test(4, A, 10, 0, 0, 52);
    Test(4, B, 10, 0, 0, 220);
    Test(4, A, 10, 1, 0, 2);
    Test(4, B, 10, 1, 0, 6);
    Test(4, C, 10, 1, 0, 10);
    Test(4, D, 10, 1, 0, 20);

    Insert(4, A, 1, 0, 0, 0, 32);
    Insert(4, A, 64, 0, 0, 0, 32);
    Insert(4, A, 128, 0, 0, 0, 32);
    Insert(4, A, 192, 0, 0, 0, 32);
    Insert(4, A, 255, 0, 0, 0, 32);
    AllowedIpsRemoveByPeer(&t, A, &Mutex);
    TestNegative(4, A, 1, 0, 0, 0);
    TestNegative(4, A, 64, 0, 0, 0);
    TestNegative(4, A, 128, 0, 0, 0);
    TestNegative(4, A, 192, 0, 0, 0);
    TestNegative(4, A, 255, 0, 0, 0);

    AllowedIpsFree(&t, &Mutex);
    AllowedIpsInit(&t);
    Insert(4, A, 192, 168, 0, 0, 16);
    Insert(4, A, 192, 168, 0, 0, 24);
    AllowedIpsRemoveByPeer(&t, A, &Mutex);
    TestNegative(4, A, 192, 168, 0, 1);

    /* These will hit the NT_ASSERT(len < STACK_ENTRIES) in RootFreeRcu if
     * something goes wrong.
     */
    for (i = 0; i < 64; ++i)
    {
        Part = CpuToBe64(~0LLU << i);
        RtlFillMemory(Ip, 8, 0xff);
        RtlCopyMemory(Ip + 8, &Part, 8);
        AllowedIpsInsertV6(&t, (IN6_ADDR *)Ip, 128, A, &Mutex);
        RtlCopyMemory(Ip, &Part, 8);
        RtlFillMemory(Ip + 8, 8, 0);
        AllowedIpsInsertV6(&t, (IN6_ADDR *)Ip, 128, A, &Mutex);
    }
    RtlFillMemory(Ip, 16, 0);
    AllowedIpsInsertV6(&t, (IN6_ADDR *)Ip, 128, A, &Mutex);
    AllowedIpsFree(&t, &Mutex);

    AllowedIpsInit(&t);
    Insert(4, A, 192, 95, 5, 93, 27);
    Insert(6, A, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128);
    Insert(4, A, 10, 1, 0, 20, 29);
    Insert(6, A, 0x26075300, 0x6d8a6bf8, 0xdab1f1df, 0xc05f1523, 83);
    Insert(6, A, 0x26075300, 0x6d8a6bf8, 0xdab1f1df, 0xc05f1523, 21);
    LIST_FOR_EACH_ENTRY (IterNode, &A->AllowedIpsList, ALLOWEDIPS_NODE, PeerList)
    {
        UINT8 Cidr;
        ADDRESS_FAMILY Family = AllowedIpsReadNode(IterNode, Ip, &Cidr);

        ++Count;

        if (Cidr == 27 && Family == AF_INET && RtlEqualMemory(Ip, Ip4(192, 95, 5, 64), sizeof(IN_ADDR)))
            FoundA = TRUE;
        else if (
            Cidr == 128 && Family == AF_INET6 &&
            RtlEqualMemory(Ip, Ip6(0x26075300, 0x60006b00, 0, 0xc05f0543), sizeof(IN6_ADDR)))
            FoundB = TRUE;
        else if (Cidr == 29 && Family == AF_INET && RtlEqualMemory(Ip, Ip4(10, 1, 0, 16), sizeof(IN_ADDR)))
            FoundC = TRUE;
        else if (
            Cidr == 83 && Family == AF_INET6 &&
            RtlEqualMemory(Ip, Ip6(0x26075300, 0x6d8a6bf8, 0xdab1e000, 0), sizeof(IN6_ADDR)))
            FoundD = TRUE;
        else if (Cidr == 21 && Family == AF_INET6 && RtlEqualMemory(Ip, Ip6(0x26075000, 0, 0, 0), sizeof(IN6_ADDR)))
            FoundE = TRUE;
        else
            FoundOther = TRUE;
    }
    TestBoolean(Count == 5);
    TestBoolean(FoundA);
    TestBoolean(FoundB);
    TestBoolean(FoundC);
    TestBoolean(FoundD);
    TestBoolean(FoundE);
    TestBoolean(!FoundOther);

    if (Success)
        LogDebug("allowedips self-tests: pass");

free:
    AllowedIpsFree(&t, &Mutex);
    MemFree(A);
    MemFree(B);
    MemFree(C);
    MemFree(D);
    MemFree(E);
    MemFree(F);
    MemFree(G);
    MemFree(H);
    MuReleasePushLockExclusive(&Mutex);

    return Success;
}

#undef TestNegative
#undef Test
#undef Remove
#undef Insert
#undef InitPeer
