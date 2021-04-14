/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include "arithmetic.h"
#include "crypto.h"

enum NOISE_LENGTHS
{
    NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
    NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
    NOISE_TIMESTAMP_LEN = sizeof(UINT64) + sizeof(UINT32),
    NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
    NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};

#define NoiseEncryptedLen(PlainLen) ((PlainLen) + NOISE_AUTHTAG_LEN)

enum COOKIE_VALUES
{
    COOKIE_SECRET_MAX_AGE = 2 * 60,
    COOKIE_SECRET_LATENCY = 5,
    COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCE_SIZE,
    COOKIE_LEN = 16
};

enum COUNTER_VALUES
{
    COUNTER_BITS_TOTAL = 8192,
    COUNTER_REDUNDANT_BITS = BITS_PER_POINTER,
    COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
};

#define REKEY_AFTER_MESSAGES (1ULL << 60)
#define REJECT_AFTER_MESSAGES (~0ULL - COUNTER_WINDOW_SIZE - 1)
#define REKEY_TIMEOUT 5
#define REKEY_TIMEOUT_JITTER_MAX_SYS_TIME_UNITS (SYS_TIME_UNITS_PER_SEC / 3)
#define REKEY_AFTER_TIME 120
#define REJECT_AFTER_TIME 180
#define INITIATIONS_PER_SECOND 50
#define MAX_PEERS_PER_DEVICE (1U << 20)
#define KEEPALIVE_TIMEOUT 10
#define MAX_TIMER_HANDSHAKES (90 / REKEY_TIMEOUT)

enum L4_LENGTHS
{
    UDP_HEADER_LEN = 8,
};

enum MESSAGE_TYPE
{
    MESSAGE_TYPE_INVALID = 0,
    MESSAGE_TYPE_HANDSHAKE_INITIATION = 1,
    MESSAGE_TYPE_HANDSHAKE_RESPONSE = 2,
    MESSAGE_TYPE_HANDSHAKE_COOKIE = 3,
    MESSAGE_TYPE_DATA = 4
};

typedef struct _IPV4HDR
{
#if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
    UINT8 Ihl : 4, Version : 4;
#elif REG_DWORD == REG_DWORD_BIG_ENDIAN
    UINT8 Version : 4, Ihl : 4;
#endif
    UINT8 Tos;
    UINT16_BE TotLen;
    UINT16_BE Id;
    UINT16_BE FragOff;
    UINT8 Ttl;
    UINT8 Protocol;
    UINT16_BE Check;
    UINT32_BE Saddr;
    UINT32_BE Daddr;
} IPV4HDR;

typedef struct _IPV6HDR
{
#if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
    UINT8 Priority : 4, Version : 4;
#elif REG_DWORD == REG_DWORD_BIG_ENDIAN
    UINT8 Version : 4, Priority : 4;
#endif
    UINT8 FlowLbl[3];
    UINT16_BE PayloadLen;
    UINT8 Nexthdr;
    UINT8 HopLimit;
    IN6_ADDR Saddr;
    IN6_ADDR Daddr;
} IPV6HDR;

typedef struct _MESSAGE_HEADER
{
    /* The actual layout of this that we want is:
     * u8 type
     * u8 reserved_zero[3]
     *
     * But it turns out that by encoding this as little endian,
     * we achieve the same thing, and it makes checking faster.
     */
    UINT32_LE Type;
} MESSAGE_HEADER;

typedef struct _MESSAGE_MACS
{
    UINT8 Mac1[COOKIE_LEN];
    UINT8 Mac2[COOKIE_LEN];
} MESSAGE_MACS;

typedef struct _MESSAGE_HANDSHAKE_INITIATION
{
    MESSAGE_HEADER Header;
    UINT32_LE SenderIndex;
    UINT8 UnencryptedEphemeral[NOISE_PUBLIC_KEY_LEN];
    UINT8 EncryptedStatic[NoiseEncryptedLen(NOISE_PUBLIC_KEY_LEN)];
    UINT8 EncryptedTimestamp[NoiseEncryptedLen(NOISE_TIMESTAMP_LEN)];
    MESSAGE_MACS Macs;
} MESSAGE_HANDSHAKE_INITIATION;

typedef struct _MESSAGE_HANDSHAKE_RESPONSE
{
    MESSAGE_HEADER Header;
    UINT32_LE SenderIndex;
    UINT32_LE ReceiverIndex;
    UINT8 UnencryptedEphemeral[NOISE_PUBLIC_KEY_LEN];
    UINT8 EncryptedNothing[NoiseEncryptedLen(0)];
    MESSAGE_MACS Macs;
} MESSAGE_HANDSHAKE_RESPONSE;

typedef struct _MESSAGE_HANDSHAKE_COOKIE
{
    MESSAGE_HEADER Header;
    UINT32_LE ReceiverIndex;
    UINT8 Nonce[COOKIE_NONCE_LEN];
    UINT8 EncryptedCookie[NoiseEncryptedLen(COOKIE_LEN)];
} MESSAGE_HANDSHAKE_COOKIE;

typedef struct _MESSAGE_DATA
{
    MESSAGE_HEADER Header;
    UINT32_LE KeyIdx;
    UINT64_LE Counter;
    UINT8 EncryptedData[];
} MESSAGE_DATA;

#define MessageDataLen(PlainLen) (NoiseEncryptedLen(PlainLen) + sizeof(MESSAGE_DATA))

enum MESSAGE_ALIGNMENTS
{
    MESSAGE_PADDING_MULTIPLE = 16,
    MESSAGE_MINIMUM_LENGTH = MessageDataLen(0)
};

#define DATA_PACKET_MINIMUM_LENGTH (max(sizeof(IPV4HDR), sizeof(IPV6HDR)) + UDP_HEADER_LEN + MESSAGE_MINIMUM_LENGTH)
#define MTU_MAX (ALIGN_DOWN_BY_T(SIZE_T, MAXLONG, MESSAGE_PADDING_MULTIPLE) - DATA_PACKET_MINIMUM_LENGTH)
