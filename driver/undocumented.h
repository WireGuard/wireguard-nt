/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#pragma once

#include <ntifs.h> /* Must be included before <wdm.h> */
#include <wdm.h>

typedef enum
{
    SystemExtendedHandleInformation = 0x40
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ACCESS_MASK GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    ULONG *ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
ZwYieldExecution(VOID);

NTSYSAPI
BOOLEAN
NTAPI
SystemPrng(_Out_writes_bytes_all_(Len) PVOID RandomData, _In_ SIZE_T Len);

#define IOCTL_NSI_SET_PARAMETER CTL_CODE(0x12, 2, METHOD_NEITHER, 0)
#define IOCTL_NSI_SET_ALL_PARAMETERS CTL_CODE(0x12, 4, METHOD_NEITHER, 0)
#define IOCTL_NSI_SET_ALL_PERSISTENT_PARAMETERS_WITH_MASK CTL_CODE(0x12, 19, METHOD_NEITHER, 0)
typedef struct _NSI_SET_ALL_PARAMETERS
{
    ULONG_PTR Unknown1;
    ULONG_PTR Unknown2;
    VOID *ModuleIdFromFamily;
    ULONG ParamType;
    ULONG Unknown3;
    ULONG Unknown4;
    VOID *MibIpInterfaceRowAfterFamily;
    ULONG Unknown5;
    VOID *OtherOptions;
    ULONG Unknown6;
} NSI_SET_ALL_PARAMETERS;
#ifdef _WIN64
typedef struct _NSI_SET_ALL_PARAMETERS_32
{
    ULONG Unknown1;
    ULONG Unknown2;
    ULONG ModuleIdFromFamily;
    ULONG ParamType;
    ULONG Unknown3;
    ULONG Unknown4;
    ULONG MibIpInterfaceRowAfterFamily;
    ULONG Unknown5;
    ULONG OtherOptions;
    ULONG Unknown6;
} NSI_SET_ALL_PARAMETERS_32;
#endif