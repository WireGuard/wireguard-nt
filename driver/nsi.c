/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2026 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "interlocked.h"
#include "containers.h"
#include "device.h"
#include "messages.h"
#include "undocumented.h"
#include "nsi.h"
#include <netiodef.h>
#include <netioapi.h>

static DRIVER_OBJECT *DriverObj;
static HANDLE IpInterfaceNotifier;
static DEVICE_OBJECT *FilterDevice, *NsiDevice;
static EX_RUNDOWN_REF FilterRundown;
static DRIVER_DISPATCH *PriorDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
static LIST_ENTRY DeviceList;
static EX_PUSH_LOCK DeviceListLock, FilterLock;

static VOID
IpInterfaceChangeNotification(
    _In_opt_ PVOID CallerContext,
    _In_opt_ PMIB_IPINTERFACE_ROW Row,
    _In_ MIB_NOTIFICATION_TYPE NotificationType)
{
    if ((NotificationType != MibAddInstance && NotificationType != MibParameterNotification) || !Row ||
        (NotificationType == MibParameterNotification && (!Row->NlMtu || Row->NlMtu == ~0U)))
        return;
    MuAcquirePushLockShared(&DeviceListLock);
    WG_DEVICE *IterWg, *Wg = NULL;
    LIST_FOR_EACH_ENTRY (IterWg, &DeviceList, DeviceList)
    {
        if (IterWg->InterfaceLuid.Value == Row->InterfaceLuid.Value)
        {
            Wg = IterWg;
            break;
        }
    }
    if (!Wg)
        goto cleanupDeviceListLock;
    ULONG *Mtu;
    if (Row->Family == AF_INET)
        Mtu = &Wg->Mtu4;
    else if (Row->Family == AF_INET6)
        Mtu = &Wg->Mtu6;
    else
        goto cleanupDeviceListLock;
    if (NotificationType == MibAddInstance && !*Mtu)
    {
        if ((!Row->NlMtu || Row->NlMtu == ~0U) && !NT_SUCCESS(GetIpInterfaceEntry(Row)))
            goto cleanupDeviceListLock;
        *Mtu = min(MTU_MAX, Row->NlMtu);
        if (Row->NlMtu == MTU_MAX || !Row->NlMtu || Row->NlMtu == ~0U)
        {
            Row->SitePrefixLength = 0;
            Row->NlMtu = 1500 - DATA_PACKET_MINIMUM_LENGTH;
            if (NT_SUCCESS(SetIpInterfaceEntry(Row)))
                *Mtu = min(MTU_MAX, Row->NlMtu);
        }
    }
    else if (NotificationType == MibParameterNotification)
        *Mtu = min(MTU_MAX, Row->NlMtu);
cleanupDeviceListLock:
    MuReleasePushLockShared(&DeviceListLock);
}

static_assert(
    FIELD_SIZE(MIB_IPINTERFACE_ROW, NlMtu) == FIELD_SIZE(NSI_IP_INTERFACE_RW, NlMtu) &&
    FIELD_SIZE(MIB_IPINTERFACE_ROW, NlMtu) == FIELD_SIZE(NSI_IP_SUBINTERFACE_RW, NlMtu),
    "NlMtu sizes must match across MIB_IPINTERFACE_ROW, NSI_IP_INTERFACE_RW, and NSI_IP_SUBINTERFACE_RW");

_Success_(return)
static BOOLEAN
TryBuildMTURow(_In_ IRP *Irp, _Out_ MIB_IPINTERFACE_ROW *Row)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->MajorFunction != IRP_MJ_DEVICE_CONTROL ||
        Stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_NSI_SET_ALL_PARAMETERS)
        return FALSE;
    NPI_MODULEID ModuleId = { 0 };
    __try
    {
        NSI_SET_ALL_PARAMETERS Params;
        UCHAR *UserBuffer = Stack->Parameters.DeviceIoControl.Type3InputBuffer;
        ULONG Len = Stack->Parameters.DeviceIoControl.InputBufferLength;
        BOOLEAN ShouldProbe = Irp->RequestorMode != KernelMode;
#ifdef _WIN64
        if (IoIs32bitProcess(Irp))
        {
            NSI_SET_ALL_PARAMETERS_32 Params32;
            if (Len < sizeof(Params32))
                return FALSE;
            if (ShouldProbe)
                ProbeForRead(UserBuffer, sizeof(Params32), 1);
            RtlCopyMemory(&Params32, UserBuffer, sizeof(Params32));
            RtlZeroMemory(&Params, sizeof(Params));
            Params.ModuleId = (PVOID)(ULONG_PTR)Params32.ModuleId;
            Params.ObjectIndex = Params32.ObjectIndex;
            Params.KeyStruct = (PVOID)(ULONG_PTR)Params32.KeyStruct;
            Params.KeyStructLength = Params32.KeyStructLength;
            Params.RwParameterStruct = (PVOID)(ULONG_PTR)Params32.RwParameterStruct;
            Params.RwParameterStructLength = Params32.RwParameterStructLength;
        }
        else
#endif
        {
            if (Len < sizeof(Params))
                return FALSE;
            if (ShouldProbe)
                ProbeForRead(UserBuffer, sizeof(Params), 1);
            RtlCopyMemory(&Params, UserBuffer, sizeof(Params));
        }
        if (Params.KeyStructLength < sizeof(Row->InterfaceLuid))
            return FALSE;
        ULONG MtuOffset;
        if ((ULONG)Params.ObjectIndex == NlInterfaceObject &&
            Params.RwParameterStructLength >= FIELD_OFFSET(NSI_IP_INTERFACE_RW, NlMtu) + FIELD_SIZE(NSI_IP_INTERFACE_RW, NlMtu))
            MtuOffset = FIELD_OFFSET(NSI_IP_INTERFACE_RW, NlMtu);
        else if ((ULONG)Params.ObjectIndex == NlSubInterfaceObject &&
                 Params.RwParameterStructLength >= FIELD_OFFSET(NSI_IP_SUBINTERFACE_RW, NlMtu) + FIELD_SIZE(NSI_IP_SUBINTERFACE_RW, NlMtu))
            MtuOffset = FIELD_OFFSET(NSI_IP_SUBINTERFACE_RW, NlMtu);
        else
            return FALSE;
        if (ShouldProbe)
            ProbeForRead(Params.ModuleId, sizeof(ModuleId), 1);
        RtlCopyMemory(&ModuleId, Params.ModuleId, sizeof(ModuleId));
        if (ShouldProbe)
            ProbeForRead(Params.KeyStruct, sizeof(Row->InterfaceLuid), 1);
        RtlCopyMemory(&Row->InterfaceLuid, Params.KeyStruct, sizeof(Row->InterfaceLuid));
        if (ShouldProbe)
            ProbeForRead((UCHAR *)Params.RwParameterStruct + MtuOffset, sizeof(Row->NlMtu), 1);
        RtlCopyMemory(&Row->NlMtu, (UCHAR *)Params.RwParameterStruct + MtuOffset, sizeof(Row->NlMtu));
    }
#pragma warning(suppress : 6320)
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
    if (!Row->NlMtu || Row->NlMtu == ~0U)
        return FALSE;
    if (RtlEqualMemory(&NPI_MS_IPV4_MODULEID, &ModuleId, sizeof(ModuleId)))
        Row->Family = AF_INET;
    else if (RtlEqualMemory(&NPI_MS_IPV6_MODULEID, &ModuleId, sizeof(ModuleId)))
        Row->Family = AF_INET6;
    else
        return FALSE;
    return TRUE;
}

#pragma prefast(push)
#pragma prefast(disable : cpp/drivers/invalid-function-class-typedef) /* It's fine to make this paged because it's only ever called from userspace. */
static DRIVER_DISPATCH_PAGED FilterDispatch;
_Use_decl_annotations_
static NTSTATUS
FilterDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    if (DeviceObject != ReadPointerNoFence(&FilterDevice))
        return PriorDispatch[IoGetCurrentIrpStackLocation(Irp)->MajorFunction](DeviceObject, Irp);

    if (!ExAcquireRundownProtection(&FilterRundown))
    {
        Irp->IoStatus.Status = STATUS_DEVICE_REMOVED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_REMOVED;
    }

    MIB_IPINTERFACE_ROW Row = { 0 };
    BOOLEAN ValidMTURow = TryBuildMTURow(Irp, &Row);
    IoSkipCurrentIrpStackLocation(Irp);
    NTSTATUS Status = IoCallDriver(NsiDevice, Irp);
    if (ValidMTURow && NT_SUCCESS(Status) && Status != STATUS_PENDING)
        IpInterfaceChangeNotification(NULL, &Row, MibParameterNotification);
    ExReleaseRundownProtection(&FilterRundown);
    return Status;
}
#pragma prefast(pop)

static NTSTATUS
Attach(VOID)
{
    NTSTATUS Status =
        NotifyIpInterfaceChange(AF_UNSPEC, IpInterfaceChangeNotification, NULL, FALSE, &IpInterfaceNotifier);
    if (!NT_SUCCESS(Status))
        return Status;

    UNICODE_STRING NsiName = RTL_CONSTANT_STRING(L"\\Device\\Nsi");
    PFILE_OBJECT NsiFileObject;
    Status = IoGetDeviceObjectPointer(&NsiName, FILE_READ_ATTRIBUTES, &NsiFileObject, &NsiDevice);
    if (!NT_SUCCESS(Status))
        goto cleanupIpInterfaceNotifier;

    Status = IoCreateDevice(DriverObj, 0, NULL, NsiDevice->DeviceType, 0, FALSE, &FilterDevice);
    if (!NT_SUCCESS(Status))
        goto cleanupFileObject;
    FilterDevice->Flags |= NsiDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);

    ExInitializeRundownProtection(&FilterRundown);

    PDEVICE_OBJECT Attached = IoAttachDeviceToDeviceStack(FilterDevice, NsiDevice);
    if (!Attached)
    {
        Status = STATUS_DEVICE_REMOVED;
        goto cleanupFilterDevice;
    }
    NsiDevice = Attached;
    FilterDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    ObReferenceObject(NsiDevice);
    ObDereferenceObject(NsiFileObject);
    return STATUS_SUCCESS;

cleanupFilterDevice:
    {
        DEVICE_OBJECT *FilterDeviceToDelete = FilterDevice;
        WritePointerNoFence(&FilterDevice, NULL);
        IoDeleteDevice(FilterDeviceToDelete);
    }
cleanupFileObject:
    ObDereferenceObject(NsiFileObject);
cleanupIpInterfaceNotifier:
    CancelMibChangeNotify2(IpInterfaceNotifier);
    return Status;
}

static VOID
Detach(VOID)
{
    CancelMibChangeNotify2(IpInterfaceNotifier);
    IoDetachDevice(NsiDevice);
    ExWaitForRundownProtectionRelease(&FilterRundown);
    DEVICE_OBJECT *FilterDeviceToDelete = FilterDevice;
    WritePointerNoFence(&FilterDevice, NULL);
    IoDeleteDevice(FilterDeviceToDelete);
    ObDereferenceObject(NsiDevice);
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, NsiDriverEntry)
#endif
#pragma prefast(push)
#pragma prefast(disable : cpp/drivers/illegal-field-access-2) /* This is a driver entry routine; we've just split them up. */
_Use_decl_annotations_
VOID
NsiDriverEntry(DRIVER_OBJECT *DriverObject)
{
    DriverObj = DriverObject;
    InitializeListHead(&DeviceList);
    MuInitializePushLock(&DeviceListLock);
    MuInitializePushLock(&FilterLock);
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        PriorDispatch[i] = DriverObject->MajorFunction[i];
        DriverObject->MajorFunction[i] = FilterDispatch;
    }
}
#pragma prefast(pop)

_Use_decl_annotations_
NTSTATUS
NsiActivate(WG_DEVICE *Wg)
{
    NTSTATUS Status;
    MuAcquirePushLockExclusive(&FilterLock);
    if (IsListEmpty(&DeviceList))
    {
        Status = Attach();
        if (!NT_SUCCESS(Status))
        {
            MuReleasePushLockExclusive(&FilterLock);
            return Status;
        }
    }
    MuAcquirePushLockExclusive(&DeviceListLock);
    InsertTailList(&DeviceList, &Wg->DeviceList);
    MuReleasePushLockExclusive(&DeviceListLock);
    MuReleasePushLockExclusive(&FilterLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
NsiDeactivate(WG_DEVICE *Wg)
{
    MuAcquirePushLockExclusive(&FilterLock);
    MuAcquirePushLockExclusive(&DeviceListLock);
    RemoveEntryList(&Wg->DeviceList);
    BOOLEAN NowEmpty = IsListEmpty(&DeviceList);
    MuReleasePushLockExclusive(&DeviceListLock);
    if (NowEmpty)
        Detach();
    MuReleasePushLockExclusive(&FilterLock);
}
