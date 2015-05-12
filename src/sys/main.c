#include "main.h"
#include "file.h"
#include "lib.h"
#include "sblist.h"
#include <Strsafe.h>

DRIVER_INITIALIZE 	DriverEntry;
DRIVER_DISPATCH 	DispatchPass;
DRIVER_UNLOAD 		DriverUnload;
DRIVER_DISPATCH 	DispatchCreate;
DRIVER_DISPATCH 	DispatchClose;
DRIVER_DISPATCH 	DispatchControl;


NTSTATUS 	DriverEntry (PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath);
VOID 		DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS 	DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS 	DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS 	DispatchControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchCreate)
#pragma alloc_text(PAGE, DispatchClose)
#pragma alloc_text(PAGE, DispatchControl)
#endif


PDRIVER_OBJECT					g_DriverObj = NULL;
PDEVICE_OBJECT					g_DeviceObj = NULL;
WCHAR							g_SymbolName[MAXNAMELEN];
WCHAR							g_DeviceName[MAXNAMELEN];
WCHAR							g_PortName[MAXNAMELEN];

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PAGED_CODE();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PAGED_CODE();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{

	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;

	PAGED_CODE();

	irpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Information = 0;
	ioBuf = pIrp->AssociatedIrp.SystemBuffer;
	inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	
	switch (ioControlCode)
	{
	case IOCTL_SET_SANDBOX_PATH:
		status = SbSetSandBoxPath(ioBuf,inBufLength);
		break;
	default:
		break;
	}

	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}



VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceDosName;
	PAGED_CODE();
	SbUnInitProcessList();
	if (g_DeviceObj)
	{
		IoUnregisterShutdownNotification(g_DeviceObj);
		IoDeleteDevice(g_DeviceObj);
		g_DeviceObj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_SymbolName);
	IoDeleteSymbolicLink(&deviceDosName);
}

NTSTATUS DispatchPass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS
DriverEntry (
     PDRIVER_OBJECT DriverObject,
     PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
	BOOLEAN bNeedToDelDevice = FALSE;
	BOOLEAN bNeedToDelSym = FALSE;
	BOOLEAN bNeedToUninitMinifilter = FALSE;
	BOOLEAN bNeedToUninitProcmon = FALSE;
	BOOLEAN bNeedToUninitRegmon = FALSE;
	BOOLEAN bNeedToUninitProcessList = FALSE;
	UNICODE_STRING  deviceName = {0};
	UNICODE_STRING  deviceDosName = {0};
	int				nIndex = 0;

	UNREFERENCED_PARAMETER( RegistryPath );
	
	status = InitLib();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	SbInitProcessList();
	bNeedToUninitProcessList = TRUE;

#ifdef DBG
	__debugbreak();
#endif

	g_DriverObj = DriverObject;


	for (; nIndex < IRP_MJ_MAXIMUM_FUNCTION; ++nIndex)
	{
		DriverObject->MajorFunction[nIndex] = DispatchPass;
	}
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

	RtlInitUnicodeString(&deviceName, g_DeviceName);
	status = IoCreateDevice(DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_NETWORK,
		0,
		FALSE,
		&g_DeviceObj);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToDelDevice = TRUE;

	RtlInitUnicodeString(&deviceDosName, g_SymbolName);
	status = IoCreateSymbolicLink(&deviceDosName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create Symbolink name failed!\n"));
		goto err_ret;
	}

	bNeedToDelSym = TRUE;
	status = SbInitMinifilter(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitMinifilter = TRUE;

    return status;
err_ret:

	if (bNeedToUninitProcessList)
	{
		SbUnInitProcessList();
	}

	if (bNeedToDelSym)
	{
		RtlInitUnicodeString(&deviceDosName, g_SymbolName);
		IoDeleteSymbolicLink(&deviceDosName);
	}

	if (bNeedToDelDevice)
	{
		IoDeleteDevice(g_DeviceObj);
		g_DeviceObj = NULL;
	}
	if (bNeedToUninitMinifilter)
	{
		SbUninitMinifilter(DriverObject);
	}
	return status;
}
