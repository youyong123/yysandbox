#include "main.h"
#include "file.h"
#include <Strsafe.h>

DRIVER_INITIALIZE 	DriverEntry;
DRIVER_DISPATCH 	dispatch_pass;
DRIVER_UNLOAD 		driver_unload;
DRIVER_DISPATCH 	dispatch_create;
DRIVER_DISPATCH 	dispatch_close;
DRIVER_DISPATCH 	dispatch_ictl;


NTSTATUS 	DriverEntry (PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath);
VOID 		driver_unload(PDRIVER_OBJECT DriverObject);
NTSTATUS 	dispatch_create(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS 	dispatch_close(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS 	dispatch_ictl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, driver_unload)
#pragma alloc_text(PAGE, dispatch_create)
#pragma alloc_text(PAGE, dispatch_close)
#pragma alloc_text(PAGE, dispatch_ictl)
#endif


PDRIVER_OBJECT					g_driver_obj = NULL;
PDEVICE_OBJECT					g_device_obj = NULL;
WCHAR							g_symbol_name[MAXNAMELEN];
WCHAR							g_device_name[MAXNAMELEN];
WCHAR							g_port_name[MAXNAMELEN];

NTSTATUS dispatch_create(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PAGED_CODE();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS dispatch_close(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PAGED_CODE();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS dispatch_ictl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
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
	default:
		break;
	}

	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}



VOID driver_unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceDosName;
	PAGED_CODE();
	if (g_device_obj)
	{
		IoUnregisterShutdownNotification(g_device_obj);
		IoDeleteDevice(g_device_obj);
		g_device_obj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	IoDeleteSymbolicLink(&deviceDosName);
}

NTSTATUS dispatch_pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
	UNICODE_STRING  deviceName = {0};
	UNICODE_STRING  deviceDosName = {0};
	int nIndex = 0;

	UNREFERENCED_PARAMETER( RegistryPath );
	
#ifdef DBG
	__debugbreak();
#endif

	g_driver_obj = DriverObject;


	for (; nIndex < IRP_MJ_MAXIMUM_FUNCTION; ++nIndex)
	{
		DriverObject->MajorFunction[nIndex] = dispatch_pass;
	}
	DriverObject->DriverUnload = driver_unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ictl;

	RtlInitUnicodeString(&deviceName, g_device_name);
	status = IoCreateDevice(DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_NETWORK,
		0,
		FALSE,
		&g_device_obj);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToDelDevice = TRUE;

	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	status = IoCreateSymbolicLink(&deviceDosName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create Symbolink name failed!\n"));
		goto err_ret;
	}

	bNeedToDelSym = TRUE;
	status = sw_init_minifliter(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitMinifilter = TRUE;

    return status;
err_ret:

	if (bNeedToDelSym)
	{
		RtlInitUnicodeString(&deviceDosName, g_symbol_name);
		IoDeleteSymbolicLink(&deviceDosName);
	}

	if (bNeedToDelDevice)
	{
		IoDeleteDevice(g_device_obj);
		g_device_obj = NULL;
	}
	if (bNeedToUninitMinifilter)
	{
		sw_uninit_minifliter(DriverObject);
	}
	return status;
}
