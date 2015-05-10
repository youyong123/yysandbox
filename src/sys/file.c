#include "main.h"
#include "file.h"
#include "lpc.h"
#include <strsafe.h>
#include <Ntdddisk.h>

static PFLT_FILTER			g_FilterHandle = NULL;


CONST FLT_OPERATION_REGISTRATION g_callbacks[] = 
{
	{ IRP_MJ_CREATE,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO ,
	(PFLT_PRE_OPERATION_CALLBACK)sw_pre_create_callback,
	NULL},

	{ IRP_MJ_SET_INFORMATION,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	(PFLT_PRE_OPERATION_CALLBACK)sw_pre_setinfo_callback,
	NULL},

	{ IRP_MJ_OPERATION_END }
};




CONST FLT_REGISTRATION g_FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	g_callbacks,                        //  Operation g_callbacks
	(PFLT_FILTER_UNLOAD_CALLBACK)sw_unload,                          //  MiniFilterUnload
	(PFLT_INSTANCE_SETUP_CALLBACK)sw_InstanceSetup,					//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};


FORCEINLINE BOOLEAN  is_dir(PWCHAR pPath) 
{
	return pPath[wcslen(pPath) - 1] == L'\\';
}

NTSTATUS
sw_InstanceSetup (
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
	)
{
	PAGED_CODE();

	if (FLT_FSTYPE_RAW == VolumeFilesystemType)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	return STATUS_SUCCESS;
}



NTSTATUS sw_unload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNICODE_STRING deviceDosName;
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	sw_uninit_minifliter(g_driver_obj);


	if (g_device_obj)
	{
		IoDeleteDevice(g_device_obj);
		g_device_obj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	IoDeleteSymbolicLink(&deviceDosName);
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS sw_pre_create_callback( PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	NTSTATUS					status = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS	callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	ASSERT( Data->Iopb->MajorFunction == IRP_MJ_CREATE );

	if (Data->RequestorMode == KernelMode)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((PsGetCurrentProcessId() == (HANDLE)4) || (PsGetCurrentProcessId() == (HANDLE)0))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FltObjects || !FltObjects->Instance || !FltObjects->FileObject)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	if (FlagOn(Data->Iopb->TargetFileObject->Flags, FO_NAMED_PIPE) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_MAILSLOT))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->IrpFlags, IRP_CLOSE_OPERATION) || FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

    if (FlagOn( Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN )) 
	{ 
        return callbackStatus;
    }

    status = FltGetFileNameInformation( Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo );
    if (!NT_SUCCESS( status )) 
	{
        return callbackStatus;
    }

    status = FltParseFileNameInformation( nameInfo );
    if (!NT_SUCCESS( status )) 
	{
		goto RepPreCreateCleanup;
    }

RepPreCreateCleanup:

    if (nameInfo != NULL) 
	{
        FltReleaseFileNameInformation( nameInfo );
    }

	return callbackStatus;
}


FLT_PREOP_CALLBACK_STATUS sw_pre_setinfo_callback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext)
{
	NTSTATUS		status = STATUS_SUCCESS;
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS sw_init_minifliter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PAGED_CODE();
	
    status = FltRegisterFilter( DriverObject,
                                &g_FilterRegistration,
                                &g_FilterHandle );
    if (NT_SUCCESS( status )) 
	{
		status = init_lpc(g_port_name, g_FilterHandle);
		if (NT_SUCCESS(status))
		{
			status = FltStartFiltering(g_FilterHandle);
			return status;
		}
		uninit_lpc();
        FltUnregisterFilter( g_FilterHandle );
		g_FilterHandle = NULL;
    }
	
	return status;
}

NTSTATUS  sw_uninit_minifliter(PDRIVER_OBJECT pDriverObj)
{
	PAGED_CODE();
	uninit_lpc();
	if (g_FilterHandle)
	{
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = NULL;
	}
	return STATUS_SUCCESS;
}