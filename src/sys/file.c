#include "main.h"
#include "file.h"
#include "port.h"
#include "macro.h"
#include "lib.h"
#include <strsafe.h>
#include <Ntdddisk.h>
#include <windef.h>
#include "common.h"

static PFLT_FILTER			g_FilterHandle = NULL;
static WCHAR				g_SandBoxPath[LONG_NAME_LEN] = L"\\Device\\HarddiskVolume1\\SandBox\\";
static WCHAR				g_SandBoxVolume[LONG_NAME_LEN] = L"\\Device\\HarddiskVolume1";
PFLT_INSTANCE				g_SbVolInstance = NULL;


CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = 
{
	{ IRP_MJ_CREATE,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO ,
	(PFLT_PRE_OPERATION_CALLBACK)SbPreCreateCallback,
	NULL},

	{ IRP_MJ_SET_INFORMATION,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	(PFLT_PRE_OPERATION_CALLBACK)SbPreSetinfoCallback,
	NULL},

	{ IRP_MJ_OPERATION_END }
};




CONST FLT_REGISTRATION g_FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	g_Callbacks,                        //  Operation g_Callbacks
	(PFLT_FILTER_UNLOAD_CALLBACK)SbMinifilterUnload,                          //  MiniFilterUnload
	(PFLT_INSTANCE_SETUP_CALLBACK)SbInstanceSetup,					//  InstanceSetup
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

BOOLEAN ShouldSkipPre(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	HANDLE						PID = PsGetCurrentProcessId();

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return TRUE;
	}
	if (PID == (HANDLE)4 || PID == (HANDLE)0)
	{
		return TRUE;
	}

	if (Data->RequestorMode == KernelMode)
	{
		return TRUE;
	}

	if (!FltObjects || !FltObjects->Instance || !FltObjects->FileObject)
	{
		return TRUE;
	}

	if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) || FlagOn(Data->Iopb->IrpFlags, IRP_CLOSE_OPERATION))
	{
		return TRUE;
	}

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) || FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN))
	{
		return TRUE;
	}

	if (FlagOn(FltObjects->FileObject->Flags, FO_NAMED_PIPE) || FlagOn(FltObjects->FileObject->Flags, FO_MAILSLOT))
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN ShouldSkipPost(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	HANDLE						PID = PsGetCurrentProcessId();

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return TRUE;
	}
	if (PID == (HANDLE)4 || PID == (HANDLE)0)
	{
		return TRUE;
	}

	if (Data->RequestorMode == KernelMode)
	{
		return TRUE;
	}

	if (!FltObjects || !FltObjects->Instance || !FltObjects->FileObject)
	{
		return TRUE;
	}

	if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
	{
		return TRUE;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return TRUE;
	}

	return FALSE;
}

NTSTATUS SbSetSandBoxPath(PVOID buf,ULONG len)
{

	HRESULT  ret;
	HRESULT  ret1;
	if (buf == NULL || len < sizeof(WCHAR)*LONG_NAME_LEN)
	{
		return STATUS_UNSUCCESSFUL;
	}
	ret = StringCbCopyNW(g_SandBoxPath, sizeof(WCHAR)*LONG_NAME_LEN, (WCHAR*)buf, len);
	ret1 = StringCbCopyNW(g_SandBoxVolume, sizeof(WCHAR)*LONG_NAME_LEN, (WCHAR*)buf, wcslen(L"\\device\\HarddiskVolume1")*sizeof(WCHAR));
	if (SUCCEEDED(ret) && SUCCEEDED(ret1))
	{
		return STATUS_SUCCESS;
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}
}



NTSTATUS
SbInstanceSetup (
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



NTSTATUS SbMinifilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNICODE_STRING deviceDosName;
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	SbUninitMinifilter(g_DriverObj);


	if (g_DeviceObj)
	{
		IoDeleteDevice(g_DeviceObj);
		g_DeviceObj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_SymbolName);
	IoDeleteSymbolicLink(&deviceDosName);
	return STATUS_SUCCESS;
}

NTSTATUS SbConvertToSandBoxPath(IN PUNICODE_STRING	pSandboxPath, IN PUNICODE_STRING	pSrcName, OUT PUNICODE_STRING pDstName)
{
	NTSTATUS		ntStatus	= STATUS_UNSUCCESSFUL;
	USHORT			usNameSize	= 0;
	PWSTR			pNameBuffer = NULL;
	UNICODE_STRING	SrcNameDos;
	UNICODE_STRING	ustrDevicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
	WCHAR			szVolume[] = L"c\\";
	
	__try
	{
		if (pSrcName == NULL || pDstName == NULL || NULL == pSandboxPath || pSrcName->Length <= 48)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(RtlPrefixUnicodeString(pSandboxPath,pSrcName,TRUE))
		{
			ntStatus = STATUS_SB_REPARSED;
			__leave;
		}
		
		ntStatus = ResolveNtPathToDosPath(pSrcName, &SrcNameDos);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		szVolume[0] = SrcNameDos.Buffer[0];

		usNameSize = pSandboxPath->Length + sizeof(szVolume) + pSrcName->Length - 48 + sizeof(WCHAR);//L"\\Device\\HarddiskVolume1\\"
		
		pNameBuffer = (PWSTR)MyAllocateMemory(PagedPool, usNameSize);
		if(pNameBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}	
		
		StringCbCopyNW(pNameBuffer, usNameSize, pSandboxPath->Buffer, pSandboxPath->Length);
		StringCbCatW(pNameBuffer, usNameSize, szVolume);
		StringCbCatNW(pNameBuffer, usNameSize, &pSrcName->Buffer[24], pSrcName->Length-48);

		pDstName->Buffer = pNameBuffer; 
		pDstName->MaximumLength = pDstName->Length  = usNameSize; 
	
		ntStatus = STATUS_SUCCESS;
	}
	__finally
	{
		if (SrcNameDos.Buffer)
		{
			ExFreePool(SrcNameDos.Buffer);
		}
		if (!NT_SUCCESS(ntStatus) && pNameBuffer)
		{
			ExFreePool(pNameBuffer);
		}
	}

	return ntStatus;
}


FLT_PREOP_CALLBACK_STATUS SbPreCreateCallback( PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	NTSTATUS					status = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS	callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	HANDLE						CurrentPid = NULL;
	UNICODE_STRING				usSandBoxPath = {0,0,NULL};
	UNICODE_STRING				usSandBoxVolume = {0,0,NULL};
	UNICODE_STRING				usInnerPath = {0,0,NULL};
	ACCESS_MASK					OriginalDesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->AccessState->OriginalDesiredAccess;
	ULONG						CreateOptions = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
	UCHAR						CreateDisposition = (UCHAR)(((Data->Iopb->Parameters.Create.Options) >> 24) & 0xFF);
	BOOLEAN						bCreateFile	= FALSE;
	BOOLEAN						bModifyFile	= FALSE;
	PFLT_INSTANCE				pOutVolumeInstance = NULL;
	BOOLEAN						bDir  = FALSE;
	WCHAR						ProcPath[LONG_NAME_LEN];
	ULONG						Len = 0;

	ASSERT( Data->Iopb->MajorFunction == IRP_MJ_CREATE );

	CurrentPid = PsGetCurrentProcessId();

	if (ShouldSkipPre(Data, FltObjects))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (GetProcFullPathById(CurrentPid, ProcPath, &Len))
	{
		if (wcsistr(ProcPath,L"yyhipsTest.exe"))
		{

		}
		else
		{
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	else
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	RtlInitUnicodeString(&usSandBoxPath, g_SandBoxPath);
	RtlInitUnicodeString(&usSandBoxVolume, g_SandBoxVolume);

	pOutVolumeInstance = FltObjects->Instance;

	if(g_SbVolInstance == NULL)
	{
		g_SbVolInstance = SbGetVolumeInstance(g_FilterHandle, &usSandBoxVolume);	

		if(g_SbVolInstance == NULL)
		{
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
    status = FltGetFileNameInformation( Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo );
    if (!NT_SUCCESS( status )) 
	{
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation( nameInfo );
    if (!NT_SUCCESS( status )) 
	{
		goto RepPreCreateCleanup;
    }

	if(RtlPrefixUnicodeString(&usSandBoxPath, &nameInfo->Name, TRUE))
	{
		goto RepPreCreateCleanup;
	}
	else
	{
		status = SbConvertToSandBoxPath(&usSandBoxPath, &nameInfo->Name, &usInnerPath);
		if(!NT_SUCCESS(status))
		{
			Data->IoStatus.Status = status;
			Data->IoStatus.Information = 0;	
			goto RepPreCreateCleanup;
		}

		bCreateFile = ((CreateDisposition == FILE_CREATE) 
					||(CreateDisposition == FILE_OPEN_IF) 
					||(CreateDisposition == FILE_OVERWRITE_IF) 
					|| (CreateDisposition == FILE_SUPERSEDE));
		
		bModifyFile =  ((OriginalDesiredAccess & FILE_WRITE_DATA)
					|| (OriginalDesiredAccess & FILE_APPEND_DATA)
					|| (OriginalDesiredAccess & DELETE)
					|| (OriginalDesiredAccess & FILE_WRITE_EA)
					|| (OriginalDesiredAccess & FILE_WRITE_ATTRIBUTES));

		if (FltIsFileExist(g_FilterHandle,pOutVolumeInstance,&nameInfo->Name,NULL))
		{
			if (FltIsDelFlagExist(g_FilterHandle,g_SbVolInstance,&usInnerPath))
			{
				if (bCreateFile)
				{
					status = RedirectFile(Data,FltObjects,usInnerPath.Buffer,usInnerPath.Length);
					if(NT_SUCCESS(status))
					{
						status = STATUS_SB_TRY_REPARSE;
					}
					else
					{
						Data->IoStatus.Status = status;
						Data->IoStatus.Information = 0;
					}
					goto RepPreCreateCleanup;
				}
				else
				{
					Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
					Data->IoStatus.Information = 0;
					status = STATUS_OBJECT_NAME_NOT_FOUND;
					goto RepPreCreateCleanup;
				}
			}
			else
			{
				if (FltIsFileExist(g_FilterHandle,g_SbVolInstance,&usInnerPath,NULL))
				{
					status = RedirectFile(Data,FltObjects,usInnerPath.Buffer,usInnerPath.Length);
					if(NT_SUCCESS(status))
					{
						status = STATUS_SB_TRY_REPARSE;
					}
					else
					{
						Data->IoStatus.Status = status;
						Data->IoStatus.Information = 0;
					}
					goto RepPreCreateCleanup;
				}
				else
				{
					if (bModifyFile)
					{
						status = SbIsDirectory(NULL, &nameInfo->Name, FltObjects->Filter, pOutVolumeInstance, &bDir);
						if(!NT_SUCCESS(status))
						{
							Data->IoStatus.Status = status;
							Data->IoStatus.Information = 0;
							goto RepPreCreateCleanup;
						}
						status = SbCopyFile(g_FilterHandle,
								pOutVolumeInstance,
								NULL,
								&nameInfo->Name,
								g_SbVolInstance,
								&usInnerPath,
								bDir);
						if(!NT_SUCCESS(status))
						{
							Data->IoStatus.Status = status;
							Data->IoStatus.Information = 0;
							goto RepPreCreateCleanup;
						}
						else
						{
							status = RedirectFile(Data,FltObjects,usInnerPath.Buffer,usInnerPath.Length);
							if(NT_SUCCESS(status))
							{
								status = STATUS_SB_TRY_REPARSE;
							}
							else
							{
								Data->IoStatus.Status = status;
								Data->IoStatus.Information = 0;
							}
							goto RepPreCreateCleanup;
						}
					}
					else
					{
						status = STATUS_SUCCESS;
						goto RepPreCreateCleanup;
					}
				}
			}
		}
		else
		{
			if (FltIsDelFlagExist(g_FilterHandle,g_SbVolInstance,&usInnerPath))
			{
				if (bCreateFile)
				{
					status = RedirectFile(Data,FltObjects,usInnerPath.Buffer,usInnerPath.Length);
					if(NT_SUCCESS(status))
					{
						status = STATUS_SB_TRY_REPARSE;
					}
					else
					{
						Data->IoStatus.Status = status;
						Data->IoStatus.Information = 0;
					}
					goto RepPreCreateCleanup;
				}
				else
				{
					Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
					Data->IoStatus.Information = 0;
					status = STATUS_OBJECT_NAME_NOT_FOUND;
					goto RepPreCreateCleanup;
				}
			}
			else
			{
				if (FltIsFileExist(g_FilterHandle,g_SbVolInstance,&usInnerPath,NULL))
				{
					status = RedirectFile(Data,FltObjects,usInnerPath.Buffer,usInnerPath.Length);
					if(NT_SUCCESS(status))
					{
						status = STATUS_SB_TRY_REPARSE;
					}
					else
					{
						Data->IoStatus.Status = status;
						Data->IoStatus.Information = 0;
					}
					goto RepPreCreateCleanup;
				}
				else
				{
					if (bCreateFile)
					{
						status = RedirectFile(Data,FltObjects,usInnerPath.Buffer,usInnerPath.Length);
						if(NT_SUCCESS(status))
						{
							status = STATUS_SB_TRY_REPARSE;
						}
						else
						{
							Data->IoStatus.Status = status;
							Data->IoStatus.Information = 0;
						}
						goto RepPreCreateCleanup;
					}
					else
					{
						Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
						Data->IoStatus.Information = 0;
						status = STATUS_OBJECT_NAME_NOT_FOUND;
						goto RepPreCreateCleanup;
					}
				}
			}
		}
	}

RepPreCreateCleanup:

    if (nameInfo != NULL) 
	{
        FltReleaseFileNameInformation( nameInfo );
    }
	FreeUnicodeString(&usInnerPath);
	return callbackStatus;
}


FLT_PREOP_CALLBACK_STATUS SbPreSetinfoCallback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext)
{
	NTSTATUS		status = STATUS_SUCCESS;
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS SbInitMinifilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PAGED_CODE();
	UNICODE_STRING	usSysrootNt;
	UNICODE_STRING	usSysrootDos;

	status = GetSysrootNtPath(&usSysrootNt);
	if (NT_SUCCESS(status))
	{
		g_SandBoxPath[22] = usSysrootNt.Buffer[22];
		g_SandBoxVolume[22] = usSysrootNt.Buffer[22];
		ExFreePool(usSysrootNt.Buffer);
	}
    status = FltRegisterFilter( DriverObject, &g_FilterRegistration, &g_FilterHandle );
    if (NT_SUCCESS( status )) 
	{
		status = InitPortComm(g_PortName, g_FilterHandle);
		if (NT_SUCCESS(status))
		{
			status = FltStartFiltering(g_FilterHandle);
			return status;
		}
		UnInitPortComm();
        FltUnregisterFilter( g_FilterHandle );
		g_FilterHandle = NULL;
    }
	return status;
}

NTSTATUS  SbUninitMinifilter(PDRIVER_OBJECT pDriverObj)
{
	PAGED_CODE();
	UnInitPortComm();
	if (g_FilterHandle)
	{
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = NULL;
	}
	return STATUS_SUCCESS;
}