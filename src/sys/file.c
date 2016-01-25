#include "main.h"
#include "file.h"
#include "port.h"
#include "macro.h"
#include <strsafe.h>
#include <Ntdddisk.h>
#include <windef.h>
#include "common.h"
#include "PRODUCER_COMSUMER_MACRO.h"

static PFLT_FILTER			g_FilterHandle = NULL;
static WCHAR				g_SandBoxPath[LONG_NAME_LEN] = L"\\Device\\HarddiskVolume1\\SandBox\\";
static WCHAR				g_SandBoxVolume[LONG_NAME_LEN] = L"\\Device\\HarddiskVolume1";
PFLT_INSTANCE				g_SbVolInstance = NULL;


typedef struct _PF_INSTANCE_CONTEXT
{
	PFLT_INSTANCE       Instance;
	WCHAR               DriveLetter[DRIVER_LETTER_LEN];
} PF_INSTANCE_CONTEXT;

typedef struct _FILE_RENAME_NODE 
{
	LIST_ENTRY		listentry;
	BOOLEAN ReplaceIfExists;
	HANDLE RootDirectory;
	WCHAR NewFileName[LONG_NAME_LEN];
	WCHAR FileName[LONG_NAME_LEN];
} FILE_RENAME_NODE, *PFILE_RENAME_NODE;


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

const FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = 
{
	{ FLT_INSTANCE_CONTEXT,
	0,
	NULL,
	sizeof(PF_INSTANCE_CONTEXT),
	'FILE' },

	{ FLT_CONTEXT_END }
};



CONST FLT_REGISTRATION g_FilterRegistration =
{
	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	g_ContextRegistration,              //  Context
	g_Callbacks,                        //  Operation g_Callbacks
	(PFLT_FILTER_UNLOAD_CALLBACK)SbMinifilterUnload,                          //  MiniFilterUnload
	(PFLT_INSTANCE_SETUP_CALLBACK)SbInstanceSetup,					//  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,								//  InstanceTeardownStart
	NULL,								//  InstanceTeardownComplete
	NcGenerateFileNameCallback,         //  GenerateFileName
	NcNormalizeNameComponentCallback,   //  GenerateDestinationFileName
	NULL,                               //  NormalizeNameComponent
	NULL,
	NULL
};



NTSTATUS
NcNormalizeNameComponentEx(
_In_     PFLT_INSTANCE            Instance,
_In_opt_ PFILE_OBJECT             FileObject,
_In_     PCUNICODE_STRING         ParentDirectory,
_In_     USHORT                   DeviceNameLength,
_In_     PCUNICODE_STRING         Component,
_Out_writes_bytes_(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
_In_     ULONG                    ExpandComponentNameLength,
_In_     FLT_NORMALIZE_NAME_FLAGS Flags,
_Inout_ PVOID           *NormalizationContext
)
{

	NTSTATUS Status;
	UNICODE_STRING MungedParentPath;  // Path we are going to open for query
	PCUNICODE_STRING MungedComponent = NULL; // File name to enumerate

	IO_STATUS_BLOCK ParentStatusBlock;
	OBJECT_ATTRIBUTES ParentAttributes;
	HANDLE ParentHandle = 0;
	PFILE_OBJECT ParentFileObject = NULL;
	BOOLEAN IgnoreCase = !BooleanFlagOn(Flags, FLTFL_NORMALIZE_NAME_CASE_SENSITIVE);

	PAGED_CODE();

	FLT_ASSERT(IoGetTopLevelIrp() == NULL);

	UNREFERENCED_PARAMETER(NormalizationContext);
	UNREFERENCED_PARAMETER(DeviceNameLength);
	UNREFERENCED_PARAMETER(FileObject);


	MungedParentPath = *ParentDirectory;
	
	MungedComponent = Component;

	InitializeObjectAttributes(&ParentAttributes,
		&MungedParentPath,
		OBJ_KERNEL_HANDLE | (IgnoreCase ? OBJ_CASE_INSENSITIVE : 0),
		NULL,
		NULL);

	Status = NcCreateFileHelper(g_FilterHandle,
		Instance,
		&ParentHandle,
		&ParentFileObject,
		FILE_LIST_DIRECTORY | FILE_TRAVERSE,
		&ParentAttributes,
		&ParentStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_DIRECTORY_FILE,
		NULL,
		0,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		FileObject);

	if (!NT_SUCCESS(Status)) 
	{
		goto NcNormalizeNameComponentExCleanup;
	}

	Status = FltQueryDirectoryFile(Instance,
		ParentFileObject,
		ExpandComponentName,
		ExpandComponentNameLength,
		FileNamesInformation,
		TRUE,
		(PUNICODE_STRING)MungedComponent,
		TRUE,
		NULL);

	if (!NT_SUCCESS(Status)) 
	{
		goto NcNormalizeNameComponentExCleanup;
	}

NcNormalizeNameComponentExCleanup:

	if (ParentHandle != 0) 
	{
		FltClose(ParentHandle);
	}

	if (ParentFileObject != NULL) 
	{
		ObDereferenceObject(ParentFileObject);
	}
	return Status;
}

NTSTATUS
NcGenerateFileName(
_In_ PFLT_INSTANCE Instance,
_In_ PFILE_OBJECT FileObject,
_In_opt_ PFLT_CALLBACK_DATA Data,
_In_ FLT_FILE_NAME_OPTIONS NameOptions,
_Out_ PBOOLEAN CacheFileNameInformation,
_Inout_ PFLT_NAME_CONTROL OutputNameControl
)
{
	NTSTATUS	Status;
	BOOLEAN		Opened = (BOOLEAN)(FileObject->FsContext != NULL);                                       // True if file object is opened.
	BOOLEAN		ReturnShortName = (BOOLEAN)(FltGetFileNameFormat(NameOptions) == FLT_FILE_NAME_SHORT);   // True if the user is requesting short name
	BOOLEAN		ReturnOpenedName = (BOOLEAN)(FltGetFileNameFormat(NameOptions) == FLT_FILE_NAME_OPENED); // True if user is requesting opened name.
	BOOLEAN		ReturnNormalizedName = (BOOLEAN)(FltGetFileNameFormat(NameOptions) == FLT_FILE_NAME_NORMALIZED); // True if user is requesting normalized name.
	BOOLEAN		IgnoreCase;

	FLT_FILE_NAME_OPTIONS		NameQueryMethod = FltGetFileNameQueryMethod(NameOptions);
	FLT_FILE_NAME_OPTIONS		NameFlags = FLT_VALID_FILE_NAME_FLAGS & NameOptions;
	PFLT_FILE_NAME_INFORMATION	LowerNameInfo = NULL; // File name as reported by lower name provider. Will always be down real mapping.
	PFLT_FILE_NAME_INFORMATION	ShortInfo = NULL;  // We will use ShortInfo to store the short name if needed.
	PUNICODE_STRING				Name = NULL; // Pointer to the name we are going to use.

	PAGED_CODE();

	FLT_ASSERT(IoGetTopLevelIrp() == NULL);
	

	if (!ReturnShortName &&
		!ReturnOpenedName &&
		!ReturnNormalizedName) 
	{
		Status = STATUS_NOT_SUPPORTED;
		goto NcGenerateFileNameCleanup;
	}

	ClearFlag(NameFlags, FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER);

	Status = NcGetFileNameInformation(Data,
		FileObject,
		Instance,
		(ReturnNormalizedName ? FLT_FILE_NAME_NORMALIZED
		: FLT_FILE_NAME_OPENED) |
		NameQueryMethod |
		NameFlags,
		&LowerNameInfo);

	if (!NT_SUCCESS(Status)) 
	{
		goto NcGenerateFileNameCleanup;
	}

	Status = FltParseFileNameInformation(LowerNameInfo);

	if (!NT_SUCCESS(Status)) 
	{
		goto NcGenerateFileNameCleanup;
	}

	if (!Opened) 
	{

		SetFlag(NameFlags, FLT_FILE_NAME_DO_NOT_CACHE);

		if (Data) 
		{
			FLT_ASSERT(Data->Iopb->MajorFunction == IRP_MJ_CREATE || Data->Iopb->MajorFunction == IRP_MJ_NETWORK_QUERY_OPEN);
			IgnoreCase = !BooleanFlagOn(Data->Iopb->OperationFlags, SL_CASE_SENSITIVE);

		}
		else 
		{
			Status = STATUS_INVALID_PARAMETER;
			goto NcGenerateFileNameCleanup;

		}

	}
	else 
	{
		IgnoreCase = !BooleanFlagOn(FileObject->Flags, FO_OPENED_CASE_SENSITIVE);
	}

	if (ReturnOpenedName || ReturnNormalizedName) 
	{
		Name = &LowerNameInfo->Name;
	}
	else if (ReturnShortName) 
	{
			Status = NcGetFileNameInformation(Data,
				FileObject,
				Instance,
				FLT_FILE_NAME_SHORT |
				NameQueryMethod |
				NameFlags,
				&ShortInfo);

			if (!NT_SUCCESS(Status)) 
			{
				goto NcGenerateFileNameCleanup;
			}

			Status = FltParseFileNameInformation(ShortInfo);

			if (!NT_SUCCESS(Status)) 
			{
				goto NcGenerateFileNameCleanup;
			}
			Name = &ShortInfo->Name;
		
	}

	FLT_ASSERT(Name != NULL);

	Status = FltCheckAndGrowNameControl(OutputNameControl, Name->Length);

	if (NT_SUCCESS(Status)) 
	{
		RtlCopyUnicodeString(&OutputNameControl->Name, Name);
		*CacheFileNameInformation = TRUE;
	}

NcGenerateFileNameCleanup:

	if (LowerNameInfo != NULL)
	{
		FltReleaseFileNameInformation(LowerNameInfo);
	}

	if (ShortInfo != NULL) 
	{
		FltReleaseFileNameInformation(ShortInfo);
	}
	return Status;
}


NTSTATUS
NcGenerateFileNameCallback(
_In_ PFLT_INSTANCE Instance,
_In_ PFILE_OBJECT FileObject,
_In_opt_ PFLT_CALLBACK_DATA Data,
_In_ FLT_FILE_NAME_OPTIONS NameOptions,
_Out_ PBOOLEAN CacheFileNameInformation,
_Inout_ PFLT_NAME_CONTROL OutputNameControl
)
{

	PAGED_CODE();

	return NcGenerateFileName(Instance,
		FileObject,
		Data,
		NameOptions,
		CacheFileNameInformation,
		OutputNameControl);
}


NTSTATUS
NcNormalizeNameComponentCallback(
_In_     PFLT_INSTANCE            Instance,
_In_     PCUNICODE_STRING         ParentDirectory,
_In_     USHORT                   DeviceNameLength,
_In_     PCUNICODE_STRING         Component,
_Out_writes_bytes_(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
_In_     ULONG                    ExpandComponentNameLength,
_In_     FLT_NORMALIZE_NAME_FLAGS Flags,
_Inout_ PVOID           *NormalizationContext
)
{

	PAGED_CODE();

	return NcNormalizeNameComponentEx(Instance,
		NULL,
		ParentDirectory,
		DeviceNameLength,
		Component,
		ExpandComponentName,
		ExpandComponentNameLength,
		Flags,
		NormalizationContext);
}


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
	NTSTATUS				status = STATUS_SUCCESS;
	NTSTATUS				result = STATUS_FLT_DO_NOT_ATTACH;
	PF_INSTANCE_CONTEXT*	pInstCtx = NULL;

	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	status = FltAllocateContext(FltObjects->Filter,
		FLT_INSTANCE_CONTEXT,
		sizeof(PF_INSTANCE_CONTEXT),
		PagedPool,
		&pInstCtx);

	if (NT_SUCCESS(status) && pInstCtx)
	{
		RtlZeroMemory(pInstCtx, sizeof(PF_INSTANCE_CONTEXT));
		pInstCtx->Instance = FltObjects->Instance;
		RtlZeroMemory(pInstCtx->DriveLetter, DRIVER_LETTER_LEN*sizeof(WCHAR));
		if (GetDriveLetter(FltObjects, pInstCtx->DriveLetter, DRIVER_LETTER_LEN*sizeof(WCHAR)))
		{
			status = FltSetInstanceContext(FltObjects->Instance,
				FLT_SET_CONTEXT_KEEP_IF_EXISTS,
				pInstCtx,
				NULL);

			if (NT_SUCCESS(status))
			{
				result = STATUS_SUCCESS;
			}
		}
		FltReleaseContext(pInstCtx);
	}

	return result;
}

NTSTATUS SbMinifilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
	SbUninitMinifilter();
	return STATUS_SUCCESS;
}

BOOLEAN ShouldSandBox(HANDLE pid)
{
	WCHAR						ProcPath[LONG_NAME_LEN];
	ULONG						Len = 0;
	BOOLEAN						b = FALSE;
	if (GetProcFullPathById(pid, ProcPath, &Len))
	{
		if (wcsistr(ProcPath, L"yyhipsTest.exe"))
		{
			b = TRUE;
		}
	}
	return b;
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
//	ULONG						CreateOptions = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
	UCHAR						CreateDisposition = (UCHAR)(((Data->Iopb->Parameters.Create.Options) >> 24) & 0xFF);
	BOOLEAN						bCreateFile	= FALSE;
	BOOLEAN						bModifyFile	= FALSE;
	PFLT_INSTANCE				pOutVolumeInstance = NULL;
	BOOLEAN						bDir  = FALSE;
	
	PF_INSTANCE_CONTEXT *		pInstCtx = NULL;
	WCHAR						DriverLetter[DRIVER_LETTER_LEN] = { 0 };

	ASSERT( Data->Iopb->MajorFunction == IRP_MJ_CREATE );

	CurrentPid = PsGetCurrentProcessId();

	if (ShouldSkipPre(Data, FltObjects))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (!ShouldSandBox(CurrentPid))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	status = FltGetInstanceContext(FltObjects->Instance, &pInstCtx);
	if (!NT_SUCCESS(status) || pInstCtx == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	StringCchCopyW(DriverLetter, DRIVER_LETTER_LEN, pInstCtx->DriveLetter);
	FltReleaseContext(pInstCtx);
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
		status = SbConvertToSbName(&usSandBoxPath, &nameInfo->Name, &usInnerPath, DriverLetter);
		if(!NT_SUCCESS(status))
		{
			Data->IoStatus.Status = status;
			Data->IoStatus.Information = 0;	
			goto RepPreCreateCleanup;
		}

		CreateSbDirectoryByOutNtPath(g_FilterHandle, pOutVolumeInstance, g_SbVolInstance, &nameInfo->Name, &usSandBoxPath);

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
					status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject, usInnerPath.Buffer, usInnerPath.Length);
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
					
					status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject, usInnerPath.Buffer, usInnerPath.Length);
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
							status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject, usInnerPath.Buffer, usInnerPath.Length);
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
					status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject, usInnerPath.Buffer, usInnerPath.Length);
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
					status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject, usInnerPath.Buffer, usInnerPath.Length);
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
						status = IoReplaceFileObjectName(Data->Iopb->TargetFileObject, usInnerPath.Buffer, usInnerPath.Length);
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

	if (STATUS_SB_TRY_REPARSE == status)
	{
		Data->IoStatus.Status = STATUS_REPARSE;
		Data->IoStatus.Information = IO_REPARSE;
		callbackStatus = FLT_PREOP_COMPLETE;
	}
	return callbackStatus;
}


MACRO_PRODUCER_COMSUMER_DECLARE(FILE_RENAME_NODE)

void Process_FILE_RENAME_NODE(FILE_RENAME_NODE* pNode)
{
	NTSTATUS					status = STATUS_SUCCESS;
	status = NtRenameFile(pNode->FileName, pNode->NewFileName, pNode->ReplaceIfExists, pNode->RootDirectory);
	if (!NT_SUCCESS(status))
	{
		NtRenameFile(pNode->FileName, pNode->NewFileName, pNode->ReplaceIfExists, pNode->RootDirectory);
	}
}

void UninitMailPost(void)
{
	Uninit_FILE_RENAME_NODE();
}

BOOLEAN InsertMailInfo(FILE_RENAME_NODE* pMailEvent)
{
	return Insert_FILE_RENAME_NODE(pMailEvent);
}

NTSTATUS InitMailPost()
{
	return Init_FILE_RENAME_NODE();
}

FLT_PREOP_CALLBACK_STATUS ProcessRename(PUNICODE_STRING pOrgNtName, PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	FILE_RENAME_NODE*			pRenameNode = NULL;
	PFILE_RENAME_INFORMATION	pfn = NULL;
	NTSTATUS					status = STATUS_SUCCESS;
	UNICODE_STRING				usSandBoxPath = { 0, 0, NULL };
	UNICODE_STRING				usDosPath = { 0, 0, NULL };
	UNICODE_STRING				usNtPath = { 0, 0, NULL };
	UNICODE_STRING				usDestNtPath = { 0, 0, NULL };
	UNICODE_STRING				usDestDosPath = { 0, 0, NULL };
	UNICODE_STRING				uDosFileName = { 0, 0, NULL };
	FLT_PREOP_CALLBACK_STATUS	ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	pfn = (PFILE_RENAME_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer);
	if (pfn)
	{
		pRenameNode = MyAllocateMemory(NonPagedPool, sizeof(FILE_RENAME_NODE));
		if (pRenameNode)
		{
			usDosPath.Buffer = &pfn->FileName[4];
			usDosPath.MaximumLength = usDosPath.Length = (USHORT)pfn->FileNameLength - 4*sizeof(WCHAR);
			RtlInitUnicodeString(&usSandBoxPath, g_SandBoxPath);

			status = ResolveDosPathToNtPath(&usDosPath, &usNtPath);
			if (NT_SUCCESS(status))
			{
				status = SbConvertToSbName(&usSandBoxPath, &usNtPath, &usDestNtPath, NULL);
				if (NT_SUCCESS(status))
				{
					if (pfn->ReplaceIfExists || !FltIsFileExist(g_FilterHandle, FltObjects->Instance, &usDestNtPath, NULL))
					{
						status = ResolveNtPathToDosPath(&usDestNtPath, &usDestDosPath);
						if (NT_SUCCESS(status))
						{
							status = ResolveNtPathToDosPath(pOrgNtName, &uDosFileName);
							if (NT_SUCCESS(status))
							{
								StringCchCopyW(pRenameNode->NewFileName, LONG_NAME_LEN, L"\\??\\");
								StringCchCatNW(pRenameNode->NewFileName, LONG_NAME_LEN, usDestDosPath.Buffer, usDestDosPath.Length / sizeof(WCHAR));

								StringCchCopyW(pRenameNode->FileName, LONG_NAME_LEN, L"\\??\\");
								StringCchCatNW(pRenameNode->FileName, LONG_NAME_LEN, uDosFileName.Buffer, uDosFileName.Length / sizeof(WCHAR));

								pRenameNode->ReplaceIfExists = pfn->ReplaceIfExists;
								pRenameNode->RootDirectory = pfn->RootDirectory;
								if (InsertMailInfo(pRenameNode))
								{
									pRenameNode = NULL;
									Data->IoStatus.Status = STATUS_SUCCESS;
									Data->IoStatus.Information = 0;
									ret = FLT_PREOP_COMPLETE;
								}
								FreeUnicodeString(&uDosFileName);
							}
							FreeUnicodeString(&usDestDosPath);
						}
						else
						{
							KdPrint(("malloc failed! \r\n"));
						}
					}
					else
					{
						Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
						Data->IoStatus.Information = 0;
						ret = FLT_PREOP_COMPLETE;
					}
					FreeUnicodeString(&usDestNtPath);
				}
				else
				{
					KdPrint(("malloc failed! \r\n"));
				}
				FreeUnicodeString(&usNtPath);
			}
			else
			{
				KdPrint(("malloc failed! \r\n"));
			}
			if (pRenameNode)
			{
				ExFreePool(pRenameNode);
				pRenameNode = NULL;
			}
		}
		else
		{
			KdPrint(("malloc failed! \r\n"));
		}
	}
	return ret;
}

FLT_PREOP_CALLBACK_STATUS SbPreSetinfoCallback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION	pNameInfo = NULL;
	BOOLEAN						IsDirectory = FALSE;
	FLT_PREOP_CALLBACK_STATUS	ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	UNREFERENCED_PARAMETER(CompletionContext);

	if (ShouldSkipPre(Data, FltObjects))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (!ShouldSandBox(PsGetCurrentProcessId()))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectory);
	if (IsDirectory)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileDispositionInformation)
		&& (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileBasicInformation)
		&& (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformation))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo);
	if (!NT_SUCCESS(status))
	{
		goto clean_ret;
	}

	status = FltParseFileNameInformation(pNameInfo);
	if (!NT_SUCCESS(status))
	{
		goto clean_ret;
	}

	if (pNameInfo->Name.Length <= 48)
	{
		goto clean_ret;
	}

	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation &&
		((PFILE_DISPOSITION_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer))->DeleteFile == TRUE)
	{

	}
	else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileBasicInformation)
	{

	}
	else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
	{
		ret = ProcessRename(&pNameInfo->Name, Data, FltObjects);
	}
	else
	{
		goto clean_ret;
	}

clean_ret:

	if (pNameInfo)
	{
		FltReleaseFileNameInformation(pNameInfo);
		pNameInfo = NULL;
	}
	return ret;
}

NTSTATUS SbInitMinifilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PAGED_CODE();
	UNICODE_STRING	usSysrootNt;

	status = InitMailPost();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

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
		UninitMailPost();
    }
	return status;
}

void  SbUninitMinifilter()
{
	UninitMailPost();
	UnInitPortComm();
	if (g_FilterHandle)
	{
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = NULL;
	}
}