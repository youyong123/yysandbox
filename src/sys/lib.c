#include "lib.h"
#include "macro.h"

fn_ZwQueryInformationProcess	g_ZwQueryInformationProcess = NULL;
fn_NtQueryInformationThread		g_ZwQueryInformationThread = NULL;
fn_IoReplaceFileObjectName		g_IoReplaceFileObjectName = NULL;

VOID
SleepImp (__int64 ReqInterval)
{
	LARGE_INTEGER	Interval;
	*(__int64*)&Interval=-(ReqInterval*10000000L);
	KeDelayExecutionThread( KernelMode, FALSE, &Interval );
}


PWCHAR GetProcNameByPid(IN  HANDLE   dwProcessId, PWCHAR pPath)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE hProcess;
	PEPROCESS pEprocess;
	ULONG returnedLength;
	PUNICODE_STRING imageName;

	PAGED_CODE();

	Status = PsLookupProcessByProcessId(dwProcessId, &pEprocess);
	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}
	Status = ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hProcess);
	if (!NT_SUCCESS(Status))
	{
		ObDereferenceObject(pEprocess);
		return NULL;
	}
	Status = g_ZwQueryInformationProcess(hProcess, ProcessImageFileName, pPath, MAXPATHLEN*sizeof(WCHAR), &returnedLength);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(hProcess);
		ObDereferenceObject(pEprocess);
		return NULL;
	}
	else
	{
		ULONG len = 0;
		imageName = (PUNICODE_STRING)pPath;
		len = imageName->Length;
		RtlMoveMemory(pPath, imageName->Buffer, imageName->Length);
		pPath[len / sizeof(WCHAR)] = L'\0';
	}
	ZwClose(hProcess);
	ObDereferenceObject(pEprocess);
	return pPath;
}

NTSTATUS
ReplaceFileObjectName (
    __in PFILE_OBJECT FileObject,
    __in_bcount(FileNameLength) PWSTR NewFileName,
    __in USHORT FileNameLength
    )
{
	PWSTR buffer;
	PUNICODE_STRING fileName;
	USHORT newMaxLength;

	PAGED_CODE();

	fileName = &FileObject->FileName;

	if (FileNameLength <= fileName->MaximumLength) 
	{
		goto CopyAndReturn;
	}

	newMaxLength = FileNameLength;

	buffer = (PWSTR)ExAllocatePoolWithTag( PagedPool,  newMaxLength, 'LIB' );
	if (!buffer) 
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (fileName->Buffer != NULL) 
	{
		ExFreePool(fileName->Buffer);
	}

	fileName->Buffer = buffer;
	fileName->MaximumLength = newMaxLength;

	CopyAndReturn:

	fileName->Length = FileNameLength;
	RtlZeroMemory(fileName->Buffer, fileName->MaximumLength);
	RtlCopyMemory(fileName->Buffer, NewFileName, FileNameLength);

	return STATUS_SUCCESS;
}


NTSTATUS InitLib()
{
	if (NULL == g_ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		g_ZwQueryInformationProcess =(fn_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&routineName);
		if (NULL == g_ZwQueryInformationProcess)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
	
	if (NULL == g_ZwQueryInformationThread)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread");
		g_ZwQueryInformationThread =(fn_NtQueryInformationThread)MmGetSystemRoutineAddress(&routineName);
		if (NULL == g_ZwQueryInformationThread)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (NULL == g_IoReplaceFileObjectName)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"IoReplaceFileObjectName");
		g_IoReplaceFileObjectName = (fn_IoReplaceFileObjectName)MmGetSystemRoutineAddress( &routineName );
		if (NULL == g_IoReplaceFileObjectName) 
		{
			g_IoReplaceFileObjectName = ReplaceFileObjectName;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS
AllocateUnicodeString (
    PUNICODE_STRING String
    )
{
	PAGED_CODE();

	String->Buffer = (PWSTR)ExAllocatePoolWithTag( NonPagedPool, String->MaximumLength,'LIB' );

	if (String->Buffer == NULL) 
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	String->Length = 0;
	return STATUS_SUCCESS;
}

VOID
FreeUnicodeString (
    PUNICODE_STRING String
    )
{
	PAGED_CODE();

	if (String->Buffer) 
	{
		ExFreePoolWithTag( String->Buffer, 'LIB' );
		String->Buffer = NULL;
	}
	String->Length = String->MaximumLength = 0;
	String->Buffer = NULL;
}


BOOLEAN
FltIsFileExist(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pInstance,
	IN PUNICODE_STRING	pFileName
	)
{
	NTSTATUS				ntStatus;
	OBJECT_ATTRIBUTES		objAttrib;
	HANDLE					hFile;
	IO_STATUS_BLOCK			ioStatus;

	
	if(pFilter == NULL || pInstance == NULL || pFileName == NULL)
	{
		return FALSE;
	}

	InitializeObjectAttributes(&objAttrib,
								pFileName,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL);

	ntStatus = FltCreateFile(pFilter,
								pInstance,    
								&hFile,
								FILE_READ_ATTRIBUTES | SYNCHRONIZE,
								&objAttrib,
								&ioStatus,
								0,
								FILE_ATTRIBUTE_NORMAL,
								FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
								FILE_OPEN,
								FILE_SYNCHRONOUS_IO_NONALERT,
								NULL,0,0);

	if(NT_SUCCESS(ntStatus))
	{
		FltClose(hFile);
		return TRUE;
	}

	if(ntStatus == STATUS_SHARING_VIOLATION )
	{
		return TRUE;
	}
	return FALSE;
}


FORCEINLINE BOOLEAN  IsFileExist(PUNICODE_STRING pPath)
{
	BOOLEAN					bret = FALSE;
	NTSTATUS				status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES		attributes;
	FILE_NETWORK_OPEN_INFORMATION  FileInformation;

	InitializeObjectAttributes(&attributes, pPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwQueryFullAttributesFile(&attributes, &FileInformation);
	if (NT_SUCCESS(status))
	{
		bret = TRUE;
	}
	return bret;
}

NTSTATUS
RedirectFile(
	IN	PFLT_CALLBACK_DATA 		Data,
	IN	PCFLT_RELATED_OBJECTS	FltObjects,
	IN	PWSTR NewFileName,
	IN  USHORT FileNameLength
	)
{
	PFILE_OBJECT		pFileObject;
	NTSTATUS			status = STATUS_SUCCESS;
	
	pFileObject= Data->Iopb->TargetFileObject;
	if(pFileObject == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = g_IoReplaceFileObjectName(pFileObject,NewFileName,FileNameLength);
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}
	Data->IoStatus.Status = STATUS_REPARSE; 
	Data->IoStatus.Information = IO_REPARSE;

	FltSetCallbackDataDirty(Data);
	
	return STATUS_SUCCESS;
}
