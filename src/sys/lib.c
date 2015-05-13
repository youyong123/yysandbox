#include "lib.h"
#include "macro.h"
#include <windef.h>

fn_ZwQueryInformationProcess	g_ZwQueryInformationProcess = NULL;
fn_NtQueryInformationThread		g_ZwQueryInformationThread = NULL;
fn_IoReplaceFileObjectName		g_IoReplaceFileObjectName = NULL;

VOID SleepImp (__int64 ReqInterval)
{
	LARGE_INTEGER	Interval;
	PAGED_CODE();
	*(__int64*)&Interval=-(ReqInterval*10000000L);
	KeDelayExecutionThread( KernelMode, FALSE, &Interval );
}

PVOID MyAllocateMemory( IN POOL_TYPE PoolType,IN SIZE_T	NumberOfBytes)
{
	PVOID	pBuffer;
	
	pBuffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, 'FCLM');
	if(pBuffer != NULL)
	{
		RtlZeroMemory(pBuffer, NumberOfBytes);
	}
	return pBuffer;
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
	PAGED_CODE();

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

	PAGED_CODE();
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

	PAGED_CODE();

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
	
	PAGED_CODE();

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

NTSTATUS
FltQueryInformationFileSyncronous (
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    OUT PULONG LengthReturned OPTIONAL
    )

/*++

Routine Description:

    This routine returns the requested information about a specified file.
    The information returned is determined by the FileInformationClass that
    is specified, and it is placed into the caller's FileInformation buffer.

Arguments:

    Instance - Supplies the Instance initiating this IO.

    FileObject - Supplies the file object about which the requested
        information should be returned.

    FileInformationClass - Specifies the type of information which should be
        returned about the file.

    Length - Supplies the length, in bytes, of the FileInformation buffer.

    FileInformation - Supplies a buffer to receive the requested information
        returned about the file.  This must be a buffer allocated from kernel
        space.

    LengthReturned - the number of bytes returned if the operation was
        successful.

Return Value:

    The status returned is the final completion status of the operation.

--*/

{
#if (NTDDI_VERSION >= NTDDI_LONGHORN)

	return FltQueryInformationFile(Instance,
									FileObject,
									FileInformation,
									Length,
									FileInformationClass,
									LengthReturned
									);

#else

    PFLT_CALLBACK_DATA data;
    NTSTATUS status;

    PAGED_CODE();

    status = FltAllocateCallbackData( Instance, FileObject, &data );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Fill out callback data
    //

    data->Iopb->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    data->Iopb->Parameters.QueryFileInformation.FileInformationClass = FileInformationClass;
    data->Iopb->Parameters.QueryFileInformation.Length = Length;
    data->Iopb->Parameters.QueryFileInformation.InfoBuffer = FileInformation;
    data->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;


    FltPerformSynchronousIo( data );

    //
    //  Return Results
    //

    status = data->IoStatus.Status;

    if (NT_SUCCESS( status ) &&
        ARGUMENT_PRESENT(LengthReturned)) {

        *LengthReturned = (ULONG) data->IoStatus.Information;
    }

    FltFreeCallbackData( data );

    return status;
#endif
}


NTSTATUS
SbCopyFile(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pSrcInstance,
	IN PFILE_OBJECT		pSrcFileObj,
	IN PUNICODE_STRING	pSrcFileName,
	IN PFLT_INSTANCE	pDstInstance,
	IN PUNICODE_STRING	pDstFileName,
	IN BOOLEAN			bDirectory
	)
{
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;
	PFILE_STREAM_INFORMATION	pStreamInfo = NULL;
	ULONG			uStreamInfoSize = PAGE_SIZE;
	PVOID			pStreamBuffer = NULL;
	UNICODE_STRING	ustrSrcFileName = {0, 0, 0};
	UNICODE_STRING	ustrDstFileName = {0, 0, 0};
	UNICODE_STRING	ustrTmpName = {0, 0, 0};
	HANDLE			hFile = NULL;
	PFILE_OBJECT	pSrcFileObject = NULL;
	static UNICODE_STRING	dataStreamName = UNICODE_STRING_CONST("::$DATA");
	IO_STATUS_BLOCK					iosb = {0};
	FILE_FS_ATTRIBUTE_INFORMATION*	fsAttribInfomation = NULL;
	ULONG							length = sizeof(FILE_FS_ATTRIBUTE_INFORMATION)+20;

	__try
	{
		if(pFilter == NULL || pSrcInstance == NULL || 
			pSrcFileName == NULL || pDstInstance == NULL || pDstFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(!pSrcFileObj && !pSrcFileName)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(!pSrcFileObj)
		{
			OBJECT_ATTRIBUTES	objAttrib;
			IO_STATUS_BLOCK		ioStatus = {0, 0};
	
			InitializeObjectAttributes(&objAttrib,
				pSrcFileName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);
			
			ntStatus = FltCreateFile(pFilter,
									 pSrcInstance,    
									 &hFile,
									 GENERIC_READ | SYNCHRONIZE,
									 &objAttrib,
									 &ioStatus,
									 0,
									 FILE_ATTRIBUTE_NORMAL,
									 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
									 FILE_OPEN,
									 FILE_SYNCHRONOUS_IO_NONALERT,
									 NULL,0,0);
			if(! NT_SUCCESS(ntStatus))
				__leave;
			
			ntStatus = ObReferenceObjectByHandle(hFile,
				FILE_ANY_ACCESS,
				NULL,
				KernelMode,
				&pSrcFileObject,
				NULL);
			if(! NT_SUCCESS(ntStatus))		
				__leave;
			
		}
		else
		{
			pSrcFileObject = pSrcFileObj;
		}
		
		do 
		{
			pStreamBuffer = MyAllocateMemory(PagedPool, uStreamInfoSize);
			if(pStreamBuffer == NULL)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			ntStatus = FltQueryInformationFileSyncronous(pSrcInstance,
											   pSrcFileObject,
											   pStreamBuffer,
											   uStreamInfoSize,
											   FileStreamInformation,
											   NULL);
			if(NT_SUCCESS(ntStatus))
				break;

			uStreamInfoSize += PAGE_SIZE;
			ExFreePool(pStreamBuffer);	
			pStreamBuffer = NULL;

		} while (ntStatus == STATUS_BUFFER_OVERFLOW || ntStatus == STATUS_BUFFER_TOO_SMALL);

		if( ntStatus == STATUS_INVALID_PARAMETER )
		{
			fsAttribInfomation = (FILE_FS_ATTRIBUTE_INFORMATION*)MyNew(BYTE, length);
			if(!fsAttribInfomation)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			ntStatus = FltQueryVolumeInformation(pSrcInstance, &iosb, fsAttribInfomation,
				length, FileFsAttributeInformation);
			if(!NT_SUCCESS(ntStatus))
				__leave;

			if(0 != _wcsnicmp(L"NTFS", 
				fsAttribInfomation->FileSystemName, 
				fsAttribInfomation->FileSystemNameLength/sizeof(WCHAR))
				)
			{
				ntStatus = SbDoCopyFile(pFilter,
					pSrcFileObject,
					pSrcInstance,
					pSrcFileName,
					pDstInstance,
					pDstFileName,
					bDirectory);
				 
				__leave;
			}
		}

		if(! NT_SUCCESS(ntStatus))
			__leave;

		pStreamInfo = (PFILE_STREAM_INFORMATION)pStreamBuffer;
		while(TRUE)
		{
			ustrTmpName.MaximumLength = ustrTmpName.Length = (USHORT)pStreamInfo->StreamNameLength;
			ustrTmpName.Buffer = pStreamInfo->StreamName;
			if( RtlEqualUnicodeString(&ustrTmpName, &dataStreamName, TRUE) )
			{
				ntStatus = SbDoCopyFile(pFilter,
										 pSrcFileObject,
										 pSrcInstance,
										 pSrcFileName,
										 pDstInstance,
										 pDstFileName,
										 bDirectory);
				
				if(! NT_SUCCESS(ntStatus) && STATUS_SB_DIR_CREATED != ntStatus)
					break;

				if(pStreamInfo->NextEntryOffset == 0)
					break;

				pStreamInfo = (PFILE_STREAM_INFORMATION)((ULONG_PTR)pStreamInfo + pStreamInfo->NextEntryOffset);
				continue;
			}

			ustrSrcFileName.MaximumLength = ustrSrcFileName.Length = pSrcFileName->Length + (USHORT)pStreamInfo->StreamNameLength;
			ustrSrcFileName.Buffer = MyAllocateMemory(PagedPool, ustrSrcFileName.Length);

			ustrDstFileName.MaximumLength = ustrDstFileName.Length = pDstFileName->Length + (USHORT)pStreamInfo->StreamNameLength;
			ustrDstFileName.Buffer = MyAllocateMemory(PagedPool, ustrDstFileName.Length);
			if(ustrSrcFileName.Buffer == NULL || ustrDstFileName.Buffer == NULL)
			{
				if(ustrSrcFileName.Buffer != NULL)
				{
					ExFreePool(ustrSrcFileName.Buffer);
					ustrSrcFileName.Buffer = NULL;	
				}
				if(ustrDstFileName.Buffer != NULL)
				{
					ExFreePool(ustrDstFileName.Buffer);
					ustrDstFileName.Buffer = NULL;
				}

				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			RtlCopyMemory(ustrSrcFileName.Buffer, pSrcFileName->Buffer, pSrcFileName->Length);
			RtlCopyMemory(ustrSrcFileName.Buffer + pSrcFileName->Length / sizeof(WCHAR),
						  pStreamInfo->StreamName,
						  pStreamInfo->StreamNameLength);

			RtlCopyMemory(ustrDstFileName.Buffer, pDstFileName->Buffer, pDstFileName->Length);
			RtlCopyMemory(ustrDstFileName.Buffer + pDstFileName->Length / sizeof(WCHAR),
						  pStreamInfo->StreamName,
						  pStreamInfo->StreamNameLength);

			ntStatus = SbDoCopyFile(pFilter,
									 pSrcFileObject,
									 pSrcInstance,
									 &ustrSrcFileName,
									 pDstInstance,
									 &ustrDstFileName,
									 bDirectory);

			ExFreePool(ustrSrcFileName.Buffer);
			ustrSrcFileName.Buffer = NULL;

			ExFreePool(ustrDstFileName.Buffer);
			ustrDstFileName.Buffer = NULL;


			if(! NT_SUCCESS(ntStatus) && ntStatus != STATUS_SB_DIR_CREATED)
				break;


			if(pStreamInfo->NextEntryOffset == 0)
				break;

			pStreamInfo = (PFILE_STREAM_INFORMATION)((ULONG_PTR)pStreamInfo + pStreamInfo->NextEntryOffset);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}

	MyDelete(fsAttribInfomation);

	if(!pSrcFileObj && pSrcFileObject)
		ObDereferenceObject(pSrcFileObject);

	if(hFile)
		FltClose(hFile);

	if(pStreamBuffer)
	{
		ExFreePool(pStreamBuffer);
		pStreamBuffer = NULL;
	}
	return ntStatus;
}

NTSTATUS
SbDoCopyFile(
	IN PFLT_FILTER	pFilter,
	IN PFILE_OBJECT	pSrcObject,
	IN PFLT_INSTANCE	pSrcInstance,
	IN PUNICODE_STRING	pSrcFileName,
	IN PFLT_INSTANCE	pDstInstance,
	IN PUNICODE_STRING	pDstFileName,
	IN BOOLEAN 			bDirectory
	)
{
	NTSTATUS		ntStatus = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES	objSrcAttrib;
	OBJECT_ATTRIBUTES	objDstAttrib;
	HANDLE			hSrcFile = NULL;
	HANDLE			hDstFile = NULL;
	PFILE_OBJECT	pSrcFileObject = NULL;
	PFILE_OBJECT	pDstFileObject = NULL;
	IO_STATUS_BLOCK	ioStatus;
	LARGE_INTEGER	liOffset;
	ULONG			uReadSize;
	ULONG			uWriteSize;
	PVOID			pBuffer = NULL;
	ULONG 			CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT;
	
	__try
	{
		if(pFilter == NULL || 
			pSrcInstance == NULL || 
			pSrcFileName == NULL || 
			pDstInstance == NULL || 
			pDstFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(bDirectory)
			CreateOptions |= FILE_DIRECTORY_FILE;
			

		if(!bDirectory)
		{
			if(!pSrcObject)
			{
				InitializeObjectAttributes(&objSrcAttrib,
										   pSrcFileName,
										   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
										   NULL,
										   NULL);
				
				ntStatus = FltCreateFile(pFilter,
										 pSrcInstance,    
										 &hSrcFile,
										 FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
										 &objSrcAttrib,
										 &ioStatus,
										 0,
										 FILE_ATTRIBUTE_NORMAL,
										 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										 FILE_OPEN,
										 CreateOptions,
										 NULL,0,0);
				if(! NT_SUCCESS(ntStatus))
					__leave;

				ntStatus = ObReferenceObjectByHandle(hSrcFile,
													 FILE_ANY_ACCESS,
													 NULL,
													 KernelMode,
													 &pSrcFileObject,
													 NULL);
				if(! NT_SUCCESS(ntStatus))
					__leave;
			}
			else
				pSrcFileObject = pSrcObject;
		}

		InitializeObjectAttributes(&objDstAttrib,
								   pDstFileName,
								   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								   NULL,
								   NULL);

		ntStatus = FltCreateFile(pFilter,
								 pDstInstance,
								 &hDstFile,
								 GENERIC_WRITE | SYNCHRONIZE,
								 &objDstAttrib,
								 &ioStatus,
								 0,
								 FILE_ATTRIBUTE_NORMAL,
								 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
								 FILE_CREATE,
								 CreateOptions,
								 NULL,0,0);
		if(! NT_SUCCESS(ntStatus))
			__leave;

		ntStatus = ObReferenceObjectByHandle(hDstFile,
											 FILE_ANY_ACCESS,
											 NULL,
											 KernelMode,
											 &pDstFileObject,
											 NULL);

		if(! NT_SUCCESS(ntStatus))
			__leave;

		if(bDirectory)
		{
			ntStatus = STATUS_SB_DIR_CREATED;
			__leave;
		}

		pBuffer = MyAllocateMemory(PagedPool, PAGE_SIZE);
		if(pBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		liOffset.QuadPart = pSrcFileObject->CurrentByteOffset.QuadPart;

		while(NT_SUCCESS(ntStatus))
		{
			uReadSize = 0;	uWriteSize = 0;

			ntStatus = FltReadFile(pSrcInstance,
								   pSrcFileObject,
								   0,
								   PAGE_SIZE,
								   pBuffer,
								   FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
								   &uReadSize,
								   NULL,
								   NULL);
			if( (!NT_SUCCESS(ntStatus)) || (uReadSize == 0) )
				break;

			pSrcFileObject->CurrentByteOffset.QuadPart += uReadSize;

			ntStatus = FltWriteFile(pDstInstance,
									pDstFileObject,
									0,
									uReadSize,
									pBuffer,
									0,
									&uWriteSize,
									NULL,
									NULL);
			if(!NT_SUCCESS(ntStatus))
				break;

			if(uReadSize < PAGE_SIZE)
				break;
		}

		pSrcFileObject->CurrentByteOffset.QuadPart = liOffset.QuadPart;
		if(ntStatus == STATUS_END_OF_FILE)
		{
			ntStatus = STATUS_SUCCESS;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if(pBuffer != NULL)
		ExFreePool(pBuffer);

	if(pDstFileObject != NULL)
		ObDereferenceObject(pDstFileObject);
	if(hDstFile != NULL)
		FltClose(hDstFile);
	if(pSrcFileObject != NULL && !pSrcObject)
		ObDereferenceObject(pSrcFileObject);
	if(hSrcFile != NULL)
		FltClose(hSrcFile);

	return ntStatus;
}

PFLT_INSTANCE 
SbGetVolumeInstance(
	IN PFLT_FILTER		pFilter,
	IN PUNICODE_STRING	pVolumeName
	)
{
	NTSTATUS		ntStatus;
	PFLT_INSTANCE	pInstance = NULL;
	PFLT_VOLUME		pVolumeList[MAX_VOLUME_CHARS];
	ULONG			uRet;
	UNICODE_STRING	uniName ={0};
	ULONG 			index = 0;
	WCHAR			wszNameBuffer[MAX_PATH] = {0};

	
	ntStatus = FltEnumerateVolumes(pFilter,
		NULL,
		0,
		&uRet);
	if(ntStatus != STATUS_BUFFER_TOO_SMALL)
	{
		return NULL;
	}
	
	ntStatus = FltEnumerateVolumes(pFilter,
		pVolumeList,
		uRet,
		&uRet);
	
	if(!NT_SUCCESS(ntStatus))
	{

		return NULL;
	}
	uniName.Buffer = wszNameBuffer;
	
	if (uniName.Buffer == NULL)
	{
		for (index = 0;index< uRet; index++)
			FltObjectDereference(pVolumeList[index]);
		
		return NULL;
	}
	
	uniName.MaximumLength = MAX_PATH*sizeof(WCHAR);
	
	for (index = 0; index < uRet; index++)
	{
		uniName.Length = 0;

		ntStatus = FltGetVolumeName( pVolumeList[index],
										&uniName,
										NULL);

		if(!NT_SUCCESS(ntStatus))
			continue;

		if(RtlCompareUnicodeString(&uniName,
									pVolumeName,
									TRUE) != 0)
			continue;
		
		ntStatus = FltGetVolumeInstanceFromName(pFilter,
												pVolumeList[index],
												NULL,
												&pInstance);

		if(NT_SUCCESS(ntStatus))
		{
			FltObjectDereference(pInstance);
			break;
		}
	}
	
	for (index = 0;index< uRet; index++)
		FltObjectDereference(pVolumeList[index]);

	return pInstance;
}


NTSTATUS 
SbIsDirectory(
	IN PFILE_OBJECT fileObject,
	IN PUNICODE_STRING dirName, 
	IN PFLT_FILTER filter, 
	IN PFLT_INSTANCE instance, 
	OUT BOOLEAN* directory
	)
{
	PFILE_OBJECT	pFileObject = NULL;
	HANDLE			hFile = NULL;
	FILE_STANDARD_INFORMATION 	stdInfo;
	NTSTATUS 		ntStatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES	objAttrib;
	IO_STATUS_BLOCK		ioStatus;

	*directory = FALSE;

	__try
	{
		if(fileObject == NULL)
		{
	
			InitializeObjectAttributes(&objAttrib,
				dirName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);
			
			ntStatus = FltCreateFile(filter,
										instance,    
										&hFile,
										GENERIC_READ | SYNCHRONIZE,
										&objAttrib,
										&ioStatus,
										0,
										FILE_ATTRIBUTE_NORMAL,
										FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										FILE_OPEN,
										FILE_SYNCHRONOUS_IO_NONALERT,
										NULL,0,0);
			if(! NT_SUCCESS(ntStatus))
				__leave;
			
			ntStatus = ObReferenceObjectByHandle(hFile,
										FILE_ANY_ACCESS,
										NULL,
										KernelMode,
										&pFileObject,
										NULL);
			if(! NT_SUCCESS(ntStatus))		
				__leave;		
		}
		else
		{
			pFileObject = fileObject;
		}
		
		ntStatus = FltQueryInformationFileSyncronous(instance,
									pFileObject,
									&stdInfo,
									sizeof(FILE_STANDARD_INFORMATION),
									FileStandardInformation,
									NULL);
		
		if(NT_SUCCESS(ntStatus))
			*directory = stdInfo.Directory;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if(pFileObject && !fileObject)
	{
		ObDereferenceObject(pFileObject);
		pFileObject = NULL;
	}
	
	if(hFile)
	{
		FltClose(hFile);
		hFile = NULL;
	}
	
	return ntStatus;
}

BOOLEAN	 FltIsDelFlagExist( PFLT_FILTER	pFilter,PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName)
{
	return TRUE;
}