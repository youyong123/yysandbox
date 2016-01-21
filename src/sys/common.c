#include "ntifs.h"
#include <fltKernel.h>
#include "common.h"
#include "macro.h"
#include <strsafe.h>

#include "macro.h"
#include "UndocApi.h"
#include <windef.h>

#define MODULE_TAG 'injc'
#define	DEL_FLAGS	L"_del"

WCHAR DriveLetters[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

WCHAR *DriveLinks[] = {
	L"\\GLOBAL??\\A:",
	L"\\GLOBAL??\\B:",
	L"\\GLOBAL??\\C:",
	L"\\GLOBAL??\\D:",
	L"\\GLOBAL??\\E:",
	L"\\GLOBAL??\\F:",
	L"\\GLOBAL??\\G:",
	L"\\GLOBAL??\\H:",
	L"\\GLOBAL??\\I:",
	L"\\GLOBAL??\\J:",
	L"\\GLOBAL??\\K:",
	L"\\GLOBAL??\\L:",
	L"\\GLOBAL??\\M:",
	L"\\GLOBAL??\\N:",
	L"\\GLOBAL??\\O:",
	L"\\GLOBAL??\\P:",
	L"\\GLOBAL??\\Q:",
	L"\\GLOBAL??\\R:",
	L"\\GLOBAL??\\S:",
	L"\\GLOBAL??\\T:",
	L"\\GLOBAL??\\U:",
	L"\\GLOBAL??\\V:",
	L"\\GLOBAL??\\W:",
	L"\\GLOBAL??\\X:",
	L"\\GLOBAL??\\Y:",
	L"\\GLOBAL??\\Z:"
};

WCHAR *umDrivePrefixes[] = {
	L"A:",
	L"B:",
	L"C:",
	L"D:",
	L"E:",
	L"F:",
	L"G:",
	L"H:",
	L"I:",
	L"J:",
	L"K:",
	L"L:",
	L"M:",
	L"N:",
	L"O:",
	L"P:",
	L"Q:",
	L"R:",
	L"S:",
	L"T:",
	L"U:",
	L"V:",
	L"W:",
	L"X:",
	L"Y:",
	L"Z:"
};


VOID SleepImp(__int64 ReqInterval)
{
	LARGE_INTEGER	Interval;
	PAGED_CODE();
	*(__int64*)&Interval = -(ReqInterval * 10000000L);
	KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}

PVOID MyAllocateMemory(IN POOL_TYPE PoolType, IN SIZE_T	NumberOfBytes)
{
	PVOID	pBuffer;

	pBuffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, 'FCLM');
	if (pBuffer != NULL)
	{
		RtlZeroMemory(pBuffer, NumberOfBytes);
	}
	return pBuffer;
}


NTSTATUS AllocateUnicodeString( PUNICODE_STRING String)
{
	PAGED_CODE();

	String->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, String->MaximumLength, 'LIB');

	if (String->Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	String->Length = 0;
	return STATUS_SUCCESS;
}

VOID FreeUnicodeString(PUNICODE_STRING String)
{
	PAGED_CODE();

	if (String->Buffer)
	{
		ExFreePoolWithTag(String->Buffer, 'LIB');
		String->Buffer = NULL;
	}
	String->Length = String->MaximumLength = 0;
	String->Buffer = NULL;
}


BOOLEAN
FltIsFileExist(
IN PFLT_FILTER	pFilter,
IN PFLT_INSTANCE	pInstance,
IN PUNICODE_STRING	pFileName,
OUT	PBOOLEAN		bDirectory
)
{
	NTSTATUS				ntStatus;
	OBJECT_ATTRIBUTES		objAttrib;
	HANDLE					hFile;
	IO_STATUS_BLOCK			ioStatus;
	FILE_BASIC_INFORMATION	fbi;
	PFILE_OBJECT			pFileObj = NULL;
	ULONG					retLen = 0;

	PAGED_CODE();
	if (pFilter == NULL || pInstance == NULL || pFileName == NULL)
	{
		return FALSE;
	}

	InitializeObjectAttributes(&objAttrib, pFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

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
		NULL, 0, 0);

	if (NT_SUCCESS(ntStatus))
	{
		if (bDirectory)
		{
			ntStatus = ObReferenceObjectByHandle(hFile, GENERIC_READ | GENERIC_WRITE, *IoFileObjectType, KernelMode, (PVOID*)&pFileObj, NULL);
			if (NT_SUCCESS(ntStatus))
			{
				ntStatus = FltQueryInformationFile(pInstance, pFileObj, &fbi, sizeof(fbi), FileBasicInformation, &retLen);
				if (NT_SUCCESS(ntStatus))
				{
					if (fbi.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						*bDirectory = TRUE;
					}
				}
				ObDereferenceObject(pFileObj);
			}
		}
		FltClose(hFile);
		return TRUE;
	}

	if (ntStatus == STATUS_SHARING_VIOLATION)
	{
		return TRUE;
	}
	return FALSE;
}


BOOLEAN  IsFileExist(PUNICODE_STRING pPath, OUT	PBOOLEAN bDirectory)
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
		if (bDirectory)
		{
			if (FileInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				*bDirectory = TRUE;
			}
		}
		bret = TRUE;
	}
	if (status == STATUS_SHARING_VIOLATION)
	{
		bret = TRUE;
	}
	return bret;
}

BOOLEAN GetDriveLetter(PCFLT_RELATED_OBJECTS FltObjects, PWCHAR pBuffer, ULONG bufferLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL irql = KeGetCurrentIrql();

	if (irql < APC_LEVEL)
	{
		BOOLEAN AreApcsDisabled = KeAreApcsDisabled();
		if (AreApcsDisabled == FALSE)
		{
			PDEVICE_OBJECT pDiskDevObj = NULL;
			status = FltGetDiskDeviceObject(FltObjects->Volume, &pDiskDevObj);
			if (NT_SUCCESS(status) && pDiskDevObj)
			{
				UNICODE_STRING DriveLetter = { 0 };
				status = IoVolumeDeviceToDosName(pDiskDevObj, &DriveLetter);
				if (NT_SUCCESS(status))
				{
					ULONG cbToCopy = min(DriveLetter.Length, bufferLength);
					RtlCopyMemory(pBuffer, DriveLetter.Buffer, cbToCopy);
					ExFreePool(DriveLetter.Buffer);
					ObDereferenceObject(pDiskDevObj);
					return TRUE;
				}
				ObDereferenceObject(pDiskDevObj);
			}
		}
	}
	return FALSE;
}


NTSTATUS
FltQueryInformationFileSyncronous(
IN PFLT_INSTANCE Instance,
IN PFILE_OBJECT FileObject,
OUT PVOID FileInformation,
IN ULONG Length,
IN FILE_INFORMATION_CLASS FileInformationClass,
OUT PULONG LengthReturned OPTIONAL
)
{
	return FltQueryInformationFile(Instance,
		FileObject,
		FileInformation,
		Length,
		FileInformationClass,
		LengthReturned
		);
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
	UNICODE_STRING	ustrSrcFileName = { 0, 0, 0 };
	UNICODE_STRING	ustrDstFileName = { 0, 0, 0 };
	UNICODE_STRING	ustrTmpName = { 0, 0, 0 };
	HANDLE			hFile = NULL;
	PFILE_OBJECT	pSrcFileObject = NULL;
	static UNICODE_STRING	dataStreamName = UNICODE_STRING_CONST("::$DATA");
	IO_STATUS_BLOCK					iosb = { 0 };
	FILE_FS_ATTRIBUTE_INFORMATION*	fsAttribInfomation = NULL;
	ULONG							length = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 20;

	__try
	{
		if (pFilter == NULL || pSrcInstance == NULL ||
			pSrcFileName == NULL || pDstInstance == NULL || pDstFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if (!pSrcFileObj && !pSrcFileName)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if (!pSrcFileObj)
		{
			OBJECT_ATTRIBUTES	objAttrib;
			IO_STATUS_BLOCK		ioStatus = { 0, 0 };

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
				NULL, 0, 0);
			if (!NT_SUCCESS(ntStatus))
				__leave;

			ntStatus = ObReferenceObjectByHandle(hFile,
				FILE_ANY_ACCESS,
				NULL,
				KernelMode,
				&pSrcFileObject,
				NULL);
			if (!NT_SUCCESS(ntStatus))
				__leave;

		}
		else
		{
			pSrcFileObject = pSrcFileObj;
		}

		do
		{
			pStreamBuffer = MyAllocateMemory(PagedPool, uStreamInfoSize);
			if (pStreamBuffer == NULL)
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
			if (NT_SUCCESS(ntStatus))
				break;

			uStreamInfoSize += PAGE_SIZE;
			ExFreePool(pStreamBuffer);
			pStreamBuffer = NULL;

		} while (ntStatus == STATUS_BUFFER_OVERFLOW || ntStatus == STATUS_BUFFER_TOO_SMALL);

		if (ntStatus == STATUS_INVALID_PARAMETER)
		{
			fsAttribInfomation = (FILE_FS_ATTRIBUTE_INFORMATION*)MyNew(BYTE, length);
			if (!fsAttribInfomation)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			ntStatus = FltQueryVolumeInformation(pSrcInstance, &iosb, fsAttribInfomation,
				length, FileFsAttributeInformation);
			if (!NT_SUCCESS(ntStatus))
				__leave;

			if (0 != _wcsnicmp(L"NTFS",
				fsAttribInfomation->FileSystemName,
				fsAttribInfomation->FileSystemNameLength / sizeof(WCHAR))
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

		if (!NT_SUCCESS(ntStatus))
			__leave;

		pStreamInfo = (PFILE_STREAM_INFORMATION)pStreamBuffer;
		while (TRUE)
		{
			ustrTmpName.MaximumLength = ustrTmpName.Length = (USHORT)pStreamInfo->StreamNameLength;
			ustrTmpName.Buffer = pStreamInfo->StreamName;
			if (RtlEqualUnicodeString(&ustrTmpName, &dataStreamName, TRUE))
			{
				ntStatus = SbDoCopyFile(pFilter,
					pSrcFileObject,
					pSrcInstance,
					pSrcFileName,
					pDstInstance,
					pDstFileName,
					bDirectory);

				if (!NT_SUCCESS(ntStatus) && STATUS_SB_DIR_CREATED != ntStatus)
					break;

				if (pStreamInfo->NextEntryOffset == 0)
					break;

				pStreamInfo = (PFILE_STREAM_INFORMATION)((ULONG_PTR)pStreamInfo + pStreamInfo->NextEntryOffset);
				continue;
			}

			ustrSrcFileName.MaximumLength = ustrSrcFileName.Length = pSrcFileName->Length + (USHORT)pStreamInfo->StreamNameLength;
			ustrSrcFileName.Buffer = MyAllocateMemory(PagedPool, ustrSrcFileName.Length);

			ustrDstFileName.MaximumLength = ustrDstFileName.Length = pDstFileName->Length + (USHORT)pStreamInfo->StreamNameLength;
			ustrDstFileName.Buffer = MyAllocateMemory(PagedPool, ustrDstFileName.Length);
			if (ustrSrcFileName.Buffer == NULL || ustrDstFileName.Buffer == NULL)
			{
				if (ustrSrcFileName.Buffer != NULL)
				{
					ExFreePool(ustrSrcFileName.Buffer);
					ustrSrcFileName.Buffer = NULL;
				}
				if (ustrDstFileName.Buffer != NULL)
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


			if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_SB_DIR_CREATED)
				break;


			if (pStreamInfo->NextEntryOffset == 0)
				break;

			pStreamInfo = (PFILE_STREAM_INFORMATION)((ULONG_PTR)pStreamInfo + pStreamInfo->NextEntryOffset);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	MyDelete(fsAttribInfomation);

	if (!pSrcFileObj && pSrcFileObject)
		ObDereferenceObject(pSrcFileObject);

	if (hFile)
		FltClose(hFile);

	if (pStreamBuffer)
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
		if (pFilter == NULL ||
			pSrcInstance == NULL ||
			pSrcFileName == NULL ||
			pDstInstance == NULL ||
			pDstFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if (bDirectory)
			CreateOptions |= FILE_DIRECTORY_FILE;


		if (!bDirectory)
		{
			if (!pSrcObject)
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
					NULL, 0, 0);
				if (!NT_SUCCESS(ntStatus))
					__leave;

				ntStatus = ObReferenceObjectByHandle(hSrcFile,
					FILE_ANY_ACCESS,
					NULL,
					KernelMode,
					&pSrcFileObject,
					NULL);
				if (!NT_SUCCESS(ntStatus))
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
			NULL, 0, 0);
		if (!NT_SUCCESS(ntStatus))
			__leave;

		ntStatus = ObReferenceObjectByHandle(hDstFile,
			FILE_ANY_ACCESS,
			NULL,
			KernelMode,
			&pDstFileObject,
			NULL);

		if (!NT_SUCCESS(ntStatus))
			__leave;

		if (bDirectory)
		{
			ntStatus = STATUS_SB_DIR_CREATED;
			__leave;
		}

		pBuffer = MyAllocateMemory(PagedPool, PAGE_SIZE);
		if (pBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		liOffset.QuadPart = pSrcFileObject->CurrentByteOffset.QuadPart;

		while (NT_SUCCESS(ntStatus))
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
			if ((!NT_SUCCESS(ntStatus)) || (uReadSize == 0))
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
			if (!NT_SUCCESS(ntStatus))
				break;

			if (uReadSize < PAGE_SIZE)
				break;
		}

		pSrcFileObject->CurrentByteOffset.QuadPart = liOffset.QuadPart;
		if (ntStatus == STATUS_END_OF_FILE)
		{
			ntStatus = STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (pBuffer != NULL)
		ExFreePool(pBuffer);

	if (pDstFileObject != NULL)
		ObDereferenceObject(pDstFileObject);
	if (hDstFile != NULL)
		FltClose(hDstFile);
	if (pSrcFileObject != NULL && !pSrcObject)
		ObDereferenceObject(pSrcFileObject);
	if (hSrcFile != NULL)
		FltClose(hSrcFile);

	return ntStatus;
}

PFLT_INSTANCE  SbGetVolumeInstance(IN PFLT_FILTER pFilter, IN PUNICODE_STRING pVolumeName)
{
	NTSTATUS		ntStatus;
	PFLT_INSTANCE	pInstance = NULL;
	PFLT_VOLUME		pVolumeList[MAX_VOLUME_CHARS];
	ULONG			uRet = MAX_VOLUME_CHARS;
	UNICODE_STRING	uniName = { 0 };
	ULONG 			index = 0;
	WCHAR			wszNameBuffer[SHORT_NAME_LEN] = { 0 };

	ntStatus = FltEnumerateVolumes(pFilter, pVolumeList, uRet, &uRet);
	if (!NT_SUCCESS(ntStatus))
	{
		return NULL;
	}
	for (index = 0; index < uRet; index++)
	{
		uniName.Length = 0;
		uniName.Buffer = wszNameBuffer;
		uniName.MaximumLength = SHORT_NAME_LEN*sizeof(WCHAR);

		ntStatus = FltGetVolumeName(pVolumeList[index], &uniName, NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			continue;
		}
		if (!RtlEqualUnicodeString(&uniName, pVolumeName, TRUE))
		{
			continue;
		}

		ntStatus = FltGetVolumeInstanceFromName(pFilter, pVolumeList[index], NULL, &pInstance);
		if (NT_SUCCESS(ntStatus))
		{
			FltObjectDereference(pInstance);
			break;
		}
	}

	for (index = 0; index < uRet; index++)
	{
		FltObjectDereference(pVolumeList[index]);
	}
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
		if (fileObject == NULL)
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
				NULL, 0, 0);
			if (!NT_SUCCESS(ntStatus))
				__leave;

			ntStatus = ObReferenceObjectByHandle(hFile,
				FILE_ANY_ACCESS,
				NULL,
				KernelMode,
				&pFileObject,
				NULL);
			if (!NT_SUCCESS(ntStatus))
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

		if (NT_SUCCESS(ntStatus))
			*directory = stdInfo.Directory;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (pFileObject && !fileObject)
	{
		ObDereferenceObject(pFileObject);
		pFileObject = NULL;
	}

	if (hFile)
	{
		FltClose(hFile);
		hFile = NULL;
	}

	return ntStatus;
}

BOOLEAN	 FltIsDelFlagExist(PFLT_FILTER	pFilter, PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName)
{
	UNICODE_STRING		usNewName = { 0, 0, NULL };
	WCHAR				delFlag[] = DEL_FLAGS;
	NTSTATUS			status;
	BOOLEAN				bExist = FALSE;

	if (NULL == pFilter || NULL == pInstance || NULL == pFileName)
	{
		return FALSE;
	}
	
	usNewName.MaximumLength = pFileName->Length + sizeof(delFlag);
	status = AllocateUnicodeString(&usNewName);
	if (NT_SUCCESS(status))
	{
		RtlCopyUnicodeString(&usNewName, pFileName);
		if (usNewName.Buffer[usNewName.Length/sizeof(WCHAR)-1]==L'\\')
		{
			usNewName.Buffer[usNewName.Length / sizeof(WCHAR) - 1] = L'\0';
			usNewName.Length -= sizeof(WCHAR);
		}
		status = RtlAppendUnicodeToString(&usNewName, delFlag);
		if (NT_SUCCESS(status))
		{
			bExist = FltIsFileExist(pFilter, pInstance, &usNewName, NULL);
		}
	}
	FreeUnicodeString(&usNewName);
	return bExist;
}

BOOLEAN  AcquireResourceExclusive(__inout PERESOURCE Resource)
{
	BOOLEAN ret = FALSE;

	PAGED_CODE();

	KeEnterCriticalRegion();
	ret = ExAcquireResourceExclusiveLite(Resource, TRUE);
	return ret;
}


BOOLEAN  AcquireResourceShare(__inout PERESOURCE Resource)
{
	BOOLEAN ret;

	PAGED_CODE();

	KeEnterCriticalRegion();
	ret = ExAcquireResourceSharedLite(Resource, TRUE);
	return ret;
}


VOID ReleaseResource(__inout PERESOURCE Resource)
{
	PAGED_CODE();
	ExReleaseResourceLite(Resource);
	KeLeaveCriticalRegion();
}

ULONGLONG BKDRHashW(PWCHAR wstr)
{
	ULONGLONG seed = 131;
	ULONGLONG hash = 0;
	while (*wstr)
	{
		hash = hash*seed + (*wstr++);
	}
	return hash;
}

ULONGLONG APHashW(PWCHAR wstr)
{
	ULONGLONG hash = 0;
	int i;
	for (i = 0; *wstr; i++)
	{
		if ((i & 1) == 0)
		{
			hash ^= ((hash << 7) ^ (*wstr++) ^ (hash >> 3));
		}
		else
		{
			hash ^= (~((hash << 11) ^ (*wstr++) ^ (hash >> 5)));
		}
	}
	return hash;
}


ULONGLONG BKDRHashA(PCHAR wstr)
{
	ULONGLONG seed = 131;
	ULONGLONG hash = 0;
	while (*wstr)
	{
		hash = hash*seed + (*wstr++);
	}
	return hash;
}

ULONGLONG APHashA(PCHAR wstr)
{
	ULONGLONG hash = 0;
	int i;
	for (i = 0; *wstr; i++)
	{
		if ((i & 1) == 0)
		{
			hash ^= ((hash << 7) ^ (*wstr++) ^ (hash >> 3));
		}
		else
		{
			hash ^= (~((hash << 11) ^ (*wstr++) ^ (hash >> 5)));
		}
	}
	return hash;
}

BOOLEAN GetHostFromPost(const char* http_block, ULONG	http_len, char* pOutBuf, ULONG OutBufLen, BOOLEAN* pbMail, BOOLEAN* pbSpecial)
{
	ULONG	i = 0;
	ULONG	len = 0;
	ULONG	j = 0;
	BOOLEAN bFoundHost = FALSE;

	if (!http_block || !http_len || !pOutBuf || !OutBufLen)
	{
		return	FALSE;
	}

	len = http_len - 6;

	for (; http_block[i] && i < len; i++)
	{
		if (http_block[i] != '\n')
		{
			continue;
		}
		if (http_block[i + 1] == '\r' && http_block[i + 2] == '\n')
		{
			break;
		}
		if (_strnicmp(&http_block[i + 1], "Host:", strlen("Host:")) == 0)
		{
			bFoundHost = TRUE;
			break;
		}
	}
	if (bFoundHost)
	{
		i += 6;
		for (; http_block[i] && http_block[i] != '\r' && http_block[i] != '\n' && j < OutBufLen; i++)
		{
			if (http_block[i] != ' ')
			{
				pOutBuf[j] = http_block[i];
				j++;
			}
		}
		pOutBuf[j] = '\0';
		if (pbMail && pbSpecial)
		{
			if (strstr(pOutBuf, "mail"))
			{
				*pbMail = TRUE;
				if (strstr(pOutBuf, "189") || strstr(pOutBuf, "21cn"))
				{
					*pbSpecial = TRUE;
				}
				else
				{
					*pbSpecial = FALSE;
				}
			}
			else
			{
				*pbMail = FALSE;
			}
		}
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

WCHAR  my_towupper(WCHAR wch)
{
	if (wch >= L'a' && wch <= L'z')
	{
		return wch - L'a' + L'A';
	}
	return wch;
}
NTSTATUS ToUpperStringW(WCHAR* Src, WCHAR* Dest, USHORT cbDestLen)
{
	NTSTATUS	status = STATUS_SUCCESS;
	UNICODE_STRING	usSrc = { 0 };
	UNICODE_STRING  usDst = { 0 };
	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		RtlInitUnicodeString(&usSrc, Src);
		RtlInitEmptyUnicodeString(&usDst, Dest, cbDestLen);
		status = RtlUpcaseUnicodeString(&usDst, &usSrc, FALSE);
		if (NT_SUCCESS(status))
		{
			ULONG value = min(cbDestLen / sizeof(WCHAR) - 1, usDst.Length / sizeof(WCHAR));
			Dest[value] = L'\0';
		}
		else
		{
			*Dest = L'\0';
		}
	}
	else
	{
		int i = 0;
		ULONG value = 0;
		int j = cbDestLen / sizeof(WCHAR);
		for (; Src[i] && i<j; i++)
		{
			wchar_t k = my_towupper(Src[i]);
			Dest[i] = k;
		}
		value = min(j - 1, i);
		Dest[value] = L'\0';
	}
	return status;
}

PWCHAR GetProcFullPathById(IN  HANDLE   dwProcessId, PWCHAR pPath, PULONG pPathLen)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE hProcess;
	PEPROCESS pEprocess;
	ULONG returnedLength;
	PUNICODE_STRING imageName;

	PAGED_CODE();

	if (!pPathLen || !pPath)
	{
		return NULL;
	}
	*pPathLen = 0;

	Status = PsLookupProcessByProcessId(dwProcessId, &pEprocess);
	if (!NT_SUCCESS(Status))
	{
		pPath[0] = L'\0';
		return NULL;
	}
	Status = ObOpenObjectByPointer(pEprocess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &hProcess);
	if (!NT_SUCCESS(Status))
	{
		ObDereferenceObject(pEprocess);
		pPath[0] = L'\0';
		return NULL;
	}
	Status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, pPath, LONG_NAME_LEN*sizeof(WCHAR), &returnedLength);
	if (!NT_SUCCESS(Status) || ((PUNICODE_STRING)pPath)->Length >= LONG_NAME_LEN*sizeof(WCHAR))
	{
		ZwClose(hProcess);
		ObDereferenceObject(pEprocess);
		pPath[0] = L'\0';
		return NULL;
	}
	else
	{
		ULONG len = 0;
		imageName = (PUNICODE_STRING)pPath;
		*pPathLen = imageName->Length;
		len = imageName->Length;
		RtlMoveMemory(pPath, imageName->Buffer, imageName->Length);
		pPath[len / sizeof(WCHAR)] = L'\0';

	}
	ZwClose(hProcess);
	ObDereferenceObject(pEprocess);
	return pPath;
}

BOOLEAN GetProcNameFromPath(WCHAR* pFullProcPath, ULONG Len, WCHAR* ProcName, ULONG cbProcNameLen)
{
	ULONG NumOfChars = Len / sizeof(WCHAR);
	BOOLEAN bReached = FALSE;
	ULONG i = NumOfChars - 1;

	if (pFullProcPath == NULL || Len <= 48 || ProcName == NULL || cbProcNameLen <= 8)
	{
		return FALSE;
	}

	for (; i >= 23; i--)
	{
		if (pFullProcPath[i] == L'\\')
		{
			bReached = TRUE;
			break;
		}
	}
	if (bReached)
	{
		++i;
		StringCchCopyNW(ProcName, cbProcNameLen / sizeof(WCHAR), &pFullProcPath[i], NumOfChars - i);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

PWCHAR GetProcNameById(IN  HANDLE   dwProcessId, PWCHAR pProcName, ULONG ProcNameLen)
{
	WCHAR	procFullPath[LONG_NAME_LEN];
	ULONG	procFullPathLen = 0;
	if (GetProcFullPathById(dwProcessId, procFullPath, &procFullPathLen))
	{
		if (GetProcNameFromPath(procFullPath, procFullPathLen, pProcName, ProcNameLen))
		{
			return pProcName;
		}
	}
	return NULL;
}

NTSTATUS ResolveSymLink(PUNICODE_STRING obName, PUNICODE_STRING resolvedName)
{
	OBJECT_ATTRIBUTES	ObjectAttributes;
	HANDLE				hSymLink = NULL;
	NTSTATUS			Status = STATUS_SUCCESS;
	UNICODE_STRING		LinkTarget = { 0, 0, NULL };
	BOOLEAN				LinkTargetRef = FALSE;

	LinkTarget.MaximumLength = 512;
	LinkTarget.Length = 0;
	LinkTarget.Buffer = ExAllocatePoolWithTag(NonPagedPool, LinkTarget.MaximumLength, MODULE_TAG);
	if (LinkTarget.Buffer == NULL)
	{
		return STATUS_NO_MEMORY;
	}

	InitializeObjectAttributes(
		&ObjectAttributes,
		obName,
		(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
		NULL,
		NULL
		);

	Status = ZwOpenSymbolicLinkObject(&hSymLink, GENERIC_READ, &ObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		goto cleanup;
	}

	Status = ZwQuerySymbolicLinkObject(hSymLink, &LinkTarget, NULL);
	if (!NT_SUCCESS(Status))
	{
		goto cleanup;
	}

	if (resolvedName != NULL)
	{
		*resolvedName = LinkTarget;
		LinkTargetRef = TRUE;
	}

	Status = STATUS_SUCCESS;

cleanup:
	if (!LinkTargetRef)
	{
		ExFreePoolWithTag(LinkTarget.Buffer, MODULE_TAG);
	}

	if (hSymLink != NULL)
	{
		ZwClose(hSymLink);
	}
	return Status;
}

int PathSplitByLastComponent(PUNICODE_STRING path, PUNICODE_STRING remain)
{
	LONG    Index = 0;
	BOOLEAN bIndexFound = FALSE;

	for (Index = (path->Length - remain->Length) / sizeof(WCHAR) - 1; Index >= 0; Index--)
	{
		if (path->Buffer[Index] == L'\\')
		{
			bIndexFound = TRUE;
			break;
		}
	}

	if (!bIndexFound)
	{
		return -1;
	}

	remain->Buffer = ((PWCHAR)path->Buffer + Index);
	remain->Length = path->Length - (USHORT)Index*sizeof(WCHAR);
	remain->MaximumLength = remain->Length;

	return 0;
}


NTSTATUS ResolveSymPathStep(PUNICODE_STRING symPath, PUNICODE_STRING TargetName)
{
	UNICODE_STRING currSymPath = { 0, 0, NULL };
	UNICODE_STRING resolvedName = { 0, 0, NULL };
	UNICODE_STRING remainName = { 0, 0, NULL };
	NTSTATUS		Status = 0;

	RtlZeroMemory(TargetName, sizeof(UNICODE_STRING));
	currSymPath = *symPath;

	while (TRUE)
	{
		Status = ResolveSymLink(&currSymPath, &resolvedName);
		if (NT_SUCCESS(Status))
		{
			break;
		}

		if (0 != PathSplitByLastComponent(symPath, &remainName))
		{
			Status = STATUS_UNSUCCESSFUL;
			goto cleanup;
		}

		currSymPath.Length = symPath->Length - remainName.Length;
		currSymPath.MaximumLength = currSymPath.Length;

		if (currSymPath.Length == 0)
		{
			Status = STATUS_NOT_FOUND;
			goto cleanup;
		}
	}

	TargetName->MaximumLength = resolvedName.Length + remainName.Length + sizeof(WCHAR);
	TargetName->Length = 0;
	TargetName->Buffer = ExAllocatePoolWithTag(NonPagedPool, TargetName->MaximumLength, MODULE_TAG);
	if (TargetName->Buffer == NULL)
	{
		Status = STATUS_NO_MEMORY;
		goto cleanup;
	}

	RtlZeroMemory(TargetName->Buffer, TargetName->MaximumLength);
	Status = RtlAppendUnicodeStringToString(TargetName, &resolvedName);
	if (!NT_SUCCESS(Status))
	{
		goto cleanup;
	}

	if (remainName.Length > 0)
	{
		Status = RtlAppendUnicodeStringToString(TargetName, &remainName);
		if (!NT_SUCCESS(Status))
		{
			goto cleanup;
		}
	}

	Status = STATUS_SUCCESS;

cleanup:
	if (resolvedName.Buffer != NULL)
	{
		ExFreePoolWithTag(resolvedName.Buffer, MODULE_TAG);
	}

	if (!NT_SUCCESS(Status))
	{
		if (TargetName->Buffer != NULL)
		{
			ExFreePoolWithTag(TargetName->Buffer, MODULE_TAG);
		}
		RtlZeroMemory(TargetName, sizeof(UNICODE_STRING));
	}
	return Status;
}

NTSTATUS CRtlPrefixUnicodeStringReplace(PUNICODE_STRING Prefix, PUNICODE_STRING Replacement, PUNICODE_STRING Source, PUNICODE_STRING Destination)
{
	UNICODE_STRING target = { 0, 0, NULL };
	UNICODE_STRING sourceRemains = { 0, 0, NULL };
	NTSTATUS Status;

	if (!RtlPrefixUnicodeString(Prefix, Source, TRUE))
	{
		return STATUS_NOT_FOUND;
	}

	target.MaximumLength = Replacement->Length + Source->Length - Prefix->Length + sizeof(WCHAR);
	target.Length = 0;
	target.Buffer = ExAllocatePoolWithTag(NonPagedPool, target.MaximumLength, MODULE_TAG);
	if (target.Buffer == NULL)
	{
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(target.Buffer, target.MaximumLength);

	Status = RtlAppendUnicodeStringToString(&target, Replacement);
	if (!NT_SUCCESS(Status))
	{
		goto cleanup;
	}

	sourceRemains.Buffer = (PWCHAR)Source->Buffer + Prefix->Length / sizeof(WCHAR);
	sourceRemains.Length = Source->Length - Prefix->Length;
	sourceRemains.MaximumLength = sourceRemains.Length;

	Status = RtlAppendUnicodeStringToString(&target, &sourceRemains);
	if (!NT_SUCCESS(Status))
	{
		goto cleanup;
	}
	target.Buffer[target.Length / sizeof(WCHAR)] = L'\0';
	Status = STATUS_SUCCESS;
	*Destination = target;

cleanup:
	if (!NT_SUCCESS(Status))
	{
		if (target.Buffer != NULL)
			ExFreePoolWithTag(target.Buffer, MODULE_TAG);
	}

	return Status;
}


NTSTATUS GetSysrootNtPath(PUNICODE_STRING sysrootNtPath)
{
	NTSTATUS Status;
	UNICODE_STRING targetName = { 0, 0, NULL };
	UNICODE_STRING currName = { 0, 0, NULL };
	UNICODE_STRING Path = RTL_CONSTANT_STRING(L"\\SystemRoot");

	if (!sysrootNtPath)
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(sysrootNtPath, sizeof(UNICODE_STRING));

	currName.MaximumLength = Path.Length + sizeof(WCHAR);
	currName.Length = 0;
	currName.Buffer = ExAllocatePoolWithTag(NonPagedPool, Path.Length + sizeof(WCHAR), MODULE_TAG);
	if (currName.Buffer == NULL)
	{
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(currName.Buffer, currName.MaximumLength);

	Status = RtlAppendUnicodeStringToString(&currName, &Path);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(currName.Buffer, MODULE_TAG);
		return Status;
	}

	while (TRUE)
	{
		Status = ResolveSymPathStep(&currName, &targetName);
		if (!NT_SUCCESS(Status))
		{
			break;
		}

		ExFreePoolWithTag(currName.Buffer, MODULE_TAG);
		currName = targetName;
	}
	if (Status == STATUS_NOT_FOUND)
	{
		*sysrootNtPath = currName;
		return STATUS_SUCCESS;
	}
	else
	{
		if (currName.Buffer)
		{
			ExFreePoolWithTag(currName.Buffer, MODULE_TAG);
		}
		return Status;
	}
}

NTSTATUS ResolveNtPathToDosPath(PUNICODE_STRING pNtPath, PUNICODE_STRING UmPath)
{
	NTSTATUS Status = 0;
	LONG Index;
	UNICODE_STRING usDriveLink = { 0, 0, NULL };
	UNICODE_STRING volumeName = { 0, 0, NULL };
	UNICODE_STRING umDrivePrefix = { 0, 0, NULL };
	BOOLEAN found = FALSE;

	if (pNtPath == NULL || UmPath == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(UmPath, sizeof(UNICODE_STRING));


	for (Index = 0; Index < (LONG)wcslen(DriveLetters); Index++)
	{
		RtlInitUnicodeString(&usDriveLink, DriveLinks[Index]);

		Status = ResolveSymLink(&usDriveLink, &volumeName);
		if (!NT_SUCCESS(Status))
			continue;

		RtlInitUnicodeString(&umDrivePrefix, umDrivePrefixes[Index]);

		Status = CRtlPrefixUnicodeStringReplace(&volumeName, &umDrivePrefix, pNtPath, UmPath);
		ExFreePoolWithTag(volumeName.Buffer, MODULE_TAG);

		if (Status == STATUS_SUCCESS)
		{
			found = TRUE;
			goto cleanup;
		}
	}

cleanup:
	if (!found)
	{
		Status = STATUS_NOT_FOUND;
	}
	return Status;
}


NTSTATUS ResolveDosPathToNtPath(PUNICODE_STRING pDosPath, PUNICODE_STRING UmPath)
{
	NTSTATUS Status = 0;
	LONG Index = 0;
	UNICODE_STRING usDriveLink = { 0, 0, NULL };
	UNICODE_STRING volumeName = { 0, 0, NULL };
	UNICODE_STRING umDrivePrefix = { 0, 0, NULL };
	BOOLEAN found = FALSE;

	if (pDosPath == NULL || UmPath == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(UmPath, sizeof(UNICODE_STRING));


	for (Index = 0; Index < (LONG)wcslen(DriveLetters); Index++)
	{
		RtlInitUnicodeString(&usDriveLink, DriveLinks[Index]);

		Status = ResolveSymLink(&usDriveLink, &volumeName);
		if (!NT_SUCCESS(Status))
			continue;

		RtlInitUnicodeString(&umDrivePrefix, umDrivePrefixes[Index]);

		Status = CRtlPrefixUnicodeStringReplace(&umDrivePrefix, &volumeName, pDosPath, UmPath);
		ExFreePoolWithTag(volumeName.Buffer, MODULE_TAG);

		if (Status == STATUS_SUCCESS)
		{
			found = TRUE;
			goto cleanup;
		}
	}

cleanup:
	if (!found)
	{
		Status = STATUS_NOT_FOUND;
	}
	return Status;
}


BOOLEAN	 GetNtPathDir(const WCHAR* pNtPath, ULONG uNtPathLen, WCHAR* pNtPathDir, ULONG uNtPathDirLen)
{
	LONG i = uNtPathLen / sizeof(WCHAR) - 1;
	BOOLEAN bFind = FALSE;

	if (!pNtPath || !uNtPathDirLen || !uNtPathLen || !pNtPathDir)
	{
		return FALSE;
	}

	for (; i >= 0; i--)
	{
		if (pNtPath[i] == L'\\')
		{
			bFind = TRUE;
			break;
		}
	}
	if (bFind)
	{
		StringCchCopyNW(pNtPathDir, uNtPathDirLen / sizeof(WCHAR), pNtPath, i);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2)
{
	const wchar_t *s1, *s2;
	const wchar_t l = towlower(*wcs2);
	const wchar_t u = towupper(*wcs2);

	if (!*wcs2)
		return wcs1;

	for (; *wcs1; ++wcs1)
	{
		if (*wcs1 == l || *wcs1 == u)
		{
			s1 = wcs1 + 1;
			s2 = wcs2 + 1;

			while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
				++s1, ++s2;

			if (!*s2)
				return wcs1;
		}
	}

	return NULL;
}

WCHAR* ReplaceString(WCHAR* pString, WCHAR* pOldString, WCHAR* pNewString,BOOLEAN IgnoreCase)
{
	WCHAR*		pStart = NULL;
	WCHAR*		pReplaced = NULL;
	WCHAR*		pRet = NULL;
	ULONG		NewLength = 0;

	if (!pString || !pOldString || !pNewString || !*pString || !*pOldString || !*pNewString)
	{
		return NULL;
	}
	if (IgnoreCase)
	{
		pStart = wcsistr(pString, pOldString);
	}
	else
	{
		pStart = wcsstr(pString, pOldString);
	}
	
	if (!pStart)
	{
		return NULL;
	}
	NewLength = (wcslen(pString) - wcslen(pOldString) + wcslen(pNewString) + 1)*sizeof(WCHAR);
	pReplaced = (WCHAR*)ExAllocatePoolWithTag(PagedPool, NewLength, 'str');
	if (!pReplaced)
	{
		return NULL;
	}
	RtlZeroMemory(pReplaced, NewLength);
	StringCbCopyNW(pReplaced, NewLength, pString, (ULONG_PTR)pStart - (ULONG_PTR)pString);
	StringCbCatW(pReplaced, NewLength, pNewString);
	StringCbCatW(pReplaced, NewLength, pStart + wcslen(pOldString));
	return pReplaced;
}

void PrintProcessById(HANDLE PID)
{
#if DBG
	WCHAR	ProcPath[LONG_NAME_LEN];
	ULONG	Len;
	if (GetProcFullPathById(PID, ProcPath, &Len))
	{
		KdPrint(("pid:%d\r\npath:%ws\r\n", (DWORD)PID, ProcPath));
	}
#endif
}


NTSTATUS
SbConvertToSbName(
IN PUNICODE_STRING			pSandboxPath,
IN PUNICODE_STRING			pSrcName,
OUT PUNICODE_STRING			pDstName,
IN WCHAR*			pVolName
)
{
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;
	USHORT			usNameSize = 0;
	char*			pNameBuffer = NULL;
	UNICODE_STRING	ustrDevicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
	UNICODE_STRING	ustrHardVolumeName = { 0, 0, 0 };
	USHORT			usIndex = 0;

	__try
	{
		if (pSrcName == NULL || pDstName == NULL || NULL == pSandboxPath )
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if (RtlPrefixUnicodeString(pSandboxPath,pSrcName,TRUE))
		{
			ntStatus = STATUS_SB_REPARSED;
			__leave;
		}

		usNameSize = pSandboxPath->Length + pSrcName->Length - ustrDevicePrefix.Length;

		pNameBuffer = MyAllocateMemory(PagedPool, usNameSize);
		if (pNameBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}


		RtlCopyMemory(pNameBuffer,
			pSandboxPath->Buffer,
			pSandboxPath->Length
			);
		RtlCopyMemory(pNameBuffer + pSandboxPath->Length,
			pSrcName->Buffer + ustrDevicePrefix.Length / sizeof(WCHAR),
			pSrcName->Length - ustrDevicePrefix.Length
			);


		pDstName->Buffer = (PWSTR)pNameBuffer;
		pDstName->MaximumLength = pDstName->Length = usNameSize;

		ntStatus = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}

	return ntStatus;
}

NTSTATUS NtRenameFile(WCHAR *szFileName, WCHAR *szNewFileName, BOOLEAN ReplaceIfExists, HANDLE RootDirectory)
{
	OBJECT_ATTRIBUTES 			objectAttributes = { 0 };
	IO_STATUS_BLOCK 			iostatus = { 0 };
	HANDLE 						hfile = NULL;
	UNICODE_STRING 				uFile = { 0 };
	NTSTATUS					ntStatus = 0;
	PFILE_RENAME_INFORMATION	pFbi = NULL;
	ULONG						fbiLen = 0;

	if (NULL == szFileName || NULL == szNewFileName)
	{
		return STATUS_INVALID_PARAMETER;
	}
	fbiLen = sizeof(FILE_RENAME_INFORMATION) + sizeof(WCHAR)*wcslen(szNewFileName);
	pFbi = MyAllocateMemory(PagedPool, fbiLen);
	if (!pFbi)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlInitUnicodeString(&uFile, szFileName);
	InitializeObjectAttributes(&objectAttributes,&uFile,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
	ntStatus = ZwCreateFile(&hfile,
		GENERIC_READ,
		&objectAttributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pFbi);
		return ntStatus;
	}
	pFbi->ReplaceIfExists = ReplaceIfExists;
	pFbi->RootDirectory = RootDirectory;
	StringCchCopyW(pFbi->FileName, wcslen(szNewFileName)+sizeof(WCHAR), szNewFileName);
	pFbi->FileNameLength = sizeof(WCHAR)*wcslen(szNewFileName);
	ntStatus = ZwSetInformationFile(hfile,&iostatus,pFbi,fbiLen,FileRenameInformation);
	ExFreePool(pFbi);
	ZwClose(hfile);
	return ntStatus;
}
