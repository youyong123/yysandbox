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

NTSTATUS GetFileSize(IN PFLT_INSTANCE Instance, IN PFILE_OBJECT FileObject, OUT PLARGE_INTEGER pFileSize)
{
	FILE_NETWORK_OPEN_INFORMATION	FileInformation;
	NTSTATUS						status = STATUS_SUCCESS;
	ULONG							Length = 0;

	if (!Instance || !FileObject || !pFileSize)
	{
		return STATUS_INVALID_PARAMETER;
	}
	status = FltQueryInformationFile(Instance, FileObject,&FileInformation,sizeof(FILE_NETWORK_OPEN_INFORMATION),FileNetworkOpenInformation,&Length);
	if (NT_SUCCESS(status))
	{
		*pFileSize = FileInformation.EndOfFile;
	}
	return status;
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

NTSTATUS FltCreateDelFlagExist(PFLT_FILTER	pFilter, PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName)
{
	UNICODE_STRING			usNewName = { 0, 0, NULL };
	WCHAR					delFlag[] = DEL_FLAGS;
	NTSTATUS				status;
	OBJECT_ATTRIBUTES		objAttrib = { 0 };
	HANDLE					hFile = NULL;
	IO_STATUS_BLOCK 		io_status = { 0 };

	if (NULL == pFilter || NULL == pInstance || NULL == pFileName)
	{
		return STATUS_INVALID_PARAMETER;
	}

	usNewName.MaximumLength = pFileName->Length + sizeof(delFlag);
	status = AllocateUnicodeString(&usNewName);
	if (NT_SUCCESS(status))
	{
		RtlCopyUnicodeString(&usNewName, pFileName);
		if (usNewName.Buffer[usNewName.Length / sizeof(WCHAR) - 1] == L'\\')
		{
			usNewName.Buffer[usNewName.Length / sizeof(WCHAR) - 1] = L'\0';
			usNewName.Length -= sizeof(WCHAR);
		}
		status = RtlAppendUnicodeToString(&usNewName, delFlag);

		if (NT_SUCCESS(status))
		{
			InitializeObjectAttributes(&objAttrib, &usNewName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			status = FltCreateFile(
				pFilter,
				pInstance,
				&hFile,
				SYNCHRONIZE | DELETE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
				&objAttrib,
				&io_status,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_OPEN_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0,
				0
				);
			if (NT_SUCCESS(status))
			{
				FltClose(hFile);
			}
		}
	}
	FreeUnicodeString(&usNewName);
	return status;
}

NTSTATUS DeleteFile(PFLT_FILTER	pFilter, PFLT_INSTANCE pInstance, IN PUNICODE_STRING pusFileName)
{
	NTSTATUS			status;
	HANDLE				hFile = NULL;
	OBJECT_ATTRIBUTES	fileOA;
	IO_STATUS_BLOCK		ioSB;

	if (!pFilter || !pInstance || !pusFileName)
	{
		return STATUS_INVALID_PARAMETER;
	}
	InitializeObjectAttributes(
		&fileOA,
		pusFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);
	status = FltCreateFile(
		pFilter,
		pInstance,
		&hFile,
		DELETE,
		&fileOA,
		&ioSB,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_DELETE_ON_CLOSE,
		NULL,
		0,
		0
		);
	if (NT_SUCCESS(status))
	{
		FltClose(hFile);
	}
	return status;
}

NTSTATUS FltDeleteDelFlagExist(PFLT_FILTER	pFilter, PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName)
{
	UNICODE_STRING			usNewName = { 0, 0, NULL };
	WCHAR					delFlag[] = DEL_FLAGS;
	NTSTATUS				status;

	if (NULL == pFilter || NULL == pInstance || NULL == pFileName)
	{
		return STATUS_INVALID_PARAMETER;
	}

	usNewName.MaximumLength = pFileName->Length + sizeof(delFlag);
	status = AllocateUnicodeString(&usNewName);
	if (NT_SUCCESS(status))
	{
		RtlCopyUnicodeString(&usNewName, pFileName);
		if (usNewName.Buffer[usNewName.Length / sizeof(WCHAR) - 1] == L'\\')
		{
			usNewName.Buffer[usNewName.Length / sizeof(WCHAR) - 1] = L'\0';
			usNewName.Length -= sizeof(WCHAR);
		}
		status = RtlAppendUnicodeToString(&usNewName, delFlag);

		if (NT_SUCCESS(status))
		{
			status = DeleteFile(pFilter, pInstance, &usNewName);
		}
	}
	FreeUnicodeString(&usNewName);
	return status;
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
//	WCHAR*		pRet = NULL;
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
	NewLength = (ULONG)(wcslen(pString) - wcslen(pOldString) + wcslen(pNewString) + 1)*sizeof(WCHAR);
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
IN WCHAR*					pVolName
)
{
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;
	USHORT			usNameSize = 0;
	char*			pNameBuffer = NULL;
	UNICODE_STRING	ustrDevicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");

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
	fbiLen = (ULONG)sizeof(FILE_RENAME_INFORMATION) + (ULONG)(sizeof(WCHAR)*wcslen(szNewFileName));
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
	pFbi->FileNameLength = (ULONG)(sizeof(WCHAR)*wcslen(szNewFileName));
	ntStatus = ZwSetInformationFile(hfile,&iostatus,pFbi,fbiLen,FileRenameInformation);
	ExFreePool(pFbi);
	ZwClose(hfile);
	return ntStatus;
}

NTSTATUS
NcCreateFileHelper(
_In_ PFLT_FILTER Filter,
_In_opt_ PFLT_INSTANCE Instance,
_Out_ PHANDLE FileHandle,
_Outptr_opt_ PFILE_OBJECT *FileObject,
_In_ ACCESS_MASK DesiredAccess,
_In_ POBJECT_ATTRIBUTES ObjectAttributes,
_Out_ PIO_STATUS_BLOCK IoStatusBlock,
_In_opt_ PLARGE_INTEGER AllocationSize,
_In_ ULONG FileAttributes,
_In_ ULONG ShareAccess,
_In_ ULONG CreateDisposition,
_In_ ULONG CreateOptions,
_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
_In_ ULONG EaLength,
_In_ ULONG Flags,
_In_opt_ PFILE_OBJECT ParentFileObject
)
{
	IO_DRIVER_CREATE_CONTEXT	DriverContext;
	NTSTATUS					Status;
	PAGED_CODE();

	IoInitializeDriverCreateContext(&DriverContext);

	if (ARGUMENT_PRESENT(ParentFileObject))
	{
		PTXN_PARAMETER_BLOCK TxnInfo;
		TxnInfo = IoGetTransactionParameterBlock(ParentFileObject);
		DriverContext.TxnParameters = TxnInfo;
	}

	Status = FltCreateFileEx2(Filter,
		Instance,
		FileHandle,
		FileObject,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength,
		Flags,
		&DriverContext);
	return Status;
}


NTSTATUS
NcGetFileNameInformation(
_In_opt_ PFLT_CALLBACK_DATA Data,
_In_opt_ PFILE_OBJECT FileObject,
_In_opt_ PFLT_INSTANCE Instance,
_In_ FLT_FILE_NAME_OPTIONS NameOptions,
_Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation
)
{
	NTSTATUS Status;

	PAGED_CODE();

	FLT_ASSERT(Data || FileObject);

	*FileNameInformation = NULL;

	if (ARGUMENT_PRESENT(Data))
	{
		Status = FltGetFileNameInformation(Data, NameOptions, FileNameInformation);
	}
	else if (ARGUMENT_PRESENT(FileObject))
	{
		Status = FltGetFileNameInformationUnsafe(FileObject, Instance, NameOptions, FileNameInformation);
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}

NTSTATUS 
FltCreateDirectory(
IN PFLT_FILTER		pFilter,
IN PFLT_INSTANCE	pInstance,
IN PUNICODE_STRING	pDirectory
)
{
	OBJECT_ATTRIBUTES		objAttrib = { 0 };
	HANDLE					hFile = NULL;
	IO_STATUS_BLOCK 		io_status = { 0 };
	NTSTATUS				status = 0;

	if (NULL == pFilter || NULL == pInstance || NULL == pDirectory)
	{
		return STATUS_INVALID_PARAMETER;
	}

	InitializeObjectAttributes(&objAttrib,pDirectory,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);

	FltCreateFile(pFilter,
		pInstance,
		&hFile,
		GENERIC_READ | GENERIC_WRITE,
		&objAttrib,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		0);
	if (NT_SUCCESS(status))
	{
		FltClose(hFile);
	}
	return status;
}
NTSTATUS 
CreateSbDirectoryByOutNtPath(
IN PFLT_FILTER		pFilter,
IN PFLT_INSTANCE	pInstance,
IN PFLT_INSTANCE	pSbInstance,
IN PUNICODE_STRING	pOutPath,
IN PUNICODE_STRING	pSandboxPath
)
{
	UNICODE_STRING	usPrefix;
	UNICODE_STRING	usDirectory;
	UNICODE_STRING	usSbDirectory;
	BOOLEAN			bDirectory = FALSE;

	if (NULL == pFilter || NULL == pInstance || NULL == pOutPath || NULL == pSbInstance || NULL == pSandboxPath)
	{
		return STATUS_INVALID_PARAMETER;
	}
	RtlInitUnicodeString(&usPrefix, L"\\Device\\HarddiskVolume");
	if (!RtlPrefixUnicodeString(&usPrefix, pOutPath, TRUE))
	{
		return STATUS_INVALID_PARAMETER; 
	}
	if (FltCreateDirectory(pFilter, pSbInstance, pSandboxPath) != STATUS_SUCCESS)
	{
		return STATUS_UNSUCCESSFUL;
	}
	for (USHORT i = usPrefix.Length / sizeof(WCHAR); i < pOutPath->Length / sizeof(WCHAR) ; i++)
	{
		if (pOutPath->Buffer[i] == '\\')
		{
			bDirectory = FALSE;
			usDirectory.Buffer = pOutPath->Buffer;
			usDirectory.Length = usDirectory.MaximumLength = sizeof(WCHAR)*i;
			if (i == 23 || i == 24 || (FltIsFileExist(pFilter, pInstance, &usDirectory, &bDirectory) && bDirectory))
			{
				if (SbConvertToSbName(pSandboxPath,&usDirectory,&usSbDirectory,NULL)==STATUS_SUCCESS)
				{
					if (!FltIsFileExist(pFilter, pSbInstance, &usSbDirectory, NULL))
					{
						FltCreateDirectory(pFilter, pSbInstance, &usSbDirectory);
					}
					FreeUnicodeString(&usSbDirectory);
				}
			}
			else
			{
				break;
			}
		}
	}
	return STATUS_SUCCESS;
}


NTSTATUS CopyFile(PFLT_FILTER Filter,IN PUNICODE_STRING pusFileName1, PFLT_INSTANCE	pInstance1, IN PUNICODE_STRING pusFileName2, PFLT_INSTANCE	pInstance2)
{
	NTSTATUS			status;
	OBJECT_ATTRIBUTES	file2OA;
	OBJECT_ATTRIBUTES	file1OA;
	HANDLE				hFile1 = NULL;
	HANDLE				hFile2 = NULL;
	IO_STATUS_BLOCK		ioSB;
	PFILE_OBJECT		pFileObject1 = NULL;
	PFILE_OBJECT		pFileObject2 = NULL;

	if (!Filter || !pusFileName1 || !pusFileName2 || !pInstance1 || !pInstance2)
	{
		return STATUS_INVALID_PARAMETER;
	}

	InitializeObjectAttributes(
		&file1OA,
		pusFileName1,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);
	InitializeObjectAttributes(
		&file2OA,
		pusFileName2,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);

	status = FltCreateFile(
		Filter,
		pInstance1,
		&hFile1,
		SYNCHRONIZE | FILE_READ_DATA,
		&file1OA,
		&ioSB,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		0
		);
	if (NT_SUCCESS(status))
	{
		status = ObReferenceObjectByHandle(
			hFile1,
			0,
			*IoFileObjectType,
			KernelMode,
			(PVOID *)&pFileObject1,
			NULL
			);
		if (NT_SUCCESS(status))
		{
			status = FltCreateFile(
				Filter,
				pInstance2,
				&hFile2,
				SYNCHRONIZE | DELETE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
				&file2OA,
				&ioSB,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_SUPERSEDE,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0,
				0
				);
			if (NT_SUCCESS(status))
			{
				status = ObReferenceObjectByHandle(
					hFile2,
					0,
					*IoFileObjectType,
					KernelMode,
					(PVOID *)&pFileObject2,
					NULL
					);
				if (NT_SUCCESS(status))
				{
					LARGE_INTEGER FileSize;
					FileSize.QuadPart = 0; 

					status = GetFileSize(pInstance1, pFileObject1, &FileSize);
					if (NT_SUCCESS(status) && FileSize.QuadPart)
					{
						ULONG BufSize = 64 * 1024;
						PVOID Buf = ExAllocatePoolWithTag(PagedPool, BufSize, 'fie');
						if (!Buf)
						{
							status = STATUS_INSUFFICIENT_RESOURCES;
						}
						else
						{
							ULONG cbRead = 0;
							do
							{
								cbRead = 0;
								status = FltReadFile(
									pInstance1,
									pFileObject1,
									NULL,
									BufSize,
									Buf,
									0,
									&cbRead,
									NULL,
									NULL
									);

								if (NT_SUCCESS(status) && 0 != cbRead)
								{
									ULONG cbWritten = 0;
									status = FltWriteFile(
										pInstance2,
										pFileObject2,
										NULL,
										cbRead,
										Buf,
										0,
										&cbWritten,
										NULL,
										NULL
										);
								}
							} while (NT_SUCCESS(status) && BufSize == cbRead);

							ExFreePool(Buf);
						}
					}
					ObDereferenceObject(pFileObject2);
				}

				FltClose(hFile2);
			}

			ObDereferenceObject(pFileObject1);
		}

		FltClose(hFile1);
	}
	return status;
}
