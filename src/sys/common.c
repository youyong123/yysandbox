#include "ntifs.h"
#include "common.h"
#include "macro.h"
#include <strsafe.h>

#define MODULE_TAG 'injc'

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

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	__in       HANDLE ProcessHandle,
	__in       PROCESSINFOCLASS ProcessInformationClass,
	__out      PVOID ProcessInformation,
	__in       ULONG ProcessInformationLength,
	__out_opt  PULONG ReturnLength
	);

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

BOOLEAN  IsFileExist(PUNICODE_STRING pPath)
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