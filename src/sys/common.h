#ifndef _TL_COMMON_UTILS_H_
#define _TL_COMMON_UTILS_H_

VOID		SleepImp(__int64 ReqInterval);
PWCHAR		GetProcNameByPid(IN  HANDLE   dwProcessId, PWCHAR pPath);
NTSTATUS	AllocateUnicodeString(PUNICODE_STRING String);
VOID		FreeUnicodeString(PUNICODE_STRING String);
BOOLEAN
FltIsFileExist(
IN PFLT_FILTER	pFilter,
IN PFLT_INSTANCE	pInstance,
IN PUNICODE_STRING	pFileName,
OUT	PBOOLEAN		bDirectory
);
BOOLEAN		FltIsDelFlagExist(PFLT_FILTER	pFilter, PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName);

PVOID		MyAllocateMemory(IN POOL_TYPE PoolType, IN SIZE_T	NumberOfBytes);

NTSTATUS
FltQueryInformationFileSyncronous(
IN PFLT_INSTANCE Instance,
IN PFILE_OBJECT FileObject,
OUT PVOID FileInformation,
IN ULONG Length,
IN FILE_INFORMATION_CLASS FileInformationClass,
OUT PULONG LengthReturned OPTIONAL
);

NTSTATUS
SbDoCopyFile(
IN PFLT_FILTER	pFilter,
IN PFILE_OBJECT	pSrcObject,
IN PFLT_INSTANCE	pSrcInstance,
IN PUNICODE_STRING	pSrcFileName,
IN PFLT_INSTANCE	pDstInstance,
IN PUNICODE_STRING	pDstFileName,
IN BOOLEAN 			bDirectory
);

NTSTATUS
SbCopyFile(
IN PFLT_FILTER	pFilter,
IN PFLT_INSTANCE	pSrcInstance,
IN PFILE_OBJECT		pSrcFileObj,
IN PUNICODE_STRING	pSrcFileName,
IN PFLT_INSTANCE	pDstInstance,
IN PUNICODE_STRING	pDstFileName,
IN BOOLEAN			bDirectory
);

PFLT_INSTANCE
SbGetVolumeInstance(
IN PFLT_FILTER		pFilter,
IN PUNICODE_STRING	pVolumeName
);

NTSTATUS
SbIsDirectory(
IN PFILE_OBJECT fileObject,
IN PUNICODE_STRING dirName,
IN PFLT_FILTER filter,
IN PFLT_INSTANCE instance,
OUT BOOLEAN* directory
);

BOOLEAN AcquireResourceExclusive(__inout PERESOURCE Resource);
BOOLEAN AcquireResourceShare(__inout PERESOURCE Resource);
VOID	ReleaseResource(__inout PERESOURCE Resource);

ULONGLONG BKDRHashW(PWCHAR wstr);

ULONGLONG APHashW(PWCHAR wstr);

ULONGLONG BKDRHashA(PCHAR wstr);

ULONGLONG APHashA(PCHAR wstr);

BOOLEAN GetHostFromPost(const char* http_block, ULONG	http_len, char* pOutBuf, ULONG OutBufLen, BOOLEAN* pbMail, BOOLEAN* pbSpecial);

NTSTATUS ToUpperStringW(WCHAR* Src, WCHAR* Dest, USHORT cbDestLen);

PWCHAR GetProcFullPathById(IN  HANDLE   dwProcessId, PWCHAR pPath, PULONG pPathLen);

PWCHAR GetProcNameById(IN  HANDLE   dwProcessId, PWCHAR pProcName, ULONG ProcNameLen);

typedef volatile LONG EX_SPIN_LOCK, *PEX_SPIN_LOCK;

KIRQL ExAcquireSpinLockExclusive( PEX_SPIN_LOCK SpinLock);

KIRQL ExAcquireSpinLockShared(PEX_SPIN_LOCK SpinLock);

VOID ExReleaseSpinLockShared( PEX_SPIN_LOCK SpinLock, KIRQL  OldIrql);

VOID ExReleaseSpinLockExclusive(PEX_SPIN_LOCK SpinLock, KIRQL  OldIrql);

BOOLEAN GetProcNameFromPath(WCHAR* pFullProcPath, ULONG Len, WCHAR* ProcName, ULONG cbProcNameLen);

NTSTATUS GetSysrootNtPath(PUNICODE_STRING sysrootNtPath);
NTSTATUS ResolveNtPathToDosPath(PUNICODE_STRING pNtPath, PUNICODE_STRING UmPath);
NTSTATUS ResolveDosPathToNtPath(PUNICODE_STRING pDosPath, PUNICODE_STRING UmPath);

BOOLEAN	 GetNtPathDir(const WCHAR* pNtPath, ULONG uNtPathLen, WCHAR* pNtPathDir, ULONG uNtPathDirLen);

PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2);

WCHAR* ReplaceString(WCHAR* pString, WCHAR* pOldString, WCHAR* pNewString, BOOLEAN IgnoreCase);

void PrintProcessById(HANDLE PID);

BOOLEAN  IsFileExist(PUNICODE_STRING pPath, OUT	PBOOLEAN bDirectory);

NTSTATUS
SbConvertToSbName(
IN PUNICODE_STRING			pSandboxPath,
IN PUNICODE_STRING			pSrcName,
OUT PUNICODE_STRING			pDstName,
IN WCHAR*			pVolName
);

BOOLEAN GetDriveLetter(PCFLT_RELATED_OBJECTS FltObjects, PWCHAR pBuffer, ULONG bufferLength);
NTSTATUS NtRenameFile(WCHAR *szFileName, WCHAR *szNewFileName, BOOLEAN ReplaceIfExists, HANDLE RootDirectory);

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
);

NTSTATUS
NcGetFileNameInformation(
_In_opt_ PFLT_CALLBACK_DATA Data,
_In_opt_ PFILE_OBJECT FileObject,
_In_opt_ PFLT_INSTANCE Instance,
_In_ FLT_FILE_NAME_OPTIONS NameOptions,
_Outptr_ PFLT_FILE_NAME_INFORMATION *FileNameInformation
);
#endif 
