#pragma once
#include <fltKernel.h>


typedef NTSTATUS(*fn_ZwQueryInformationProcess) (HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*fn_NtQueryInformationThread)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass,PVOID ThreadInformation,ULONG ThreadInformationLength,PULONG ReturnLength );
typedef NTSTATUS (* fn_IoReplaceFileObjectName ) (PFILE_OBJECT FileObject,PWSTR NewFileName, USHORT FileNameLength);


VOID		SleepImp (__int64 ReqInterval);
PWCHAR		GetProcNameByPid(IN  HANDLE   dwProcessId, PWCHAR pPath);
NTSTATUS	InitLib();
NTSTATUS	AllocateUnicodeString (PUNICODE_STRING String );
VOID		FreeUnicodeString (PUNICODE_STRING String);
BOOLEAN		FltIsFileExist( PFLT_FILTER	pFilter,PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName);
BOOLEAN		FltIsDelFlagExist( PFLT_FILTER	pFilter,PFLT_INSTANCE	pInstance, PUNICODE_STRING	pFileName);
NTSTATUS	RedirectFile(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS	FltObjects,PWSTR NewFileName, USHORT FileNameLength);
FORCEINLINE BOOLEAN  IsFileExist(PUNICODE_STRING pPath);
PVOID		MyAllocateMemory( IN POOL_TYPE PoolType,IN SIZE_T	NumberOfBytes);

NTSTATUS
FltQueryInformationFileSyncronous (
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

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SleepImp)
#pragma alloc_text(PAGE, GetProcNameByPid)
#pragma alloc_text(PAGE, InitLib)
#pragma alloc_text(PAGE, AllocateUnicodeString)
#pragma alloc_text(PAGE, FreeUnicodeString)
#pragma alloc_text(PAGE, FltIsFileExist)
#pragma alloc_text(PAGE, RedirectFile)
#pragma alloc_text(PAGE, IsFileExist)
#endif
