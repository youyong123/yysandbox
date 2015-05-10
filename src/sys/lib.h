#pragma once
#include <fltKernel.h>


typedef NTSTATUS(*QUERY_INFO_PROCESS) (HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef NTSTATUS
(*fn_NtQueryInformationThread)(
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __out_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef
NTSTATUS
(* PReplaceFileObjectName ) (
    __in PFILE_OBJECT FileObject,
    __in_bcount(FileNameLength) PWSTR NewFileName,
    __in USHORT FileNameLength
    );


VOID SleepImp (__int64 ReqInterval);

PWCHAR	get_proc_name_by_pid(IN  HANDLE   dwProcessId, PWCHAR pPath);

NTSTATUS init_lib();

NTSTATUS
AllocateUnicodeString (
    PUNICODE_STRING String
    );

VOID
FreeUnicodeString (
    PUNICODE_STRING String
    );

BOOLEAN
flt_is_file_exist(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pInstance,
	IN PUNICODE_STRING	pFileName
	);

FORCEINLINE BOOLEAN  is_file_exist(PUNICODE_STRING pPath);

NTSTATUS
redirect_file(
	IN	PFLT_CALLBACK_DATA 		Data,
	IN	PCFLT_RELATED_OBJECTS	FltObjects,
	IN	PWSTR NewFileName,
	IN  USHORT FileNameLength
	);