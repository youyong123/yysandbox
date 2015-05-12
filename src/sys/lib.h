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
NTSTATUS	RedirectFile(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS	FltObjects,PWSTR NewFileName, USHORT FileNameLength);
FORCEINLINE BOOLEAN  IsFileExist(PUNICODE_STRING pPath);

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
