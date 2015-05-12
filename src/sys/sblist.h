#pragma once
#include <ntddk.h>

typedef struct _PROCESS_NODE
{
	LIST_ENTRY	ListEntry;
	HANDLE		Pid;
}PROCESS_NODE,*PPROCESS_NODE; 

typedef struct _PROCESS_LIST
{
	LIST_ENTRY	ListHead;
	ERESOURCE	Lock;
}PROCESS_LIST,*PPROCESS_LIST; 

NTSTATUS	SbInsertPidToList( __in HANDLE pid);
NTSTATUS	SbDelPidFromList(__in HANDLE pid);
BOOLEAN		SbIsPidInList(__in HANDLE pid);
void		SbUnInitProcessList();
void		SbInitProcessList();

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SbInsertPidToList)
#pragma alloc_text(PAGE, SbDelPidFromList)
#pragma alloc_text(PAGE, SbIsPidInList)
#pragma alloc_text(PAGE, SbUnInitProcessList)
#pragma alloc_text(PAGE, SbInitProcessList)
#endif