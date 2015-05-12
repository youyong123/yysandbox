#include "sblist.h"
#include "macro.h"
PROCESS_LIST g_SbProcessList;

void SbInitProcessList()
{
	PAGED_CODE();

	InitializeListHead(&g_SbProcessList.ListHead);
	ExInitializeResourceLite( &g_SbProcessList.Lock );
}

BOOLEAN  AcquireResourceExclusive ( __inout PERESOURCE Resource )
{
	BOOLEAN ret;
	PAGED_CODE();

	KeEnterCriticalRegion();
	ret = ExAcquireResourceExclusiveLite( Resource, TRUE );
	KeLeaveCriticalRegion();
	return ret;
}

BOOLEAN  AcquireResourceShare ( __inout PERESOURCE Resource )
{
	BOOLEAN ret;
	PAGED_CODE();

	KeEnterCriticalRegion();
	ret = ExAcquireResourceSharedLite( Resource, TRUE );
	KeLeaveCriticalRegion();
	return ret;
}


VOID ReleaseResource( __inout PERESOURCE Resource )
{
	PAGED_CODE();

	KeEnterCriticalRegion();
	ExReleaseResourceLite( Resource );
	KeLeaveCriticalRegion();
}


void SbUnInitProcessList()
{
	PLIST_ENTRY		Flink;
	PPROCESS_NODE	pdev_list_entry;
	
	PAGED_CODE();

	RUN_ONCE

	AcquireResourceExclusive( &g_SbProcessList.Lock );
	
	if ( IsListEmpty( &g_SbProcessList.ListHead ) )
	{
		ReleaseResource( &g_SbProcessList.Lock );
		ExDeleteResourceLite(&g_SbProcessList.Lock);
		return;
	}

	Flink=g_SbProcessList.ListHead.Flink;
	while ( Flink!=&g_SbProcessList.ListHead )
	{
		pdev_list_entry=CONTAINING_RECORD( Flink, PROCESS_NODE, ListEntry );

		Flink=Flink->Flink;
		RemoveEntryList( Flink->Blink );

		if ( pdev_list_entry )
		{
			ExFreePool( pdev_list_entry );
		}
	}
	ReleaseResource( &g_SbProcessList.Lock );
	ExDeleteResourceLite(&g_SbProcessList.Lock);
}

NTSTATUS SbDelPidFromListEx(__in PLIST_ENTRY pDevRulHead, __in HANDLE pid)
{
	PLIST_ENTRY		Flink = NULL;
	PPROCESS_NODE	pdev_rul_entry = NULL;
	PAGED_CODE();

	if (!pDevRulHead) 
	{
		return STATUS_INVALID_PARAMETER;
	}

	if ( IsListEmpty( pDevRulHead ) )
	{
		return	STATUS_SUCCESS;
	}

	Flink=pDevRulHead->Flink;
	while ( Flink != pDevRulHead )
	{
		pdev_rul_entry=CONTAINING_RECORD( Flink, PROCESS_NODE, ListEntry );
		if (pdev_rul_entry->Pid == pid)
		{
			Flink = Flink->Flink;
			RemoveEntryList(Flink->Blink);

			if ( pdev_rul_entry )
			{
				ExFreePool (pdev_rul_entry);
			}	
		}
		else
		{
			Flink=Flink->Flink;
		}	
	}
	return STATUS_SUCCESS;
}


BOOLEAN SbIsPidInList(__in HANDLE pid)
{
	PLIST_ENTRY		Flink = NULL;
	PPROCESS_NODE	pdev_rul_entry = NULL;

	PAGED_CODE();

	AcquireResourceShare ( &g_SbProcessList.Lock );

	if ( IsListEmpty( &g_SbProcessList.ListHead ) )
	{
		ReleaseResource( &g_SbProcessList.Lock );
		return	FALSE;
	}

	Flink=g_SbProcessList.ListHead.Flink;
	while ( Flink != &g_SbProcessList.ListHead )
	{
		pdev_rul_entry=CONTAINING_RECORD( Flink, PROCESS_NODE, ListEntry );
		if (pdev_rul_entry->Pid == pid)
		{
			ReleaseResource( &g_SbProcessList.Lock );
			return TRUE;
		}
		else
		{
			Flink=Flink->Flink;
		}	
	}
	ReleaseResource( &g_SbProcessList.Lock );
	return	FALSE;
}


NTSTATUS SbDelPidFromList(__in HANDLE pid)
{
	NTSTATUS status;
	PAGED_CODE();
	AcquireResourceExclusive(&g_SbProcessList.Lock );
	status = SbDelPidFromListEx( &g_SbProcessList.ListHead, pid );
	ReleaseResource( &g_SbProcessList.Lock );
	return status;
}


NTSTATUS SbInsertPidToList( __in HANDLE pid)
{
	NTSTATUS status = STATUS_SUCCESS;
	PPROCESS_NODE	pdev_rul_entry = NULL;
	PAGED_CODE();
	AcquireResourceExclusive( &g_SbProcessList.Lock );
	
	pdev_rul_entry = ExAllocatePoolWithTag( PagedPool, sizeof (PROCESS_NODE), 'proc' );

	if (pdev_rul_entry)
	{
		RtlZeroMemory(pdev_rul_entry, sizeof (PROCESS_NODE));
		pdev_rul_entry->Pid = pid;
		InsertHeadList( &g_SbProcessList.ListHead, &(pdev_rul_entry->ListEntry) );
	}
	else
	{
		status = STATUS_UNSUCCESSFUL;
	}
	ReleaseResource( &g_SbProcessList.Lock );
	return status;
}