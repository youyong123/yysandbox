#ifndef _TL_PRODUCER_COMSUMER_MACRO_INC_H_
#define _TL_PRODUCER_COMSUMER_MACRO_INC_H_

#define	MACRO_PRODUCER_COMSUMER_DECLARE(node_struct)\
\
static LIST_ENTRY	g_List_##node_struct;\
static KSPIN_LOCK	g_ListLock_##node_struct;\
static void*		g_ThreadObj_##node_struct;\
static KEVENT		g_WorkerEvent_##node_struct;\
static BOOLEAN		g_IsStop_##node_struct;\
static BOOLEAN		g_bEnter_##node_struct = 0;\
\
void Process_##node_struct(node_struct*);\
void Uninit_##node_struct(void)\
{\
	g_IsStop_##node_struct = TRUE;\
	if (!g_bEnter_##node_struct)\
	{\
		return;\
	}\
	if (IsListEmpty(&g_List_##node_struct))\
	{\
		KeSetEvent(&g_WorkerEvent_##node_struct,IO_NO_INCREMENT,FALSE);\
	}\
	if (g_ThreadObj_##node_struct)\
	{\
		KeWaitForSingleObject(g_ThreadObj_##node_struct,Executive,KernelMode,FALSE,NULL);\
		ObDereferenceObject(g_ThreadObj_##node_struct);\
		g_ThreadObj_##node_struct = NULL;\
	}\
}\
\
BOOLEAN Insert_##node_struct(node_struct* pMailEvent)\
{\
	KLOCK_QUEUE_HANDLE	connListLockHandle = { 0 };\
	BOOLEAN				signalWorkerThread = FALSE;\
	if (pMailEvent == NULL || g_IsStop_##node_struct)\
	{\
		return FALSE;\
	}\
	KeAcquireInStackQueuedSpinLock(&g_ListLock_##node_struct, &connListLockHandle);\
	signalWorkerThread = IsListEmpty(&g_List_##node_struct);\
	InsertTailList(&g_List_##node_struct, &pMailEvent->listentry);\
	KeReleaseInStackQueuedSpinLock(&connListLockHandle);\
	if (signalWorkerThread)\
	{\
		KeSetEvent(&g_WorkerEvent_##node_struct,0,FALSE);\
	}\
	return TRUE;\
}\
\
void WorkerThread_##node_struct(void* StartContext)\
{\
	LIST_ENTRY*			listEntry = NULL;\
	node_struct*		mail_info = NULL;\
	KLOCK_QUEUE_HANDLE	connListLockHandle = { 0 };\
	UNREFERENCED_PARAMETER(StartContext);\
	for (;;)\
	{\
		KeWaitForSingleObject(&g_WorkerEvent_##node_struct,Executive,KernelMode,FALSE,NULL);\
		if (g_IsStop_##node_struct)\
		{\
			break;\
		}\
		listEntry = NULL;\
		KeAcquireInStackQueuedSpinLock(&g_ListLock_##node_struct,&connListLockHandle);\
		if (!IsListEmpty(&g_List_##node_struct))\
		{\
			listEntry = RemoveHeadList(&g_List_##node_struct);\
			mail_info = CONTAINING_RECORD(listEntry,node_struct,listentry);\
		}\
		KeReleaseInStackQueuedSpinLock(&connListLockHandle);\
		if (mail_info)\
		{\
			Process_##node_struct(mail_info);\
			ExFreePool(mail_info);\
			mail_info = NULL;\
		}\
		KeAcquireInStackQueuedSpinLock(&g_ListLock_##node_struct,&connListLockHandle);\
		if (IsListEmpty(&g_List_##node_struct) && !g_IsStop_##node_struct)\
		{\
			KeClearEvent(&g_WorkerEvent_##node_struct);\
		}\
		KeReleaseInStackQueuedSpinLock(&connListLockHandle);\
	}\
	while (!IsListEmpty(&g_List_##node_struct))\
	{\
		KeAcquireInStackQueuedSpinLock(&g_ListLock_##node_struct,&connListLockHandle);\
		if (!IsListEmpty(&g_List_##node_struct))\
		{\
			listEntry = RemoveHeadList(&g_List_##node_struct);\
			mail_info = CONTAINING_RECORD(listEntry,node_struct,listentry);\
		}\
		KeReleaseInStackQueuedSpinLock(&connListLockHandle);\
		if (mail_info != NULL)\
		{\
			ExFreePool(mail_info);\
			mail_info = NULL;\
		}\
	}\
	PsTerminateSystemThread(STATUS_SUCCESS);\
}\
\
NTSTATUS Init_##node_struct()\
{\
	NTSTATUS	status = STATUS_SUCCESS;\
	HANDLE		threadHandle = NULL;\
	g_IsStop_##node_struct = FALSE;\
	g_bEnter_##node_struct = TRUE;\
	InitializeListHead(&g_List_##node_struct);\
	KeInitializeSpinLock(&g_ListLock_##node_struct);\
	KeInitializeEvent(&g_WorkerEvent_##node_struct, NotificationEvent, FALSE);\
	status = PsCreateSystemThread(\
		&threadHandle,\
		THREAD_ALL_ACCESS,\
		NULL,\
		NULL,\
		NULL,\
		WorkerThread_##node_struct,\
		NULL\
		);\
	if (!NT_SUCCESS(status))\
	{\
		return status;\
	}\
	status = ObReferenceObjectByHandle(\
		threadHandle,\
		0,\
		NULL,\
		KernelMode,\
		&g_ThreadObj_##node_struct,\
		NULL\
		);\
	ZwClose(threadHandle);\
	threadHandle = NULL;\
	if (!NT_SUCCESS(status))\
	{\
		goto clean_ret;\
	}\
	if (NT_SUCCESS(status))\
	{\
		return status;\
	}\
clean_ret:\
	if (g_ThreadObj_##node_struct)\
	{\
		KeWaitForSingleObject(\
			g_ThreadObj_##node_struct,\
			Executive,\
			KernelMode,\
			FALSE,\
			NULL\
			);\
		ObDereferenceObject(g_ThreadObj_##node_struct);\
		g_ThreadObj_##node_struct = NULL;\
	}\
	return status;\
}\

#endif