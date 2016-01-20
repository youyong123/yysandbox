#ifndef __PF_UNDOC_API_H__
#define __PF_UNDOC_API_H__


#ifdef __cplusplus
extern "C" {
#endif

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts,
	SystemConfigurationInformation,
	SystemProcessorTimes,
	SystemGlobalFlag,
	SystemNotImplemented2,
	SystemModuleInformation,
	SystemLockInformation,
	SystemNotImplemented3,
	SystemNotImplemented4,
	SystemNotImplemented5,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPagefileInformation,
	SystemInstructionEmulationCounts,
	SystemInvalidInfoClass1,
	SystemCacheInformation,
	SystemPoolTagInformation,
	SystemProcessorStatistics,
	SystemDpcInformation,
	SystemNotImplemented6,
	SystemLoadImage,
	SystemUnloadImage,
	SystemTimeAdjustment,
	SystemNotImplemented7,
	SystemNotImplemented8,
	SystemNotImplemented9,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,
	SystemPrioritySeparation,
	SystemNotImplemented10,
	SystemNotImplemented11,
	SystemInvalidInfoClass2,
	SystemInvalidInfoClass3,
	SystemTimeZoneInformation,
	SystemLookasideInformation,
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession,
	SystemInvalidInfoClass4,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
#ifdef _AMD64_
	ULONG Reserved2[2];
#endif
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG         WaitTime;
	PVOID         StartAddress;
	CLIENT_ID     ClientId;
	KPRIORITY     Priority;
	KPRIORITY     BasePriority;
	ULONG         ContextSwitchCount;
	LONG          State;
	LONG          WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG             NextEntryOffset;
	ULONG             NumberOfThreads;
	ULONG             Reserved1[6];
	LARGE_INTEGER     CreateTime;
	LARGE_INTEGER     UserTime;
	LARGE_INTEGER     KernelTime;
	UNICODE_STRING    ProcessName;
	KPRIORITY         BasePriority;
	HANDLE            UniqueProcessId;
	HANDLE            InheritedFromProcessId;
	ULONG             HandleCount;
	ULONG             Reserved2[2];
	VM_COUNTERS       VmCounters;
#if _WIN32_WINNT >= 0x500
	IO_COUNTERS       IoCounters;
#endif
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out PVOID               SystemInformation,
	__in ULONG                SystemInformationLength,
	__out PULONG              ReturnLength OPTIONAL );

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
	__in HANDLE               ThreadHandle,
	__in THREADINFOCLASS      ThreadInformationClass,
	__out PVOID               ThreadInformation,
	__in ULONG                ThreadInformationLength,
	__out PULONG              ReturnLength OPTIONAL );


NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	__in       HANDLE ProcessHandle,
	__in       PROCESSINFOCLASS ProcessInformationClass,
	__out      PVOID ProcessInformation,
	__in       ULONG ProcessInformationLength,
	__out_opt  PULONG ReturnLength
	);

UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

#ifdef __cplusplus
}
#endif

#endif //  __PF_UNDOC_API_H__




