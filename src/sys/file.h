#pragma once

NTSTATUS					SbMinifilterUnload( FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS	SbPreCreateCallback(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS	SbPostCreateCallback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS	SbPreSetinfoCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS					SbInstanceSetup ( PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType,__in FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS					SbInitMinifilter(PDRIVER_OBJECT pDriverObj);
NTSTATUS					SbUninitMinifilter(PDRIVER_OBJECT pDriverObj);
NTSTATUS					SbSetSandBoxPath(PVOID buf,ULONG len);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SbPreCreateCallback)
#pragma alloc_text(PAGE, SbPostCreateCallback)
#pragma alloc_text(PAGE, SbPreSetinfoCallback)
#pragma alloc_text(PAGE, SbMinifilterUnload)
#pragma alloc_text(PAGE, SbInitMinifilter)
#pragma alloc_text(PAGE, SbUninitMinifilter)
#pragma alloc_text(PAGE, SbInstanceSetup)
#pragma alloc_text(PAGE, SbSetSandBoxPath)
#endif
