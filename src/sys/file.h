#pragma once

NTSTATUS					SbMinifilterUnload( FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS	SbPreCreateCallback(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS	SbPostCreateCallback( PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS	SbPreSetinfoCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS					SbInstanceSetup ( PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType,__in FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS					SbInitMinifilter(PDRIVER_OBJECT pDriverObj);
void						SbUninitMinifilter();
NTSTATUS					SbSetSandBoxPath(PVOID buf,ULONG len);

void UninitMailPost(void);
NTSTATUS InitMailPost();

NTSTATUS
NcNormalizeNameComponentCallback(
_In_     PFLT_INSTANCE            Instance,
_In_     PCUNICODE_STRING         ParentDirectory,
_In_     USHORT                   DeviceNameLength,
_In_     PCUNICODE_STRING         Component,
_Out_writes_bytes_(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
_In_     ULONG                    ExpandComponentNameLength,
_In_     FLT_NORMALIZE_NAME_FLAGS Flags,
_Inout_ PVOID           *NormalizationContext
);

NTSTATUS
NcGenerateFileNameCallback(
_In_ PFLT_INSTANCE Instance,
_In_ PFILE_OBJECT FileObject,
_In_opt_ PFLT_CALLBACK_DATA Data,
_In_ FLT_FILE_NAME_OPTIONS NameOptions,
_Out_ PBOOLEAN CacheFileNameInformation,
_Inout_ PFLT_NAME_CONTROL OutputNameControl
);


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
