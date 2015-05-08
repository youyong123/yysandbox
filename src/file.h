#pragma once

NTSTATUS SbFileUnload (FLT_FILTER_UNLOAD_FLAGS Flags );
NTSTATUS SbFileInit(PDRIVER_OBJECT DriverObject);

typedef struct _GLOBAL_FILTER_DATA
{
    PFLT_FILTER FilterHandle;
} GLOBAL_FILTER_DATA, *PGLOBAL_FILTER_DATA;

extern GLOBAL_FILTER_DATA g_GlobalFilterData;

#ifdef ALLOC_PRAGMA
#pragma alloc_text( PAGE, SbFileUnload)
#pragma alloc_text( PAGE, SbFileInit)
#endif 