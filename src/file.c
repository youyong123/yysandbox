#include "main.h"
#include "file.h"

GLOBAL_FILTER_DATA g_GlobalFilterData;

CONST FLT_REGISTRATION g_FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                               //  Context
    NULL,                               //  Operation callbacks
    (PFLT_FILTER_UNLOAD_CALLBACK)SbFileUnload,                         
    NULL,                               //  InstanceSetup
	NULL,								//  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


NTSTATUS
SbFileUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )

{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    FltUnregisterFilter( g_GlobalFilterData.FilterHandle );

    return STATUS_SUCCESS;
}

NTSTATUS SbFileInit(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PAGED_CODE();

    status = FltRegisterFilter( DriverObject,  &g_FilterRegistration,&g_GlobalFilterData.FilterHandle );
    if (NT_SUCCESS( status )) 
	{
		
		status = FltStartFiltering(g_GlobalFilterData.FilterHandle);
		if (NT_SUCCESS( status ))
		{
			return status;
		}
        FltUnregisterFilter( g_GlobalFilterData.FilterHandle  );
    }
	
	return status;
}