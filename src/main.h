#pragma once

#include <fltKernel.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <wdmsec.h> 


#define FILEIO_TYPE 40001

#define IOCTL_NONPNP_METHOD_IN_DIRECT		CTL_CODE( FILEIO_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS  )
#define IOCTL_NONPNP_METHOD_OUT_DIRECT		CTL_CODE( FILEIO_TYPE, 0x901, METHOD_OUT_DIRECT , FILE_ANY_ACCESS  )
#define IOCTL_NONPNP_METHOD_BUFFERED		CTL_CODE( FILEIO_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_NONPNP_METHOD_NEITHER			CTL_CODE( FILEIO_TYPE, 0x903, METHOD_NEITHER , FILE_ANY_ACCESS  )



#define NTDEVICE_NAME_STRING				L"\\Device\\NONPNP"
#define SYMBOLIC_NAME_STRING				L"\\DosDevices\\NONPNP"
#define POOL_TAG							'ELIF'

typedef struct _CONTROL_DEVICE_EXTENSION 
{
    HANDLE   FileHandle; 
} CONTROL_DEVICE_EXTENSION, *PCONTROL_DEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CONTROL_DEVICE_EXTENSION,ControlGetData)


typedef struct _REQUEST_CONTEXT 
{

    WDFMEMORY InputMemoryBuffer;
    WDFMEMORY OutputMemoryBuffer;

} REQUEST_CONTEXT, *PREQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(REQUEST_CONTEXT, GetRequestContext)



DRIVER_INITIALIZE						DriverEntry;
EVT_WDF_DRIVER_UNLOAD					NonPnpEvtDriverUnload;
EVT_WDF_DEVICE_CONTEXT_CLEANUP			NonPnpEvtDriverContextCleanup;
EVT_WDF_DEVICE_SHUTDOWN_NOTIFICATION	NonPnpShutdown;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL		FileEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_READ				FileEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE				FileEvtIoWrite;
EVT_WDF_IO_IN_CALLER_CONTEXT			NonPnpEvtDeviceIoInCallerContext;
EVT_WDF_DEVICE_FILE_CREATE				NonPnpEvtDeviceFileCreate;
EVT_WDF_FILE_CLOSE						NonPnpEvtFileClose;

VOID
PrintChars(
    __in_ecount(CountChars) PCHAR BufferAddress,
    __in size_t CountChars
    );

NTSTATUS
NonPnpDeviceAdd(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    );

#pragma warning(disable:4127)

