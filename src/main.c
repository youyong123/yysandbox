
#include "main.h"
#include "file.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, NonPnpDeviceAdd)
#pragma alloc_text( PAGE, NonPnpEvtDriverContextCleanup)
#pragma alloc_text( PAGE, NonPnpEvtDriverUnload)
#pragma alloc_text( PAGE, NonPnpEvtDeviceIoInCallerContext)
#pragma alloc_text( PAGE, NonPnpEvtDeviceFileCreate)
#pragma alloc_text( PAGE, NonPnpEvtFileClose)
#pragma alloc_text( PAGE, FileEvtIoRead)
#pragma alloc_text( PAGE, FileEvtIoWrite)
#pragma alloc_text( PAGE, FileEvtIoDeviceControl)
#endif 


NTSTATUS
DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
    NTSTATUS                       status;
    WDF_DRIVER_CONFIG              config;
    WDFDRIVER                      hDriver;
    PWDFDEVICE_INIT                pInit = NULL;
    WDF_OBJECT_ATTRIBUTES          attributes;

#ifdef	DBG
	DbgBreakPoint();
#endif

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK );
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = NonPnpEvtDriverUnload;

 
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = NonPnpEvtDriverContextCleanup;

    status = WdfDriverCreate(DriverObject,RegistryPath, &attributes,&config, &hDriver);

    if (!NT_SUCCESS(status)) 
	{
        KdPrint (("NonPnp: WdfDriverCreate failed with status 0x%x\n", status));
        return status;
    }

	status = SbFileInit(DriverObject);
	if (!NT_SUCCESS(status)) 
	{
        KdPrint (("NonPnp: SbFileInit failed with status 0x%x\n", status));
        return status;
    }

    pInit = WdfControlDeviceInitAllocate( hDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R );
    if (pInit == NULL) 
	{
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }
    return  NonPnpDeviceAdd(hDriver, pInit);
}

NTSTATUS
NonPnpDeviceAdd(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS						status;
    WDF_OBJECT_ATTRIBUTES           attributes;
    WDF_IO_QUEUE_CONFIG				ioQueueConfig;
    WDF_FILEOBJECT_CONFIG			fileConfig;
    WDFQUEUE                        queue;
    WDFDEVICE						controlDevice;

    DECLARE_CONST_UNICODE_STRING(ntDeviceName, NTDEVICE_NAME_STRING) ;
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, SYMBOLIC_NAME_STRING) ;

    UNREFERENCED_PARAMETER( Driver );
    PAGED_CODE();

    
    WdfDeviceInitSetExclusive(DeviceInit, TRUE);

    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) 
	{
        goto End;
    }

    WdfControlDeviceInitSetShutdownNotification(DeviceInit, NonPnpShutdown,WdfDeviceShutdown);

    WDF_FILEOBJECT_CONFIG_INIT( &fileConfig,NonPnpEvtDeviceFileCreate, NonPnpEvtFileClose, WDF_NO_EVENT_CALLBACK  );

    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig,  WDF_NO_OBJECT_ATTRIBUTES);

    WdfDeviceInitSetIoInCallerContextCallback(DeviceInit, NonPnpEvtDeviceIoInCallerContext);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,CONTROL_DEVICE_EXTENSION);

    status = WdfDeviceCreate(&DeviceInit, &attributes, &controlDevice);
    if (!NT_SUCCESS(status)) 
	{
        goto End;
    }

    status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicLinkName);
    if (!NT_SUCCESS(status)) 
	{
        goto End;
    }

 
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);
    ioQueueConfig.EvtIoRead = FileEvtIoRead;
    ioQueueConfig.EvtIoWrite = FileEvtIoWrite;
    ioQueueConfig.EvtIoDeviceControl = FileEvtIoDeviceControl;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
 
    status = WdfIoQueueCreate(controlDevice,&ioQueueConfig,&attributes,&queue);
    if (!NT_SUCCESS(status)) 
	{
        goto End;
    }

    WdfControlFinishInitializing(controlDevice);

End:
   
    if (DeviceInit != NULL) 
	{
        WdfDeviceInitFree(DeviceInit);
    }
    return status;
}

VOID
NonPnpEvtDriverContextCleanup(
    IN WDFDRIVER Driver
    )
{
    PAGED_CODE();
}



VOID
NonPnpEvtDeviceFileCreate (
    IN WDFDEVICE            Device,
    IN WDFREQUEST Request,
    IN WDFFILEOBJECT        FileObject
    )
{
    PUNICODE_STRING             fileName;
    UNICODE_STRING              absFileName, directory;
    OBJECT_ATTRIBUTES           fileAttributes;
    IO_STATUS_BLOCK             ioStatus;
    PCONTROL_DEVICE_EXTENSION   devExt;
    NTSTATUS                    status;
    USHORT                      length = 0;


    UNREFERENCED_PARAMETER( FileObject );

    PAGED_CODE ();

    devExt = ControlGetData(Device);

    RtlInitUnicodeString(&directory, L"\\SystemRoot\\temp");

    fileName = WdfFileObjectGetFileName(FileObject);

    length = directory.Length + fileName->Length;

    absFileName.Buffer = ExAllocatePoolWithTag(PagedPool, length, POOL_TAG);
    if(absFileName.Buffer == NULL) 
	{
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto End;
    }
    absFileName.Length = 0;
    absFileName.MaximumLength =  length;

    status = RtlAppendUnicodeStringToString(&absFileName, &directory);
    if (!NT_SUCCESS(status)) 
	{
        goto End;
    }

    status = RtlAppendUnicodeStringToString(&absFileName, fileName);
    if (!NT_SUCCESS(status)) 
	{
        goto End;
    }

    InitializeObjectAttributes( &fileAttributes, &absFileName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,  NULL );

    status = ZwCreateFile (
                    &devExt->FileHandle,
                    SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
                    &fileAttributes,
                    &ioStatus,
                    NULL,// alloc size = none
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ,
                    FILE_OPEN_IF,
                    FILE_SYNCHRONOUS_IO_NONALERT |FILE_NON_DIRECTORY_FILE,
                    NULL,// eabuffer
                    0// ealength
                    );

    if (!NT_SUCCESS(status)) 
	{

        devExt->FileHandle = NULL;
    }

End:
    if(absFileName.Buffer != NULL) 
	{
        ExFreePool(absFileName.Buffer);
    }

    WdfRequestComplete(Request, status);
    return;
}


VOID
NonPnpEvtFileClose (
    IN WDFFILEOBJECT    FileObject
    )

{
    PCONTROL_DEVICE_EXTENSION devExt;

    PAGED_CODE ();

    devExt = ControlGetData(WdfFileObjectGetDevice(FileObject));

    if(devExt->FileHandle) 
	{
        ZwClose(devExt->FileHandle);
    }
    return;
}


VOID
FileEvtIoRead(
    IN WDFQUEUE         Queue,
    IN WDFREQUEST       Request,
    IN size_t            Length
    )
{
    NTSTATUS                   status = STATUS_SUCCESS;
    PVOID                       outBuf;
    IO_STATUS_BLOCK             ioStatus;
    PCONTROL_DEVICE_EXTENSION   devExt;
    FILE_POSITION_INFORMATION   position;
    ULONG_PTR                   bytesRead = 0;
    size_t  bufLength;



    PAGED_CODE ();


    status = WdfRequestRetrieveOutputBuffer(Request, 0, &outBuf, &bufLength);
    if(!NT_SUCCESS(status)) 
	{
        WdfRequestComplete(Request, status);
        return;
    }

    devExt = ControlGetData(WdfIoQueueGetDevice(Queue));

    if(devExt->FileHandle)
	{

        position.CurrentByteOffset.QuadPart = 0;
        status = ZwSetInformationFile(devExt->FileHandle,
                             &ioStatus,
                             &position,
                             sizeof(FILE_POSITION_INFORMATION),
                             FilePositionInformation);
        if (NT_SUCCESS(status)) 
		{

            status = ZwReadFile (devExt->FileHandle,
                                NULL,//   Event,
                                NULL,// PIO_APC_ROUTINE  ApcRoutine
                                NULL,// PVOID  ApcContext
                                &ioStatus,
                                outBuf,
                                (ULONG)Length,
                                0, // ByteOffset
                                NULL // Key
                                );

            if (!NT_SUCCESS(status)) 
			{

            }
            status = ioStatus.Status;
            bytesRead = ioStatus.Information;
        }
    }

    WdfRequestCompleteWithInformation(Request, status, bytesRead);

}



VOID
FileEvtIoWrite(
    IN WDFQUEUE         Queue,
    IN WDFREQUEST       Request,
    IN size_t            Length
    )
{
    NTSTATUS                   status = STATUS_SUCCESS;
    PVOID                       inBuf;
    IO_STATUS_BLOCK             ioStatus;
    PCONTROL_DEVICE_EXTENSION   devExt;
    FILE_POSITION_INFORMATION   position;
    ULONG_PTR                   bytesWritten = 0;
    size_t      bufLength;


    PAGED_CODE ();

  
    status = WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, &bufLength);
    if(!NT_SUCCESS(status)) 
	{
        WdfRequestComplete(Request, status);
        return;
    }

    devExt = ControlGetData(WdfIoQueueGetDevice(Queue));

    if(devExt->FileHandle) 
	{

        position.CurrentByteOffset.QuadPart = 0;
        status = ZwSetInformationFile(devExt->FileHandle,
                             &ioStatus,
                             &position,
                             sizeof(FILE_POSITION_INFORMATION),
                             FilePositionInformation);
        if (NT_SUCCESS(status))
        {

            status = ZwWriteFile(devExt->FileHandle,
                                NULL,//   Event,
                                NULL,// PIO_APC_ROUTINE  ApcRoutine
                                NULL,// PVOID  ApcContext
                                &ioStatus,
                                inBuf,
                                (ULONG)Length,
                                0, // ByteOffset
                                NULL // Key
                                );
            if (!NT_SUCCESS(status))
            {

            }

            status = ioStatus.Status;
            bytesWritten =  ioStatus.Information;
        }
    }

    WdfRequestCompleteWithInformation(Request, status, bytesWritten);

}

VOID
FileEvtIoDeviceControl(
    IN WDFQUEUE         Queue,
    IN WDFREQUEST       Request,
    IN size_t            OutputBufferLength,
    IN size_t            InputBufferLength,
    IN ULONG            IoControlCode
    )
{
    NTSTATUS            status = STATUS_SUCCESS;// Assume success
    PCHAR               inBuf = NULL, outBuf = NULL; // pointer to Input and output buffer
    PCHAR               data = "this String is from Device Driver !!!";
    ULONG               datalen = (ULONG) strlen(data)+1;//Length of data including null
    PCHAR               buffer = NULL;
    PREQUEST_CONTEXT    reqContext = NULL;
    size_t              bufSize;

    UNREFERENCED_PARAMETER( Queue );

    PAGED_CODE();

    if(!OutputBufferLength || !InputBufferLength)
    {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }


    switch (IoControlCode)
    {
    case IOCTL_NONPNP_METHOD_BUFFERED:

        status = WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, &bufSize);
        if(!NT_SUCCESS(status)) 
		{
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ASSERT(bufSize == InputBufferLength);
        PrintChars(inBuf, InputBufferLength  );


        status = WdfRequestRetrieveOutputBuffer(Request, 0, &outBuf, &bufSize);
        if(!NT_SUCCESS(status)) 
		{
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ASSERT(bufSize == OutputBufferLength);
        RtlCopyMemory(outBuf, data, OutputBufferLength);
        PrintChars(outBuf, datalen  );
        WdfRequestSetInformation(Request,OutputBufferLength < datalen? OutputBufferLength:datalen);

       break;


    case IOCTL_NONPNP_METHOD_IN_DIRECT:
        status = WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, &bufSize);
        if(!NT_SUCCESS(status)) 
		{
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ASSERT(bufSize == InputBufferLength);


        PrintChars(inBuf, InputBufferLength);

        status = WdfRequestRetrieveOutputBuffer(Request, 0, &buffer, &bufSize);
        if(!NT_SUCCESS(status)) 
		{
            break;
        }

        ASSERT(bufSize == OutputBufferLength);

        PrintChars(buffer, OutputBufferLength);

        WdfRequestSetInformation(Request, OutputBufferLength);

      break;

    case IOCTL_NONPNP_METHOD_OUT_DIRECT:
        status = WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, &bufSize);
        if(!NT_SUCCESS(status)) 
		{
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ASSERT(bufSize == InputBufferLength);


        PrintChars(inBuf, InputBufferLength);
        status = WdfRequestRetrieveOutputBuffer(Request, 0, &buffer, &bufSize);
        if(!NT_SUCCESS(status)) 
		{
            break;
        }

        ASSERT(bufSize == OutputBufferLength);

        RtlCopyMemory(buffer, data, OutputBufferLength);

        PrintChars(buffer, datalen);

        WdfRequestSetInformation(Request,OutputBufferLength < datalen? OutputBufferLength: datalen);

        break;

    case IOCTL_NONPNP_METHOD_NEITHER:
        {
            size_t inBufLength, outBufLength;

            reqContext = GetRequestContext(Request);

            inBuf = WdfMemoryGetBuffer(reqContext->InputMemoryBuffer, &inBufLength);
            outBuf = WdfMemoryGetBuffer(reqContext->OutputMemoryBuffer, &outBufLength);

            if(inBuf == NULL || outBuf == NULL) 
			{
                status = STATUS_INVALID_PARAMETER;
            }

            ASSERT(inBufLength == InputBufferLength);
            ASSERT(outBufLength == OutputBufferLength);

            PrintChars(inBuf, inBufLength);

            RtlCopyMemory(outBuf, data, outBufLength);


            PrintChars(outBuf, datalen);

            WdfRequestSetInformation(Request,  outBufLength < datalen? outBufLength:datalen);

            break;
        }
    default:

        status = STATUS_INVALID_DEVICE_REQUEST;
       
        break;
    }


    WdfRequestComplete( Request, status);

}

VOID
NonPnpEvtDeviceIoInCallerContext(
    IN WDFDEVICE  Device,
    IN WDFREQUEST Request
    )
{
    NTSTATUS					status = STATUS_SUCCESS;
    PREQUEST_CONTEXT            reqContext = NULL;
    WDF_OBJECT_ATTRIBUTES       attributes;
    WDF_REQUEST_PARAMETERS		params;
    size_t						inBufLen, outBufLen;
    PVOID						inBuf, outBuf;

    PAGED_CODE();

    WDF_REQUEST_PARAMETERS_INIT(&params);

    WdfRequestGetParameters(Request,  &params );



    if(!(params.Type == WdfRequestTypeDeviceControl &&params.Parameters.DeviceIoControl.IoControlCode == IOCTL_NONPNP_METHOD_NEITHER))
	{

        status = WdfDeviceEnqueueRequest(Device, Request);
        if( !NT_SUCCESS(status) )
		{
            goto End;
        }
        return;
    }



    status = WdfRequestRetrieveUnsafeUserInputBuffer(Request, 0, &inBuf, &inBufLen);
    if(!NT_SUCCESS(status)) 
	{
        goto End;
    }

    status = WdfRequestRetrieveUnsafeUserOutputBuffer(Request, 0, &outBuf, &outBufLen);
    if(!NT_SUCCESS(status)) 
	{
       goto End;
    }


    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, REQUEST_CONTEXT);

    status = WdfObjectAllocateContext(Request, &attributes, &reqContext);
    if(!NT_SUCCESS(status)) 
	{
        goto End;
    }


    status = WdfRequestProbeAndLockUserBufferForRead(Request, inBuf,inBufLen,&reqContext->InputMemoryBuffer);

    if(!NT_SUCCESS(status)) 
	{
        goto End;
    }

    status = WdfRequestProbeAndLockUserBufferForWrite(Request, outBuf, outBufLen, &reqContext->OutputMemoryBuffer);
    if(!NT_SUCCESS(status)) 
	{
        goto End;
    }

    status = WdfDeviceEnqueueRequest(Device, Request);
    if(!NT_SUCCESS(status)) 
	{
        goto End;
    }
    return;

End:
    WdfRequestComplete(Request, status);
    return;
}

VOID
NonPnpShutdown(
    WDFDEVICE Device
    )
{
    UNREFERENCED_PARAMETER(Device);
    return;
}


VOID
NonPnpEvtDriverUnload(
    IN WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    return;
}

VOID
PrintChars(
    __in_ecount(CountChars) PCHAR BufferAddress,
    __in size_t CountChars
    )
{
    return;
}

