#include<ntddk.h>

typedef char *PBYTE;

extern POBJECT_TYPE *IoDriverObjectType;

typedef struct _C2P_DEV_EXT{
    PDEVICE_OBJECT Target;
    PDEVICE_OBJECT Lower;
}C2P_DEV_EXT,*PC2P_DEV_EXT;

int keycount = 0;

UNICODE_STRING com_name = RTL_CONSTANT_STRING("L\\Device\\Serial");
#define KBD_DRIVER_NAME L"\\Driver\\Kbdclass"

NTSTATUS ObReferenceObjectByName( PUNICODE_STRING a,ULONG b,PACCESS_STATE c,ACCESS_MASK d,POBJECT_TYPE e,KPROCESSOR_MODE f,PVOID g,PVOID h);

PDEVICE_OBJECT pnext;


VOID DriverUnload( PDRIVER_OBJECT pDrvObj ){

    DbgPrint("<in Driver Unload>\n");

    return;

}

NTSTATUS MyAttach( PDRIVER_OBJECT pDrvObj,PDEVICE_OBJECT pphy,PDEVICE_OBJECT *ppflt,PDEVICE_OBJECT *ppnext ){
    NTSTATUS status;

    status = IoCreateDevice(pDrvObj,0,NULL,pphy->DeviceType,0,FALSE,ppflt);
    if( status != STATUS_SUCCESS ){
        DbgPrint("<Create Device Error>\n");
        return status;
    }

    if( pphy->Flags & DO_BUFFERED_IO ){
        (*ppflt)->Flags |= DO_BUFFERED_IO;
    }
    if( pphy->Flags & DO_DIRECT_IO ){
        (*ppflt)->Flags |= DO_DIRECT_IO;
    }
    if( pphy->Characteristics & FILE_DEVICE_SECURE_OPEN ){
        (*ppflt)->Flags |= FILE_DEVICE_SECURE_OPEN;
    }
    (*ppflt)->Flags |= DO_POWER_PAGABLE;

    status = IoAttachDeviceToDeviceStackSafe( *ppflt,pphy,ppnext );

    if( status != STATUS_SUCCESS ){
        IoDeleteDevice(*ppflt);
        *ppflt = NULL;
        DbgPrint("<Attach Error>\n");
        return status;
    }

    return status;
}

NTSTATUS MyAttachAll( PDRIVER_OBJECT pDrvObj ){
    NTSTATUS status;
    UNICODE_STRING uniNtNameString;
    PC2P_DEV_EXT devExt;

    PDEVICE_OBJECT pFilterDevObj = NULL;
    PDEVICE_OBJECT pTargetDevObj = NULL;
    PDEVICE_OBJECT pLowerDevObj = NULL;

    PDRIVER_OBJECT KbdDrvObj = NULL;

    RtlInitUnicodeString( &uniNtNameString,KBD_DRIVER_NAME );

    status = ObReferenceObjectByName( &uniNtNameString,OBJ_CASE_INSENSITIVE,NULL,0,*IoDriverObjectType,KernelMode,NULL,&KbdDrvObj );
    if( !NT_SUCCESS(status) ){
        DbgPrint("<Get DrvObj Error>\n");
        return status;
    }

    pTargetDevObj = KbdDrvObj->DeviceObject;
    ObDereferenceObject( KbdDrvObj );

    while( pTargetDevObj ){
        status = IoCreateDevice( pDrvObj,sizeof(C2P_DEV_EXT),NULL,pTargetDevObj->DeviceType,pTargetDevObj->Characteristics,FALSE,&pFilterDevObj );
        if( !NT_SUCCESS(status) ){
            DbgPrint("<A Create Dev Error>\n");
            return status;
        }


        status = IoAttachDeviceToDeviceStackSafe( pFilterDevObj,pTargetDevObj,&pLowerDevObj );
        if( !NT_SUCCESS(status) ){
            DbgPrint("<A Attach Error>\n");
            return status;
        }

        pFilterDevObj->StackSize = pLowerDevObj->StackSize + 1;
        pFilterDevObj->Flags = pLowerDevObj->Flags;

        devExt = (PC2P_DEV_EXT)( pFilterDevObj->DeviceExtension );
        devExt->Target = pTargetDevObj;
        devExt->Lower = pLowerDevObj;

        pTargetDevObj = pTargetDevObj->NextDevice;
    }


    return status;
}

NTSTATUS Dispatch( PDEVICE_OBJECT device,PIRP irp ){

    NTSTATUS status;
    PBYTE buffer;
    ULONG length;
    int i,j;
    PIO_STACK_LOCATION irpsp;

    irpsp = IoGetCurrentIrpStackLocation(irp);

    if( irpsp->MajorFunction == IRP_MJ_POWER ){
        PoStartNextPowerIrp(irp);
        IoSkipCurrentIrpStackLocation(irp);
        return PoCallDriver( pnext,irp );
    }

    if( irp->MdlAddress != NULL )
        buffer = (PBYTE)MmGetSystemAddressForMdlSafe( irp->MdlAddress,NormalPagePriority );
    else
        buffer = (PBYTE)irp->UserBuffer;
    if( !buffer )
        buffer = (PBYTE)irp->AssociatedIrp.SystemBuffer;

    if( irpsp->MajorFunction == IRP_MJ_WRITE ){

        length = irpsp->Parameters.Write.Length;
        for( i = 0; i < length; i++ ){
            DbgPrint( "%x",buffer[i] );
        }

    }else if( irpsp->MajorFunction == IRP_MJ_READ ){

    }

    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver( pnext,irp );
}

NTSTATUS DispatchGeneral( PDEVICE_OBJECT device,PIRP irp ){
    NTSTATUS status;
    PIO_STACK_LOCATION irpsp;

    irpsp = IoGetCurrentIrpStackLocation(irp);

    if( irpsp->MajorFunction == IRP_MJ_POWER ){
        PoStartNextPowerIrp(irp);
        IoSkipCurrentIrpStackLocation(irp);
        return PoCallDriver( ((PC2P_DEV_EXT)(device->DeviceExtension))->Lower,irp );
    }

    return IoCallDriver( ((PC2P_DEV_EXT)(device->DeviceExtension))->Lower,irp );

}

NTSTATUS ReadComplete( PDEVICE_OBJECT DevObj,PIRP irp,PVOID Context ){

    PIO_STACK_LOCATION Irpsp;

    ULONG buf_len = 0;
    PCHAR buf = NULL;
    int i;

    DbgPrint("in complete\n");
    Irpsp = IoGetCurrentIrpStackLocation( irp );

    if( NT_SUCCESS( irp->IoStatus.Status ) ){
        buf = irp->AssociatedIrp.SystemBuffer;
        buf_len = irp->IoStatus.Information;
        for( i = 0; i < buf_len; i++ ){
            DbgPrint("%x\n",buf[i]);
        }
    }
    keycount--;
    if( irp->PendingReturned )
        IoMarkIrpPending( irp );

    return irp->IoStatus.Status;
}


NTSTATUS DispatchRead( PDEVICE_OBJECT device,PIRP irp ){
    NTSTATUS status;
    PIO_STACK_LOCATION irpsp;

    keycount++;

    if( irp->CurrentLocation == 1 ){
        DbgPrint("Error\n");
        return -1;
    }

    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine( irp,ReadComplete,device,TRUE,TRUE,TRUE );

    return IoCallDriver( ((PC2P_DEV_EXT)(device->DeviceExtension))->Lower,irp );
}


NTSTATUS DriverEntry( PDRIVER_OBJECT pDrvObj,PUNICODE_STRING RegPath ){

    int i;
    NTSTATUS status;

    PDEVICE_OBJECT pdev;
    PFILE_OBJECT pfobj;

    PDEVICE_OBJECT pflt;

    DbgPrint("<in DriverEntry>\n");
    /*
    status = IoGetDeviceObjectPointer( &com_name,FILE_ALL_ACCESS,&pfobj,&pdev );

    if( status != STATUS_SUCCESS ){
        DbgPrint("<Get Phy Device Error>\n");
        return status; 
    }
    ObDereferenceObject( pfobj );

    status = MyAttach( pDrvObj,pdev,&pflt,&pnext );
    if( status != STATUS_SUCCESS )
        return status;
    */
    status = MyAttachAll( pDrvObj );

    if( status != STATUS_SUCCESS ){
        return status; 
    }

    for( i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++ )
        pDrvObj->MajorFunction[i] = DispatchGeneral;

    pDrvObj->MajorFunction[IRP_MJ_READ] = DispatchRead;

    pDrvObj->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

