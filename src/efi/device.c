/* SPDX-License-Identifier: GPL-2.0-only
 * PCI restore whitelist and FLR ordering informed by pinned Ada UEFI port;
 * implemented independently with exact statuses and terminal ambiguity.
 * SEC2 propagation follows NVIDIA 610.43.03 ksec2ResetHw_TU102.
 */
#include "device.h"
static EFI_PCI_IO_PROTOCOL *pci(RTX_DEVICE *d){return d->Lease->Pci;}
EFI_STATUS EFIAPI RtxDeviceLatch(RTX_DEVICE *d,EFI_STATUS s){
    if(!d)return EFI_INVALID_PARAMETER;
    if(!d->Fault)d->Fault=EFI_ERROR(s)?s:EFI_DEVICE_ERROR;
    d->Verified=FALSE;return d->Fault;
}
static BOOLEAN bad(UINT32 x){return x==0xffffffffu || (x&0xffff0000u)==0xbadf0000u;}
static BOOLEAN live(RTX_DEVICE *d){return d && d->Bs && d->Lease && d->Lease->Phase==RtxLeaseHeld && d->Lease->Pci;}
static EFI_STATUS cfg(RTX_DEVICE *d,BOOLEAN write,UINT32 off,UINTN bytes,VOID *p){
    if(!live(d) || !p || d->ConfigUnavailable || d->Busy)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    if((bytes!=1 && bytes!=2 && bytes!=4) || off>256-bytes || (off&(bytes-1)))return RtxDeviceLatch(d,EFI_INVALID_PARAMETER);
    EFI_PCI_IO_PROTOCOL_WIDTH w=bytes==1?EfiPciIoWidthUint8:bytes==2?EfiPciIoWidthUint16:EfiPciIoWidthUint32;
    d->LastOffset=off;EFI_STATUS prior=d->Fault;d->Busy=TRUE;
    if(write)d->ConfigWrites++;
    EFI_STATUS s=write?pci(d)->Pci.Write(pci(d),w,off,1,p):pci(d)->Pci.Read(pci(d),w,off,1,p);
    d->Busy=FALSE;d->LastStatus=s;
    if(d->Fault!=prior)return d->Fault;
    return s==EFI_SUCCESS?EFI_SUCCESS:RtxDeviceLatch(d,s);
}
EFI_STATUS EFIAPI RtxDeviceConfigRead(RTX_DEVICE *d,UINT32 off,UINTN n,VOID *p){
    if(!live(d) || d->Fault)return d && d->Fault?d->Fault:EFI_NOT_READY;
    return cfg(d,FALSE,off,n,p);
}
static EFI_STATUS identity(RTX_DEVICE *d){
    UINT32 id=0,sub=0;EFI_STATUS s=cfg(d,FALSE,0,4,&id);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,0x2c,4,&sub);if(s!=EFI_SUCCESS)return s;
    return id==0x270410de && sub==0x15007377?EFI_SUCCESS:RtxDeviceLatch(d,EFI_SECURITY_VIOLATION);
}
static EFI_STATUS owner(RTX_DEVICE *d){
    EFI_STATUS s=RtxOwnerInspectAfterStop(d->System,&d->Lease->Before,d->Lease->Application,d->Workspace,&d->OwnerCheck);
    return s==EFI_SUCCESS?EFI_SUCCESS:RtxDeviceLatch(d,s);
}
EFI_STATUS EFIAPI RtxDeviceInit(RTX_DEVICE *d,EFI_SYSTEM_TABLE *st,RTX_LEASE *l,RTX_DMA_ARENA *a,RTX_OWNER_WORKSPACE *w){
    if(!d || !st || !st->BootServices || !l || !a || !w)return EFI_INVALID_PARAMETER;
    EFI_BOOT_SERVICES *bs=st->BootServices;
    if(d->Bs || d->Lease || d->Fault)return EFI_ALREADY_STARTED;
    if(l->Phase!=RtxLeaseHeld || !l->Pci || !l->HeldBoard.ColdObservationsAccepted ||
       !l->AfterClaim.InspectionComplete || !l->AfterClaim.LeaseObserved || !l->AfterClaim.IntelPathObserved ||
       a->Pci!=l->Pci || a->Phase!=RtxDmaCold || !bs->Stall || !l->Pci->Pci.Write ||
       !l->Pci->Pci.Read || !l->Pci->Mem.Read || !l->Pci->Mem.Write || !l->Pci->Attributes)return EFI_NOT_READY;
    d->System=st;d->Bs=bs;d->Lease=l;d->Arena=a;d->Workspace=w;
    for(UINTN i=0;i<64;i++)d->Saved[i]=l->HeldBoard.PciConfig[i];
    const UINT8 *b=(const UINT8 *)d->Saved;UINTN pos=b[0x34],iterations=0;
    while(pos){if(++iterations>48 || pos<0x40 || pos>0xfc || (pos&3))return RtxDeviceLatch(d,EFI_COMPROMISED_DATA);
        if(b[pos]==0x10)d->Pcie=(UINT16)pos;
        if(b[pos]==1)d->Pm=(UINT16)pos;
        pos=b[pos+1];}
    if(!d->Pcie || d->Pcie>0xd4 || !d->Pm)return RtxDeviceLatch(d,EFI_UNSUPPORTED);
    d->PcieVersion=b[d->Pcie+2]&15;
    d->SavedDevctl=(UINT16)(b[d->Pcie+8]|(UINT16)b[d->Pcie+9]<<8);
    d->SavedDevctl2=(UINT16)(b[d->Pcie+0x28]|(UINT16)b[d->Pcie+0x29]<<8);
    if((d->Saved[1]&6)!=2 || d->SavedDevctl&0x8000 || (d->Saved[12]&1))return RtxDeviceLatch(d,EFI_NOT_READY);
    return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxDeviceRead(RTX_DEVICE *d,UINT32 off,UINT32 *v){
    if(!live(d) || !v || d->Fault)return d && d->Fault?d->Fault:EFI_NOT_READY;
    if(d->Busy || d->ConfigUnavailable || (off&3) || off>d->Lease->HeldBoard.BarBytes-4)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    *v=0xffffffffu;d->LastOffset=off;d->Busy=TRUE;EFI_STATUS s=pci(d)->Mem.Read(pci(d),EfiPciIoWidthUint32,0,off,1,v);d->Busy=FALSE;
    d->LastStatus=s;d->LastValue=*v;if(s!=EFI_SUCCESS)return RtxDeviceLatch(d,s);
    if(d->Fault)return d->Fault;
    if(d->ConfigRestored && off==0x8403c0){
        if(bad(*v))return RtxDeviceLatch(d,EFI_DEVICE_ERROR);
        d->LastEngine=*v;
        if(d->ReleaseAttempted){if(d->ReleaseReads<10)d->ReleaseReads++;if(d->ReleaseReads>=10 && !(*v&1))d->ReleaseObserved=TRUE;}
        else if(d->AssertAttempted){if(d->AssertReads<10)d->AssertReads++;if(d->AssertReads>=10 && (*v&1))d->AssertObserved=TRUE;}
    }
    if(d->ReleaseObserved && off==0x8400f4 && !bad(*v) && !(*v&(1u<<12)))d->ScrubObserved=TRUE;
    return EFI_SUCCESS;
}
static BOOLEAN allowed(UINT32 off){
    static const UINT32 local[]={0x3c0,0x84,0x110,0x128,0x114,0x11c,0x118,0x624,0x10c,0x600,
        0x1210,0x119c,0x1198,0x1180,0x1668,0x104,0x40,0x44,0x130,0x100};
    if(off==0x82381c || off==0x823820)return TRUE;
    for(UINTN i=0;i<sizeof(local)/sizeof(local[0]);i++)if(off==0x110000+local[i] || off==0x840000+local[i])return TRUE;
    return FALSE;
}
EFI_STATUS EFIAPI RtxDeviceWrite(RTX_DEVICE *d,UINT32 off,UINT32 v){
    if(!live(d) || d->Fault)return d && d->Fault?d->Fault:EFI_NOT_READY;
    if(d->Busy || d->ConfigUnavailable || d->Arena->Phase!=RtxDmaDeviceMayAccess || !allowed(off))return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    if(d->FlrAttempted){
        if(!d->ConfigRestored || off!=0x8403c0)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
        if(!d->AssertAttempted){if(v!=(d->LastEngine|1u))return RtxDeviceLatch(d,EFI_ACCESS_DENIED);d->AssertAttempted=TRUE;}
        else {if(!d->AssertObserved || d->ReleaseAttempted || v!=(d->LastEngine&~1u))return RtxDeviceLatch(d,EFI_ACCESS_DENIED);d->ReleaseAttempted=TRUE;}
    }
    if(off==0x82381c){if(d->Selector0Attempted || v!=0x88888888u)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);d->Selector0Attempted=TRUE;}
    if(off==0x823820){if(!d->Selector0Attempted || d->Selector1Attempted || v!=8)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);d->Selector1Attempted=TRUE;}
    d->MmioWrites++;d->LastOffset=off;d->LastValue=v;d->Busy=TRUE;
    EFI_STATUS s=pci(d)->Mem.Write(pci(d),EfiPciIoWidthUint32,0,off,1,&v);d->Busy=FALSE;d->LastStatus=s;
    if(d->Fault)return d->Fault;
    return s==EFI_SUCCESS?EFI_SUCCESS:RtxDeviceLatch(d,s);
}
EFI_STATUS EFIAPI RtxDeviceProm(RTX_DEVICE *d,VOID *buffer,UINTN bytes){
    if(!live(d) || !buffer || bytes!=1024*1024 || d->Fault || d->MasterAttempted || d->Busy)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    d->Busy=TRUE;EFI_STATUS s=pci(d)->Mem.Read(pci(d),EfiPciIoWidthUint32,0,0x300000,bytes/4,buffer);d->Busy=FALSE;
    if(d->Fault)return d->Fault;
    return s==EFI_SUCCESS?EFI_SUCCESS:RtxDeviceLatch(d,s);
}
EFI_STATUS EFIAPI RtxDeviceStall(RTX_DEVICE *d,UINTN usec){
    if(!live(d) || !usec || usec>1000000 || d->Busy || usec>MAX_UINT64-d->Ticks)return RtxDeviceLatch(d,EFI_INVALID_PARAMETER);
    d->Busy=TRUE;EFI_STATUS s=d->Bs->Stall(usec);d->Busy=FALSE;d->Ticks+=usec;
    return s==EFI_SUCCESS?EFI_SUCCESS:RtxDeviceLatch(d,s);
}
static EFI_STATUS attributes(RTX_DEVICE *d,EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION op,UINT64 mask,UINT64 *out){
    if(d->Busy || d->ConfigUnavailable)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    EFI_STATUS prior=d->Fault;d->Busy=TRUE;EFI_STATUS s=pci(d)->Attributes(pci(d),op,mask,out);d->Busy=FALSE;
    if(d->Fault!=prior)return d->Fault;
    return s==EFI_SUCCESS?EFI_SUCCESS:RtxDeviceLatch(d,s);
}
EFI_STATUS EFIAPI RtxDeviceEnableMaster(RTX_DEVICE *d){
    if(!live(d) || d->Fault || d->MasterAttempted)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    UINT16 cmd=0,after=0;UINT64 support=0,attrs=0;
    EFI_STATUS s=owner(d);if(s!=EFI_SUCCESS)return s;
    s=identity(d);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;
    if(cmd!=(UINT16)d->Saved[1])return RtxDeviceLatch(d,EFI_NOT_READY);
    s=attributes(d,EfiPciIoAttributeOperationSupported,0,&support);if(s!=EFI_SUCCESS)return s;
    if(!(support&EFI_PCI_IO_ATTRIBUTE_BUS_MASTER))return RtxDeviceLatch(d,EFI_UNSUPPORTED);
    s=attributes(d,EfiPciIoAttributeOperationGet,0,&d->InitialAttributes);if(s!=EFI_SUCCESS)return s;
    UINT64 decode=(cmd&1?EFI_PCI_IO_ATTRIBUTE_IO:0)|(cmd&2?EFI_PCI_IO_ATTRIBUTE_MEMORY:0);
    if((d->InitialAttributes&(EFI_PCI_IO_ATTRIBUTE_BUS_MASTER|EFI_PCI_IO_ATTRIBUTE_IO|EFI_PCI_IO_ATTRIBUTE_MEMORY))!=decode)
        return RtxDeviceLatch(d,EFI_NOT_READY);
    s=RtxDmaExpose(d->Arena);if(s!=EFI_SUCCESS)return RtxDeviceLatch(d,s);
    d->MasterAttempted=TRUE;
    s=attributes(d,EfiPciIoAttributeOperationEnable,EFI_PCI_IO_ATTRIBUTE_BUS_MASTER,NULL);if(s!=EFI_SUCCESS)return s;
    s=attributes(d,EfiPciIoAttributeOperationGet,0,&attrs);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,4,2,&after);if(s!=EFI_SUCCESS)return s;
    return attrs==(d->InitialAttributes|EFI_PCI_IO_ATTRIBUTE_BUS_MASTER) && after==(UINT16)(cmd|4)?EFI_SUCCESS:RtxDeviceLatch(d,EFI_DEVICE_ERROR);
}
EFI_STATUS EFIAPI RtxDeviceClearMaster(RTX_DEVICE *d){
    if(!live(d) || d->ConfigUnavailable || d->Busy)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    if(d->MasterCleared)return d->Fault?d->Fault:EFI_SUCCESS;
    if(d->ClearAttempted || !d->MasterAttempted)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    d->ClearAttempted=TRUE;EFI_STATUS s=identity(d);if(s!=EFI_SUCCESS)return s;
    /* Only this containment path remains available after a latched fault.
     * One protocol disable; one hardware clear if it did not clear BME.
     * Never reinterpret an ambiguous protocol result as overall success. */
    EFI_STATUS as=attributes(d,EfiPciIoAttributeOperationDisable,EFI_PCI_IO_ATTRIBUTE_BUS_MASTER,NULL);
    UINT16 cmd=0,after=0;UINT64 attrs=0;
    s=cfg(d,FALSE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;
    if(cmd==0xffff)return RtxDeviceLatch(d,EFI_DEVICE_ERROR);
    if(cmd&4){cmd&=(UINT16)~4u;s=cfg(d,TRUE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;}
    s=cfg(d,FALSE,4,2,&after);if(s!=EFI_SUCCESS)return s;
    s=attributes(d,EfiPciIoAttributeOperationGet,0,&attrs);if(s!=EFI_SUCCESS)return s;
    if(as!=EFI_SUCCESS || after!=(UINT16)d->Saved[1] || attrs!=d->InitialAttributes)return RtxDeviceLatch(d,EFI_DEVICE_ERROR);
    d->MasterCleared=TRUE;return d->Fault?d->Fault:EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxDeviceFlr(RTX_DEVICE *d){
    if(!live(d) || d->Fault || !d->MasterCleared || d->FlrAttempted || !d->Selector0Attempted || !d->Selector1Attempted)
        return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    UINT16 cmd=0,pending=0,ctl=0;UINT32 cap=0,ss0=0,ss1=0;
    EFI_STATUS s=owner(d);if(s!=EFI_SUCCESS)return s;
    s=identity(d);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,d->Pcie+4,4,&cap);if(s!=EFI_SUCCESS)return s;
    if((cmd&6)!=2 || !(cap&(1u<<28)))return RtxDeviceLatch(d,EFI_NOT_READY);
    for(UINTN n=0;;n++){
        s=cfg(d,FALSE,d->Pcie+10,2,&pending);if(s!=EFI_SUCCESS)return s;
        if(pending==0xffff)return RtxDeviceLatch(d,EFI_DEVICE_ERROR);
        if(!(pending&32))break;
        if(n==1000)return RtxDeviceLatch(d,EFI_TIMEOUT);
        s=RtxDeviceStall(d,1000);if(s!=EFI_SUCCESS)return s;
    }
    s=RtxDeviceRead(d,0x82381c,&ss0);if(s!=EFI_SUCCESS)return s;
    s=RtxDeviceRead(d,0x823820,&ss1);if(s!=EFI_SUCCESS)return s;
    if(ss0!=0x88888888u || ss1!=8)return RtxDeviceLatch(d,EFI_NOT_READY);
    s=cfg(d,FALSE,d->Pcie+8,2,&ctl);if(s!=EFI_SUCCESS)return s;
    if(ctl&0x8000)return RtxDeviceLatch(d,EFI_NOT_READY);
    ctl|=0x8000;d->FlrAttempted=TRUE;
    EFI_STATUS write=cfg(d,TRUE,d->Pcie+8,2,&ctl);
    d->ConfigUnavailable=TRUE;s=RtxDeviceStall(d,100000);
    if(write!=EFI_SUCCESS || s!=EFI_SUCCESS)return RtxDeviceLatch(d,write!=EFI_SUCCESS?write:s);
    d->ConfigUnavailable=FALSE;
    for(UINTN n=0;n<=1000;n++){
        UINT32 id=0;s=cfg(d,FALSE,0,4,&id);if(s!=EFI_SUCCESS)return s;
        if(id==0x270410de){d->FlrComplete=TRUE;return EFI_SUCCESS;}
        if(id!=0 && id!=0xffffffffu)return RtxDeviceLatch(d,EFI_SECURITY_VIOLATION);
        if(n<1000){s=RtxDeviceStall(d,1000);if(s!=EFI_SUCCESS)return s;}
    }
    return RtxDeviceLatch(d,EFI_TIMEOUT);
}
EFI_STATUS EFIAPI RtxDeviceRestore(RTX_DEVICE *d){
    if(!live(d) || d->Fault || !d->FlrComplete || d->ConfigRestored)return RtxDeviceLatch(d,EFI_ACCESS_DENIED);
    UINT16 cmd=0,now=0;EFI_STATUS s=identity(d);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;
    if(cmd==0xffff || (cmd&4))return RtxDeviceLatch(d,EFI_NOT_READY);
    cmd&=(UINT16)~7u;s=cfg(d,TRUE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,4,2,&now);if(s!=EFI_SUCCESS)return s;
    if(now!=cmd)return RtxDeviceLatch(d,EFI_DEVICE_ERROR);
    for(INTN off=0x24;off>=0x10;off-=4){UINT32 v=d->Saved[off/4];s=cfg(d,TRUE,(UINT32)off,4,&v);if(s!=EFI_SUCCESS)return s;}
    UINT32 rom=d->Saved[12]&~1u;s=cfg(d,TRUE,0x30,4,&rom);if(s!=EFI_SUCCESS)return s;
    UINT16 pair=(UINT16)d->Saved[3];s=cfg(d,TRUE,0x0c,2,&pair);if(s!=EFI_SUCCESS)return s;
    UINT8 line=(UINT8)d->Saved[15];s=cfg(d,TRUE,0x3c,1,&line);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,TRUE,d->Pcie+8,2,&d->SavedDevctl);if(s!=EFI_SUCCESS)return s;
    if(d->PcieVersion>=2){s=cfg(d,TRUE,d->Pcie+0x28,2,&d->SavedDevctl2);if(s!=EFI_SUCCESS)return s;}
    cmd=(UINT16)d->Saved[1];s=cfg(d,TRUE,4,2,&cmd);if(s!=EFI_SUCCESS)return s;
    s=cfg(d,FALSE,4,2,&now);if(s!=EFI_SUCCESS)return s;
    if(now!=cmd)return RtxDeviceLatch(d,EFI_DEVICE_ERROR);
    for(UINT32 off=0x10;off<=0x24;off+=4){UINT32 v=0;s=cfg(d,FALSE,off,4,&v);if(s!=EFI_SUCCESS)return s;
        if(v!=d->Saved[off/4])return RtxDeviceLatch(d,EFI_DEVICE_ERROR);}
    d->ConfigRestored=TRUE;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxDeviceVerifyStop(VOID *context,EFI_PCI_IO_PROTOCOL *p){
    RTX_DEVICE *d=context;
    if(!live(d) || d->Fault || p!=pci(d) || d->Arena->Phase!=RtxDmaCheckingStop || !d->MasterCleared ||
       !d->FlrComplete || !d->ConfigRestored || !d->AssertObserved || !d->ReleaseObserved || !d->ScrubObserved)
        return EFI_NOT_READY;
    EFI_STATUS s=owner(d);if(s!=EFI_SUCCESS)return s;
    s=RtxBoardReadRecovery(d->Bs,p,&d->Lease->HeldBoard,&d->Recovery);
    if(s!=EFI_SUCCESS)return RtxDeviceLatch(d,s);
    d->Verified=TRUE;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxDeviceVerifyReadyToBoot(RTX_DEVICE *d){
    if(!d)return EFI_INVALID_PARAMETER;
    d->ReadyCheck=RtxReadyCheckPrerequisites;
    d->ReadyOffset=d->ReadyActual=d->ReadyExpected=d->ReadyMask=0;
    if(!live(d) || d->Fault || !d->Verified || d->Arena->Phase!=RtxDmaStopped || !RtxDmaIsEmpty(d->Arena))return EFI_NOT_READY;
    d->ReadyCheck=RtxReadyCheckOwner;
    EFI_STATUS s=owner(d);if(s!=EFI_SUCCESS)return s;
    d->ReadyCheck=RtxReadyCheckRecovery;
    s=RtxBoardReadRecovery(d->Bs,pci(d),&d->Lease->HeldBoard,&d->Recovery);
    if(s!=EFI_SUCCESS)return RtxDeviceLatch(d,s);
    d->ReadyCheck=RtxReadyCheckFeatures;
    static const UINT32 required[][3]={
        {0x82381c,0xffffffffu,0x88888888u},{0x823820,0xffffffffu,8},
        {0x823818,0x07ffffffu,0},{0x823804,0xffffffffu,0xffffffffu}};
    for(UINTN i=0;i<sizeof(required)/sizeof(required[0]);i++){
        d->ReadyOffset=required[i][0];d->ReadyMask=required[i][1];d->ReadyExpected=required[i][2];
        BOOLEAN found=FALSE;
        for(UINTN j=0;j<d->Recovery.Board.RegistersRead;j++){
            RTX_BOARD_REGISTER *r=&d->Recovery.Board.Registers[j];
            if(r->Offset==required[i][0]){
                d->ReadyActual=r->Value;
                if((r->Value&required[i][1])!=required[i][2])return RtxDeviceLatch(d,EFI_NOT_READY);
                found=TRUE;break;
            }
        }
        if(!found)return RtxDeviceLatch(d,EFI_COMPROMISED_DATA);
    }
    /* The payload-time WPR permissions are already required by the unmodified
     * core BEFORE selectors/FLR. Pinned physical AD103 logs restore these two
     * PLMs after FLR, unlike FEAT/SS. Require this board's fresh held-entry
     * values here, not another card's constants or the pre-FLR payload values.
     * This read-only acceptance rule never writes WPR to make it pass. */
    d->ReadyCheck=RtxReadyCheckRestoredWpr;
    for(UINTN i=0;i<2;i++){
        UINT32 off=i?0x1fa7c4:0x1fa7cc;BOOLEAN before=FALSE,after=FALSE;
        d->ReadyOffset=off;d->ReadyMask=0xffffffffu;d->ReadyExpected=d->ReadyActual=0;
        const RTX_BOARD_STATE *entry=&d->Lease->HeldBoard;
        if(entry->RegistersRead!=RTX_BOARD_REGISTER_COUNT)return RtxDeviceLatch(d,EFI_COMPROMISED_DATA);
        for(UINTN j=0;j<entry->RegistersRead;j++)if(entry->Registers[j].Offset==off){
            d->ReadyExpected=entry->Registers[j].Value;before=TRUE;
        }
        for(UINTN j=0;j<d->Recovery.Board.RegistersRead;j++)if(d->Recovery.Board.Registers[j].Offset==off){
            d->ReadyActual=d->Recovery.Board.Registers[j].Value;after=TRUE;
        }
        if(!before || !after)return RtxDeviceLatch(d,EFI_COMPROMISED_DATA);
        if(bad(d->ReadyExpected) || d->ReadyActual!=d->ReadyExpected)return RtxDeviceLatch(d,EFI_NOT_READY);
    }
    d->ReadyCheck=RtxReadyCheckComplete;
    return EFI_SUCCESS;
}
