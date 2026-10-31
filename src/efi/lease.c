/* SPDX-License-Identifier: GPL-2.0-only */
#include "lease.h"
static EFI_GUID binding_guid=EFI_DRIVER_BINDING_PROTOCOL_GUID;
static EFI_GUID pci_guid=EFI_PCI_IO_PROTOCOL_GUID;
static EFI_STATUS EFIAPI unsupported(EFI_DRIVER_BINDING_PROTOCOL *self,EFI_HANDLE controller,
    EFI_DEVICE_PATH_PROTOCOL *path) {
    (void)self;(void)controller;(void)path;return EFI_UNSUPPORTED;
}
static EFI_STATUS EFIAPI refuse_stop(EFI_DRIVER_BINDING_PROTOCOL *self,EFI_HANDLE controller,
    UINTN children,EFI_HANDLE *buffer) {
    (void)self;(void)controller;(void)children;(void)buffer;return EFI_ACCESS_DENIED;
}
static EFI_STATUS fail(RTX_LEASE *l,EFI_STATUS s) {
    l->Failure=EFI_ERROR(s)?s:EFI_DEVICE_ERROR;
    l->Phase=l->StopAttempted?RtxLeaseRetained:RtxLeaseRejected;
    return l->Failure;
}
BOOLEAN EFIAPI RtxLeaseMustRemainResident(const RTX_LEASE *l) {return l && l->StopAttempted;}
static EFI_STATUS compare_config(RTX_LEASE *l,const UINT32 *before,
    const UINT32 *after,UINTN first,UINTN end,UINT32 command_add)
{
    for(UINTN i=first;i<end;i++)if(after[i]!=(before[i]|(i==1?command_add:0))){
        l->CompareOffset=(UINT32)i*4;l->CompareBefore=before[i];l->CompareAfter=after[i];
        return EFI_NOT_READY;
    }
    return EFI_SUCCESS;
}
static EFI_STATUS enable_memory(EFI_SYSTEM_TABLE *st,const RTX_BOARD_STATE *entry,
    RTX_OWNER_WORKSPACE *w,RTX_LEASE *l)
{
    EFI_PCI_IO_PROTOCOL *pci=l->Pci;
    l->Step=RtxLeaseStepStoppedBoard;
    EFI_STATUS s=RtxBoardReadPciState(st->BootServices,pci,&l->StoppedBoard);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseClaiming)return fail(l,s);
    if(l->StoppedBoard.BarBase!=entry->BarBase || l->StoppedBoard.BarBytes!=entry->BarBytes)
        return fail(l,EFI_NOT_READY);
    s=compare_config(l,entry->PciConfig,l->StoppedBoard.PciConfig,4,10,0);
    if(s!=EFI_SUCCESS)return fail(l,s);
    if(l->StoppedBoard.PciConfig[1]&2)return EFI_SUCCESS; /* already decoded */
    /* Config-only helper admits Command=0 here. Do NOT set DEVICE_ENABLE,
     * restore the old IO bit, set BME, or bypass a stale Attributes cache. */
    if(!pci->Attributes)return fail(l,EFI_UNSUPPORTED);
    l->Phase=RtxLeaseEnablingMemory;
    l->Step=RtxLeaseStepMemorySupported;
    UINT64 supported=0;
    s=pci->Attributes(pci,EfiPciIoAttributeOperationSupported,0,&supported);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    if(!(supported&EFI_PCI_IO_ATTRIBUTE_MEMORY))return fail(l,EFI_UNSUPPORTED);
    l->Step=RtxLeaseStepMemoryBefore;
    s=pci->Attributes(pci,EfiPciIoAttributeOperationGet,0,&l->MemoryAttributesBefore);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    if(l->MemoryAttributesBefore&(EFI_PCI_IO_ATTRIBUTE_IO|EFI_PCI_IO_ATTRIBUTE_MEMORY|
        EFI_PCI_IO_ATTRIBUTE_BUS_MASTER))return fail(l,EFI_NOT_READY);
    /* Attributes queries are external callbacks too. Recheck every config
     * dword before mutation; never interpret success as actual hardware state. */
    l->Step=RtxLeaseStepMemoryFresh;
    UINT32 fresh[64];
    s=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,64,fresh);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    s=compare_config(l,l->StoppedBoard.PciConfig,fresh,0,64,0);
    if(s!=EFI_SUCCESS)return fail(l,s);
    l->Step=RtxLeaseStepMemoryEnable;l->MemoryEnableAttempted=TRUE;
    s=pci->Attributes(pci,EfiPciIoAttributeOperationEnable,EFI_PCI_IO_ATTRIBUTE_MEMORY,NULL);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    l->Step=RtxLeaseStepMemoryAfter;
    s=pci->Attributes(pci,EfiPciIoAttributeOperationGet,0,&l->MemoryAttributesAfter);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    if(l->MemoryAttributesAfter!=(l->MemoryAttributesBefore|EFI_PCI_IO_ATTRIBUTE_MEMORY))
        return fail(l,EFI_NOT_READY);
    l->Step=RtxLeaseStepMemoryVerify;
    s=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,64,fresh);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    s=compare_config(l,l->StoppedBoard.PciConfig,fresh,0,64,2);
    if(s!=EFI_SUCCESS)return fail(l,s);
    l->MemoryEnabledVerified=TRUE;
    l->Step=RtxLeaseStepMemoryOwner;
    s=RtxOwnerInspectAfterStop(st,&l->Before,l->Application,w,&l->AfterClaim);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseEnablingMemory)return fail(l,s);
    l->Phase=RtxLeaseClaiming;
    return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxLeaseAcquire(EFI_SYSTEM_TABLE *st,EFI_HANDLE app,EFI_HANDLE target,
    EFI_HANDLE intel,const RTX_BOARD_STATE *entry,RTX_OWNER_WORKSPACE *w,RTX_LEASE *l)
{
    if(!l)return EFI_INVALID_PARAMETER;
    if(l->Phase!=RtxLeaseEmpty || l->Application || l->StopAttempted)return EFI_ALREADY_STARTED;
    if(!st || !st->BootServices || !app || app==target || app==intel || !w || !entry ||
       !entry->ColdObservationsAccepted || entry->LayoutResult!=RTX_LAYOUT_OK)return EFI_INVALID_PARAMETER;
    EFI_BOOT_SERVICES *bs=st->BootServices;
    if(!bs->DisconnectController || !bs->InstallProtocolInterface || !bs->OpenProtocol)
        return EFI_INVALID_PARAMETER;
    l->Phase=RtxLeaseInspecting;l->Application=app;l->Target=target;
    l->Step=RtxLeaseStepOwner;
    EFI_STATUS s=RtxOwnerInspect(st,target,intel,w,&l->Before);
    if(s!=EFI_SUCCESS)return fail(l,s);
    l->Step=RtxLeaseStepApplication;
    /* Require an existing loaded application without a driver binding. Never
     * replace a protocol on another agent's handle. */
    BOOLEAN found=FALSE;
    for(UINTN i=0;i<w->NodeCount;i++)if(w->Nodes[i].Handle==app) {
        found=TRUE;
        if(w->Nodes[i].Binding || w->Nodes[i].Image)return fail(l,EFI_ACCESS_DENIED);
    }
    if(!found)return fail(l,EFI_INVALID_PARAMETER);
    EFI_LOADED_IMAGE_PROTOCOL *loaded=NULL;
    EFI_GUID loaded_guid=EFI_LOADED_IMAGE_PROTOCOL_GUID;
    s=bs->HandleProtocol(app,&loaded_guid,(VOID **)&loaded);
    if(s!=EFI_SUCCESS || !loaded)return fail(l,s==EFI_SUCCESS?EFI_COMPROMISED_DATA:s);
    EFI_PCI_IO_PROTOCOL *preflight=NULL;
    s=bs->HandleProtocol(target,&pci_guid,(VOID **)&preflight);
    if(s!=EFI_SUCCESS || !preflight)return fail(l,s==EFI_SUCCESS?EFI_COMPROMISED_DATA:s);
    l->Step=RtxLeaseStepBoard;
    s=RtxBoardReadState(bs,preflight,entry->Layout.input.image_size,entry->Layout.input.boot_size,&l->PreStop);
    if(s!=EFI_SUCCESS)return fail(l,s);
    l->Step=RtxLeaseStepCompare;
    for(UINTN i=0;i<64;i++)if(l->PreStop.PciConfig[i]!=entry->PciConfig[i]){
        l->CompareOffset=(UINT32)i*4;l->CompareBefore=entry->PciConfig[i];l->CompareAfter=l->PreStop.PciConfig[i];
        return fail(l,EFI_NOT_READY);
    }
    if(l->PreStop.BarBase!=entry->BarBase || l->PreStop.BarBytes!=entry->BarBytes)return fail(l,EFI_NOT_READY);
    /* Mark BEFORE external callbacks. An error does not imply no side effects. */
    l->Phase=RtxLeaseStopping;l->StopAttempted=TRUE;
    l->Step=RtxLeaseStepDisconnect;
    s=bs->DisconnectController(target,l->Before.Driver,NULL);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseStopping)return fail(l,s);
    l->Step=RtxLeaseStepAfterStop;
    s=RtxOwnerInspectAfterStop(st,&l->Before,NULL,w,&l->AfterStop);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseStopping)return fail(l,s);
    l->Guard=(EFI_DRIVER_BINDING_PROTOCOL){unsupported,unsupported,refuse_stop,0x10,app,app};
    l->Phase=RtxLeaseInstallingGuard;l->GuardAttempted=TRUE;
    l->Step=RtxLeaseStepInstall;
    EFI_HANDLE installed=app;
    s=bs->InstallProtocolInterface(&installed,&binding_guid,EFI_NATIVE_INTERFACE,&l->Guard);
    if(s!=EFI_SUCCESS || installed!=app || l->Phase!=RtxLeaseInstallingGuard)return fail(l,s);
    l->Phase=RtxLeaseClaiming;l->ClaimAttempted=TRUE;
    l->Step=RtxLeaseStepClaim;
    s=bs->OpenProtocol(target,&pci_guid,(VOID **)&l->Pci,app,target,EFI_OPEN_PROTOCOL_BY_DRIVER);
    if(s!=EFI_SUCCESS || !l->Pci || l->Phase!=RtxLeaseClaiming)return fail(l,s);
    l->Step=RtxLeaseStepAfterClaim;
    s=RtxOwnerInspectAfterStop(st,&l->Before,app,w,&l->AfterClaim);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseClaiming)return fail(l,s);
    l->Step=RtxLeaseStepInterface;
    if(l->Pci!=preflight)return fail(l,EFI_NOT_READY);
    s=enable_memory(st,entry,w,l);
    if(s!=EFI_SUCCESS)return s;
    l->Step=RtxLeaseStepHeldBoard;
    s=RtxBoardReadState(bs,l->Pci,entry->Layout.input.image_size,entry->Layout.input.boot_size,&l->HeldBoard);
    if(s!=EFI_SUCCESS || l->Phase!=RtxLeaseClaiming)return fail(l,s);
    l->Step=RtxLeaseStepHeldCompare;
    if(l->HeldBoard.BarBase!=entry->BarBase || l->HeldBoard.BarBytes!=entry->BarBytes)return fail(l,EFI_NOT_READY);
    for(UINTN i=4;i<10;i++)if(l->HeldBoard.PciConfig[i]!=entry->PciConfig[i]){
        l->CompareOffset=(UINT32)i*4;l->CompareBefore=entry->PciConfig[i];l->CompareAfter=l->HeldBoard.PciConfig[i];
        return fail(l,EFI_NOT_READY);
    }
    l->Phase=RtxLeaseHeld;l->Step=RtxLeaseStepDone;return EFI_SUCCESS;
}
