/* SPDX-License-Identifier: GPL-2.0-only */
#include "session.h"
static EFI_STATUS failed(RTX_SESSION *s,EFI_STATUS status){
    s->MustRemainResident=s->Handoff.LoadAttempted || RtxLeaseMustRemainResident(&s->Lease);
    s->Failure=EFI_ERROR(status)?status:EFI_DEVICE_ERROR;
    return s->Failure;
}
EFI_STATUS EFIAPI RtxSessionRunApproved(RTX_SESSION *s,EFI_SYSTEM_TABLE *st,EFI_HANDLE app,
    EFI_HANDLE target,EFI_HANDLE intel,RTX_OWNER_WORKSPACE *w,const RTX_CORE_ASSET assets[5],const RTX_BOOT_PIN *pin){
    if(!s || !st || !st->BootServices || !app || !target || !intel || target==intel || !w || !assets || !pin)return EFI_INVALID_PARAMETER;
    if(s->Attempted)return EFI_ALREADY_STARTED;
    s->Attempted=TRUE;
    s->Step=RtxStepAssets;
    EFI_STATUS r=RtxCoreValidateAssets(assets);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Phase=RtxSessionAssets;
    s->Step=RtxStepBootPrepare;
    r=RtxHandoffPrepare(st->BootServices,pin,&s->Handoff);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Phase=RtxSessionBootPrepared;
    s->Step=RtxStepBootLoad;
    r=RtxHandoffLoad(st->BootServices,app,&s->Handoff);if(r!=EFI_SUCCESS)return failed(s,r);
    s->MustRemainResident=TRUE;s->Phase=RtxSessionBootLoaded;
    s->Step=RtxStepDisplayBefore;
    r=RtxDisplayCheck(st,intel,&s->Display,0);if(r!=EFI_SUCCESS)return failed(s,r);
    if(s->Journal){s->Step=RtxStepPreStopJournal;r=s->Journal(s->JournalContext,s);if(r!=EFI_SUCCESS)return failed(s,r);}
    /* Re-enumeration/LoadImage callbacks precede this fresh board and the
     * lease's fresh graph check. No image loading after GPU mutation. */
    EFI_PCI_IO_PROTOCOL *pci=NULL;EFI_GUID guid=EFI_PCI_IO_PROTOCOL_GUID;
    s->Step=RtxStepPciHandle;
    if(!st->BootServices->HandleProtocol)return failed(s,EFI_UNSUPPORTED);
    r=st->BootServices->HandleProtocol(target,&guid,(VOID **)&pci);
    if(r!=EFI_SUCCESS || !pci)return failed(s,r==EFI_SUCCESS?EFI_NOT_FOUND:r);
    s->Step=RtxStepEntryBoard;
    r=RtxBoardReadState(st->BootServices,pci,84226048,36864,&s->Entry);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Step=RtxStepLease;
    r=RtxLeaseAcquire(st,app,target,intel,&s->Entry,w,&s->Lease);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Phase=RtxSessionLease;
    s->Step=RtxStepDisplayLease;
    r=RtxDisplayCheck(st,intel,&s->Display,1);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Step=RtxStepDmaInit;
    r=RtxDmaInit(&s->Arena,s->Lease.Pci);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Step=RtxStepDeviceInit;
    r=RtxDeviceInit(&s->Device,st,&s->Lease,&s->Arena,w);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Step=RtxStepCore;
    r=RtxCoreRun(&s->Core,&s->Device,assets);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Phase=RtxSessionCore;
    s->Step=RtxStepCorePostcondition;
    if(!s->Core.CleanupComplete || s->Core.Retained || !s->Core.UnlockReported || !RtxDmaIsEmpty(&s->Arena))return failed(s,EFI_NOT_READY);
    s->Step=RtxStepVerify;
    r=RtxDeviceVerifyReadyToBoot(&s->Device);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Step=RtxStepDisplayCore;
    r=RtxDisplayCheck(st,intel,&s->Display,2);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Phase=RtxSessionFinalCheck;
    if(s->Journal){
        s->Step=RtxStepFinalJournal;
        r=s->Journal(s->JournalContext,s);if(r!=EFI_SUCCESS)return failed(s,r);
    }
    /* File/console and display-inspection callbacks must not be the last
     * observation of GPU safety. Neither gate repairs or retries anything. */
    s->Step=RtxStepDisplayStart;
    r=RtxDisplayCheck(st,intel,&s->Display,3);if(r!=EFI_SUCCESS)return failed(s,r);
    s->Step=RtxStepReverify;
    r=RtxDeviceVerifyReadyToBoot(&s->Device);if(r!=EFI_SUCCESS)return failed(s,r);
    s->StartAttempted=TRUE;s->Phase=RtxSessionStarting;
    s->Step=RtxStepWindowsStart;
    r=RtxHandoffStart(st->BootServices,&s->Handoff);
    return failed(s,r==EFI_SUCCESS?EFI_ABORTED:r);
}
