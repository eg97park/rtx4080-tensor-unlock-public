/* SPDX-License-Identifier: GPL-2.0-only
 * DRAFT experimental frontend; separate token, no USB deployment automation.
 * No auto retry/reboot/return after LoadImage or NVIDIA Stop. */
#include "session.h"
#include "ready_pin.h"
#include "unlock_assets.h" /* private generated filenames/sizes, hash checked */
static RTX_SESSION *unlock_session;
static RTX_OWNER_WORKSPACE *unlock_workspace;
static RTX_CORE_ASSET unlock_assets[5];
static EFI_FILE_PROTOCOL *unlock_asset_files[5];
static VOID unlock_say(EFI_SYSTEM_TABLE *st,CHAR16 *s){st->ConOut->OutputString(st->ConOut,s);}
static EFI_STATUS unlock_key(EFI_SYSTEM_TABLE *st,CHAR16 *out){
    for(;;){EFI_INPUT_KEY k={0};EFI_STATUS s=st->ConIn->ReadKeyStroke(st->ConIn,&k);
        if(s==EFI_SUCCESS){*out=k.ScanCode==0x17?0x1b:k.UnicodeChar;return EFI_SUCCESS;}
        if(s!=EFI_NOT_READY)return s;
        UINTN index=0;s=bs->WaitForEvent(1,&st->ConIn->WaitForKey,&index);
        if(s!=EFI_SUCCESS || index)return EFI_DEVICE_ERROR;
    }
}
static EFI_STATUS unlock_load_assets(VOID){
    for(UINTN i=0;i<5;i++){
        EFI_FILE_PROTOCOL *f=NULL;VOID *bytes=NULL;
        EFI_STATUS s=root->Open(root,&f,unlock_files[i].Path,EFI_FILE_MODE_READ,0);
        unlock_asset_files[i]=f;
        if(s!=EFI_SUCCESS || !f || !f->Read || !f->Close)return EFI_LOAD_ERROR;
        s=bs->AllocatePool(EfiLoaderData,unlock_files[i].Bytes,&bytes);
        if(s!=EFI_SUCCESS || !bytes)return EFI_OUT_OF_RESOURCES;
        unlock_assets[i]=(RTX_CORE_ASSET){unlock_files[i].Name,{unlock_files[i].Bytes,bytes}};
        for(UINTN off=0;off<unlock_files[i].Bytes;){
            UINTN n=unlock_files[i].Bytes-off;if(n>1024*1024)n=1024*1024;UINTN expected=n;
            s=f->Read(f,&n,(UINT8 *)bytes+off);if(s!=EFI_SUCCESS || n!=expected)return EFI_LOAD_ERROR;off+=n;
        }
        UINT8 extra=0;UINTN n=1;s=f->Read(f,&n,&extra);
        if(s!=EFI_SUCCESS || n)return EFI_BAD_BUFFER_SIZE;
        s=f->Close(f);if(s!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
        unlock_asset_files[i]=NULL;
    }
    return RtxCoreValidateAssets(unlock_assets);
}
static EFI_STATUS unlock_targets(EFI_HANDLE *target,EFI_HANDLE *intel){
    EFI_HANDLE *handles=NULL;UINTN count=0;
    EFI_STATUS s=bs->LocateHandleBuffer(ByProtocol,&pci_guid,NULL,&count,&handles);
    if(s!=EFI_SUCCESS || !handles || !count || count>1024)return EFI_COMPROMISED_DATA;
    for(UINTN i=0;i<count;i++){
        EFI_PCI_IO_PROTOCOL *p=NULL;UINT32 id=0;
        s=bs->HandleProtocol(handles[i],&pci_guid,(VOID **)&p);
        if(s!=EFI_SUCCESS || !p || !p->Pci.Read)return EFI_COMPROMISED_DATA;
        s=p->Pci.Read(p,EfiPciIoWidthUint32,0,1,&id);if(s!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
        if(id==0x270410de){if(*target)return EFI_ACCESS_DENIED;*target=handles[i];}
        if(id==0x7d678086){if(*intel)return EFI_ACCESS_DENIED;*intel=handles[i];}
    }
    s=bs->FreePool(handles);if(s!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
    return *target && *intel?EFI_SUCCESS:EFI_NOT_FOUND;
}
/* Cached RAM only, called before Stop or after independently verified GPU
 * cleanup. No new device query or file write from a failure screen. */
static VOID unlock_display_record(const RTX_DISPLAY_SNAPSHOT *d,UINTN stage){
    record("display_snapshot_phase",stage);record("display_snapshot_status",d->Status);
    record("display_handle",d->Handle);record("display_interface",d->Interface);
    record("display_mode_pointer",d->ModePointer);record("display_info_pointer",d->InfoPointer);
    record("display_console",d->Console);record("display_console_interface",d->ConsoleInterface);
    record("display_framebuffer_base",d->FrameBufferBase);record("display_framebuffer_bytes",d->FrameBufferBytes);
    record("display_info_bytes",d->InfoBytes);record("display_pci_attributes",d->Attributes);
    record("display_pci_interface",d->PciInterface);record("display_mode",d->Mode);record("display_max_mode",d->MaxMode);
    record("display_info_version",d->Info.Version);record("display_width",d->Info.HorizontalResolution);
    record("display_height",d->Info.VerticalResolution);record("display_pixel_format",d->Info.PixelFormat);
    record("display_stride",d->Info.PixelsPerScanLine);record("display_red_mask",d->Info.PixelInformation.RedMask);
    record("display_green_mask",d->Info.PixelInformation.GreenMask);record("display_blue_mask",d->Info.PixelInformation.BlueMask);
    record("display_reserved_mask",d->Info.PixelInformation.ReservedMask);
    record_bytes("display_device_path",d->Path,d->PathBytes);
    record_bytes("display_pci_path",d->PciPath,d->PciPathBytes);
    for(UINTN n=0;n<16;n++){record("display_pci_offset",n*4);record("display_pci_word",d->Pci[n]);}
}
static EFI_STATUS EFIAPI unlock_journal(VOID *context,const RTX_SESSION *s){
    (void)context;
    if(s->Phase!=RtxSessionBootLoaded && s->Phase!=RtxSessionFinalCheck)return EFI_ACCESS_DENIED;
    record("unlock_phase",s->Phase);
    if(s->Phase==RtxSessionBootLoaded){
        if(!s->Display.Snapshots[0].Complete)return EFI_NOT_READY;
        unlock_display_record(&s->Display.Snapshots[0],0);
    }
    if(s->Phase==RtxSessionFinalCheck){
        if(!s->Core.CleanupComplete || s->Core.Retained || !s->Core.UnlockReported || !RtxDmaIsEmpty(&s->Arena))return EFI_NOT_READY;
        record("core_result",(UINT64)(INT64)s->Core.CoreResult);record("dma_empty",1);
        record("flr_count",s->Device.FlrAttempted);record("gpu_recovery_verified",s->Device.Verified);
        record("core_log_truncated",s->Core.LogTruncated);record("core_log_format_rejected",s->Core.LogFormatRejected);
        if(!s->Display.Snapshots[1].Complete || !s->Display.Snapshots[2].Complete)return EFI_NOT_READY;
        record("display_guard_schema",1);
        unlock_display_record(&s->Display.Snapshots[1],1);unlock_display_record(&s->Display.Snapshots[2],2);
        record("display_guard_end",1);
        UINTN n=s->Core.LogBytes;EFI_STATUS r=log_file->Write(log_file,&n,(VOID *)s->Core.Log);
        if(r!=EFI_SUCCESS || n!=s->Core.LogBytes)return EFI_DEVICE_ERROR;
        record("unlock_windows_start_intent",1);
    }
    if(fault!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
    if(log_file->Flush(log_file)!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
    if(s->Phase==RtxSessionFinalCheck){
        if(log_file->Close(log_file)!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
        log_file=NULL;
        if(root->Close(root)!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
        root=NULL;
    }
    return EFI_SUCCESS;
}
/* Bounded RAM snapshot only: no allocation, file IO or fresh hardware query.
 * Print all fields before the terminal pause so a photograph identifies the
 * failed operation even when persisting a journal would be unsafe. */
static VOID unlock_pair(EFI_SYSTEM_TABLE *st,const CHAR16 *label,UINT64 a,UINT64 b){
    CHAR16 line[80];UINTN n=0;
    while(n<32 && label[n]){line[n]=label[n];n++;}
    line[n++]=L' ';
    for(UINTN i=0;i<16;i++)line[n++]=L"0123456789abcdef"[(a>>(60-i*4))&15];
    line[n++]=L' ';
    for(UINTN i=0;i<16;i++)line[n++]=L"0123456789abcdef"[(b>>(60-i*4))&15];
    line[n++]=L'\r';line[n++]=L'\n';line[n]=0;unlock_say(st,line);
}
static VOID unlock_failure_screen(EFI_SYSTEM_TABLE *st,EFI_STATUS status,const RTX_SESSION *s){
    /* Capture before any console callback. Never dereference GPU/driver/DMA
     * pointers or infer nonexecution merely from a zero write counter. */
    UINT64 values[15][2]={{0}};
    BOOLEAN ready=s && s->Device.ReadyCheck!=RtxReadyCheckNone;
    BOOLEAN display=s && s->Display.Status!=EFI_SUCCESS;
    if(s){
        const RTX_LEASE *l=&s->Lease;const RTX_DEVICE *d=&s->Device;const RTX_CORE *c=&s->Core;
        const RTX_BOARD_STATE *b=&s->Entry;
        if(l->Step>=RtxLeaseStepStoppedBoard)b=&l->StoppedBoard;
        else if(l->Step>=RtxLeaseStepHeldBoard)b=&l->HeldBoard;
        else if(l->Step>=RtxLeaseStepBoard)b=&l->PreStop;
        if(d->ReadyCheck>=RtxReadyCheckRecovery)b=&d->Recovery.Board;
        UINT64 flags=(UINT64)l->StopAttempted | (UINT64)l->GuardAttempted<<1 | (UINT64)l->ClaimAttempted<<2 |
            (UINT64)c->Attempted<<3 | (UINT64)d->MasterAttempted<<4 | (UINT64)d->FlrAttempted<<5 |
            (UINT64)s->StartAttempted<<6 | (UINT64)d->Verified<<7 | (UINT64)c->CleanupComplete<<8 |
            (UINT64)c->Retained<<9 | (UINT64)l->MemoryEnableAttempted<<10 |
            (UINT64)l->MemoryEnabledVerified<<11;
        values[0][0]=s->Step;values[0][1]=s->Phase;
        values[1][0]=l->Step;values[1][1]=l->Phase;
        values[2][0]=flags;values[2][1]=s->Arena.Count;
        values[3][0]=d->MmioWrites;values[3][1]=d->ConfigWrites;
        values[4][0]=c->Status;values[4][1]=(UINT64)(INT64)c->CoreResult;
        values[5][0]=d->Fault;values[5][1]=d->LastStatus;
        values[6][0]=d->LastOffset;values[6][1]=d->LastValue;
        values[7][0]=s->Entry.PciConfig[1]&0xffff;values[7][1]=l->HeldBoard.PciConfig[1]&0xffff;
        values[8][0]=b->Check;values[8][1]=b->LastReadOffset;
        values[9][0]=b->RegistersRead;
        if(b->RegistersRead && b->RegistersRead<=RTX_BOARD_REGISTER_COUNT)values[9][1]=b->Registers[b->RegistersRead-1].Value;
        values[10][0]=b->CompareOffset;values[10][1]=b->CompareAfter;
        values[11][0]=l->CompareBefore;values[11][1]=l->CompareAfter;
        values[12][0]=l->CompareOffset;
        if(b->CompareOffset<256 && !(b->CompareOffset&3))values[12][1]=b->PciConfig[b->CompareOffset/4];
        values[13][0]=c->LogBytes;values[13][1]=c->LogTruncated;
        values[14][0]=l->MemoryAttributesBefore;values[14][1]=l->MemoryAttributesAfter;
        if(ready){
            values[6][0]=d->ReadyCheck;values[6][1]=d->ReadyOffset;
            values[10][0]=d->ReadyActual;values[10][1]=d->ReadyExpected;
            values[11][0]=d->ReadyMask;values[11][1]=d->Recovery.ObservationsAccepted;
            values[12][0]=values[12][1]=0;
            for(UINTN i=0;i<d->Recovery.Board.RegistersRead && i<RTX_BOARD_REGISTER_COUNT;i++){
                const RTX_BOARD_REGISTER *r=&d->Recovery.Board.Registers[i];
                if(r->Offset==0x1fa7cc)values[12][0]=r->Value;
                if(r->Offset==0x1fa7c4)values[12][1]=r->Value;
            }
        }
    }
    if(display){
        values[6][0]=s->Display.Stage;values[6][1]=s->Display.Status;
        values[10][0]=s->Display.Difference;values[10][1]=0;
        values[11][0]=s->Display.Before;values[11][1]=s->Display.After;
    }
    static const CHAR16 *labels[]={L"step/phase",L"lease-step/phase",L"attempt-flags/dma-count",
        L"mmio/pci-write-attempts",L"core-status/result",L"device-fault/last-status",
        L"last-offset/value",L"entry/held-pci-command",L"board-check/read-offset",
        L"board-read-count/value",L"board-delta-offset/after",L"lease-delta-before/after",
        L"lease-offset/board-before",L"core-log-bytes/truncated",L"memory-attrs-before/after"};
    CHAR16 line[]=L"Status 0x0000000000000000. STOP. Manual power off required.\r\n";
    for(UINTN i=0;i<16;i++)line[9+i]=L"0123456789abcdef"[(status>>(60-i*4))&15];
    unlock_say(st,L"\r\nEXPERIMENT STOPPED. Do not restart or select Windows.\r\n");
    unlock_say(st,line);
    unlock_say(st,L"DIAG4 RAM snapshot; hexadecimal pairs; zero is not proof of no GPU change.\r\n");
    for(UINTN i=0;i<15;i++){
        const CHAR16 *label=labels[i];
        if(ready){
            if(i==6)label=L"ready-check/offset";
            if(i==10)label=L"ready-actual/expected";
            if(i==11)label=L"ready-mask/recovery-ok";
            if(i==12)label=L"post-WPR-CFG/WPR";
        }
        if(display){
            if(i==6)label=L"display-stage/status";
            if(i==10)label=L"display-difference/reserved";
            if(i==11)label=L"display-before/after";
        }
        unlock_pair(st,label,values[i][0],values[i][1]);
    }
    unlock_say(st,L"STOP. Photograph this screen, then manual power off.\r\n");
}
static VOID unlock_terminal(EFI_SYSTEM_TABLE *st,EFI_STATUS status){
    unlock_failure_screen(st,status,unlock_session);
    /* CPU-only terminal wait. No boot services, file IO, GPU reads/writes,
     * cleanup, retry or automatic reset after uncertain device state. */
    for(;;)__asm__ volatile("pause");
}
EFI_STATUS EFIAPI EfiMain(EFI_HANDLE image,EFI_SYSTEM_TABLE *st){
    if(!image || !st || !st->BootServices || !st->ConOut || !st->ConOut->OutputString ||
       !st->ConIn || !st->ConIn->ReadKeyStroke || !st->ConIn->WaitForKey ||
       !st->BootServices->WaitForEvent || !st->BootServices->SetWatchdogTimer)return EFI_INVALID_PARAMETER;
    if(relocated_entry!=EfiMain)return EFI_LOAD_ERROR;
    bs=st->BootServices;root=NULL;log_file=NULL;log_bytes=0;fault=EFI_SUCCESS;
    EFI_STATUS s=bs->SetWatchdogTimer(0,0,0,NULL);if(s!=EFI_SUCCESS)return s;
    unlock_say(st,L"\r\nRTX4080 EXPERIMENTAL UNLOCK - GPU WRITES, FIRMWARE, ONE FLR\r\nFor a separately approved supervised experiment only.\r\n");
    s=open_log(image);if(s!=EFI_SUCCESS)return s;
    record("unlock_schema",1);record("gpu_write_capability",1);
    s=claim_one_shot();if(s==EFI_SUCCESS)s=graph(st);if(s==EFI_SUCCESS)s=capture_target();
    if(s==EFI_SUCCESS && fault==EFI_SUCCESS)s=unlock_load_assets();
    if(fault!=EFI_SUCCESS)s=EFI_DEVICE_ERROR;
    EFI_HANDLE target=NULL,intel=NULL;if(s==EFI_SUCCESS)s=unlock_targets(&target,&intel);
    if(s==EFI_SUCCESS){s=bs->AllocatePool(EfiLoaderData,sizeof(*unlock_session),(VOID **)&unlock_session);
        if(s==EFI_SUCCESS && unlock_session)memset(unlock_session,0,sizeof(*unlock_session));else s=EFI_OUT_OF_RESOURCES;}
    if(s==EFI_SUCCESS){s=bs->AllocatePool(EfiLoaderData,sizeof(*unlock_workspace),(VOID **)&unlock_workspace);
        if(s!=EFI_SUCCESS || !unlock_workspace)s=EFI_OUT_OF_RESOURCES;}
    record("unlock_preflight_status",s);
    if(fault!=EFI_SUCCESS || log_file->Flush(log_file)!=EFI_SUCCESS)s=EFI_DEVICE_ERROR;
    if(s!=EFI_SUCCESS){unlock_say(st,L"Preflight failed. No GPU mutation requested. Preserve USB log.\r\n");return s;}
    unlock_say(st,L"U: authorize this ONE transaction now. ESC: cancel.\r\nIf it fails, keep power off; no automatic Windows boot.\r\n");
    CHAR16 k=0;do{s=unlock_key(st,&k);if(s!=EFI_SUCCESS)return s;if(k==0x1b)return EFI_ABORTED;}while(k!=L'u' && k!=L'U');
    record("unlock_user_selected",1);if(fault!=EFI_SUCCESS || log_file->Flush(log_file)!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
    unlock_session->Journal=unlock_journal;
    s=RtxSessionRunApproved(unlock_session,st,image,target,intel,unlock_workspace,unlock_assets,&ready_pin);
    if(unlock_session->MustRemainResident)unlock_terminal(st,s);
    record("unlock_failure_before_load",s);log_file->Flush(log_file);
    return s==EFI_SUCCESS?EFI_ABORTED:s;
}
