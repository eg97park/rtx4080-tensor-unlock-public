/* SPDX-License-Identifier: GPL-2.0-only
 * Optional no-unlock frontend. probe.c's normal build is unchanged.
 * Links owner/board read-only modules and the separately gated OS handoff.
 * NEVER links lease/DMA/reset/firmware transaction code.
 */
#include "owner.h"
#include "board.h"
#include "handoff.h"
#include <Protocol/GraphicsOutput.h>
#include "ready_pin.h" /* private generated ESP path/hash, .local only */
static RTX_BOARD_STATE ready_board;
static RTX_OWNER_STATE ready_owner;
static RTX_HANDOFF ready_handoff;
static RTX_OWNER_WORKSPACE *ready_workspace;
/* RAM metadata only. Never call GOP QueryMode/SetMode/Blt, dereference the
 * framebuffer or alter a protocol/console. Both snapshots use the same
 * Windows handoff implementation as UNLOCK. This is an isolation experiment,
 * not a fix for the observed ROOT\BasicDisplay duplicate desktop. */
static EFI_STATUS display_snapshot(UINT64 phase) {
    EFI_GUID guid=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    EFI_HANDLE *handles=NULL;UINTN count=0;
    record("display_snapshot_phase",phase);
    EFI_STATUS s=bs->LocateHandleBuffer(ByProtocol,&guid,NULL,&count,&handles);
    record("display_enumeration_status",s);record("display_handle_count",count);
    if(s!=EFI_SUCCESS)return s;
    if(!handles || !count || count>32){
        if(handles)(void)bs->FreePool(handles);
        return EFI_COMPROMISED_DATA;
    }
    for(UINTN i=0;i<count && s==EFI_SUCCESS;i++){
        EFI_GRAPHICS_OUTPUT_PROTOCOL *g=NULL;
        record("display_handle",(UINTN)handles[i]);
        s=bs->HandleProtocol(handles[i],&guid,(VOID **)&g);
        record("display_protocol_status",s);
        if(s!=EFI_SUCCESS)break;
        if(!g || !g->Mode || !g->Mode->Info ||
           g->Mode->SizeOfInfo<sizeof(*g->Mode->Info)) {s=EFI_COMPROMISED_DATA;break;}
        const EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *m=g->Mode;
        const EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *v=m->Info;
        record("display_interface",(UINTN)g);
        record("display_mode",m->Mode);record("display_max_mode",m->MaxMode);
        record("display_framebuffer_base",m->FrameBufferBase);
        record("display_framebuffer_bytes",m->FrameBufferSize);
        record("display_info_bytes",m->SizeOfInfo);record("display_info_version",v->Version);
        record("display_width",v->HorizontalResolution);record("display_height",v->VerticalResolution);
        record("display_pixel_format",v->PixelFormat);record("display_stride",v->PixelsPerScanLine);
        record("display_red_mask",v->PixelInformation.RedMask);record("display_green_mask",v->PixelInformation.GreenMask);
        record("display_blue_mask",v->PixelInformation.BlueMask);record("display_reserved_mask",v->PixelInformation.ReservedMask);
        EFI_DEVICE_PATH_PROTOCOL *p=NULL;BOOLEAN usb=FALSE;
        EFI_STATUS ps=bs->HandleProtocol(handles[i],&path_guid,(VOID **)&p);
        record("display_path_status",ps);
        if(ps==EFI_SUCCESS){
            UINTN n=path_size(p,&usb);
            if(!n){s=EFI_COMPROMISED_DATA;break;}
            record_bytes("display_device_path",p,n);
        }else if(ps!=EFI_UNSUPPORTED && ps!=EFI_NOT_FOUND){s=ps;break;}
        if(fault!=EFI_SUCCESS)s=fault;
    }
    EFI_STATUS freed=bs->FreePool(handles);
    if(s==EFI_SUCCESS)s=freed;
    record("display_snapshot_status",s);
    return fault==EFI_SUCCESS?s:fault;
}
static VOID say(EFI_SYSTEM_TABLE *st,CHAR16 *message) {st->ConOut->OutputString(st->ConOut,message);}
static EFI_STATUS key(EFI_SYSTEM_TABLE *st,CHAR16 *out) {
    for(;;) {
        EFI_INPUT_KEY k={0};EFI_STATUS s=st->ConIn->ReadKeyStroke(st->ConIn,&k);
        if(s==EFI_SUCCESS){*out=k.ScanCode==0x17?0x1b:k.UnicodeChar;return EFI_SUCCESS;}
        if(s!=EFI_NOT_READY)return EFI_ERROR(s)?s:EFI_DEVICE_ERROR;
        UINTN selected=0;s=bs->WaitForEvent(1,&st->ConIn->WaitForKey,&selected);
        if(s!=EFI_SUCCESS || selected)return EFI_ERROR(s)?s:EFI_DEVICE_ERROR;
    }
}
static EFI_STATUS ready_inspect(EFI_SYSTEM_TABLE *st) {
    EFI_HANDLE *handles=NULL,target=NULL,intel=NULL;UINTN count=0;
    EFI_PCI_IO_PROTOCOL *pci=NULL;
    EFI_STATUS s=bs->LocateHandleBuffer(ByProtocol,&pci_guid,NULL,&count,&handles);
    if(s!=EFI_SUCCESS || !handles || !count || count>1024)return EFI_COMPROMISED_DATA;
    for(UINTN i=0;i<count;i++) {
        EFI_PCI_IO_PROTOCOL *p=NULL;UINT32 id=0;
        s=bs->HandleProtocol(handles[i],&pci_guid,(VOID **)&p);
        if(s!=EFI_SUCCESS || !p || !p->Pci.Read)return EFI_COMPROMISED_DATA;
        s=p->Pci.Read(p,EfiPciIoWidthUint32,0,1,&id);if(s!=EFI_SUCCESS)return s;
        if(id==0x270410de){if(target)return EFI_ACCESS_DENIED;target=handles[i];pci=p;}
        if(id==0x7d678086){if(intel)return EFI_ACCESS_DENIED;intel=handles[i];}
    }
    s=bs->FreePool(handles);if(s!=EFI_SUCCESS)return s;
    if(!target || !intel)return EFI_NOT_FOUND;
    s=RtxBoardReadState(bs,pci,84226048,36864,&ready_board);record("ready_board_status",s);
    if(s!=EFI_SUCCESS)return s;
    s=bs->AllocatePool(EfiLoaderData,sizeof(*ready_workspace),(VOID **)&ready_workspace);
    if(s!=EFI_SUCCESS || !ready_workspace)return EFI_OUT_OF_RESOURCES;
    s=RtxOwnerInspect(st,target,intel,ready_workspace,&ready_owner);
    record("ready_owner_status",s);record("ready_code_matched",ready_owner.CodeIdentityMatched);
    record("ready_intel_path",ready_owner.IntelPathObserved);
    record("ready_driver",(UINTN)ready_owner.Driver);record("ready_image_base",ready_owner.ImageBase);
    if(s!=EFI_SUCCESS)return s;
    record("ready_binding_pointer",ready_owner.ImageBase+0x21b60);
    record("ready_binding_start",ready_owner.ImageBase+0x704);
    record("ready_binding_stop",ready_owner.ImageBase+0x6ec);
    s=RtxHandoffPrepare(bs,&ready_pin,&ready_handoff);record("ready_boot_file_status",s);
    record("ready_boot_file_bytes",ready_handoff.Size);
    if(s==EFI_SUCCESS)record_bytes("ready_boot_file_sha256",ready_handoff.VerifiedHash,32);
    return s;
}
static EFI_STATUS finish_log(EFI_STATUS s) {
    record("ready_final_status",s);
    EFI_STATUS a=log_file->Flush(log_file),b=log_file->Close(log_file),c=root->Close(root);
    log_file=NULL;root=NULL;
    if(s!=EFI_SUCCESS)return s;
    if(fault!=EFI_SUCCESS)return fault;
    if(a!=EFI_SUCCESS || b!=EFI_SUCCESS || c!=EFI_SUCCESS)return EFI_DEVICE_ERROR;
    return EFI_SUCCESS;
}
EFI_STATUS EFIAPI EfiMain(EFI_HANDLE image,EFI_SYSTEM_TABLE *st) {
    if(!image || !st || !st->BootServices || !st->ConOut || !st->ConOut->OutputString ||
       !st->ConIn || !st->ConIn->ReadKeyStroke || !st->ConIn->WaitForKey ||
       !st->BootServices->WaitForEvent || !st->BootServices->SetWatchdogTimer)return EFI_INVALID_PARAMETER;
    if(relocated_entry!=EfiMain)return EFI_LOAD_ERROR;
    root=NULL;log_file=NULL;log_bytes=0;fault=EFI_SUCCESS;bs=st->BootServices;
    /* Disable the per-application watchdog, not a persistent boot setting. */
    EFI_STATUS s=bs->SetWatchdogTimer(0,0,0,NULL);if(s!=EFI_SUCCESS)return s;
    say(st,L"\r\nRTX4080 READINESS - NO UNLOCK / NO GPU RESET\r\nReading board, GOP identity and Windows boot file...\r\n");
    s=open_log(image);
    if(s!=EFI_SUCCESS){say(st,L"USB log unavailable. No experiment started.\r\n");return s;}
    record("probe_schema",2);record("readiness_schema",1);record("gpu_write_capability",0);
    s=claim_one_shot();record("one_shot_status",s);
    if(s==EFI_SUCCESS)s=graph(st);
    if(s==EFI_SUCCESS)s=capture_target();
    record("capture_status",s);record("capture_complete",s==EFI_SUCCESS && fault==EFI_SUCCESS);
    if(s==EFI_SUCCESS && fault==EFI_SUCCESS)s=ready_inspect(st);
    if(s==EFI_SUCCESS && fault==EFI_SUCCESS)s=display_snapshot(1);
    if(fault!=EFI_SUCCESS)s=fault;
    record("ready_preflight_status",s);
    EFI_STATUS flushed=log_file->Flush(log_file);if(flushed!=EFI_SUCCESS)s=EFI_DEVICE_ERROR;
    if(s!=EFI_SUCCESS) {
        s=finish_log(s);say(st,L"READINESS FAILED. No GPU changes or Windows launch.\r\nPreserve USB logs. Press ESC to return to firmware.\r\n");
        CHAR16 k=0;while(k!=0x1b)if(key(st,&k)!=EFI_SUCCESS)break;
        return s;
    }
    say(st,L"READINESS PASS: live GOP and boot file verified. No unlock performed.\r\nW: start the existing Windows Boot Manager once. ESC: cancel.\r\nKeep track of any motherboard logo / restart, then select the test Windows.\r\n");
    CHAR16 k=0;
    for(;;) {
        s=key(st,&k);if(s!=EFI_SUCCESS)return finish_log(s);
        if(k==0x1b){record("ready_handoff_cancelled",1);return finish_log(EFI_ABORTED);}
        if(k==L'w' || k==L'W')break;
    }
    record("ready_handoff_user_selected",1);
    if(fault!=EFI_SUCCESS)return finish_log(fault);
    s=log_file->Flush(log_file);if(s!=EFI_SUCCESS)return finish_log(s);
    s=RtxHandoffLoad(bs,image,&ready_handoff);record("ready_load_status",s);
    if(s==EFI_SUCCESS && fault==EFI_SUCCESS)s=display_snapshot(2);
    if(s==EFI_SUCCESS && fault==EFI_SUCCESS) {
        record("ready_start_attempt",1);
        s=fault==EFI_SUCCESS?log_file->Flush(log_file):fault;
        if(s==EFI_SUCCESS)s=RtxHandoffStart(bs,&ready_handoff);
    }
    record("ready_handoff_returned",1);(void)finish_log(s);
    say(st,L"WINDOWS HANDOFF DID NOT COMPLETE. No automatic retry or restart.\r\nPreserve USB logs. Power off manually, remove USB, then boot Windows normally.\r\n");
    /* A loaded child may hold references. Keep this parent resident. */
    for(;;){CHAR16 ignored=0;(void)key(st,&ignored);}
}
