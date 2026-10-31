/* SPDX-License-Identifier: GPL-2.0-only */
#include "display.h"
#include <Protocol/DevicePath.h>
static EFI_GUID gop_guid=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GUID pci_guid=EFI_PCI_IO_PROTOCOL_GUID;
static EFI_GUID path_guid=EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_STATUS copy_path(const VOID *ptr,UINT8 out[RTX_DISPLAY_PATH_MAX],UINTN *bytes){
    if(!ptr)return EFI_COMPROMISED_DATA;
    const UINT8 *p=ptr;UINTN off=0;
    while(off<=RTX_DISPLAY_PATH_MAX-4){
        UINTN n=p[off+2]|((UINTN)p[off+3]<<8);
        if(n<4 || n>RTX_DISPLAY_PATH_MAX-off)return EFI_COMPROMISED_DATA;
        for(UINTN i=0;i<n;i++)out[off+i]=p[off+i];
        if(p[off]==0x7f){
            if(p[off+1]!=0xff || n!=4 || !off)return EFI_COMPROMISED_DATA;
            *bytes=off+4;return EFI_SUCCESS;
        }
        off+=n;
    }
    return EFI_COMPROMISED_DATA;
}
static EFI_STATUS capture(EFI_SYSTEM_TABLE *st,EFI_HANDLE intel,RTX_DISPLAY_SNAPSHOT *s){
    EFI_BOOT_SERVICES *b=st->BootServices;EFI_PCI_IO_PROTOCOL *pci=NULL;
    VOID *path=NULL;EFI_STATUS r;
    if(!b->LocateHandleBuffer || !b->HandleProtocol || !b->FreePool)return EFI_UNSUPPORTED;
    s->Console=(UINTN)st->ConsoleOutHandle;s->ConsoleInterface=(UINTN)st->ConOut;
    if(!s->Console || !s->ConsoleInterface)return EFI_NOT_READY;
    r=b->HandleProtocol(intel,&pci_guid,(VOID **)&pci);if(r!=EFI_SUCCESS)return r;
    if(!pci || !pci->Pci.Read || !pci->GetLocation || !pci->Attributes)return EFI_UNSUPPORTED;
    s->PciInterface=(UINTN)pci;
    UINTN seg=0,bus=0,dev=0,fn=0;
    r=pci->GetLocation(pci,&seg,&bus,&dev,&fn);if(r!=EFI_SUCCESS)return r;
    if(seg || bus || dev!=2 || fn)return EFI_UNSUPPORTED;
    r=pci->Attributes(pci,EfiPciIoAttributeOperationGet,0,&s->Attributes);if(r!=EFI_SUCCESS)return r;
    r=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,16,s->Pci);if(r!=EFI_SUCCESS)return r;
    if(s->Pci[0]!=0x7d678086 || (s->Pci[2]>>8)!=0x030000 ||
       !(s->Pci[1]&2) || !(s->Attributes&EFI_PCI_IO_ATTRIBUTE_MEMORY))return EFI_NOT_READY;
    r=b->HandleProtocol(intel,&path_guid,&path);if(r!=EFI_SUCCESS)return r;
    r=copy_path(path,s->PciPath,&s->PciPathBytes);if(r!=EFI_SUCCESS)return r;
    EFI_HANDLE *handles=NULL;UINTN count=0;
    r=b->LocateHandleBuffer(ByProtocol,&gop_guid,NULL,&count,&handles);
    if(r!=EFI_SUCCESS)return r;
    if(!handles)return EFI_COMPROMISED_DATA;
    /* The READY hardware control has exactly one GOP on the Intel path. Do
     * not select an arbitrary first GOP if firmware topology changes. */
    if(count!=1){(void)b->FreePool(handles);return EFI_NOT_READY;}
    EFI_HANDLE h=handles[0];s->Handle=(UINTN)h;
    r=b->FreePool(handles);if(r!=EFI_SUCCESS)return r;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *g=NULL;
    r=b->HandleProtocol(h,&gop_guid,(VOID **)&g);if(r!=EFI_SUCCESS)return r;
    if(!g || !g->Mode || !g->Mode->Info || g->Mode->SizeOfInfo<sizeof(s->Info))return EFI_COMPROMISED_DATA;
    const EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *m=g->Mode;
    s->Interface=(UINTN)g;s->ModePointer=(UINTN)m;s->InfoPointer=(UINTN)m->Info;
    s->FrameBufferBase=m->FrameBufferBase;s->FrameBufferBytes=m->FrameBufferSize;
    s->InfoBytes=m->SizeOfInfo;s->Mode=m->Mode;s->MaxMode=m->MaxMode;s->Info=*m->Info;
    const EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *i=&s->Info;
    if(!s->MaxMode || s->Mode>=s->MaxMode || i->Version ||
       !i->HorizontalResolution || !i->VerticalResolution || i->PixelsPerScanLine<i->HorizontalResolution ||
       i->PixelFormat>PixelBitMask || !s->FrameBufferBase || !s->FrameBufferBytes ||
       s->FrameBufferBase>MAX_UINT64-s->FrameBufferBytes ||
       (UINT64)i->PixelsPerScanLine*i->VerticalResolution>s->FrameBufferBytes/4)return EFI_COMPROMISED_DATA;
    path=NULL;r=b->HandleProtocol(h,&path_guid,&path);if(r!=EFI_SUCCESS)return r;
    r=copy_path(path,s->Path,&s->PathBytes);if(r!=EFI_SUCCESS)return r;
    if(s->PathBytes<=s->PciPathBytes)return EFI_NOT_READY;
    for(UINTN n=0;n<s->PciPathBytes-4;n++)if(s->Path[n]!=s->PciPath[n])return EFI_NOT_READY;
    return EFI_SUCCESS;
}
static BOOLEAN changed(RTX_DISPLAY_GUARD *g,UINTN field,UINT64 a,UINT64 b){
    if(a==b)return FALSE;
    g->Difference=field;g->Before=a;g->After=b;return TRUE;
}
static EFI_STATUS compare(RTX_DISPLAY_GUARD *g,const RTX_DISPLAY_SNAPSHOT *b){
    const RTX_DISPLAY_SNAPSHOT *a=&g->Snapshots[0];
    /* Stable fields only: do not compare PCI status/BIST/interrupt status or
     * framebuffer contents. Field numbers are permanent RAM diagnostics. */
#define SAME(field,id) if(changed(g,id,a->field,b->field))return EFI_NOT_READY
    SAME(Handle,1);SAME(Interface,2);SAME(ModePointer,3);SAME(InfoPointer,4);
    SAME(Console,5);SAME(ConsoleInterface,6);SAME(FrameBufferBase,7);SAME(FrameBufferBytes,8);
    SAME(InfoBytes,9);SAME(Attributes,10);SAME(PciInterface,11);SAME(Mode,12);SAME(MaxMode,13);
    SAME(Info.Version,14);SAME(Info.HorizontalResolution,15);SAME(Info.VerticalResolution,16);
    SAME(Info.PixelFormat,17);SAME(Info.PixelsPerScanLine,18);
    SAME(Info.PixelInformation.RedMask,19);SAME(Info.PixelInformation.GreenMask,20);
    SAME(Info.PixelInformation.BlueMask,21);SAME(Info.PixelInformation.ReservedMask,22);
    SAME(PathBytes,23);SAME(PciPathBytes,24);
#undef SAME
    for(UINTN n=0;n<16;n++){
        UINT32 mask=(n==1)?0xffff:(n==0 || n==2 || (n>=4 && n<=9) || n==11 || n==12)?MAX_UINT32:0;
        if(changed(g,0x100+n*4,a->Pci[n]&mask,b->Pci[n]&mask))return EFI_NOT_READY;
    }
    for(UINTN n=0;n<a->PathBytes;n++)if(changed(g,0x200+n,a->Path[n],b->Path[n]))return EFI_NOT_READY;
    for(UINTN n=0;n<a->PciPathBytes;n++)if(changed(g,0x300+n,a->PciPath[n],b->PciPath[n]))return EFI_NOT_READY;
    return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxDisplayCheck(EFI_SYSTEM_TABLE *st,EFI_HANDLE intel,RTX_DISPLAY_GUARD *g,UINTN stage){
    if(!st || !st->BootServices || !intel || !g || stage>=4)return EFI_INVALID_PARAMETER;
    if(g->Snapshots[stage].Attempted || (stage && (!g->Snapshots[stage-1].Complete || g->Status!=EFI_SUCCESS)))return EFI_ALREADY_STARTED;
    g->Stage=stage;RTX_DISPLAY_SNAPSHOT *s=&g->Snapshots[stage];s->Attempted=TRUE;
    EFI_STATUS r=capture(st,intel,s);
    if(r==EFI_SUCCESS && stage)r=compare(g,s);
    if(r!=EFI_SUCCESS && !EFI_ERROR(r))r=EFI_DEVICE_ERROR;
    g->Status=s->Status=r;s->Complete=r==EFI_SUCCESS;return r;
}
