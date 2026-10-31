/* SPDX-License-Identifier: GPL-2.0-only. RAM/PCI service mocks, no hardware. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "display.h"
#include <Protocol/DevicePath.h>
static EFI_GUID gg=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID,pg=EFI_PCI_IO_PROTOCOL_GUID,dg=EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_PCI_IO_PROTOCOL pci;
static EFI_GRAPHICS_OUTPUT_PROTOCOL gop;
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE mode;
static EFI_GRAPHICS_OUTPUT_MODE_INFORMATION info;
static EFI_BOOT_SERVICES bs;
static EFI_SYSTEM_TABLE st;
static UINT32 cfg[16];static UINT64 attrs;static UINTN count;
static unsigned calls,inject;static EFI_STATUS injected;
static UINT8 path[256],pci_path[256];
static const UINT8 observed[]={2,1,12,0,0xd0,0x41,3,0x0a,0,0,0,0,1,1,6,0,0,2,2,3,8,0,0x74,0x23,1,0x80,0x7f,0xff,4,0};
static EFI_STATUS status(void){return ++calls==inject?injected:EFI_SUCCESS;}
static EFI_STATUS EFIAPI loc(EFI_PCI_IO_PROTOCOL *p,UINTN *s,UINTN *b,UINTN *d,UINTN *f){assert(p==&pci);*s=*b=*f=0;*d=2;return status();}
static EFI_STATUS EFIAPI attr(EFI_PCI_IO_PROTOCOL *p,EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION op,UINT64 v,UINT64 *out){
    assert(p==&pci && op==EfiPciIoAttributeOperationGet && !v && out);*out=attrs;return status();}
static EFI_STATUS EFIAPI read_pci(EFI_PCI_IO_PROTOCOL *p,EFI_PCI_IO_PROTOCOL_WIDTH w,UINT32 off,UINTN n,VOID *out){
    assert(p==&pci && w==EfiPciIoWidthUint32 && !off && n==16);memcpy(out,cfg,sizeof(cfg));return status();}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h,EFI_GUID *g,VOID **out){
    if(h==(VOID *)1 && !memcmp(g,&pg,16))*out=&pci;
    else if(h==(VOID *)1 && !memcmp(g,&dg,16))*out=pci_path;
    else if(h==(VOID *)2 && !memcmp(g,&gg,16))*out=&gop;
    else if(h==(VOID *)2 && !memcmp(g,&dg,16))*out=path;
    else assert(!"unexpected handle/protocol");
    return status();
}
static EFI_STATUS EFIAPI locate(EFI_LOCATE_SEARCH_TYPE t,EFI_GUID *g,VOID *k,UINTN *n,EFI_HANDLE **out){
    assert(t==ByProtocol && !memcmp(g,&gg,16) && !k);EFI_STATUS r=status();
    if(r!=EFI_SUCCESS)return r;
    *n=count;*out=calloc(2,sizeof(**out));assert(*out);(*out)[0]=(VOID *)2;return r;
}
static EFI_STATUS EFIAPI release(VOID *p){assert(p);free(p);return status();}
static void reset(void){
    memset(path,0,sizeof(path));memcpy(path,observed,sizeof(observed));
    memset(pci_path,0,sizeof(pci_path));memcpy(pci_path,observed,18);memcpy(pci_path+18,observed+26,4);
    memset(cfg,0,sizeof(cfg));cfg[0]=0x7d678086;cfg[1]=7;cfg[2]=0x03000000;cfg[4]=0x70000004;
    attrs=0x700;count=1;calls=inject=0;injected=EFI_DEVICE_ERROR;
    info=(EFI_GRAPHICS_OUTPUT_MODE_INFORMATION){.HorizontalResolution=1920,.VerticalResolution=1080,
        .PixelFormat=PixelBlueGreenRedReserved8BitPerColor,.PixelsPerScanLine=1920};
    mode=(EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE){.MaxMode=6,.Mode=0,.Info=&info,.SizeOfInfo=sizeof(info),.FrameBufferBase=0x70800000,.FrameBufferSize=0x7e9000};
    gop=(EFI_GRAPHICS_OUTPUT_PROTOCOL){.Mode=&mode}; /* All GOP methods NULL: must not call. */
    pci=(EFI_PCI_IO_PROTOCOL){.Pci={.Read=read_pci},.GetLocation=loc,.Attributes=attr};
    bs=(EFI_BOOT_SERVICES){.HandleProtocol=handle,.LocateHandleBuffer=locate,.FreePool=release};
    st=(EFI_SYSTEM_TABLE){.BootServices=&bs,.ConsoleOutHandle=(VOID *)3,.ConOut=(VOID *)4};
}
static void mutate(unsigned n){
    switch(n){
    case 0:mode.FrameBufferBase+=0x1000;break;case 1:mode.FrameBufferSize+=0x1000;break;
    case 2:mode.Mode=1;break;case 3:mode.MaxMode++;break;case 4:info.HorizontalResolution-=8;break;
    case 5:info.VerticalResolution--;break;case 6:info.PixelsPerScanLine--;info.HorizontalResolution--;break;
    case 7:info.PixelFormat=PixelRedGreenBlueReserved8BitPerColor;break;case 8:info.PixelInformation.RedMask=1;break;
    case 9:attrs^=0x100;break;case 10:cfg[1]^=1;break;case 11:cfg[4]+=0x1000;break;
    case 12:cfg[5]++;break;case 13:cfg[11]++;break;case 14:cfg[12]=1;break;case 15:path[22]++;break;
    case 16:st.ConsoleOutHandle=(VOID *)5;break;case 17:st.ConOut=(VOID *)6;break;
    case 18:mode.SizeOfInfo++;break;case 19:cfg[2]++;break;
    default:assert(!"bad mutation");
    }
}
int main(void){
    unsigned cases=0;
    reset();RTX_DISPLAY_GUARD g={0};
    for(UINTN n=0;n<4;n++)assert(RtxDisplayCheck(&st,(VOID *)1,&g,n)==EFI_SUCCESS);
    assert(!g.Difference && g.Snapshots[3].Complete);unsigned per=calls/4;cases++;
    assert(RtxDisplayCheck(&st,(VOID *)1,&g,3)==EFI_ALREADY_STARTED);cases++;
    /* Inject all service failures, including warnings, at each observation.
     * Failure cannot be retried or followed by the next stage. */
    for(unsigned stage=0;stage<4;stage++)for(unsigned fail=1;fail<=per;fail++)for(unsigned kind=0;kind<2;kind++){
        reset();memset(&g,0,sizeof(g));
        for(unsigned n=0;n<stage;n++)assert(RtxDisplayCheck(&st,(VOID *)1,&g,n)==EFI_SUCCESS);
        inject=calls+fail;injected=kind?EFI_WARN_UNKNOWN_GLYPH:EFI_NOT_READY;
        assert(EFI_ERROR(RtxDisplayCheck(&st,(VOID *)1,&g,stage)) && !g.Snapshots[stage].Complete);
        unsigned before=calls;assert(RtxDisplayCheck(&st,(VOID *)1,&g,stage)==EFI_ALREADY_STARTED);
        if(stage<3)assert(RtxDisplayCheck(&st,(VOID *)1,&g,stage+1)==EFI_ALREADY_STARTED);
        assert(calls==before);cases++;
    }
    for(unsigned stage=1;stage<4;stage++)for(unsigned n=0;n<20;n++){
        reset();memset(&g,0,sizeof(g));
        for(unsigned i=0;i<stage;i++)assert(RtxDisplayCheck(&st,(VOID *)1,&g,i)==EFI_SUCCESS);
        mutate(n);assert(RtxDisplayCheck(&st,(VOID *)1,&g,stage)==EFI_NOT_READY && g.Difference);cases++;
    }
    for(unsigned n=0;n<13;n++){
        reset();memset(&g,0,sizeof(g));
        switch(n){
        case 0:count=0;break;case 1:count=2;break;case 2:gop.Mode=NULL;break;case 3:mode.Info=NULL;break;
        case 4:mode.SizeOfInfo--;break;case 5:mode.FrameBufferBase=MAX_UINT64-1;break;
        case 6:mode.FrameBufferSize=1;break;case 7:info.PixelFormat=PixelBltOnly;break;
        case 8:path[2]=0;break;case 9:path[27]=1;break;case 10:path[17]=3;break;
        case 11:cfg[0]++;break;case 12:cfg[1]&=~2u;break;
        }
        assert(EFI_ERROR(RtxDisplayCheck(&st,(VOID *)1,&g,0)));cases++;
    }
    reset();memset(&g,0,sizeof(g));assert(RtxDisplayCheck(&st,(VOID *)1,&g,0)==EFI_SUCCESS);
    cfg[1]|=0x80000000;cfg[3]^=0x80000000;cfg[15]++;
    assert(RtxDisplayCheck(&st,(VOID *)1,&g,1)==EFI_SUCCESS);cases++;
    printf("Intel display preservation: %u CPU cases PASS; GOP metadata from READY shape, PCI responses synthetic\n",cases);return 0;
}
