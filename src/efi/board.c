/* SPDX-License-Identifier: GPL-2.0-only */
#include "board.h"
#include <IndustryStandard/Acpi.h>

static const UINT32 offsets[RTX_BOARD_REGISTER_COUNT] = {
    0,0x118128,0x118234,0x110100,0x1fa824,0x1fa828,
    0x1183a4,0x625f04,0x1fa7c8,0x1fa82c,0x1fa830,
    0x1fa7cc,0x9a0148,0x1fa7c4,0x823804,0x823814,
    0x823818,0x82381c,0x823820,0x824148,0x8241c8,0x8241e0
};
static UINT16 word(const UINT8 *b, UINTN off) {
    return (UINT16)(b[off] | (UINT16)b[off+1]<<8);
}
static UINT32 dword(const UINT8 *b, UINTN off) {
    return (UINT32)b[off] | (UINT32)b[off+1]<<8 |
           (UINT32)b[off+2]<<16 | (UINT32)b[off+3]<<24;
}
static EFI_STATUS exact(EFI_STATUS s) {
    return EFI_ERROR(s) ? s : EFI_DEVICE_ERROR;
}
static EFI_STATUS validate_config(const UINT32 *config,BOOLEAN require_memory) {
    const UINT8 *b=(const UINT8 *)config;
    if(config[0]!=0x270410de || config[11]!=0x15007377)
        return EFI_SECURITY_VIOLATION;
    if((config[2]&0xffffff00u)!=0x03000000 || (b[0x0e]&0x7f) ||
       (config[4]&15)) return EFI_UNSUPPORTED;
    UINT16 command=word(b,4);
    if((command&4) || (require_memory && !(command&2))) return EFI_NOT_READY;
    /* Only the observed stopped state (0), or MEM already enabled (2/3).
     * This exception is for config/resource inspection, NEVER BAR MMIO. */
    if(!require_memory && command!=0 && command!=2 && command!=3)return EFI_NOT_READY;
    if(!(word(b,6)&0x10)) return EFI_UNSUPPORTED;
    BOOLEAN seen[64]={0},kinds[256]={0};
    UINTN pm=0,pcie=0,pos=b[0x34];
    while(pos) {
        if(pos<0x40 || pos>0xfc || (pos&3) || seen[pos/4] || kinds[b[pos]])
            return EFI_COMPROMISED_DATA;
        seen[pos/4]=TRUE;kinds[b[pos]]=TRUE;
        if(b[pos]==1)pm=pos;
        if(b[pos]==0x10)pcie=pos;
        pos=b[pos+1];
    }
    if(!pm || !pcie) return EFI_UNSUPPORTED;
    if(pm+6>256 || pcie+12>256) return EFI_COMPROMISED_DATA;
    if((word(b,pm+4)&3) || (word(b,pcie+10)&0x20)) return EFI_NOT_READY;
    if(!(dword(b,pcie+4)&(1u<<28))) return EFI_UNSUPPORTED;
    return EFI_SUCCESS;
}
static UINT32 reg(const RTX_BOARD_STATE *s,UINT32 off) {
    for(UINTN i=0;i<s->RegistersRead;i++)
        if(s->Registers[i].Offset==off)return s->Registers[i].Value;
    return 0xffffffffu;
}
static UINT32 version(UINT32 raw) {
    UINT32 n=0;raw&=0xffff;
    while(raw){n++;raw>>=1;}
    return n;
}
static EFI_STATUS read_pci_state(EFI_BOOT_SERVICES *bs,
    EFI_PCI_IO_PROTOCOL *pci,RTX_BOARD_STATE *out,BOOLEAN require_memory)
{
    if(!out) return EFI_INVALID_PARAMETER;
    out->ColdObservationsAccepted=FALSE;
    /* Records with unresolved resources must not be silently reused. */
    if(out->UnreleasedBarResources) return EFI_ALREADY_STARTED;
    *out=(RTX_BOARD_STATE){0};
    out->LayoutResult=RTX_LAYOUT_INVALID_ARGUMENT;
    if(!bs || !bs->FreePool || !pci || !pci->GetLocation || !pci->GetBarAttributes ||
       !pci->Pci.Read)
        return EFI_INVALID_PARAMETER;
    out->Check=RtxBoardCheckLocation;
    EFI_STATUS s=pci->GetLocation(pci,&out->Segment,&out->Bus,&out->Device,&out->Function);
    if(s!=EFI_SUCCESS) return exact(s);
    /* Board's observed PCI function. An enumeration change needs review. */
    if(out->Segment || out->Bus!=2 || out->Device || out->Function)
        return EFI_SECURITY_VIOLATION;
    out->Check=RtxBoardCheckPciRead;
    s=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,64,out->PciConfig);
    if(s!=EFI_SUCCESS) return exact(s);
    out->Check=RtxBoardCheckConfig;s=validate_config(out->PciConfig,require_memory);
    if(s!=EFI_SUCCESS) return s;
    VOID *resources=NULL;
    out->Check=RtxBoardCheckBarRead;
    s=pci->GetBarAttributes(pci,0,NULL,&resources);
    /* Failed/ambiguous providers do not establish ownership of their output. */
    if(s!=EFI_SUCCESS) {
        out->UnreleasedBarResources=resources;
        return exact(s);
    }
    if(!resources) return EFI_DEVICE_ERROR;
    out->UnreleasedBarResources=resources;
    EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *bar=resources;
    BOOLEAN valid=bar->Desc==ACPI_ADDRESS_SPACE_DESCRIPTOR &&
        bar->Len==sizeof(*bar)-3 && bar->ResType==0;
    if(valid) {
        out->BarBase=bar->AddrRangeMin;out->BarBytes=bar->AddrLen;
        valid=out->BarBase && !(out->BarBase&4095) && out->BarBytes>=0x9a014c &&
            out->BarBytes-1<=MAX_UINT64-out->BarBase && !bar->AddrTranslationOffset &&
            out->BarBase==(out->PciConfig[4]&0xfffffff0u);
    }
    out->Check=RtxBoardCheckBarFree;s=bs->FreePool(resources);
    if(s!=EFI_SUCCESS) return exact(s);
    out->UnreleasedBarResources=NULL;
    out->Check=RtxBoardCheckBarValidate;
    if(!valid) return EFI_UNSUPPORTED;
    return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxBoardReadPciState(EFI_BOOT_SERVICES *bs,
    EFI_PCI_IO_PROTOCOL *pci,RTX_BOARD_STATE *out)
{
    return read_pci_state(bs,pci,out,FALSE);
}
EFI_STATUS EFIAPI RtxBoardReadState(EFI_BOOT_SERVICES *bs,
    EFI_PCI_IO_PROTOCOL *pci,UINT64 image_size,UINT32 boot_size,RTX_BOARD_STATE *out)
{
    if(!out)return EFI_INVALID_PARAMETER;
    out->ColdObservationsAccepted=FALSE;
    if(out->UnreleasedBarResources)return EFI_ALREADY_STARTED;
    if(!pci || !pci->Mem.Read || !image_size || !boot_size){
        *out=(RTX_BOARD_STATE){0};out->LayoutResult=RTX_LAYOUT_INVALID_ARGUMENT;
        return EFI_INVALID_PARAMETER;
    }
    EFI_STATUS s=read_pci_state(bs,pci,out,TRUE);
    if(s!=EFI_SUCCESS)return s;
    for(UINTN i=0;i<RTX_BOARD_REGISTER_COUNT;i++) {
        UINT32 value=0;
        out->Check=RtxBoardCheckRegisters;out->LastReadOffset=offsets[i];
        s=pci->Mem.Read(pci,EfiPciIoWidthUint32,0,offsets[i],1,&value);
        if(s!=EFI_SUCCESS) return exact(s);
        out->Registers[i]=(RTX_BOARD_REGISTER){offsets[i],value};out->RegistersRead++;
        BOOLEAN permission=offsets[i]==0x1fa7cc || offsets[i]==0x9a0148 ||
                           offsets[i]==0x1fa7c4 || offsets[i]==0x823804;
        if((value&0xffff0000u)==0xbadf0000u || (value==0xffffffffu && !permission))
            return EFI_DEVICE_ERROR;
        if(!i && value!=0x193000a1) return EFI_SECURITY_VIOLATION;
        /* The GFW scratch register follows this PLM. Do not attempt the
         * protected scratch read when level 0 access has not been established. */
        if(offsets[i]==0x118128 && !(value&1))return EFI_NOT_READY;
    }
    out->Check=RtxBoardCheckCold;
    if(!(reg(out,0x118128)&1) || (reg(out,0x118234)&255)!=255 ||
       !(reg(out,0x110100)&0x10) || (reg(out,0x1fa828)>>4)) return EFI_NOT_READY;
    out->BooterFuseVersion=version(reg(out,0x824148));
    out->FwsecFuseVersion=version(reg(out,0x8241e0));
    out->Check=RtxBoardCheckFuses;
    if(out->BooterFuseVersion>1 || out->FwsecFuseVersion>1) return EFI_UNSUPPORTED;
    struct rtx4080_layout_registers r={reg(out,0x1183a4),reg(out,0x625f04),
        reg(out,0x1fa7c8),reg(out,0x1fa82c),reg(out,0x1fa830)};
    out->Check=RtxBoardCheckLayout;
    out->LayoutResult=rtx4080_plan_layout(&r,image_size,boot_size,&out->Layout);
    if(out->LayoutResult!=RTX_LAYOUT_OK) return EFI_UNSUPPORTED;
    UINT32 after[64];
    out->Check=RtxBoardCheckPciReread;
    s=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,64,after);
    if(s!=EFI_SUCCESS) return exact(s);
    /* Abort on ANY observed PCI change; no automatic retry or normalization. */
    out->Check=RtxBoardCheckCompare;
    for(UINTN i=0;i<64;i++)if(after[i]!=out->PciConfig[i]){
        out->CompareOffset=(UINT32)i*4;out->CompareAfter=after[i];return EFI_NOT_READY;
    }
    out->Check=RtxBoardCheckComplete;
    out->ColdObservationsAccepted=TRUE;
    return EFI_SUCCESS;
}
