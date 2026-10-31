/* SPDX-License-Identifier: GPL-2.0-only
 * Recovery observations follow pinned gpu-unlock-ada unlock_transaction_reset
 * and NVIDIA 610.43.03 ksec2ResetHw_TU102. No reset sequence is executed here.
 */
#include "recovery.h"
static EFI_STATUS read_reg(EFI_PCI_IO_PROTOCOL *pci,UINT32 off,UINT32 *value) {
    EFI_STATUS s=pci->Mem.Read(pci,EfiPciIoWidthUint32,0,off,1,value);
    if(s!=EFI_SUCCESS)return EFI_ERROR(s)?s:EFI_DEVICE_ERROR;
    if(*value==0xffffffffu || (*value&0xffff0000u)==0xbadf0000u)return EFI_DEVICE_ERROR;
    return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxBoardReadRecovery(EFI_BOOT_SERVICES *bs,EFI_PCI_IO_PROTOCOL *pci,
    const RTX_BOARD_STATE *entry,RTX_RECOVERY_STATE *out)
{
    if(!out)return EFI_INVALID_PARAMETER;
    out->ObservationsAccepted=FALSE;
    if(out->Board.UnreleasedBarResources)return EFI_ALREADY_STARTED;
    if(!entry || entry==&out->Board || !entry->ColdObservationsAccepted ||
       entry->LayoutResult!=RTX_LAYOUT_OK || entry->UnreleasedBarResources ||
       entry->RegistersRead!=RTX_BOARD_REGISTER_COUNT)return EFI_INVALID_PARAMETER;
    *out=(RTX_RECOVERY_STATE){0};
    EFI_STATUS s=RtxBoardReadState(bs,pci,entry->Layout.input.image_size,entry->Layout.input.boot_size,&out->Board);
    if(s!=EFI_SUCCESS)return s;
    /* BAR0 being usable is insufficient if another BAR was restored wrongly. */
    for(UINTN i=4;i<10;i++)if(out->Board.PciConfig[i]!=entry->PciConfig[i])return EFI_NOT_READY;
    if(out->Board.BarBase!=entry->BarBase || out->Board.BarBytes!=entry->BarBytes)return EFI_NOT_READY;
    /* This board uses SEC2 Falcon base 0x840000. ENGINE.RESET is bit 0;
     * HWCFG2.MEM_SCRUBBING is bit 12. Reset-held PRI errors are failures. */
    s=read_reg(pci,0x8403c0,&out->Sec2Engine);if(s!=EFI_SUCCESS)return s;
    if(out->Sec2Engine&1)return EFI_NOT_READY;
    s=read_reg(pci,0x8400f4,&out->Sec2Hwcfg2);if(s!=EFI_SUCCESS)return s;
    if(out->Sec2Hwcfg2&(1u<<12))return EFI_NOT_READY;
    UINT32 after[64];
    s=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,64,after);
    if(s!=EFI_SUCCESS)return EFI_ERROR(s)?s:EFI_DEVICE_ERROR;
    for(UINTN i=0;i<64;i++)if(after[i]!=out->Board.PciConfig[i])return EFI_NOT_READY;
    out->ObservationsAccepted=TRUE;return EFI_SUCCESS;
}
