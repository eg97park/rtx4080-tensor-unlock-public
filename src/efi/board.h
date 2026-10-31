/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_BOARD_H
#define RTX4080_BOARD_H
#include <Uefi.h>
#include <Protocol/PciIo.h>
#include "board_layout.h"

#define RTX_BOARD_REGISTER_COUNT 22
typedef struct {
    UINT32 Offset, Value;
} RTX_BOARD_REGISTER;
typedef enum {RtxBoardCheckNone,RtxBoardCheckLocation,RtxBoardCheckPciRead,
    RtxBoardCheckConfig,RtxBoardCheckBarRead,RtxBoardCheckBarFree,
    RtxBoardCheckBarValidate,RtxBoardCheckRegisters,RtxBoardCheckCold,
    RtxBoardCheckFuses,RtxBoardCheckLayout,RtxBoardCheckPciReread,
    RtxBoardCheckCompare,RtxBoardCheckComplete} RTX_BOARD_CHECK;
typedef struct {
    RTX_BOARD_CHECK Check;
    UINT32 LastReadOffset, CompareOffset, CompareAfter;
    UINT32 PciConfig[64];
    UINTN Segment, Bus, Device, Function;
    UINT64 BarBase, BarBytes;
    RTX_BOARD_REGISTER Registers[RTX_BOARD_REGISTER_COUNT];
    UINTN RegistersRead;
    UINT32 BooterFuseVersion, FwsecFuseVersion;
    struct rtx4080_layout_plan Layout;
    enum rtx4080_layout_result LayoutResult;
    VOID *UnreleasedBarResources;
    BOOLEAN ColdObservationsAccepted;
} RTX_BOARD_STATE;

/* Fresh read-only preflight for this board. No command-bit/attribute writes,
 * DMA, detach, firmware execution or reset. No persistent/session handle pins.
 * State must be zero-initialized before first use. Geometry must come from
 * independently hash-verified firmware assets. This board's reviewed BAR0 is
 * 32-bit, non-prefetchable memory with no address translation. BDF is a
 * reviewed board policy, not an invariant of all RTX 4080 installations.
 * Output is diagnostic on failure. A successful sequential snapshot is NOT
 * exclusive ownership, a hardware stop proof, or permission to start firmware.
 * Caller must preserve ambiguous pool resources and stop if this fails.
 */
EFI_STATUS EFIAPI RtxBoardReadState(EFI_BOOT_SERVICES *Services,
    EFI_PCI_IO_PROTOCOL *Pci, UINT64 GspImageSize, UINT32 BootSize,
    RTX_BOARD_STATE *State);
/* Configuration/resource inspection only; NEVER MMIO or writes. Accepts the
 * observed post-Stop Command=0 in addition to 2/3, still requires D0, BME off,
 * no transaction pending, reviewed identity/capabilities/BAR resource. Does
 * not set ColdObservationsAccepted. Used by the owned lease before MEM enable;
 * cannot replace the strict RtxBoardReadState preflight. */
EFI_STATUS EFIAPI RtxBoardReadPciState(EFI_BOOT_SERVICES *Services,
    EFI_PCI_IO_PROTOCOL *Pci,RTX_BOARD_STATE *State);
#endif
