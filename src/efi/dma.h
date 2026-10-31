/* SPDX-License-Identifier: GPL-2.0-only
 * UEFI common-buffer ownership for the future AD103 transaction adapter.
 * This module is NOT linked into RTX4080-PROBE.efi.
 */
#ifndef RTX4080_DMA_H
#define RTX4080_DMA_H
#include <Uefi.h>
#include <Protocol/PciIo.h>

typedef enum {
    RtxDmaCold, RtxDmaDeviceMayAccess, RtxDmaCheckingStop,
    RtxDmaStopped, RtxDmaRetained
} RTX_DMA_PHASE;

typedef struct RTX_DMA_ARENA RTX_DMA_ARENA;
typedef struct RTX_DMA_BUFFER RTX_DMA_BUFFER;
struct RTX_DMA_BUFFER {
    RTX_DMA_ARENA *Owner;
    RTX_DMA_BUFFER *Next;
    VOID *Cpu;
    EFI_PHYSICAL_ADDRESS Device;
    VOID *Mapping;
    UINTN Bytes, Pages;
    BOOLEAN Mapped;
};
struct RTX_DMA_ARENA {
    EFI_PCI_IO_PROTOCOL *Pci;
    RTX_DMA_BUFFER *Head;
    UINTN Count;
    RTX_DMA_PHASE Phase;
    EFI_STATUS RetainReason;
};

/* The eventual board adapter must freshly verify identity, BME off, PCIe
 * pending clear, GFW/GSP/SEC2 stopped and WPR cleanup. No write/reset here.
 * device.c supplies a history-aware verifier; Host responses remain synthetic.
 * A success callback is a caller contract, not hardware evidence by itself.
 */
typedef EFI_STATUS (EFIAPI *RTX_DMA_VERIFY_STOP)(VOID *Context, EFI_PCI_IO_PROTOCOL *Pci);

/* The caller must already establish the reviewed PCI lease and cold, contained
 * hardware before allocating. Init does not inspect hardware or authorize DMA.
 * Caller owns zero-initialized arena/buffer records and keeps them alive until
 * their allocations are released. Never clear/reinitialize a retained record.
 * Allocate every buffer before exposing ANY address to GPU-visible metadata or
 * enabling device access. Exposure is irreversible without verified containment.
 */
EFI_STATUS EFIAPI RtxDmaInit(RTX_DMA_ARENA *Arena, EFI_PCI_IO_PROTOCOL *Pci);
EFI_STATUS EFIAPI RtxDmaAllocate(RTX_DMA_ARENA *Arena, RTX_DMA_BUFFER *Buffer, UINTN Bytes);
EFI_STATUS EFIAPI RtxDmaExpose(RTX_DMA_ARENA *Arena);
EFI_STATUS EFIAPI RtxDmaConfirmStopped(RTX_DMA_ARENA *Arena, RTX_DMA_VERIFY_STOP Verify, VOID *Context);
EFI_STATUS EFIAPI RtxDmaRelease(RTX_DMA_ARENA *Arena, RTX_DMA_BUFFER *Buffer);
EFI_STATUS EFIAPI RtxDmaReleaseAll(RTX_DMA_ARENA *Arena);
/* Resource accounting only; never means unlock success or Windows may boot. */
BOOLEAN EFIAPI RtxDmaIsEmpty(const RTX_DMA_ARENA *Arena);
#endif
