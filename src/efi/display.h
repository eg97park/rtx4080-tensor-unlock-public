/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_DISPLAY_H
#define RTX4080_DISPLAY_H
#include <Uefi.h>
#include <Protocol/PciIo.h>
#include <Protocol/GraphicsOutput.h>
/* This board's single Intel GOP. Session-local addresses are observations,
 * never cross-boot pins. No GOP methods or framebuffer/MMIO access. */
#define RTX_DISPLAY_PATH_MAX 256
typedef struct {
    UINT64 Handle, Interface, ModePointer, InfoPointer, Console, ConsoleInterface;
    UINT64 FrameBufferBase, FrameBufferBytes, InfoBytes, Attributes, PciInterface;
    UINT32 Mode, MaxMode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION Info;
    UINT32 Pci[16];
    UINT8 Path[RTX_DISPLAY_PATH_MAX], PciPath[RTX_DISPLAY_PATH_MAX];
    UINTN PathBytes, PciPathBytes;
    EFI_STATUS Status;
    BOOLEAN Attempted, Complete;
} RTX_DISPLAY_SNAPSHOT;
typedef struct {
    RTX_DISPLAY_SNAPSHOT Snapshots[4]; /* pre-Stop, post-lease, post-core, pre-start */
    UINTN Stage, Difference;
    UINT64 Before, After;
    EFI_STATUS Status;
} RTX_DISPLAY_GUARD;
/* Caller provides a zeroed guard. Capture each stage once, in order. Mismatch
 * fails closed without repair. After failure do not call again for diagnostics.
 * Get/PCI reads and handle enumeration only; GPU safety still needs its own
 * independent gate. Unchanged metadata does NOT prove Windows stability. */
EFI_STATUS EFIAPI RtxDisplayCheck(EFI_SYSTEM_TABLE *,EFI_HANDLE Intel,
    RTX_DISPLAY_GUARD *,UINTN Stage);
#endif
