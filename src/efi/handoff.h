/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_HANDOFF_H
#define RTX4080_HANDOFF_H
#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
typedef struct {
    const UINT8 *EspPath;
    UINTN EspPathBytes;
    UINT8 FileSha256[32];
} RTX_BOOT_PIN;
typedef struct {
    EFI_HANDLE Volume, Child;
    EFI_HANDLE *Handles;
    EFI_FILE_PROTOCOL *Root, *File;
    VOID *Bytes;
    EFI_DEVICE_PATH_PROTOCOL *Path;
    UINTN Size;
    UINT8 VerifiedHash[32];
    EFI_STATUS Failure;
    BOOLEAN Attempted, Verified, LoadAttempted, Loaded, StartAttempted;
} RTX_HANDOFF;
/* Read the one exact, independently matched ESP path. Read-only file opens;
 * no ESP/BCD edits, LoadOptions, BootNext, reset or reconnect. No cleanup or
 * retry on ambiguous service failure: outputs remain available for diagnosis.
 * Pin/device identifiers stay in private generated input, never source Git.
 * Prepare does NOT execute a boot image. Load and Start require a separately
 * approved hardware handoff frontend. Not sufficient after GPU mutation.
 */
EFI_STATUS EFIAPI RtxHandoffPrepare(EFI_BOOT_SERVICES *Bs,const RTX_BOOT_PIN *Pin,RTX_HANDOFF *State);
EFI_STATUS EFIAPI RtxHandoffLoad(EFI_BOOT_SERVICES *Bs,EFI_HANDLE Parent,RTX_HANDOFF *State);
EFI_STATUS EFIAPI RtxHandoffStart(EFI_BOOT_SERVICES *Bs,RTX_HANDOFF *State);
#endif
