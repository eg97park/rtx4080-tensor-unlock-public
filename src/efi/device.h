/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_DEVICE_H
#define RTX4080_DEVICE_H
#include "lease.h"
#include "dma.h"
#include "recovery.h"
typedef enum {RtxReadyCheckNone,RtxReadyCheckPrerequisites,RtxReadyCheckOwner,
    RtxReadyCheckRecovery,RtxReadyCheckFeatures,RtxReadyCheckRestoredWpr,
    RtxReadyCheckComplete} RTX_READY_CHECK;
typedef struct {
    EFI_SYSTEM_TABLE *System;
    EFI_BOOT_SERVICES *Bs;
    RTX_LEASE *Lease;
    RTX_DMA_ARENA *Arena;
    RTX_OWNER_WORKSPACE *Workspace;
    RTX_OWNER_STATE OwnerCheck;
    RTX_RECOVERY_STATE Recovery;
    EFI_STATUS Fault, LastStatus;
    UINT32 LastOffset, LastValue, Saved[64];
    UINT16 Pcie, Pm, PcieVersion, SavedDevctl, SavedDevctl2;
    UINT64 InitialAttributes, Ticks;
    UINTN MmioWrites, ConfigWrites, AssertReads, ReleaseReads;
    UINT32 LastEngine;
    RTX_READY_CHECK ReadyCheck;
    UINT32 ReadyOffset, ReadyActual, ReadyExpected, ReadyMask;
    BOOLEAN MasterAttempted, MasterCleared, ClearAttempted, FlrAttempted,
        FlrComplete, ConfigUnavailable, ConfigRestored, AssertAttempted,
        AssertObserved, ReleaseAttempted, ReleaseObserved, ScrubObserved,
        Selector0Attempted, Selector1Attempted, Verified, Busy;
} RTX_DEVICE;
/* MUTATING component for a future approved frontend. Never linked into the
 * probe/READY. Init needs a held lease and fresh accepted board state; that is
 * a technical precondition, not user authorization or callback quiescence.
 * Exact EFI status, one FLR, no automatic retry. Every exposed DMA allocation
 * stays retained unless independent fresh ownership/recovery checks pass.
 */
EFI_STATUS EFIAPI RtxDeviceInit(RTX_DEVICE *,EFI_SYSTEM_TABLE *,RTX_LEASE *,RTX_DMA_ARENA *,RTX_OWNER_WORKSPACE *);
EFI_STATUS EFIAPI RtxDeviceRead(RTX_DEVICE *,UINT32,UINT32 *);
EFI_STATUS EFIAPI RtxDeviceWrite(RTX_DEVICE *,UINT32,UINT32);
EFI_STATUS EFIAPI RtxDeviceConfigRead(RTX_DEVICE *,UINT32,UINTN,VOID *);
EFI_STATUS EFIAPI RtxDeviceProm(RTX_DEVICE *,VOID *,UINTN);
EFI_STATUS EFIAPI RtxDeviceStall(RTX_DEVICE *,UINTN);
EFI_STATUS EFIAPI RtxDeviceEnableMaster(RTX_DEVICE *);
EFI_STATUS EFIAPI RtxDeviceClearMaster(RTX_DEVICE *);
EFI_STATUS EFIAPI RtxDeviceFlr(RTX_DEVICE *);
EFI_STATUS EFIAPI RtxDeviceRestore(RTX_DEVICE *);
EFI_STATUS EFIAPI RtxDeviceVerifyStop(VOID *,EFI_PCI_IO_PROTOCOL *);
/* Fresh post-cleanup check. Requires prior full recovery history and empty
 * DMA arena. Failure never undoes cleanup or permits a Windows handoff. */
EFI_STATUS EFIAPI RtxDeviceVerifyReadyToBoot(RTX_DEVICE *);
EFI_STATUS EFIAPI RtxDeviceLatch(RTX_DEVICE *,EFI_STATUS);
#endif
