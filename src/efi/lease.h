/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_LEASE_H
#define RTX4080_LEASE_H
#include "owner.h"
#include "board.h"
#include <Protocol/PciIo.h>
typedef enum {
    RtxLeaseEmpty, RtxLeaseInspecting, RtxLeaseRejected, RtxLeaseStopping,
    RtxLeaseInstallingGuard, RtxLeaseClaiming, RtxLeaseHeld, RtxLeaseRetained,
    RtxLeaseEnablingMemory
} RTX_LEASE_PHASE;
typedef enum {RtxLeaseStepNone,RtxLeaseStepOwner,RtxLeaseStepApplication,
    RtxLeaseStepBoard,RtxLeaseStepCompare,RtxLeaseStepDisconnect,
    RtxLeaseStepAfterStop,RtxLeaseStepInstall,RtxLeaseStepClaim,
    RtxLeaseStepAfterClaim,RtxLeaseStepInterface,RtxLeaseStepHeldBoard,
    RtxLeaseStepHeldCompare,RtxLeaseStepDone,
    /* Append: preserve DIAG1 numeric values from physical photographs. */
    RtxLeaseStepStoppedBoard,RtxLeaseStepMemorySupported,RtxLeaseStepMemoryBefore,
    RtxLeaseStepMemoryFresh,RtxLeaseStepMemoryEnable,RtxLeaseStepMemoryAfter,
    RtxLeaseStepMemoryVerify,RtxLeaseStepMemoryOwner} RTX_LEASE_STEP;
typedef struct {
    RTX_LEASE_PHASE Phase;
    RTX_LEASE_STEP Step;
    UINT32 CompareOffset, CompareBefore, CompareAfter;
    EFI_STATUS Failure;
    EFI_HANDLE Application, Target;
    EFI_PCI_IO_PROTOCOL *Pci;
    EFI_DRIVER_BINDING_PROTOCOL Guard;
    RTX_OWNER_STATE Before, AfterStop, AfterClaim;
    RTX_BOARD_STATE PreStop, HeldBoard, StoppedBoard;
    BOOLEAN StopAttempted, GuardAttempted, ClaimAttempted;
    BOOLEAN MemoryEnableAttempted, MemoryEnabledVerified;
    UINT64 MemoryAttributesBefore, MemoryAttributesAfter;
} RTX_LEASE;
/* MUTATING UEFI operation, never linked into the read-only probe.
 * Future frontend must require explicit authorization for a target-driver
 * Stop experiment. Call once on a zeroed state at TPL_APPLICATION.
 * Keeps the original NVIDIA image resident, never calls Unload/Connect/reset.
 * Claim is BY_DRIVER, intentionally NOT EXCLUSIVE: competing claims fail
 * without OpenProtocol implicitly disconnecting an unreviewed owner.
 * This guard's Stop refuses all automatic disconnect requests.
 * If the owned device's decode was disabled by Stop, enables only MEMORY
 * through PCI I/O Attributes after config/resource/owner checks, and verifies
 * attributes AND raw PCI state before any MMIO. BME stays disabled. No direct
 * PCI writes, MMIO writes/DMA/firmware execution are implemented by this module,
 * but NVIDIA's own Stop may touch its GPU. Host tests mock that call.
 * After StopAttempted, parent application MUST remain resident through a
 * separately verified child Windows handoff or manual power off, even on
 * error. No blind reconnect, retry, cleanup or return to firmware is supplied.
 * Held establishes a driver-model claim, not full callback/hardware isolation.
 */
EFI_STATUS EFIAPI RtxLeaseAcquire(EFI_SYSTEM_TABLE *System, EFI_HANDLE Application,
    EFI_HANDLE Target, EFI_HANDLE Intel, const RTX_BOARD_STATE *Entry,
    RTX_OWNER_WORKSPACE *Workspace, RTX_LEASE *Lease);
BOOLEAN EFIAPI RtxLeaseMustRemainResident(const RTX_LEASE *Lease);
#endif
