/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_OWNER_H
#define RTX4080_OWNER_H
#include <Uefi.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/LoadedImage.h>

#define RTX_OWNER_MAX_HANDLES 4096
#define RTX_OWNER_MAX_OPENS 16384
typedef struct {
    EFI_HANDLE Handle, Image;
    EFI_DRIVER_BINDING_PROTOCOL *Binding;
    UINT32 Flags, Indegree;
    BOOLEAN IntelReachable;
} RTX_OWNER_NODE;
typedef struct {
    UINTN Node;
    EFI_GUID Protocol;
    EFI_OPEN_PROTOCOL_INFORMATION_ENTRY Entry;
} RTX_OWNER_OPEN;
/* Caller-owned heap workspace, never put this on the firmware stack. */
typedef struct {
    RTX_OWNER_NODE Nodes[RTX_OWNER_MAX_HANDLES];
    RTX_OWNER_OPEN Opens[RTX_OWNER_MAX_OPENS];
    UINTN Queue[RTX_OWNER_MAX_HANDLES], NodeCount, OpenCount;
} RTX_OWNER_WORKSPACE;
typedef struct {
    EFI_HANDLE Driver, Image, Target, Intel, Console;
    VOID *ConsoleInterface;
    UINTN ImageBase;
    /* Preserve on any failure. No retry/cleanup after an ambiguous EFI result.
     * These are diagnostic pool references, NEVER device DMA allocations. */
    VOID *Unreleased[3];
    BOOLEAN CodeIdentityMatched, OpaqueBindingReferenceObserved;
    BOOLEAN IntelPathObserved, InspectionComplete;
    BOOLEAN TargetDriverGone, LeaseObserved;
} RTX_OWNER_STATE;

/* Read-only handle database and PCI identity inspection. No OpenProtocol,
 * Disconnect/ConnectController, UnloadImage, callback, DMA or GPU writes.
 * State must be zero-initialized initially and not reused with retained pools.
 * Target/Intel are freshly enumerated handles, not addresses from old logs.
 * Success describes a sequential snapshot, NOT exclusive ownership, safe
 * Stop/Unload, callback quiescence, console preservation or permission to run.
 * A later mutation requires its own fresh gate and explicit execution approval.
 */
EFI_STATUS EFIAPI RtxOwnerInspect(EFI_SYSTEM_TABLE *System,
    EFI_HANDLE Target, EFI_HANDLE Intel, RTX_OWNER_WORKSPACE *Workspace,
    RTX_OWNER_STATE *State);
/* After a separately authorized Stop, require the old image to remain loaded,
 * its private target protocol to be absent, and Intel's path to remain.
 * LeaseAgent NULL: require no target driver owner. Non-NULL: require exactly
 * that guard's BY_DRIVER claim. This never disconnects or claims a device.
 */
EFI_STATUS EFIAPI RtxOwnerInspectAfterStop(EFI_SYSTEM_TABLE *System,
    const RTX_OWNER_STATE *BeforeStop, EFI_HANDLE LeaseAgent,
    RTX_OWNER_WORKSPACE *Workspace, RTX_OWNER_STATE *State);
#endif
