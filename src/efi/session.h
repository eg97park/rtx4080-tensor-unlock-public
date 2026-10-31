/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_SESSION_H
#define RTX4080_SESSION_H
#include "core_bridge.h"
#include "handoff.h"
#include "display.h"
typedef enum {RtxSessionCold,RtxSessionAssets,RtxSessionBootPrepared,RtxSessionBootLoaded,
    RtxSessionLease,RtxSessionCore,RtxSessionFinalCheck,RtxSessionStarting} RTX_SESSION_PHASE;
/* RAM-only attempted operation. Phase remains the last completed milestone.
 * Keep numeric values stable for photographed diagnostics. No service calls. */
typedef enum {RtxStepNone,RtxStepAssets,RtxStepBootPrepare,RtxStepBootLoad,
    RtxStepPreStopJournal,RtxStepPciHandle,RtxStepEntryBoard,RtxStepLease,
    RtxStepDmaInit,RtxStepDeviceInit,RtxStepCore,RtxStepCorePostcondition,
    RtxStepVerify,RtxStepFinalJournal,RtxStepReverify,RtxStepWindowsStart,
    RtxStepDisplayBefore,RtxStepDisplayLease,RtxStepDisplayCore,RtxStepDisplayStart} RTX_SESSION_STEP;
typedef struct RTX_SESSION RTX_SESSION;
typedef EFI_STATUS (EFIAPI *RTX_SESSION_JOURNAL)(VOID *,const RTX_SESSION *);
struct RTX_SESSION {
    RTX_HANDOFF Handoff;
    RTX_BOARD_STATE Entry;
    RTX_LEASE Lease;
    RTX_DMA_ARENA Arena;
    RTX_DEVICE Device;
    RTX_CORE Core;
    RTX_DISPLAY_GUARD Display;
    RTX_SESSION_PHASE Phase;
    RTX_SESSION_STEP Step;
    EFI_STATUS Failure;
    BOOLEAN Attempted, MustRemainResident, StartAttempted;
    RTX_SESSION_JOURNAL Journal;
    VOID *JournalContext;
};
/* Heap-only zeroed context, immutable preloaded assets, verified target/Intel
 * handles and a reviewed boot pin. FUTURE explicit user-approved frontend only.
 * This is not a runnable EFI, permission prompt, USB token or terminal UI.
 * Preload Windows before Stop. No automatic reconnect/unload/reset/retry.
 * If MustRemainResident, caller MUST NOT return/unload, reboot or start another
 * image; remain resident for manual power off. Even EFI_SUCCESS from a returning
 * StartImage is failure. This function never reports Windows boot success.
 */
EFI_STATUS EFIAPI RtxSessionRunApproved(RTX_SESSION *,EFI_SYSTEM_TABLE *,EFI_HANDLE,
    EFI_HANDLE,EFI_HANDLE,RTX_OWNER_WORKSPACE *,const RTX_CORE_ASSET [5],const RTX_BOOT_PIN *);
#endif
