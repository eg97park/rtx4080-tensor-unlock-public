/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_RECOVERY_H
#define RTX4080_RECOVERY_H
#include "board.h"
typedef struct {
    RTX_BOARD_STATE Board;
    UINT32 Sec2Engine, Sec2Hwcfg2;
    BOOLEAN ObservationsAccepted;
} RTX_RECOVERY_STATE;
/* Read-only post-recovery observations, not a reset implementation.
 * State is initially zeroed; Entry is the saved accepted pre-transaction
 * snapshot of this same PCI function. Preserve any retained pool on failure.
 * Caller must FIRST have established exclusive ownership, completed FLR and
 * SEC2 reset assertion/release/propagation with no intervening CPU start.
 * This function cannot prove that history from register values.
 *
 * No polling/retry, DMA release, Windows handoff, device writes or reset.
 * Success does not assess selector/unlock success. It is only one prerequisite
 * of a future production DMA stop verifier, which remains unimplemented.
 */
EFI_STATUS EFIAPI RtxBoardReadRecovery(EFI_BOOT_SERVICES *Services,
    EFI_PCI_IO_PROTOCOL *Pci, const RTX_BOARD_STATE *Entry, RTX_RECOVERY_STATE *State);
#endif
