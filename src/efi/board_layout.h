/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_BOARD_LAYOUT_H
#define RTX4080_BOARD_LAYOUT_H
#include "layout_610.h"

/* Register observations supplied by the future live PCI adapter. This pure
 * component neither reads hardware nor establishes ownership/cold state.
 * Never use values saved from an earlier boot for a live transaction.
 */
struct rtx4080_layout_registers {
    u32 fb_mb, vga, mmu_plm, mmu_lo, mmu_hi;
};
struct rtx4080_layout_plan {
    struct gpu_unlock_layout_in input;
    struct gpu_unlock_layout_out output;
    u64 mmu_high, mmu_top;
    int core_result;
};
enum rtx4080_layout_result {
    RTX_LAYOUT_OK, RTX_LAYOUT_INVALID_ARGUMENT, RTX_LAYOUT_BAD_REGISTER,
    RTX_LAYOUT_FB_RANGE, RTX_LAYOUT_VGA_RANGE, RTX_LAYOUT_CORE_REJECTED,
    RTX_LAYOUT_BELOW_SCRUBBED_TOP
};
/* Decode using the pinned unlock_transaction_layout rules, then call the same
 * unmodified reservation calculator. Additionally reject BADF sentinel words
 * in every input, including a non-top MMU lock ignored by the old decoder.
 * Output is diagnostic only on failure.
 * Valid layout is not FWSEC acceptance, DMA containment or boot permission.
 */
enum rtx4080_layout_result rtx4080_plan_layout(
    const struct rtx4080_layout_registers *registers,
    u64 image_size, u32 boot_size, struct rtx4080_layout_plan *plan);
#endif
