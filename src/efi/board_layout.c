/* SPDX-License-Identifier: GPL-2.0-only
 * Public adaptation reviewed/updated 2026-10-31.
 * Register decoding adapted from gpu-unlock-ada unlock_610.c
 * (d28c485418c3d9d034cd4bac19200bc33dd3453b). Copyright notices in
 * third_party/gpu-unlock-ada are retained. No device or firmware operations.
 */
#include "board_layout.h"

static bool inaccessible(u32 value)
{
    return value == 0xffffffffu || (value & 0xffff0000u) == 0xbadf0000u;
}

enum rtx4080_layout_result rtx4080_plan_layout(
    const struct rtx4080_layout_registers *r,
    u64 image_size, u32 boot_size, struct rtx4080_layout_plan *p)
{
    if (!p) return RTX_LAYOUT_INVALID_ARGUMENT;
    *p = (struct rtx4080_layout_plan){0};
    if (!r || !image_size || !boot_size) return RTX_LAYOUT_INVALID_ARGUMENT;
    if (!r->fb_mb || inaccessible(r->fb_mb) || inaccessible(r->vga) ||
        inaccessible(r->mmu_plm) || !(r->mmu_plm & 1) ||
        inaccessible(r->mmu_lo) || inaccessible(r->mmu_hi))
        return RTX_LAYOUT_BAD_REGISTER;
    struct gpu_unlock_layout_in *in = &p->input;
    in->usable_fb = (u64)r->fb_mb << 20;
    if (in->usable_fb < (256ull << 20)) return RTX_LAYOUT_FB_RANGE;
    in->vga_base = in->usable_fb - (1ull << 20);
    if (r->vga & 8) {
        in->vga_base = (u64)(r->vga >> 8) << 16;
        if (in->vga_base < in->usable_fb - (1ull << 20))
            in->vga_base = in->usable_fb - 0x20000;
    }
    if (in->vga_base >= in->usable_fb) return RTX_LAYOUT_VGA_RANGE;
    in->mmu_lock_low = (u64)(r->mmu_lo >> 4) << 12;
    p->mmu_high = (u64)(r->mmu_hi >> 4) << 12;
    /* A 28-bit VAL shifted by 12 cannot overflow the following addition. */
    p->mmu_top = (p->mmu_high + 0xffffull) & ~0xffffull;
    in->mmu_lock_valid = p->mmu_high >= in->mmu_lock_low &&
        (p->mmu_top >> 20) == (in->usable_fb >> 20);
    in->frts_size = in->nonwpr_size = 1ull << 20;
    in->heap_request = 88ull << 20;
    in->image_size = image_size;
    in->boot_size = boot_size;
    p->core_result = gpu_unlock_layout(in, &p->output);
    if (p->core_result) return RTX_LAYOUT_CORE_REJECTED;
    if (p->output.nonwpr_start < in->usable_fb - (256ull << 20))
        return RTX_LAYOUT_BELOW_SCRUBBED_TOP;
    return RTX_LAYOUT_OK;
}
