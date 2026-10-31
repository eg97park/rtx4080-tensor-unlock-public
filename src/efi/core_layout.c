/* SPDX-License-Identifier: GPL-2.0-only
 * Compile the pinned pure calculator for UEFI without libc logging. Every
 * calculation/check and original negative errno result is preserved. The
 * caller receives core_result for its own UEFI log. This does not include
 * the Linux hardware adapter. Kept out of the capture-only EFI.
 */
#define GPU_UNLOCK_DIAGNOSTIC_H
#define GU_DIAG(result) (result)
#include "../../third_party/gpu-unlock-ada/kernel/gpu_unlock/layout_610.c"
