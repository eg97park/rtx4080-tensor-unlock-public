/* SPDX-License-Identifier: GPL-2.0-only
 * Independent cross-check using the unchanged upstream C FWSEC parser.
 * Input is one normalized PCI image chain on stdin, never a device path.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vbios_610.h"
int main(void) {
    const size_t limit = 1024 * 1024;
    unsigned char *data = malloc(limit + 1);
    if (!data) return 2;
    size_t count = fread(data, 1, limit + 1, stdin);
    if (ferror(stdin) || count > limit) { free(data); return 2; }
    struct gpu_unlock_fwsec fw;
    int result = gpu_unlock_vbios_fwsec(data, count, &fw);
    free(data);
    if (result) { fprintf(stderr, "parser refused: %d\n", result); return 1; }
    printf("{\"image_off\":%u,\"image_size\":%u,\"imem_size\":%u,\"dmem_size\":%u,"
           "\"ucode_id\":%u,\"engine_mask\":%u,\"sig_count\":%u,\"sig_versions\":%u,"
           "\"pkc_off\":%u,\"interface_off\":%u,\"sig_off\":%u,\"sig_bytes\":%u}\n",
           fw.image_off, fw.image_size, fw.imem_size, fw.dmem_size, fw.ucode_id,
           fw.engine_mask, fw.sig_count, fw.sig_versions, fw.pkc_off, fw.interface_off,
           fw.sig_off, fw.sig_bytes);
    return 0;
}
