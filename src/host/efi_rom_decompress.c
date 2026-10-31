/* SPDX-License-Identifier: GPL-2.0-only
 * CPU-only wrapper around pinned EDK2's EfiDecompress. Input/output are data;
 * the decoded PE is NEVER loaded, linked or executed. The EDK2 implementation
 * remains in .local/references with its BSD-2-Clause-Patent notices intact.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "Decompress.h"

static unsigned char source[1024*1024+1];
int main(void)
{
    size_t n=fread(source,1,sizeof(source),stdin);
    assert(!ferror(stdin) && feof(stdin) && n>=8 && n<=1024*1024);
    UINT32 size=0,scratch_size=0;
    assert(EfiGetInfo(source,(UINT32)n,&size,&scratch_size)==EFI_SUCCESS);
    assert(size && size<=32*1024*1024 && scratch_size && scratch_size<=1024*1024);
    void *out=calloc(1,size),*scratch=calloc(1,scratch_size);
    assert(out && scratch);
    assert(EfiDecompress(source,(UINT32)n,out,size,scratch,scratch_size)==EFI_SUCCESS);
    assert(fwrite(out,1,size,stdout)==size);
    free(scratch);free(out);
    return 0;
}
