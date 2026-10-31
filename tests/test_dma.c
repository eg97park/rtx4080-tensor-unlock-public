/* SPDX-License-Identifier: GPL-2.0-only
 * CPU-only EFI mocks. All PCI/MMIO write/reset callbacks remain NULL.
 * Test teardown frees retained HOST allocations, never device-owned memory.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "dma.h"

enum { NORMAL, NULL_TOKEN, ALLOC_FAIL, ALLOC_NULL, ALLOC_UNALIGNED, MAP_FAIL,
       MAP_FAIL_TOKEN, MAP_WARNING, PARTIAL, DMA_ZERO, DMA_UNALIGNED, DMA_HIGH,
       DMA_CROSS_4G, UNMAP_FAIL, FREE_FAIL, VERIFY_FAIL, FLUSH_FAIL, VERIFY_REENTER };
static int mode, allocate_calls, map_calls, unmap_calls, free_calls, verify_calls, flush_calls;
static int unmap_fault,free_fault,flush_reenter;
static EFI_PCI_IO_PROTOCOL pci;
static RTX_DMA_ARENA arena;
static RTX_DMA_BUFFER buffers[3];
static VOID *host_allocations[8];
static UINTN host_pages[8];
static char order[128];
static unsigned order_length;

static VOID event(char c) { assert(order_length < sizeof(order)-1); order[order_length++] = c; }
static EFI_STATUS EFIAPI allocate(EFI_PCI_IO_PROTOCOL *p, EFI_ALLOCATE_TYPE type,
        EFI_MEMORY_TYPE memory, UINTN pages, VOID **cpu, UINT64 attributes) {
    assert(p == &pci && type == AllocateAnyPages && memory == EfiBootServicesData && !attributes);
    ++allocate_calls; event('A');
    if (mode == ALLOC_FAIL) return EFI_OUT_OF_RESOURCES;
    if (mode == ALLOC_NULL) return EFI_SUCCESS;
    unsigned i = (unsigned)allocate_calls-1; assert(i < 8);
    host_allocations[i] = aligned_alloc(4096, pages*4096); assert(host_allocations[i]);
    host_pages[i] = pages; memset(host_allocations[i], 0xa5, pages*4096);
    *cpu = (UINT8 *)host_allocations[i] + (mode == ALLOC_UNALIGNED ? 8 : 0);
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI map(EFI_PCI_IO_PROTOCOL *p, EFI_PCI_IO_PROTOCOL_OPERATION operation,
        VOID *cpu, UINTN *bytes, EFI_PHYSICAL_ADDRESS *address, VOID **token) {
    assert(p == &pci && operation == EfiPciIoOperationBusMasterCommonBuffer && cpu && !(*bytes&4095));
    for (UINTN i=0;i<*bytes;++i) assert(((UINT8 *)cpu)[i] == 0);
    ++map_calls; event('M');
    if (mode == MAP_FAIL) return EFI_UNSUPPORTED;
    *address = 0x200000 + (UINTN)map_calls * 0x20000;
    *token = mode == NULL_TOKEN ? NULL : (VOID *)(UINTN)map_calls;
    if (mode == MAP_FAIL_TOKEN) return EFI_DEVICE_ERROR;
    if (mode == MAP_WARNING) return EFI_WARN_UNKNOWN_GLYPH;
    if (mode == PARTIAL) *bytes -= 4096;
    if (mode == DMA_ZERO) *address = 0;
    if (mode == DMA_UNALIGNED) *address += 8;
    if (mode == DMA_HIGH) *address = 0x100000000ULL;
    if (mode == DMA_CROSS_4G) *address = 0xfffff000;
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI unmap(EFI_PCI_IO_PROTOCOL *p, VOID *token) {
    assert(p == &pci); assert(token || mode == NULL_TOKEN); ++unmap_calls; event('U');
    return mode == UNMAP_FAIL || unmap_fault ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS EFIAPI free_buffer(EFI_PCI_IO_PROTOCOL *p, UINTN pages, VOID *cpu) {
    assert(p == &pci); ++free_calls; event('D');
    if (mode == FREE_FAIL || free_fault) return EFI_DEVICE_ERROR;
    for (unsigned i=0;i<8;++i) if (host_allocations[i] == cpu) {
        assert(host_pages[i] == pages); free(cpu); host_allocations[i] = NULL; return EFI_SUCCESS;
    }
    assert(0 && "free must match an owned allocation"); return EFI_INVALID_PARAMETER;
}
static EFI_STATUS EFIAPI flush(EFI_PCI_IO_PROTOCOL *p) {
    assert(p == &pci && arena.Phase == RtxDmaCheckingStop); ++flush_calls; event('F');
    if (flush_reenter) assert(RtxDmaReleaseAll(&arena)==EFI_ACCESS_DENIED);
    return mode == FLUSH_FAIL ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS EFIAPI verify(VOID *context, EFI_PCI_IO_PROTOCOL *p) {
    assert(p == &pci && context == &arena && arena.Phase == RtxDmaCheckingStop);
    ++verify_calls; event('V');
    if (mode == VERIFY_REENTER) assert(RtxDmaReleaseAll(&arena) == EFI_ACCESS_DENIED);
    return mode == VERIFY_FAIL ? EFI_NOT_READY : EFI_SUCCESS;
}
static VOID setup(int chosen) {
    /* Any retained resources are ordinary aligned_alloc host fixtures. */
    for (unsigned i=0;i<8;++i) { free(host_allocations[i]); host_allocations[i] = NULL; }
    memset(&pci,0,sizeof(pci)); memset(&arena,0,sizeof(arena)); memset(buffers,0,sizeof(buffers));
    memset(order,0,sizeof(order)); order_length=0;
    mode=chosen; allocate_calls=map_calls=unmap_calls=free_calls=verify_calls=flush_calls=0;
    unmap_fault=free_fault=flush_reenter=0;
    pci.AllocateBuffer=allocate; pci.Map=map; pci.Unmap=unmap; pci.FreeBuffer=free_buffer; pci.Flush=flush;
    assert(RtxDmaInit(&arena,&pci) == EFI_SUCCESS);
}
static VOID allocated(VOID) { assert(RtxDmaAllocate(&arena,&buffers[0],4097) == EFI_SUCCESS); }

int main(void) {
    unsigned cases=0;
    setup(NORMAL); assert(RtxDmaIsEmpty(&arena));
    assert(RtxDmaAllocate(&arena,&buffers[0],0) == EFI_INVALID_PARAMETER);
    assert(RtxDmaAllocate(&arena,&buffers[0],(128U<<20)+1) == EFI_INVALID_PARAMETER);
    assert(!allocate_calls); ++cases;
    setup(NORMAL); allocated();
    assert(buffers[0].Pages==2 && buffers[0].Bytes==8192 && (UINTN)buffers[0].Cpu != buffers[0].Device);
    assert(RtxDmaAllocate(&arena,&buffers[1],1)==EFI_SUCCESS);
    assert(RtxDmaRelease(&arena,&buffers[0])==EFI_SUCCESS && arena.Count==1);
    assert(RtxDmaReleaseAll(&arena)==EFI_SUCCESS && RtxDmaIsEmpty(&arena));
    assert(!strcmp(order,"AMAMUDUD")); ++cases;
    setup(NULL_TOKEN); allocated(); assert(buffers[0].Mapped && !buffers[0].Mapping);
    assert(RtxDmaReleaseAll(&arena)==EFI_SUCCESS && unmap_calls==1); ++cases;
    setup(ALLOC_FAIL); assert(RtxDmaAllocate(&arena,&buffers[0],4096)==EFI_OUT_OF_RESOURCES);
    assert(RtxDmaIsEmpty(&arena) && !map_calls && !free_calls); ++cases;
    for (int m=ALLOC_NULL;m<=ALLOC_UNALIGNED;++m) {
        setup(m); assert(RtxDmaAllocate(&arena,&buffers[0],4096)==EFI_DEVICE_ERROR);
        assert(arena.Phase==RtxDmaRetained && arena.Head==&buffers[0] && !map_calls && !free_calls); ++cases;
    }
    setup(MAP_FAIL); assert(RtxDmaAllocate(&arena,&buffers[0],4096)==EFI_UNSUPPORTED);
    assert(RtxDmaIsEmpty(&arena) && !unmap_calls && free_calls==1); ++cases;
    for (int m=MAP_FAIL_TOKEN;m<=MAP_WARNING;++m) {
        setup(m); assert(EFI_ERROR(RtxDmaAllocate(&arena,&buffers[0],4096)));
        assert(arena.Phase==RtxDmaRetained && !unmap_calls && !free_calls); ++cases;
    }
    for (int m=PARTIAL;m<=DMA_CROSS_4G;++m) {
        setup(m); assert(RtxDmaAllocate(&arena,&buffers[0],4097)==EFI_UNSUPPORTED);
        assert(RtxDmaIsEmpty(&arena) && unmap_calls==1 && free_calls==1); ++cases;
    }
    setup(UNMAP_FAIL); allocated(); assert(RtxDmaReleaseAll(&arena)==EFI_DEVICE_ERROR);
    assert(buffers[0].Mapped && !free_calls && arena.Phase==RtxDmaRetained);
    assert(RtxDmaReleaseAll(&arena)==EFI_ACCESS_DENIED && unmap_calls==1); ++cases;
    setup(FREE_FAIL); allocated(); assert(RtxDmaReleaseAll(&arena)==EFI_DEVICE_ERROR);
    assert(!buffers[0].Mapped && arena.Head && arena.Phase==RtxDmaRetained);
    assert(RtxDmaReleaseAll(&arena)==EFI_ACCESS_DENIED && free_calls==1); ++cases;
    setup(NORMAL); allocated(); assert(RtxDmaInit(&arena,&pci)==EFI_ALREADY_STARTED);
    assert(RtxDmaAllocate(&arena,&buffers[0],4096)==EFI_ALREADY_STARTED && allocate_calls==1); ++cases;
    setup(NORMAL); allocated(); RTX_DMA_ARENA other={0}; assert(RtxDmaInit(&other,&pci)==EFI_SUCCESS);
    assert(RtxDmaRelease(&other,&buffers[0])==EFI_INVALID_PARAMETER && !unmap_calls); ++cases;
    setup(NORMAL); allocated(); assert(RtxDmaExpose(&arena)==EFI_SUCCESS);
    assert(RtxDmaAllocate(&arena,&buffers[1],4096)==EFI_ACCESS_DENIED && allocate_calls==1);
    assert(RtxDmaReleaseAll(&arena)==EFI_ACCESS_DENIED && !unmap_calls && !free_calls);
    assert(!RtxDmaIsEmpty(&arena)); ++cases;
    for (int m=VERIFY_FAIL;m<=VERIFY_REENTER;++m) {
        setup(m); allocated(); assert(RtxDmaExpose(&arena)==EFI_SUCCESS);
        assert(EFI_ERROR(RtxDmaConfirmStopped(&arena,verify,&arena)));
        assert(arena.Phase==RtxDmaRetained && !unmap_calls && !free_calls);
        assert(RtxDmaConfirmStopped(&arena,verify,&arena)==EFI_ACCESS_DENIED && verify_calls==1); ++cases;
    }
    setup(NORMAL); allocated(); assert(RtxDmaExpose(&arena)==EFI_SUCCESS);
    assert(RtxDmaConfirmStopped(&arena,NULL,NULL)==EFI_ACCESS_DENIED && !unmap_calls); ++cases;
    setup(NORMAL); allocated(); assert(RtxDmaExpose(&arena)==EFI_SUCCESS);
    assert(RtxDmaConfirmStopped(&arena,verify,&arena)==EFI_SUCCESS);
    assert(RtxDmaExpose(&arena)==EFI_ACCESS_DENIED);
    assert(RtxDmaReleaseAll(&arena)==EFI_SUCCESS && RtxDmaIsEmpty(&arena));
    assert(!strcmp(order,"AMVFUD")); ++cases;
    setup(PARTIAL); unmap_fault=1;
    assert(RtxDmaAllocate(&arena,&buffers[0],8192)==EFI_DEVICE_ERROR);
    assert(arena.Phase==RtxDmaRetained && buffers[0].Mapped && !free_calls); ++cases;
    setup(MAP_FAIL); free_fault=1;
    assert(RtxDmaAllocate(&arena,&buffers[0],8192)==EFI_DEVICE_ERROR);
    assert(arena.Phase==RtxDmaRetained && arena.Count==1 && !unmap_calls); ++cases;
    setup(NORMAL); allocated(); assert(RtxDmaAllocate(&arena,&buffers[1],4096)==EFI_SUCCESS);
    assert(RtxDmaExpose(&arena)==EFI_SUCCESS && RtxDmaRelease(&arena,&buffers[0])==EFI_ACCESS_DENIED);
    assert(arena.Count==2 && !unmap_calls && !free_calls); ++cases;
    setup(NORMAL); allocated(); assert(RtxDmaExpose(&arena)==EFI_SUCCESS);
    assert(RtxDmaConfirmStopped(&arena,verify,&arena)==EFI_SUCCESS); unmap_fault=1;
    assert(RtxDmaReleaseAll(&arena)==EFI_DEVICE_ERROR && !free_calls && arena.Phase==RtxDmaRetained); ++cases;
    setup(NORMAL); allocated(); assert(RtxDmaExpose(&arena)==EFI_SUCCESS); flush_reenter=1;
    assert(RtxDmaConfirmStopped(&arena,verify,&arena)==EFI_ACCESS_DENIED);
    assert(arena.Phase==RtxDmaRetained && !unmap_calls && !free_calls); ++cases;
    setup(NORMAL); /* host-only final teardown */
    printf("UEFI DMA CPU mocks: %u cases passed; no hardware verifier/execution implied.\n",cases);
    return 0;
}
