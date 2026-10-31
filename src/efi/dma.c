/* SPDX-License-Identifier: GPL-2.0-only
 * Uses pinned EDK2 EFI_PCI_IO_PROTOCOL AllocateBuffer/Map/Unmap/FreeBuffer.
 * Like the pinned Ada UEFI reference, restrict device addresses to 32 bits.
 * No device MMIO/configuration writes, attributes changes or reset operations.
 */
#include "dma.h"

static VOID clear_buffer(RTX_DMA_BUFFER *b) {
    b->Owner = NULL; b->Next = NULL; b->Cpu = NULL; b->Mapping = NULL;
    b->Device = 0; b->Bytes = 0; b->Pages = 0; b->Mapped = FALSE;
}

static EFI_STATUS retain(RTX_DMA_ARENA *a, EFI_STATUS reason) {
    a->Phase = RtxDmaRetained;
    if (a->RetainReason == EFI_SUCCESS) a->RetainReason = reason;
    return reason;
}

static VOID fence(VOID) {
    /* x64 CPU ordering; this is NOT a replacement for common-buffer mapping
     * semantics or a cache flush on an unsupported noncoherent platform. */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

EFI_STATUS EFIAPI RtxDmaInit(RTX_DMA_ARENA *a, EFI_PCI_IO_PROTOCOL *pci) {
    if (!a || !pci || !pci->AllocateBuffer || !pci->FreeBuffer || !pci->Map ||
        !pci->Unmap || !pci->Flush) return EFI_INVALID_PARAMETER;
    if (a->Pci || a->Head || a->Count || a->Phase != RtxDmaCold || a->RetainReason)
        return EFI_ALREADY_STARTED;
    a->Pci = pci;
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI RtxDmaRelease(RTX_DMA_ARENA *a, RTX_DMA_BUFFER *b) {
    if (!a || !a->Pci || !b || b->Owner != a) return EFI_INVALID_PARAMETER;
    if (a->Phase != RtxDmaCold && a->Phase != RtxDmaStopped)
        return retain(a, EFI_ACCESS_DENIED);
    RTX_DMA_BUFFER **link = &a->Head;
    while (*link && *link != b) link = &(*link)->Next;
    if (!*link || !a->Count) return retain(a, EFI_COMPROMISED_DATA);
    if (b->Mapped) {
        /* A successful Map can have a NULL token on identity mappings. */
        EFI_STATUS s = a->Pci->Unmap(a->Pci, b->Mapping);
        if (s != EFI_SUCCESS) return retain(a, EFI_ERROR(s) ? s : EFI_DEVICE_ERROR);
        b->Mapped = FALSE; b->Mapping = NULL;
    }
    EFI_STATUS s = a->Pci->FreeBuffer(a->Pci, b->Pages, b->Cpu);
    if (s != EFI_SUCCESS) return retain(a, EFI_ERROR(s) ? s : EFI_DEVICE_ERROR);
    *link = b->Next; --a->Count; clear_buffer(b);
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI RtxDmaAllocate(RTX_DMA_ARENA *a, RTX_DMA_BUFFER *b, UINTN bytes) {
    if (!a || !a->Pci || !b || !bytes || bytes > (128U << 20)) return EFI_INVALID_PARAMETER;
    if (a->Phase != RtxDmaCold) return EFI_ACCESS_DENIED;
    if (b->Owner || b->Cpu || b->Next || b->Mapping || b->Mapped || b->Pages || b->Bytes || b->Device)
        return EFI_ALREADY_STARTED;
    b->Pages = (bytes + 4095) / 4096; b->Bytes = b->Pages * 4096;
    EFI_STATUS s = a->Pci->AllocateBuffer(a->Pci, AllocateAnyPages, EfiBootServicesData, b->Pages, &b->Cpu, 0);
    if (EFI_ERROR(s) && !b->Cpu) { clear_buffer(b); return s; }
    /* Register ownership before every cleanup path. An inconsistent provider
     * result is retained; do not discard a possibly allocated CPU pointer. */
    b->Owner = a; b->Next = a->Head; a->Head = b; ++a->Count;
    if (s != EFI_SUCCESS || !b->Cpu || ((UINTN)b->Cpu & 4095))
        return retain(a, EFI_DEVICE_ERROR);
    UINT8 *cpu = b->Cpu;
    for (UINTN i = 0; i < b->Bytes; ++i) cpu[i] = 0;
    UINTN mapped = b->Bytes;
    s = a->Pci->Map(a->Pci, EfiPciIoOperationBusMasterCommonBuffer,
                    b->Cpu, &mapped, &b->Device, &b->Mapping);
    if ((EFI_ERROR(s) && (b->Mapping || b->Device)) || (!EFI_ERROR(s) && s != EFI_SUCCESS))
        return retain(a, EFI_ERROR(s) ? s : EFI_DEVICE_ERROR);
    if (!EFI_ERROR(s)) b->Mapped = TRUE;
    if (s == EFI_SUCCESS && mapped == b->Bytes && b->Device && !(b->Device & 4095) &&
        b->Device <= 0xffffffffULL && b->Bytes - 1 <= 0xffffffffULL - b->Device)
        return EFI_SUCCESS;
    EFI_STATUS original = EFI_ERROR(s) ? s : EFI_UNSUPPORTED;
    EFI_STATUS cleanup = RtxDmaRelease(a, b);
    return EFI_ERROR(cleanup) ? cleanup : original;
}

EFI_STATUS EFIAPI RtxDmaExpose(RTX_DMA_ARENA *a) {
    if (!a || !a->Pci || !a->Head) return EFI_INVALID_PARAMETER;
    if (a->Phase != RtxDmaCold) return EFI_ACCESS_DENIED;
    for (RTX_DMA_BUFFER *b = a->Head; b; b = b->Next)
        if (!b->Mapped || b->Owner != a) return retain(a, EFI_COMPROMISED_DATA);
    fence(); a->Phase = RtxDmaDeviceMayAccess;
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI RtxDmaConfirmStopped(RTX_DMA_ARENA *a, RTX_DMA_VERIFY_STOP verify, VOID *context) {
    if (!a || !a->Pci) return EFI_INVALID_PARAMETER;
    if (a->Phase != RtxDmaDeviceMayAccess) return EFI_ACCESS_DENIED;
    if (!verify) return retain(a, EFI_ACCESS_DENIED);
    a->Phase = RtxDmaCheckingStop;
    EFI_STATUS s = verify(context, a->Pci);
    if (a->Phase != RtxDmaCheckingStop) return retain(a, EFI_ACCESS_DENIED);
    if (s != EFI_SUCCESS) return retain(a, EFI_ERROR(s) ? s : EFI_DEVICE_ERROR);
    /* Flush drains PCI writes toward host memory; it cannot stop GPU firmware.
     * The independent verifier must establish containment first. */
    s = a->Pci->Flush(a->Pci);
    if (a->Phase != RtxDmaCheckingStop) return retain(a, EFI_ACCESS_DENIED);
    if (s != EFI_SUCCESS) return retain(a, EFI_ERROR(s) ? s : EFI_DEVICE_ERROR);
    fence(); a->Phase = RtxDmaStopped;
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI RtxDmaReleaseAll(RTX_DMA_ARENA *a) {
    if (!a || !a->Pci) return EFI_INVALID_PARAMETER;
    if (a->Phase != RtxDmaCold && a->Phase != RtxDmaStopped)
        return retain(a, EFI_ACCESS_DENIED);
    while (a->Head) {
        EFI_STATUS s = RtxDmaRelease(a, a->Head);
        if (EFI_ERROR(s)) return s;
    }
    return a->Count ? retain(a, EFI_COMPROMISED_DATA) : EFI_SUCCESS;
}

BOOLEAN EFIAPI RtxDmaIsEmpty(const RTX_DMA_ARENA *a) {
    return a && a->Pci && !a->Head && !a->Count &&
        (a->Phase == RtxDmaCold || a->Phase == RtxDmaStopped);
}
