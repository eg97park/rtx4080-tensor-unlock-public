/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTX4080_CORE_BRIDGE_H
#define RTX4080_CORE_BRIDGE_H
#include "device.h"
#include "core_compat/compat.h"
#define RTX_CORE_DMA_SLOTS 65536u
typedef struct RTX_CORE_POOL RTX_CORE_POOL;
typedef struct RTX_CORE_DMA RTX_CORE_DMA;
typedef struct {const char *Name;struct firmware Firmware;} RTX_CORE_ASSET;
typedef struct {
    RTX_DEVICE *Device;
    const RTX_CORE_ASSET *Assets;
    RTX_CORE_POOL *Pools;
    VOID *AmbiguousPool;
    RTX_CORE_DMA *Dma[RTX_CORE_DMA_SLOTS];
    struct pci_dev Pci;
    u64 StreamingMask;
    UINTN PoolBytes, DmaCount, LogCalls;
    const char *LastLogFormat;
    char Log[131072];
    UINTN LogBytes;
    BOOLEAN LogTruncated, LogFormatRejected;
    int CoreResult;
    EFI_STATUS Status;
    BOOLEAN Attempted, Retained, CleanupComplete, UnlockReported;
} RTX_CORE;
/* Caller-owned zeroed HEAP context (~512 KiB). Five immutable preloaded asset
 * files, held lease and initialized device required. Core hashes every asset.
 * Single card at TPL_APPLICATION. NOT a runnable frontend/permission mechanism.
 * Deferred DMA releases occur only after independent containment verification.
 * Never reset/retry on a fault. Does not release the lease or start Windows.
 */
EFI_STATUS EFIAPI RtxCoreRun(RTX_CORE *,RTX_DEVICE *,const RTX_CORE_ASSET [5]);
/* Pure preflight, to run BEFORE driver Stop as well as at transaction entry.
 * Reads five immutable caller-owned buffers. No firmware services/GPU access. */
EFI_STATUS EFIAPI RtxCoreValidateAssets(const RTX_CORE_ASSET [5]);
#endif
