# Architecture and evidence boundaries

The target is a stock-capacity AD103 RTX 4080, 16GB, Non-SUPER. The initial
upstream AD102/Ada chain is a research starting point, not a device-ID substitution.
The board implementation checks live identity, layout, signature-related fuses,
ownership and recovery conditions independently.

## Pre-boot transaction

`src/efi/session.c` sequences asset validation, verified Windows boot-file
preparation/loading, a display snapshot, fresh board inspection and a targeted
NVIDIA driver lease. It then runs the core, checks resource cleanup/recovery and
verifies display/GPU conditions before Windows `StartImage`.

`owner.c` distinguishes real driver handles from observed opaque protocol
references. `lease.c` disconnects only the verified target driver and installs a
guard; it does not reconnect arbitrary controllers. Only memory decode is enabled
when required, rather than restoring the complete device-enable attribute set.

`dma.c`, `device.c` and `recovery.c` retain allocations when device ownership is
uncertain. A transaction permits at most one FLR. Success needs independent
permission/selector and recovery checks; a marker alone is insufficient. Failed
mutation or unknown DMA state does not trigger automatic reboot, retry or handoff.

`display.c` reads the Intel GOP and stable PCI metadata at four stages. It never
calls Intel SetMode/Blt or writes its framebuffer. The journal persists the first
three snapshots; it does not prove the fourth check or Windows boot completed.

The source frontend `unlock.inc` depends on private, generated boot and asset
headers, plus `private_board_pins.h` for PROM/GOP identity. These are intentionally
absent; missing pins fail compilation. Offline ROM review also requires an
independently reviewed identity to remove its ROM-identity blocker. This public snapshot does **not** contain
an unlock-image packaging/deployment command. Hardware adaptation must supply
independently reviewed inputs and revisit the board/console/recovery assumptions.
The provided `tools/build.py` builds only the capture EFI and host ROM checker.

## Windows measurement

`windows_bench.cu` separates MMA issue throughput from cuBLAS GEMM. FP16/BF16
use FP32 accumulation, TF32 has its own error threshold, and a pedantic FP32 path
provides a control. Small matrices have complete reference checks. Larger cases
use deterministic reference samples plus finiteness checks of every output.

The PowerShell runner pins executable/library identity, checks driver and device
health, records thermal telemetry and stops on errors or time/temperature limits.
Schema 2 also records display and Windows-session context before/after each
process. Offline validators require coherent timestamps, mode contents and
post-health linkage to the exact `run.json` bytes. Legacy runs without that
context remain explicitly unrecorded.

## Open display issue

A no-unlock chainload control returned with one normal Intel display. Full
experimental transactions returned with Intel plus a duplicate BasicDisplay
path. A reversible desktop experiment removed and restored the symptoms together
with that extra path. `review_display_isolation.py` checks the saved topology and
mode transitions; it does not turn user observations into a proof of root cause.

Unchanged GOP metadata does not establish correct Windows framebuffer ownership.
The official [BasicDisplay description](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/microsoft-basic-display-driver)
and [POST ownership interface](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dispmprt/nc-dispmprt-dxgkcb_acquire_post_display_ownership)
explain why those are separate observations. NVIDIA Stop, firmware work, FLR and
Windows initialization have not been independently isolated as causes. A GOP
reconnect, Intel mode reset or PCI command change is not a demonstrated fix.

Host tests establish behavior against specified simulations. They do not prove
firmware acceptance, hardware callback quiescence, Windows recovery or stability.
