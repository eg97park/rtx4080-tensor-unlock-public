# Development

Default `python3 tools/test_public.py` runs the included synthetic Python tests.
It requires no firmware, ROM, private capture or GPU. Do not substitute the
original private project's all-assets gate: that gate deliberately requires inputs
that are not distributed here.

`--native` additionally builds/runs C/C++ mocks for capture, DMA, Intel display,
Windows handoff, session sequencing and numerical reference checks. GCC/G++,
AddressSanitizer/UndefinedBehaviorSanitizer and the pinned EDK2 headers are required.
No UEFI image is executed. Firmware service callbacks are test implementations.

The bootstrap and capture build use `.conda/dev` and `.local/references/edk2`.
They do not install a Linux NVIDIA driver in WSL. `config/toolchain-linux-64.lock`
pins the Linux toolchain; Windows CUDA and MSVC are separate installations.

## Windows build and CPU tests

From a Windows PowerShell opened at the repository root:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\windows\Build-Benchmark.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\windows\Test-MeasurementMock.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tools\windows\Test-DisplayIsolationHost.ps1
```

The build needs existing Visual Studio C++ Build Tools and a Windows CUDA Toolkit
with cuBLAS. It does not install them. The two Host test scripts use synthetic
inputs; the display Host test replaces every native display import with a throwing
stub before compilation. The measurement mock uses text placeholders as fake
EXE/DLL files and never launches them.

Real measurements are a separate action: `Measure-Benchmark.ps1` requires an
explicit `-RunApproved` switch and verified board/display preconditions. Smoke
uses 3 CUDA processes; standard uses 7. Current bounds are 83°C, 60 seconds per
case and 180 seconds per suite. It stops its own failed benchmark process and
does not reset the GPU or reboot. A command-line switch does not replace informed
authorization or qualify an unsafe boot state.

`Test-DisplayIsolation.ps1` is a **display-changing experiment** when invoked with
`-Apply`. It is not part of either default test suite. It requires the observed
Intel/monitor identity and validates preservation of the existing mode; do not
remove those checks to accommodate another system.

## Working with private data

All collected data belongs under `.local/`, and build outputs under `build/`.
Do not attach raw benchmark JSON, display captures, TCG logs or Windows diagnostic
outputs to an issue without reviewing them: they can include boot/device IDs,
volume serials, paths, exact timestamps and event messages. Never collect or
publish BitLocker recovery keys, PINs, tokens or account credentials.

Run `python3 tools/audit_public.py` before publication. For local known private
markers, put one marker per line in `.local/private-markers.txt` and pass
`--deny-file .local/private-markers.txt`. The checker scans the working tree,
staged content, all Git objects, commit/tag identities and messages, refs and local
metadata. Use `--release` for a clean committed tree and `--archive PATH` to compare
a source ZIP against HEAD. See [publication scope](PUBLICATION.md). It is an aid to review,
not a guarantee of anonymity. Preserve third-party copyright notices.

Public issues should contain a GPU model, driver/OS version, short aggregate
results and a minimal synthetic reproducer. A change of board or firmware needs
fresh compatibility work, not a promise inferred from the reported board.

## Local firmware identity inputs

The capture-only build does not require a private board pin. The experimental
`owner.c` and `core_bridge.c` deliberately require a separately reviewed
`private_board_pins.h`, supplied via a local include directory such as
`.local/generated`. It must define `RTX_REVIEWED_PROM_SHA256_BYTES` and
`RTX_REVIEWED_GOP_TEXT_SHA256_BYTES` as exactly 32 comma-separated byte constants
each. There are no default/zero/wildcard digests; missing inputs fail compilation.
Do not fill these values from an unchecked live capture merely to pass a check.
The GOP PE layout/relocation and ownership assumptions need independent review too.

`review_capture.py` and `review_unlock.py` accept `--rom-chain-sha256` for a locally
reviewed expected ROM-chain identity. Without it, parsing can proceed but ROM
identity remains explicitly blocked. A matching hash alone never produces
`write_ready=true` or proves that hardware can run the transaction safely.
