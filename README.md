# RTX 4080 Tensor Unlock Research

Experimental UEFI source and Windows measurement tools for the **Colorful iGame
RTX 4080 Ultra W OC 16GB, Non-SUPER** (`10DE:2704`). Development uses WSL2;
performance validation uses native Windows 11. Display output uses an Intel iGPU.

On one board, an experimental pre-boot transaction followed by Windows driver
initialization produced approximately **1.9× throughput in 4096³ Tensor GEMM**.
Short accuracy checks passed. This is a research source release, not a qualified
installer or a claim that all RTX 4080 cards are compatible.

## Measured result

Median TFLOP/s, 15 timing samples per case, same executable, libraries, driver,
power limit and clock-limit settings:

| 4096³ GEMM | Stock | Unlocked | Ratio |
|---|---:|---:|---:|
| FP16 inputs / FP32 accumulation | 90.75 | 172.74 | 1.904× |
| BF16 inputs / FP32 accumulation | 90.75 | 172.96 | 1.906× |
| TF32 | 45.95 | 89.66 | 1.951× |
| FP32 control | 34.83 | 34.65 | 0.995× |

The unlocked run used Intel-only 3840×2160 at approximately 143.99 Hz. Stock
refresh was not recorded. Actual operating clocks and temperature were not fixed.
These are single-suite observations; sustained stability and stock→unlocked→stock
repeatability have not been established. See [results and limits](docs/RESULTS.md).

**Known display issue:** after experimental Windows handoff, a duplicate
BasicDisplay path appeared alongside Intel and caused visible artifacts. Excluding
that path for the session removed the observed symptoms; restoring it brought
them back. The underlying ownership/initialization fault remains unresolved.
The source does not silently disable devices or permanently change display settings.

## Included

- Board-specific UEFI transaction, ownership, DMA, recovery and handoff source.
- A capture-only EFI build target and host simulations using fake firmware services.
- Native Windows CUDA/cuBLAS benchmarks, accuracy checks and bounded measurement.
- Offline VBIOS/FWSEC, PCI/UEFI graph, measured-boot and benchmark analysis.
- Display/boot-context checks and narrowly scoped display-isolation research tools.
- Pinned third-party source with original copyright and license notices.

No ROM, NVIDIA firmware, boot manager, ready-to-boot unlock image, private boot
path, USB identity, raw machine logs or original Git history is distributed.
The experimental unlock frontend is source for review: the original machine's
asset/boot-pin generators and deployment wrappers are deliberately excluded.
See [architecture and reproduction boundaries](docs/ARCHITECTURE.md) and the
[publication review scope](docs/PUBLICATION.md).

## Start with offline tests

Python 3.13 was used for verification. Python's standard library is sufficient for
the default test suite; it does not access a GPU or download dependencies.

```bash
python3 tools/test_public.py
python3 tools/audit_public.py
```

The prepared snapshot passed 65 Python tests; 312 C mock cases across capture,
DMA, display, handoff and session sequencing; a C++ reference test; and 28
measurement / 21 display Host scenarios in Windows PowerShell. Native C/C++
checks used AddressSanitizer and UndefinedBehaviorSanitizer. The capture-only EFI
built with Clang/LLD 20.1.8. Six focused compile checks also verified missing/malformed private pins are rejected
and correctly sized synthetic pins compile. These are software checks, not
additional hardware trials.

For the native CPU mocks and capture-only EFI build, use an existing Conda and
GCC/G++ installation in WSL2/Linux. Bootstrap downloads the pinned EDK2 source
and creates only project-local dependencies; it does not modify Conda base.

```bash
python3 tools/bootstrap.py --with-conda
.conda/dev/bin/python tools/test_public.py --native
.conda/dev/bin/python tools/build.py
```

Building creates local artifacts only. **Do not boot an EFI just because it
compiles or because host tests pass.** No USB staging or boot changes are included
in these commands. [Development guide](docs/DEVELOPMENT.md) describes the separate
Windows build and mock-test path.

## Hardware scope

The implementation retains board/firmware identity checks, ownership inspection,
bounded waits, a single FLR per transaction, independent recovery checks and
stop-on-unknown-state behavior. Removing a rejected check is not a compatibility
port. Intel display checks are also specific to the observed setup.

Hardware testing requires a separately reviewed plan, backups and a recovery
path. Do not retry or chainload Windows after an unknown GPU/DMA failure. Secure
Boot trust, BitLocker measured-boot behavior and dual-boot routing are distinct
from GPU correctness. Tested runs used Secure Boot off and BitLocker protection
suspended; protected boot through this unsigned experimental EFI is not qualified.
No VBIOS flash, TPM reset or Secure Boot key deletion is part of this project.

## License and provenance

New code is GPL-2.0-only. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Vendored source is hash-pinned;
NVIDIA firmware licensing is separate and no firmware is redistributed here.

한국어: 한 대의 Non-SUPER 16GB 보드에서 확인한 연구 소스입니다. 실측 성능 향상은
확인했지만 화면 인계 문제와 장시간 안정성은 미완료입니다. 개인 식별자·원본 로그·
펌웨어·자동 실행 패키지는 포함하지 않으며, Host Test 통과를 실물 실행 승인으로
해석하면 안 됩니다.
