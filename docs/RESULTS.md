# Results and limitations

These are manually selected, rounded aggregates from one privately operated board.
Raw logs, observation timestamps, filesystem paths, machine/boot identifiers and
hashes of private logs are omitted. The aggregate claims cannot be independently
reconstructed from this public snapshot alone; analysis and measurement source are
provided for independent experiments.

| Item | Observed configuration |
|---|---|
| GPU | Colorful iGame RTX 4080 Ultra W OC 16GB, Non-SUPER |
| PCI identity | NVIDIA `10DE:2704`, subsystem `7377:1500` |
| VBIOS | `95.03.1E.00.84` |
| NVIDIA Windows driver | `621.01` |
| OS | Windows 11; WSL2 Ubuntu used for development |
| Display | Intel iGPU HDMI, 3840×2160; unlocked test at approximately 143.99 Hz |
| Power limit | 320 W; actual clocks/temperatures not locked |
| Standard suite | 7 processes, 27 results, 15 timing repetitions per result |

The corresponding 60 Hz unlocked run measured 173.18 / 173.18 / 88.71 TFLOP/s
for 4096³ FP16 / BF16 / TF32. The 143.99 Hz run measured 172.74 / 172.96 / 89.66.
This does not establish a causal effect of refresh rate: configurations had only
one measured suite each. In the larger 8192³ BF16 case, 191.40 → 169.57 TFLOP/s
was observed; rectangular BF16 was also lower and noisier. Gains are workload-dependent.

FP16 and BF16 MMA issue throughput reached approximately 192 TFLOP/s, about
1.99× their stock observations. An issue microbenchmark is not end-to-end app speed.

Maximum observed normalized reference errors were approximately:

| Mode | Maximum NRMSE | Acceptance threshold |
|---|---:|---:|
| FP16 | 6.43e-6 | 2e-5 |
| BF16 | 6.30e-6 | 2e-5 |
| TF32 | 2.68e-4 | 2e-3 |
| FP32 control | 1.59e-6 | 2e-5 |

For large matrices these are sampled reference errors, not every output's error.
Every output is additionally checked for NaN/Inf. The current suite took about
16.5 seconds; maximum *sampled* temperature/power were about 60°C / 198 W.
Those samples do not establish instantaneous peaks or sustained-load behavior.

Observed stages: UEFI transaction reported successful selector/permission changes
and recovery; Windows subsequently produced higher Tensor throughput with passing
short accuracy and error checks. Windows did not directly re-read the selectors.

Not established: long-term stability, repeated cold/warm boot reliability, a new
stock→unlocked→stock series, general app speedups, all-board compatibility, Secure
Boot trust integration, or BitLocker-protected boot through the experimental EFI.
The duplicated display path remains an unresolved compatibility issue.
