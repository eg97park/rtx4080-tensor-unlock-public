# Source provenance and redistribution scope

New project code is **GPL-2.0-only**; the license text is in `LICENSE`.

`third_party/gpu-unlock-ada/` is an unchanged subset of
[JustAResearcher/gpu-unlock-ada](https://github.com/JustAResearcher/gpu-unlock-ada)
at `d28c485418c3d9d034cd4bac19200bc33dd3453b`. Its `provenance.json`
records the hashes of the copied files. The GPL, CMP40HX, NVIDIA MIT and Windows
port notices are retained verbatim. Paths outside this selected subset that are
mentioned in upstream notices belong to the upstream repository.

The Ada payload generator's origins, including TOTORONG's AD103 work and
WildFlash1st's CMP work, are documented in the unmodified
[firmware notice](third_party/gpu-unlock-ada/firmware/NOTICE.md). Attribution is
preserved; the original sources' authors are not the private experiment operator.

EDK2 `c1415771ac592ad8509351c46cd3cda4f38d7d52` supplies header definitions
under its BSD-2-Clause-Patent notices. `tools/bootstrap.py` retrieves and verifies
the pinned archive in `.local/`; the source archive's notices remain there.
No EDK2 library binaries are linked into the minimal capture build.

NVIDIA firmware, GPU ROM/PROM dumps, Windows boot manager, CUDA DLLs and NVIDIA
driver archives are **not included**. A source-code license does not grant
permission to redistribute those separate assets. Deterministic generators and
public asset hashes are source provenance, not proof of runtime compatibility.

This repository has separate export history and owner-approved contributor metadata.
The private development history and experiment identifiers were not imported.
