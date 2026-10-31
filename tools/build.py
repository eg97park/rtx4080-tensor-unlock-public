#!/usr/bin/env python3
"""Build CPU tools and the capture-only EFI. Never stages or runs an EFI."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
from bootstrap import header_digest

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build"
VENDOR = ROOT / "third_party/gpu-unlock-ada"


def check_vendor() -> None:
    manifest = json.loads((VENDOR / "provenance.json").read_text())
    for name, expected in manifest["files"].items():
        if hashlib.sha256((VENDOR / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"vendored source hash changed without review: {name}")


def run(args: list[str]) -> None:
    subprocess.run([str(a) for a in args], cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, default=ROOT / '.conda/dev',
                        help='existing LLVM prefix (default: project .conda/dev)')
    args = parser.parse_args()
    check_vendor()
    OUT.mkdir(exist_ok=True)
    clang = args.toolchain / 'bin/clang'
    lld = args.toolchain / 'bin/lld-link'
    headers = ROOT / ".local/references/edk2/MdePkg/Include"
    if not clang.is_file() or not lld.is_file() or not (headers / "Uefi.h").is_file():
        raise SystemExit("missing project LLVM or pinned EDK2 headers; see tools/bootstrap.py")
    if header_digest(headers) != json.loads((ROOT / "config/edk2.json").read_text())["include_tree_sha256"]:
        raise ValueError("pinned EDK2 header tree changed")
    includes = ["-I", headers, "-I", headers / "X64", "-I", VENDOR / "windows/ad104-msi"]
    flags = ["--no-default-config", "--target=x86_64-pc-windows-msvc", "-std=c11",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-mno-red-zone",
             "-fshort-wchar", "-Os", "-g0", "-Wall", "-Wextra", "-Werror"]
    sources = [ROOT / "src/efi/probe.c", ROOT / "src/efi/runtime.c", VENDOR / "windows/ad104-msi/sha256.c"]
    objects = []
    for source in sources:
        obj = OUT / (source.stem + ".obj")
        run([clang, *flags, *includes, "-c", source, "-o", obj])
        objects.append(obj)
    efi = OUT / "RTX4080-PROBE.efi"
    run([lld, "/subsystem:efi_application", "/entry:EfiMain", "/nodefaultlib", "/machine:x64",
         "/dynamicbase", "/nxcompat", "/opt:ref", "/timestamp:0", f"/out:{efi}", *objects])
    kernel = VENDOR / "kernel/gpu_unlock"
    run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", kernel,
         ROOT / "src/host/rom_check.c", kernel / "vbios_610.c", "-o", OUT / "rom_check"])
    report = {"schema_version": 1, "hardware_execution": False,
              "efi_capabilities": ["USB file capture", "PCI configuration reads", "existing BAR memory reads"],
              "efi_forbidden_capabilities": ["GPU writes", "DMA", "reset", "firmware execution", "chainload"],
              "tools": {"clang": subprocess.check_output([clang, "--version"], text=True).splitlines()[0],
                        "gcc": subprocess.check_output(["gcc", "-dumpfullversion"], text=True).strip()},
              "artifacts": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [efi, OUT / "rom_check"]},
              "sources": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}
    (OUT / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
