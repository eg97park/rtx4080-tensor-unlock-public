#!/usr/bin/env python3
"""Project-local toolchain and pinned reference headers. No global installs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
EDK_REV = "c1415771ac592ad8509351c46cd3cda4f38d7d52"
EDK_SHA = "666f953e84e09ad469c5558da37e35ed8b08c3e6345f7e3caa6ab1fc32654d95"


def sha_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url: str, target: Path, expected: str) -> None:
    if target.exists():
        if sha_file(target) != expected:
            raise ValueError(f"cached input mismatch: {target}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    # A failed download never masquerades as a complete cache entry.
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                size = 0
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > 1024 ** 3:
                        raise ValueError("download exceeds 1 GiB")
                    stream.write(block)
            stream.flush()
            if sha_file(temporary) != expected:
                raise ValueError("download SHA-256 mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)


def unpack_source(archive: Path, output: Path) -> None:
    """Reject links, traversal, duplicate members and oversized source archives."""
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        temporary = Path(temp) / "source"
        temporary.mkdir()
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            if len(members) > 50000 or sum(m.size for m in members) > 1024 ** 3:
                raise ValueError("source archive exceeds limit")
            roots, seen = set(), set()
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not path.parts:
                    raise ValueError("unsafe source member")
                roots.add(path.parts[0])
                if not member.isfile() and not member.isdir():
                    raise ValueError("source archive contains links/special files")
                if member.name in seen:
                    raise ValueError("duplicate archive member")
                seen.add(member.name)
                if len(path.parts) == 1:
                    if not member.isdir():
                        raise ValueError("source root is a file")
                    continue
                target = temporary.joinpath(*path.parts[1:])
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as source, target.open("xb") as sink:
                        shutil.copyfileobj(source, sink)
            if len(roots) != 1:
                raise ValueError("source archive must have one root")
        temporary.rename(output)


def header_digest(headers: Path) -> str:
    state = hashlib.sha256()
    for path in sorted(headers.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in headers")
        if path.is_file():
            state.update(path.relative_to(headers).as_posix().encode() + b"\0")
            state.update(bytes.fromhex(sha_file(path)))
    return state.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--with-conda", action="store_true", help="create .conda/dev from explicit lock if absent")
    args = p.parse_args()
    headers = ROOT / ".local/references/edk2"
    if not headers.exists():
        archive = ROOT / ".local/cache" / f"edk2-{EDK_REV}.tar.gz"
        download(f"https://codeload.github.com/tianocore/edk2/tar.gz/{EDK_REV}", archive, EDK_SHA)
        unpack_source(archive, headers)
    expected = json.loads((ROOT / "config/edk2.json").read_text())
    if header_digest(headers / "MdePkg/Include") != expected["include_tree_sha256"]:
        raise ValueError("EDK2 header tree differs from pinned source")
    if args.with_conda:
        prefix = ROOT / ".conda/dev"
        if not prefix.exists():
            conda = shutil.which("conda")
            if not conda:
                raise ValueError("existing conda required; no system bootstrap is performed")
            env = dict(os.environ, CONDA_PKGS_DIRS=str(ROOT / ".local/conda-pkgs"), CONDA_REPORT_ERRORS="false")
            subprocess.run([conda, "create", "--yes", "--prefix", str(prefix), "--file",
                            str(ROOT / "config/toolchain-linux-64.lock")], env=env, check=True)
        subprocess.run([str(prefix / "bin/python"), "--version"], check=True)
        subprocess.run([str(prefix / "bin/clang"), "--version"], check=True)
    print("Pinned headers verified. Existing environments were not modified.")


if __name__ == "__main__":
    main()
