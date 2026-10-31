"""Read-only NVIDIA ROM container/FWSEC inspection; no device access.

Format references: NVIDIA kernel_gsp_vbios_tu102.c, kernel_gsp_fwsec.c
(452cec62d827034798072827d3866d1881662b77) and NVIDIA BIT specification.
Offsets in FWSEC reports are relative to the normalized PCI image chain.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import hashlib
import struct

MAX_ROM_BYTES = 16 * 1024 * 1024
MAX_CHAIN_BYTES = 1024 * 1024


class RomError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded(data: bytes, off: int, size: int) -> bytes:
    if off < 0 or size < 0 or off > len(data) or size > len(data) - off:
        raise RomError(f"range outside input: offset={off:#x}, size={size:#x}")
    return data[off:off + size]


def u16(data: bytes, off: int) -> int:
    return struct.unpack("<H", bounded(data, off, 2))[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack("<I", bounded(data, off, 4))[0]


def locate_base(data: bytes) -> tuple[int, dict]:
    if len(data) > MAX_ROM_BYTES:
        raise RomError("container exceeds 16 MiB inspection limit")
    if bounded(data, 0, 2) == b"\x55\xaa":
        return 0, {"kind": "pci-rom"}
    if bounded(data, 0, 4) != b"NVGI":
        raise RomError("neither PCI ROM nor NVIDIA IFR signature")
    fixed1, fixed2 = u32(data, 4), u32(data, 8)
    version = (fixed1 >> 8) & 255
    info = {"kind": "ifr", "version": version}
    if version in (1, 2):
        extended = (fixed1 >> 16) & 0x7fff
        base = u32(data, extended + 4)
        info["extended_offset"] = extended
    elif version == 3:
        total = fixed2 & 0xfffff
        flash = u32(data, total)
        directory = flash + 4096
        if bounded(data, directory, 4) != b"RFRD":
            raise RomError("IFR v3 ROM directory signature mismatch")
        base = u32(data, directory + 8)
        info.update(total_data_size=total, flash_status_offset=flash,
                    directory_offset=directory)
    else:
        raise RomError(f"unsupported IFR version {version}")
    if base % 4 or bounded(data, base, 2) != b"\x55\xaa":
        raise RomError("IFR points to an invalid PCI ROM start")
    return base, info


def parse_chain(data: bytes, base: int) -> tuple[bytes, dict]:
    pos, base_size, extension = base, None, None
    images = []
    for index in range(8):
        if u16(data, pos) not in (0xaa55, 0x4e56, 0xbb77):
            raise RomError("invalid expansion ROM signature")
        pcir = pos + u16(data, pos + 0x18)
        signature = bounded(data, pcir, 4)
        if signature not in (b"PCIR", b"NPDS", b"RGIS"):
            raise RomError("invalid PCI data signature")
        pcir_size = u16(data, pcir + 0x10) * 512
        size, last = pcir_size, bool(bounded(data, pcir + 0x15, 1)[0] & 128)
        npde_end = None
        npde = (pcir + u16(data, pcir + 0x0a) + 15) & ~15
        if npde + 4 <= len(data) and bounded(data, npde, 4) == b"NPDE":
            revision, length = u16(data, npde + 4), u16(data, npde + 6)
            if revision not in (0x100, 0x101) or length < 10:
                raise RomError("unsupported NPDE revision/length")
            bounded(data, npde, length)
            npde_end = npde + length
            size = u16(data, npde + 8) * 512
            if length > 10:
                last = bool(data[npde + 10] & 128)
            elif size < pcir_size:
                last = False
        if not size or pos + size - base > MAX_CHAIN_BYTES:
            raise RomError("empty image or PCI chain exceeds 1 MiB")
        image = bounded(data, pos, size)
        if pcir < pos or pcir + 0x16 > pos + size:
            raise RomError("PCI data structure outside its image")
        if npde_end is not None and npde_end > pos + size:
            raise RomError("NPDE structure outside its image")
        code_type = data[pcir + 0x14]
        vendor, device = u16(data, pcir + 4), u16(data, pcir + 6)
        if index == 0 and (signature != b"PCIR" or code_type != 0):
            raise RomError("first image is not a legacy PCIR image")
        if code_type not in (0, 3, 0xe0):
            raise RomError(f"unsupported image type {code_type:#x}")
        if vendor != 0x10de or (code_type in (0, 3) and device != 0x2704):
            raise RomError("not the target NVIDIA 2704 legacy/UEFI image")
        if code_type == 0 and base_size is None:
            base_size = size
        if code_type == 0xe0 and extension is None:
            extension = pos - base
        checksum = sum(image) & 255
        if checksum:
            raise RomError(f"image {index} checksum mismatch")
        images.append({"offset": pos - base, "file_offset": pos, "size": size,
                       "code_type": code_type, "vendor": vendor, "device": device,
                       "last": last, "checksum8": checksum, "sha256": digest(image)})
        pos += size
        if last:
            break
    else:
        raise RomError("unterminated or excessive expansion ROM chain")
    if base_size is None or extension is None or extension < base_size:
        raise RomError("missing/invalid NVIDIA extension")
    chain = bounded(data, base, pos - base)
    return chain, {"file_offset": base, "size": len(chain), "sha256": digest(chain),
                   "pointer_adjustment": extension - base_size, "images": images}


def parse_fwsec(chain: bytes, adjustment: int) -> dict:
    bit_offsets = []
    start = 0
    while (start := chain.find(b"\xff\xb8BIT\0", start)) >= 0:
        bounded(chain, start, 12)
        size, stride, count = chain[start + 8:start + 11]
        if size >= 12 and stride >= 6 and sum(bounded(chain, start, size)) % 256 == 0:
            bit_offsets.append((start, size, stride, count))
        start += 1
    if len(bit_offsets) != 1:
        raise RomError("expected exactly one valid BIT header")
    bit, size, stride, count = bit_offsets[0]
    bounded(chain, bit + size, stride * count)
    falcon = []
    for i in range(count):
        off = bit + size + i * stride
        if chain[off:off + 2] == b"p\x02":
            if u16(chain, off + 2) < 4:
                raise RomError("short Falcon token")
            ptr = u32(chain, off + 4) if stride >= 8 else u16(chain, off + 4)
            bounded(chain, ptr, u16(chain, off + 2))
            falcon.append(adjustment + u32(chain, ptr))
    if len(falcon) != 1:
        raise RomError("expected exactly one Falcon token v2")
    table = falcon[0]
    version, header, entry_size, entries = bounded(chain, table, 4)
    if version != 1 or header < 6 or entry_size < 6:
        raise RomError("unsupported Falcon table")
    bounded(chain, table + header, entry_size * entries)
    descriptors = [adjustment + u32(chain, table + header + i * entry_size + 2)
                   for i in range(entries) if chain[table + header + i * entry_size] == 0x85]
    if len(descriptors) != 1:
        raise RomError("expected exactly one production FWSEC descriptor")
    off = descriptors[0]
    descriptor = u32(chain, off)
    descriptor_size = descriptor >> 16
    # This target has an unencrypted v3 descriptor; do not reinterpret unknown flags.
    if descriptor & 255 != 1 or (descriptor >> 8) & 255 != 3 or descriptor_size < 44:
        raise RomError("unsupported FWSEC descriptor flags/version/size")
    bounded(chain, off, descriptor_size)
    stored = u32(chain, off + 4)
    if not stored or stored > 0xffffff00:
        raise RomError("invalid FWSEC stored length")
    image_size = (stored + 255) & ~255
    image_off = off + descriptor_size
    image = bounded(chain, image_off, image_size)
    fw = {"descriptor_offset": off, "descriptor_version": 3,
          "descriptor_size": descriptor_size, "image_off": image_off, "image_size": image_size,
          "stored_size": stored}
    names = ("pkc_off", "interface_off", "imem_pa", "imem_size", "imem_va", "dmem_pa", "dmem_size")
    fw.update({name: u32(chain, off + 8 + 4 * i) for i, name in enumerate(names)})
    fw.update(engine_mask=u16(chain, off + 36), ucode_id=chain[off + 38],
              sig_count=chain[off + 39], sig_versions=u16(chain, off + 40),
              sig_off=off + 44, sig_bytes=descriptor_size - 44)
    fw["data_off"] = fw["imem_size"]
    if (fw["engine_mask"] != 0x400 or not 1 <= fw["ucode_id"] <= 16 or
        not fw["sig_count"] or fw["sig_versions"].bit_count() != fw["sig_count"] or
        fw["sig_bytes"] != fw["sig_count"] * 384 or not fw["imem_size"] or not fw["dmem_size"]):
        raise RomError("invalid/unsupported FWSEC geometry")
    dmem = bounded(image, fw["data_off"], fw["dmem_size"])
    bounded(dmem, fw["pkc_off"], 384)
    bounded(image, fw["data_off"], (fw["dmem_size"] + 255) & ~255)
    interface = fw["interface_off"]
    iv, ih, stride, count = bounded(dmem, interface, 4)
    if (iv, ih, stride) != (1, 4, 8) or count < 2:
        raise RomError("unsupported FWSEC interface")
    bounded(dmem, interface + ih, stride * count)
    mappers = [u32(dmem, interface + ih + i * stride + 4) for i in range(count)
               if u32(dmem, interface + ih + i * stride) == 4]
    if len(mappers) != 1:
        raise RomError("missing/duplicate DMEM mapper")
    mapper = mappers[0]
    bounded(dmem, mapper, 64)
    mv, ms = u16(dmem, mapper + 4), u16(dmem, mapper + 6)
    co, cs = u32(dmem, mapper + 8), u32(dmem, mapper + 12)
    if mv != 3 or ms < 64 or cs < 44:
        raise RomError("unsupported DMEM mapper or FRTS command size")
    bounded(dmem, mapper, ms)
    bounded(dmem, co, cs)
    fw.update(bit_offset=bit, falcon_table_offset=table, mapper_offset=mapper,
              mapper_version=mv, mapper_size=ms, command_offset=co, command_size=cs,
              image_sha256=digest(image), signatures_sha256=digest(bounded(chain, fw["sig_off"], fw["sig_bytes"])),
              supported_fuse_versions=[i for i in range(16) if fw["sig_versions"] & (1 << i)])
    return fw


def analyze(data: bytes) -> dict:
    base, container = locate_base(data)
    chain, info = parse_chain(data, base)
    fwsec = parse_fwsec(chain, info["pointer_adjustment"])
    duplicates = []
    # Advisory scan only. The primary image always comes from IFR/PCI structure.
    for candidate in range(0, len(data), 512):
        if candidate == base or data[candidate:candidate + 2] != b"\x55\xaa":
            continue
        try:
            other, other_info = parse_chain(data, candidate)
            parse_fwsec(other, other_info["pointer_adjustment"])
        except RomError:
            continue
        duplicates.append({"file_offset": candidate, "size": len(other),
                           "sha256": digest(other), "identical_to_primary": other == chain})
    return {"schema_version": 1, "input": {"bytes": len(data), "sha256": digest(data)},
            "container": container, "pci_chain": info, "fwsec": fwsec,
            "other_valid_chains": duplicates, "offline_format_compatible": True,
            "hardware_compatible": None, "cryptographic_signature_verified": False,
            "unverified": ["cold PROM mapping and content", "live FWSEC/Booter fuse versions",
                           "UEFI PCI ownership and DMA mapping", "cold VRAM reservations",
                           "firmware acceptance and cleanup", "Windows driver handoff"]}
