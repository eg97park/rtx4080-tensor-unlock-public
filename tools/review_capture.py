#!/usr/bin/env python3
"""Offline review of one USB probe capture; never generates a write-ready profile."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from rom_image import analyze, RomError
from uefi_path import match_esp
from uefi_graph import analyze_graph

BYTE_FIELDS={'device_path','protocol_guid','mapped_image_sha256','ready_boot_file_sha256','display_device_path','display_pci_path'}



def signature_fuses(mmio):
    report={};blockers=[]
    # Engine and ucode ID matter. GSP UCODE3 at 0x8241c8 cannot substitute
    # for Booter SEC2 UCODE3 at 0x824140+(3-1)*4.
    for name,offset in (('booter_sec2_ucode3',0x824148),('fwsec_gsp_ucode9',0x8241e0)):
        value=mmio.get(offset)
        entry={'offset':hex(offset),'observed':value is not None,'version':None,'supported':False}
        if value is None:blockers.append(f'{name} fuse was not captured at {offset:#x}')
        elif value==0xffffffff or value&0xffff0000==0xbadf0000:
            blockers.append(f'inaccessible {name} fuse at {offset:#x}')
        else:
            version=(value&0xffff).bit_length()
            entry.update(raw=hex(value),version=version,supported=version<2)
            if version>=2:blockers.append(f'fuse version outside reproduced signatures at {offset:#x}')
        report[name]=entry
    return report,blockers


def review_rom_views(blobs: dict[str, bytes], expected_chain_sha256=None) -> tuple[dict, list[str]]:
    """A partial PCI ROM is explained only by an independent pinned full PROM.

    Keep the strict parser unchanged and retain its error. A byte-identical
    prefix ending at a complete legacy/EFI image boundary is NOT a FWSEC asset.
    """
    roms={};blockers=[];prom=None
    if expected_chain_sha256 is not None:
        if not re.fullmatch(r'[0-9a-fA-F]{64}', expected_chain_sha256):
            raise ValueError('expected ROM chain SHA-256 must have 64 hexadecimal digits')
        expected_chain_sha256=expected_chain_sha256.lower()
    else:
        blockers.append('no independently reviewed ROM chain identity supplied')
    for suffix,data in blobs.items():
        try:
            report=analyze(data)
            roms[suffix]={'classification':'full_chain','chain_sha256':report['pci_chain']['sha256'],'fwsec':report['fwsec']}
            if expected_chain_sha256 is None or report['pci_chain']['sha256']!=expected_chain_sha256:
                blockers.append(suffix+' has no match to an independently reviewed board ROM chain')
            elif suffix=='.PRM':prom=report['pci_chain']
        except RomError as e:
            roms[suffix]={'classification':'unresolved','parse_error':str(e)}
            blockers.append(suffix+' requires ROM-view investigation')
    if prom and '.ROM' in roms and 'parse_error' in roms['.ROM']:
        data=blobs['.ROM'];start=prom['file_offset']
        full=blobs['.PRM'][start:start+prom['size']]
        images=[i for i in prom['images'] if i['offset']+i['size']<=len(data)]
        if (images and len(data)<len(full) and data==full[:len(data)] and
            images[-1]['offset']+images[-1]['size']==len(data) and
            [i['code_type'] for i in images]==[0,3]):
            roms['.ROM'].update(classification='verified_legacy_efi_prefix',complete_fwsec_asset=False,
                compared_to='.PRM',full_chain_sha256=expected_chain_sha256,
                prefix_size=len(data),complete_image_count=len(images))
            blockers.remove('.ROM requires ROM-view investigation')
    if '.PRM' not in roms:blockers.append('no cold PROM snapshot')
    return roms,blockers


def records(raw: bytes) -> list[tuple[str,int|bytes]]:
    if len(raw)>16*1024*1024: raise ValueError('capture log too large')
    lines=raw.decode('ascii').splitlines(); pairs=[];i=0
    while i<len(lines):
        match=re.fullmatch(r'([a-z0-9_]+)=0x([0-9a-f]{16})',lines[i]);i+=1
        if not match: raise ValueError('malformed or partial log record')
        key,value=match[1],int(match[2],16)
        if key=='data_le': raise ValueError('orphan binary data')
        if key in BYTE_FIELDS:
            if value>4096: raise ValueError('binary record exceeds bound')
            result=bytearray()
            for _ in range((value+7)//8):
                if i>=len(lines): raise ValueError('truncated binary record')
                match=re.fullmatch(r'data_le=0x([0-9a-f]{16})',lines[i]);i+=1
                if not match: raise ValueError('invalid binary continuation')
                result.extend(int(match[1],16).to_bytes(8,'little'))
            value=bytes(result[:value])
        pairs.append((key,value))
    return pairs


def pci_status(data: bytes) -> dict:
    if len(data)!=256: raise ValueError('PCI snapshot must be exactly 256 bytes')
    def word(off):return struct.unpack_from('<H',data,off)[0]
    def dword(off):return struct.unpack_from('<I',data,off)[0]
    if dword(0)!=0x270410de or dword(0x2c)!=0x15007377: raise ValueError('target PCI identity mismatch')
    caps={}; pos=data[0x34] if word(6)&0x10 else 0;seen=set()
    while pos:
        if pos%4 or pos<0x40 or pos>0xfc or pos in seen: raise ValueError('invalid/cyclic PCI capability list')
        seen.add(pos);kind=data[pos]
        if kind in caps: raise ValueError('duplicate PCI capability')
        caps[kind]=pos;pos=data[pos+1]
    pm,pcie=caps.get(1),caps.get(0x10)
    if (pm and pm+6>256) or (pcie and pcie+12>256): raise ValueError('truncated capability')
    return {'command':word(4),'memory_decode':bool(word(4)&2),'bus_master':bool(word(4)&4),
            'power_d0':(word(pm+4)&3)==0 if pm else None,
            'flr_capable':bool(dword(pcie+4)&(1<<28)) if pcie else None,
            'transactions_pending':bool(word(pcie+10)&(1<<5)) if pcie else None}


def review(path: Path, expected_chain_sha256=None) -> dict:
    if not re.fullmatch(r'RTX[0-9]{5}\.LOG',path.name): raise ValueError('expected RTXnnnnn.LOG')
    pairs=records(path.read_bytes())
    scalar={}
    for key in ('probe_schema','gpu_write_capability','capture_status','capture_complete','target_handle','console_out_handle','pci_command'):
        values=[v for k,v in pairs if k==key]
        if len(values)!=1: raise ValueError('missing/duplicate capture field: '+key)
        scalar[key]=values[0]
    if scalar['probe_schema'] not in (1,2) or scalar['gpu_write_capability']!=0 or scalar['capture_status']!=0 or scalar['capture_complete']!=1:
        raise ValueError('failed/incomplete capture')
    if scalar['probe_schema']==2 and [v for k,v in pairs if k=='one_shot_status']!=[0]:
        raise ValueError('one-shot claim missing or failed')
    return review_observations(path,pairs,scalar,expected_chain_sha256)


def review_observations(path,pairs,scalar,expected_chain_sha256=None):
    """Shared entry observations only; caller validates its own log schema.

    These bytes precede a possible unlock transaction and cannot establish its
    outcome or absence of writes. The strict read-only probe gate stays above.
    """
    pci=pci_status(path.with_suffix('.PCI').read_bytes())
    if pci['command']!=scalar['pci_command']: raise ValueError('PCI snapshot/log mismatch')
    mmio={}
    for i,(key,value) in enumerate(pairs):
        if key=='mmio_offset':
            if i+1==len(pairs) or pairs[i+1][0]!='mmio_value' or value in mmio: raise ValueError('malformed MMIO observation')
            mmio[value]=pairs[i+1][1]
    required={0,0x118128,0x118234,0x110100,0x1fa824,0x1fa828,0x1183a4,0x625f04,0x1fa7c8,
              0x1fa82c,0x1fa830,0x1fa7cc,0x9a0148,0x1fa7c4,0x823804,0x823818,0x82381c,0x823820,0x824148,0x8241e0}
    blockers=[]
    if not pci['memory_decode'] or pci['bus_master']: blockers.append('probe did not have passive MMIO preconditions; do not change command bits without approval')
    if pci['power_d0'] is not True: blockers.append('D0 not confirmed')
    if pci['flr_capable'] is not True or pci['transactions_pending'] is not False: blockers.append('FLR capability/idle PCIe not confirmed')
    complete=required.issubset(mmio)
    if not complete: blockers.append('required cold registers were not captured')
    if 0 in mmio and mmio[0]!=0x193000a1: blockers.append('AD103 chip identity mismatch')
    if {0x118128,0x118234,0x110100}.issubset(mmio) and not (mmio[0x118128]&1 and mmio[0x118234]&0xff==0xff and mmio[0x110100]&0x10):
        blockers.append('cold GFW completion/halt not established')
    for offset in required.intersection(mmio):
        v=mmio[offset]
        if (v&0xffff0000)==0xbadf0000 or (v==0xffffffff and offset not in {0x1fa7cc,0x9a0148,0x1fa7c4,0x823804}):
            blockers.append(f'inaccessible/suspect register {offset:#x}')
    if mmio.get(0x1fa828,0)>>4: blockers.append('WPR2.HI.VAL is nonzero: initialized/live reservation')
    fuses,fuse_blockers=signature_fuses(mmio);blockers+=fuse_blockers
    blobs={};hashes={}
    for suffix in ('.LOG','.PCI','.ROM','.PRM'):
        p=path.with_suffix(suffix)
        if not p.exists():continue
        data=p.read_bytes();hashes[p.name]=hashlib.sha256(data).hexdigest()
        if suffix in ('.ROM','.PRM'):blobs[suffix]=data
    roms,rom_blockers=review_rom_views(blobs,expected_chain_sha256);blockers+=rom_blockers
    graph,ownership=analyze_graph(pairs)
    blockers+=['UEFI ownership: '+s for s in ownership['issues']+ownership['conflicts']]
    blockers+=['verify live Intel/NVIDIA ownership and console preservation before any detach',
               'derive/replay VRAM layout and UEFI DMA mappings',
               'identify approved Windows ESP/GPT/boot manager hash and test no-unlock handoff',
               'implement and test board-specific UEFI transaction adapter; explicit execution approval']
    return {'schema_version':1,'write_ready':False,'mmio_capture_complete':complete,'pci':pci,
            'mmio':{hex(k):hex(v) for k,v in mmio.items()},'rom_views':roms,'signature_fuses':fuses,
            'input_sha256':hashes,'graph':graph,'ownership_review':ownership,'remaining_conditions':blockers}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--windows-review',type=Path,help='offline correspondence to the reviewed Windows ESP; never a boot permission')
    p.add_argument('--rom-chain-sha256',help='independently reviewed local ROM identity; absence stays blocked')
    a=p.parse_args();report=review(a.log,a.rom_chain_sha256)
    if a.windows_review:
        raw=a.windows_review.read_bytes();windows=json.loads(raw.decode('utf-8-sig'))
        report['windows_review_sha256']=hashlib.sha256(raw).hexdigest()
        report['windows_esp_match']=match_esp(report['graph'],windows)
    result=json.dumps(report,indent=2)+'\n'
    if a.output:
        with a.output.open('x') as f:f.write(result)
    else:print(result,end='')
