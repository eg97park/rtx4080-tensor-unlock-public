#!/usr/bin/env python3
"""Check the build's x64 EFI image without loading/executing it."""
import json
import struct
from pathlib import Path


def inspect(path: Path) -> dict:
    data=path.read_bytes()
    def u16(p): return struct.unpack_from('<H',data,p)[0]
    def u32(p): return struct.unpack_from('<I',data,p)[0]
    if data[:2]!=b'MZ': raise ValueError('missing DOS header')
    pe=u32(0x3c)
    if data[pe:pe+4]!=b'PE\0\0' or u16(pe+4)!=0x8664: raise ValueError('not x64 PE')
    count=u16(pe+6); opt=pe+24; size=u16(pe+20)
    if not 1<=count<=16 or size<240 or opt+size+count*40>len(data): raise ValueError('invalid PE bounds')
    if u16(opt)!=0x20b or u16(opt+68)!=10: raise ValueError('not a PE32+ EFI application')
    if u32(pe+8): raise ValueError('nondeterministic PE timestamp')
    # No imported OS/library services: all UEFI services arrive via protocols.
    if any(u32(opt+112+8*i+j) for i in (1,12) for j in (0,4)): raise ValueError('unexpected import/IAT directory')
    entry=u32(opt+16); executable_entry=False; sections=[]
    for i in range(count):
        off=opt+size+i*40
        name=data[off:off+8].split(b'\0')[0].decode('ascii')
        virtual=u32(off+8); addr=u32(off+12); raw=u32(off+16); pos=u32(off+20); flags=u32(off+36)
        if raw and (pos<opt+size+count*40 or pos+raw>len(data)): raise ValueError('section outside file')
        if flags & 0x20000000 and flags & 0x80000000: raise ValueError('writable executable section')
        if flags & 0x20000000 and addr<=entry<addr+virtual: executable_entry=True
        sections.append({'name':name,'bytes':raw,'flags':hex(flags)})
    if not executable_entry: raise ValueError('entry outside executable section')
    if not u32(opt+112+8*5) or not u32(opt+112+8*5+4): raise ValueError('relocations required')
    return {'machine':'x86_64','subsystem':'EFI application','imports':False,'executed':False,'sections':sections}


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',type=Path)
    print(json.dumps(inspect(p.parse_args().file),indent=2))
