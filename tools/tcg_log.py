#!/usr/bin/env python3
"""Offline TCG2 boot log and our unsigned EFI measurement comparison.

Format: Microsoft Tbsi_Get_TCG_Log_Ex / TCG PC Client firmware profile.
PE hashing: pinned EDK2 MeasureBootPeCoff.c. This deliberately accepts only
our contiguous, unsigned x64 EFI layout; it is not a general Authenticode tool.
No TPM access, PCR replay/quote, hardware-reset inference or attestation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from uefi_path import decode


class Reader:
    def __init__(self,data):self.data=data;self.pos=0
    def take(self,n):
        if n<0 or n>len(self.data)-self.pos:raise ValueError('truncated TCG record')
        value=self.data[self.pos:self.pos+n];self.pos+=n;return value
    def u32(self):return struct.unpack('<I',self.take(4))[0]
    def u16(self):return struct.unpack('<H',self.take(2))[0]


def parse(data):
    if not 32<=len(data)<=16*1024*1024:raise ValueError('TCG file size out of bounds')
    r=Reader(data);pcr,event=r.u32(),r.u32();digest=r.take(20);spec=Reader(r.take(r.u32()))
    if (pcr,event,digest)!=(0,3,bytes(20)) or spec.take(16)!=b'Spec ID Event03\0':
        raise ValueError('expected TCG2 Spec ID Event03')
    platform=spec.u32();minor,major,errata,uintn=spec.take(4)
    count=spec.u32()
    if major!=2 or uintn not in (1,2) or not 1<=count<=16:raise ValueError('unsupported Spec ID geometry')
    algorithms={};known={4:20,11:32,12:48,13:64,18:32}
    for _ in range(count):
        alg,size=spec.u16(),spec.u16()
        if alg in algorithms or not 1<=size<=64 or (alg in known and size!=known[alg]):
            raise ValueError('invalid digest algorithm table')
        algorithms[alg]=size
    spec.take(spec.take(1)[0])
    if spec.pos!=len(spec.data):raise ValueError('Spec ID trailing data')
    events=[]
    while r.pos<len(data):
        if len(events)>=100000:raise ValueError('too many TCG events')
        offset=r.pos;pcr,event,count=r.u32(),r.u32(),r.u32()
        if pcr>23 or not 1<=count<=len(algorithms):raise ValueError('event PCR/digest count out of bounds')
        digests={}
        for _ in range(count):
            alg=r.u16()
            if alg not in algorithms or alg in digests:raise ValueError('unknown/duplicate event digest')
            digests[alg]=r.take(algorithms[alg]).hex()
        size=r.u32()
        if size>1024*1024:raise ValueError('oversize event payload')
        payload=r.take(size)
        entry={'index':len(events),'offset':offset,'pcr':pcr,'type':hex(event),
               'digests':{hex(k):v for k,v in digests.items()},'event_bytes':size}
        if event in (0x80000003,0x80000004,0x80000005):
            if size<32:raise ValueError('truncated UEFI image event')
            base,image_size,link,path_size=struct.unpack_from('<4Q',payload)
            if path_size!=size-32:raise ValueError('UEFI image path size mismatch')
            entry['image']={'base':hex(base),'size':image_size,'link_address':hex(link),
                'device_path_hex':payload[32:].hex(),'path':decode(payload[32:])}
        events.append(entry)
    return {'platform_class':platform,'spec_version':[major,minor,errata],
            'algorithm_sizes':{hex(k):v for k,v in algorithms.items()},'events':events,'complete':True}


def efi_measurement(data):
    if len(data)<256 or data[:2]!=b'MZ':raise ValueError('not PE')
    pe=struct.unpack_from('<I',data,60)[0]
    if pe>len(data)-264 or data[pe:pe+4]!=b'PE\0\0':raise ValueError('bad PE header')
    machine,count=struct.unpack_from('<HH',data,pe+4);opt=pe+24;size=struct.unpack_from('<H',data,pe+20)[0]
    if machine!=0x8664 or not 1<=count<=16 or size<240 or opt+size+40*count>len(data):raise ValueError('unsupported PE layout')
    if struct.unpack_from('<H',data,opt)[0]!=0x20b or struct.unpack_from('<H',data,opt+68)[0]!=10:
        raise ValueError('expected PE32+ EFI application')
    header_size=struct.unpack_from('<I',data,opt+60)[0];directories=struct.unpack_from('<I',data,opt+108)[0]
    if not 5<=directories<=16 or not opt+size+40*count<=header_size<=len(data):raise ValueError('invalid PE header size')
    cert=opt+112+4*8
    if struct.unpack_from('<II',data,cert)!=(0,0):raise ValueError('signed images outside this tool scope')
    spans=[(0,opt+64),(opt+68,cert),(cert+8,header_size)];sections=[]
    for i in range(count):
        raw,pos=struct.unpack_from('<II',data,opt+size+40*i+16)
        if raw:sections.append((pos,raw))
    consumed=header_size
    for pos,n in sorted(sections):
        if pos!=consumed or n>len(data)-pos:raise ValueError('noncontiguous/overlapping section')
        spans.append((pos,pos+n));consumed+=n
    if consumed!=len(data):raise ValueError('overlay outside this tool scope')
    result={}
    for name in ('sha1','sha256','sha384','sha512'):
        h=hashlib.new(name)
        for begin,end in spans:h.update(data[begin:end])
        result[name]=h.hexdigest()
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path)
    p.add_argument('--efi',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();data=a.log.read_bytes();binary=a.efi.read_bytes();r=parse(data);hashes=efi_measurement(binary)
    names={'0x4':'sha1','0xb':'sha256','0xc':'sha384','0xd':'sha512'}
    matches=[]
    for e in r['events']:
        if e['pcr']!=4 or e['type']!='0x80000003':continue
        matched=[names[k] for k,v in e['digests'].items() if k in names and hashes[names[k]]==v]
        if matched:matches.append({'index':e['index'],'algorithms':matched,'image':e.get('image')})
    r.update(log_sha256=hashlib.sha256(data).hexdigest(),efi_file_sha256=hashlib.sha256(binary).hexdigest(),
        efi_measured_hashes=hashes,matching_pcr4_application_events=matches,
        gpu_reset_absence_proven=False,cryptographic_attestation_performed=False,
        interpretation='Image-measurement correlation only. Presence links image loading to the reported boot log; absence alone does not prove a restart.')
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print('Events:',len(r['events']),'matching application measurements:',len(matches));print(a.output)


if __name__=='__main__':main()
