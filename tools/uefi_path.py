"""Decode captured UEFI paths and match a Windows ESP candidate, offline only.

Layout follows pinned EDK2 Protocol/DevicePath.h. A GPT path match never
authenticates a boot file or authorizes LoadImage/StartImage.
"""
import re
import struct
import uuid

SIMPLE_FS='964e5b22-6459-11d2-8e39-00a0c969723b'

def decode(data: bytes) -> dict:
    if not 4<=len(data)<=4096:raise ValueError('device path length out of bounds')
    off=0;nodes=0;instances=1;instance_nodes=0;hard_drives=[];file_paths=[]
    while off<len(data) and nodes<128:
        if off+4>len(data):raise ValueError('truncated device path header')
        kind,subtype,size=struct.unpack_from('<BBH',data,off)
        if size<4 or off+size>len(data):raise ValueError('invalid device path node size')
        payload=data[off:off+size];off+=size;nodes+=1
        if kind==0x7f:
            if size!=4:raise ValueError('invalid device path end size')
            if subtype==0xff:
                if off!=len(data):raise ValueError('bytes after entire path end')
                if instances>1 and not instance_nodes:raise ValueError('empty path instance')
                return {'instances':instances,'node_count':nodes,'hard_drives':hard_drives,'file_paths':file_paths}
            if subtype!=1 or not instance_nodes:raise ValueError('invalid device path instance end')
            instances+=1;instance_nodes=0;continue
        instance_nodes+=1
        if kind==4 and subtype==1:
            if size!=42:raise ValueError('invalid hard-drive node size')
            part,start,length=struct.unpack_from('<IQQ',payload,4)
            gpt=payload[40]==2 and payload[41]==2
            hard_drives.append({'instance':instances,'partition_number':part,'start_lba':start,
                'size_lba':length,'gpt_guid':str(uuid.UUID(bytes_le=payload[24:40])) if gpt else None,
                'mbr_type':payload[40],'signature_type':payload[41]})
        elif kind==4 and subtype==4:
            if size<6 or size%2 or payload[-2:]!=b'\0\0':raise ValueError('invalid file-path node')
            name=payload[4:-2].decode('utf-16-le')
            if '\0' in name:raise ValueError('embedded NUL in file path')
            file_paths.append(name)
    raise ValueError('unterminated device path or node count exceeded')

def match_esp(graph: list[dict], windows_review: dict) -> dict:
    candidates=windows_review.get('boot_manager_candidates',[])
    if windows_review.get('administrative_queries_complete') is not True or len(candidates)!=1:
        raise ValueError('one independently reviewed Windows ESP candidate required')
    candidate=candidates[0]
    expected=str(uuid.UUID(candidate['partition_guid'].strip('{}')))
    if candidate.get('boot_manager_path','').lower()!='\\efi\\microsoft\\boot\\bootmgfw.efi' or not re.fullmatch('[a-f0-9]{64}',candidate.get('sha256','')):
        raise ValueError('missing Windows boot-file path/hash pin')
    matches=[];seen=set()
    for node in graph:
        handle=node['handle']
        if handle in seen:raise ValueError('duplicate captured handle')
        seen.add(handle)
        paths=[bytes.fromhex(v) for k,v in node['records'] if k=='device_path']
        if len(paths)>1:raise ValueError('duplicate device path on handle')
        protocols=[]
        for k,v in node['records']:
            if k=='protocol_guid':protocols.append(str(uuid.UUID(bytes_le=bytes.fromhex(v))))
        if not paths:continue
        path=decode(paths[0])
        if SIMPLE_FS not in protocols or path['instances']!=1 or path['file_paths']:continue
        if len(path['hard_drives'])==1 and path['hard_drives'][0]['gpt_guid']==expected:
            matches.append({'handle':handle,'hard_drive':path['hard_drives'][0]})
    return {'expected_partition_guid':expected,'expected_boot_manager_sha256':candidate['sha256'],
        'matched_handles':matches,'unique_partition_match':len(matches)==1,
        'boot_file_verified_in_uefi':False,'boot_ready':False,
        'remaining':'Require actual EFI file hash verification and a separately approved no-unlock handoff to the selected Windows.'}
