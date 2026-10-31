#!/usr/bin/env python3
"""Review UNLOCK entry or final journals offline; never prove Windows outcomes."""
import argparse
import hashlib
import json
from pathlib import Path
from review_capture import records,review_observations

DISPLAY_SCALARS=('handle','interface','mode_pointer','info_pointer','console','console_interface',
    'framebuffer_base','framebuffer_bytes','info_bytes','pci_attributes','pci_interface','mode','max_mode',
    'info_version','width','height','pixel_format','stride','red_mask','green_mask','blue_mask','reserved_mask')

def display_snapshot_pairs(pairs,stages):
    """Strict envelope only; addresses/values are observations, not boot proof."""
    remaining=list(pairs);out=[]
    for stage in stages:
        expected=['display_snapshot_phase','display_snapshot_status',
                  *('display_'+x for x in DISPLAY_SCALARS),'display_device_path','display_pci_path',
                  *(['display_pci_offset','display_pci_word']*16)]
        part=remaining[:len(expected)];remaining=remaining[len(expected):]
        if [k for k,v in part]!=expected or part[:2]!=[('display_snapshot_phase',stage),('display_snapshot_status',0)]:
            raise ValueError('malformed display snapshot envelope')
        for k,v in part:
            if k.endswith('_path'):
                if not isinstance(v,bytes) or not 4<=len(v)<=256:raise ValueError('invalid display path bytes')
            elif not isinstance(v,int):raise ValueError('invalid display scalar')
        pci=part[-32:]
        if [v for k,v in pci[::2]]!=list(range(0,64,4)) or any(v>0xffffffff for k,v in pci[1::2]):
            raise ValueError('invalid display PCI header')
        out.append([(k,v.hex() if isinstance(v,bytes) else hex(v)) for k,v in part])
    if remaining:raise ValueError('trailing display records')
    return out


def review_entry(path,expected_chain_sha256=None):
    return _review_entry(path,records(path.read_bytes()),expected_chain_sha256)


def _review_entry(path,pairs,expected_chain_sha256=None):
    if any(k in ('probe_schema','readiness_schema') for k,_ in pairs):
        raise ValueError('mixed probe/unlock schemas')
    scalar={}
    for key in ('unlock_schema','gpu_write_capability','unlock_preflight_status',
                'target_handle','console_out_handle','pci_command'):
        values=[v for k,v in pairs if k==key]
        if len(values)!=1 or not isinstance(values[0],int):
            raise ValueError('missing/duplicate unlock field: '+key)
        scalar[key]=values[0]
    if (scalar['unlock_schema'],scalar['gpu_write_capability'],scalar['unlock_preflight_status'])!=(1,1,0):
        raise ValueError('unsupported or failed unlock entry capture')
    phases=[v for k,v in pairs if k=='unlock_phase']
    selected=[v for k,v in pairs if k=='unlock_user_selected']
    if phases not in ([],[3]) or selected not in ([],[1]) or (phases and selected!=[1]):
        raise ValueError('contradictory or later-stage log outside entry-only review')
    report=review_observations(path,pairs,scalar,expected_chain_sha256)
    display=[(k,v) for k,v in pairs if k.startswith('display_')]
    report['display_entry_snapshot']=display_snapshot_pairs(display,[0]) if display else None
    report['unlock_entry']={
        'scope':'Pre-transaction observations only; not a read-only-probe execution.',
        'preflight_reported_success':True,'user_selected_recorded':selected==[1],
        'windows_image_load_recorded':phases==[3],
        'last_persisted_phase':phases[-1] if phases else None,
        'gpu_writes_executed':None,'firmware_executed':None,'flr_executed':None,
        'failure_step':None,'failure_status':None,'unlock_success_confirmed':False,
        'limitation':'No failure journal after LoadImage; lack of later records does not prove no GPU mutation.'}
    return report


def review_transaction(path,expected_chain_sha256=None):
    """Separate the fixed journal envelope from untrusted plaintext core output.

    The journal precedes a fresh hardware check and StartImage. Even a complete
    journal cannot establish either of those subsequent operations succeeded.
    """
    raw=path.read_bytes()
    if len(raw)>16*1024*1024:raise ValueError('capture log too large')
    raw=raw.replace(b'\r\n',b'\n')
    marker=b'unlock_phase=0x0000000000000006\n'
    if raw.count(marker)!=1:raise ValueError('missing/duplicate final journal')
    entry,tail=raw.split(marker)
    if not entry.endswith(b'\n'):raise ValueError('misaligned final journal')
    result=_review_entry(path,records(entry),expected_chain_sha256)
    if result['unlock_entry']['last_persisted_phase']!=3:
        raise ValueError('missing preceding loaded-image journal')
    fields={'core_result':0,'dma_empty':1,'flr_count':1,'gpu_recovery_verified':1,
            'core_log_truncated':0,'core_log_format_rejected':0}
    for key,value in fields.items():
        line=f'{key}=0x{value:016x}\n'.encode('ascii')
        if not tail.startswith(line):raise ValueError('failed/malformed final field: '+key)
        tail=tail[len(line):]
    display=None
    begin=b'display_guard_schema=0x0000000000000001\n'
    finish=b'display_guard_end=0x0000000000000001\n'
    if tail.startswith(begin):
        if tail.count(begin)!=1 or tail.count(finish)!=1 or not result['display_entry_snapshot']:
            raise ValueError('incomplete display guard journal')
        block,tail=tail[len(begin):].split(finish)
        display=display_snapshot_pairs(records(block),[1,2])
    elif result['display_entry_snapshot']:
        raise ValueError('display baseline without final snapshots')
    end=b'unlock_windows_start_intent=0x0000000000000001\n'
    if not tail.endswith(end) or tail.count(end)!=1:
        raise ValueError('missing/duplicate/trailing start intent')
    core=tail[:-len(end)]
    if not core or len(core)>65536 or not core.endswith(b'\n'):
        raise ValueError('missing/truncated/oversized core log')
    if any(c!=10 and not 32<=c<=126 for c in core):
        raise ValueError('non-printable core log')
    reserved=tuple((k+'=').encode() for k in (*fields,'unlock_phase','unlock_windows_start_intent','unlock_schema'))+(b'display_',)
    if any(line.startswith(reserved) for line in core.splitlines()):
        raise ValueError('structured journal record inside core text')
    result['unlock_entry']['scope']='Pre-transaction observations extracted from a final journal.'
    result['unlock_transaction']={
        'last_persisted_phase':6,'final_journal_reports_success':True,**fields,
        'core_text':core.decode('ascii'),'core_text_sha256':hashlib.sha256(core).hexdigest(),
        'windows_start_intent_recorded':True,'windows_handoff_proven':False,
        'windows_unlock_retention_proven':False,'performance_gain_proven':False,
        'stability_proven':False,
        'display_post_lease_and_core_snapshots':display,
        'limitation':'Journal claims only. Core text is preserved, not interpreted as structured proof. Correlate build, measured boot, Windows diagnostics and user observations separately.'}
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path)
    p.add_argument('--transaction',action='store_true',help='Require a complete final journal; entry-only default stays strict')
    p.add_argument('--rom-chain-sha256',help='independently reviewed local ROM identity; absence stays blocked')
    p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    result=review_transaction(a.log,a.rom_chain_sha256) if a.transaction else review_entry(a.log,a.rom_chain_sha256)
    result['reviewer_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with a.output.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    print(a.output)


if __name__=='__main__':main()
