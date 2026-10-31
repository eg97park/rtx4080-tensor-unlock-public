#!/usr/bin/env python3
"""Strict comparison of native Windows runs. No GPU or Windows API access."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
from measurement_context import comparison_context, validate_run_context


def read(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def load_run(directory: Path) -> tuple[dict, dict]:
    run=read(directory/'run.json')
    if run.get('schema_version') not in (1,2) or run.get('complete') is not True or run.get('event_review_required') is not False or run.get('failures'):
        raise ValueError('incomplete/failed run or events need review')
    if run.get('control_before')!=run.get('control_after') or not run.get('control_before'):
        raise ValueError('controls changed or absent')
    validate_run_context(run)
    results={}
    for case in run['cases']:
        name=case['file']
        if Path(name).name!=name or not name.startswith('case-') or not name.endswith('.json'):
            raise ValueError('invalid case path')
        path=directory/name
        if hashlib.sha256(path.read_bytes()).hexdigest()!=case['sha256']:
            raise ValueError('case hash mismatch')
        data=read(path)
        if data.get('complete') is not True or data.get('schema_version')!=1:
            raise ValueError('incomplete benchmark JSON')
        identity=tuple(data[k] for k in ('device','pci_bus','sm_count','cuda_driver','cuda_runtime','cublas','reps'))
        for item in data['results']:
            if item.get('accuracy_pass') is not True: raise ValueError('accuracy failed')
            samples=item['samples_ms']
            if len(samples)!=data['reps'] or len(samples)<3 or not all(isinstance(x,(float,int)) and math.isfinite(x) and x>0 for x in samples):
                raise ValueError('invalid timing samples')
            med=sorted(samples)[len(samples)//2]  # same upper median as native tool
            if not math.isclose(med,item['median_ms'],rel_tol=1e-7): raise ValueError('median mismatch')
            kind,mode=item['kind'],item['mode']
            if kind=='gemm':
                if mode not in ('f16_f32','bf16_f32','tf32','fp32_pedantic'): raise ValueError('unknown GEMM mode')
                shape=tuple(item[k] for k in ('m','n','k','seed'))
                if item.get('all_outputs_finite') is not True or item.get('validation_runs')!=2 or item.get('checked_per_validation',0)<1:
                    raise ValueError('incomplete accuracy checks')
                for key in ('nrmse','initial_nrmse'):
                    value=item[key]
                    if not math.isfinite(value) or not 0<=value<=(0.002 if mode=='tf32' else 0.00002):
                        raise ValueError('accuracy threshold exceeded')
                ops=2.0*item['m']*item['n']*item['k']
            elif kind=='mma_issue':
                if mode not in ('f16_f32','bf16_f32','tf32') or item.get('all_sinks_checked_each_repeat') is not True:
                    raise ValueError('incomplete MMA check')
                shape=tuple(item[k] for k in ('blocks','threads','iters','chains'))
                ops=item['blocks']*(item['threads']//32)*item['iters']*item['chains']*2*16*8*(8 if mode=='tf32' else 16)
            else: raise ValueError('unknown measurement kind')
            if not math.isclose(item['tflops'],ops/(med*1e9),rel_tol=1e-7): raise ValueError('throughput accounting mismatch')
            key=(kind,mode,*shape)
            if key in results: raise ValueError('duplicate measurement key')
            results[key]={'identity':identity,'median_ms':med,'tflops':item['tflops'],
                          'sample_cv':statistics.pstdev(samples)/statistics.mean(samples),
                          'min_ms':min(samples),'max_ms':max(samples)}
    if not results: raise ValueError('empty run')
    return run,results


def compare(before: Path, after: Path) -> dict:
    a,ar=load_run(before);b,br=load_run(after)
    for key in ('suite','exe_sha256','cublas_dlls','control_before','environment'):
        if not a.get(key) or a[key]!=b.get(key): raise ValueError('comparison control mismatch: '+key)
    if ar.keys()!=br.keys(): raise ValueError('measurement matrix differs')
    rows=[]
    for key in ar:
        x,y=ar[key],br[key]
        if x['identity']!=y['identity']: raise ValueError('runtime/device/repetition mismatch')
        rows.append({'case':key,'before':x,'after':y,'speedup':x['median_ms']/y['median_ms'],
                     'timing_noise_review':max(x['sample_cv'],y['sample_cv'])>0.05})
    return {'schema_version':1,'before_state':a['state'],'after_state':b['state'],'rows':rows,
            'measurement_context':comparison_context(a,b),
            'interpretation':'Observed issue rate and GEMM speedups are separate. measurement_context marks unrecorded or different display/Windows conditions; a ratio does not imply those conditions matched. Review telemetry/clocks/temperature and stock-unlocked-stock repeats; no fixed 2x success criterion.',
            'hardware_unlock_proven_by_this_report':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('before',type=Path);p.add_argument('after',type=Path)
    p.add_argument('--output',type=Path);args=p.parse_args()
    report=json.dumps(compare(args.before,args.after),indent=2)+'\n'
    if args.output:
        with args.output.open('x') as f:f.write(report)
    else:print(report,end='')
