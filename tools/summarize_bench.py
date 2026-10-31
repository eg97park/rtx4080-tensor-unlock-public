#!/usr/bin/env python3
"""Summarize a preserved Windows run without running a GPU workload."""
import argparse
import csv
import datetime
import hashlib
import json
import math
from pathlib import Path
from compare_bench import load_run,read
from measurement_context import instant, same_context, validate_run_context

def validate_post_health(path: Path, run_file: Path, run: dict) -> None:
    """A healthy flag is useful only when bound to this exact completed run."""
    health=read(path)
    if (health.get('schema_version')!=1 or health.get('healthy') is not True or
        health.get('gpu_workload_started') is not False or health.get('errors')!=[] or
        health.get('events')!=[]):
        raise ValueError('post-health report failed or incomplete')
    if health.get('run_sha256')!=hashlib.sha256(run_file.read_bytes()).hexdigest():
        raise ValueError('post-health report belongs to a different run')
    if health.get('control')!=run['control_after']:
        raise ValueError('post-health control mismatch')
    baseline=validate_run_context(run)
    if baseline is not None:
        if health.get('context_verified') is not True:
            raise ValueError('post-health context not verified')
        same_context(baseline,health.get('context'))
        if instant(health['context']['captured_utc'])<instant(run['end_utc']):
            raise ValueError('post-health context predates run completion')
    try:
        start,end=instant(run['start_utc']),instant(run['end_utc'])
        event_start,event_end=instant(health['event_start_utc']),instant(health['event_end_utc'])
    except (KeyError,TypeError) as error:
        raise ValueError('incomplete health time window') from error
    if end<start or event_start>start or event_end<end:
        raise ValueError('post-health event window does not cover the run')
    displays=health.get('display')
    if not isinstance(displays,list):raise ValueError('missing post-health device observations')
    for prefix in ('PCI\\VEN_10DE&DEV_2704&SUBSYS_15007377', 'PCI\\VEN_8086&DEV_7D67'):
        devices=[d for d in displays if str(d.get('PNPDeviceID','')).upper().startswith(prefix)]
        if len(devices)!=1 or devices[0].get('ConfigManagerErrorCode')!=0:
            raise ValueError('post-health device identity or status mismatch')

def summarize(directory: Path) -> dict:
    run,results=load_run(directory)
    expected={'smoke':(3,11),'standard':(7,27)}
    if run['suite'] not in expected or (len(run['cases']),len(results))!=expected[run['suite']]:
        raise ValueError('unexpected suite coverage')
    records=list(csv.reader((directory/'telemetry.csv').read_text(encoding='utf-8-sig').splitlines()))
    if not records or any(len(r)!=7 for r in records):raise ValueError('missing/malformed telemetry')
    telemetry={}
    for name,column in [('temperature_c',2),('power_w',3),('sm_clock_mhz',4),('memory_clock_mhz',5),('utilization_percent',6)]:
        values=[];unavailable=0
        for row in records:
            try:value=float(row[column])
            except ValueError:unavailable+=1;continue
            if not math.isfinite(value):unavailable+=1;continue
            values.append(value)
        telemetry[name]={'sampled_min':min(values) if values else None,'sampled_max':max(values) if values else None,
                         'unavailable_samples':unavailable}
    accuracy=[]
    for case in run['cases']:
        data=read(directory/case['file'])
        for row in data['results']:
            if row['kind']=='gemm':
                accuracy.append({k:row[k] for k in ('mode','m','n','k','seed','checked_per_validation','validation_runs',
                                                   'all_outputs_finite','initial_nrmse','nrmse')})
    health_files=sorted(directory.glob('post-health-*.json'))
    for path in health_files:
        validate_post_health(path,directory/'run.json',run)
    return {'schema_version':1,'run_directory':str(directory),'state':run['state'],'suite':run['suite'],
        'measurement_context':validate_run_context(run),
        'exe_sha256':run['exe_sha256'],'case_count':len(run['cases']),'validated_result_count':len(results),
        'elapsed_seconds':(datetime.datetime.fromisoformat(run['end_utc'])-datetime.datetime.fromisoformat(run['start_utc'])).total_seconds(),
        'rows':[{'case':list(key),**value,'timing_noise_review':value['sample_cv']>0.05} for key,value in results.items()],
        'gemm_accuracy':accuracy,'telemetry_samples':len(records),'telemetry':telemetry,
        'post_health_passed':True if health_files else None,
        'input_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.is_file()},
        'limitations':['Telemetry samples do not establish instantaneous peaks.',
                       'Context checkpoints do not continuously monitor display changes or prove the absence of visible artifacts.',
                       'A single suite does not establish repeatability, sustained stability or hardware unlock state.',
                       'Review clock ramp and rows marked timing_noise_review before interpreting future speedups.',
                       'Small GEMMs check every output; larger GEMMs check deterministic samples and all-output finiteness.']}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    result=summarize(args.directory)
    with args.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(f"{result['suite']}: {result['validated_result_count']} validated results, {result['elapsed_seconds']:.2f} s; summary saved.")
