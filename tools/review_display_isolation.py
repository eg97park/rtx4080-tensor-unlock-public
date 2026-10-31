#!/usr/bin/env python3
"""Replay saved CCD isolation evidence. No Windows API, GPU or settings access."""
import argparse
import hashlib
import json
from pathlib import Path
from compare_bench import read
from review_unlock import review_transaction


def paths(snapshot):
    if snapshot.get('QueryFlags') != 82 or not 1 <= len(snapshot.get('Paths', [])) <= 2:
        raise ValueError('expected active virtual-mode-aware CCD snapshot')
    result = {}
    for path in snapshot['Paths']:
        native = path['Native']
        adapter = path['SourceAdapterName']
        name = adapter['Name'].upper()
        kind = ('intel' if name.startswith('\\\\?\\PCI#VEN_8086&DEV_7D67&') else
                'basic' if name.startswith('\\\\?\\ROOT#BASICDISPLAY#0000#') else None)
        target = path['TargetName']
        if (kind is None or kind in result or adapter['Status'] != 0 or
            path['TargetAdapterName']['Status'] != 0 or
            path['TargetAdapterName']['Name'].upper() != name or target['Status'] != 0 or
            target['Name'] != 'Odyssey G70D' or
            not target['MonitorPath'].upper().startswith('\\\\?\\DISPLAY#SAME069#') or
            native['Flags'] != 9 or native['Target']['Available'] != 1):
            raise ValueError('unknown/duplicate adapter or monitor')
        source, dest = native['Source'], native['Target']
        if source['Adapter'] != dest['Adapter']:
            raise ValueError('source/target adapters differ')
        indices = [source['ModeIndex'] >> 16, dest['ModeIndex'] >> 16, dest['ModeIndex'] & 65535]
        if indices[:2] != [path['SourceModeIndex'], path['TargetModeIndex']]:
            raise ValueError('inconsistent CCD mode indices')
        modes = []
        for index, kind_id in zip(indices, (1, 2, 3)):
            if not 0 <= index < len(snapshot['Modes']):
                raise ValueError('CCD mode outside table')
            mode = snapshot['Modes'][index]
            if (mode['Type'] != kind_id or mode['Adapter'] != source['Adapter'] or
                mode['Id'] != (source['Id'] if kind_id == 1 else dest['Id'])):
                raise ValueError('CCD mode association mismatch')
            modes.append({k: mode[k] for k in ('Type', 'Id', 'Adapter', *(f'Raw{i}' for i in range(6)))})
        refresh = dest['Refresh']
        if refresh['Numerator'] <= 0 or refresh['Denominator'] <= 0:
            raise ValueError('invalid refresh')
        source_mode = snapshot['Modes'][indices[0]]
        result[kind] = {
            'adapter': name, 'monitor': target['MonitorPath'].upper(),
            'source': {k: v for k, v in source.items() if k != 'ModeIndex'},
            'target': {k: v for k, v in dest.items() if k != 'ModeIndex'},
            'clone_group': source['ModeIndex'] & 65535, 'modes': modes,
            'width': source_mode['SourceWidth'], 'height': source_mode['SourceHeight'],
            'hz': refresh['Numerator'] / refresh['Denominator']}
    if 'intel' not in result:
        raise ValueError('Intel display absent')
    return result


def review(before, during, after):
    a, b, c = (paths(s) for s in (before, during, after))
    if set(a) != {'intel', 'basic'} or set(b) != {'intel'} or set(c) != set(a):
        raise ValueError('expected Intel+BasicDisplay -> Intel -> original pair')
    if a['intel'] != b['intel'] or a != c:
        raise ValueError('Intel mode changed or original topology was not restored')
    return {'schema_version': 1, 'gpu_access': False, 'active_path_counts': [2, 1, 2],
            'intel_mode_preserved': True, 'original_paths_restored': True,
            'intel': {k: b['intel'][k] for k in ('width', 'height', 'hz')},
            'basic': {k: a['basic'][k] for k in ('width', 'height', 'hz')},
            'visual_symptoms_proven_by_ccd': False, 'root_cause_proven': False,
            'limitations': ['Snapshots do not record visible artifacts or framebuffer ownership.',
                            'NVIDIA Stop, firmware execution and FLR were not isolated by this desktop trial.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--unlock-journal', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    inputs = [args.directory / name for name in ('before.json', 'during.json', 'after.json')]
    result = review(*(read(p) for p in inputs))
    if args.unlock_journal:
        journal = review_transaction(args.unlock_journal)
        before = journal['display_entry_snapshot']
        after = journal['unlock_transaction']['display_post_lease_and_core_snapshots']
        if not before or not after:
            raise ValueError('journal has no complete display guard snapshots')
        snapshots = [[(k, v) for k, v in s if k != 'display_snapshot_phase'] for s in before + after]
        result['uefi'] = {'persisted_phases': ['pre-stop', 'post-lease', 'post-core'],
                          'metadata_equal': all(s == snapshots[0] for s in snapshots),
                          'pre_start_snapshot_persisted': False,
                          'windows_framebuffer_ownership_observed': False}
        inputs.append(args.unlock_journal)
    result['input_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print('Saved-data display transition verified. Root cause remains unproven.')


if __name__ == '__main__':
    main()
