#!/usr/bin/env python3
"""Self-contained public CPU tests. No firmware, private captures or GPU access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from bootstrap import header_digest
from build import check_vendor

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', help='also compile/run CPU C/C++ mocks using GCC and pinned headers')
    args = parser.parse_args()
    check_vendor()
    out = ROOT / 'build/public-tests'
    out.mkdir(parents=True, exist_ok=True)
    jobs = [('python', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py', '-v'])]
    if args.native:
        headers = ROOT / '.local/references/edk2/MdePkg/Include'
        expected = json.loads((ROOT / 'config/edk2.json').read_text())['include_tree_sha256']
        if header_digest(headers) != expected:
            raise ValueError('Pinned headers missing or changed; run tools/bootstrap.py first')
        vendor = ROOT / 'third_party/gpu-unlock-ada/windows/ad104-msi'
        flags = ['-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror', '-g', '-O1',
                 '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                 '-I', str(headers), '-I', str(headers / 'X64'), '-I', 'src/efi', '-I', str(vendor),
                 '-I', 'third_party/gpu-unlock-ada/kernel/gpu_unlock']
        sources = {
            'probe': ['tests/test_probe.c', str(vendor / 'sha256.c')],
            'dma': ['tests/test_dma.c', 'src/efi/dma.c'],
            'display': ['tests/test_display.c', 'src/efi/display.c'],
            'handoff': ['tests/test_handoff.c', 'src/efi/handoff.c', str(vendor / 'sha256.c')],
            'session': ['tests/test_session.c', 'src/efi/session.c']}
        for name, files in sources.items():
            exe = out / name
            jobs.extend([(name + '-compile', ['gcc', *flags, *files, '-o', str(exe)]),
                         (name, [str(exe)])])
        exe = out / 'reference'
        jobs.extend([('reference-compile', ['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-O1',
                                          '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                                          'tests/test_reference.cpp', '-o', str(exe)]),
                     ('reference', [str(exe)])])
    report = {'schema_version': 1, 'gpu_access': False, 'firmware_executed': False,
              'private_inputs_required': False, 'native_tests': args.native,
              'jobs': [], 'complete': False}
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    for name, command in jobs:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True)
        log = out / (name + '.log')
        log.write_bytes(result.stdout + result.stderr)
        report['jobs'].append({'name': name, 'exit_code': result.returncode,
                               'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{name}: exit {result.returncode}', flush=True)
        if result.returncode:
            print(log.read_text(errors='replace')[-6000:])
            raise SystemExit(1)
    report['complete'] = True
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Public CPU suite passed. No hardware result is implied.')


if __name__ == '__main__':
    main()
