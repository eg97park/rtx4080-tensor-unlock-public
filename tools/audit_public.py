#!/usr/bin/env python3
"""Publication aid: audit tracked source and Git metadata; never upload anything."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import zipfile
import hashlib

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {'.local', '.conda', '.venv', 'build', 'dist', '__pycache__'}
PUBLIC_IDENTITY = 'Eungyu Park <ekpark97.dev@gmail.com>'
# Previously reviewed export identity can remain in local reflogs/old objects.
REVIEWED_IDENTITIES = {PUBLIC_IDENTITY, 'RTX 4080 Research Contributors <contributors@example.invalid>'}
FORBIDDEN_NAMES = {'private_board_pins.h', '.gitmodules', '.gitattributes'}
FORBIDDEN_SUFFIXES = {'.efi', '.rom', '.bin', '.exe', '.dll', '.obj', '.o', '.pdb', '.etl', '.dmp', '.zip', '.7z'}
PATTERNS = {
    'user-home-path': re.compile(r'(?:/home/|/Users/|[A-Za-z]:\\Users\\)[A-Za-z0-9_.-]+', re.I),
    'personal-wsl-path': re.compile(r'\\\\wsl(?:\.localhost|\$)\\[^\s"\']+\\home\\', re.I),
    'machine-name': re.compile(r'\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{3,}\b', re.I),
    'recovery-password': re.compile(r'\b[0-9]{6}(?:-[0-9]{6}){7}\b'),
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'access-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b')}


def findings(text, markers=()):
    # Also recognize escaped Windows paths and byte-array representations of pins.
    normalized = re.sub(r'\\+', lambda _: chr(92), text)
    byte_arrays = ''.join(re.findall(r'0x([0-9a-fA-F]{2})(?![0-9a-fA-F])', text)).lower()
    problems = [name for name, pattern in PATTERNS.items() if pattern.search(text) or pattern.search(normalized)]
    # The owner explicitly chose this name/email for public attribution. Only
    # those exact strings are exempt from local private-marker matching; generic
    # path/key/token checks above still inspect the complete original text.
    marker_text, marker_normalized = text, normalized
    for approved in (PUBLIC_IDENTITY.split(' <')[0], PUBLIC_IDENTITY.split('<')[1][:-1]):
        marker_text = marker_text.replace(approved, '')
        marker_normalized = marker_normalized.replace(approved, '')
    if any(marker.casefold() in marker_text.casefold() or marker.casefold() in marker_normalized.casefold() or
           (re.fullmatch(r'[0-9a-fA-F]{64}', marker) and marker.lower() in byte_arrays) for marker in markers):
        problems.append('private-marker')
    return problems


def audit(root, markers=(), archive=None, release=False):
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    names = [n for n in names if n]
    if not names:
        raise ValueError('No tracked/staged files to review')
    errors = []
    def inspect_blob(name, data, location):
        if Path(name).name in FORBIDDEN_NAMES or any(p in FORBIDDEN_PARTS for p in Path(name).parts) or Path(name).suffix.lower() in FORBIDDEN_SUFFIXES or Path(name).name.startswith('.env'):
            errors.append({'file': name, 'reason': 'forbidden-path-or-type', 'location': location})
            return
        try:
            text = data.decode('utf-8-sig')
        except UnicodeDecodeError:
            errors.append({'file': name, 'reason': 'non-text-content', 'location': location})
            return
        for reason in findings(name + '\n' + text, markers):
            errors.append({'file': name, 'reason': reason, 'location': location})
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file():
            errors.append({'file': name, 'reason': 'forbidden-path-or-type'})
            continue
        inspect_blob(name, path.read_bytes(), 'worktree')
    # Review the bytes Git would actually publish, including staged content that
    # differs from a subsequently cleaned working copy and older deleted files.
    seen = set()
    def inspect_entries(raw, location):
        for entry in raw.split(b'\0'):
            if not entry:
                continue
            meta, encoded_name = entry.split(b'\t', 1)
            fields = meta.decode().split()
            mode, oid = fields[0], fields[1] if location == 'index' else fields[2]
            name = encoded_name.decode()
            if (name, oid) in seen:
                continue
            seen.add((name, oid))
            if mode not in ('100644', '100755'):
                errors.append({'file': name, 'reason': 'non-regular-git-object', 'location': location})
                continue
            inspect_blob(name, subprocess.check_output(['git', 'cat-file', 'blob', oid], cwd=root), location)
    inspect_entries(subprocess.check_output(['git', 'ls-files', '--stage', '-z'], cwd=root), 'index')
    # Do not silently audit only the tip's author and overlook earlier history.
    head = subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, capture_output=True)
    if head.returncode == 0:
        for commit in subprocess.check_output(['git', 'rev-list', '--all'], cwd=root).decode().splitlines():
            inspect_entries(subprocess.check_output(['git', 'ls-tree', '-rz', commit], cwd=root), 'history')
        history = subprocess.check_output(['git', 'log', '--all', '--format=%an%n%ae%n%cn%n%ce%n%B'], cwd=root).decode()
        for reason in findings(history, markers):
            errors.append({'file': '<git-history-metadata>', 'reason': reason})
        authors = subprocess.check_output(['git', 'log', '--all', '--format=%an <%ae>%n%cn <%ce>'], cwd=root).decode().splitlines()
        if any(author not in REVIEWED_IDENTITIES for author in authors):
            errors.append({'file': '<git-history-metadata>', 'reason': 'unreviewed-author-or-committer'})
    # Inspect tag messages/taggers, all refs, dangling/staged Git objects, and
    # local metadata too. Ordinary push omits some of these; copying .git does not.
    refs = subprocess.check_output(['git', 'for-each-ref', '--format=%(refname)'], cwd=root).decode()
    for reason in findings(refs, markers):
        errors.append({'file': '<git-refs>', 'reason': reason})
    object_rows = subprocess.check_output(['git', 'cat-file', '--batch-all-objects',
        '--batch-check=%(objectname) %(objecttype)'], cwd=root).decode().splitlines()
    for row in object_rows:
        oid, kind = row.split()
        if kind == 'tree':
            raw = subprocess.check_output(['git', 'ls-tree', '-rz', oid], cwd=root)
            inspect_entries(raw, 'object-store')
            continue
        data = subprocess.check_output(['git', 'cat-file', kind, oid], cwd=root)
        try:
            content = data.decode('utf-8-sig')
        except UnicodeDecodeError:
            errors.append({'file': '<git-object>', 'object': oid, 'reason': 'non-text-content'})
            continue
        for reason in findings(content, markers):
            errors.append({'file': '<git-object>', 'object': oid, 'reason': reason})
        if kind in ('commit', 'tag'):
            header = content.split('\n\n', 1)[0]
            keys = ('author ', 'committer ') if kind == 'commit' else ('tagger ',)
            for key in keys:
                identities = [line[len(key):].rsplit(' ', 2)[0] for line in header.splitlines() if line.startswith(key)]
                if len(identities) != 1 or identities[0] not in REVIEWED_IDENTITIES:
                    errors.append({'file': '<git-object>', 'object': oid, 'reason': 'unreviewed-git-identity'})
    gitdir = Path(subprocess.check_output(['git', 'rev-parse', '--absolute-git-dir'], cwd=root).decode().strip())
    metadata_files = [gitdir / name for name in ('config', 'COMMIT_EDITMSG', 'description', 'packed-refs', 'FETCH_HEAD', 'ORIG_HEAD')]
    metadata_files += list((gitdir / 'logs').rglob('*'))
    for path in metadata_files:
        if path.is_file():
            for reason in findings(path.read_text(errors='replace'), markers):
                errors.append({'file': '<local-git-metadata>', 'reason': reason})
    if release:
        if head.returncode:
            errors.append({'file': '<release>', 'reason': 'no-commit'})
        if head.returncode == 0:
            identities = subprocess.check_output(['git', 'show', '-s', '--format=%an <%ae>%n%cn <%ce>', 'HEAD'], cwd=root).decode().splitlines()
            if identities != [PUBLIC_IDENTITY, PUBLIC_IDENTITY]:
                errors.append({'file': '<release>', 'reason': 'unexpected-release-identity'})
        if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root):
            errors.append({'file': '<release>', 'reason': 'dirty-or-untracked-worktree'})
    archive_review = None
    if archive is not None:
        if head.returncode:
            errors.append({'file': '<archive>', 'reason': 'no-commit-to-compare'})
        else:
            expected = {}
            for entry in subprocess.check_output(['git', 'ls-tree', '-rz', 'HEAD'], cwd=root).split(b'\0'):
                if entry:
                    meta, name = entry.split(b'\t', 1)
                    expected[name.decode()] = meta.decode().split()[2]
            try:
                with zipfile.ZipFile(archive) as bundle:
                    members = bundle.infolist()
                    names_in_zip = [member.filename for member in members if not member.is_dir()]
                    if len(names_in_zip) != len(set(names_in_zip)) or set(names_in_zip) != set(expected):
                        errors.append({'file': '<archive>', 'reason': 'archive-file-set-mismatch'})
                    for member in members:
                        if member.is_dir():
                            if member.filename != './' and not any(n.startswith(member.filename) for n in expected):
                                errors.append({'file': '<archive>', 'reason': 'unexpected-archive-directory'})
                            continue
                        if member.filename not in expected:
                            continue
                        data = bundle.read(member)
                        reference = subprocess.check_output(['git', 'cat-file', 'blob', expected[member.filename]], cwd=root)
                        if data != reference or (member.external_attr >> 16) & 0o170000 not in (0, 0o100000):
                            errors.append({'file': member.filename, 'reason': 'archive-content-or-type-mismatch'})
                        inspect_blob(member.filename, data, 'archive')
                        for reason in findings((member.comment + member.extra).decode('latin1'), markers):
                            errors.append({'file': '<archive-metadata>', 'reason': reason})
                    for reason in findings(bundle.comment.decode('latin1'), markers):
                        errors.append({'file': '<archive-metadata>', 'reason': reason})
                archive_review = {'files': len(names_in_zip), 'sha256': hashlib.sha256(Path(archive).read_bytes()).hexdigest()}
            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
                errors.append({'file': '<archive>', 'reason': 'unreadable-archive'})
    return {'schema_version': 2, 'tracked_files': len(names), 'git_path_objects_reviewed': len(seen),
            'all_git_objects_reviewed': len(object_rows), 'archive': archive_review,
            'release_cleanliness_required': release, 'passed': not errors, 'findings': errors,
            'limitation': 'Heuristic scan, not proof of anonymity or licensing. Ignored/untracked files are not a distribution; publish only the reviewed commit or verified ZIP. Never upload the whole working directory.'}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deny-file', type=Path, help='private local markers, one per line; not printed')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--release', action='store_true', help='also require a committed clean worktree')
    parser.add_argument('--archive', type=Path, help='verify an existing source ZIP byte-for-byte against HEAD')
    args = parser.parse_args()
    markers = ()
    if args.deny_file:
        markers = tuple(s.strip() for s in args.deny_file.read_text().splitlines() if s.strip())
    result = audit(ROOT, markers, args.archive, args.release)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
