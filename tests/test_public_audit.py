from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audit_public import audit, findings, PUBLIC_IDENTITY


class PublicAuditTests(unittest.TestCase):
    def test_metadata_allowed_and_private_content_detected(self):
        self.assertEqual(findings('RTX 4080 / NVIDIA 621.01 / Windows 11 / 10DE:2704'), [])
        # Assemble samples so that the test source itself contains no personal paths.
        for sample in ('/home/' + 'example-person/project', 'C:' + '\\Users\\' + 'example-person',
                       'DESKTOP' + '-ABC123', '-'.join(['123456'] * 8)):
            with self.subTest(sample_type=sample[:5]):
                self.assertTrue(findings(sample))
        self.assertEqual(findings('SAMPLE-PRIVATE-MARKER', ['sample-private-marker']), ['private-marker'])

    def test_rejects_tracked_private_directory_and_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
            (root / '.local').mkdir()
            (root / '.local/raw.txt').write_text('synthetic')
            (root / 'payload.efi').write_bytes(b'MZ\0\0')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            result = audit(root)
            self.assertFalse(result['passed'])
            self.assertEqual({x['file'] for x in result['findings']}, {'.local/raw.txt', 'payload.efi'})

    def test_staged_private_bytes_survive_a_clean_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
            (root / 'notes.txt').write_text('fixture-private-marker')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            (root / 'notes.txt').write_text('clean worktree')
            result = audit(root, ['fixture-private-marker'])
            self.assertFalse(result['passed'])
            self.assertTrue(any(f.get('location') == 'index' for f in result['findings']))

    def test_deleted_private_bytes_remain_in_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
            (root / 'notes.txt').write_text('fixture-private-marker')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            git = ['git', '-c', 'user.name=RTX 4080 Research Contributors', '-c',
                   'user.email=contributors@example.invalid', '-c', 'commit.gpgsign=false',
                   '-c', 'core.hooksPath=/dev/null']
            subprocess.run([*git, 'commit', '-qm', 'Synthetic initial fixture'], cwd=root, check=True)
            (root / 'notes.txt').write_text('clean replacement')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run([*git, 'commit', '-qm', 'Synthetic replacement'], cwd=root, check=True)
            result = audit(root, ['fixture-private-marker'])
            self.assertFalse(result['passed'])
            self.assertTrue(any(f.get('location') == 'history' for f in result['findings']))

    def make_repo(self, root):
        subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, check=True)
        name, email = PUBLIC_IDENTITY[:-1].split(' <')
        for key, value in [('user.name', name),
                           ('user.email', email),
                           ('commit.gpgsign', 'false'), ('core.hooksPath', '/dev/null')]:
            subprocess.run(['git', 'config', '--local', key, value], cwd=root, check=True)
        (root / 'source.txt').write_text('public fixture\n')
        subprocess.run(['git', 'add', '.'], cwd=root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'Synthetic public fixture'], cwd=root, check=True)

    def test_annotated_tag_and_ref_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.make_repo(root)
            subprocess.run(['git', '-c', 'user.email=fixture@example.invalid', 'tag', '-a', 'fixture-private-marker',
                            '-m', 'fixture-private-marker'], cwd=root, check=True)
            result = audit(root, ['fixture-private-marker'])
            reasons = {f['reason'] for f in result['findings']}
            self.assertIn('unreviewed-git-identity', reasons)
            self.assertIn('private-marker', reasons)
            self.assertTrue(any(f['file'] == '<git-refs>' for f in result['findings']))

    def test_dangling_blob_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.make_repo(root)
            subprocess.run(['git', 'hash-object', '-w', '--stdin'], cwd=root, input=b'fixture-private-marker',
                           check=True, capture_output=True)
            self.assertFalse(audit(root, ['fixture-private-marker'])['passed'])

    def test_clean_release_and_archive_content(self):
        import zipfile
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as z:
            root = Path(d); self.make_repo(root)
            archive = Path(z) / 'source.zip'
            subprocess.run(['git', 'archive', '--format=zip', '-o', str(archive), 'HEAD'], cwd=root, check=True)
            self.assertTrue(audit(root, archive=archive, release=True)['passed'])
            with zipfile.ZipFile(archive, 'a') as bundle:
                bundle.writestr('extra-private.txt', 'unexpected content')
            self.assertFalse(audit(root, archive=archive)['passed'])
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('source.txt', 'changed bytes')
            self.assertFalse(audit(root, archive=archive)['passed'])
            (root / 'unreviewed.txt').write_text('new file')
            self.assertFalse(audit(root, release=True)['passed'])

    def test_byte_encoded_pin_and_escaped_path(self):
        marker = '0123456789abcdef' * 4
        encoded = ', '.join('0x' + marker[i:i+2] for i in range(0, 64, 2))
        self.assertIn('private-marker', findings(encoded, [marker]))
        sample = 'C:' + chr(92) * 2 + 'Users' + chr(92) * 2 + 'fixture-person'
        self.assertIn('user-home-path', findings(sample))

    def test_explicit_public_identity_does_not_exempt_other_private_data(self):
        marker = PUBLIC_IDENTITY.split()[0]
        self.assertEqual(findings(PUBLIC_IDENTITY, [marker]), [])
        self.assertIn('private-marker', findings(marker + '-private-host', [marker]))
        self.assertIn('user-home-path', findings('/home/' + PUBLIC_IDENTITY.split(' <')[0], [marker]))
