# SPDX-License-Identifier: Apache-2.0
"""Publication audit adversarial checks in local disposable Git repositories.

All identities/tokens are generated synthetic strings. No network or real
credential is used, and no original/private research tree is accessed.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from scripts.publication_audit import audit, scan_bytes


class PublicationTests(unittest.TestCase):
    def test_working_tree_redacts_match_values_and_detects_binary_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix='openig831t-audit-') as temp:
            root = Path(temp)
            secret = 'gh' + 'p_' + 'S' * 28
            home = '/' + 'Users' + '/' + 'SYNTHETIC_USER'
            (root / 'example.txt').write_text(secret + '\n' + home + '\n')
            (root / 'binary.py').write_bytes(b'ELF' + bytes([0]) + b'SYNTHETIC')
            (root / 'link').symlink_to(root / 'example.txt')
            result = audit(root)
            self.assertEqual(result['status'], 'FAIL')
            self.assertTrue({'github-token', 'private-home-path', 'binary-content',
                             'symlink-excluded'} <= {f['rule'] for f in result['findings']})
            self.assertNotIn(secret, json.dumps(result))
            self.assertNotIn(home, json.dumps(result))

    def test_synthetic_identifier_patterns_and_exact_private_rules(self):
        examples = [('1234' * 4, 'long-numeric-identifier'),
                    ('gh' + 'p_' + 'A' * 24, 'github-token'),
                    ('-----BEGIN ' + 'PRIVATE KEY-----', 'private-key'),
                    ('author' + '@' + 'example.invalid', 'personal-email')]
        for value, expected in examples:
            with self.subTest(rule=expected):
                results = scan_bytes(value.encode(), 'example.txt')
                self.assertIn(expected, {row['rule'] for row in results})
                self.assertNotIn(value, json.dumps(results))
        result = scan_bytes(b'SYNTHETIC_EXACT_MARKER', 'example.txt', ['synthetic_exact_marker'])
        self.assertEqual(result[0]['rule'], 'known-private-value')

    def test_clean_tree_and_missing_git_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'README.md').write_text('# Synthetic safe documentation\n')
            report = audit(root, include_objects=True)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(report['git_object_status'], 'NOT_INITIALIZED')


class GitPublicationTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('git'):
            self.skipTest('git unavailable; all-object audit tests not performed')
        self.temp = tempfile.TemporaryDirectory(prefix='openig831t-git-audit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Synthetic Test', GIT_COMMITTER_NAME='Synthetic Test',
                        GIT_AUTHOR_EMAIL='1+synthetic@users.noreply.github.com',
                        GIT_COMMITTER_EMAIL='1+synthetic@users.noreply.github.com')
        self.git('init', '-q')

    def git(self, *args, data=None):
        result = subprocess.run(['git', *args], input=data, cwd=self.root, env=self.env,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result.stdout

    def commit(self):
        self.git('add', '-A')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic test commit')

    def test_unreachable_secret_and_binary_objects_are_scanned(self):
        secret = ('gh' + 'p_' + 'Z' * 28).encode()
        self.git('hash-object', '-w', '--stdin', data=secret)
        self.git('hash-object', '-w', '--stdin', data=b'ELF' + bytes([0]) + b'SYNTHETIC')
        result = audit(self.root, include_objects=True)
        self.assertEqual(result['status'], 'FAIL')
        rules = {item['rule'] for item in result['findings']}
        self.assertTrue({'github-token', 'binary-content'} <= rules)
        self.assertNotIn(secret.decode(), json.dumps(result))

    def test_history_keeps_forbidden_alias_and_excluded_path_findings(self):
        safe = b'SYNTHETIC SAME BLOB\n'
        (self.root / 'safe.txt').write_bytes(safe)
        (self.root / 'module.dll').write_bytes(safe)
        cache = self.root / '.cache'; cache.mkdir()
        (cache / 'excluded.txt').write_text('synthetic cache content\n')
        self.commit()
        self.git('rm', 'module.dll', '.cache/excluded.txt'); self.commit()
        result = audit(self.root, include_objects=True)
        self.assertEqual(result['status'], 'FAIL')
        pairs = {(item['file'], item['rule']) for item in result['findings']}
        self.assertIn(('module.dll', 'forbidden-git-path'), pairs)
        self.assertIn(('.cache/excluded.txt', 'excluded-artifact-in-git'), pairs)

    def test_staged_excluded_paths_are_not_hidden_by_working_tree_exclusions(self):
        cache = self.root / '.cache'; cache.mkdir()
        (cache / 'staged.txt').write_text('synthetic cache metadata\n')
        self.git('add', '.cache/staged.txt')
        result = audit(self.root, include_objects=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('excluded-artifact-in-git', {f['rule'] for f in result['findings']})

    def test_license_contact_exception_does_not_leak_to_same_blob_alias(self):
        contact = ('synthetic' + '@' + 'example.invalid\n').encode()
        license_dir = self.root / 'LICENSES'; license_dir.mkdir()
        (license_dir / 'GPL-2.0-only.txt').write_bytes(contact)
        (self.root / 'other.txt').write_bytes(contact)
        self.commit()
        self.git('rm', 'other.txt'); self.commit()
        result = audit(self.root, include_objects=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('personal-email', {f['rule'] for f in result['findings']})


if __name__ == '__main__':
    unittest.main()
