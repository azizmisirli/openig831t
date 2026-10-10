# SPDX-License-Identifier: Apache-2.0
"""Archive integrity on ordinary temporary files, no device or network access."""
import hashlib
import tarfile
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts.build_bundle import build


class PackagingTests(unittest.TestCase):
    def test_captured_bytes_match_manifest_even_if_source_mutates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'source'; root.mkdir()
            source = root/'test.py'; source.write_bytes(b'before')
            out = Path(tmp)/'out'
            original = tarfile.TarFile.addfile
            def mutate(tar, info, fileobj=None):
                source.write_bytes(b'after')
                return original(tar, info, fileobj)
            with patch.object(tarfile.TarFile, 'addfile', mutate):
                manifest = build(root, out)
            self.assertEqual(manifest['status'], 'SOURCE_CHANGED_DURING_BUILD')
            self.assertEqual(manifest['sources_changed_during_build'], ['test.py'])
            with tarfile.open(out/manifest['archive']) as tar:
                raw = tar.extractfile('openig831t/test.py').read()
            self.assertEqual(raw, b'before')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['files']['test.py'])

    def test_source_snapshot_excludes_symlinks_outputs_and_generated_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'source'; root.mkdir()
            (root/'main.py').write_text('pass\n')
            (root/'link').symlink_to(root/'main.py')
            (root/'harness').write_bytes(b'compiled fixture')
            (root/'harness.dSYM').mkdir(); (root/'harness.dSYM'/'debug').write_bytes(b'debug')
            out = root/'dist'/'bundle'
            manifest = build(root, out)
            self.assertEqual(manifest['status'], 'PASS')
            self.assertEqual(set(manifest['files']), {'main.py'})
            with tarfile.open(out/manifest['archive']) as tar:
                self.assertEqual(tar.getnames(), ['openig831t/main.py'])
            with self.assertRaises(FileExistsError):
                build(root, out)

    def test_archives_are_deterministic_safe_and_documentation_is_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'; root.mkdir()
            (root / 'README.md').write_text('# Synthetic documentation\n')
            (root / 'main.py').write_text('pass\n')
            for directory in ('.git', '.cache', 'private', 'captures'):
                hidden = root / directory; hidden.mkdir()
                (hidden / 'excluded.txt').write_text('synthetic excluded data\n')
            (root / 'AUTH_REQUIRED.md').write_text('local authentication instructions\n')
            (root / 'vendor.dll').write_bytes(b'synthetic forbidden extension')
            outside = Path(tmp) / 'outside'; outside.mkdir()
            (outside / 'not-copied.md').write_text('outside\n')
            (root / 'linked-directory').symlink_to(outside, target_is_directory=True)
            first, second = Path(tmp) / 'one', Path(tmp) / 'two'
            a, b = build(root, first), build(root, second)
            self.assertEqual(a, b)
            self.assertEqual(set(a['files']), {'README.md', 'main.py'})
            for name in (a['archive'], a['documentation_archive'], 'manifest.json', 'SHA256SUMS'):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            for name, expected in ((a['archive'], {'README.md', 'main.py'}),
                                   (a['documentation_archive'], {'README.md'})):
                with tarfile.open(first / name) as archive:
                    self.assertEqual(set(archive.getnames()), {'openig831t/' + v for v in expected})
                    for member in archive.getmembers():
                        self.assertTrue(member.isfile())
                        self.assertFalse(Path(member.name).is_absolute())
                        self.assertNotIn('..', Path(member.name).parts)
                        self.assertEqual((member.mtime, member.uid, member.gid), (0, 0, 0))
            for row in (first / 'SHA256SUMS').read_text().splitlines():
                digest, name = row.split('  ')
                self.assertEqual(hashlib.sha256((first / name).read_bytes()).hexdigest(), digest)

    def test_binary_disguised_as_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'; root.mkdir()
            (root / 'bad.py').write_bytes(b'\x7fELF\x00synthetic')
            with self.assertRaisesRegex(ValueError, 'binary'):
                build(root, Path(tmp) / 'out')

    def test_deleted_source_is_reported_without_silent_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'; root.mkdir()
            source = root / 'test.py'; source.write_text('before\n')
            original = tarfile.TarFile.addfile
            def remove(tar, info, fileobj=None):
                source.unlink(missing_ok=True)
                return original(tar, info, fileobj)
            with patch.object(tarfile.TarFile, 'addfile', remove):
                report = build(root, Path(tmp) / 'out')
            self.assertEqual(report['status'], 'SOURCE_CHANGED_DURING_BUILD')
            self.assertEqual(report['sources_changed_during_build'], ['test.py'])
