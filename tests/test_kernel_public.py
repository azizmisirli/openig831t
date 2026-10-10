# SPDX-License-Identifier: Apache-2.0
"""Offline checks of attributed GPL harnesses and optional upstream sources.

Only host C programs and ordinary temporary trees are used. The default suite
never downloads sources, loads kernel code, opens USB or modifies configfs.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'patches/linux-functionfs'
MANIFEST = json.loads((PATCHES / 'upstream.json').read_text())
PATHS = ('drivers/usb/gadget/function/f_fs.c',
         'include/uapi/linux/usb/functionfs.h')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PublicKernelTests(unittest.TestCase):
    def test_bundled_patch_and_harness_hashes(self):
        for row in MANIFEST['patches'] + MANIFEST['harnesses']:
            with self.subTest(path=row['path']):
                self.assertEqual(sha256(PATCHES / row['path']), row['sha256'])
        self.assertEqual(MANIFEST['limits']['full_kernel_build'], 'UNVERIFIED')
        self.assertEqual(MANIFEST['limits']['physical_hardware'], 'NOT_TESTED')

    def run_harness(self, name, sanitized=False):
        compiler = shutil.which('clang') or shutil.which('cc')
        if not compiler:
            self.skipTest('Host C compiler absent; extracted C checks not performed')
        expectation = ({'status': 'PASS', 'checks': 74} if name == 'cdc'
                       else {'result': 'PASS', 'assertions': 1268})
        expectation.update(hardware=False, full_kernel_build=False)
        with tempfile.TemporaryDirectory(prefix='openig831t-harness-') as temp:
            work = Path(temp)
            binary = work / 'harness'
            args = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(PATCHES / 'harnesses' / (name + '.c')), '-o', str(binary)]
            if sanitized:
                args += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            build = subprocess.run(args, capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=30, env=dict(os.environ,
                                 ASAN_OPTIONS='halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, '')
            self.assertEqual(json.loads(run.stdout), expectation)

    def test_cdc_strict(self):
        self.run_harness('cdc')

    def test_exact_address_strict(self):
        self.run_harness('exact-address')

    def test_cdc_asan_ubsan(self):
        self.run_harness('cdc', sanitized=True)

    def test_exact_address_asan_ubsan(self):
        self.run_harness('exact-address', sanitized=True)

    def test_optional_cached_upstream_patch_application(self):
        """Hash-verified cache only; missing sources are a visible skip."""
        cache = ROOT / '.cache/upstream/linux-v6.12'
        if not all((cache / path).is_file() for path in PATHS):
            self.skipTest('Optional pinned upstream cache absent; patch application not performed; no fetch')
        git = shutil.which('git')
        if not git:
            self.skipTest('git unavailable; optional patch application not performed')
        entries = {row['path']: row for row in MANIFEST['sources'] if row['project'] == 'Linux'}
        for path in PATHS:
            self.assertEqual(sha256(cache / path), entries[path]['sha256'])
        for stacked in (False, True):
            with self.subTest(stacked=stacked), tempfile.TemporaryDirectory(
                    prefix='openig831t-patch-') as temp:
                work = Path(temp)
                for path in PATHS:
                    dest = work / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes((cache / path).read_bytes())
                stages = [('cdc-exact-combined-v6.12.patch', 'combined')]
                if stacked:
                    stages = [('cdc-v6.12.patch', 'cdc'),
                              ('exact-address-stacked-v6.12.patch', 'combined')]
                for patch, stage in stages:
                    for args in (['--check'], []):
                        result = subprocess.run([git, 'apply', *args, str(PATCHES / patch)],
                                                cwd=work, capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stderr)
                    for path in PATHS:
                        self.assertEqual(sha256(work / path),
                                         MANIFEST['patched_source_sha256'][stage][path])


if __name__ == '__main__':
    unittest.main()
