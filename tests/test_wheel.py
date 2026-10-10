# SPDX-License-Identifier: Apache-2.0
"""Build a wheel from a temporary copy and smoke-test unpacked resources offline."""
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class WheelTests(unittest.TestCase):
    def test_wheel_contains_resources_and_imports_outside_source_tree(self):
        if not importlib.util.find_spec('setuptools') or not importlib.util.find_spec('wheel'):
            self.skipTest('Optional local setuptools/wheel absent; wheel build not performed; no install/fetch')
        major = int(importlib.metadata.version('setuptools').split('.')[0])
        if major < 77:
            self.skipTest('Local setuptools is older than pyproject requirement; no automatic upgrade')
        with tempfile.TemporaryDirectory(prefix='openig831t-wheel-') as temp:
            work = Path(temp); source = work / 'source'; source.mkdir()
            for name in ('pyproject.toml', 'README.md', 'LICENSE'):
                shutil.copyfile(ROOT / name, source / name)
            shutil.copytree(ROOT / 'LICENSES', source / 'LICENSES')
            shutil.copytree(ROOT / 'src', source / 'src',
                            ignore=shutil.ignore_patterns('__pycache__', '*.egg-info'))
            wheel_dir = work / 'wheel'; wheel_dir.mkdir()
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            env.pop('PYTHONPATH', None)
            result = subprocess.run([sys.executable, '-c',
                'from setuptools.build_meta import build_wheel; build_wheel(' + repr(str(wheel_dir)) + ')'],
                cwd=source, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            wheels = list(wheel_dir.glob('*.whl')); self.assertEqual(len(wheels), 1)
            installed = work / 'installed'; installed.mkdir()
            with zipfile.ZipFile(wheels[0]) as archive:
                members = archive.namelist()
                self.assertIn('igbridge/data/ig831t_exact.json', members)
                self.assertIn('igbridge/data/candidate_readonly_queries.json', members)
                self.assertIn('igbridge/data/ig831t_lab_target.json', members)
                for name in members:
                    self.assertFalse(Path(name).is_absolute())
                    self.assertNotIn('..', Path(name).parts)
                    self.assertNotIn('__pycache__', Path(name).parts)
                    self.assertFalse(name.endswith(('.so', '.dll', '.exe')))
                archive.extractall(installed)
            smoke = subprocess.run([sys.executable, '-c',
                'import json; from igbridge.descriptors import load_profile; '
                'print(json.dumps(load_profile().summary()))'], cwd=work,
                env=dict(env, PYTHONPATH=str(installed)), capture_output=True, text=True, timeout=10)
            self.assertEqual(smoke.returncode, 0, smoke.stderr)
            self.assertEqual(json.loads(smoke.stdout)['serial'], 'REDACTED_USB_SERIAL')


if __name__ == '__main__':
    unittest.main()
