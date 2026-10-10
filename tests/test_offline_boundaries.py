# SPDX-License-Identifier: Apache-2.0
"""Fresh-interpreter guards for imports and default plans; no hardware access."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OfflineBoundaryTests(unittest.TestCase):
    def test_imports_and_default_plans_do_not_open_transport_or_start_children(self):
        # The parent starts only this owned synthetic Python process. Inside it,
        # sentinels reject all process/network/native-library and mutation paths.
        code = r'''
import contextlib, ctypes, importlib, io, json, os, socket, subprocess
from pathlib import Path
from unittest.mock import patch
names = sorted(p.stem for p in Path('src/igbridge').glob('*.py')
               if p.stem not in ('__init__', '__main__'))
def denied(*args, **kwargs):
    raise AssertionError('side effect during import or default plan')
with contextlib.ExitStack() as guard:
    for target in ('subprocess.Popen', 'ctypes.CDLL', 'socket.socket', 'os.open',
                   'os.mkdir', 'pathlib.Path.mkdir', 'pathlib.Path.write_text',
                   'pathlib.Path.write_bytes'):
        guard.enter_context(patch(target, side_effect=denied))
    for name in names:
        importlib.import_module('igbridge.' + name)
    from igbridge import cli, lab_daemon, candidate_inventory, host_logs
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli.main(['dry-run']) == 0
        assert lab_daemon.main([]) == 0
        assert candidate_inventory.main([]) == 0
        assert host_logs.main(['--adb', '/nonexistent/adb', '--serial',
                              'REDACTED_USB_SERIAL', '--package', 'com.example.app',
                              '--pid', '123']) is None
print(json.dumps({'modules': len(names), 'status': 'PASS'}))
'''
        result = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                                env=dict(os.environ, PYTHONPATH=str(ROOT / 'src'),
                                         PYTHONDONTWRITEBYTECODE='1'),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status": "PASS"', result.stdout)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
