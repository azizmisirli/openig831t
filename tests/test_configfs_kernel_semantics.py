# SPDX-License-Identifier: Apache-2.0
"""Kernel-like ENODEV on empty/double unbind; only temp directories used."""
from pathlib import Path
import tempfile
import unittest
from igbridge.configfs import ConfigfsTransaction, DirectoryFS
from test_configfs import synthetic_nonexact_profile, READY


class KernelSemanticsFS(DirectoryFS):
    def __init__(self, root, failed_bind=False):
        super().__init__(root)
        self.failed_bind, self.udc_writes = failed_bind, []
    def mkdir(self, path):
        super().mkdir(path)
        if '/' not in path:
            self._path(path + '/UDC').write_text('\n')
    def write_text(self, path, value):
        if path.endswith('/UDC'):
            if not value.strip() and not self.read_text(path).strip():
                raise OSError(19, 'ENODEV synthetic already-unbound')
            self.udc_writes.append(value)
            if self.failed_bind and value.strip():
                raise OSError(19, 'ENODEV synthetic failed-bind')
        super().write_text(path, value)


class KernelSemanticTests(unittest.TestCase):
    def test_exactly_one_unbind_then_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            fs = KernelSemanticsFS(td)
            tr = ConfigfsTransaction(synthetic_nonexact_profile(), fs)
            tr.stage(serial_number='LAB'); tr.bind('test_udc', explicit=True, readiness=READY)
            tr.cleanup(); tr.cleanup()
            self.assertEqual(fs.udc_writes, ['test_udc\n', '\n'])
            self.assertFalse(list(Path(td).iterdir()))

    def test_failed_bind_with_empty_udc_does_not_unbind(self):
        with tempfile.TemporaryDirectory() as td:
            fs = KernelSemanticsFS(td, failed_bind=True)
            tr = ConfigfsTransaction(synthetic_nonexact_profile(), fs)
            tr.stage(serial_number='LAB')
            with self.assertRaises(OSError):
                tr.bind('test_udc', explicit=True, readiness=READY)
            tr.cleanup()
            self.assertEqual(fs.udc_writes, ['test_udc\n'])
            self.assertFalse(list(Path(td).iterdir()))
