# SPDX-License-Identifier: Apache-2.0
"""Compile header layout only; the resulting program has no libusb calls/link."""
import ctypes
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from igbridge.libusb_backend import DeviceDescriptor, EndpointDescriptor, InterfaceDescriptor, Interface, ConfigDescriptor
from igbridge.async_interrupt import Transfer, Timeval


class AbiTests(unittest.TestCase):
    def test_public_header_matches_ctypes_native_layout(self):
        cc = shutil.which('cc')
        if not cc:
            self.skipTest('C compiler unavailable; ABI remains unverified on this host')
        header = Path(os.environ.get('OPENIG831T_LIBUSB_HEADER',
            str(Path(__file__).resolve().parents[1] / '.cache/upstream/libusb-1.0.29/libusb.h')))
        if not header.is_file():
            self.skipTest('Optional pinned libusb header absent; ABI check not performed; no automatic fetch')
        self.assertEqual(hashlib.sha256(header.read_bytes()).hexdigest(),
            '8c77e192d53960966c42d5f6ef204e3be88c9ff3ca431acdd5c6039689b3fe0b')
        structs = [(DeviceDescriptor, 'libusb_device_descriptor'),
                   (EndpointDescriptor, 'libusb_endpoint_descriptor'),
                   (InterfaceDescriptor, 'libusb_interface_descriptor'),
                   (Interface, 'libusb_interface'), (ConfigDescriptor, 'libusb_config_descriptor'),
                   (Transfer, 'libusb_transfer'), (Timeval, 'timeval')]
        lines, expected = [], []
        for py, c in structs:
            lines.append(f'printf("%zu\\n", sizeof(struct {c}));')
            expected.append(ctypes.sizeof(py))
            for name, _ in py._fields_:
                lines.append(f'printf("%zu\\n", offsetof(struct {c}, {name}));')
                expected.append(getattr(py, name).offset)
        source = '#include <stdio.h>\n#include <stddef.h>\n#include "' + str(header) + '"\nint main(void) {\n' + '\n'.join(lines) + '\nreturn 0;}\n'
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p/'abi.c').write_text(source)
            subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', str(p/'abi.c'), '-o', str(p/'abi')], check=True, capture_output=True, timeout=30)
            result = subprocess.run([str(p/'abi')], check=True, capture_output=True, text=True, timeout=5)
        self.assertEqual([int(v) for v in result.stdout.split()], expected)
