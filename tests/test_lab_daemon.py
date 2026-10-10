# SPDX-License-Identifier: Apache-2.0
"""Injected lab lifecycle integration only: no libusb, mount, UDC or device I/O."""
from collections import deque
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from igbridge.configfs import ConfigfsTransaction, DirectoryFS
from igbridge.descriptors import load_profile, split_descriptors
from igbridge.errors import BridgeError, PolicyDenied, ProtocolError
from igbridge.functionfs import Event, BIND, ENABLE, DISABLE, SETUP
from igbridge.lab_daemon import (LaboratoryDaemon, launch_template, validate_launch,
                                PATCH_SHA256, CDC_PATCH_SHA256, PATCHED_SOURCE_HASHES,
                                DESCRIPTOR_FLAGS, main)
from igbridge.libusb_backend import UsbTarget, UsbError
from igbridge.qmi import TLV, build_message, parse_message
from igbridge.runtime import LaboratoryRuntime
from igbridge.usb import send_setup, get_setup, dtr_setup, response_available

OK = TLV(2, b'\0' * 4)
VERSION = build_message(0, 0, 1, 0x21)


class Clock:
    def __init__(self): self.value = 0
    def __call__(self): return self.value


class Backend:
    def __init__(self, events, interface=4):
        self.events = events
        eps = ((0x89, 3), (0x88, 2), (5, 2)) if interface == 4 else ((0x85, 3), (0x84, 2), (3, 2))
        self.target = UsbTarget(0x2ca3, 0x4009, interface, eps)
        self.calls, self.writes = [], []
        self.notifications, self.responses, self.at_responses = deque(), deque(), deque()
        self.claimed = False
    def open(self):
        self.events.append(f'backend_open_{self.target.interface}'); self.claimed = True
    def control(self, setup, data=b''):
        self.calls.append((setup, data))
        if setup.request == 0x22:
            self.events.append(f'dtr_{setup.value}'); return 0
        if setup.incoming:
            return self.responses.popleft()
        message = parse_message(data)
        fields = [OK]
        if message.message_id == 0x22:
            fields.append(TLV(1, message.tlv(1) + b'\x11'))
        elif message.message_id == 0x23:
            fields.append(TLV(1, message.tlv(1))); self.events.append('owned_release')
        self.responses.append(build_message(message.service, message.cid, message.transaction_id,
                                            message.message_id, 'response', fields))
        self.notifications.append(response_available(self.target.interface))
        return len(data)
    def transfer(self, endpoint, length, data=None, timeout_ms=250):
        if data is not None:
            self.writes.append(data)
            self.at_responses.append(b'OK\r\n')
            return len(data)
        if self.at_responses:
            return self.at_responses.popleft()
        raise UsbError('bulk', -7)
    def close(self):
        self.events.append(f'backend_close_{self.target.interface}'); self.claimed = False
        return []


class IRQ:
    def __init__(self, backend, endpoint, timeout_ms):
        self.backend, self.pending = backend, False
    def arm(self):
        if self.pending: raise AssertionError('double arm')
        self.pending = True; self.backend.events.append('irq_arm')
        return {'armed': True, 'endpoint': 0x89, 'submit_status': 0}
    def pump(self, timeout_ms):
        if self.backend.notifications:
            if not self.pending: raise AssertionError('notification without pending read')
            self.pending = False
            return 0, self.backend.notifications.popleft()
        return None
    def close(self):
        self.backend.events.append('irq_cancel'); self.pending = False


class Frontend:
    def __init__(self, events, clock, script, host_data=()):
        self.events, self.clock = events, clock
        self.script, self.host_data = deque(script), deque(host_data)
        self.writes, self.in_data, self.stalls = [], [], []
        self.out_reads = 0
        self.endpoint_reads = {}
        self.bad_address = self.bad_descriptor = False
        self.fail_open = self.fail_close = False
        self.profile = load_profile()
    def open(self, descriptors, strings):
        self.events.append('ffs_open')
        self.descriptors = descriptors
        if self.fail_open: raise OSError('synthetic descriptor write rejection')
    def endpoint_address(self, slot):
        expected = self.profile.endpoints()[slot - 1].address
        return (expected ^ 1) if self.bad_address and slot == 1 else expected
    def interface_local(self, host): return host
    def endpoint_descriptor(self, slot):
        eps = [d for d in split_descriptors(self.profile.high_speed) if d[1] == 5]
        raw = bytearray(eps[slot - 1] + b'\0\0')
        if self.bad_descriptor and slot == 1: raw[4] = 1
        return bytes(raw)
    def read_events(self, timeout_ms):
        self.clock.value += .02
        item = self.script.popleft() if self.script else None
        return [] if item is None else [item]
    def read_out(self, length):
        self.out_reads += 1
        self.events.append('host_out_data')
        return self.host_data.popleft() if length else b''
    def write_in(self, raw): self.in_data.append(raw)
    def stall(self, setup): self.stalls.append(setup)
    def read_endpoint(self, slot, capacity):
        queue = self.endpoint_reads.get(slot)
        return queue.popleft() if queue else None
    def write_endpoint(self, slot, raw): self.writes.append((slot, raw))
    def close(self):
        self.events.append('ffs_close')
        if self.fail_close: raise OSError('synthetic FD close error')


class Mount:
    def __init__(self, events): self.events, self.fail_close = events, False
    def open(self): self.events.append('mount')
    def close(self):
        self.events.append('unmount')
        if self.fail_close: raise OSError('synthetic unmount error')


class Transaction(ConfigfsTransaction):
    def __init__(self, profile, fs, events):
        super().__init__(profile, fs, 'test_lab'); self.events, self.fail_unbind = events, False
    def stage(self, **kwargs): self.events.append('stage'); return super().stage(**kwargs)
    def bind(self, *args, **kwargs): self.events.append('bind'); return super().bind(*args, **kwargs)
    def unbind(self):
        self.events.append('unbind')
        if self.fail_unbind: raise OSError('synthetic unbind error')
        return super().unbind()
    def cleanup(self): self.events.append('config_cleanup'); return super().cleanup()


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.events, self.clock = [], Clock()
        self.backend, self.at_backend = Backend(self.events), Backend(self.events, 2)
        self.runtime = LaboratoryRuntime(self.backend, 0x89, interrupt_factory=IRQ)
        self.io = Frontend(self.events, self.clock, [Event(BIND), Event(ENABLE), None, Event(DISABLE)])
        self.tx = Transaction(load_profile(), DirectoryFS(self.temp.name), self.events)
        self.mount = Mount(self.events)
        self.config = {'duration_seconds': .5, 'frontend_serial': 'SYNTHETIC_LAB', 'udc': 'SYNTHETIC_UDC'}
    def daemon(self, **kwargs):
        return LaboratoryDaemon(self.config, load_profile(), self.io, self.runtime, self.at_backend,
                                self.tx, self.mount, clock=self.clock, experimental_build_verified=True, **kwargs)
    def test_real_qmi_control_roundtrip_and_cleanup_order(self):
        self.io.script = deque([Event(BIND), Event(ENABLE), Event(SETUP, dtr_setup(4, True)),
                                Event(SETUP, send_setup(4, len(VERSION))), None,
                                Event(SETUP, get_setup(4)), Event(DISABLE)])
        self.io.host_data.append(VERSION)
        result = self.daemon().run()
        self.assertTrue(result['success'], result)
        self.assertEqual(parse_message(self.io.in_data[0]).message_id, 0x21)
        self.assertIn((12, response_available(4)), self.io.writes)
        self.assertLess(self.events.index('irq_arm'), self.events.index('bind'))
        chain = ['irq_cancel', 'dtr_0', 'backend_close_4', 'unbind', 'ffs_close', 'unmount', 'config_cleanup']
        self.assertEqual([self.events.index(x) for x in chain], sorted(self.events.index(x) for x in chain))
        self.assertFalse(list(Path(self.temp.name).iterdir()))
        self.assertEqual(struct.unpack_from('<I', self.io.descriptors, 8)[0], DESCRIPTOR_FLAGS)
    def test_owned_cid_release_uses_runtime_before_cancel(self):
        request = build_message(0, 0, 1, 0x22, tlvs=(TLV(1, b'\2'),))
        self.io.script = deque([Event(BIND), Event(ENABLE), Event(SETUP, send_setup(4, len(request))),
                                None, Event(SETUP, get_setup(4)), Event(DISABLE)])
        self.io.host_data.append(request)
        result = self.daemon().run()
        self.assertTrue(result['success'], result)
        self.assertEqual(sum(x == 'owned_release' for x in self.events), 1)
        self.assertLess(self.events.index('owned_release'), self.events.index('irq_cancel'))
        self.assertNotIn('dtr_1', self.events); self.assertNotIn('dtr_0', self.events)
    def test_cleanup_releases_two_clients_with_undelivered_host_responses(self):
        requests = [build_message(0, 0, tid, 0x22, tlvs=(TLV(1, bytes([service])),))
                    for tid, service in ((1, 2), (2, 3))]
        self.io.script = deque([Event(BIND), Event(ENABLE),
            Event(SETUP, send_setup(4, len(requests[0]))), None,
            Event(SETUP, send_setup(4, len(requests[1]))), None, Event(DISABLE)])
        self.io.host_data.extend(requests)
        result = self.daemon().run()
        self.assertTrue(result['cleanup']['success'], result)
        self.assertEqual(self.events.count('owned_release'), 2)
        self.assertEqual(self.io.in_data, [])  # Host never consumed either ACK.
    def test_at_command_policy_then_exact_wire_suffix(self):
        self.io.endpoint_reads[8] = deque([b'AT\r', b'\nAT+CGMI\r'])
        self.io.script = deque([Event(BIND), Event(ENABLE), None, None, Event(DISABLE)])
        result = self.daemon().run()
        self.assertTrue(result['success'], result)
        self.assertEqual(self.at_backend.writes, [b'AT\r', b'\nAT+CGMI\r'])
        self.assertEqual(result['counts']['at_commands'], 2)
        self.assertEqual([raw for slot, raw in self.io.writes if slot == 7], [b'OK\r\n', b'OK\r\n'])
    def test_forbidden_at_and_qmi_never_forward(self):
        self.io.endpoint_reads[8] = deque([b'AT+CFUN=1\r'])
        result = self.daemon().run()
        self.assertEqual(result['error_type'], 'PolicyDenied'); self.assertFalse(self.at_backend.writes)
    def test_forbidden_qmi_no_backend_send(self):
        request = build_message(1, 1, 1, 0x20)
        self.io.script = deque([Event(BIND), Event(ENABLE), Event(SETUP, send_setup(4, len(request)))])
        self.io.host_data.append(request)
        result = self.daemon().run()
        self.assertEqual(result['error_type'], 'PolicyDenied'); self.assertFalse(self.backend.calls)
    def test_interface_control_is_rejected_before_data_stage(self):
        self.io.script = deque([Event(BIND), Event(ENABLE), Event(SETUP, send_setup(2, 12))])
        result = self.daemon().run()
        self.assertEqual(result['error_type'], 'ProtocolError'); self.assertEqual(self.io.out_reads, 0)
        self.assertEqual(len(self.io.stalls), 1)
    def test_actual_address_or_descriptor_failure_prevents_forwarding(self):
        for key in ('bad_address', 'bad_descriptor'):
            with self.subTest(key=key):
                self.setUp()
                setattr(self.io, key, True)
                self.io.endpoint_reads[8] = deque([b'AT\r'])
                result = self.daemon().run()
                self.assertFalse(result['binding_verified']); self.assertFalse(self.at_backend.writes)
    def test_unimplemented_bulk_and_active_data_stop_without_backend_writes(self):
        for slot in (2, 5, 11, 14):
            with self.subTest(slot=slot):
                self.setUp(); self.io.endpoint_reads[slot] = deque([b'SYNTHETIC'])
                result = self.daemon().run()
                self.assertEqual(result['error_type'], 'PolicyDenied')
                self.assertFalse(self.backend.calls); self.assertFalse(self.at_backend.writes)
    def test_descriptor_rejection_prevents_backend_open_and_bind(self):
        self.io.fail_open = True
        result = self.daemon().run()
        self.assertFalse(result['success']); self.assertNotIn('bind', self.events)
        self.assertNotIn('backend_open_4', self.events)
    def test_failed_partial_runtime_open_never_claims_safe_cleanup_or_retries_cancel(self):
        class RetainedIRQ(IRQ):
            def close(self):
                self.backend.events.append('failed_cancel')
                raise ProtocolError('synthetic cancellation failure; native resources retained')
        self.runtime.interrupt_factory = RetainedIRQ
        def fail_log(*args, **kwargs): raise OSError('synthetic log failure after arm')
        self.runtime.emit = fail_log
        result = self.daemon().run()
        self.assertFalse(result['cleanup']['success'])
        self.assertEqual(result['cleanup']['errors'][0]['cleanup_status'], 'UNCONFIRMED')
        self.assertTrue(result['cleanup']['errors'][0]['irq_pending'])
        self.assertTrue(self.backend.claimed)
        self.assertEqual(self.events.count('failed_cancel'), 1)
        self.assertNotIn('backend_close_4', self.events)
        self.assertNotIn('bind', self.events)
    def test_irq_pre_setup_guard_happens_before_host_out(self):
        self.io.script = deque([Event(BIND), Event(ENABLE), Event(SETUP, send_setup(4, len(VERSION)))])
        def fail_ready(): raise ProtocolError('synthetic IRQ not armed')
        self.runtime._ready = fail_ready
        result = self.daemon().run()
        self.assertEqual(result['error_type'], 'ProtocolError'); self.assertEqual(self.io.out_reads, 0)
        self.assertFalse(self.backend.calls)
    def test_cleanup_failure_preserves_frontend_ownership(self):
        for fail, forbidden in [('unbind', 'ffs_close'), ('ffs', 'unmount'), ('mount', 'config_cleanup')]:
            with self.subTest(fail=fail):
                self.setUp()
                if fail == 'unbind': self.tx.fail_unbind = True
                if fail == 'ffs': self.io.fail_close = True
                if fail == 'mount': self.mount.fail_close = True
                result = self.daemon().run()
                self.assertFalse(result['cleanup']['success']); self.assertNotIn(forbidden, self.events)
                self.assertTrue((Path(self.temp.name) / 'test_lab').exists())
    def test_loop_deadline_and_no_default_dtr(self):
        self.io.script = deque([Event(BIND), Event(ENABLE)])
        self.config['duration_seconds'] = .06
        result = self.daemon().run()
        self.assertEqual(result['stop_reason'], 'duration_elapsed')
        self.assertLess(self.clock(), .1)
        self.assertFalse(self.backend.calls)
    def test_invalid_duration_before_start(self):
        self.config['duration_seconds'] = float('nan')
        result = self.daemon().run()
        self.assertFalse(result['success']); self.assertNotIn('stage', self.events)


class LaunchTests(unittest.TestCase):
    def evidence(self, path, data):
        path.write_bytes(data)
        return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()}
    def ready_synthetic_config(self, directory):
        cfg = launch_template()
        cfg.update(status='READY', udc='SYNTHETIC_UDC', endpoint_resource_plan_verified=True,
                   exact_address_allocation_verified=True)
        cfg['backend'].update(bus=1, address=2)
        cfg['endpoint_resource_evidence'] = self.evidence(directory / 'endpoints', b'SYNTHETIC resource test')
        expected_sources = {}
        for name in PATCHED_SOURCE_HASHES:
            path = directory / 'patched' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = ('SYNTHETIC SOURCE FIXTURE: ' + name).encode()
            path.write_bytes(raw)
            expected_sources[name] = hashlib.sha256(raw).hexdigest()
        # Test-only known synthetic source hashes. Production constants are never changed.
        source_constants = patch('igbridge.lab_daemon.PATCHED_SOURCE_HASHES', expected_sources)
        source_constants.start()
        self.addCleanup(source_constants.stop)
        manifest = {'status': 'VERIFIED_BY_OPERATOR', 'full_kernel_build': 'PASS',
                    'kernel_release': 'synthetic-kernel', 'running_image_matches_build': True,
                    'patch_sha256': PATCH_SHA256, 'source_hashes': expected_sources,
                    'cdc_patch_sha256': CDC_PATCH_SHA256, 'functionfs_flags': DESCRIPTOR_FLAGS,
                    'exact_address_allocation_verified': True,
                    'operator_evidence_ref': 'SYNTHETIC TEST ONLY',
                    'patched_source_root': str(directory / 'patched'),
                    'patch_root': str(Path(__file__).resolve().parents[1] / 'patches/linux-functionfs'),
                    'kernel_image': self.evidence(directory / 'image', b'SYNTHETIC NOT A KERNEL'),
                    'build_log': self.evidence(directory / 'buildlog', b'SYNTHETIC NOT A BUILD')}
        cfg['build_manifest'] = self.evidence(directory / 'manifest.json', json.dumps(manifest).encode())
        return cfg
    def test_hash_gate_pass_is_only_operator_assertion_not_boot_attestation(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self.ready_synthetic_config(Path(td))
            result = validate_launch(cfg, 'synthetic-kernel')
            self.assertFalse(result['running_kernel_attestation'])
            self.assertEqual(result['build_evidence'], 'HASH_VERIFIED_OPERATOR_ASSERTION')
            self.assertEqual(result['qmi'].endpoint_packets, ((137, 8), (136, 512), (5, 512)))
    def test_notready_hash_release_and_manual_selection_fail(self):
        with self.assertRaises(PolicyDenied): validate_launch(launch_template(), 'synthetic-kernel')
        with tempfile.TemporaryDirectory() as td:
            cfg = self.ready_synthetic_config(Path(td))
            with self.assertRaises(PolicyDenied): validate_launch(cfg, 'different-running-kernel')
            allocation = copy.deepcopy(cfg); allocation['exact_address_allocation_verified'] = False
            with self.assertRaises(PolicyDenied): validate_launch(allocation, 'synthetic-kernel')
            broken = copy.deepcopy(cfg); broken['backend']['bus'] = None
            with self.assertRaises(BridgeError): validate_launch(broken, 'synthetic-kernel')
            Path(cfg['endpoint_resource_evidence']['path']).write_text('changed')
            with self.assertRaises(BridgeError): validate_launch(cfg, 'synthetic-kernel')
    def test_offline_cli_never_constructs_transport(self):
        with patch('igbridge.lab_daemon.LibUsbBackend') as backend, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main([]), 0)
        backend.assert_not_called()
        self.assertFalse(json.loads(stdout.getvalue())['hardware_access'])
    def test_execute_notready_denied_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'config.json'; path.write_text(json.dumps(launch_template()))
            with patch('igbridge.lab_daemon.sys.platform', 'linux'), patch('igbridge.lab_daemon.os.geteuid', return_value=0), \
                 patch('igbridge.lab_daemon.LibUsbBackend') as backend:
                with self.assertRaises(PolicyDenied): main(['--config', str(path), '--execute-lab'])
                backend.assert_not_called()
    def test_config_rejects_symlink_fifo_oversize_and_nonobject_offline(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            regular = root / 'ordinary'; regular.write_text('{}')
            link = root / 'link'; link.symlink_to(regular)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            large = root / 'large'; large.write_bytes(b' ' * (1024 * 1024 + 1))
            array = root / 'array'; array.write_text('[]')
            for path in (link, fifo, large, array):
                with self.subTest(path=path.name), patch('igbridge.lab_daemon.LibUsbBackend') as backend:
                    with self.assertRaises((BridgeError, OSError)):
                        main(['--config', str(path)])
                    backend.assert_not_called()


if __name__ == '__main__': unittest.main()
