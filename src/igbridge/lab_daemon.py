# SPDX-License-Identifier: Apache-2.0
"""Explicit Linux laboratory daemon; import/default CLI are entirely offline.

Full descriptor layout, MI2 AT and MI4 read-only QMI only. This is deliberately
not a complete IG831T protocol clone. No automatic DTR, data session or retry.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import threading
import time

from .at import ATProxy
from .configfs import BindReadiness, ConfigfsTransaction, KernelConfigFS
from .descriptors import FS, HS, load_profile
from .errors import BridgeError, ConfigurationError, PolicyDenied, ProtocolError
from .functionfs import FunctionFSIO, EventDriver
from .libusb_backend import LibUsbBackend, UsbTarget, UsbError
from .logging import EventLog
from .mapping import AddressMap, InterfaceBinding, EndpointBinding
from .policy import LaboratoryPolicy
from .qmi_session import QmiSession
from .runtime import LaboratoryRuntime, cleanup_succeeded

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTAL_FLAG = 0x40000000
EXACT_ADDRESS_FLAG = 0x20000000
DESCRIPTOR_FLAGS = 3 | EXPERIMENTAL_FLAG | EXACT_ADDRESS_FLAG
CDC_PATCH_SHA256 = '915eff0d6eef9cf3e4aa2b421e7bdf2206f8961b07023ff456ba2e03cce9a278'
PATCH_SHA256 = '2908856977ce6a0fbb2b3c1da9ef803364c9000235a5f5b11a633e64712b1b68'
PATCHED_SOURCE_HASHES = {
    'drivers/usb/gadget/function/f_fs.c': '69c05bd84cebdaa3ed5fd483e1c7fec4332b793e35a38012aab6e035127813f3',
    'include/uapi/linux/usb/functionfs.h': '51dc655b2c12bf53524d82208a605640ad0cc411b832060a5d5f5739395620e7',
}


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ConfigurationError(f'invalid {name}')
    return value


def _hash_file(path, limit=512 * 1024 * 1024):
    """Only bounded ordinary evidence files; never devices, pipes or symlinks."""
    p = Path(path)
    resolved = p.resolve()
    if any(resolved == Path(v) or Path(v) in resolved.parents for v in ('/sys', '/proc', '/dev')):
        raise PolicyDenied('kernel pseudo-files are not build evidence')
    st = p.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        raise ConfigurationError('evidence must be a bounded regular file')
    digest = hashlib.sha256()
    total = 0
    with p.open('rb') as stream:
        while chunk := stream.read(65536):
            total += len(chunk)
            if total > limit:
                raise ConfigurationError('evidence grew beyond bound')
            digest.update(chunk)
    return digest.hexdigest()


def _evidence(row, limit=512 * 1024 * 1024):
    if not isinstance(row, dict) or not re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')):
        raise ConfigurationError('evidence path and SHA256 required')
    if _hash_file(row['path'], limit) != row['sha256']:
        raise ConfigurationError('evidence hash mismatch')


def _json_file(path, expected_hash=None):
    """Bounded regular JSON; never block opening a FIFO or follow a final symlink."""
    p = Path(path)
    resolved = p.resolve()
    if any(resolved == Path(v) or Path(v) in resolved.parents for v in ('/sys', '/proc', '/dev')):
        raise PolicyDenied('configuration must be an ordinary file')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1024 * 1024:
            raise ConfigurationError('bounded regular JSON file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ConfigurationError('JSON file exceeded bound')
        if expected_hash is not None and hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ConfigurationError('JSON evidence hash mismatch')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ConfigurationError('JSON object required')
        return value
    finally:
        os.close(fd)


def launch_template():
    return {'schema_version': 1, 'status': 'NOT_READY', 'duration_seconds': 30,
            'gadget_name': 'ig831t_lab', 'mount_path': '/run/ig831t-ffs-lab',
            'udc': 'UNKNOWN_MANUAL_UDC_REQUIRED', 'frontend_serial': 'LAB_ONLY',
            'build_manifest': {'path': 'UNKNOWN', 'sha256': 'UNKNOWN'},
            'endpoint_resource_evidence': {'path': 'UNKNOWN', 'sha256': 'UNKNOWN'},
            'endpoint_resource_plan_verified': False,
            'exact_address_allocation_verified': False,
            'backend': {'vid': 0x2ca3, 'pid': 0x4009, 'bus': None, 'address': None,
                        'configuration': 1,
                        'qmi': {'interface': 4, 'alternate': 0, 'interface_class': [255, 255, 255],
                                'endpoints': [[0x89, 3, 8], [0x88, 2, 512], [5, 2, 512]]},
                        'at': {'interface': 2, 'alternate': 0, 'interface_class': [255, 0, 0],
                               'endpoints': [[0x85, 3, 10], [0x84, 2, 512], [3, 2, 512]]}},
            'limitations': ['template is not ready for execution', 'no verified running kernel build supplied',
                            'backend serial/whole-device identity not proven by this contract',
                            'MI0/1/3 and active data are unsupported; full protocol clone NOT_READY']}


def _target(config, role):
    backend, row = config['backend'], config['backend'][role]
    endpoints = row['endpoints']
    if not isinstance(endpoints, list) or len(endpoints) != 3:
        raise ConfigurationError('three explicit backend endpoints required per interface')
    seen, counts = set(), {('IN', 2): 0, ('OUT', 2): 0, ('IN', 3): 0}
    for ep in endpoints:
        if not isinstance(ep, list) or len(ep) != 3:
            raise ConfigurationError('backend endpoint requires address/type/maxpacket')
        address = _integer(ep[0], 1, 255, 'endpoint address')
        if address & 0x70 or not address & 15 or address in seen:
            raise ConfigurationError('invalid/duplicate backend endpoint')
        seen.add(address)
        kind = _integer(ep[1], 2, 3, 'endpoint type')
        _integer(ep[2], 1, 1024, 'endpoint maxpacket')
        key = ('IN' if address & 0x80 else 'OUT', kind)
        if key not in counts:
            raise ConfigurationError('unsupported backend endpoint role')
        counts[key] += 1
    if set(counts.values()) != {1}:
        raise ConfigurationError('one bulk IN/OUT plus interrupt IN required')
    classes = row['interface_class']
    if not isinstance(classes, list) or len(classes) != 3:
        raise ConfigurationError('explicit backend interface class triple required')
    for value in classes:
        _integer(value, 0, 255, 'interface class')
    return UsbTarget(_integer(backend['vid'], 1, 65535, 'VID'),
                     _integer(backend['pid'], 1, 65535, 'PID'),
                     _integer(row['interface'], 0, 255, 'backend interface'),
                     tuple((e[0], e[1]) for e in endpoints),
                     _integer(backend['configuration'], 1, 255, 'configuration'),
                     _integer(row['alternate'], 0, 0, 'alternate'),
                     _integer(backend['bus'], 1, 255, 'manual backend bus'),
                     _integer(backend['address'], 1, 127, 'manual backend address'),
                     tuple(classes), tuple((e[0], e[2]) for e in endpoints))


def validate_launch(config, running_release):
    """File-only gate. Build/boot linkage is an explicit operator assertion."""
    if not isinstance(config, dict) or config.get('schema_version') != 1 or config.get('status') != 'READY':
        raise PolicyDenied('launch configuration NOT_READY')
    duration = config.get('duration_seconds', 30)
    if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 < duration <= 300:
        raise ConfigurationError('lab duration must be finite and at most 300 seconds')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', config.get('gadget_name', '')):
        raise ConfigurationError('explicit gadget name required')
    if not re.fullmatch(r'/run/ig831t-[A-Za-z0-9_-]{1,64}', config.get('mount_path', '')):
        raise ConfigurationError('exclusive FunctionFS mount must be under /run/ig831t-*')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', config.get('udc', '')) or 'UNKNOWN' in config['udc']:
        raise ConfigurationError('manual UDC name required')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,126}', config.get('frontend_serial', '')):
        raise ConfigurationError('explicit frontend serial choice required')
    if config.get('endpoint_resource_plan_verified') is not True:
        raise PolicyDenied('endpoint resource plan is unverified')
    if config.get('exact_address_allocation_verified') is not True:
        raise PolicyDenied('exact endpoint allocator build is unverified')
    _evidence(config['endpoint_resource_evidence'])
    _evidence(config['build_manifest'], 1024 * 1024)
    manifest = _json_file(config['build_manifest']['path'], config['build_manifest']['sha256'])
    if (manifest.get('status') != 'VERIFIED_BY_OPERATOR' or manifest.get('full_kernel_build') != 'PASS'
            or manifest.get('kernel_release') != running_release
            or manifest.get('running_image_matches_build') is not True
            or manifest.get('patch_sha256') != PATCH_SHA256
            or manifest.get('cdc_patch_sha256') != CDC_PATCH_SHA256
            or manifest.get('functionfs_flags') != DESCRIPTOR_FLAGS
            or manifest.get('exact_address_allocation_verified') is not True
            or not manifest.get('operator_evidence_ref')):
        raise PolicyDenied('exact experimental kernel build/boot contract not provided')
    if _hash_file(Path(manifest['patch_root']) / 'cdc-v6.12.patch') != CDC_PATCH_SHA256:
        raise PolicyDenied('local experimental patch changed')
    if _hash_file(Path(manifest['patch_root']) / 'cdc-exact-combined-v6.12.patch') != PATCH_SHA256:
        raise PolicyDenied('local exact-address combined patch changed')
    if manifest.get('source_hashes') != PATCHED_SOURCE_HASHES:
        raise PolicyDenied('kernel build source hashes do not match this patch')
    for name, expected_hash in PATCHED_SOURCE_HASHES.items():
        if _hash_file(Path(manifest['patched_source_root']) / name) != expected_hash:
            raise PolicyDenied('reviewed patched source changed')
    _evidence(manifest['kernel_image'])
    _evidence(manifest['build_log'])
    qmi, at = _target(config, 'qmi'), _target(config, 'at')
    if qmi.interface == at.interface:
        raise ConfigurationError('AT and QMI require separately claimed backend interfaces')
    return {'duration_seconds': duration, 'qmi': qmi, 'at': at,
            'build_evidence': 'HASH_VERIFIED_OPERATOR_ASSERTION', 'running_kernel_attestation': False}


class LabFunctionFSIO(FunctionFSIO):
    def read_endpoint(self, slot, capacity=512):
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ConfigurationError('bounded endpoint read required')
        try:
            return os.read(self.endpoint(slot), capacity)
        except BlockingIOError:
            return None

    def endpoint_descriptor(self, slot):
        # Linux UAPI struct usb_endpoint_descriptor is packed 9 bytes (includes
        # optional audio fields); bLength for this captured profile remains 7.
        return bytes(fcntl.ioctl(self.endpoint(slot), 0x80096782, bytes(9)))


class OwnedFunctionFSMount:
    """Explicit mount/unmount, exclusively created directory; no shell/process."""
    def __init__(self, path):
        self.path = Path(path)
        self.created = self.mounted = False
        self.original_identity = self.mounted_identity = None

    def _identity(self):
        st = self.path.stat()
        return st.st_dev, st.st_ino

    @staticmethod
    def _libc():
        lib = ctypes.CDLL(None, use_errno=True)
        lib.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
        lib.mount.restype = ctypes.c_int
        lib.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.umount2.restype = ctypes.c_int
        return lib

    def open(self):
        if sys.platform != 'linux' or os.geteuid() != 0 or self.created:
            raise PolicyDenied('fresh explicit privileged Linux mount required')
        if not re.fullmatch(r'/run/ig831t-[A-Za-z0-9_-]{1,64}', str(self.path)) or self.path.parent.is_symlink():
            raise PolicyDenied('unsafe FunctionFS mount path')
        self.path.mkdir(mode=0o700, exist_ok=False)
        self.created = True
        self.original_identity = self._identity()
        if self._libc().mount(b'ig831t', os.fsencode(self.path), b'functionfs', 6, b'rmode=0700,fmode=0600'):
            code = ctypes.get_errno()
            self.close()
            raise OSError(code, 'FunctionFS mount failed')
        self.mounted = True
        self.mounted_identity = self._identity()

    def close(self):
        if not self.created:
            return
        if self.mounted:
            if self._identity() != self.mounted_identity:
                raise PolicyDenied('mount identity changed; refusing unmount')
            if self._libc().umount2(os.fsencode(self.path), 0):
                raise OSError(ctypes.get_errno(), 'owned FunctionFS unmount failed')
            self.mounted = False
        if self._identity() != self.original_identity:
            raise PolicyDenied('directory identity changed; refusing removal')
        self.path.rmdir()
        self.created = False


class LaboratoryDaemon:
    """One-owner loop. Injected objects permit real integration tests without I/O."""
    def __init__(self, config, profile, io, runtime, at_backend, transaction, mount,
                 *, experimental_build_verified=False, clock=time.monotonic,
                 should_stop=lambda: False, log=None):
        self.config, self.profile, self.io, self.runtime = config, profile, io, runtime
        self.at_backend, self.transaction, self.mount = at_backend, transaction, mount
        self.experimental_build_verified = experimental_build_verified
        self.clock, self.should_stop, self.log = clock, should_stop, log
        self.at = ATProxy()
        self.policy = LaboratoryPolicy()
        self.driver = None
        self.started = self.at_open = self.runtime_open = self.verified = False
        self.partial_start_failures = []
        self.cleanup_result = None
        self.counts = {'at_commands': 0, 'host_notifications': 0, 'blocked_endpoint_writes': 0}
        self.owner = threading.get_ident()
        self._endpoints = profile.endpoints(HS)
        self.slots = {ep.address: n for n, ep in enumerate(self._endpoints, 1)}
        self.at_in = next(a for a, k in at_backend.target.endpoints if a & 0x80 and k == 2)
        self.at_out = next(a for a, k in at_backend.target.endpoints if not a & 0x80 and k == 2)

    def emit(self, event, **fields):
        if self.log:
            self.log.emit(event, **fields)

    def verify_binding(self):
        actual = {ep.address: self.io.endpoint_address(n) for n, ep in enumerate(self._endpoints, 1)}
        interfaces = {self.io.interface_local(n): n for n in range(5)}
        mapping = AddressMap([InterfaceBinding(n, n) for n in range(5)],
                             [EndpointBinding(e.address, e.address, actual[e.address]) for e in self._endpoints])
        mapping.verify_exact_binding(actual, interfaces)
        observed = [self.io.endpoint_descriptor(n) for n in range(1, 15)]
        matches = []
        for speed in (FS, HS):
            expected = self.profile.endpoints(speed)
            valid = True
            for raw, ep in zip(observed, expected):
                if (len(raw) != 9 or raw[:2] != b'\x07\x05' or raw[2] != ep.address or
                        raw[3] != ep.transfer_type or int.from_bytes(raw[4:6], 'little') != ep.max_packet
                        or raw[6] != ep.interval):
                    valid = False
                    break
            if valid:
                matches.append(speed)
        if len(matches) != 1:
            raise ProtocolError('actual enabled endpoint type/maxpacket/interval mismatch')
        self.verified = True
        self.emit('frontend_binding_verified', speed=matches[0], endpoints=14, interfaces=5,
                  host_acceptance='NOT_PROVEN', virtual_addr_used=False)

    def _start(self):
        if self.experimental_build_verified is not True or self.started:
            raise PolicyDenied('verified explicit experimental launch required; no restart')
        self.started = True
        self.transaction.stage(serial_number=self.config['frontend_serial'])
        self.mount.open()
        blob = bytearray(self.profile.functionfs_descriptors())
        struct.pack_into('<I', blob, 8, DESCRIPTOR_FLAGS)
        self.io.open(bytes(blob), self.profile.functionfs_strings())
        try:
            self.runtime.open()
        except BaseException:
            # open() owns rollback. A failed cancellation may intentionally retain
            # native objects; never retry it here or claim cleanup success.
            self.partial_start_failures.append({'action': 'qmi_open_rollback',
                'cleanup_status': 'UNCONFIRMED',
                'backend_claimed': getattr(self.runtime.backend, 'claimed', None),
                'irq_pending': getattr(self.runtime.irq, 'pending', None)})
            raise
        self.runtime_open = True
        # FunctionFS host-facing/local interface is 4; backend numbering is explicit.
        self.runtime.control.local_interface = self.runtime.control.host_interface = 4
        self.runtime.control.session = QmiSession(max_clients=4, max_pending=8)
        try:
            self.at_backend.open()
        except BaseException:
            self.partial_start_failures.append({'action': 'at_open_rollback',
                'cleanup_status': 'UNCONFIRMED',
                'backend_claimed': getattr(self.at_backend, 'claimed', None)})
            raise
        self.at_open = True
        self.at.open()
        self.driver = EventDriver(self.io, self.runtime.control, self.verify_binding,
                                  self.log, pre_setup=self.runtime._ready)
        self.transaction.bind(self.config['udc'], explicit=True,
            readiness=BindReadiness(functionfs_descriptors_written=True,
                functionfs_strings_written=True, functionfs_ep0_open=True,
                endpoint_resource_plan_verified=True, coordinator_authorized=True,
                experimental_descriptor_acceptance_verified=True,
                exact_address_allocation_verified=True))
        self.emit('lab_started', full_protocol_clone=False, active_data_allowed=False,
                  kernel_boot_evidence='OPERATOR_ASSERTION_NOT_ATTESTATION')

    def _service_at(self):
        raw = self.io.read_endpoint(self.slots[3], 512)
        if raw is not None:
            decision = self.at.host_to_backend_frame(raw, self.clock())
            if decision.command is not None:
                self.policy.at(decision.command)
                self.counts['at_commands'] += 1
            if decision.wire:
                self.emit('at_out', length=len(decision.wire), command=decision.command is not None)
                self.at_backend.transfer(self.at_out, length=len(decision.wire), data=decision.wire, timeout_ms=250)
        try:
            incoming = self.at_backend.transfer(self.at_in, length=512, timeout_ms=10)
        except UsbError as exc:
            if exc.code == -7 and not exc.partial:
                incoming = b''  # bounded passive idle read; no command replay
            else:
                raise
        if incoming:
            outgoing = self.at.backend_to_host(incoming, self.clock())
            if outgoing:
                self.io.write_endpoint(self.slots[0x84], outgoing)
        if self.at.expire(self.clock()):
            raise TimeoutError('AT transaction expired; channel stops')

    def _block_other_writes(self):
        for address in (1, 2, 4, 5):
            raw = self.io.read_endpoint(self.slots[address], 512)
            if raw:
                self.counts['blocked_endpoint_writes'] += 1
                self.emit('blocked_endpoint_write', address=address, length=len(raw))
                raise PolicyDenied('MI0/1/3 and active data writes are unsupported')

    def run(self):
        if threading.get_ident() != self.owner:
            raise ConfigurationError('daemon must remain on one owner thread')
        status = {'mode': 'LAB_PROXY', 'full_protocol_clone': False, 'data_session_started': False}
        try:
            duration = self.config.get('duration_seconds', 30)
            if type(duration) not in (int, float) or not math.isfinite(duration) or not 0 < duration <= 300:
                raise ConfigurationError('finite lab duration required')
            self._start()
            deadline = self.clock() + duration
            while self.clock() < deadline and not self.should_stop():
                self.runtime.poll(0, idle_allowed=True)
                for event in self.io.read_events(timeout_ms=10):
                    if not self.driver.handle(event):
                        status['stop_reason'] = 'host_disconnect'
                        return status
                if self.driver.state == 'ENABLED':
                    self._block_other_writes()
                    self._service_at()
                    for _ in range(64):
                        raw = self.runtime.control.pop_notification()
                        if raw is None:
                            break
                        self.io.write_endpoint(self.slots[0x89], raw)
                        self.counts['host_notifications'] += 1
                    else:
                        raise ProtocolError('frontend notification flood')
            status['stop_reason'] = 'stop_signal' if self.should_stop() else 'duration_elapsed'
        except Exception as exc:
            status.update(stop_reason='fault', error_type=type(exc).__name__, error=str(exc))
        finally:
            status['cleanup'] = self.cleanup()
            status['counts'] = dict(self.counts)
            status['binding_verified'] = self.verified
            status['success'] = ('error' not in status and self.verified and status['cleanup']['success'])
        return status

    def cleanup(self):
        if self.cleanup_result is not None:
            return self.cleanup_result
        errors, runtime_result = list(self.partial_start_failures), None
        def attempt(name, fn):
            try:
                return True, fn()
            except Exception as exc:
                errors.append({'action': name, 'error_type': type(exc).__name__, 'error': str(exc)})
                return False, None
        self.at.close()
        if self.runtime_open:
            _, runtime_result = attempt('qmi_release_cancel_dtr_backend_close', self.runtime.close)
        if self.at_open:
            _, result = attempt('at_backend_close', self.at_backend.close)
            if result:
                errors.append({'action': 'at_backend_close', 'errors': result})
        # Preserve owned frontend resources if unbind/FD close/unmount fails.
        unbound, _ = attempt('udc_unbind', self.transaction.unbind)
        if unbound:
            closed, _ = attempt('functionfs_close', self.io.close)
            if closed:
                unmounted, _ = attempt('functionfs_unmount', self.mount.close)
                if unmounted:
                    attempt('configfs_cleanup', self.transaction.cleanup)
        ok = not errors and (not self.runtime_open or cleanup_succeeded(runtime_result))
        self.cleanup_result = {'success': ok, 'runtime': runtime_result, 'errors': errors}
        return self.cleanup_result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Bounded IG831T lab daemon; default offline')
    parser.add_argument('--config')
    parser.add_argument('--execute-lab', action='store_true')
    parser.add_argument('--output')
    parser.add_argument('--library')
    args = parser.parse_args(argv)
    config = _json_file(args.config) if args.config else launch_template()
    if not args.execute_lab:
        print(json.dumps({'mode': 'OFFLINE_PLAN', 'hardware_access': False,
                          'launch_status': config.get('status', 'NOT_READY'),
                          'full_protocol_clone': False, 'template': launch_template()}, indent=2))
        return 0
    if sys.platform != 'linux' or os.geteuid() != 0 or not args.config:
        raise PolicyDenied('explicit --config, privileged Linux and --execute-lab required')
    approved = validate_launch(config, os.uname().release)
    output = Path(args.output or config.get('output', ''))
    if not str(output) or str(output) == '.':
        raise ConfigurationError('exclusive --output or config.output directory required')
    if threading.current_thread() is not threading.main_thread():
        raise PolicyDenied('main thread signal watchdog required')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    stopped = [False]
    old_handlers = {}
    def stop(signum, frame):
        stopped[0] = True
    def watchdog(signum, frame):
        raise TimeoutError('laboratory hard watchdog expired')
    for sig, handler in ((signal.SIGINT, stop), (signal.SIGTERM, stop), (signal.SIGALRM, watchdog)):
        old_handlers[sig] = signal.signal(sig, handler)
        signal.siginterrupt(sig, True)
    signal.setitimer(signal.ITIMER_REAL, approved['duration_seconds'] + 15)
    try:
        with EventLog(output / 'events.jsonl') as log:
            qmi_backend = LibUsbBackend(approved['qmi'], args.library)
            at_backend = LibUsbBackend(approved['at'], args.library)
            irq = next(a for a, k in approved['qmi'].endpoints if k == 3)
            daemon = LaboratoryDaemon(config, load_profile(), LabFunctionFSIO(config['mount_path']),
                LaboratoryRuntime(qmi_backend, irq, log), at_backend,
                ConfigfsTransaction(load_profile(), KernelConfigFS('/sys/kernel/config/usb_gadget',
                    allow_kernel_writes=True), config['gadget_name']), OwnedFunctionFSMount(config['mount_path']),
                experimental_build_verified=True, should_stop=lambda: stopped[0], log=log)
            result = daemon.run()
            (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
            return 0 if result['success'] else 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def entry():
    try:
        return main()
    except (BridgeError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({'status': 'STOPPED', 'error': str(exc), 'retry': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(entry())
