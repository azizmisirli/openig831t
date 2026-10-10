# SPDX-License-Identifier: Apache-2.0
"""Explicit offline default; live subcommand requires an exact target file."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from .descriptors import load_profile
from .qmi import build_message, parse_message, result_code, service_versions
from .usb import send_setup, get_setup, response_available
from .errors import BridgeError, ConfigurationError


def _dump(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def dry_run(profile_path=None):
    profile = load_profile(profile_path)
    payload = build_message(0, 0, 1, 0x21)
    return {'mode': 'OFFLINE', 'usb_open': False, 'transfers': 0,
            'target': profile.summary(), 'configuration': 1, 'interface': 4,
            'alternate': 0, 'request_hex': payload.hex(' '),
            'send_setup': send_setup(4, len(payload)).pack().hex(' '),
            'interrupt_endpoint': '0x89',
            'expected_notification': response_available(4).hex(' '),
            'get_setup_after_notification': get_setup(4).pack().hex(' '),
            'transaction': 1, 'message': '0x0021',
            'success_requires': ['matched CTL/client0/transaction1/message0x21 response',
                                 'consistent QMUX/TLV lengths', 'result SUCCESS',
                                 'consistent service-version list'],
            'live_gadget_ready': False,
            'reason': 'stock FunctionFS CDC descriptor rejection; real UDC/host unmeasured'}


def target_from_file(path):
    from .libusb_backend import UsbTarget
    data = json.loads(Path(path).read_text())
    if data.get('schema_version') != 1:
        raise ConfigurationError('target schema_version must be 1')
    def integer(name, maximum):
        value = data.get(name)
        if type(value) is not int or not 0 <= value <= maximum:
            raise ConfigurationError(f'invalid target {name}')
        return value
    endpoints = tuple(tuple(row) for row in data['endpoints'])
    if not endpoints or any(len(row) != 2 or type(row[0]) is not int or type(row[1]) is not int
                            or not 1 <= row[0] <= 255 or row[0] & 0x70
                            or not row[0] & 15 or row[1] not in (2, 3) for row in endpoints):
        raise ConfigurationError('invalid exact endpoint contract')
    if len(endpoints) != len(set(address for address, kind in endpoints)):
        raise ConfigurationError('duplicate endpoints')
    interrupt = integer('interrupt_endpoint', 255)
    if (interrupt, 3) not in endpoints or not interrupt & 0x80:
        raise ConfigurationError('interrupt IN contract required')
    t = UsbTarget(integer('vid', 65535), integer('pid', 65535), integer('interface', 255),
                  endpoints, integer('configuration', 255), integer('alternate', 255),
                  data.get('bus'), data.get('address'))
    return t, interrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description='IG831T laboratory tools; offline by default')
    commands = parser.add_subparsers(dest='command')
    dry = commands.add_parser('dry-run'); dry.add_argument('--profile')
    descriptors = commands.add_parser('emit-descriptors')
    descriptors.add_argument('--profile'); descriptors.add_argument('--output', required=True)
    parse = commands.add_parser('parse-qmi'); parse.add_argument('hex_file')
    sandbox = commands.add_parser('configfs-sandbox')
    sandbox.add_argument('--output', required=True)
    probe = commands.add_parser('probe-version', help='EXPLICIT LIVE read-only CTL probe; never automatic')
    probe.add_argument('--target', required=True); probe.add_argument('--output', required=True)
    probe.add_argument('--execute-live', action='store_true')
    probe.add_argument('--dtr', action='store_true')
    probe.add_argument('--wait-sync', action='store_true')
    probe.add_argument('--library')
    args = parser.parse_args(argv)
    if args.command in (None, 'dry-run'):
        _dump(dry_run(getattr(args, 'profile', None))); return 0
    if args.command == 'parse-qmi':
        raw = bytes.fromhex(Path(args.hex_file).read_text())
        m = parse_message(raw)
        _dump({'service': m.service, 'client': m.cid, 'transaction': m.transaction_id,
               'message': m.message_id, 'kind': m.kind, 'raw_hex': raw.hex(' '),
               'tlvs': [{'type': t.type, 'hex': t.value.hex(' ')} for t in m.tlvs]})
        return 0
    if args.command == 'emit-descriptors':
        p = load_profile(args.profile)
        out = Path(args.output); out.mkdir(mode=0o700, parents=True, exist_ok=False)
        blobs = {'functionfs_descriptors.bin': p.functionfs_descriptors(),
                 'functionfs_strings.bin': p.functionfs_strings(),
                 'configuration_hs.bin': p.high_speed,
                 'configuration_fs.bin': p.full_speed}
        for name, raw in blobs.items():
            (out / name).write_bytes(raw)
        report = {'mode': 'OFFLINE_ENCODE_ONLY', 'hardware_access': False,
                  'profile': p.summary(),
                  'sha256': {n: hashlib.sha256(b).hexdigest() for n, b in blobs.items()}}
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        _dump(report); return 0
    if args.command == 'configfs-sandbox':
        from .configfs import DirectoryFS, ConfigfsTransaction
        out = Path(args.output); out.mkdir(mode=0o700, parents=True, exist_ok=False)
        transaction = ConfigfsTransaction(load_profile(), DirectoryFS(out))
        transaction.stage(serial_number='LAB_ONLY')
        transaction.cleanup()
        _dump({'mode': 'ORDINARY_TEMP_DIRECTORY', 'kernel_access': False,
               'stage_and_rollback': 'PASS', 'remaining_entries': len(list(out.iterdir()))})
        return 0
    if not args.execute_live:
        raise ConfigurationError('live operation requires --execute-live; no device opened')
    if args.wait_sync and not args.dtr:
        raise ConfigurationError('--wait-sync requires explicit --dtr in this probe flow')
    target, interrupt = target_from_file(args.target)
    from .libusb_backend import LibUsbBackend
    from .runtime import LaboratoryRuntime, cleanup_succeeded
    from .logging import EventLog
    out = Path(args.output); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    status = {'mode': 'LIVE_LAB_CTL_VERSION_ONLY', 'target_vid': target.vid,
              'target_pid': target.pid, 'interface': target.interface,
              'data_session_started': False, 'automatic_retry': False}
    with EventLog(out / 'events.jsonl') as log:
        runtime = LaboratoryRuntime(LibUsbBackend(target, args.library), interrupt, log)
        runtime_opened = False
        try:
            runtime.open()
            runtime_opened = True
            if args.dtr:
                runtime.set_dtr(True)
            if args.wait_sync:
                runtime.wait_sync()
            response = runtime.query(build_message(0, 0, 1, 0x21))
            status['response_hex'] = response.to_bytes().hex(' ')
            status['result'] = result_code(response)
            if status['result'] == (0, 0):
                status['service_versions'] = service_versions(response)
                status['qmi_confirmed'] = True
            else:
                status['qmi_confirmed'] = False
        except Exception as exc:
            status.update(error_type=type(exc).__name__, error=str(exc), qmi_confirmed=False)
        finally:
            try:
                if runtime_opened:
                    status['cleanup'] = runtime.close()
                    status['cleanup_success'] = cleanup_succeeded(status['cleanup'])
                else:
                    # open() already attempted its own partial-start cleanup.
                    # Do not automatically repeat a failed native cancellation.
                    status['cleanup'] = {'status': 'UNCONFIRMED', 'retry': False,
                                         'reason': 'runtime initialization did not complete'}
                    status['cleanup_success'] = False
            except Exception as exc:
                status['cleanup_error'] = str(exc)
            (out / 'result.json').write_text(json.dumps(status, ensure_ascii=False, indent=2) + '\n')
    _dump(status)
    return 0 if status.get('qmi_confirmed') and status.get('cleanup_success') else 1


def entry():
    try:
        return main()
    except (BridgeError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({'status': 'STOPPED', 'error': str(exc), 'retry': False}), file=sys.stderr)
        return 2
