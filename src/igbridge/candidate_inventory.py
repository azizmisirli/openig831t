# SPDX-License-Identifier: Apache-2.0
"""Finite candidate comparison capture. Default is an offline launch plan.

Exact target topology must be supplied; this module never chooses a USB mode,
creates a data session, probes alternative endpoints, or retries a request.
"""
import argparse
import json
from pathlib import Path
from .cli import target_from_file
from .errors import ProtocolError
from .qmi import TLV, build_message, result_code, service_versions
from .policy import LaboratoryPolicy

PLAN = ((2, (0x20, 0x21, 0x22, 0x23, 0x2c, 0x2d, 0x45)),
        (3, (0x24, 0x31, 0x4f)), (26, (0x21,)), (11, (0x2f,)), (1, (0x22,)))


def plan():
    return {'mode': 'OFFLINE_PLAN', 'device_open': False,
            'queries': [{'service': sid, 'messages': list(messages)} for sid, messages in PLAN],
            'temporary_clients': [sid for sid, _ in PLAN],
            'no_input_tlvs': True, 'data_session': False, 'retry': False,
            'dtr': 'explicit --dtr only', 'sync': 'explicit --wait-sync only',
            'requires': 'measured exact candidate VID/PID/interface/endpoint target JSON',
            'schema': 'igbridge/data/candidate_readonly_queries.json',
            'cleanup': 'owned CID release once, interrupt cancel/drain, DTR clear if attempted, interface release'}


def capture(runtime, record):
    """Runtime must already be open. Caller ALWAYS owns close(), even on error.

    Each reply is persisted by record before any semantic extraction. Valid QMI
    errors are measurements, not absent hardware capabilities. Transport or
    framing failures propagate immediately; runtime's fail-safe owns cleanup.
    """
    policy = LaboratoryPolicy()
    def query(raw):
        from .qmi import parse_message
        policy.qmi(parse_message(raw))
        response = runtime.query(raw)
        row = {'request_hex': raw.hex(' '), 'response_hex': response.to_bytes().hex(' '),
               'service': response.service, 'client': response.cid,
               'transaction': response.transaction_id, 'message': response.message_id,
               'result': list(result_code(response)),
               'tlvs': [{'type': t.type, 'raw_hex': t.value.hex(' ')} for t in response.tlvs]}
        record(row)
        return response
    version = query(build_message(0, 0, 1, 0x21))
    if result_code(version) != (0, 0):
        return {'status': 'CTL_QUERY_FAILED', 'hardware_capability_conclusion': 'UNKNOWN'}
    versions = service_versions(version)
    skipped, allocated, ctl_tid = [], [], 2
    for service, messages in PLAN:
        if service not in versions:
            skipped.append({'service': service, 'reason': 'not advertised; no probe'})
            continue
        response = query(build_message(0, 0, ctl_tid, 0x22, tlvs=(TLV(1, bytes([service])),)))
        ctl_tid += 1
        if result_code(response) != (0, 0):
            skipped.append({'service': service, 'reason': 'allocation error; no retry'})
            continue
        binding = response.tlv(1)
        if len(binding) != 2 or binding[0] != service or binding[1] in (0, 255):
            raise ProtocolError('unexpected candidate client allocation')
        allocated.append({'service': service, 'client': binding[1]})
        for tid, message in enumerate(messages, 1):
            query(build_message(service, binding[1], tid, message))
    return {'status': 'CAPTURE_COMPLETE', 'service_versions': versions,
            'allocated_clients': allocated, 'skipped': skipped,
            'data_session_started': False, 'query_errors_are_not_capability_absence': True}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target'); p.add_argument('--output'); p.add_argument('--library')
    p.add_argument('--execute-live', action='store_true')
    p.add_argument('--dtr', action='store_true'); p.add_argument('--wait-sync', action='store_true')
    args = p.parse_args(argv)
    if not args.execute_live:
        print(json.dumps(plan(), indent=2)); return 0
    if not args.target or not args.output or (args.wait_sync and not args.dtr):
        p.error('live requires target/output; wait-sync requires explicit dtr')
    target, endpoint = target_from_file(args.target)
    from .libusb_backend import LibUsbBackend
    from .logging import EventLog
    from .runtime import LaboratoryRuntime, cleanup_succeeded
    out = Path(args.output); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'mode': 'LIVE_READONLY_CANDIDATE', 'target_vid': target.vid,
              'target_pid': target.pid, 'interface': target.interface, 'data_session_started': False}
    with EventLog(out/'events.jsonl') as log, EventLog(out/'responses.jsonl') as raw_log:
        runtime = LaboratoryRuntime(LibUsbBackend(target, args.library), endpoint, log)
        runtime_opened = False
        try:
            runtime.open()
            runtime_opened = True
            if args.dtr:
                runtime.set_dtr(True)
            if args.wait_sync:
                runtime.wait_sync()
            report.update(capture(runtime, lambda row: raw_log.emit('query_result', **row)))
        except Exception as exc:
            report.update(status='STOPPED', error_type=type(exc).__name__, error=str(exc))
        finally:
            try:
                if runtime_opened:
                    report['cleanup'] = runtime.close()
                    report['cleanup_success'] = cleanup_succeeded(report['cleanup'])
                else:
                    report['cleanup'] = {'status': 'UNCONFIRMED', 'retry': False,
                                         'reason': 'runtime initialization did not complete'}
                    report['cleanup_success'] = False
            except Exception as exc:
                report['cleanup_success'] = False
                report['cleanup_error'] = str(exc)
            (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report.get('status') == 'CAPTURE_COMPLETE' and report.get('cleanup_success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
