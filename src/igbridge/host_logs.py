# SPDX-License-Identifier: Apache-2.0
"""Read-only existing Android log collector; never injects code or clears logs.

Raw text matches are search leads, not callback/cache/control acceptance events.
Actual execution requires an explicit adb path, device serial, package and PID.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from .errors import ConfigurationError


def capture_command(argv, *, limit=2*1024*1024, timeout=15):
    if not 1 <= limit <= 16*1024*1024 or not 0 < timeout <= 30:
        raise ConfigurationError('bounded capture required')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, shell=False, start_new_session=True)
    raw, reason = bytearray(), 'completed'
    deadline = time.monotonic() + timeout
    poller = selectors.DefaultSelector()
    poller.register(process.stdout, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = 'deadline'; break
            ready = poller.select(min(remaining, 0.1))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), min(65536, limit-len(raw)+1))
            if not chunk:
                break
            raw += chunk
            if len(raw) > limit:
                del raw[limit:]; reason = 'size_limit'; break
        if reason != 'completed':
            process.kill()  # Only the collector's own local child, never DJI/device process.
        try:
            code = process.wait(timeout=max(0.01, deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill(); code = process.wait(timeout=2); reason = 'deadline'
    finally:
        poller.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill(); process.wait(timeout=2)
    return bytes(raw), {'exit_code': code, 'termination': reason,
                        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def command_plan(adb, serial, package, pid):
    if not Path(adb).is_absolute():
        raise ConfigurationError('explicit absolute adb path required')
    if not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', serial):
        raise ConfigurationError('invalid adb device selector')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+', package):
        raise ConfigurationError('explicit application package required')
    if type(pid) is not int or not 1 <= pid <= 2**31-1:
        raise ConfigurationError('explicit process PID required')
    prefix = [adb, '-s', serial]
    return [
        ('pidof', prefix + ['shell', 'pidof', package]),
        ('package', prefix + ['shell', 'dumpsys', 'package', package]),
        ('module_maps', prefix + ['shell', 'cat', f'/proc/{pid}/maps']),
        ('logcat_help', prefix + ['logcat', '--help']),
        ('existing_logcat', prefix + ['logcat', '-d', '-v', 'threadtime', f'--pid={pid}', '-t', '5000']),
        ('pidof_after', prefix + ['shell', 'pidof', package]),
    ]


def collect(adb, serial, package, pid, output):
    plan = command_plan(adb, serial, package, pid)
    if not os.access(adb, os.X_OK):
        raise ConfigurationError('adb unavailable; no automatic install')
    out = Path(output); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'timestamp': datetime.now(timezone.utc).isoformat(), 'package': package,
              'pid': pid, 'device_selector': 'REDACTED_USB_SERIAL', 'context': 'CONTEXT_UNKNOWN',
              'runtime_gate': {'callback': 'UNKNOWN', 'cache': 'UNKNOWN', 'control': 'UNKNOWN'},
              'code_injection': False, 'state_writes': False, 'connection_started': False,
              'captures': []}
    for name, command in plan:
        if name == 'existing_logcat':
            help_text = (out/'logcat_help.raw').read_bytes()
            if b'--pid' not in help_text or b'-t' not in help_text:
                report['stop_reason'] = 'device logcat options unavailable; no broad-log fallback'
                break
        raw, meta = capture_command(command)
        fd = os.open(out/f'{name}.raw', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
        except BaseException:
            raise
        report['captures'].append(dict(meta, name=name))
        if meta['exit_code'] != 0 or meta['termination'] != 'completed':
            report['stop_reason'] = name + ' unavailable/incomplete; no escalation'
            break
        if name.startswith('pidof') and str(pid).encode() not in raw.split():
            report['stop_reason'] = 'PID/package mismatch; no attach/launch'
            break
    (out/'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description='Existing Android logs; plan only by default')
    p.add_argument('--adb', required=True); p.add_argument('--serial', required=True)
    p.add_argument('--package', required=True); p.add_argument('--pid', type=int, required=True)
    p.add_argument('--output'); p.add_argument('--execute-live', action='store_true')
    args = p.parse_args(argv)
    plan = command_plan(args.adb, args.serial, args.package, args.pid)
    if args.execute_live:
        if not args.output:
            p.error('--execute-live requires --output')
        report = collect(args.adb, args.serial, args.package, args.pid, args.output)
    else:
        report = {'mode': 'PLAN_ONLY', 'executed': False, 'serial': 'REDACTED_USB_SERIAL',
                  'operations': [name for name, _ in plan], 'runtime_gate': 'UNKNOWN'}
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
