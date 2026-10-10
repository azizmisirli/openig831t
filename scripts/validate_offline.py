#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run hardware-free tests and offline entry points; do not discover devices."""
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', help='New ordinary directory for sanitized test metadata')
    args = p.parse_args()
    os.chdir(ROOT); sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT/'src'))
    sys.dont_write_bytecode = True
    log = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(ROOT/'src'))
    smoke = []
    for module, arguments in [('igbridge', ['dry-run']), ('igbridge.lab_daemon', []),
                              ('igbridge.candidate_inventory', [])]:
        run = subprocess.run([sys.executable, '-m', module, *arguments], cwd=ROOT,
                             env=env, capture_output=True, text=True, timeout=30)
        smoke.append({'module': module, 'exit_code': run.returncode})
        if run.returncode:
            log.write(run.stderr)
    report = {'mode': 'OFFLINE_ONLY', 'hardware_access': False, 'tests': result.testsRun,
              'failures': len(result.failures), 'errors': len(result.errors),
              'skipped': len(result.skipped), 'smoke': smoke,
              'passed': result.wasSuccessful() and all(s['exit_code'] == 0 for s in smoke)}
    if args.output:
        out = Path(args.output); out.mkdir(parents=True, exist_ok=False)
        (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        # Tracebacks may contain local paths: logs stay in ignored output only.
        (out/'unittest.log').write_text(log.getvalue())
    if not report['passed']:
        print(log.getvalue(), file=sys.stderr)
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
