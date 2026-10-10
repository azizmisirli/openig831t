#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent detect-secrets engine, with network verification disabled."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from publication_audit import ROOT, public_files


def metadata_digest_values(name, report, allowed):
    """Only computed or independently reviewed digest metadata is eligible.

    This does not exempt any file or any credential detector. A finding must be
    the exact digest value, recognized by its detector-generated SHA1 identity.
    """
    values = set()
    if name == 'PUBLICATION_RESULT.md':
        result = subprocess.run(['git', 'rev-list', '--all'], cwd=ROOT, text=True,
                                capture_output=True, check=True)
        values.update(result.stdout.splitlines())
    elif name == 'PUBLICATION_INVENTORY.json':
        from evidence_validator import validate
        if validate()['status'] != 'PASS':
            return values
        data = json.loads((ROOT/name).read_text())
        values.update(row['sha256'] for row in data['included'])
    elif name == 'evidence/manifests/licenses.json':
        data = json.loads((ROOT/name).read_text())
        for row in data['files']:
            target = ROOT/row['path']
            if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == row['sha256']:
                values.add(row['sha256'])
    elif name == 'evidence/manifests/secret-scan-allowlist.json':
        for row in allowed:
            target = ROOT/row['file']
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != row['file_sha256']:
                continue
            source_findings = report['results'].get(row['file'], report['results'].get('./'+row['file'], []))
            if row.get('reason') and any(item['type'] == row['type'] and
                    item['hashed_secret'] == row['finding_digest'] for item in source_findings):
                values.update((row['file_sha256'], row['finding_digest']))
    return {v for v in values if isinstance(v, str) and re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', v)}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output')
    args = parser.parse_args()
    executable = shutil.which('detect-secrets')
    if not executable:
        print('detect-secrets is required; install the dev extra.', file=sys.stderr); return 2
    # Scan only curated candidates, independent of Git's staging state.
    with tempfile.TemporaryDirectory(prefix='openig831t-secret-scan-') as temp:
        base = Path(temp)
        for path in public_files():
            if path.is_symlink():
                raise ValueError('symlink is not a publication candidate')
            target = base/path.relative_to(ROOT); target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        command = [str(Path(executable).resolve()), 'scan', '--all-files', '--no-verify', '.']
        run = subprocess.run(command, cwd=base, text=True, capture_output=True, check=True, timeout=120)
        report = json.loads(run.stdout)
    allow_file = ROOT/'evidence/manifests/secret-scan-allowlist.json'
    allowed = json.loads(allow_file.read_text()) if allow_file.exists() else []
    unresolved = []; reviewed = 0; computed_metadata = 0
    for name, items in report['results'].items():
        name = name.removeprefix('./')
        digest = hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
        digests = {hashlib.sha1(v.encode()).hexdigest() for v in metadata_digest_values(name, report, allowed)}
        for item in items:
            if item['type'] == 'Hex High Entropy String' and item['hashed_secret'] in digests:
                computed_metadata += 1
                continue
            match = next((a for a in allowed if a['file'] == name and a['file_sha256'] == digest
                          and a['type'] == item['type'] and a['finding_digest'] == item['hashed_secret']), None)
            if match and match.get('reason'):
                reviewed += 1
            else:
                unresolved.append({'file': name, 'type': item['type'], 'line': item['line_number'],
                                   'hashed_secret': item['hashed_secret'], 'file_sha256': digest})
    result = {'engine': 'detect-secrets', 'version': report['version'], 'network_verification': False,
              'reviewed_false_positives': reviewed, 'verified_digest_metadata': computed_metadata, 'unresolved': unresolved,
              'status': 'PASS' if not unresolved else 'FAIL'}
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
