#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scan working files and all Git objects; findings never echo matched values."""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.venv', '__pycache__', '.cache', '.ruff_cache', 'dist', 'artifacts', 'build'}
FORBIDDEN = {'.aar', '.jar', '.dll', '.so', '.dylib', '.exe', '.sys', '.cat', '.dmg', '.pkg',
             '.pcap', '.pcapng', '.qcn', '.nv', '.pem', '.key', '.pdf', '.gpr', '.gzf'}
# Split literals keep the scanner's own source free of example private paths.
RULES = {
    'private-home-path': re.compile(r'/' + r'(?:Users|home)/[^\s/"\'<>]+'),
    'windows-user-path': re.compile(r'[A-Z]:\\' + r'Users\\[^\s\\]+', re.I),
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?' + r'PRIVATE KEY-----'),
    'github-token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b'),
    'cloud-access-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'credential-header': re.compile(r'(?i)(?:authorization:\s*(?:bearer|basic)\s+)[A-Za-z0-9+/=_-]{16,}'),
    'long-numeric-identifier': re.compile(r'(?<![A-Za-z0-9_])\d{14,22}(?![A-Za-z0-9_])'),
    'personal-email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
}
# Upstream license notices are preserved, including their public contact addresses.
LICENSE_CONTACT_PATHS = ('LICENSES/Apache-2.0.txt', 'LICENSES/GPL-2.0-only.txt',
                         'LICENSES/CC-BY-4.0.txt', 'LICENSES/LGPL-2.1-or-later.txt',
                         'LICENSES/Linux-syscall-note.txt')


def public_files(root=ROOT):
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(part in EXCLUDED or part.endswith('.egg-info') for part in relative.parts):
            continue
        if path.is_file() or path.is_symlink():
            yield path


def scan_bytes(raw, label, private_values=()):
    findings = []
    text = raw.decode('utf-8', errors='replace')
    for name, regex in RULES.items():
        if name == 'personal-email' and label in LICENSE_CONTACT_PATHS:
            continue
        for match in regex.finditer(text):
            # GitHub's public noreply identities are metadata, not personal mail.
            if name == 'personal-email' and match.group().endswith('@users.noreply.github.com'):
                continue
            findings.append({'file': label, 'rule': name,
                             'line': text.count('\n', 0, match.start()) + 1})
    for value in private_values:
        if value and value.casefold() in text.casefold():
            findings.append({'file': label, 'rule': 'known-private-value', 'line': None})
    return findings


def git_objects(root, private_values):
    """Include unreachable objects too; do not rely only on current tracked files."""
    if not (root/'.git').exists():
        return {'status': 'NOT_INITIALIZED', 'objects': 0, 'findings': []}
    objects = subprocess.run(['git', 'cat-file', '--batch-all-objects',
                              '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
                             cwd=root, text=True, capture_output=True, check=True).stdout.splitlines()
    findings = []; count = 0
    # Resolve reachable blobs to safe public paths so upstream notices can keep contacts.
    listing = subprocess.run(['git', 'rev-list', '--objects', '--all'], cwd=root,
                             text=True, capture_output=True, check=True).stdout.splitlines()
    names = {row.split(' ', 1)[0]: row.split(' ', 1)[1] for row in listing if ' ' in row}
    # Names in trees and the index matter independently of blob identity.
    commits = subprocess.run(['git', 'rev-list', '--all'], cwd=root, text=True,
                             capture_output=True, check=True).stdout.splitlines()
    entries = []
    for commit in commits:
        tree = subprocess.run(['git', 'ls-tree', '-r', '-z', commit],
                              cwd=root, capture_output=True, check=True).stdout
        for raw_entry in tree.split(b'\0'):
            if raw_entry:
                meta, raw_path = raw_entry.split(b'\t', 1)
                mode, kind, oid = meta.decode().split()
                if kind == 'blob':
                    entries.append((mode, oid, raw_path.decode('utf-8', errors='replace')))
    index = subprocess.run(['git', 'ls-files', '--stage', '-z'], cwd=root,
                           capture_output=True, check=True).stdout
    for raw_entry in index.split(b'\0'):
        if raw_entry:
            meta, raw_path = raw_entry.split(b'\t', 1)
            mode, oid, stage = meta.decode().split()
            entries.append((mode, oid, raw_path.decode('utf-8', errors='replace')))
    content_cache = {}
    for mode, oid, label in sorted(set(entries)):
        if mode == '120000':
            findings.append({'file': label, 'rule': 'symlink-in-git', 'line': None})
        if Path(label).suffix.lower() in FORBIDDEN:
            findings.append({'file': label, 'rule': 'forbidden-git-path', 'line': None})
        if any(part in EXCLUDED or part.endswith('.egg-info') for part in Path(label).parts):
            findings.append({'file': label, 'rule': 'excluded-artifact-in-git', 'line': None})
        findings.extend(scan_bytes(label.encode(), label, private_values))
        if oid not in content_cache:
            content_cache[oid] = subprocess.run(['git', 'cat-file', 'blob', oid], cwd=root,
                capture_output=True, check=True).stdout
        # A license-text exception must never exempt another alias of the same blob.
        findings.extend(scan_bytes(content_cache[oid], label, private_values))
    for row in objects:
        oid, kind, size = row.split()
        if int(size) > 8 * 1024 * 1024:
            findings.append({'file': 'git-object:'+oid, 'rule': 'oversized-object', 'line': None}); continue
        if kind not in ('blob', 'commit', 'tag'):
            continue
        raw = subprocess.run(['git', 'cat-file', kind, oid], cwd=root,
                             capture_output=True, check=True).stdout
        label = names.get(oid, 'git-object:'+oid)
        if kind == 'blob':
            findings.extend(artifact_findings(raw, label))
            if any(part in EXCLUDED or part.endswith('.egg-info') for part in Path(label).parts):
                findings.append({'file': label, 'rule': 'excluded-artifact-in-git', 'line': None})
        findings.extend(scan_bytes(raw, label, private_values)); count += 1
    return {'status': 'PASS' if not findings else 'FAIL', 'objects': count, 'findings': findings}


def artifact_findings(raw, label):
    findings = []
    if Path(label).suffix.lower() in FORBIDDEN or len(raw) > 2 * 1024 * 1024:
        findings.append({'file': label, 'rule': 'prohibited-or-oversized-artifact', 'line': None})
    if b'\0' in raw:
        findings.append({'file': label, 'rule': 'binary-content', 'line': None})
    return findings


def audit(root=ROOT, include_objects=False, private_values=()):
    findings = []; count = 0
    for path in public_files(root):
        label = str(path.relative_to(root)); count += 1
        if path.is_symlink():
            findings.append({'file': label, 'rule': 'symlink-excluded', 'line': None}); continue
        raw = path.read_bytes()
        findings.extend(artifact_findings(raw, label))
        findings.extend(scan_bytes(raw, label, private_values))
    objects = git_objects(root, private_values) if include_objects else {'status': 'NOT_REQUESTED', 'objects': 0, 'findings': []}
    findings.extend(objects['findings'])
    return {'scanner': 'OpenIG831T publication audit', 'files': count, 'git_objects': objects['objects'],
            'git_object_status': objects['status'], 'network_verification': False,
            'findings': findings, 'status': 'PASS' if not findings else 'FAIL'}


def main():
    p = argparse.ArgumentParser(); p.add_argument('--git-objects', action='store_true')
    p.add_argument('--private-rules', help='Untracked local JSON list of exact values; never printed')
    p.add_argument('--output', help='Write metadata outside the tracked tree or in ignored artifacts')
    args = p.parse_args()
    values = json.loads(Path(args.private_rules).read_text()) if args.private_rules else []
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        p.error('private rules must be a list of strings')
    result = audit(include_objects=args.git_objects, private_values=values)
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
