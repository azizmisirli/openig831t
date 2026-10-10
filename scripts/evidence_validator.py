#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify curated provenance and hashes without devices, subprocesses or network."""
import argparse
import copy
import hashlib
import json
try:
    from publication_audit import ROOT, public_files
except ImportError:
    from scripts.publication_audit import ROOT, public_files

INVENTORY = 'PUBLICATION_INVENTORY.json'
REQUIRED = {'source_path', 'destination_path', 'purpose', 'origin', 'ownership',
            'license', 'redaction', 'sha256', 'publication_decision'}


def inventory_digest(document):
    value = copy.deepcopy(document)
    for record in value['included']:
        if record['destination_path'] == INVENTORY:
            record['sha256'] = None
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def validate(root=ROOT):
    data = json.loads((root/INVENTORY).read_text())
    found = {str(p.relative_to(root)): p for p in public_files(root)}
    records = data['included']; indexed = {row['destination_path']: row for row in records}
    errors = []
    if len(indexed) != len(records):
        errors.append('duplicate inventory destination')
    if set(found) != set(indexed):
        errors.append('inventory/file set mismatch: '+str(sorted(set(found)^set(indexed))))
    for name, row in indexed.items():
        if not REQUIRED <= row.keys() or any(not row.get(key) for key in REQUIRED):
            errors.append('incomplete provenance: '+name)
        if row.get('license') in ('UNKNOWN', 'UNKNOWN_LICENSE', None):
            errors.append('unknown license: '+name)
        if not row.get('publication_decision', '').startswith('PUBLIC_'):
            errors.append('unapproved file: '+name)
        if name not in found:
            continue
        path = found[name]
        if path.is_symlink():
            errors.append('symlink: '+name); continue
        actual = inventory_digest(data) if name == INVENTORY else hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != row['sha256']:
            errors.append('hash mismatch: '+name)
    status = json.loads((root/'RESEARCH_STATUS.json').read_text())
    for key in ('end_to_end_5g_demonstrated', 'direct_replacement_established',
                'bridge_required_established', 'physical_gadget_validated', 'candidate_5g_modem_measured'):
        if status.get(key) is not False:
            errors.append('research preview safety gate: '+key)
    if status.get('final_verdict', 'missing') is not None:
        errors.append('final verdict must remain null')
    return {'status': 'PASS' if not errors else 'FAIL', 'included_files': len(records), 'errors': errors}


def refresh(root=ROOT):
    """Refresh hashes only. New files require an explicit reviewed provenance record."""
    path = root/INVENTORY; data = json.loads(path.read_text())
    expected = {row['destination_path'] for row in data['included']}
    actual = {str(p.relative_to(root)) for p in public_files(root)}
    if expected != actual:
        raise ValueError('review new/removed files before refreshing the inventory')
    for row in data['included']:
        name = row['destination_path']
        row['sha256'] = None if name == INVENTORY else hashlib.sha256((root/name).read_bytes()).hexdigest()
    next(row for row in data['included'] if row['destination_path'] == INVENTORY)['sha256'] = inventory_digest(data)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True)+'\n')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    if args.refresh:
        refresh()
    result = validate(); print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
