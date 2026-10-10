#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate local links, JSON and research status without network access."""
import json
from pathlib import Path
import re
from urllib.parse import unquote
from publication_audit import ROOT, public_files


def main():
    errors = []; links = documents = json_files = 0
    for path in public_files():
        if path.suffix == '.json':
            json.loads(path.read_text()); json_files += 1
        if path.suffix not in ('.md', '.cff', '.yml', '.yaml'):
            continue
        if path.suffix != '.md':
            import yaml
            yaml.safe_load(path.read_text()); continue
        documents += 1
        text = re.sub(r'```.*?```', '', path.read_text(), flags=re.S)
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            target = target.split(' "', 1)[0].strip('<>')
            if target.startswith(('https://', 'http://', '#', 'mailto:')):
                continue
            target = unquote(target.split('#', 1)[0])
            if not target:
                continue
            resolved = (path.parent/target).resolve()
            if ROOT not in resolved.parents or not resolved.exists():
                errors.append({'file': str(path.relative_to(ROOT)), 'missing_local_link': target})
            links += 1
    status = json.loads((ROOT/'RESEARCH_STATUS.json').read_text())
    for field in ('end_to_end_5g_demonstrated', 'direct_replacement_established',
                  'bridge_required_established', 'physical_gadget_validated', 'candidate_5g_modem_measured'):
        if status.get(field) is not False:
            errors.append({'research_status_field': field, 'error': 'preview evidence does not establish this claim'})
    if status.get('final_verdict') is not None or status.get('stage') != 'research-preview':
        errors.append({'error': 'unsupported final verdict or stage'})
    import jsonschema
    jsonschema.validate(status, json.loads((ROOT/'schemas/research-status.schema.json').read_text()))
    print(json.dumps({'status': 'PASS' if not errors else 'FAIL', 'documents': documents,
                      'local_links': links, 'json_files': json_files, 'external_links_checked': False,
                      'errors': errors}, indent=2))
    return 0 if not errors else 1


if __name__ == '__main__':
    raise SystemExit(main())
