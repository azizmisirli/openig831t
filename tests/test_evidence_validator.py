# SPDX-License-Identifier: Apache-2.0
"""Synthetic provenance, self-hash and refresh-boundary tests; file-only."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from scripts.evidence_validator import INVENTORY, inventory_digest, refresh, validate


class EvidenceValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='openig831t-evidence-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.status = {'end_to_end_5g_demonstrated': False,
                       'direct_replacement_established': False,
                       'bridge_required_established': False,
                       'physical_gadget_validated': False,
                       'candidate_5g_modem_measured': False, 'final_verdict': None}
        (self.root / 'RESEARCH_STATUS.json').write_text(json.dumps(self.status))
        (self.root / 'example.txt').write_text('Synthetic original evidence summary\n')
        self.document = {'included': [self.record(name) for name in
                         ('RESEARCH_STATUS.json', 'example.txt', INVENTORY)]}
        self.save()

    def record(self, name):
        return {'source_path': 'original-project/' + name, 'destination_path': name,
                'purpose': 'Synthetic fixture', 'origin': 'Original synthetic test',
                'ownership': 'Project original', 'license': 'Apache-2.0',
                'redaction': 'No personal data', 'publication_decision': 'PUBLIC_ORIGINAL_CODE',
                'sha256': hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                          if name != INVENTORY else None}

    def save(self):
        next(row for row in self.document['included'] if row['destination_path'] == INVENTORY)[
            'sha256'] = inventory_digest(self.document)
        (self.root / INVENTORY).write_text(json.dumps(self.document, indent=2) + '\n')

    def test_valid_inventory_then_hash_mutation(self):
        self.assertEqual(validate(self.root)['status'], 'PASS')
        (self.root / 'example.txt').write_text('changed\n')
        self.assertIn('hash mismatch: example.txt', validate(self.root)['errors'])
        refresh(self.root)
        self.assertEqual(validate(self.root)['status'], 'PASS')

    def test_refresh_does_not_invent_provenance_for_unreviewed_file(self):
        original = (self.root / INVENTORY).read_bytes()
        (self.root / 'new.txt').write_text('unreviewed synthetic artifact\n')
        with self.assertRaisesRegex(ValueError, 'review new/removed files'):
            refresh(self.root)
        self.assertEqual((self.root / INVENTORY).read_bytes(), original)
        self.assertEqual(validate(self.root)['status'], 'FAIL')

    def test_missing_provenance_unknown_license_and_duplicates_fail(self):
        row = self.document['included'][1]
        row.pop('ownership'); row['license'] = 'UNKNOWN_LICENSE'
        self.document['included'].append(dict(row))
        self.save()
        errors = validate(self.root)['errors']
        self.assertIn('incomplete provenance: example.txt', errors)
        self.assertIn('unknown license: example.txt', errors)
        self.assertIn('duplicate inventory destination', errors)

    def test_hash_refresh_does_not_override_research_status_gates(self):
        self.status['physical_gadget_validated'] = True
        (self.root / 'RESEARCH_STATUS.json').write_text(json.dumps(self.status))
        refresh(self.root)
        self.assertIn('research preview safety gate: physical_gadget_validated',
                      validate(self.root)['errors'])

    def test_symlink_is_rejected_as_evidence(self):
        path = self.root / 'example.txt'; path.unlink()
        path.symlink_to(self.root / 'RESEARCH_STATUS.json')
        self.assertIn('symlink: example.txt', validate(self.root)['errors'])


if __name__ == '__main__':
    unittest.main()
