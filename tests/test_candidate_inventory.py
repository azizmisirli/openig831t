# SPDX-License-Identifier: Apache-2.0
"""Finite read-only candidate plan; synthetic transport only."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from igbridge import candidate_inventory as inventory
from igbridge.qmi import TLV, build_message, parse_message
from igbridge.runtime import LaboratoryRuntime, cleanup_succeeded
from test_runtime import SyntheticBackend, SyntheticInterrupt


class Backend(SyntheticBackend):
    def __init__(self, services=(2, 3, 26, 11, 1), error_service=None):
        super().__init__(); self.services = services; self.error_service = error_service

    def control(self, setup, data=b''):
        result = super().control(setup, data)
        if setup.request == 0:
            request = parse_message(data)
            tlvs = [TLV(2, b'\0'*4)]
            if request.service == 0 and request.message_id == 0x21:
                tlvs.append(TLV(1, bytes([len(self.services)]) +
                                b''.join(struct.pack('<BHH', sid, 1, 0) for sid in self.services)))
            elif request.service == self.error_service:
                tlvs = [TLV(2, struct.pack('<HH', 1, 71))]
            else:
                return result
            self.responses[-1] = build_message(request.service, request.cid, request.transaction_id,
                                               request.message_id, 'response', tlvs)
        return result


class CandidateInventoryTests(unittest.TestCase):
    def run_capture(self, backend):
        runtime = LaboratoryRuntime(backend, 0x89, interrupt_factory=SyntheticInterrupt)
        runtime.open(); rows = []
        try:
            report = inventory.capture(runtime, rows.append)
        finally:
            cleanup = runtime.close()
        self.assertTrue(cleanup_succeeded(cleanup))
        return report, rows, cleanup

    def test_schema_plan_is_only_no_input_readonly_queries(self):
        entries = json.loads((Path(__file__).resolve().parents[1]/'src/igbridge/data/candidate_readonly_queries.json').read_text())
        self.assertEqual({(sid, mid) for sid, mids in inventory.PLAN for mid in mids},
                         {(e['service'], e['message']) for e in entries})
        for e in entries:
            self.assertTrue(e['name'].startswith('Get '))
            self.assertEqual(e['input_tlvs'], [])
            self.assertEqual(e['evidence_level'], 'SOURCE_SUPPORTED')
            self.assertRegex(e['source_sha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(e['source_url'].startswith('https://github.com/linux-mobile-broadband/libqmi/blob/'))
            self.assertNotIn('schema', e)  # Upstream schema is reference-only.
            request = parse_message(build_message(e['service'], 17, 1, e['message']))
            self.assertEqual(request.tlvs, ())

    def test_full_capture_and_owned_cleanup_have_no_network_actions(self):
        b = Backend(); report, rows, cleanup = self.run_capture(b)
        self.assertEqual(report['status'], 'CAPTURE_COMPLETE')
        self.assertEqual(len(rows), 19)
        self.assertEqual(len(cleanup['releases']), 5)
        requests = [parse_message(c[2]) for c in b.calls if isinstance(c, tuple) and c[0] == 0]
        self.assertEqual(len(requests), 24)
        self.assertFalse(any(r.service == 1 and r.message_id in (0x20, 0x21) for r in requests))
        self.assertFalse(any(c[0] == 0x22 for c in b.calls if isinstance(c, tuple)))

    def test_absent_service_is_not_probed(self):
        report, rows, cleanup = self.run_capture(Backend(services=(2,)))
        self.assertEqual(len(cleanup['releases']), 1)
        self.assertEqual(len(report['skipped']), 4)
        self.assertEqual({r['service'] for r in rows}, {0, 2})

    def test_valid_query_failure_is_preserved_once_and_does_not_mean_no_hardware(self):
        report, rows, _ = self.run_capture(Backend(error_service=3))
        errors = [r for r in rows if r['result'] == [1, 71]]
        self.assertEqual(len(errors), 3)
        self.assertTrue(report['query_errors_are_not_capability_absence'])
        self.assertEqual(len({(r['service'], r['client'], r['transaction']) for r in rows}), len(rows))

    def test_default_cli_never_constructs_backend(self):
        with patch('igbridge.libusb_backend.LibUsbBackend', side_effect=AssertionError('USB forbidden')):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(inventory.main([]), 0)
        self.assertFalse(json.loads(out.getvalue())['device_open'])

    def test_live_entrypoints_never_retry_partial_open_cleanup(self):
        from igbridge.cli import main as cli_main
        class PartialRuntime:
            def __init__(self, *args):
                pass
            def open(self):
                raise OSError('synthetic failed interrupt cancellation during open')
            def close(self):
                raise AssertionError('must not retry cancellation')
        target = str(Path(__file__).resolve().parents[1]/'src/igbridge/data/ig831t_lab_target.json')
        for entry, prefix in ((inventory.main, []), (cli_main, ['probe-version'])):
            with self.subTest(entry=entry.__module__), tempfile.TemporaryDirectory() as tmp:
                out = str(Path(tmp)/'run')
                with patch('igbridge.libusb_backend.LibUsbBackend', return_value=object()), \
                        patch('igbridge.runtime.LaboratoryRuntime', PartialRuntime), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(entry(prefix+['--target', target, '--output', out, '--execute-live']), 1)
                report = json.loads((Path(out)/'result.json').read_text())
                self.assertFalse(report['cleanup_success'])
                self.assertEqual(report['cleanup']['status'], 'UNCONFIRMED')
