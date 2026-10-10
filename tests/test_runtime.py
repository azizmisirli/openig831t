# SPDX-License-Identifier: Apache-2.0
"""Synthetic complete lifecycle, no native USB calls or live CLI branch."""
from collections import deque
from types import SimpleNamespace
import unittest
from igbridge.runtime import LaboratoryRuntime, cleanup_succeeded
from igbridge.qmi import build_message, parse_message, TLV
from igbridge.usb import response_available, send_setup
from igbridge.errors import ProtocolError


class SyntheticBackend:
    def __init__(self):
        self.target = SimpleNamespace(interface=4)
        self.calls, self.responses, self.notifications = [], deque(), deque()
        self.bad_result = self.timeout_once = self.no_response = False
        self.opened = False
    def open(self):
        self.opened = True; self.calls.append('OPEN')
    def close(self):
        self.calls.append('CLOSE'); self.opened = False; return []
    def control(self, setup, data=b''):
        self.calls.append((setup.request, setup.value, data))
        if setup.request == 1:
            return self.responses.popleft()
        if setup.request == 0:
            request = parse_message(data)
            tlvs = [TLV(2, b'\0'*4)]
            if request.service == 0 and request.message_id == 0x22:
                tlvs.append(TLV(1, request.tlv(1) + b'\x07'))
            elif request.service == 0 and request.message_id == 0x23:
                tlvs.append(TLV(1, request.tlv(1)))
            elif self.bad_result and request.service == 2:
                tlvs = []
            response = build_message(request.service, request.cid, request.transaction_id,
                                     request.message_id, 'response', tlvs)
            if self.timeout_once:
                self.notifications.append((2, b'')); self.timeout_once = False
            if not self.no_response:
                self.responses.append(response)
                self.notifications.append((0, response_available(4)))
        return len(data)


class SyntheticInterrupt:
    def __init__(self, backend, endpoint, timeout_ms):
        self.backend, self.pending = backend, False
    def arm(self):
        if self.pending:
            raise AssertionError('double arm')
        self.backend.calls.append('ARM'); self.pending = True
        return {'armed': True}
    def pump(self, timeout_ms):
        if self.backend.notifications:
            self.pending = False
            return self.backend.notifications.popleft()
        return None
    def close(self):
        self.backend.calls.append('CANCEL_DRAIN'); self.pending = False


class RuntimeTests(unittest.TestCase):
    def runtime(self):
        backend = SyntheticBackend()
        runtime = LaboratoryRuntime(backend, 0x89, interrupt_factory=SyntheticInterrupt)
        runtime.open()
        return backend, runtime

    def test_submit_precedes_dtr_send_and_cancel_precedes_clear_release(self):
        b, r = self.runtime()
        r.set_dtr(True)
        r.query(build_message(0, 0, 1, 0x21))
        self.assertTrue(cleanup_succeeded(r.close()))
        self.assertEqual(b.calls[:3], ['OPEN', 'ARM', (0x22, 1, b'')])
        self.assertEqual(b.calls[-3:], ['CANCEL_DRAIN', (0x22, 0, b''), 'CLOSE'])

    def test_idle_interrupt_timeout_never_resends_request(self):
        b, r = self.runtime(); b.timeout_once = True
        result = r.query(build_message(0, 0, 1, 0x21))
        self.assertEqual(result.message_id, 0x21)
        sends = [c for c in b.calls if isinstance(c, tuple) and c[0] == 0]
        self.assertEqual(len(sends), 1)
        self.assertTrue(cleanup_succeeded(r.close()))

    def test_owned_client_release_on_normal_close(self):
        b, r = self.runtime()
        r.query(build_message(0, 0, 1, 0x22, tlvs=(TLV(1, b'\2'),)))
        result = r.close()
        self.assertEqual(len(result['releases']), 1)
        self.assertTrue(cleanup_succeeded(result))
        self.assertEqual(result['control']['client_cleanup']['known_backend_clients'], [])

    def test_undelivered_host_allocation_replies_do_not_poison_local_cleanup(self):
        b, r = self.runtime()
        for tid, service in ((1, 2), (2, 3)):
            request = build_message(0, 0, tid, 0x22, tlvs=(TLV(1, bytes([service])),))
            r._ready()
            r.control.request(send_setup(4, len(request)), request)
            r.poll()
        self.assertEqual(len(r.control.responses), 2)
        result = r.close()
        self.assertEqual(result['abandoned_frontend_delivery_count'], 2)
        self.assertEqual(len(result['releases']), 2)
        self.assertTrue(cleanup_succeeded(result))
        self.assertEqual(result['control']['client_cleanup']['known_backend_clients'], [])

    def test_cleanup_log_failure_does_not_skip_owned_usb_teardown(self):
        b, r = self.runtime()
        request = build_message(0, 0, 1, 0x22, tlvs=(TLV(1, b'\2'),))
        r.control.request(send_setup(4, len(request)), request); r.poll()
        class DiskFull:
            def emit(self, *args, **kwargs):
                raise OSError('synthetic full disk')
        r.log = DiskFull()
        result = r.close()
        self.assertFalse(cleanup_succeeded(result))
        self.assertEqual(result['errors'][0]['action'], 'cleanup_log')
        self.assertEqual(len(result['releases']), 1)
        self.assertEqual(result['control']['client_cleanup']['known_backend_clients'], [])
        self.assertEqual(b.calls[-2:], ['CANCEL_DRAIN', 'CLOSE'])
        self.assertFalse(b.opened)

    def test_matched_semantic_error_stops_queries_but_releases_known_client(self):
        b, r = self.runtime()
        r.query(build_message(0, 0, 1, 0x22, tlvs=(TLV(1, b'\2'),)))
        b.bad_result = True
        with self.assertRaises(ProtocolError):
            r.query(build_message(2, 7, 1, 0x20))
        with self.assertRaises(ProtocolError):
            r.query(build_message(0, 0, 2, 0x21))
        result = r.close()
        self.assertEqual(len(result['releases']), 1)
        self.assertTrue(cleanup_succeeded(result))

    def test_timeout_has_one_send_and_unresolved_request_is_reported(self):
        b, r = self.runtime(); b.no_response = True
        with self.assertRaises(TimeoutError):
            r.query(build_message(0, 0, 1, 0x21), timeout_ms=1)
        self.assertEqual(sum(isinstance(c, tuple) and c[0] == 0 for c in b.calls), 1)
        result = r.close()
        self.assertFalse(cleanup_succeeded(result))
        self.assertEqual(result['control']['client_cleanup']['abandoned_requests'], 1)

    def test_nested_cleanup_errors_and_ownership_cannot_report_success(self):
        for r in ({'errors': ['release']}, {'control': {'errors': ['DTR clear']}},
                  {'control': {'client_cleanup': {'known_backend_clients': [{'cid': 7}]}}},
                  {'control': {'client_cleanup': {'unresolved_allocation_requests': 1}}}):
            self.assertFalse(cleanup_succeeded(r))
