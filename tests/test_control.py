# SPDX-License-Identifier: Apache-2.0
"""Synthetic transport integration. These tests never load libusb or open USB."""
import unittest
from igbridge.control import ControlBridge
from igbridge.usb import Setup, Notification, send_setup, get_setup, dtr_setup, response_available
from igbridge.qmi import build_message, TLV
from igbridge.errors import ProtocolError, PolicyDenied
from igbridge.functionfs import Event, EventDriver, parse_events, BIND, ENABLE, SETUP, DISABLE

REQUEST = build_message(0, 0, 1, 0x21)
RESPONSE = build_message(0, 0, 1, 0x21, 'response', (TLV(2, b'\0\0\0\0'), TLV(1, b'\1\0\1\0\5\0')))


class Backend:
    def __init__(self):
        self.calls, self.response, self.fail = [], RESPONSE, None

    def control(self, setup, data=b''):
        self.calls.append((setup, data))
        if self.fail:
            raise self.fail
        return self.response if setup.incoming else len(data)


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.bridge = ControlBridge(self.backend, local_interface=1, host_interface=4, backend_interface=7)

    def send(self):
        self.bridge.request(send_setup(1, len(REQUEST)), REQUEST)

    def test_numbering_roundtrip_and_commit(self):
        self.send()
        self.assertEqual(self.backend.calls[0][0].index, 7)
        self.bridge.backend_notification(response_available(7))
        self.assertEqual(self.bridge.pop_notification(), response_available(4))
        self.assertEqual(self.backend.calls[1][0], get_setup(7))
        self.assertEqual(self.bridge.request(get_setup(1)), RESPONSE)
        self.assertEqual(self.bridge.request(get_setup(1)), RESPONSE)
        self.bridge.commit_get(RESPONSE)
        self.assertEqual(self.bridge.request(get_setup(1)), b'')

    def test_invalid_notification_never_gets(self):
        self.send()
        for raw in (b'', response_available(4), bytes.fromhex('a1 01 01 00 07 00 00 00'),
                    bytes.fromhex('a1 01 00 00 07 00 01 00')):
            with self.assertRaises(ProtocolError):
                self.bridge.backend_notification(raw)
        self.assertEqual(len(self.backend.calls), 1)

    def test_network_notification_remap_is_not_response(self):
        self.bridge.backend_notification(Notification(0, 1, 7).pack())
        self.assertEqual(self.bridge.pop_notification(), Notification(0, 1, 4).pack())
        self.assertEqual(self.backend.calls, [])

    def test_no_dtr_no_clear(self):
        self.bridge.cleanup()
        self.assertEqual(self.backend.calls, [])

    def test_dtr_cleanup_one_clear_no_extra_qmi(self):
        self.bridge.request(dtr_setup(1, True))
        self.bridge.cleanup()
        self.bridge.cleanup()
        self.assertEqual([s.pack().hex(' ') for s, _ in self.backend.calls],
                         ['21 22 01 00 07 00 00 00', '21 22 00 00 07 00 00 00'])

    def test_forbidden_requests_no_backend_io(self):
        for raw in (build_message(1, 1, 1, 0x20), build_message(0, 0, 1, 0x27),
                    build_message(0x1a, 1, 1, 0x20), build_message(2, 1, 1, 0x2e)):
            with self.assertRaises(PolicyDenied):
                self.bridge.request(send_setup(1, len(raw)), raw)
        self.assertEqual(self.backend.calls, [])

    def test_short_get_retains_response(self):
        self.send()
        self.bridge.backend_notification(response_available(7))
        with self.assertRaises(ProtocolError):
            self.bridge.request(get_setup(1, 12))
        self.assertEqual(self.bridge.request(get_setup(1)), RESPONSE)

    def test_unexpected_response_rejected(self):
        self.send()
        self.backend.response = build_message(0, 0, 2, 0x21, 'response', (TLV(2, b'\0'*4),))
        with self.assertRaises(ProtocolError):
            self.bridge.backend_notification(response_available(7))
        self.assertFalse(self.bridge.responses)

    def test_queue_bound_prevents_extra_get(self):
        b = ControlBridge(self.backend, queue_limit=1)
        b.responses.append(RESPONSE)
        with self.assertRaises(ProtocolError):
            b.backend_notification(response_available(4))
        self.assertFalse(self.backend.calls)

    def test_send_failure_disables_no_retry(self):
        self.backend.fail = OSError('synthetic STALL')
        with self.assertRaises(OSError):
            self.send()
        with self.assertRaises(ProtocolError):
            self.send()
        self.assertEqual(len(self.backend.calls), 1)

    def test_exact_known_setup_bytes(self):
        self.assertEqual(send_setup(4, 12).pack().hex(' '), '21 00 00 00 04 00 0c 00')
        self.assertEqual(get_setup(4).pack().hex(' '), 'a1 01 00 00 04 00 00 10')
        self.assertEqual(dtr_setup(4, True).pack().hex(' '), '21 22 01 00 04 00 00 00')


class FakeIO:
    def __init__(self):
        self.out = REQUEST
        self.written, self.stalled = [], []

    def read_out(self, length):
        if length != len(self.out):
            raise AssertionError('unexpected length')
        return self.out

    def write_in(self, data):
        self.written.append(data)

    def stall(self, setup):
        self.stalled.append(setup)


class EventTests(unittest.TestCase):
    def test_event_to_ep0_and_notification_roundtrip(self):
        io, backend = FakeIO(), Backend()
        b = ControlBridge(backend)
        verified = []
        driver = EventDriver(io, b, lambda: verified.append(True))
        for kind in (BIND, ENABLE):
            driver.handle(Event(kind))
        self.assertEqual(verified, [True])
        driver.handle(Event(SETUP, send_setup(4, 12)))
        b.backend_notification(response_available(4))
        driver.handle(Event(SETUP, get_setup(4)))
        self.assertEqual(io.written, [RESPONSE])
        self.assertFalse(b.responses)
        self.assertFalse(driver.handle(Event(DISABLE)))

    def test_unmapped_setup_stalls_before_read(self):
        io, b = FakeIO(), ControlBridge(Backend())
        driver = EventDriver(io, b, lambda: None)
        driver.handle(Event(BIND)); driver.handle(Event(ENABLE))
        s = Setup(0x21, 0x20, 0, 2, 7)
        with self.assertRaises(ProtocolError):
            driver.handle(Event(SETUP, s))
        self.assertEqual(io.stalled, [s])
        self.assertEqual(b.backend.calls, [])

    def test_event_abi_length_and_setup(self):
        raw = send_setup(4, 12).pack() + bytes([SETUP, 0, 0, 0])
        self.assertEqual(parse_events(raw), [Event(SETUP, send_setup(4, 12))])
        for cut in range(12):
            with self.assertRaises(ProtocolError):
                parse_events(raw[:cut])

    def test_failed_host_write_retains_response(self):
        class Fault(FakeIO):
            def write_in(self, data):
                raise OSError('synthetic disconnect')
        io, b = Fault(), ControlBridge(Backend())
        b.responses.append(RESPONSE)
        driver = EventDriver(io, b, lambda: None)
        driver.handle(Event(BIND)); driver.handle(Event(ENABLE))
        with self.assertRaises(OSError):
            driver.handle(Event(SETUP, get_setup(4)))
        self.assertEqual(b.responses[0], RESPONSE)
