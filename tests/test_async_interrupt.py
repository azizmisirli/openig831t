# SPDX-License-Identifier: Apache-2.0
"""In-memory fake libusb dispatch only; native library is never loaded."""
import ctypes as C
import unittest
from types import SimpleNamespace
from igbridge.async_interrupt import AsyncInterrupt, Transfer
from igbridge.errors import ConfigurationError
from igbridge.libusb_backend import LibUsbBackend, UsbTarget
from igbridge.usb import Setup
from igbridge.errors import ProtocolError


class Fn:
    def __init__(self, fn):
        self.fn = fn
    def __call__(self, *args):
        return self.fn(*args)


class Library:
    def __init__(self, immediate=False):
        self.tr = Transfer()
        self.ptr = C.pointer(self.tr)
        self.immediate, self.cancelled, self.free_count, self.alloc_count = immediate, False, 0, 0
        for name in ('alloc_transfer', 'free_transfer', 'submit_transfer', 'cancel_transfer', 'handle_events_timeout_completed'):
            setattr(self, 'libusb_' + name, Fn(getattr(self, name)))
    def alloc_transfer(self, n):
        self.alloc_count += 1
        return self.ptr
    def free_transfer(self, tr):
        self.free_count += 1
    def complete(self, status, raw=b''):
        self.tr.status = status
        self.tr.actual_length = len(raw)
        if raw:
            C.memmove(self.tr.buffer, raw, len(raw))
        self.tr.callback(self.ptr)
    def submit_transfer(self, tr):
        if self.immediate:
            self.complete(0, b'12345678')
        return 0
    def cancel_transfer(self, tr):
        self.cancelled = True
        return 0
    def handle_events_timeout_completed(self, ctx, tv, done):
        if self.cancelled:
            self.cancelled = False
            self.complete(3)
        return 0


def backend(lib):
    return SimpleNamespace(claimed=True, target=SimpleNamespace(endpoints=((0x89, 3),)),
                           lib=lib, ctx=C.c_void_p(1), handle=C.c_void_p(2), active_interrupts=set())


class InterruptTests(unittest.TestCase):
    def test_completion_during_submit_not_overwritten(self):
        lib = Library(immediate=True); b = backend(lib)
        irq = AsyncInterrupt(b, 0x89)
        self.assertTrue(irq.arm()['armed'])
        self.assertFalse(irq.pending)
        self.assertEqual(irq.pump(0), (0, b'12345678'))
        irq.close()
        self.assertEqual(lib.free_count, 1)
        self.assertFalse(b.active_interrupts)

    def test_cancel_drains_before_free(self):
        lib = Library(); b = backend(lib); irq = AsyncInterrupt(b, 0x89)
        irq.arm()
        self.assertTrue(irq.pending)
        irq.close()
        self.assertEqual(lib.free_count, 1)
        self.assertFalse(irq.pending)
        self.assertFalse(b.active_interrupts)
        irq.close()
        self.assertEqual(lib.free_count, 1)

    def test_invalid_bounds_rejected_before_native_allocation(self):
        for kwargs in ({'capacity': 8.5}, {'timeout_ms': float('inf')}, {'timeout_ms': -1}):
            lib = Library()
            with self.assertRaises(ConfigurationError):
                AsyncInterrupt(backend(lib), 0x89, **kwargs)
            self.assertEqual(lib.alloc_count, 0)

    def test_unbounded_cancel_rejected(self):
        irq = AsyncInterrupt(backend(Library()), 0x89)
        for value in (float('inf'), 0, 10001, 1.5, True):
            with self.assertRaises(ConfigurationError):
                irq.close(value)
        irq.close()

    def test_double_arm_and_unconsumed_completion_blocked(self):
        irq = AsyncInterrupt(backend(Library()), 0x89)
        irq.arm()
        with self.assertRaises(ConfigurationError):
            irq.arm()
        irq.close()


class NativeGuardTests(unittest.TestCase):
    def test_setup_overflow_negative_and_noninteger_before_native_call(self):
        for length in (-1, 65536, 8.5, float('inf'), True):
            with self.assertRaises(ProtocolError):
                Setup(0xa1, 1, 0, 4, length)

    def test_shape_lengths_before_native_call(self):
        b = LibUsbBackend(UsbTarget(0x2ca3, 0x4009, 4, ((0x89, 3),)))
        b.claimed = True
        # lib remains None: any accidental native call would fail the test.
        for setup in (Setup(0xa1, 1, 0, 4, 0), Setup(0xa1, 1, 0, 4, 4097),
                      Setup(0x81, 0x0a, 0, 4, 2), Setup(0x21, 0x22, 1, 4, 1)):
            with self.assertRaises(ProtocolError):
                b.control(setup)
