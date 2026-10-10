# SPDX-License-Identifier: Apache-2.0
"""An interrupt read is armed when libusb_submit_transfer succeeds, not at thread start.

Callbacks only copy bounded results. GET/control I/O is never performed inside
a libusb callback. Pending memory is retained until cancellation completion.
"""
import ctypes as C
import time
import sys
import threading
from .errors import ConfigurationError, ProtocolError
from .libusb_backend import P, U8, I, UsbError


class Transfer(C.Structure):
    pass


Callback = C.CFUNCTYPE(None, C.POINTER(Transfer))
Transfer._fields_ = [('dev_handle', P), ('flags', U8), ('endpoint', U8), ('type', U8),
    ('timeout', C.c_uint), ('status', I), ('length', I), ('actual_length', I),
    ('callback', Callback), ('user_data', P), ('buffer', P), ('num_iso_packets', I)]


class Timeval(C.Structure):
    _fields_ = [('tv_sec', C.c_long),
                ('tv_usec', C.c_int if sys.platform == 'darwin' else C.c_long)]


class AsyncInterrupt:
    def __init__(self, backend, endpoint, capacity=8, timeout_ms=1000):
        if not backend.claimed or (endpoint, 3) not in backend.target.endpoints or not endpoint & 0x80:
            raise ConfigurationError('claimed interrupt IN endpoint required')
        if (type(capacity) is not int or type(timeout_ms) is not int
                or not 8 <= capacity <= 4096 or not 1 <= timeout_ms <= 10000):
            raise ConfigurationError('bounded interrupt length/deadline required')
        self.backend, self.lib, self.endpoint = backend, backend.lib, endpoint
        self.owner = threading.get_ident()
        self.lock = threading.RLock()
        ptr = C.POINTER(Transfer)
        for name, result, args in [
            ('alloc_transfer', ptr, [I]), ('free_transfer', None, [ptr]),
            ('submit_transfer', I, [ptr]), ('cancel_transfer', I, [ptr]),
            ('handle_events_timeout_completed', I, [P, C.POINTER(Timeval), C.POINTER(I)])]:
            fn = getattr(self.lib, 'libusb_' + name)
            fn.restype, fn.argtypes = result, args
        self.buffer = C.create_string_buffer(capacity)
        self.callback = Callback(self._complete)
        self.pending, self.result, self.closed = False, None, False
        self.transfer = self.lib.libusb_alloc_transfer(0)
        if not self.transfer:
            raise MemoryError('libusb_alloc_transfer')
        try:
            tr = self.transfer.contents
            tr.dev_handle, tr.endpoint, tr.type = backend.handle, endpoint, 3
            tr.flags, tr.timeout, tr.length = 0, timeout_ms, capacity
            tr.buffer, tr.callback, tr.user_data = C.cast(self.buffer, P), self.callback, None
            tr.num_iso_packets = 0
        except BaseException:
            self.lib.libusb_free_transfer(self.transfer)
            raise
        # Keep this object and the C callback alive even after a failed cancellation.
        backend.active_interrupts.add(self)

    def _complete(self, pointer):
        with self.lock:
            tr = pointer.contents
            self.pending = False
            if not 0 <= tr.actual_length <= tr.length:
                self.result = (6, b'')  # overflow/malformed length
            else:
                self.result = (tr.status, bytes(self.buffer.raw[:tr.actual_length]))

    def _owner(self):
        if threading.get_ident() != self.owner:
            raise ConfigurationError('arm/pump/close must share one owner thread')

    def arm(self):
        self._owner()
        with self.lock:
            if self.closed or self.pending or self.result is not None:
                raise ConfigurationError('interrupt cannot be rearmed with pending result')
            self.pending = True
            code = self.lib.libusb_submit_transfer(self.transfer)
            if code < 0:
                self.pending = False
                raise UsbError('submit_interrupt', code)
        return {'armed': True, 'submit_status': code, 'endpoint': self.endpoint}

    def pump(self, timeout_ms=10):
        self._owner()
        if self.closed or type(timeout_ms) is not int or not 0 <= timeout_ms <= 100:
            raise ConfigurationError('invalid pump state/deadline')
        tv = Timeval(0, timeout_ms * 1000)
        code = self.lib.libusb_handle_events_timeout_completed(self.backend.ctx, C.byref(tv), None)
        if code < 0:
            raise UsbError('handle_events', code)
        with self.lock:
            result, self.result = self.result, None
        return result

    def close(self, timeout_ms=2000):
        self._owner()
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ConfigurationError('finite bounded cancellation deadline required')
        if self.closed:
            return
        if self.pending:
            code = self.lib.libusb_cancel_transfer(self.transfer)
            if code not in (0, -5):  # NOT_FOUND may mean completion already queued
                raise UsbError('cancel_interrupt', code)
            deadline = time.monotonic() + timeout_ms / 1000
            while self.pending and time.monotonic() < deadline:
                self.pump(10)
            if self.pending:
                raise ProtocolError('cancel not completed; retain transfer memory and device handle')
        with self.lock:
            if self.pending:
                raise ProtocolError('cannot free a pending interrupt')
            self.lib.libusb_free_transfer(self.transfer)
            self.transfer = None
            self.closed = True
            self.backend.active_interrupts.remove(self)
