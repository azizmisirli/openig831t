# SPDX-License-Identifier: Apache-2.0
"""Bounded QMI CDC bridge core, with injected transport and explicit numbering.

One interrupt reader owns backend GET operations. EP0 host GET consumes an
already validated frame. Indications and responses remain separate messages.
"""
from collections import deque
import threading
from .errors import ConfigurationError, ProtocolError
from .usb import Notification, send_setup, get_setup, dtr_setup, response_available
from .qmi import parse_message
from .qmi_session import QmiSession
from .policy import LaboratoryPolicy


class ControlBridge:
    def __init__(self, backend, local_interface=4, host_interface=4,
                 backend_interface=4, session=None, policy=None, queue_limit=64):
        if not 1 <= queue_limit <= 1024:
            raise ConfigurationError('response queue bound invalid')
        for v in (local_interface, host_interface, backend_interface):
            if not 0 <= v <= 255:
                raise ConfigurationError('explicit interface index must fit byte')
        self.backend = backend
        self.local_interface, self.host_interface = local_interface, host_interface
        self.backend_interface = backend_interface
        self.session = session or QmiSession()
        self.policy = policy or LaboratoryPolicy()
        self.queue_limit = queue_limit
        self.responses, self.notifications = deque(), deque()
        self.lock = threading.RLock()
        self.dtr_asserted = False
        self.dtr_attempted = False
        self.active = True

    def check_setup(self, setup):
        if not self.active or setup.index != self.local_interface:
            raise ProtocolError('inactive/unmapped FunctionFS local interface')
        shape = (setup.request_type, setup.request, setup.value)
        if shape == (0x21, 0, 0) and 12 <= setup.length <= 4096:
            return 'send'
        if shape == (0xa1, 1, 0) and 1 <= setup.length <= 4096:
            return 'get'
        if (setup.request_type, setup.request, setup.length) == (0x21, 0x22, 0):
            self.policy.dtr(setup.value)
            return 'dtr'
        raise ProtocolError('unsupported setup; no alternate request')

    def request(self, setup, payload=b''):
        kind = self.check_setup(setup)
        with self.lock:
            if kind == 'get':
                if payload:
                    raise ProtocolError('IN request cannot carry OUT payload')
                if not self.responses:
                    return b''
                if len(self.responses[0]) > setup.length:
                    raise ProtocolError('host GET capacity would truncate QMI')
                # Commit only after successful host data-stage delivery.
                return self.responses[0]
            if kind == 'dtr':
                if payload:
                    raise ProtocolError('DTR is zero-data request')
                self.dtr_attempted |= bool(setup.value)
                result = self.backend.control(dtr_setup(self.backend_interface, bool(setup.value)))
                if result != 0:
                    raise ProtocolError('DTR returned nonzero data length')
                self.dtr_asserted = bool(setup.value)
                return b''
            if len(payload) != setup.length:
                raise ProtocolError('SEND data stage length mismatch')
            message = parse_message(payload)
            self.policy.qmi(message)
            outbound = self.session.host_to_backend(payload)
            try:
                n = self.backend.control(send_setup(self.backend_interface, len(outbound)), outbound)
                if n != len(outbound):
                    raise ProtocolError('short backend SEND')
            except BaseException:
                # Uncertain delivery: do not reuse transactions or retry.
                self.active = False
                raise
            return b''

    def commit_get(self, delivered):
        with self.lock:
            if not delivered:
                return
            if not self.responses or self.responses[0] != delivered:
                raise ProtocolError('GET commit does not match queued frame')
            self.responses.popleft()
            if self.responses:
                self._notify(response_available(self.host_interface))

    def _notify(self, raw):
        if len(self.notifications) >= self.queue_limit:
            self.active = False
            raise ProtocolError('notification queue full; stop')
        self.notifications.append(raw)

    def backend_notification(self, raw):
        notification = Notification.parse(raw, self.backend_interface)
        with self.lock:
            if not self.active:
                raise ProtocolError('notification after stop')
            if notification.code == 0:
                self._notify(Notification(0, notification.value, self.host_interface).pack())
                return
            if len(self.responses) >= self.queue_limit:
                self.active = False
                raise ProtocolError('response queue full; do not consume backend response')
            # Exactly one GET per valid RESPONSE_AVAILABLE; no blind polling/retry.
            raw_response = self.backend.control(get_setup(self.backend_interface))
            if not raw_response:
                raise ProtocolError('empty response after notification')
            forwarded = self.session.backend_to_host(raw_response)
            self.responses.append(forwarded)
            self._notify(response_available(self.host_interface))

    def pop_notification(self):
        with self.lock:
            return self.notifications.popleft() if self.notifications else None

    def cleanup(self):
        # The owner must join the interrupt worker before calling this method.
        # Only a session we attempted to assert receives one DTR clear.
        with self.lock:
            errors = []
            if self.dtr_attempted:
                try:
                    n = self.backend.control(dtr_setup(self.backend_interface, False))
                    if n != 0:
                        raise ProtocolError('cleanup DTR clear length mismatch')
                except Exception as exc:
                    errors.append({'action': 'DTR clear', 'error': str(exc)})
            self.dtr_asserted = self.dtr_attempted = False
            client_cleanup = self.session.disconnect()
            self.responses.clear()
            self.notifications.clear()
            self.active = False
            # Do not fabricate client release success; return exact obligations.
            return {'errors': errors, 'client_cleanup': client_cleanup}
