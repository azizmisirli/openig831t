# SPDX-License-Identifier: Apache-2.0
"""One-owner, bounded laboratory QMI runtime. No data session or retry logic.

Instantiating does not access hardware. open() is an explicit live operation.
Each valid backend notification causes at most one encapsulated GET.
"""
import time
from .async_interrupt import AsyncInterrupt
from .control import ControlBridge
from .errors import ConfigurationError, ProtocolError
from .qmi import parse_message, match_response, result_code
from .usb import send_setup, dtr_setup


class LaboratoryRuntime:
    def __init__(self, backend, interrupt_endpoint, log=None, interrupt_factory=AsyncInterrupt):
        self.backend, self.interrupt_endpoint, self.log = backend, interrupt_endpoint, log
        self.interrupt_factory = interrupt_factory
        self.irq = self.control = None
        self.faulted = False
        self.release_only_cleanup_safe = False
        self.cleanup_result = None
        self._cleanup_logging_errors = None

    def emit(self, event, **fields):
        if self.log:
            try:
                self.log.emit(event, **fields)
            except Exception as exc:
                if self._cleanup_logging_errors is None:
                    raise
                # Once teardown starts, disk-full/bounded-log errors must not
                # prevent CID release, IRQ cancellation or interface close.
                # Preserve failure in the returned cleanup result; never
                # claim a complete audit or success after losing the log.
                self._cleanup_logging_errors.append({'action': 'cleanup_log',
                    'event': event, 'error_type': type(exc).__name__, 'error': str(exc)})
                self.log = None

    def open(self):
        if self.control is not None:
            raise ConfigurationError('runtime already initialized; no implicit reconnect')
        self.backend.open()
        try:
            interface = self.backend.target.interface
            self.irq = self.interrupt_factory(self.backend, self.interrupt_endpoint, timeout_ms=3000)
            armed = self.irq.arm()
            self.emit('interrupt_armed', **armed)
            self.control = ControlBridge(self.backend, local_interface=interface,
                                         host_interface=interface, backend_interface=interface)
            return self
        except BaseException:
            if self.irq:
                self.irq.close()
            self.backend.close()
            raise

    def poll(self, timeout_ms=10, idle_allowed=False):
        if self.irq is None or self.control is None:
            raise ConfigurationError('runtime not open')
        event = self.irq.pump(timeout_ms)
        if event is None:
            return False
        status, raw = event
        self.emit('interrupt_completion', status=status, payload=raw)
        if status == 2 and not raw and idle_allowed:
            self.irq.arm()  # passive read only, never repeats a QMI request
            return False
        if status != 0:
            self.faulted = True
            self.release_only_cleanup_safe = False
            raise ProtocolError(f'interrupt transfer status={status}; no protocol retry')
        # Arm next receive before any EP0 GET/DTR/SEND can generate a notification.
        self.irq.arm()
        try:
            self.control.backend_notification(raw)
        except BaseException:
            self.faulted = True
            self.release_only_cleanup_safe = False
            raise
        return True

    def _ready(self, release_only_cleanup=False):
        if ((self.faulted and not (release_only_cleanup and self.release_only_cleanup_safe))
                or self.control is None or not self.control.active):
            raise ProtocolError('runtime failed/inactive')
        # Handle completions already dispatched during synchronous libusb calls.
        for _ in range(64):
            if not self.poll(0, idle_allowed=True):
                break
        else:
            raise ProtocolError('notification flood before request')
        if not self.irq.pending:
            raise ProtocolError('successful interrupt arm required before control output')

    def set_dtr(self, asserted):
        self._ready()
        self.control.request(dtr_setup(self.control.local_interface, asserted))
        self.emit('dtr', asserted=asserted)

    def wait_sync(self, timeout_ms=3000):
        """Optional explicit observed-profile prerequisite, not a universal rule."""
        self._deadline(timeout_ms)
        deadline = time.monotonic() + timeout_ms / 1000
        count = 0
        while time.monotonic() < deadline and count < 64:
            self.poll(idle_allowed=True)
            while self.control.responses:
                raw = self.control.responses[0]
                self.control.commit_get(raw)
                message = parse_message(raw)
                count += 1
                self.emit('init_indication', payload=raw, service=message.service,
                          message=message.message_id, kind=message.kind)
                if (message.service, message.message_id, message.kind) == (0, 0x27, 'indication'):
                    self._discard_notifications()
                    return
                if message.kind != 'indication':
                    raise ProtocolError('unexpected init response')
        self.faulted = True
        raise TimeoutError('Sync indication not observed; no automatic request')

    @staticmethod
    def _deadline(timeout_ms):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ConfigurationError('finite 1..10000 ms deadline required')

    def _discard_notifications(self):
        # In direct laboratory mode there is no frontend host to notify.
        while self.control.pop_notification() is not None:
            pass

    def query(self, request, timeout_ms=3000, *, _release_cleanup=False):
        self._deadline(timeout_ms)
        expected = parse_message(request)
        if _release_cleanup and (expected.service, expected.message_id) != (0, 0x23):
            raise ProtocolError('fault cleanup permits only owned CID release')
        self._ready(release_only_cleanup=_release_cleanup)
        try:
            self.control.request(send_setup(self.control.local_interface, len(request)), request)
            self.emit('qmi_request', payload=request, service=expected.service,
                      message=expected.message_id, transaction=expected.transaction_id)
            deadline = time.monotonic() + timeout_ms / 1000
            count = 0
            while time.monotonic() < deadline and count < 64:
                self.poll(idle_allowed=True)
                while self.control.responses:
                    raw = self.control.responses[0]
                    self.control.commit_get(raw)
                    received = parse_message(raw)
                    self.emit('qmi_received', payload=raw, service=received.service,
                              message=received.message_id, kind=received.kind)
                    self._discard_notifications()
                    count += 1
                    if match_response(expected, received):
                        try:
                            result_code(received)  # Error remains error, never translated to success.
                        except ProtocolError:
                            # Framing/routing matched and pending transaction was removed.
                            # New queries stop, but known owned CIDs can be released once.
                            self.release_only_cleanup_safe = True
                            raise
                        return received
                    if received.kind != 'indication':
                        raise ProtocolError('unmatched QMI response; stop')
            raise TimeoutError('matching QMI response not observed; no retry')
        except BaseException:
            self.faulted = True
            raise

    def close(self):
        if self.cleanup_result is not None:
            return self.cleanup_result
        releases, errors = [], []
        self._cleanup_logging_errors = errors
        abandoned_delivery = 0
        if self.control:
            # The frontend must have stopped before close(). These frames have
            # already passed QmiSession.backend_to_host(), including CID state
            # commits. They are undelivered host replies, not replies to the
            # new local cleanup transactions. Keep an audit event and retire
            # the delivery queue before issuing any owned-CID releases.
            while self.control.responses:
                raw = self.control.responses[0]
                self.emit('cleanup_abandoned_frontend_delivery', payload=raw)
                self.control.commit_get(raw)
                abandoned_delivery += 1
            self._discard_notifications()
        if self.control and (not self.faulted or self.release_only_cleanup_safe) and self.control.active:
            try:
                for raw in self.control.session.cleanup_requests():
                    response = self.query(raw, timeout_ms=2000, _release_cleanup=True)
                    result = result_code(response)
                    releases.append({'request_hex': raw.hex(), 'result': result})
                    if result != (0, 0):
                        break
            except Exception as exc:
                errors.append({'action': 'client_cleanup', 'error': str(exc)})
        # A failed cancellation prevents handle close/free. The owner gets a
        # hard failure with retained native objects; never fake a safe release.
        if self.irq:
            self.irq.close()
        control_cleanup = self.control.cleanup() if self.control else None
        errors.extend(self.backend.close() or [])
        self.cleanup_result = {'releases': releases, 'control': control_cleanup, 'errors': errors,
                               'abandoned_frontend_delivery_count': abandoned_delivery}
        self.emit('cleanup', result=self.cleanup_result)
        return self.cleanup_result

    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()


def cleanup_succeeded(result):
    if not isinstance(result, dict) or result.get('errors'):
        return False
    control = result.get('control') or {}
    clients = control.get('client_cleanup') or {}
    if control.get('errors') or clients.get('known_backend_clients'):
        return False
    if any(clients.get(name) for name in ('unresolved_allocation_requests',
           'unresolved_release_requests', 'abandoned_requests', 'planned_unsent_cleanup_requests')):
        return False
    return all(tuple(row['result']) == (0, 0) for row in result.get('releases', ()))
