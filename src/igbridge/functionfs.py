# SPDX-License-Identifier: Apache-2.0
"""Linux FunctionFS event/data I/O, with an injectable event driver for tests.

No filesystem mount, configfs binding or USB opening occurs on import.
FunctionFS v6.12 event ABI: 8-byte setup + type byte + 3-byte padding.
"""
import errno
import fcntl
import os
import select
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from .errors import ConfigurationError, ProtocolError, PolicyDenied
from .usb import Setup

BIND, UNBIND, ENABLE, DISABLE, SETUP, SUSPEND, RESUME = range(7)


@dataclass(frozen=True)
class Event:
    kind: int
    setup: Setup | None = None


def parse_events(raw):
    if not raw or len(raw) % 12 or len(raw) > 48:
        raise ProtocolError('FunctionFS event read must contain 1..4 complete events')
    events = []
    for pos in range(0, len(raw), 12):
        kind = raw[pos + 8]
        if kind > RESUME:
            raise ProtocolError('unknown FunctionFS event')
        events.append(Event(kind, Setup.parse(raw[pos:pos + 8]) if kind == SETUP else None))
    return events


class FunctionFSIO:
    def __init__(self, mount_path):
        self.path = Path(mount_path)
        self.ep0 = None
        self.endpoints = {}

    def open(self, descriptor_bytes, string_bytes):
        if sys.platform != 'linux' or self.ep0 is not None:
            raise ConfigurationError('FunctionFS requires Linux and a fresh endpoint instance')
        self.ep0 = os.open(self.path / 'ep0', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            for name, data in (('descriptors', descriptor_bytes), ('strings', string_bytes)):
                if os.write(self.ep0, data) != len(data):
                    raise ProtocolError(f'short FunctionFS {name} write; no retry')
        except BaseException:
            self.close()
            raise
        return self

    def endpoint(self, slot):
        if type(slot) is not int or not 1 <= slot <= 30 or self.ep0 is None:
            raise ConfigurationError('invalid endpoint slot')
        if slot not in self.endpoints:
            self.endpoints[slot] = os.open(self.path / f'ep{slot}',
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        return self.endpoints[slot]

    def read_events(self, timeout_ms=10):
        if not 0 <= timeout_ms <= 1000:
            raise ConfigurationError('bounded event wait required')
        poller = select.poll()
        poller.register(self.ep0, select.POLLIN)
        events = poller.poll(timeout_ms)
        if not events:
            return []
        if any(flags & (select.POLLERR | select.POLLHUP | select.POLLNVAL) for _, flags in events):
            raise ProtocolError('FunctionFS endpoint disconnected/error')
        # One event at a time: finish any SETUP data stage before reading another.
        return parse_events(os.read(self.ep0, 12))

    def read_out(self, length):
        raw = os.read(self.ep0, length)
        if len(raw) != length:
            raise ProtocolError('short FunctionFS OUT data stage')
        return raw

    def write_in(self, data):
        if os.write(self.ep0, data) != len(data):
            raise ProtocolError('short FunctionFS IN; no retry')

    def stall(self, setup):
        # f_fs.c: a wrong-direction operation explicitly stalls pending setup.
        try:
            if setup.incoming:
                os.read(self.ep0, 0)
            else:
                os.write(self.ep0, b'')
        except OSError as exc:
            if exc.errno not in (errno.EL2HLT, errno.EPIPE):
                raise

    def write_endpoint(self, slot, raw):
        if os.write(self.endpoint(slot), raw) != len(raw):
            raise ProtocolError('short endpoint write; no automatic replay')

    def endpoint_address(self, slot):
        return fcntl.ioctl(self.endpoint(slot), 0x6781, 0)

    def interface_local(self, host_interface):
        # Despite its name, this is host-assigned interface -> FunctionFS-local.
        return fcntl.ioctl(self.ep0, 0x6780, host_interface)

    def close(self):
        for fd in self.endpoints.values():
            os.close(fd)
        self.endpoints.clear()
        if self.ep0 is not None:
            os.close(self.ep0)
            self.ep0 = None


class EventDriver:
    def __init__(self, io, control, verify_binding, log=None, pre_setup=None):
        self.io, self.control, self.verify_binding, self.log = io, control, verify_binding, log
        self.state = 'OPEN'
        self.pre_setup = pre_setup

    def _log(self, event, **fields):
        if self.log:
            self.log.emit(event, **fields)

    def handle(self, event):
        if event.kind == BIND:
            if self.state != 'OPEN':
                raise ProtocolError('unexpected BIND lifecycle')
            self.state = 'BOUND'
        elif event.kind == ENABLE:
            if self.state not in ('BOUND', 'DISABLED'):
                raise ProtocolError('unexpected ENABLE lifecycle')
            self.verify_binding()
            self.state = 'ENABLED'
        elif event.kind == SETUP:
            if self.state != 'ENABLED':
                self.io.stall(event.setup)
                raise ProtocolError('SETUP outside enabled state')
            try:
                self.control.check_setup(event.setup)
            except (ProtocolError, PolicyDenied):
                self.io.stall(event.setup)
                raise
            if self.pre_setup:
                self.pre_setup()
            if event.setup.incoming:
                response = self.control.request(event.setup)
                self.io.write_in(response)
                self.control.commit_get(response)
            else:
                payload = self.io.read_out(event.setup.length)
                # An OUT read can complete USB before backend semantic success.
                # Later rejection is logged and stops the channel, never QMI SUCCESS.
                self.control.request(event.setup, payload)
        elif event.kind == SUSPEND:
            if self.state != 'ENABLED':
                raise ProtocolError('SUSPEND outside enabled state')
            self.state = 'SUSPENDED'
        elif event.kind == RESUME:
            if self.state != 'SUSPENDED':
                raise ProtocolError('unexpected RESUME')
            self.state = 'ENABLED'
        elif event.kind in (DISABLE, UNBIND):
            self.state = 'DISABLED' if event.kind == DISABLE else 'UNBOUND'
            # Stop at disconnect; coordinator cleans CIDs/DTR and starts a new
            # generation only after a fresh explicit bind and transport drain.
            return False
        else:
            raise ProtocolError('unhandled event')
        self._log('functionfs_event', kind=event.kind, state=self.state)
        return True
