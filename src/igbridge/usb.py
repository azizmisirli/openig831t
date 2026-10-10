# SPDX-License-Identifier: Apache-2.0
"""USB CDC wire helpers; pure bytes only, no device access."""
from dataclasses import dataclass
import struct
from .errors import ProtocolError


@dataclass(frozen=True)
class Setup:
    request_type: int
    request: int
    value: int
    index: int
    length: int

    def __post_init__(self):
        for field, value, limit in (
                ('request_type', self.request_type, 255), ('request', self.request, 255),
                ('value', self.value, 65535), ('index', self.index, 65535),
                ('length', self.length, 65535)):
            if type(value) is not int or not 0 <= value <= limit:
                raise ProtocolError(f'USB setup {field} out of range')

    def pack(self):
        try:
            return struct.pack('<BBHHH', self.request_type, self.request,
                               self.value, self.index, self.length)
        except struct.error as exc:
            raise ProtocolError('setup field out of range') from exc

    @classmethod
    def parse(cls, data):
        if len(data) != 8:
            raise ProtocolError('setup must be exactly 8 bytes')
        return cls(*struct.unpack('<BBHHH', data))

    @property
    def incoming(self):
        return bool(self.request_type & 0x80)

    def remap_interface(self, interface):
        if self.request_type & 0x1f != 1 or self.index > 255:
            raise ProtocolError('only interface recipient with zero high byte supported')
        return Setup(self.request_type, self.request, self.value, interface, self.length)


def send_setup(interface, length):
    if not 1 <= length <= 4096:
        raise ProtocolError('encapsulated request length outside bound')
    return Setup(0x21, 0, 0, interface, length)


def get_setup(interface, capacity=4096):
    if not 1 <= capacity <= 4096:
        raise ProtocolError('encapsulated response capacity outside bound')
    return Setup(0xa1, 1, 0, interface, capacity)


def dtr_setup(interface, asserted):
    if not isinstance(asserted, bool):
        raise ProtocolError('DTR must be bool; RTS not implemented')
    return Setup(0x21, 0x22, int(asserted), interface, 0)


@dataclass(frozen=True)
class Notification:
    code: int
    value: int
    interface: int
    payload: bytes = b''

    def pack(self):
        return Setup(0xa1, self.code, self.value, self.interface,
                     len(self.payload)).pack() + self.payload

    @classmethod
    def parse(cls, raw, expected_interface):
        if len(raw) < 8:
            raise ProtocolError('truncated CDC notification')
        s = Setup.parse(raw[:8])
        if s.request_type != 0xa1 or s.index != expected_interface:
            raise ProtocolError('notification recipient/type/interface mismatch')
        if s.length != len(raw) - 8:
            raise ProtocolError('notification length mismatch')
        if s.request == 1:
            if s.value != 0 or s.length != 0:
                raise ProtocolError('malformed RESPONSE_AVAILABLE')
        elif s.request == 0:
            if s.value not in (0, 1) or s.length != 0:
                raise ProtocolError('malformed NETWORK_CONNECTION')
        else:
            raise ProtocolError('unimplemented notification; never infer QMI')
        return cls(s.request, s.value, s.index, raw[8:])


def response_available(host_interface):
    return Notification(1, 0, host_interface).pack()
