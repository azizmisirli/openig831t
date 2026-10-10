# SPDX-License-Identifier: Apache-2.0
"""Strict QMUX framing; no I/O, schema-generated code, or identity rewriting.

Unknown TLVs (including ordering and duplicates) round-trip byte for byte.
This supports single, non-compound QMI messages. Unsupported flag combinations
are rejected rather than silently reinterpreted. See docs/qmi-initialization.md.
"""
from dataclasses import dataclass, replace
import struct
from typing import Iterable

from .errors import ProtocolError

MAX_FRAME_SIZE = 65536  # uint16 QMUX length excludes the one-byte marker.
CTL = 0
CTL_GET_VERSION = 0x21
CTL_ALLOCATE_CID = 0x22
CTL_RELEASE_CID = 0x23
CTL_SYNC = 0x27
_FLAGS = {True: {"request": 0, "response": 1, "indication": 2},
          False: {"request": 0, "response": 2, "indication": 4}}


def _uint(value: int, bits: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ProtocolError(f"{name} must be uint{bits}")
    return value


def _bytes(value, name="payload") -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ProtocolError(f"{name} must be bytes-like")
    return bytes(value)


@dataclass(frozen=True)
class TLV:
    type: int
    value: bytes

    def __post_init__(self):
        _uint(self.type, 8, "TLV type")
        object.__setattr__(self, "value", _bytes(self.value, "TLV value"))
        _uint(len(self.value), 16, "TLV length")


@dataclass(frozen=True)
class QmiMessage:
    service: int
    cid: int
    transaction_id: int
    message_id: int
    kind: str
    tlvs: tuple[TLV, ...] = ()

    def __post_init__(self):
        _uint(self.service, 8, "service")
        _uint(self.cid, 8, "CID")
        if self.service == CTL and self.cid != 0:
            raise ProtocolError("CTL CID must be zero")
        _uint(self.transaction_id, 8 if self.service == CTL else 16, "transaction ID")
        _uint(self.message_id, 16, "message ID")
        if not isinstance(self.kind, str) or self.kind not in _FLAGS[self.service == CTL]:
            raise ProtocolError("unsupported QMI kind")
        object.__setattr__(self, "tlvs", tuple(self.tlvs))
        if any(not isinstance(t, TLV) for t in self.tlvs):
            raise ProtocolError("TLVs must be TLV objects")
        size = (12 if self.service == CTL else 13) + sum(3 + len(t.value) for t in self.tlvs)
        if size > MAX_FRAME_SIZE:
            raise ProtocolError("QMUX frame exceeds uint16 length")

    @property
    def client_id(self) -> int:
        return self.cid

    @property
    def flags(self) -> int:
        return _FLAGS[self.service == CTL][self.kind]

    @property
    def qmux_flags(self) -> int:
        return 0 if self.kind == "request" else 0x80

    def to_bytes(self) -> bytes:
        return encode_message(self)

    def with_ids(self, *, cid=None, transaction_id=None) -> "QmiMessage":
        return replace(self, cid=self.cid if cid is None else cid,
                       transaction_id=self.transaction_id if transaction_id is None else transaction_id)

    def tlv(self, type_id: int, *, required=True) -> bytes | None:
        """Semantic lookup: duplicated required fields are ambiguous and fail."""
        _uint(type_id, 8, "TLV type")
        values = [t.value for t in self.tlvs if t.type == type_id]
        if len(values) > 1:
            raise ProtocolError(f"duplicate semantic TLV 0x{type_id:02x}")
        if not values:
            if required:
                raise ProtocolError(f"missing TLV 0x{type_id:02x}")
            return None
        return values[0]

    def replace_tlv(self, type_id: int, value: bytes) -> "QmiMessage":
        self.tlv(type_id)  # Exactly one; preserve every other byte and position.
        return replace(self, tlvs=tuple(TLV(type_id, value) if t.type == type_id else t for t in self.tlvs))


def encode_message(message: QmiMessage) -> bytes:
    if not isinstance(message, QmiMessage):
        raise ProtocolError("expected QmiMessage")
    payload = b"".join(struct.pack("<BH", t.type, len(t.value)) + t.value for t in message.tlvs)
    fmt = "<BBHH" if message.service == CTL else "<BHHH"
    qmi = struct.pack(fmt, message.flags, message.transaction_id, message.message_id, len(payload)) + payload
    return b"\x01" + struct.pack("<HBBB", 5 + len(qmi), message.qmux_flags, message.service, message.cid) + qmi


def parse_message(data: bytes) -> QmiMessage:
    raw = _bytes(data)
    if not 12 <= len(raw) <= MAX_FRAME_SIZE:
        raise ProtocolError("invalid QMUX frame size")
    if raw[0] != 1:
        raise ProtocolError("unsupported QMUX marker")
    length, direction, service, cid = struct.unpack_from("<HBBB", raw, 1)
    if length != len(raw) - 1:
        raise ProtocolError("QMUX length mismatch or multiple frames")
    header_size = 12 if service == CTL else 13
    if len(raw) < header_size:
        raise ProtocolError("truncated service header")
    fmt = "<BBHH" if service == CTL else "<BHHH"
    flags, tid, message_id, tlv_size = struct.unpack_from(fmt, raw, 6)
    kind = {v: k for k, v in _FLAGS[service == CTL].items()}.get(flags)
    if kind is None:
        raise ProtocolError("unsupported/compound QMI flags")
    if direction != (0 if kind == "request" else 0x80):
        raise ProtocolError("QMUX direction/QMI kind mismatch")
    if tlv_size != len(raw) - header_size:
        raise ProtocolError("QMI TLV length mismatch")
    offset, tlvs = header_size, []
    while offset < len(raw):
        if len(raw) - offset < 3:
            raise ProtocolError("truncated TLV header")
        type_id, size = struct.unpack_from("<BH", raw, offset)
        offset += 3
        if size > len(raw) - offset:
            raise ProtocolError("truncated TLV value")
        tlvs.append(TLV(type_id, raw[offset:offset + size]))
        offset += size
    return QmiMessage(service, cid, tid, message_id, kind, tuple(tlvs))


def build_message(service: int, cid: int, transaction_id: int, message_id: int,
                  kind="request", tlvs: Iterable[TLV] = ()) -> bytes:
    return QmiMessage(service, cid, transaction_id, message_id, kind, tuple(tlvs)).to_bytes()


def result_code(message: QmiMessage) -> tuple[int, int]:
    if message.kind != "response":
        raise ProtocolError("only responses have an operation result")
    value = message.tlv(2)
    if len(value) != 4:
        raise ProtocolError("result TLV must contain two uint16 values")
    result, error = struct.unpack("<HH", value)
    if result not in (0, 1) or (result == 0 and error != 0):
        raise ProtocolError("invalid operation result")
    return result, error


def match_response(request: QmiMessage, response: QmiMessage) -> bool:
    return (request.kind == "request" and response.kind == "response" and
            (request.service, request.cid, request.transaction_id, request.message_id) ==
            (response.service, response.cid, response.transaction_id, response.message_id))


def service_versions(message: QmiMessage) -> dict[int, tuple[int, int]]:
    if (message.service, message.message_id, message.kind) != (CTL, CTL_GET_VERSION, "response"):
        raise ProtocolError("not a CTL Get Version Info response")
    if result_code(message) != (0, 0):
        raise ProtocolError("Get Version Info returned a protocol error")
    value = message.tlv(1)
    if not value or len(value) != 1 + 5 * value[0]:
        raise ProtocolError("invalid service-version list length")
    versions = {}
    for offset in range(1, len(value), 5):
        service, major, minor = struct.unpack_from("<BHH", value, offset)
        if service in versions:
            raise ProtocolError("duplicate service-version entry")
        versions[service] = (major, minor)
    return versions
