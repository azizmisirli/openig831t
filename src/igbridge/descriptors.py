# SPDX-License-Identifier: Apache-2.0
"""Sanitized measured USB descriptors and FunctionFS UAPI encoders; no I/O at import.

Encoding the measured composition does NOT make it acceptable to stock FunctionFS:
Linux v6.12 rejects type 0x24 here. Call compatibility_report before live use.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

from .errors import ConfigurationError, ProtocolError

FS = "full_speed"
HS = "high_speed"
DEFAULT_PROFILE = Path(__file__).resolve().parent / "data" / "ig831t_exact.json"
STOCK_FFS_REFERENCE = {
    "url": "https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/usb/gadget/function/f_fs.c",
    "sha256": "42dd5eb95e78fe0161b028ad3f0dd8ed10a60966a06e7d8e63d59ad633cfea43",
    "function": "ffs_do_single_desc",
    "line_start": 2477,
    "line_end": 2621,
}


def split_descriptors(data: bytes) -> tuple[bytes, ...]:
    if not isinstance(data, bytes) or len(data) > 65535:
        raise ProtocolError("bounded descriptor bytes required")
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2 or data[offset] < 2:
            raise ProtocolError("short descriptor header")
        end = offset + data[offset]
        if end > len(data):
            raise ProtocolError("truncated descriptor")
        result.append(data[offset:end])
        offset = end
    return tuple(result)


@dataclass(frozen=True)
class Endpoint:
    interface: int
    address: int
    transfer_type: int
    max_packet: int
    interval: int

    @property
    def direction(self) -> str:
        return "IN" if self.address & 0x80 else "OUT"


def inspect_configuration(data: bytes, speed: str) -> tuple[Endpoint, ...]:
    if speed not in (FS, HS):
        raise ConfigurationError("only full/high speed supported")
    records = split_descriptors(data)
    if not records or len(records[0]) != 9 or records[0][1] not in (2, 7):
        raise ProtocolError("configuration header required")
    header = records[0]
    if int.from_bytes(header[2:4], "little") != len(data):
        raise ProtocolError("configuration total length mismatch")
    interfaces = set()
    addresses = set()
    endpoints = []
    current = None
    remaining = 0
    for d in records[1:]:
        if d[1] == 4:
            if len(d) != 9 or remaining or d[3] != 0 or d[2] in interfaces:
                raise ProtocolError("invalid interface/count/alternate")
            current = d[2]
            remaining = d[4]
            interfaces.add(current)
        elif d[1] == 5:
            if current is None or len(d) != 7 or not remaining:
                raise ProtocolError("endpoint outside declared interface")
            address, kind = d[2], d[3] & 3
            packet = int.from_bytes(d[4:6], "little")
            if address & 0x70 or not address & 15 or address in addresses:
                raise ProtocolError("invalid or duplicate endpoint address")
            if kind not in (2, 3) or packet & ~0x7ff or packet == 0:
                raise ProtocolError("unsupported endpoint format")
            if kind == 2 and packet not in ((8, 16, 32, 64) if speed == FS else (512,)):
                raise ProtocolError("bulk packet size invalid for speed")
            if kind == 3 and (packet > (64 if speed == FS else 1024) or not 1 <= d[6] <= (255 if speed == FS else 16)):
                raise ProtocolError("interrupt packet/interval invalid")
            addresses.add(address)
            endpoints.append(Endpoint(current, address, kind, packet, d[6]))
            remaining -= 1
        elif d[1] == 0x24:
            if current is None or len(d) < 3:
                raise ProtocolError("class descriptor outside interface")
        else:
            raise ProtocolError("unsupported descriptor in captured profile")
    if remaining or len(interfaces) != header[4] or interfaces != set(range(header[4])):
        raise ProtocolError("interface/endpoint count mismatch")
    return tuple(endpoints)


def encode_functionfs_strings(languages: dict[int, tuple[str, ...]]) -> bytes:
    """Function string indexes only. Device strings belong to configfs instead."""
    if not languages:
        return struct.pack("<IIII", 2, 16, 0, 0)
    counts = {len(strings) for strings in languages.values()}
    if len(counts) != 1 or not next(iter(counts)):
        raise ConfigurationError("equal positive string count required per language")
    body = bytearray()
    for lang, strings in sorted(languages.items()):
        if type(lang) is not int or not 1 <= lang <= 65535:
            raise ConfigurationError("invalid LANGID")
        body += struct.pack("<H", lang)
        for text in strings:
            if not isinstance(text, str) or "\0" in text:
                raise ConfigurationError("invalid function string")
            encoded = text.encode("utf-8")
            if len(encoded) > 1024:
                raise ConfigurationError("function string too long")
            body += encoded + b"\0"
    return struct.pack("<IIII", 2, 16 + len(body), next(iter(counts)), len(languages)) + body


@dataclass(frozen=True)
class GadgetProfile:
    name: str
    device: bytes
    qualifier: bytes
    full_speed: bytes
    high_speed: bytes
    # (LANGID, index, raw USB string descriptor), with the published serial redacted.
    strings: tuple[tuple[int, int, bytes], ...]
    limitations: tuple[str, ...]

    def configuration(self, speed: str) -> bytes:
        if speed not in (FS, HS):
            raise ConfigurationError("unknown speed")
        return getattr(self, speed)

    def endpoints(self, speed: str = HS) -> tuple[Endpoint, ...]:
        return inspect_configuration(self.configuration(speed), speed)

    def string(self, index: int, language: int = 0x409) -> str:
        for lang, idx, raw in self.strings:
            if (lang, idx) == (language, index):
                return raw[2:].decode("utf-16-le", errors="strict")
        raise ConfigurationError("captured string unavailable")

    def functionfs_descriptors(self, *, virtual_addresses: bool = False,
                               all_control_recipients: bool = False) -> bytes:
        """Pure encoder preserves all CDC bytes. Compatibility is a separate gate."""
        fs = split_descriptors(self.full_speed)[1:]
        hs = split_descriptors(self.high_speed)[1:]
        inspect_configuration(self.full_speed, FS)
        inspect_configuration(self.high_speed, HS)
        flags = 3 | (16 if virtual_addresses else 0) | (64 if all_control_recipients else 0)
        body = b"".join(fs + hs)
        return struct.pack("<IIIII", 3, 20 + len(body), flags, len(fs), len(hs)) + body

    def functionfs_strings(self) -> bytes:
        if any(d[1] == 4 and d[8] for d in split_descriptors(self.high_speed)):
            raise ConfigurationError("nonzero function strings need explicit remap")
        return encode_functionfs_strings({})

    def compatibility_report(self) -> dict:
        rejected = sorted({d[1] for d in split_descriptors(self.high_speed)[1:] if d[1] not in (4, 5)})
        return {"kernel_reference": "Linux v6.12 ffs_do_single_desc",
                "kernel_source": dict(STOCK_FFS_REFERENCE),
                "stock_functionfs_supported": not rejected,
                "rejected_descriptor_types": rejected,
                "exact_live_clone": "NOT_VERIFIED", "minimum_host_acceptance": "UNKNOWN",
                "virtual_address_is_universal_fix": False,
                "requires_actual_endpoint_enable_verification": True}

    def summary(self) -> dict:
        eps = self.endpoints()
        return {"name": self.name, "vid": int.from_bytes(self.device[8:10], "little"),
                "pid": int.from_bytes(self.device[10:12], "little"), "interfaces": self.high_speed[4],
                "in_endpoints": sum(e.direction == "IN" for e in eps),
                "out_endpoints": sum(e.direction == "OUT" for e in eps),
                "serial": "REDACTED_USB_SERIAL", "configuration_sha256": hashlib.sha256(self.high_speed).hexdigest(),
                "compatibility": self.compatibility_report()}


def load_profile(path: str | Path | None = None) -> GadgetProfile:
    try:
        raw = json.loads(Path(path or DEFAULT_PROFILE).read_text(encoding="utf-8"))
        if raw["schema_version"] != 1:
            raise ConfigurationError("unsupported profile schema")
        profile = GadgetProfile(raw["name"], bytes.fromhex(raw["device_hex"]),
                                bytes.fromhex(raw["qualifier_hex"]), bytes.fromhex(raw["full_speed_hex"]),
                                bytes.fromhex(raw["high_speed_hex"]),
                                tuple((int(lang), int(idx), bytes.fromhex(value))
                                      for lang, table in raw["strings"].items() for idx, value in table.items()),
                                tuple(raw["limitations"]))
        if len(profile.device) != 18 or profile.device[:2] != b"\x12\x01":
            raise ConfigurationError("invalid device descriptor")
        if len(profile.qualifier) != 10 or profile.qualifier[:2] != b"\x0a\x06":
            raise ConfigurationError("invalid qualifier")
        for lang, idx, value in profile.strings:
            if not 1 <= lang <= 65535 or not 1 <= idx <= 255 or len(value) < 2 or value[:2] != bytes((len(value), 3)) or len(value) % 2:
                raise ConfigurationError("invalid string descriptor")
            value[2:].decode("utf-16-le", errors="strict")
        fs, hs = profile.endpoints(FS), profile.endpoints(HS)
        if [(e.interface, e.address, e.transfer_type) for e in fs] != [(e.interface, e.address, e.transfer_type) for e in hs]:
            raise ConfigurationError("speed topology mismatch")
        return profile
    except (OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("invalid profile or unavailable source file") from exc
