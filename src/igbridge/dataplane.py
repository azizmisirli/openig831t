# SPDX-License-Identifier: Apache-2.0
"""Bytes-only RAW_IP and bounded MAP/QMAP framing; no IO or format negotiation.

QMAPv5 matches Linux v6.12 include/linux/if_rmnet.h and rmnet_map_data.c:
4-byte MAP header + 4-byte checksum header + IP/pad. pkt_len EXCLUDES
both headers, including the v5 extension. No QMAP commands/chained extensions
or checksum computation requests are generated. Exact modem support is unknown.
"""
from collections import deque
from dataclasses import dataclass
import math
import struct

from .errors import ConfigurationError, ProtocolError


def validate_ip(packet, mtu=1500):
    """Return IP version after structural length/MTU checks; bytes never change.

    This is not checksum verification, IP reassembly, or transport validation.
    A caller must supply complete packet bytes, not CHECKSUM_PARTIAL/offload data.
    IPv6 jumbograms are deliberately unsupported. Extension bytes are preserved.
    """
    if type(mtu) is not int or not 40 <= mtu <= 65575:
        raise ConfigurationError('invalid MTU')
    if not isinstance(packet, bytes) or not packet:
        raise ProtocolError('IP packet must be nonempty bytes')
    if len(packet) > mtu:
        raise ProtocolError('IP MTU exceeded')
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            raise ProtocolError('truncated IPv4 header')
        header = (packet[0] & 15) * 4
        total = int.from_bytes(packet[2:4], 'big')
        if header < 20 or header > len(packet) or total < header or total != len(packet):
            raise ProtocolError('IPv4 header or total length mismatch')
    elif version == 6:
        if len(packet) < 40:
            raise ProtocolError('truncated IPv6 header')
        length = int.from_bytes(packet[4:6], 'big')
        if length + 40 != len(packet):
            raise ProtocolError('IPv6 payload length mismatch or unsupported jumbogram')
    else:
        raise ProtocolError('unsupported IP version')
    return version


@dataclass(frozen=True)
class QmapFrame:
    mux_id: int
    packet: bytes
    padding: bytes
    raw: bytes
    checksum_valid_reported: bool | None = None


class QmapCodec:
    """Whole-aggregate codec. Decode validates ALL frames before returning any.

    version=1 means the base MAP format, not QMI's WDA protocol enum value.
    version=5 requires the checksum-extension header. Downlink validity is only
    modem-reported metadata; we never turn it into a verified checksum claim.
    Nonzero padding is rejected by default as a deliberately strict local policy.
    """
    def __init__(self, *, version=1, allowed_mux_ids=(0x81,), mtu=1500,
                 max_aggregate=65536, max_frames=64, require_zero_padding=True):
        if type(version) is not int or version not in (1, 5):
            raise ConfigurationError('only base QMAP and QMAPv5 implemented')
        ids = tuple(allowed_mux_ids)
        if not ids or any(type(x) is not int or not 0 <= x <= 255 for x in ids) or len(set(ids)) != len(ids):
            raise ConfigurationError('explicit unique byte mux IDs required')
        if type(mtu) is not int or not 40 <= mtu <= 65535:
            raise ConfigurationError('QMAP MTU outside length field')
        if type(max_aggregate) is not int or not 4 <= max_aggregate <= 16 * 1024 * 1024 or type(max_frames) is not int or not 1 <= max_frames <= 4096:
            raise ConfigurationError('invalid aggregate bounds')
        if type(require_zero_padding) is not bool:
            raise ConfigurationError('padding policy must be bool')
        self.version, self.mux_ids, self.mtu = version, frozenset(ids), mtu
        self.max_aggregate, self.max_frames = max_aggregate, max_frames
        self.require_zero_padding = require_zero_padding

    def _mux(self, mux_id):
        if type(mux_id) is not int or mux_id not in self.mux_ids:
            raise ProtocolError('unmapped QMAP mux ID')

    def encode(self, packet, mux_id, *, alignment=1, checksum_offload=False):
        self._mux(mux_id)
        validate_ip(packet, self.mtu)
        if checksum_offload is not False:
            raise ProtocolError('partial checksum/offload requests unsupported')
        if type(alignment) is not int or alignment not in (1, 4):
            raise ConfigurationError('supported alignment is 1 or 4')
        pad = (-len(packet)) % alignment
        size = len(packet) + pad
        if size > 65535:
            raise ProtocolError('QMAP packet length overflow')
        extension = b'\x04\x00\x00\x00' if self.version == 5 else b''
        flags = pad | (0x40 if self.version == 5 else 0)
        raw = struct.pack('!BBH', flags, mux_id, size) + extension + packet + bytes(pad)
        if len(raw) > self.max_aggregate:
            raise ProtocolError('QMAP aggregate byte bound')
        return raw

    def aggregate(self, packets):
        """Iterable of (mux_id, packet); no partial output on a late invalid item."""
        frames, size = [], 0
        for mux, packet in packets:
            if len(frames) >= self.max_frames:
                raise ProtocolError('QMAP aggregate frame bound')
            raw = self.encode(packet, mux)
            size += len(raw)
            if size > self.max_aggregate:
                raise ProtocolError('QMAP aggregate byte bound')
            frames.append(raw)
        if not frames:
            raise ProtocolError('empty QMAP aggregate')
        return b''.join(frames)

    def decode(self, aggregate):
        if not isinstance(aggregate, bytes) or not aggregate:
            raise ProtocolError('QMAP aggregate must be nonempty bytes')
        if len(aggregate) > self.max_aggregate:
            raise ProtocolError('QMAP aggregate byte bound')
        frames, offset = [], 0
        while offset < len(aggregate):
            if len(frames) >= self.max_frames:
                raise ProtocolError('QMAP aggregate frame bound')
            if len(aggregate) - offset < 4:
                raise ProtocolError('truncated QMAP header')
            flags, mux, size = struct.unpack_from('!BBH', aggregate, offset)
            self._mux(mux)
            if flags & 0x80:
                raise ProtocolError('QMAP command unsupported')
            has_extension = bool(flags & 0x40)
            if has_extension != (self.version == 5):
                raise ProtocolError('QMAP extension/profile mismatch')
            pad = flags & 0x3f
            extra = 4 if has_extension else 0
            end = offset + 4 + extra + size
            if not size or pad >= size or end > len(aggregate):
                raise ProtocolError('QMAP length or padding bounds')
            valid = None
            if extra:
                info, csum, reserved = struct.unpack_from('!BBH', aggregate, offset + 4)
                if info != 0x04 or csum & 0x7f or reserved:
                    raise ProtocolError('unsupported QMAPv5 header chain/type/reserved fields')
                valid = bool(csum & 0x80)  # Downlink assertion only, no trusted offload metadata.
            start = offset + 4 + extra
            packet = aggregate[start:end - pad] if pad else aggregate[start:end]
            padding = aggregate[end - pad:end] if pad else b''
            if self.require_zero_padding and any(padding):
                raise ProtocolError('nonzero padding rejected by local policy')
            validate_ip(packet, self.mtu)
            frames.append(QmapFrame(mux, packet, padding, aggregate[offset:end], valid))
            offset = end
        return frames


class DataPlaneAdapter:
    """One explicitly mapped backend mux; atomic malformed/rate-limit drops.

    The caller supplies monotonic time. Complete USB aggregate boundaries must be
    provided; this class never guesses framing from time or fragment bytes. A
    shared token bucket limits packets in both directions; event storage is bounded.
    """
    def __init__(self, *, backend_format='raw_ip', mux_id=0x81, mtu=1500,
                 max_aggregate=65536, max_frames=64, packets_per_second=1000,
                 burst_packets=1000, max_events=128):
        if backend_format not in ('raw_ip', 'qmap', 'qmapv5'):
            raise ConfigurationError('unknown backend data format')
        if type(mux_id) is not int or not 0 <= mux_id <= 255:
            raise ConfigurationError('invalid mapped mux ID')
        if type(packets_per_second) not in (int, float) or not math.isfinite(packets_per_second) or packets_per_second <= 0 or type(burst_packets) is not int or burst_packets <= 0 or type(max_events) is not int or max_events <= 0:
            raise ConfigurationError('invalid rate/event bounds')
        self.codec = QmapCodec(version=5 if backend_format == 'qmapv5' else 1,
                               allowed_mux_ids=(mux_id,), mtu=mtu,
                               max_aggregate=max_aggregate, max_frames=max_frames)
        self.backend_format, self.mux_id, self.mtu = backend_format, mux_id, mtu
        self.rate, self.burst, self.tokens = packets_per_second, burst_packets, float(burst_packets)
        self._last = None
        self._events = deque(maxlen=max_events)
        self.suppressed_events = 0
        self.dropped = 0

    def _event(self, kind, **meta):
        if len(self._events) == self._events.maxlen:
            self.suppressed_events += 1
        self._events.append({'kind': kind, **meta})

    def pop_events(self):
        events = list(self._events)
        self._events.clear()
        if self.suppressed_events:
            events.append({'kind': 'metadata_overflow', 'count': self.suppressed_events})
            self.suppressed_events = 0
        return events

    def _clock(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0 or (self._last is not None and now < self._last):
            raise ProtocolError('invalid monotonic time')
        if self._last is not None:
            self.tokens = min(self.burst, self.tokens + (now - self._last) * self.rate)
        self._last = now

    def _admit(self, count):
        if count > self.tokens:
            raise ProtocolError('packet rate limit')
        self.tokens -= count

    def _drop(self, direction, reason, byte_count):
        self.dropped += 1
        self._event('drop', direction=direction, reason=reason, byte_count=byte_count)

    def to_backend(self, packet, now):
        try:
            self._clock(now)
            validate_ip(packet, self.mtu)
            output = packet if self.backend_format == 'raw_ip' else self.codec.encode(packet, self.mux_id)
            self._admit(1)
        except ProtocolError as e:
            self._drop('uplink', str(e), len(packet) if isinstance(packet, bytes) else 0)
            return b''
        self._event('forward', direction='uplink', packets=1, byte_count=len(output))
        return output

    def to_host(self, aggregate, now):
        try:
            self._clock(now)
            if self.backend_format == 'raw_ip':
                validate_ip(aggregate, self.mtu)
                packets = [aggregate]
            else:
                packets = [f.packet for f in self.codec.decode(aggregate)]
            self._admit(len(packets))
        except ProtocolError as e:
            self._drop('downlink', str(e), byte_count=len(aggregate) if isinstance(aggregate, bytes) else 0)
            return []
        self._event('forward', direction='downlink', packets=len(packets), byte_count=sum(map(len, packets)))
        return packets
