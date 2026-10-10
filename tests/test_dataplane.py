# SPDX-License-Identifier: Apache-2.0
"""SYNTHETIC protocol fixtures; no recorded target/candidate bulk traffic exists."""
import unittest
from igbridge.dataplane import validate_ip, QmapCodec, DataPlaneAdapter
from igbridge.errors import ConfigurationError, ProtocolError

# Explicit IPv4 header total length 20; checksum is structurally opaque here.
V4 = bytes.fromhex('4500001400000000403b00007f0000017f000001')
V6 = bytes.fromhex('6000000000003b40' + '00' * 32)


class IPTests(unittest.TestCase):
    def test_versions_and_mtu(self):
        self.assertEqual(validate_ip(V4), 4)
        self.assertEqual(validate_ip(V6), 6)
        self.assertEqual(validate_ip(V6, 40), 6)
        with self.assertRaises(ProtocolError): validate_ip(V6 + b'x', 40)

    def test_ipv4_ihl_options_and_total_length(self):
        with self.assertRaises(ProtocolError): validate_ip(bytes([0x44]) + V4[1:])
        with self.assertRaises(ProtocolError): validate_ip(bytes([0x46]) + V4[1:])
        options = b'\x46' + V4[1:2] + b'\x00\x18' + V4[4:] + b'\0' * 4
        self.assertEqual(validate_ip(options), 4)
        for bad in [b'', V4[:-1], V4 + b'x', V4[:2] + b'\x00\x10' + V4[4:], b'\x70' + V4[1:]]:
            with self.assertRaises(ProtocolError): validate_ip(bad)

    def test_ipv6_payload_and_no_jumbo_guess(self):
        v6 = V6[:4] + b'\x00\x04' + V6[6:] + b'test'
        self.assertEqual(validate_ip(v6), 6)
        for bad in [v6[:-1], v6 + b'x', V6[:-1], V6 + b'test']:
            with self.assertRaises(ProtocolError): validate_ip(bad)


class QmapTests(unittest.TestCase):
    def test_base_known_wire_header_and_preserve(self):
        q = QmapCodec()
        wire = b'\x00\x81\x00\x14' + V4
        self.assertEqual(q.encode(V4, 0x81), wire)
        f = q.decode(wire)[0]
        self.assertEqual((f.mux_id, f.packet, f.raw, f.padding), (129, V4, wire, b''))

    def test_v5_known_wire_header_length_excludes_extension(self):
        q = QmapCodec(version=5)
        wire = bytes.fromhex('40 81 00 14 04 00 00 00') + V4
        self.assertEqual(q.encode(V4, 129), wire)
        self.assertEqual(q.decode(wire)[0].packet, V4)
        marked = wire[:5] + b'\x80' + wire[6:]
        self.assertTrue(q.decode(marked)[0].checksum_valid_reported)
        # Including the extension in pkt_len must not parse as the next frame.
        wrong = wire[:2] + b'\x00\x18' + wire[4:]
        with self.assertRaises(ProtocolError): q.decode(wrong)
        with self.assertRaises(ProtocolError): q.encode(V4, 129, checksum_offload=True)

    def test_v5_reject_chain_unknown_type_reserved_csum(self):
        base = bytes.fromhex('40 81 00 14 04 00 00 00') + V4
        for pos, value in [(4, 5), (4, 6), (5, 1), (6, 1), (7, 1), (0, 0), (0, 0xc0)]:
            bad = base[:pos] + bytes([value]) + base[pos+1:]
            with self.subTest(pos=pos, value=value), self.assertRaises(ProtocolError): QmapCodec(version=5).decode(bad)
        with self.assertRaises(ProtocolError): QmapCodec().decode(base)

    def test_padding_bounds_and_explicit_local_zero_policy(self):
        packet = V4[:2] + b'\x00\x15' + V4[4:] + b'x'
        wire = b'\x03\x81\x00\x18' + packet + b'\0' * 3
        q = QmapCodec()
        self.assertEqual(q.encode(packet, 129, alignment=4), wire)
        self.assertEqual(q.decode(wire)[0].padding, b'\0' * 3)
        nonzero = wire[:-1] + b'x'
        with self.assertRaises(ProtocolError): q.decode(nonzero)
        self.assertEqual(QmapCodec(require_zero_padding=False).decode(nonzero)[0].raw, nonzero)
        for bad in [b'\x14\x81\x00\x14' + V4, b'\x00\x81\0\0', b'\x80\x81\x00\x14' + V4]:
            with self.assertRaises(ProtocolError): q.decode(bad)

    def test_aggregate_mixed_versions_mux_and_atomic_failure(self):
        q = QmapCodec(allowed_mux_ids=(1, 2))
        wire = b'\x00\x01\x00\x14' + V4 + b'\x00\x02\x00\x28' + V6
        self.assertEqual(q.aggregate([(1, V4), (2, V6)]), wire)
        self.assertEqual([f.packet for f in q.decode(wire)], [V4, V6])
        for bad in [wire[:-1], wire + b'\x00', b'\x00\x03\x00\x14' + V4, wire + b'\0' * 4]:
            with self.assertRaises(ProtocolError): q.decode(bad)
        with self.assertRaises(ProtocolError): q.aggregate([(1, V4), (3, V6)])

    def test_every_truncated_single_frame_rejected(self):
        for version in (1, 5):
            q = QmapCodec(version=version)
            wire = q.encode(V6, 129)
            for cut in range(len(wire)):
                with self.subTest(version=version, cut=cut), self.assertRaises(ProtocolError): q.decode(wire[:cut])

    def test_aggregate_bounds_and_configuration(self):
        q = QmapCodec(max_frames=1)
        wire = q.encode(V4, 129)
        with self.assertRaises(ProtocolError): q.decode(wire * 2)
        with self.assertRaises(ProtocolError): q.aggregate([(129, V4)] * 2)
        with self.assertRaises(ProtocolError): QmapCodec(max_aggregate=23).encode(V4, 129)
        with self.assertRaises(ProtocolError): q.aggregate([])
        for kwargs in [{'version': 4}, {'allowed_mux_ids': ()}, {'allowed_mux_ids': (1, 1)}, {'max_frames': 0}, {'allowed_mux_ids': (True,)}]:
            with self.assertRaises(ConfigurationError): QmapCodec(**kwargs)


class AdapterTests(unittest.TestCase):
    def test_plain_ip_preserves_bytes(self):
        d = DataPlaneAdapter()
        self.assertEqual(d.to_backend(V4, 0), V4)
        self.assertEqual(d.to_host(V6, .1), [V6])

    def test_bad_late_frame_no_prefix_forward_or_token_debit(self):
        d = DataPlaneAdapter(backend_format='qmap', burst_packets=2)
        good = b'\x00\x81\x00\x14' + V4
        self.assertEqual(d.to_host(good + good[:-1], 0), [])
        self.assertEqual(d.tokens, 2)
        self.assertEqual(d.to_host(good * 2, 0), [V4, V4])
        self.assertEqual(d.tokens, 0)

    def test_mux_map_reject_wrong_channel(self):
        d = DataPlaneAdapter(backend_format='qmapv5', mux_id=7)
        self.assertEqual(d.to_backend(V4, 0), b'\x40\x07\x00\x14\x04\0\0\0' + V4)
        self.assertEqual(d.to_host(b'\x40\x08\x00\x14\x04\0\0\0' + V4, .1), [])

    def test_rate_limit_refill_and_time_errors(self):
        d = DataPlaneAdapter(packets_per_second=1, burst_packets=1)
        self.assertEqual(d.to_backend(V4, 0), V4)
        self.assertEqual(d.to_backend(V4, .5), b'')
        self.assertEqual(d.to_backend(V4, 1), V4)
        for now in [0, float('inf'), float('nan')]:
            self.assertEqual(d.to_backend(V4, now), b'')
        self.assertEqual(d.to_backend(V4, 2), V4)

    def test_bounded_logs_no_payload_and_bad_type(self):
        d = DataPlaneAdapter(max_events=2)
        for _ in range(5): self.assertEqual(d.to_backend(b'not an IP SECRET', 0), b'')
        events = d.pop_events()
        self.assertLessEqual(len(events), 3)
        self.assertEqual(events[-1]['kind'], 'metadata_overflow')
        self.assertNotIn('SECRET', repr(events))
        self.assertEqual(d.to_host(None, 0), [])


if __name__ == '__main__': unittest.main()
