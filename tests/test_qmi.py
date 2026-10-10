# SPDX-License-Identifier: Apache-2.0
"""Offline codec tests using synthetic-derived metadata, never raw captures."""
import hashlib
import random
import struct
import unittest

from igbridge.errors import ProtocolError
from igbridge.qmi import (QmiMessage, TLV, build_message, parse_message,
                          encode_message, result_code, service_versions, match_response)

# SYNTHETIC_DERIVED_METADATA: independently encoded protocol fixtures.
# Service versions derive from non-identifying measured metadata. No private
# raw capture is included; the transaction and TLV order are deliberately synthetic.
# Measurement source SHA256: c0de7c22538150eb5c7c3425d274cf606d537bf49d1f0f1161e08587082ad2a2
SYNTHETIC_FIXTURES = {'synthetic_sync': ('6f265f9e7270e92c9baa3c70cf42771ba488f5fd7e74843641afc6557ac8e916', '010b00800000020027000000'), 'synthetic_version_request': ('91321669fcbc6b7a7011803161096f30ca3412c7faaf89d290ed4d2e94b6eb38', '010b00000000005a21000000'), 'synthetic_version_response': ('236b3fc7704686227b445a540e157389d8c5d74ce3a93d7b8532e9b6ef625a0e', '01a700800000015a21009c000192001d00010005000101004300020100000003010019000401000c000501000a000701000300080100040009020001000a020018000b010057000c010004000f01000000100200000011010000001201000000170100000018010000001a010010001d010001001f0100000021010000002201000000240100000029010000002a010000002d010000003001000000360100000002040000000000')}
SYNC = bytes.fromhex(SYNTHETIC_FIXTURES["synthetic_sync"][1])
REQUEST = bytes.fromhex(SYNTHETIC_FIXTURES["synthetic_version_request"][1])
VERSIONS = bytes.fromhex(SYNTHETIC_FIXTURES["synthetic_version_response"][1])
OK = TLV(2, b"\0\0\0\0")


class QmiTests(unittest.TestCase):
    def test_fixture_hashes_and_byte_roundtrip(self):
        for name, (sha, hexdata) in SYNTHETIC_FIXTURES.items():
            with self.subTest(name=name):
                raw = bytes.fromhex(hexdata)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), sha)
                self.assertEqual(encode_message(parse_message(raw)), raw)

    def test_all_29_target_service_versions(self):
        actual = service_versions(parse_message(VERSIONS))
        expected = {0:(1,5), 1:(1,67), 2:(1,0), 3:(1,25), 4:(1,12),
                    5:(1,10), 7:(1,3), 8:(1,4), 9:(2,1), 10:(2,24),
                    11:(1,87), 12:(1,4), 15:(1,0), 16:(2,0), 17:(1,0),
                    18:(1,0), 23:(1,0), 24:(1,0), 26:(1,16), 29:(1,1),
                    31:(1,0), 33:(1,0), 34:(1,0), 36:(1,0), 41:(1,0),
                    42:(1,0), 45:(1,0), 48:(1,0), 54:(1,0)}
        self.assertEqual(actual, expected)

    def test_sync_indication_is_not_version_response_or_success(self):
        sync = parse_message(SYNC)
        self.assertEqual((sync.kind, sync.transaction_id, sync.message_id), ("indication", 0, 0x27))
        self.assertFalse(match_response(parse_message(REQUEST), sync))
        with self.assertRaises(ProtocolError):
            result_code(sync)
        with self.assertRaises(ProtocolError):
            service_versions(sync)

    def test_response_matches_all_four_fields(self):
        request, response = parse_message(REQUEST), parse_message(VERSIONS)
        self.assertTrue(match_response(request, response))
        from dataclasses import replace
        for modified in (replace(response, transaction_id=3), replace(response, message_id=0x27),
                         replace(response, service=2, cid=1), replace(response, kind="request")):
            self.assertFalse(match_response(request, modified))

    def test_ctl_vs_service_tid_width_and_flags(self):
        for service, tid in ((0,255), (2,0x1234), (0x99,65535)):
            for kind, flag in (("request",0), ("response",1 if service == 0 else 2),
                               ("indication",2 if service == 0 else 4)):
                raw = build_message(service, 0 if service == 0 else 13, tid, 0xabcd, kind)
                self.assertEqual(raw[6], flag)
                self.assertEqual(len(raw), 12 if service == 0 else 13)
                self.assertEqual(parse_message(raw).transaction_id, tid)
                if service:
                    self.assertEqual(raw[7:9], struct.pack("<H", tid))
        with self.assertRaises(ProtocolError):
            build_message(0,0,256,1)

    def test_client_id_alias(self):
        self.assertEqual(parse_message(build_message(2,17,1,0x20)).client_id, 17)

    def test_unknown_tlvs_duplicates_order_unchanged(self):
        tlvs = (TLV(255, b"\0\xff\x80"), TLV(0x80,b""), TLV(255,b"tail"))
        raw = build_message(0xaa,17,0xbeef,0xfefe,"response",tlvs)
        msg = parse_message(raw)
        self.assertEqual(msg.tlvs, tlvs)
        self.assertEqual(msg.to_bytes(), raw)
        with self.assertRaises(ProtocolError):
            msg.tlv(255)
        self.assertIsNone(msg.tlv(9,required=False))

    def test_rewrite_only_explicit_ids_preserves_payload(self):
        raw = build_message(2,7,0x1234,0x22,"response",(TLV(0x99,b"opaque"),OK))
        new = parse_message(raw).with_ids(cid=3,transaction_id=9).to_bytes()
        self.assertEqual(new[9:],raw[9:])
        self.assertEqual(parse_message(new).cid,3)

    def test_every_target_truncation_is_rejected(self):
        for raw in (SYNC, REQUEST, VERSIONS):
            for end in range(len(raw)):
                with self.subTest(size=len(raw),end=end), self.assertRaises(ProtocolError):
                    parse_message(raw[:end])

    def test_malformed_marker_length_direction_flags_and_cid(self):
        cases = []
        for offset,value in ((0,2),(1,10),(2,1),(3,0x80),(5,1),(6,3),(10,1)):
            raw=bytearray(REQUEST); raw[offset]=value; cases.append(raw)
        cases += [REQUEST+b"\0",REQUEST+REQUEST]
        svc=bytearray(build_message(2,1,1,0x20))
        for flag in (1,3,5,6,0x80,0xff):
            raw=bytearray(svc);raw[6]=flag;cases.append(raw)
        for raw in cases:
            with self.subTest(raw=bytes(raw).hex()), self.assertRaises(ProtocolError):
                parse_message(raw)

    def test_tlv_declared_length_overrun_and_short_header(self):
        for body in (b"\x01",b"\x01\x00",b"\x01\x05\x00abc"):
            raw = bytearray(REQUEST)
            struct.pack_into("<H",raw,1,11+len(body));struct.pack_into("<H",raw,10,len(body))
            with self.assertRaises(ProtocolError):
                parse_message(raw+body)

    def test_result_error_preserved_never_success(self):
        msg = parse_message(build_message(3,1,1,0x4f,"response",(TLV(2,b"\x01\x00\x4a\x00"),)))
        self.assertEqual(result_code(msg),(1,74))
        for value in (b"",b"\0"*3,b"\0\0\x01\0",b"\x02\0\0\0"):
            with self.assertRaises(ProtocolError):
                result_code(QmiMessage(2,1,1,0x20,"response",(TLV(2,value),)))

    def test_versions_bad_count_duplicate_and_failure(self):
        for value in (b"", b"\x02\x00\x01\x00\x05\x00", b"\0trailing",
                      b"\x02\x00\x01\x00\x05\x00\x00\x01\x00\x05\x00"):
            with self.assertRaises(ProtocolError):
                service_versions(QmiMessage(0,0,1,0x21,"response",(OK,TLV(1,value))))
        with self.assertRaises(ProtocolError):
            service_versions(QmiMessage(0,0,1,0x21,"response",(TLV(2,b"\1\0\x4a\0"),)))

    def test_invalid_types_ranges_and_maximum_frame(self):
        for args in ((True,0,1,1),(256,0,1,1),(0,1,1,1),(0,0,-1,1),(2,256,1,1),(2,1,65536,1)):
            with self.assertRaises(ProtocolError):
                build_message(*args)
        for raw in (None,42,"hex",[1]*12):
            with self.assertRaises(ProtocolError):
                parse_message(raw)
        raw=build_message(2,1,1,1,tlvs=(TLV(1,b"\0"*(65536-13-3)),))
        self.assertEqual(len(raw),65536)
        self.assertEqual(parse_message(raw).to_bytes(),raw)
        with self.assertRaises(ProtocolError):
            build_message(2,1,1,1,tlvs=(TLV(1,b"\0"*(65536-13-2)),))

    def test_deterministic_valid_property_roundtrips(self):
        rng=random.Random(20261010)
        for _ in range(500):
            service=rng.randrange(256)
            message=QmiMessage(service,0 if service==0 else rng.randrange(256),
                               rng.randrange(256 if service==0 else 65536),rng.randrange(65536),
                               rng.choice(("request","response","indication")),
                               tuple(TLV(rng.randrange(256),rng.randbytes(rng.randrange(80))) for _ in range(rng.randrange(8))))
            self.assertEqual(parse_message(message.to_bytes()),message)

    def test_random_input_never_leaks_unexpected_exception(self):
        rng=random.Random(7)
        for _ in range(1000):
            raw=rng.randbytes(rng.randrange(200))
            try:
                parsed=parse_message(raw)
            except ProtocolError:
                continue
            self.assertEqual(parsed.to_bytes(),raw)


if __name__ == "__main__":
    unittest.main()
