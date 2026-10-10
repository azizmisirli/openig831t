# SPDX-License-Identifier: Apache-2.0
import hashlib
import struct
import unittest

from igbridge.descriptors import (FS, HS, encode_functionfs_strings,
                                  inspect_configuration, load_profile, split_descriptors)
from igbridge.errors import ConfigurationError, ProtocolError


class DescriptorTests(unittest.TestCase):
    def setUp(self):
        self.p = load_profile()

    def test_captured_topology_and_speeds(self):
        expected = [(0, 0x81), (0, 1), (1, 0x83), (1, 0x82), (1, 2),
                    (2, 0x85), (2, 0x84), (2, 3), (3, 0x87), (3, 0x86), (3, 4),
                    (4, 0x89), (4, 0x88), (4, 5)]
        for speed, bulk, interval in [(FS, 64, 32), (HS, 512, 9)]:
            endpoints = self.p.endpoints(speed)
            self.assertEqual([(e.interface, e.address) for e in endpoints], expected)
            self.assertEqual(sum(e.direction == "IN" for e in endpoints), 9)
            for e in endpoints:
                self.assertEqual(e.max_packet, bulk if e.transfer_type == 2 else (8 if e.interface == 4 else 10))
                self.assertEqual(e.interval, 0 if e.transfer_type == 2 else interval)
        self.assertEqual(self.p.device.hex(), "1201000200000040a32c0940180301020301")

    def test_functionfs_header_length_and_full_cdc_preservation(self):
        encoded = self.p.functionfs_descriptors()
        self.assertEqual(struct.unpack_from("<IIIII", encoded), (3, 420, 3, 31, 31))
        self.assertEqual(encoded[20:220], self.p.full_speed[9:])
        self.assertEqual(encoded[220:], self.p.high_speed[9:])
        # Includes all twelve odd CDC descriptors; no normalization of their references.
        records = split_descriptors(encoded[20:220])
        self.assertEqual(sum(x[1] == 0x24 for x in records), 12)
        self.assertEqual(sum(x == bytes.fromhex("0524060000") for x in records), 3)

    def test_virtual_and_control_flags_are_explicit_only(self):
        encoded = self.p.functionfs_descriptors(virtual_addresses=True, all_control_recipients=True)
        self.assertEqual(struct.unpack_from("<I", encoded, 8)[0], 3 | 16 | 64)
        self.assertEqual(encoded[20:], self.p.functionfs_descriptors()[20:])

    def test_stock_parser_rejection_is_not_hidden_by_successful_encoding(self):
        # Pinned f_fs.c:2477-2621 has no 0x24 case; default returns EINVAL.
        # This is our preflight regression, not execution of the kernel parser.
        report = self.p.compatibility_report()
        self.assertEqual(report["rejected_descriptor_types"], [0x24])
        self.assertFalse(report["stock_functionfs_supported"])
        self.assertEqual(report["exact_live_clone"], "NOT_VERIFIED")
        self.assertTrue(report["requires_actual_endpoint_enable_verification"])
        self.assertEqual(report["kernel_source"]["sha256"],
                         "42dd5eb95e78fe0161b028ad3f0dd8ed10a60966a06e7d8e63d59ad633cfea43")

    def test_device_strings_are_not_function_strings_or_summary_identity(self):
        self.assertEqual(self.p.string(1), "BAIWANG")
        self.assertEqual(self.p.string(2), "Baiwang")
        self.assertEqual(self.p.functionfs_strings(), struct.pack("<IIII", 2, 16, 0, 0))
        self.assertEqual(self.p.string(3), "REDACTED_USB_SERIAL")
        self.assertEqual(self.p.summary()["serial"], "REDACTED_USB_SERIAL")

    def test_function_strings_uapi_multilingual(self):
        data = encode_functionfs_strings({0x409: ("one", "two"), 0x407: ("eins", "zwei")})
        self.assertEqual(struct.unpack_from("<IIII", data), (2, len(data), 2, 2))
        self.assertEqual(data[16:], b"\x07\x04eins\0zwei\0\x09\x04one\0two\0")
        for languages in [{0x409: ()}, {0x409: ("a",), 0x407: ("b", "c")}, {0x409: ("a\0b",)}]:
            with self.assertRaises(ConfigurationError):
                encode_functionfs_strings(languages)

    def test_truncation_invalid_lengths_and_counts(self):
        mutations = [self.p.high_speed[:-1], b"\0\2", b"\x01\2"]
        t = bytearray(self.p.high_speed); t[4] = 4; mutations.append(bytes(t))
        t = bytearray(self.p.high_speed); t[13] = 1; mutations.append(bytes(t))
        t = bytearray(self.p.high_speed); t[27] = 0x81; mutations.append(bytes(t))
        for data in mutations:
            with self.assertRaises(ProtocolError):
                inspect_configuration(data, HS)
        with self.assertRaises(ProtocolError):
            inspect_configuration(self.p.high_speed, FS)

    def test_profile_raw_hashes_match_provenance(self):
        import json
        from igbridge.descriptors import DEFAULT_PROFILE
        profile_json = json.loads(DEFAULT_PROFILE.read_text())
        expected = {p["path"]: p["sha256"] for p in profile_json["provenance"]}
        for name, data in [("configuration_0.bin", self.p.high_speed),
                           ("other_speed_configuration_0.bin", self.p.full_speed),
                           ("device_descriptor.bin", self.p.device), ("device_qualifier.bin", self.p.qualifier)]:
            self.assertEqual(hashlib.sha256(data).hexdigest(), expected["raw/" + name])


if __name__ == "__main__":
    unittest.main()
