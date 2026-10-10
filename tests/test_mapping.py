# SPDX-License-Identifier: Apache-2.0
import unittest
from igbridge.mapping import AddressMap, EndpointBinding as E, InterfaceBinding as I
from igbridge.errors import ConfigurationError, PolicyDenied


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.m = AddressMap([I(4, 0, 4), I(2, 1, 2)],
                            [E(0x89, 0x81, 0x89, 0x88), E(0x88, 0x82, 0x88, 0x8e), E(5, 1, 5, 0xf)])

    def test_setup_interface_and_endpoint_are_separate(self):
        self.assertEqual(self.m.setup_to_backend(0x21, 0), 4)
        self.assertEqual(self.m.setup_to_backend(0x22, 1), 0xf)
        self.assertEqual(self.m.setup_to_backend(0x21, 1), 2)
        self.assertEqual(self.m.notification_interface(4), 4)
        self.assertEqual(self.m.translate(0x8e, recipient="endpoint", source="backend", destination="host"), 0x88)

    def test_no_blind_forward_or_high_byte_loss(self):
        for bm, idx in [(0x20, 4), (0x21, 0x104), (0x21, 9), (0xA3, 0)]:
            with self.assertRaises(PolicyDenied):
                self.m.setup_to_backend(bm, idx)

    def test_unknown_backend_and_invalid_direction_rejected(self):
        unbound = AddressMap([I(4, 0)], [])
        with self.assertRaises(PolicyDenied):
            unbound.setup_to_backend(0x21, 0)
        with self.assertRaises(ConfigurationError):
            AddressMap([], [E(0x89, 1)])
        with self.assertRaises(ConfigurationError):
            AddressMap([I(None, 0)], [])

    def test_duplicate_and_invalid_addresses(self):
        for records in [[E(0x81, 0x81), E(0x82, 0x81)], [E(0x80, 0x81)], [E(0x91, 0x81)]]:
            with self.assertRaises(ConfigurationError):
                AddressMap([], records)
        with self.assertRaises(ConfigurationError):
            AddressMap([I(1, 0, 3), I(2, 1, 3)], [])

    def test_full_direction_key_and_source_low_nibble_hazard(self):
        mapping = AddressMap([], [E(0x81, 0x81, 0x81, 0x82), E(1, 1, 1, 2)])
        self.assertEqual(mapping.physical_low_nibble_collisions(), (1,))
        self.assertEqual(mapping.translate(1, recipient="endpoint", source="host", destination="backend"), 2)
        self.assertEqual(mapping.translate(0x81, recipient="endpoint", source="host", destination="backend"), 0x82)

    def test_exact_observed_map_required(self):
        self.m.verify_exact_binding({0x81: 0x89, 0x82: 0x88, 1: 5}, {0: 4, 1: 2})
        for eps in [{0x81: 0x8b, 0x82: 0x8a, 1: 0xc}, {0x81: 0x89}]:
            with self.assertRaises(ConfigurationError):
                self.m.verify_exact_binding(eps, {0: 4, 1: 2})
        with self.assertRaises(ConfigurationError):
            self.m.verify_exact_binding({0x81: 0x89, 0x82: 0x88, 1: 5}, {False: 4, 1: 2})


if __name__ == "__main__":
    unittest.main()
