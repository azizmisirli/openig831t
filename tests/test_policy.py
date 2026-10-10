# SPDX-License-Identifier: Apache-2.0
"""Policy boundary: status queries cannot become network activation."""
import unittest
from igbridge.errors import PolicyDenied
from igbridge.policy import LaboratoryPolicy
from igbridge.qmi import TLV, build_message, parse_message


class WdsPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = LaboratoryPolicy()

    def check(self, service, message, tlvs=()):
        self.policy.qmi(parse_message(build_message(service, 0 if service == 0 else 1,
                                                   1, message, tlvs=tlvs)))

    def test_readonly_status_and_transient_client_are_allowed(self):
        self.check(1, 0x22)
        self.check(0, 0x22, (TLV(1, b'\x01'),))
        self.check(0, 0x23, (TLV(1, b'\x01\x01'),))

    def test_network_actions_and_status_variants_are_denied(self):
        for message, tlvs in ((0x20, ()), (0x21, ()),
                              (0x22, (TLV(0x10, b'\x01'),))):
            with self.subTest(message=message, tlvs=tlvs):
                with self.assertRaises(PolicyDenied):
                    self.check(1, message, tlvs)

    def test_client_allocation_can_be_disabled_independently(self):
        self.policy = LaboratoryPolicy(allow_transient_clients=False)
        self.check(1, 0x22)
        with self.assertRaises(PolicyDenied):
            self.check(0, 0x22, (TLV(1, b'\x01'),))
