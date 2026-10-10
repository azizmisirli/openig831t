# SPDX-License-Identifier: Apache-2.0
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from igbridge.configfs import BindReadiness, ConfigfsTransaction, DirectoryFS, KernelConfigFS
from igbridge.descriptors import load_profile, split_descriptors
from igbridge.errors import ConfigurationError, PolicyDenied


class FailingFS(DirectoryFS):
    def __init__(self, root, fail_write=None, fail_unbind=False):
        super().__init__(root)
        self.fail_write, self.fail_unbind, self.count = fail_write, fail_unbind, 0
        self.operations = []

    def write_text(self, path, value):
        self.count += 1
        self.operations.append((path, value))
        if self.count == self.fail_write or (self.fail_unbind and path.endswith("/UDC") and value == "\n"):
            raise OSError("synthetic injected failure")
        super().write_text(path, value)


def synthetic_nonexact_profile():
    """Test-only adaptation; explicitly not an exact IG831T or host-accepted profile."""
    p = load_profile()
    def stripped(raw):
        records = split_descriptors(raw)
        body = b"".join(d for d in records[1:] if d[1] != 0x24)
        head = bytearray(records[0]); head[2:4] = (len(body) + 9).to_bytes(2, "little")
        return bytes(head) + body
    return replace(p, name="SYNTHETIC_NONEXACT_DIAGNOSTIC", full_speed=stripped(p.full_speed), high_speed=stripped(p.high_speed))


READY = BindReadiness(True, True, True, True, True)


class ConfigfsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_stage_preserves_config_and_no_udc_write_then_cleanup(self):
        fs = FailingFS(self.root)
        transaction = ConfigfsTransaction(load_profile(), fs)
        transaction.stage(serial_number="LAB_ONLY")
        gadget = self.root / "ig831t"
        self.assertEqual((gadget / "idVendor").read_text(), "0x2ca3\n")
        self.assertEqual((gadget / "configs/c.1/MaxPower").read_text(), "500\n")
        self.assertEqual((gadget / "configs/c.1/bmAttributes").read_text(), "0xa0\n")
        self.assertTrue((gadget / "configs/c.1/ffs.ig831t").is_symlink())
        self.assertFalse((gadget / "configs/c.1/strings").exists())
        self.assertFalse(any(path.endswith("/UDC") for path, _ in fs.operations))
        transaction.cleanup(); transaction.cleanup()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_gadget_is_never_adopted_or_deleted(self):
        gadget = self.root / "ig831t"; gadget.mkdir(); (gadget / "keep").write_text("existing")
        transaction = ConfigfsTransaction(load_profile(), DirectoryFS(self.root))
        with self.assertRaises(PolicyDenied):
            transaction.stage(serial_number="LAB")
        transaction.cleanup()
        self.assertEqual((gadget / "keep").read_text(), "existing")

    def test_each_attribute_failure_rolls_back_only_own_gadget(self):
        for count in range(1, 15):
            with self.subTest(count=count):
                transaction = ConfigfsTransaction(load_profile(), FailingFS(self.root, fail_write=count))
                with self.assertRaises(ConfigurationError):
                    transaction.stage(serial_number="LAB")
                self.assertEqual(list(self.root.iterdir()), [])

    def test_stock_exact_bind_denied_even_with_coordinator_readiness(self):
        fs = FailingFS(self.root)
        transaction = ConfigfsTransaction(load_profile(), fs); transaction.stage(serial_number="LAB")
        with self.assertRaises(PolicyDenied):
            transaction.bind("dummy_udc", explicit=True, readiness=READY)
        self.assertFalse(any(path.endswith("/UDC") for path, _ in fs.operations))
        transaction.cleanup()

    def test_synthetic_bind_is_explicit_single_attempt_and_unbind_precedes_cleanup(self):
        fs = FailingFS(self.root)
        transaction = ConfigfsTransaction(synthetic_nonexact_profile(), fs); transaction.stage(serial_number="LAB")
        for explicit, ready in [(False, READY), (True, BindReadiness()), ("yes", READY)]:
            with self.assertRaises(PolicyDenied):
                transaction.bind("dummy_udc", explicit=explicit, readiness=ready)
        transaction.bind("dummy_udc", explicit=True, readiness=READY)
        with self.assertRaises(PolicyDenied):
            transaction.bind("dummy_udc", explicit=True, readiness=READY)
        transaction.cleanup()
        self.assertEqual([v for path, v in fs.operations if path.endswith("/UDC")], ["dummy_udc\n", "\n"])
        self.assertFalse((self.root / "ig831t").exists())

    def test_unbind_failure_retains_gadget_and_journal(self):
        fs = FailingFS(self.root, fail_unbind=True)
        transaction = ConfigfsTransaction(synthetic_nonexact_profile(), fs); transaction.stage(serial_number="LAB")
        transaction.bind("dummy_udc", explicit=True, readiness=READY)
        with self.assertRaises(ConfigurationError):
            transaction.cleanup()
        self.assertTrue((self.root / "ig831t/configs/c.1/ffs.ig831t").is_symlink())
        self.assertTrue(transaction.cleanup_errors)

    def test_foreign_entry_never_recursively_deleted(self):
        transaction = ConfigfsTransaction(load_profile(), DirectoryFS(self.root)); transaction.stage(serial_number="LAB")
        (self.root / "ig831t/foreign").write_text("do not delete")
        with self.assertRaises(ConfigurationError):
            transaction.cleanup()
        self.assertEqual((self.root / "ig831t/foreign").read_text(), "do not delete")

    def test_serial_path_and_kernel_opt_in_guards(self):
        transaction = ConfigfsTransaction(load_profile(), DirectoryFS(self.root))
        with self.assertRaises(ConfigurationError):
            transaction.stage()
        self.assertFalse((self.root / "ig831t").exists())
        with self.assertRaises(ConfigurationError):
            ConfigfsTransaction(load_profile(), DirectoryFS(self.root), "../other")
        with self.assertRaises(PolicyDenied):
            DirectoryFS("/sys/kernel/config/usb_gadget")
        with self.assertRaises(PolicyDenied):
            KernelConfigFS("/sys/kernel/config/usb_gadget")


if __name__ == "__main__":
    unittest.main()
