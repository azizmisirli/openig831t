# SPDX-License-Identifier: Apache-2.0
import sys
import unittest
from igbridge.host_logs import command_plan, capture_command
from igbridge.errors import ConfigurationError


class HostLogTests(unittest.TestCase):
    def test_plan_has_only_read_operations_and_explicit_pid(self):
        plan = command_plan('/nonexistent/adb', 'TEST_SERIAL', 'com.example.dji', 123)
        self.assertEqual(len(plan), 6)
        self.assertIn('--pid=123', dict(plan)['existing_logcat'])
        for name, args in plan:
            self.assertNotIn('-c', args)
            self.assertNotIn('setprop', args)
            self.assertNotIn('root', args)
            self.assertNotIn('am', args)

    def test_shell_injection_selector_rejected(self):
        for package in ('com.x;reboot', 'com.x$(id)', 'x y', '../x'):
            with self.assertRaises(ConfigurationError):
                command_plan('/adb', 'SERIAL', package, 1)

    def test_bounded_local_child_capture_without_adb(self):
        raw, meta = capture_command([sys.executable, '-c', 'print("SYNTHETIC")'])
        self.assertEqual(raw, b'SYNTHETIC\n')
        self.assertEqual(meta['termination'], 'completed')

    def test_flood_and_timeout_stop_only_owned_local_child(self):
        raw, meta = capture_command([sys.executable, '-c', 'print("x"*20000)'], limit=1024)
        self.assertEqual(len(raw), 1024)
        self.assertEqual(meta['termination'], 'size_limit')
        _, meta = capture_command([sys.executable, '-c', 'import time; time.sleep(1)'], timeout=0.01)
        self.assertEqual(meta['termination'], 'deadline')
