# SPDX-License-Identifier: Apache-2.0
"""Offline tests; TARGET response fixtures exclude ATI because it contains PII.
Source: windows_driver_research/macos_tests/mi02_identification_run_01/transfers.jsonl
SHA256 b7b57a2845cb9176942c2a9b603d36b41d11612b8a19bb49ec301924f6e59c97.
Only the three identity responses below are copied. Other fixtures are SYNTHETIC.
"""
import unittest
from igbridge.at import ATForward, ATProxy, IdentityRule
from igbridge.errors import ConfigurationError, ProtocolError

TARGET = (
    (b'AT+CGMI\r', b'AT+CGMI\r\r\nFibocom Wireless Inc.\r\n\r\nOK\r\n'),
    (b'AT+CGMM\r', b'AT+CGMM\r\r\nNL668T-GL\r\n\r\nOK\r\n'),
    (b'AT+CGMR\r', b'AT+CGMR\r\r\n19906.5090.00.02.00.23\r\n\r\nOK\r\n'),
)


def proxy(**kwargs):
    p = ATProxy(**kwargs)
    p.open()
    return p


def rule():
    return IdentityRule(b'AT+CGMM', b'Candidate', b'Baseline', 'SYNTHETIC evidence only')


class ATTests(unittest.TestCase):
    def test_target_responses_all_two_chunk_splits_byte_exact(self):
        for command, response in TARGET:
            for cut in range(len(response) + 1):
                with self.subTest(command=command, cut=cut):
                    p = proxy()
                    self.assertEqual(p.host_to_backend(command, 0), command)
                    got = p.backend_to_host(response[:cut], .1) + p.backend_to_host(response[cut:], .2)
                    self.assertEqual(got, response)
                    self.assertEqual(p.state, 'IDLE')

    def test_target_single_byte_stream_preserves_echo_and_endings(self):
        p = proxy()
        cmd, response = TARGET[0]
        self.assertEqual(b''.join(p.host_to_backend(bytes([x]), 0) for x in cmd), cmd)
        self.assertEqual(b''.join(p.backend_to_host(bytes([x]), .1) for x in response), response)
        self.assertIn('echo', [e['kind'] for e in p.pop_events()])

    def test_crlf_command_fragment_suffix(self):
        p = proxy()
        self.assertEqual(p.host_to_backend(b'AT\r', 0) + p.host_to_backend(b'\n', .1), b'AT\r\n')

    def test_previous_crlf_suffix_and_next_command_share_chunk(self):
        p = proxy()
        self.assertEqual(p.host_to_backend(b'AT\r', 0), b'AT\r')
        self.assertEqual(p.backend_to_host(b'OK\r\n', .1), b'OK\r\n')
        self.assertEqual(p.host_to_backend(b'\nAT+CGMI\r', .2), b'\nAT+CGMI\r')
        self.assertEqual(p.state, 'RESPONSE_PENDING')

    def test_non_lf_byte_consumes_previous_crlf_suffix_allowance(self):
        p = proxy()
        p.host_to_backend(b'AT\r', 0)
        p.backend_to_host(b'OK\r\n', .1)
        self.assertEqual(p.host_to_backend(b'AT+', .2), b'')
        with self.assertRaises(ProtocolError):
            p.host_to_backend(b'\n', .3)
        self.assertEqual(p.state, 'FAULT')

    def test_framed_output_separates_policy_command_from_wire(self):
        from igbridge.policy import LaboratoryPolicy
        policy = LaboratoryPolicy()
        p = proxy()
        first = p.host_to_backend_frame(b'AT\r', 0)
        policy.at(first.command)
        self.assertEqual(first, ATForward(b'AT\r', b'AT\r'))
        p.backend_to_host(b'OK\r\n', .1)
        second = p.host_to_backend_frame(b'\nAT+CGMI\r\n', .2)
        policy.at(second.command)
        self.assertEqual(second, ATForward(b'\nAT+CGMI\r\n', b'AT+CGMI\r'))

    def test_suffix_plus_partial_all_two_chunk_splits(self):
        raw = b'\nAT+CGMI\r\n'
        for cut in range(len(raw) + 1):
            with self.subTest(cut=cut):
                p = proxy()
                p.host_to_backend(b'AT\r', 0)
                p.backend_to_host(b'OK\r\n', .1)
                first = p.host_to_backend_frame(raw[:cut], .2)
                second = p.host_to_backend_frame(raw[cut:], .3)
                self.assertEqual(first.wire + second.wire, raw)
                self.assertEqual([f.command for f in (first, second) if f.command is not None], [b'AT+CGMI\r'])
                self.assertEqual(p.state, 'RESPONSE_PENDING')

    def test_suffix_only_once_and_empty_chunk_does_not_consume_it(self):
        p = proxy()
        p.host_to_backend_frame(b'AT\r', 0)
        self.assertEqual(p.host_to_backend_frame(b'', .1), ATForward(b''))
        self.assertEqual(p.host_to_backend_frame(b'\n', .2), ATForward(b'\n'))
        with self.assertRaises(ProtocolError):
            p.host_to_backend_frame(b'\n', .3)

    def test_suffix_prefix_invalid_batch_has_no_forward_decision(self):
        for bad in (b'\nAT\rAT\r', b'\nAT+\n', b'\n\n', b'\nAT\x00\r'):
            with self.subTest(bad=bad):
                p = proxy()
                p.host_to_backend_frame(b'AT\r', 0)
                p.backend_to_host(b'OK\r\n', .1)
                with self.assertRaises(ProtocolError):
                    p.host_to_backend_frame(bad, .2)
                self.assertEqual(p.state, 'FAULT')

    def test_pending_suffix_plus_new_command_is_still_pipelining(self):
        p = proxy()
        p.host_to_backend_frame(b'AT\r', 0)
        with self.assertRaisesRegex(ProtocolError, 'pipelining'):
            p.host_to_backend_frame(b'\nAT+CGMI\r', .1)
        self.assertEqual(p.state, 'FAULT')

    def test_partial_prefix_lf_then_embedded_lf_is_rejected(self):
        p = proxy()
        p.host_to_backend_frame(b'AT\r', 0)
        p.backend_to_host(b'OK\r\n', .1)
        self.assertEqual(p.host_to_backend_frame(b'\nAT+', .2), ATForward(b'\n'))
        with self.assertRaises(ProtocolError):
            p.host_to_backend_frame(b'\n', .3)

    def test_disabled_identity_even_with_rules(self):
        p = proxy(identity_rules=[rule()])
        p.host_to_backend(b'AT+CGMM\r', 0)
        response = b'\r\nCandidate\r\nOK\r\n'
        self.assertEqual(p.backend_to_host(response, .1), response)

    def test_identity_atomic_every_byte_and_urc_preservation(self):
        p = proxy(identity_rules=[rule()], rewrite_enabled=True)
        p.host_to_backend(b'AT+CGMM\r', 0)
        response = b'AT+CGMM\r\r\n+CEREG: 0\r\nCandidate\r\nOK\r\n'
        got = b''.join(p.backend_to_host(bytes([x]), .1) for x in response)
        self.assertEqual(got, response.replace(b'Candidate', b'Baseline'))
        self.assertIn('urc', [e['kind'] for e in p.pop_events()])

    def test_identity_rollback_error_extra_line_and_mismatch(self):
        for response in [b'Candidate\r\nERROR\r\n', b'Candidate\r\nunknown\r\nOK\r\n', b'Other\r\nOK\r\n', b'Candidate\r\n+CME ERROR: 3\r\n']:
            with self.subTest(response=response):
                p = proxy(identity_rules=[rule()], rewrite_enabled=True)
                p.host_to_backend(b'AT+CGMM\r', 0)
                self.assertEqual(p.backend_to_host(response, .1), response)
                self.assertIn('identity_rollback', [e['kind'] for e in p.pop_events()])

    def test_identity_rollback_replacement_response_bound(self):
        r = IdentityRule(b'AT+CGMM', b'A', b'B' * 12, 'SYNTHETIC')
        p = proxy(identity_rules=[r], rewrite_enabled=True, max_line=12, max_response=16)
        p.host_to_backend(b'AT+CGMM\r', 0)
        response = b'A\r\n\r\nOK\r\n'
        self.assertEqual(p.backend_to_host(response, .1), response)

    def test_partial_identity_timeout_does_not_emit_or_reuse(self):
        p = proxy(identity_rules=[rule()], rewrite_enabled=True)
        p.host_to_backend(b'AT+CGMM\r', 0)
        self.assertEqual(p.backend_to_host(b'Candidate\r\n', .5), b'')
        self.assertTrue(p.expire(3))
        with self.assertRaises(ProtocolError): p.backend_to_host(b'OK\r', 3.1)
        with self.assertRaises(ProtocolError): p.open()
        p.close(); p.open()
        self.assertEqual(p.backend_to_host(b'OK\r', 4), b'OK\r')

    def test_identity_disallows_imei_sim_ati_and_newline(self):
        for cmd in [b'ATI', b'AT+CGSN', b'AT+CCID', b'AT+CGMM=1']:
            with self.assertRaises(ConfigurationError): IdentityRule(cmd, b'x', b'y', 'SYNTHETIC')
        for val in [b'', b'a\r\nOK', b'\xff']:
            with self.assertRaises(ConfigurationError): IdentityRule(b'AT+CGMM', val, b'x', 'SYNTHETIC')
        with self.assertRaises(ConfigurationError): IdentityRule(b'AT+CGMM', b'x', b'y', '')

    def test_unsolicited_idle_bytes_exact_no_pending(self):
        p = proxy()
        raw = b'\r\nRING\r\n+CREG: 1\nunknown\x80\r'
        self.assertEqual(p.backend_to_host(raw, 0), raw)
        self.assertEqual(p.state, 'IDLE')

    def test_pipelined_batch_not_partially_forwarded(self):
        p = proxy()
        with self.assertRaises(ProtocolError): p.host_to_backend(b'AT\rAT+CGMI\r', 0)
        self.assertEqual(p.state, 'FAULT')

    def test_pending_command_rejects_second(self):
        p = proxy(); p.host_to_backend(b'AT\r', 0)
        with self.assertRaises(ProtocolError): p.host_to_backend(b'AT\r', .1)

    def test_partial_command_timeout_and_line_limit(self):
        p = proxy(max_line=5)
        self.assertEqual(p.host_to_backend(b'AT+', 0), b'')
        self.assertTrue(p.expire(3))
        p.close(); p.open()
        with self.assertRaises(ProtocolError): p.host_to_backend(b'AT123456\r', 4)

    def test_response_bounds_connect_and_time_regression(self):
        for data in [b'123456', b'CONNECT\r']:
            p = proxy(max_line=5)
            with self.assertRaises(ProtocolError): p.backend_to_host(data, 0)
        p = proxy(); p.backend_to_host(b'R', 2)
        with self.assertRaises(ProtocolError): p.backend_to_host(b'ING\r', 1)

    def test_response_budget_and_metadata_bound(self):
        p = proxy(max_line=8, max_response=10)
        p.host_to_backend(b'AT\r', 0)
        p.backend_to_host(b'1234\r1234\r', .1)
        with self.assertRaises(ProtocolError): p.backend_to_host(b'X', .2)
        p = proxy(max_events=3)
        p.backend_to_host(b'RING\r' * 9, 0)
        events = p.pop_events()
        self.assertLessEqual(len(events), 4)
        self.assertEqual(events[-1]['kind'], 'metadata_overflow')
        self.assertNotIn('RING', repr(events))

    def test_solicited_registration_line_not_marked_urc(self):
        p = proxy(); p.host_to_backend(b'AT+CEREG?\r', 0)
        p.backend_to_host(b'+CEREG: 0\r\nOK\r\n', .1)
        self.assertNotIn('urc', [e['kind'] for e in p.pop_events()])

    def test_data_mode_and_private_response_metadata(self):
        p = proxy(); p.host_to_backend(b'AT\r', 0)
        with self.assertRaisesRegex(ProtocolError, 'data mode'): p.backend_to_host(b'CONNECT\r', .1)
        p.close(); p.open(); p.host_to_backend(b'ATI\r', 0)
        raw = b'SYNTHETIC_PRIVATE_IDENTIFIER\r\nOK\r\n'
        self.assertEqual(p.backend_to_host(raw, .1), raw)
        self.assertNotIn('SYNTHETIC_PRIVATE_IDENTIFIER', repr(p.pop_events()))

    def test_closed_session_rejects_and_configuration(self):
        with self.assertRaises(ProtocolError): ATProxy().host_to_backend(b'AT\r', 0)
        for kwargs in [{'timeout': float('nan')}, {'max_line': 0}, {'identity_rules': [rule(), rule()]}, {'rewrite_enabled': 1}]:
            with self.assertRaises(ConfigurationError): ATProxy(**kwargs)


if __name__ == '__main__': unittest.main()
