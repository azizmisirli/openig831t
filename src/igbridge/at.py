# SPDX-License-Identifier: Apache-2.0
"""Bounded bytes-only AT proxy. This module never opens a port or sends a command.

The coordinator must authorize each completed host command before transmitting it.
No command is synthesized. Timeout/fault requires an explicit close/open lifecycle.
"""
from collections import deque
from dataclasses import dataclass
import math
import re

from .errors import ConfigurationError, ProtocolError


@dataclass(frozen=True)
class IdentityRule:
    """Explicit evidence-gated exact response substitution; not evidence verification."""
    command: bytes
    expected: bytes
    replacement: bytes
    evidence_ref: str

    def __post_init__(self):
        if self.command not in (b'AT+CGMI', b'AT+CGMM', b'AT+CGMR'):
            raise ConfigurationError('identity command outside manufacturer/model/revision allowlist')
        if not isinstance(self.evidence_ref, str) or not self.evidence_ref.strip():
            raise ConfigurationError('identity evidence reference required')
        for value in (self.expected, self.replacement):
            if not isinstance(value, bytes) or not value or len(value) > 4096 or any(c < 32 or c > 126 for c in value):
                raise ConfigurationError('identity must be one bounded printable ASCII line')


@dataclass(frozen=True)
class ATForward:
    """One atomic forwarding decision, separating command policy from framing.

    ``command`` is exactly the newly completed body plus CR, or None. ``wire``
    preserves actual stream bytes, including a previous command's optional LF
    suffix and this command's CRLF ending. Before writing any wire bytes, the
    coordinator must authorize command when present. A denial requires closing
    the channel/proxy; no emitted decision may be reused after denial.
    """
    wire: bytes
    command: bytes | None = None


class ATProxy:
    """One in-flight command, CR/LF chunk framing, transparent responses by default.

    Host chunks are buffered until a CR terminator; emitted bytes are unchanged.
    Use host_to_backend_frame for policy integration; host_to_backend is the
    legacy bytes-only wrapper. Framing-only LF is tied to the immediately next
    host stream byte after an accepted CR, independently of USB chunk boundaries.
    Pipelining and data-mode CONNECT are deliberately unsupported. Identity-enabled
    responses are held until a final result, allowing byte-exact rollback on error
    or ambiguous extra lines. Unsolicited text stays byte-exact, including endings.
    """
    def __init__(self, *, timeout=3.0, max_line=4096, max_response=65536,
                 max_events=128, urc_prefixes=(b'+CEREG:', b'+CREG:', b'+CGREG:', b'+CMTI:'),
                 identity_rules=(), rewrite_enabled=False):
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ConfigurationError('positive finite AT timeout required')
        if any(type(v) is not int or v <= 0 for v in (max_line, max_response, max_events)) or max_line > max_response:
            raise ConfigurationError('invalid AT bounds')
        if type(rewrite_enabled) is not bool:
            raise ConfigurationError('rewrite_enabled must be bool')
        rules = tuple(identity_rules)
        if any(not isinstance(r, IdentityRule) for r in rules) or len({r.command for r in rules}) != len(rules):
            raise ConfigurationError('invalid or duplicate identity rules')
        if any(max(len(r.expected), len(r.replacement)) > max_line for r in rules):
            raise ConfigurationError('identity rule exceeds line bound')
        if any(not isinstance(v, bytes) or not v for v in urc_prefixes):
            raise ConfigurationError('URC prefixes must be nonempty bytes')
        self.timeout, self.max_line, self.max_response = timeout, max_line, max_response
        self.rules = {r.command: r for r in rules} if rewrite_enabled else {}
        self.urc_prefixes = tuple(urc_prefixes)
        self._events = deque(maxlen=max_events)
        self._lost_events = 0
        self._state = 'CLOSED'
        self._reset()

    def _reset(self):
        self._host = bytearray()
        self._line = bytearray()
        self._held = None
        self._command = None
        self._rule = None
        self._deadline = None
        self._last_time = None
        self._response_size = 0
        self._allow_lf = False

    @property
    def state(self):
        return self._state

    def _event(self, kind, **metadata):
        if len(self._events) == self._events.maxlen:
            self._lost_events += 1
        self._events.append({'kind': kind, **metadata})

    def pop_events(self):
        items = list(self._events)
        self._events.clear()
        if self._lost_events:
            items.append({'kind': 'metadata_overflow', 'count': self._lost_events})
            self._lost_events = 0
        return items

    def open(self):
        if self._state != 'CLOSED':
            raise ProtocolError('close before opening AT session')
        self._reset()
        self._state = 'IDLE'
        self._event('opened')

    def close(self):
        discarded = len(self._host) + len(self._line) + len(self._held or b'')
        self._reset()
        self._state = 'CLOSED'
        self._event('closed', buffered_bytes_discarded=discarded)

    def _fault(self, reason):
        self._reset()
        self._state = 'FAULT'
        self._event('fault', reason=reason)
        raise ProtocolError(reason)

    def _clock(self, now):
        if self._state in ('CLOSED', 'FAULT'):
            raise ProtocolError('AT session not open')
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0 or (self._last_time is not None and now < self._last_time):
            self._fault('invalid monotonic time')
        self._last_time = now

    def expire(self, now):
        self._clock(now)
        if self._deadline is not None and now >= self._deadline:
            self._reset()
            self._state = 'FAULT'
            self._event('timeout')
            return True
        return False

    def _ready(self, chunk, now):
        if not isinstance(chunk, bytes):
            raise ProtocolError('AT input must be bytes')
        if self.expire(now):
            raise ProtocolError('AT transaction expired')
        if len(chunk) > self.max_response:
            self._fault('AT chunk bound exceeded')

    def host_to_backend(self, chunk, now):
        """Legacy bytes-only API; coordinators should use the framed API below."""
        return self.host_to_backend_frame(chunk, now).wire

    def host_to_backend_frame(self, chunk, now):
        self._ready(chunk, now)
        if not chunk:
            return ATForward(b'')
        prefix = b''
        if self._allow_lf:
            # The allowance applies to exactly the next host stream byte. Any
            # other byte consumes it, even when a new command is still partial.
            self._allow_lf = False
            if chunk.startswith(b'\n'):
                prefix, chunk = b'\n', chunk[1:]
                if not chunk:
                    return ATForward(prefix)
        if self._command is not None:
            self._fault('AT pipelining unsupported')
        data = bytes(self._host) + chunk
        if len(data) > self.max_line + 2:
            self._fault('AT command line bound exceeded')
        if b'\r' not in data:
            if any(c < 32 or c > 126 for c in data):
                self._fault('unsupported command character or terminator')
            self._host[:] = data
            if self._deadline is None:
                self._deadline = now + self.timeout
            self._state = 'COMMAND_PARTIAL'
            return ATForward(prefix)
        body, rest = data.split(b'\r', 1)
        if rest not in (b'', b'\n') or not body.upper().startswith(b'AT') or any(c < 32 or c > 126 for c in body) or len(body) > self.max_line:
            self._fault('invalid or multiple AT commands')
        self._host.clear()
        self._command = body
        self._rule = self.rules.get(body.upper())
        self._held = bytearray() if self._rule else None
        self._allow_lf = not rest
        if self._deadline is None:
            self._deadline = now + self.timeout
        self._state = 'RESPONSE_PENDING'
        self._response_size = 0
        self._event('command', length=len(data), rewrite_candidate=self._rule is not None)
        return ATForward(prefix + data, body + b'\r')

    def _urc(self, line):
        # These prefixes can also be solicited query replies; do not label those URCs.
        solicited = {b'AT+CREG?': b'+CREG:', b'AT+CGREG?': b'+CGREG:',
                     b'AT+CEREG?': b'+CEREG:'}.get((self._command or b'').upper())
        if solicited is not None and line.startswith(solicited):
            return False
        return line == b'RING' or any(line.startswith(p) for p in self.urc_prefixes)

    def _rewrite(self, raw, success):
        rule = self._rule
        spans = list(re.finditer(rb'[^\r\n]+', raw))
        payload = [m for m in spans if m.group() not in (self._command, b'OK') and not self._urc(m.group())]
        if success and len(payload) == 1 and payload[0].group() == rule.expected:
            m = payload[0]
            replaced = raw[:m.start()] + rule.replacement + raw[m.end():]
            if len(replaced) > self.max_response:
                self._event('identity_rollback', reason='replacement bound')
                return raw
            self._event('identity_rewritten', field_command=rule.command.decode('ascii'))
            return replaced
        self._event('identity_rollback', reason='error or ambiguous response')
        return raw

    def backend_to_host(self, chunk, now):
        self._ready(chunk, now)
        output = bytearray()
        for c in chunk:
            if self._command is not None:
                self._response_size += 1
                if self._response_size > self.max_response:
                    self._fault('AT response bound exceeded')
            if self._held is not None:
                self._held.append(c)
            else:
                output.append(c)
            if c not in (10, 13):
                self._line.append(c)
                if len(self._line) > self.max_line:
                    self._fault('AT response line bound exceeded')
                continue
            line = bytes(self._line)
            self._line.clear()
            if not line:
                continue
            if line == b'CONNECT' or line.startswith(b'CONNECT '):
                self._fault('AT data mode unsupported')
            echo = self._command is not None and line == self._command
            final = line in (b'OK', b'ERROR', b'NO CARRIER', b'NO ANSWER', b'BUSY', b'NO DIALTONE') or line.startswith((b'+CME ERROR:', b'+CMS ERROR:'))
            kind = 'echo' if echo else ('urc' if self._urc(line) else ('final' if final and self._command is not None else 'line'))
            self._event(kind, length=len(line), pending=self._command is not None)
            if final and self._command is not None:
                if self._held is not None:
                    output.extend(self._rewrite(bytes(self._held), line == b'OK'))
                self._held = None
                self._command = self._rule = self._deadline = None
                self._response_size = 0
                self._state = 'IDLE'
        return bytes(output)
