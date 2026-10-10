# SPDX-License-Identifier: Apache-2.0
"""Explicit laboratory query policy. This is not a full operational modem policy.

IDs follow the archived libqmi schemas in the public references documented in docs/references.md.
No name-prefix heuristic, unknown request forwarding, or WDS Start Network.
"""
from .errors import PolicyDenied

NO_INPUT_QUERIES = {
    0: {0x21},
    # WDS Get Packet Service Status; Start/Stop Network remain forbidden.
    1: {0x22},
    2: {0x20, 0x21, 0x22, 0x23, 0x2c, 0x2d, 0x45},
    3: {0x24, 0x31, 0x4d, 0x4f},
    0x1a: {0x21},
    0x0b: {0x2f, 0x47},
}
READONLY_AT = frozenset((b'AT', b'ATI', b'AT+CGMI', b'AT+CGMM', b'AT+CGMR'))


class LaboratoryPolicy:
    def __init__(self, allow_transient_clients=True, allow_dtr=True):
        self.allow_transient_clients = allow_transient_clients
        self.allow_dtr = allow_dtr

    def qmi(self, message):
        if message.kind != 'request':
            raise PolicyDenied('host may submit requests only')
        if message.message_id in NO_INPUT_QUERIES.get(message.service, set()):
            if message.tlvs:
                raise PolicyDenied('query variant with input TLVs not authorized')
            return
        if self.allow_transient_clients and message.service == 0:
            if message.message_id in (0x22, 0x23):
                n = 1 if message.message_id == 0x22 else 2
                if (len(message.tlvs) == 1 and message.tlvs[0].type == 1
                        and len(message.tlvs[0].value) == n
                        and message.tlvs[0].value[0] in NO_INPUT_QUERIES
                        and message.tlvs[0].value[0] != 0):
                    if n == 2 and message.tlvs[0].value[1] in (0, 255):
                        raise PolicyDenied('invalid release client')
                    return
        raise PolicyDenied('QMI request not in documented laboratory allowlist')

    def at(self, command):
        # Entire command must be validated before any chunk is forwarded.
        if not command.endswith(b'\r') or command[:-1] not in READONLY_AT:
            raise PolicyDenied('only complete exact read-only AT commands accepted')

    def dtr(self, value):
        if not self.allow_dtr or value not in (0, 1):
            raise PolicyDenied('DTR/RTS state not permitted')

    def data(self, payload):
        raise PolicyDenied('active packet data disabled pending separate authorization')
