# SPDX-License-Identifier: Apache-2.0
"""Shared fail-closed protocol and configuration errors."""

class BridgeError(Exception):
    pass


class ProtocolError(BridgeError, ValueError):
    pass


class ConfigurationError(BridgeError, ValueError):
    pass


class PolicyDenied(BridgeError):
    pass
