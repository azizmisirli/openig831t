# SPDX-License-Identifier: Apache-2.0
"""Explicit host/local/physical/backend address spaces, with full direction bits."""
from dataclasses import dataclass
from .errors import ConfigurationError, PolicyDenied


def _byte(value: int, endpoint: bool = False) -> None:
    if type(value) is not int or not 0 <= value <= 255:
        raise ConfigurationError("invalid address")
    if endpoint and (value & 0x70 or not value & 15):
        raise ConfigurationError("invalid non-control endpoint")


@dataclass(frozen=True)
class InterfaceBinding:
    host: int
    local: int
    backend: int | None = None


@dataclass(frozen=True)
class EndpointBinding:
    host: int
    local: int
    physical: int | None = None
    backend: int | None = None


class AddressMap:
    def __init__(self, interfaces, endpoints):
        self.interfaces = tuple(interfaces)
        self.endpoints = tuple(endpoints)
        for records, endpoint in ((self.interfaces, False), (self.endpoints, True)):
            for row in records:
                _byte(row.host, endpoint)
                _byte(row.local, endpoint)
                for space in ("host", "local", "backend") + (("physical",) if endpoint else ()):
                    value = getattr(row, space)
                    if value is not None:
                        _byte(value, endpoint)
                        if endpoint and value & 0x80 != row.host & 0x80:
                            raise ConfigurationError("endpoint direction must be preserved")
            for space in ("host", "local", "backend") + (("physical",) if endpoint else ()):
                values = [getattr(row, space) for row in records if getattr(row, space) is not None]
                if len(values) != len(set(values)):
                    raise ConfigurationError("ambiguous address mapping")

    def translate(self, value: int, *, recipient: str, source: str, destination: str) -> int:
        if recipient not in ("interface", "endpoint"):
            raise PolicyDenied("only explicit interface/endpoint mapping supported")
        spaces = ("host", "local", "backend") + (("physical",) if recipient == "endpoint" else ())
        if source not in spaces or destination not in spaces:
            raise ConfigurationError("unknown address space")
        _byte(value, recipient == "endpoint")
        rows = self.interfaces if recipient == "interface" else self.endpoints
        for row in rows:
            if getattr(row, source) == value:
                result = getattr(row, destination)
                if result is None:
                    raise PolicyDenied("backend/physical resource is unbound")
                return result
        raise PolicyDenied("unmapped address")

    def setup_to_backend(self, bm_request_type: int, w_index: int, *, source: str = "local") -> int:
        _byte(bm_request_type)
        if type(w_index) is not int or not 0 <= w_index <= 255:
            raise PolicyDenied("nonzero index high byte requires request-specific handling")
        recipient = {1: "interface", 2: "endpoint"}.get(bm_request_type & 31)
        if recipient is None:
            raise PolicyDenied("device/other recipient must not be blindly forwarded")
        return self.translate(w_index, recipient=recipient, source=source, destination="backend")

    def notification_interface(self, backend_interface: int) -> int:
        return self.translate(backend_interface, recipient="interface", source="backend", destination="host")

    def verify_exact_binding(self, actual_endpoints: dict[int, int], actual_interfaces: dict[int, int]) -> None:
        """Check explicit observed local->host addresses. No ioctl/read is performed.

        Caller must obtain these from the bound gadget, and additionally verify type,
        maxpacket and successful endpoint enable before claiming a measured clone.
        """
        for observed, endpoint in ((actual_interfaces, False), (actual_endpoints, True)):
            for key, value in observed.items():
                _byte(key, endpoint)
                _byte(value, endpoint)
        if actual_interfaces != {r.local: r.host for r in self.interfaces}:
            raise ConfigurationError("actual interface assignment is not exact")
        if actual_endpoints != {r.local: r.host for r in self.endpoints}:
            raise ConfigurationError("actual endpoint assignment is not exact")
        if any(r.physical is not None and r.physical != r.host for r in self.endpoints):
            raise ConfigurationError("declared physical resource differs from exact host address")

    def physical_low_nibble_collisions(self) -> tuple[int, ...]:
        """Linux v6.12 FFS eps_revmap uses the number without direction."""
        seen = set()
        collisions = set()
        for row in self.endpoints:
            if row.physical is not None:
                number = row.physical & 15
                if number in seen:
                    collisions.add(number)
                seen.add(number)
        return tuple(sorted(collisions))
