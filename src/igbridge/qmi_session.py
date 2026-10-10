# SPDX-License-Identifier: Apache-2.0
"""Bounded single-host QMI session bookkeeping, with no transport side effects.

Policy, DTR, EP0 and interrupt I/O belong to the coordinator. Timeouts never
retry or generate protocol messages. Disconnect returns cleanup *metadata*,
not proof that any backend client was released. Reconnect requires an explicit
transport-flushed assertion; old traffic must not enter the new generation.
"""
from collections import deque
from dataclasses import dataclass
import math
import time

from .errors import ConfigurationError, ProtocolError
from .qmi import (CTL, CTL_ALLOCATE_CID, CTL_RELEASE_CID, CTL_GET_VERSION,
                  CTL_SYNC, QmiMessage, TLV, build_message, parse_message, result_code, match_response)


def _positive(value, name):
    if type(value) is not int or value <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")
    return value


def _key(message):
    return message.service, message.cid, message.transaction_id


@dataclass(frozen=True)
class ClientBinding:
    service: int
    host_cid: int
    backend_cid: int


@dataclass(frozen=True)
class _CleanupReservation:
    request: bytes
    binding: ClientBinding
    generation: int


@dataclass(frozen=True)
class Pending:
    host: QmiMessage
    backend: QmiMessage
    deadline: float
    action: str | None = None
    target_service: int | None = None
    target_host_cid: int | None = None
    target_backend_cid: int | None = None


class QmiSession:
    """Stateful passthrough by default; opt-in header/CTL allocation remapping.

    One owner/event-loop only (not thread-safe). All frames must be complete.
    Live request authorization is deliberately a separate coordinator policy.
    In remap mode opaque CTL operations are rejected because they may embed CIDs.
    Normal service payloads remain byte-exact, including opaque/unknown TLVs.
    """
    def __init__(self, *, mode="passthrough", max_pending=64, max_clients=64,
                 timeout=10.0, max_quarantined=4096, clock=time.monotonic):
        if mode not in ("passthrough", "remap"):
            raise ConfigurationError("mode must be passthrough or remap")
        self.mode = mode
        self.max_pending = _positive(max_pending, "max_pending")
        self.max_clients = _positive(max_clients, "max_clients")
        self.max_quarantined = _positive(max_quarantined, "max_quarantined")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ConfigurationError("timeout must be finite and positive")
        if not callable(clock):
            raise ConfigurationError("clock must be callable")
        self.timeout, self.clock = float(timeout), clock
        self.connected = True
        self.generation = 0
        self._pending = {}
        self._clients = {}
        self._uncertain_releases = set()
        self._quarantined = set()
        self._next_tid = {}
        self._cleanup_planned = set()
        self._cleanup_reserved = {}
        # A local cleanup plan may outlive a transport generation in caller
        # memory. Never reinterpret its host TID as a fresh release, even after
        # reconnect. Bounded by the 255 nonzero CTL host IDs; exhaustion stops
        # planning rather than recycling a stale ownership operation.
        self._cleanup_retired = set()
        self._last_now = None
        self._timeouts = deque(maxlen=max_pending)
        self.timeout_count = 0
        self.allocation_outcome_unknown = 0
        self.quarantine_exhausted = False
        self.sync_invalidated = False

    @property
    def clients(self) -> tuple[ClientBinding, ...]:
        return tuple(self._clients.values())

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def timeout_events(self) -> tuple[dict, ...]:
        return tuple(dict(event) for event in self._timeouts)

    def _now(self, now):
        value = self.clock() if now is None else now
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ProtocolError("time must be a finite monotonic value")
        value = float(value)
        if self._last_now is not None and value < self._last_now:
            raise ProtocolError("monotonic clock moved backwards")
        self._last_now = value
        return value

    def expire(self, now=None) -> list[dict]:
        current = self._now(now)
        events = []
        for key, pending in tuple(self._pending.items()):
            if current >= pending.deadline:
                del self._pending[key]
                if len(self._quarantined) < self.max_quarantined:
                    self._quarantined.add(key)
                else:
                    # No potentially ambiguous traffic may proceed after a
                    # bounded quarantine fills. No unbounded tombstone growth.
                    self.quarantine_exhausted = True
                if pending.action == "allocate":
                    self.allocation_outcome_unknown += 1
                if pending.action == "release":
                    self._uncertain_releases.add((pending.target_service, pending.target_host_cid))
                event = {"generation": self.generation, "service": pending.host.service,
                         "host_cid": pending.host.cid, "host_tid": pending.host.transaction_id,
                         "message_id": pending.host.message_id, "action": pending.action,
                         "deadline": pending.deadline, "expired_at": current,
                         "backend_allocation_unknown": pending.action == "allocate"}
                self._timeouts.append(event)
                events.append(event)
                self.timeout_count += 1
        return events

    def _ready(self, now):
        if not self.connected:
            raise ProtocolError("session disconnected")
        self.expire(now)
        if self.sync_invalidated:
            raise ProtocolError("mid-session Sync invalidated CID/transaction state; flushed reconnect required")
        if self.quarantine_exhausted:
            raise ProtocolError("timeout quarantine exhausted; explicit flushed reconnect required")
        return self._last_now

    def _binding(self, service, host_cid):
        binding = self._clients.get((service, host_cid))
        if binding is None:
            raise ProtocolError("unknown client; allocate CID first")
        if (service, host_cid) in self._uncertain_releases:
            raise ProtocolError("release outcome unknown; client cannot be reused")
        if any(p.action == "release" and (p.target_service, p.target_host_cid) == (service, host_cid)
               for p in self._pending.values()):
            raise ProtocolError("client release in flight")
        return binding

    def _tid(self, service, cid, requested):
        if self.mode == "passthrough":
            if (service, cid, requested) in self._pending or (service, cid, requested) in self._quarantined:
                raise ProtocolError("transaction in use or quarantined")
            return requested
        limit = 255 if service == CTL else 65535
        scope = (service, cid)
        candidate = self._next_tid.get(scope, 1)
        for _ in range(limit):
            if (*scope, candidate) not in self._pending and (*scope, candidate) not in self._quarantined:
                self._next_tid[scope] = 1 if candidate == limit else candidate + 1
                return candidate
            candidate = 1 if candidate == limit else candidate + 1
        raise ProtocolError("transaction ID space exhausted")

    def host_to_backend(self, data: bytes, now=None) -> bytes:
        current = self._ready(now)
        host = parse_message(data)
        if host.kind != "request" or host.transaction_id == 0:
            raise ProtocolError("host must send a request with nonzero transaction ID")
        if len(self._pending) >= self.max_pending:
            raise ProtocolError("pending request capacity reached")
        if any(_key(p.host) == _key(host) for p in self._pending.values()):
            raise ProtocolError("host transaction already in flight")
        reserved = self._cleanup_reserved.get(host.transaction_id) if host.service == CTL else None
        if host.service == CTL and host.transaction_id in self._cleanup_retired:
            raise ProtocolError("retired cleanup transaction cannot be reused")
        if reserved is not None:
            if reserved.request != host.to_bytes():
                raise ProtocolError("CTL transaction reserved for cleanup")
            owner_key = (reserved.binding.service, reserved.binding.host_cid)
            if (reserved.generation != self.generation or
                    self._clients.get(owner_key) is not reserved.binding):
                del self._cleanup_reserved[host.transaction_id]
                self._cleanup_retired.add(host.transaction_id)
                raise ProtocolError("cleanup plan no longer owns this client")
        if reserved is None and len(self._pending) + len(self._cleanup_reserved) >= self.max_pending:
            raise ProtocolError("pending plus cleanup reservations capacity reached")
        action, service, host_cid, backend_cid = None, None, None, None
        backend = host
        if host.service == CTL:
            if self.mode == "remap" and host.message_id not in (CTL_GET_VERSION, CTL_ALLOCATE_CID, CTL_RELEASE_CID, CTL_SYNC):
                raise ProtocolError("opaque CTL command cannot be safely remapped")
            if host.message_id == CTL_ALLOCATE_CID:
                info = host.tlv(1)
                if len(info) != 1 or info[0] == CTL:
                    raise ProtocolError("invalid Allocate CID service")
                reservations = sum(p.action == "allocate" for p in self._pending.values())
                if len(self._clients) + reservations >= self.max_clients:
                    raise ProtocolError("client capacity reached")
                service_count = sum(b.service == info[0] for b in self._clients.values())
                service_reserved = sum(p.action == "allocate" and p.target_service == info[0]
                                       for p in self._pending.values())
                if service_count + service_reserved >= 254:
                    raise ProtocolError("service host CID space exhausted")
                action, service = "allocate", info[0]
            elif host.message_id == CTL_RELEASE_CID:
                info = host.tlv(1)
                if len(info) != 2 or info[0] == CTL:
                    raise ProtocolError("invalid Release CID info")
                service, host_cid = info
                binding = self._binding(service, host_cid)
                backend_cid = binding.backend_cid
                if any((p.host.service, p.host.cid) == (service, host_cid) for p in self._pending.values()):
                    raise ProtocolError("cannot release a client with requests in flight")
                action = "release"
                backend = backend.replace_tlv(1, bytes((service, backend_cid)))
        else:
            binding = self._binding(host.service, host.cid)
            backend = host.with_ids(cid=binding.backend_cid)
        backend = backend.with_ids(transaction_id=self._tid(backend.service, backend.cid, host.transaction_id))
        encoded = backend.to_bytes()
        if reserved is not None:
            del self._cleanup_reserved[host.transaction_id]
            self._cleanup_retired.add(host.transaction_id)
        self._pending[_key(backend)] = Pending(host, backend, current + self.timeout,
                                              action, service, host_cid, backend_cid)
        return encoded

    def backend_to_host(self, data: bytes, now=None) -> bytes:
        self._ready(now)
        backend = parse_message(data)
        if backend.kind == "indication":
            if backend.service == CTL:
                if self.mode == "remap" and backend.message_id != CTL_SYNC:
                    raise ProtocolError("opaque CTL indication may contain unmapped CIDs")
                if backend.message_id == CTL_SYNC and (self._clients or self._pending):
                    # uqmi treats Sync as possible modem deallocation of all CIDs.
                    # Preserve obligations for the coordinator; never reuse this
                    # epoch or automatically send releases for uncertain clients.
                    self.sync_invalidated = True
                return bytes(data)  # Sync is an indication, never a request response.
            if backend.cid == 255:
                if not any(b.service == backend.service for b in self._clients.values()):
                    raise ProtocolError("broadcast for a service with no owned clients")
                return bytes(data)  # QMUX broadcast remains broadcast; no fan-out.
            bindings = [b for b in self._clients.values()
                        if (b.service, b.backend_cid) == (backend.service, backend.cid)]
            if len(bindings) != 1:
                raise ProtocolError("indication for unknown backend CID")
            return backend.with_ids(cid=bindings[0].host_cid).to_bytes()
        if backend.kind != "response":
            raise ProtocolError("backend must send a response or indication")
        pending = self._pending.get(_key(backend))
        if pending is None or not match_response(pending.backend, backend):
            raise ProtocolError("unmatched response (service/CID/TID/message ID)")
        host = backend.with_ids(cid=pending.host.cid, transaction_id=pending.host.transaction_id)
        add_binding, remove_binding = None, None
        if pending.action in ("allocate", "release"):
            success = result_code(backend) == (0, 0)
            if success:
                info = backend.tlv(1)
                if len(info) != 2 or info[0] != pending.target_service or info[1] in (0, 255):
                    raise ProtocolError("invalid lifecycle response service/CID")
                service, backend_cid = info
                if pending.action == "allocate":
                    if any((b.service, b.backend_cid) == (service, backend_cid) for b in self._clients.values()):
                        raise ProtocolError("backend reallocated a live CID")
                    if self.mode == "passthrough":
                        host_cid = backend_cid
                    else:
                        host_cid = next((c for c in range(1, 255) if (service, c) not in self._clients), None)
                        if host_cid is None:
                            raise ProtocolError("host CID space exhausted")
                    add_binding = ClientBinding(service, host_cid, backend_cid)
                    host = host.replace_tlv(1, bytes((service, host_cid)))
                else:
                    if backend_cid != pending.target_backend_cid:
                        raise ProtocolError("Release CID response does not match owned CID")
                    host = host.replace_tlv(1, bytes((service, pending.target_host_cid)))
                    remove_binding = (service, pending.target_host_cid)
        encoded = host.to_bytes()  # Finish validation/encoding before committing.
        if add_binding is not None:
            self._clients[(add_binding.service, add_binding.host_cid)] = add_binding
        if remove_binding is not None:
            released_owner = self._clients[remove_binding]
            # A manually issued Release may race a queued, unsent cleanup plan.
            # Retire the plan before the host CID can be allocated to a new owner.
            for tid, reservation in tuple(self._cleanup_reserved.items()):
                if reservation.binding is released_owner:
                    del self._cleanup_reserved[tid]
                    self._cleanup_retired.add(tid)
            del self._clients[remove_binding]
            self._cleanup_planned.discard(remove_binding)
        del self._pending[_key(backend)]
        return encoded

    def cleanup_requests(self, now=None) -> tuple[bytes, ...]:
        """Plan bounded one-shot releases; coordinator must send and await replies.

        Returned bytes are *host-facing* requests for host_to_backend(), not raw
        backend requests. No I/O occurs. Skip in-flight/uncertain releases and
        clients with in-flight queries; obligations remain in disconnect metadata.
        Planned requests reserve CTL IDs and queue capacity, and are never
        automatically reissued. Calling this after a bounded drain can plan other
        clients. A new allocation of a successfully released CID is a new owner.
        """
        self._ready(now)
        candidates = []
        for key, binding in self._clients.items():
            if key in self._cleanup_planned or key in self._uncertain_releases:
                continue
            if any((p.host.service, p.host.cid) == key or
                   (p.action == "release" and (p.target_service, p.target_host_cid) == key)
                   for p in self._pending.values()):
                continue
            candidates.append(binding)
        available = self.max_pending - len(self._pending) - len(self._cleanup_reserved)
        used = {p.host.transaction_id for p in self._pending.values() if p.host.service == CTL}
        used.update(self._cleanup_reserved)
        used.update(self._cleanup_retired)
        if self.mode == "passthrough":
            used.update(tid for service, cid, tid in self._quarantined if service == CTL)
        planned = []
        for binding in candidates[:max(0, available)]:
            tid = next((tid for tid in range(255, 0, -1) if tid not in used), None)
            if tid is None:
                break  # Remaining known allocations are still reported.
            used.add(tid)
            raw = build_message(CTL, 0, tid, CTL_RELEASE_CID,
                                tlvs=(TLV(1, bytes((binding.service, binding.host_cid))),))
            planned.append((binding, tid, raw))
        for binding, tid, raw in planned:
            self._cleanup_reserved[tid] = _CleanupReservation(raw, binding, self.generation)
            self._cleanup_planned.add((binding.service, binding.host_cid))
        return tuple(raw for _, _, raw in planned)

    def disconnect(self) -> dict:
        """Forget local routing, report actual known allocations; send nothing."""
        cleanup = {"generation": self.generation,
                   "known_backend_clients": [
                       {"service": b.service, "backend_cid": b.backend_cid,
                        "host_cid": b.host_cid,
                        "release_outcome_unknown": (b.service, b.host_cid) in self._uncertain_releases or
                            any(p.action == "release" and (p.target_service, p.target_host_cid) ==
                                (b.service, b.host_cid) for p in self._pending.values())}
                       for b in self._clients.values()],
                   "unresolved_allocation_requests": self.allocation_outcome_unknown +
                       sum(p.action == "allocate" for p in self._pending.values()),
                   "unresolved_release_requests": sum(p.action == "release" for p in self._pending.values()),
                   "abandoned_requests": len(self._pending),
                   "planned_unsent_cleanup_requests": len(self._cleanup_reserved),
                   "backend_cleanup_performed": False,
                   "sync_invalidated": self.sync_invalidated}
        self.connected = False
        self._pending.clear()
        self._clients.clear()
        self._uncertain_releases.clear()
        self._cleanup_retired.update(self._cleanup_reserved)
        self._cleanup_reserved.clear()
        self._cleanup_planned.clear()
        return cleanup

    def reconnect(self, *, transport_flushed=False):
        if self.connected:
            raise ProtocolError("disconnect before reconnect")
        if transport_flushed is not True:
            raise ProtocolError("explicit transport flush/reset assertion required")
        self._quarantined.clear()
        self._next_tid.clear()
        self._timeouts.clear()
        self.timeout_count = self.allocation_outcome_unknown = 0
        self.quarantine_exhausted = False
        self.sync_invalidated = False
        self._last_now = None
        self.generation += 1
        self.connected = True


class ResponseQueue:
    """Bounded complete-frame queue. Metadata is not a transmitted notification."""
    def __init__(self, *, max_messages=64, max_bytes=262144):
        self.max_messages = _positive(max_messages, "max_messages")
        self.max_bytes = _positive(max_bytes, "max_bytes")
        self._queue = deque()
        self.byte_count = 0
        self.generation = 0

    def enqueue(self, data: bytes):
        message = parse_message(data)
        if message.kind == "request":
            raise ProtocolError("host response queue cannot contain a request")
        raw = message.to_bytes()
        if len(self._queue) >= self.max_messages or self.byte_count + len(raw) > self.max_bytes:
            raise ProtocolError("response queue capacity reached")
        self._queue.append(raw)
        self.byte_count += len(raw)

    def pop(self, capacity: int) -> bytes:
        if type(capacity) is not int or capacity < 0:
            raise ProtocolError("GET capacity must be nonnegative integer")
        if not self._queue:
            return b""
        if len(self._queue[0]) > capacity:
            raise ProtocolError("GET capacity would truncate a QMI frame")
        raw = self._queue.popleft()
        self.byte_count -= len(raw)
        return raw

    def notification_metadata(self, host_interface: int) -> dict:
        if type(host_interface) is not int or not 0 <= host_interface <= 255:
            raise ProtocolError("host interface must be uint8")
        return {"generation": self.generation, "response_available": bool(self._queue),
                "host_interface": host_interface, "queued_messages": len(self._queue),
                "queued_bytes": self.byte_count,
                "next_length": len(self._queue[0]) if self._queue else 0}

    def clear(self):
        self._queue.clear()
        self.byte_count = 0
        self.generation += 1
