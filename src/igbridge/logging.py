# SPDX-License-Identifier: Apache-2.0
"""Bounded JSONL metadata logging. Raw payload requires explicit per-call choice."""
from datetime import datetime, timezone
import hashlib
import json
import os
import threading
import time


class EventLog:
    def __init__(self, path, max_bytes=16 * 1024 * 1024):
        # Exclusive file creation prevents overwriting a prior experiment.
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.max_bytes = max_bytes
        self.written = 0
        self.lock = threading.Lock()

    def emit(self, event, payload=None, include_raw=False, **fields):
        record = dict(fields, event=event,
                      timestamp=datetime.now(timezone.utc).isoformat(),
                      monotonic_ns=time.monotonic_ns())
        if payload is not None:
            record.update(length=len(payload), sha256=hashlib.sha256(payload).hexdigest())
            if include_raw:
                record['raw_hex'] = payload.hex(' ')
        data = (json.dumps(record, ensure_ascii=False, sort_keys=True) + '\n').encode()
        with self.lock:
            if self.written + len(data) > self.max_bytes:
                raise OSError('log bound reached; stop rather than lose audit')
            offset = 0
            while offset < len(data):
                n = os.write(self.fd, data[offset:])
                if n <= 0:
                    raise OSError('log short write')
                offset += n
            self.written += len(data)

    def close(self):
        with self.lock:
            if self.fd is not None:
                os.fsync(self.fd)
                os.close(self.fd)
                self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
