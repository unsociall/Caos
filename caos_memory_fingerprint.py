"""Read-only fingerprint of a CAOS memory file under cooperative locks.

The fingerprint is evidence for later supervised maintenance, NOT a backup,
authorization to restore, or protection against non-cooperating writers.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from caos_memory_store import MemoryStore
from caos_consistent_reader import _reader_lock


def fingerprint_memory(store: MemoryStore) -> dict:
    path = Path(store.path)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with _reader_lock(lock_fd):
            try:
                fd = os.open(path, os.O_RDONLY if os.name != "nt" else os.O_RDWR)
            except FileNotFoundError:
                return {"status": "missing", "sha256": None, "size_bytes": 0}
            try:
                with _reader_lock(fd):
                    before = os.fstat(fd)
                    digest = hashlib.sha256()
                    size = 0
                    with os.fdopen(os.dup(fd), "rb") as stream:
                        while True:
                            chunk = stream.read(1024 * 1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                            size += len(chunk)
                    after = os.fstat(fd)
                    try:
                        current = os.stat(path)
                    except FileNotFoundError:
                        current = None
                    if current is None or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                        return {"status": "path_replaced", "sha256": None, "size_bytes": size}
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns
                    ) or size != after.st_size:
                        return {"status": "file_modified", "sha256": None, "size_bytes": size}
                    return {"status": "ok", "sha256": digest.hexdigest(), "size_bytes": size}
            finally:
                os.close(fd)
    finally:
        os.close(lock_fd)
