"""Cooperative consistent reads for the CAOS append-only JSONL store.

This adapter does not alter existing storage or migrate data. Writers must use
MemoryStore.append(), which takes the same advisory exclusive file lock.
"""
from __future__ import annotations

import os
import contextlib
from pathlib import Path
from typing import Mapping

from caos_memory_store import MemoryStore, _exclusive_lock


@contextlib.contextmanager
def _reader_lock(fd: int):
    """Shared POSIX lock; Windows retains the existing exclusive lock."""
    if os.name == "nt":
        with _exclusive_lock(fd):
            yield
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


def read_consistent(store: MemoryStore, *, keys: Mapping[str, bytes] | None = None) -> list[dict]:
    """Read a stable snapshot while cooperating writers are blocked.

    A pre-existing file is required; missing files represent empty memory.
    No files or directories are created by this function.
    """
    path = Path(store.path)
    # Preserve empty-memory semantics without creating directories or locks.
    if not path.exists():
        return []
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with _reader_lock(lock_fd):
            try:
                fd = os.open(path, os.O_RDWR if os.name == "nt" else os.O_RDONLY)
            except FileNotFoundError:
                return []
            try:
                with _reader_lock(fd):
                    return _read_locked(fd, store, keys)
            finally:
                os.close(fd)
    finally:
        os.close(lock_fd)


def _read_locked(fd: int, store: MemoryStore, keys: Mapping[str, bytes] | None) -> list[dict]:
    """Validate records from a descriptor protected by both locks."""
    # Descriptor stays open until the entire snapshot has been validated.
    # Read via the *locked descriptor* rather than reopening the path:
    # replacement/rename cannot redirect us to an unlocked inode.
    with os.fdopen(os.dup(fd), "rb") as stream:
        stream.seek(0)
        raw = stream.read()
    # Reuse the same record validation logic without changing the
    # original store: the bytes are snapshotted under the lock.
    import json
    from caos_integrity import verify
    from caos_authenticated_integrity import verify_authenticated
    from caos_memory_store import MemoryIntegrityError
    ring = keys if keys is not None else {store.key_id: store.secret}
    records = []
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.endswith(b"\n"):
            raise MemoryIntegrityError(f"unterminated record at line {number}")
        try:
            decoded = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MemoryIntegrityError(f"invalid UTF-8 at line {number}") from exc
        try:
            record = json.loads(decoded)
            if not isinstance(record, dict) or not verify(record) or not verify_authenticated(record, keys=ring):
                raise ValueError("integrity verification failed")
        except (ValueError, TypeError, UnicodeError) as exc:
            raise MemoryIntegrityError(f"invalid record at line {number}") from exc
        records.append(record)
    return records
