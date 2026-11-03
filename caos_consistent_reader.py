"""Cooperative consistent reads for the CAOS append-only JSONL store.

This adapter does not alter existing storage or migrate data. Writers must use
MemoryStore.append(), which takes the same advisory exclusive file lock.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from caos_memory_store import MemoryStore, _exclusive_lock


def read_consistent(store: MemoryStore, *, keys: Mapping[str, bytes] | None = None) -> list[dict]:
    """Read a stable snapshot while cooperating writers are blocked.

    A pre-existing file is required; missing files represent empty memory.
    No files or directories are created by this function.
    """
    path = Path(store.path)
    try:
        fd = os.open(path, os.O_RDWR)
    except FileNotFoundError:
        return []
    try:
        with _exclusive_lock(fd):
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
                    record = json.loads(line.decode("utf-8"))
                    if not isinstance(record, dict) or not verify(record) or not verify_authenticated(record, keys=ring):
                        raise ValueError("integrity verification failed")
                except (ValueError, TypeError, UnicodeError) as exc:
                    raise MemoryIntegrityError(f"invalid record at line {number}") from exc
                records.append(record)
            return records
    finally:
        os.close(fd)
