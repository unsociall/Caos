"""Authenticated, read-only CAOS JSONL diagnostic under cooperative locks."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from caos_memory_store import MemoryStore, _exclusive_lock
from caos_consistent_reader import _reader_lock
from caos_integrity import verify
from caos_authenticated_integrity import verify_authenticated


def diagnose_authenticated(store: MemoryStore, *, keys: Mapping[str, bytes] | None = None) -> dict:
    """Find first malformed/unauthenticated record; never repair or truncate.

    Coordinates with MemoryStore writers via the stable sidecar lock.
    This is not a defense against non-cooperating filesystem mutations.
    """
    path = Path(store.path)
    if not path.exists():
        return {"status": "missing", "valid_prefix_bytes": 0,
                "valid_records": 0, "error_offset": None}
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with _reader_lock(lock_fd):
            try:
                fd = os.open(path, os.O_RDWR if os.name == "nt" else os.O_RDONLY)
            except FileNotFoundError:
                return {"status": "missing", "valid_prefix_bytes": 0,
                        "valid_records": 0, "error_offset": None}
            try:
                with _reader_lock(fd):
                    with os.fdopen(os.dup(fd), "rb") as stream:
                        stream.seek(0)
                        opened_stat = os.fstat(fd)
                        initial_signature = (opened_stat.st_size, opened_stat.st_mtime_ns,
                                             opened_stat.st_ctime_ns)
                        valid_end = 0
                        count = 0
                        ring = keys if keys is not None else {store.key_id: store.secret}
                        while True:
                            start = stream.tell()
                            line = stream.readline()
                            if not line:
                                # Detect non-cooperating replacement during this scan.
                                # Advisory locks cannot prevent it; reject a stale result.
                                try:
                                    current_stat = os.stat(path)
                                except FileNotFoundError:
                                    current_stat = None
                                if (current_stat is None or
                                        (opened_stat.st_dev, opened_stat.st_ino) !=
                                        (current_stat.st_dev, current_stat.st_ino)):
                                    return {"status": "path_replaced",
                                            "valid_prefix_bytes": valid_end,
                                            "valid_records": count, "error_offset": None}
                                end_stat = os.fstat(fd)
                                end_signature = (end_stat.st_size, end_stat.st_mtime_ns,
                                                 end_stat.st_ctime_ns)
                                if end_signature != initial_signature:
                                    return {"status": "file_modified",
                                            "valid_prefix_bytes": valid_end,
                                            "valid_records": count, "error_offset": None}
                                return {"status": "ok", "valid_prefix_bytes": valid_end,
                                        "valid_records": count, "error_offset": None}
                            if not line.endswith(b"\n"):
                                status = "unterminated_tail"
                            else:
                                try:
                                    record = json.loads(line.decode("utf-8"))
                                    status = ("ok" if isinstance(record, dict)
                                              and verify(record)
                                              and verify_authenticated(record, keys=ring)
                                              else "invalid_or_unauthenticated")
                                except (ValueError, TypeError, UnicodeError, KeyError):
                                    status = "invalid_or_unauthenticated"
                            if status != "ok":
                                # Recheck the snapshot even on validation failure:
                                # non-cooperating mutations can make an error stale.
                                try:
                                    current_stat = os.stat(path)
                                except FileNotFoundError:
                                    current_stat = None
                                if (current_stat is None or
                                        (opened_stat.st_dev, opened_stat.st_ino) !=
                                        (current_stat.st_dev, current_stat.st_ino)):
                                    status = "path_replaced"
                                else:
                                    end_stat = os.fstat(fd)
                                    if (end_stat.st_size, end_stat.st_mtime_ns,
                                            end_stat.st_ctime_ns) != initial_signature:
                                        status = "file_modified"
                                return {"status": status, "valid_prefix_bytes": valid_end,
                                        "valid_records": count, "error_offset": start}
                            valid_end = stream.tell()
                            count += 1
            finally:
                os.close(fd)
    finally:
        os.close(lock_fd)
