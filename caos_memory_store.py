"""Opt-in, append-only CAOS JSONL memory store. No automatic migrations."""
from __future__ import annotations

import json
import os
import contextlib
from pathlib import Path
from typing import Mapping

from caos_integrity import seal, verify
from caos_authenticated_integrity import authenticate, verify_authenticated

@contextlib.contextmanager
def _exclusive_lock(fd: int):
    """Advisory lock; all writers must cooperate."""
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


class MemoryIntegrityError(Exception):
    """A persisted record failed validation or authentication."""


class MemoryStore:
    def __init__(self, path: str | Path, *, secret: bytes, key_id: str):
        self.path = Path(path)
        self.secret = secret
        self.key_id = key_id
        # Validate configuration before creating any files.
        authenticate({"id": "_probe", "content": "", "schema_version": 1},
                     secret=secret, key_id=key_id)

    def append(self, identifier: str, content: str) -> None:
        record = authenticate(seal({"id": identifier, "content": content,
                                    "schema_version": 1}),
                              secret=self.secret, key_id=self.key_id)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        # Exclusive creation avoids silently replacing existing data.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            with _exclusive_lock(fd):
                self._append_locked(fd, line)
        finally:
            os.close(fd)

    @staticmethod
    def _append_locked(fd: int, line: str) -> None:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, -1, os.SEEK_END)
            if os.read(fd, 1) != b"\n":
                raise MemoryIntegrityError("unterminated tail: append refused")
        data = line.encode("utf-8")
        if os.write(fd, data) != len(data):
            raise OSError("short append: inspect last record before retrying")
        os.fsync(fd)

    def read_all(self, *, keys: Mapping[str, bytes] | None = None) -> list[dict]:
        """Return a consistent authenticated snapshot using the locked reader.

        Import locally to avoid a module import cycle. The reader and writer
        cooperate on the same descriptor lock; legacy records are not changed.
        """
        from caos_consistent_reader import read_consistent
        return read_consistent(self, keys=keys)
