"""Opt-in, append-only CAOS JSONL memory store. No automatic migrations."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from caos_integrity import seal, verify
from caos_authenticated_integrity import authenticate, verify_authenticated


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
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            data = line.encode("utf-8")
            # Single write; short writes are treated as failure, not retried.
            if os.write(fd, data) != len(data):
                raise OSError("short append: inspect last record before retrying")
            os.fsync(fd)
        finally:
            os.close(fd)

    def read_all(self, *, keys: Mapping[str, bytes] | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        keyring = keys if keys is not None else {self.key_id: self.secret}
        result = []
        with self.path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict) or not verify(record) or not verify_authenticated(record, keys=keyring):
                        raise ValueError("integrity verification failed")
                except (ValueError, TypeError, UnicodeError) as exc:
                    raise MemoryIntegrityError(f"invalid record at line {number}") from exc
                result.append(record)
        return result
