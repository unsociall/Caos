"""Create an opt-in, non-overwriting byte snapshot of CAOS memory.

Snapshots are NOT authenticated backups and are never restored automatically.
The caller must validate authenticated records separately before trusting data.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from caos_consistent_reader import _reader_lock
from caos_memory_store import MemoryStore


def create_memory_snapshot(store: MemoryStore, destination: str | Path) -> dict:
    """Copy a stable memory inode under cooperative locks; never overwrite.

    A failed copy may leave a partial destination: it is reported as invalid,
    never removed automatically, and must not be used for recovery.
    """
    source = Path(store.path)
    target = Path(destination)
    if source.absolute() == target.absolute():
        raise ValueError("snapshot destination must differ from memory path")
    if not target.parent.is_dir():
        raise FileNotFoundError("snapshot destination directory must exist")

    lock_path = source.with_name(source.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with _reader_lock(lock_fd):
            src_fd = os.open(source, os.O_RDONLY)
            try:
                with _reader_lock(src_fd):
                    before = os.fstat(src_fd)
                    current = os.stat(source)
                    if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                        raise RuntimeError("source path replaced before snapshot")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    dst_fd = os.open(target, flags, 0o600)
                    digest = hashlib.sha256()
                    copied = 0
                    try:
                        with os.fdopen(os.dup(src_fd), "rb") as reader:
                            while True:
                                chunk = reader.read(1024 * 1024)
                                if not chunk:
                                    break
                                view = memoryview(chunk)
                                while view:
                                    written = os.write(dst_fd, view)
                                    if written <= 0:
                                        raise OSError("short snapshot write")
                                    view = view[written:]
                                digest.update(chunk)
                                copied += len(chunk)
                        os.fsync(dst_fd)
                    finally:
                        os.close(dst_fd)
                    after = os.fstat(src_fd)
                    try:
                        current = os.stat(source)
                    except FileNotFoundError:
                        current = None
                    stable = (current is not None
                              and (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
                              and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                              == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                              and copied == after.st_size)
                    return {"status": "created" if stable else "invalid_source_changed",
                            "snapshot_path": str(target),
                            "sha256": digest.hexdigest(),
                            "size_bytes": copied,
                            "usable": bool(stable),
                            "automatic_repair_allowed": False}
            finally:
                os.close(src_fd)
    finally:
        os.close(lock_fd)
