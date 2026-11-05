"""CAOS trusted SQLite writer: cooperative process lock and owned transaction.

All writers/recovery reviewers must use the same lock path.
Not a sandbox for untrusted Python callbacks.
"""
import contextlib
import fcntl
import os
import sqlite3
import stat
import time
from pathlib import Path
from caos_sqlite_write_boundary import execute_guarded_callback

@contextlib.contextmanager
def maintenance_lock(path, timeout=5.0):
    if not isinstance(timeout, (int, float)) or not 0 <= timeout <= 300:
        raise ValueError("invalid timeout")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(Path(path), flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsafe lock file")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("CAOS maintenance lock busy")
                time.sleep(min(0.025, max(0, deadline - time.monotonic())))
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

def guarded_sqlite_write(database_path, lock_path, callback, *, timeout=5.0):
    """Execute trusted DML callback, committing only on successful return."""
    if not callable(callback):
        raise TypeError("callback must be callable")
    db = Path(database_path)
    if not db.is_file() or db.is_symlink():
        raise FileNotFoundError("regular SQLite database required")
    with maintenance_lock(lock_path, timeout):
        with contextlib.closing(sqlite3.connect(db.resolve().as_uri() + "?mode=rw",
                                               uri=True, timeout=timeout,
                                               isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                result = execute_guarded_callback(conn, callback)
                if not conn.in_transaction:
                    raise RuntimeError("callback ended the managed transaction")
                conn.commit()
                return result
            except BaseException:
                if conn.in_transaction:
                    conn.rollback()
                raise
