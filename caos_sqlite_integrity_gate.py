"""Read-only SQLite integrity gate coordinated with CAOS maintenance writers.

Use the same lock path as caos_sqlite_write_coordinator.
This performs no repair, restoration, or mutation.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from caos_sqlite_write_coordinator import maintenance_lock


def inspect_memory_database(database_path, lock_path, *, timeout=5.0):
    """Run SQLite quick_check under the cooperative maintenance lock.

    Structural consistency is not application-level integrity or authenticity.
    """
    db = Path(database_path)
    if db.is_symlink() or not db.is_file():
        raise FileNotFoundError("existing regular SQLite database required")
    with maintenance_lock(lock_path, timeout=timeout):
        if db.is_symlink() or not db.is_file():
            raise FileNotFoundError("database changed while waiting for lock")
        uri = db.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=timeout) as conn:
            conn.execute("PRAGMA query_only=ON")
            rows = conn.execute("PRAGMA quick_check").fetchall()
            return {
                "ok": rows == [("ok",)],
                "diagnostics": [str(row[0]) for row in rows],
                "check": "sqlite_quick_check",
                "read_only": True,
            }
