"""Restricted SQLite write callback for CAOS internal memory writers.

This is an API guard, not a sandbox for untrusted Python. The caller must
hold the CAOS maintenance lock and own the BEGIN IMMEDIATE transaction.
"""
from __future__ import annotations

import re
import sqlite3

_WRITE = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE)\b", re.I)
_FORBIDDEN = re.compile(r"\b(COMMIT|ROLLBACK|SAVEPOINT|RELEASE|BEGIN|ATTACH|DETACH|PRAGMA|VACUUM)\b", re.I)


class GuardedWriteCursor:
    """Expose parameterized DML only; never expose commit/rollback/connection."""

    __slots__ = ("__connection",)

    def __init__(self, connection: sqlite3.Connection):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite3.Connection required")
        self.__connection = connection

    def execute(self, sql: str, parameters: tuple | list = ()) -> int:
        if not isinstance(sql, str) or not _WRITE.match(sql):
            raise ValueError("only INSERT/UPDATE/DELETE/REPLACE statements are allowed")
        if _FORBIDDEN.search(sql) or ";" in sql or "--" in sql or "/*" in sql:
            raise ValueError("transaction control and multiple statements are forbidden")
        if not isinstance(parameters, (tuple, list)):
            raise TypeError("parameters must be a tuple or list")
        cursor = self.__connection.execute(sql, parameters)
        return cursor.rowcount


def execute_guarded_callback(connection: sqlite3.Connection, callback):
    """Run trusted callback inside an already-open transaction.

    Does not commit or roll back: the outer maintenance-lock transaction
    controller retains ownership. Callback must be internal, audited code.
    """
    if not callable(callback):
        raise TypeError("callback must be callable")
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        raise RuntimeError("an active SQLite transaction is required")
    return callback(GuardedWriteCursor(connection))
