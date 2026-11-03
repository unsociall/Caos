"""Integrity checking for CAOS memory records (stdlib only).

This module does not authenticate the writer: SHA-256 detects accidental corruption,
not malicious replacement. It never changes an existing record in place.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

SCHEMA_VERSION = 1


def _payload(record: Mapping[str, Any]) -> bytes:
    fields = ("id", "content", "schema_version")
    if any(field not in record for field in fields):
        raise ValueError("memory record missing required fields")
    if not isinstance(record["id"], str) or not record["id"]:
        raise ValueError("id must be a nonempty string")
    if not isinstance(record["content"], str):
        raise ValueError("content must be a string")
    if record["schema_version"] != SCHEMA_VERSION or isinstance(record["schema_version"], bool):
        raise ValueError("unsupported schema version")
    payload = {field: record[field] for field in fields}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_payload(record)).hexdigest()


def seal(record: Mapping[str, Any]) -> dict[str, Any]:
    if "integrity_hash" in record:
        raise ValueError("refusing to overwrite existing integrity hash")
    result = dict(record)
    result["integrity_hash"] = digest(record)
    return result


def verify(record: Mapping[str, Any]) -> bool:
    expected = record.get("integrity_hash")
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    try:
        actual = digest(record)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, actual)
