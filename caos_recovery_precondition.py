"""Read-only preflight for supervised CAOS recovery.

A recovery assessment is advisory. This module checks that the bytes still
match an earlier assessment; it never copies, truncates or restores memory.
"""
from __future__ import annotations

import hmac
import re
from typing import Mapping, Any

from caos_memory_fingerprint import fingerprint_memory
from caos_memory_store import MemoryStore

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def verify_recovery_precondition(store: MemoryStore, expected: Mapping[str, Any]) -> dict:
    """Reject stale/malformed fingerprints before a supervised maintenance step.

    This is a preflight, NOT a transaction: callers must revalidate under an
    exclusive maintenance lock immediately before any authorized write.
    """
    digest = expected.get("sha256")
    size = expected.get("size_bytes")
    if (expected.get("status") != "ok"
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or type(size) is not int or size < 0):
        return {"status": "invalid_precondition", "matches": False,
                "automatic_repair_allowed": False}
    current = fingerprint_memory(store)
    matches = (current.get("status") == "ok"
               and current.get("size_bytes") == size
               and isinstance(current.get("sha256"), str)
               and hmac.compare_digest(digest, current["sha256"]))
    return {"status": "match" if matches else "stale",
            "matches": matches, "automatic_repair_allowed": False}
