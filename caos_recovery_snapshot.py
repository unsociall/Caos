"""Read-only recovery assessment bound to a stable memory fingerprint.

A matching SHA-256 is evidence of unchanged bytes during assessment, not
authorization to repair, proof of authenticity, or a transactional snapshot.
"""
from __future__ import annotations

import hmac
from typing import Mapping

from caos_memory_fingerprint import fingerprint_memory
from caos_memory_store import MemoryStore
from caos_recovery_plan import plan_authenticated_recovery


def assess_recovery_snapshot(
    store: MemoryStore, *, keys: Mapping[str, bytes] | None = None
) -> dict:
    """Fail closed if memory changes between fingerprint and diagnostic."""
    before = fingerprint_memory(store)
    if before["status"] != "ok":
        return {
            "status": "unavailable",
            "stable": False,
            "fingerprint": None,
            "plan": None,
            "automatic_repair_allowed": False,
            "reason": "Initial fingerprint unavailable: " + before["status"],
        }

    plan = plan_authenticated_recovery(store, keys=keys)
    after = fingerprint_memory(store)
    stable = (
        after["status"] == "ok"
        and before["size_bytes"] == after["size_bytes"]
        and hmac.compare_digest(before["sha256"], after["sha256"])
        and plan["diagnostic"]["status"] not in ("file_modified", "path_replaced")
    )
    return {
        "status": "stable" if stable else "stale",
        "stable": stable,
        "fingerprint": before if stable else None,
        "plan": plan if stable else None,
        "automatic_repair_allowed": False,
        "reason": (
            "Read-only assessment; revalidate under exclusive lock before any action."
            if stable else "Memory changed or verification became stale; retry."
        ),
    }
