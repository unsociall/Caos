"""Read-only recovery planning for CAOS authenticated JSONL memory.

This module NEVER truncates, copies or modifies the memory file.
A plan is advisory; it must not be used as authorization to rewrite data.
"""
from __future__ import annotations

from typing import Mapping

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore

RECOVERABLE_STATUS = "unterminated_tail"


def plan_authenticated_recovery(
    store: MemoryStore, *, keys: Mapping[str, bytes] | None = None
) -> dict:
    """Return a fail-closed recovery recommendation without touching memory.

    Only a verified prefix followed by an incomplete final record is eligible
    for *manual review*. A verified prefix of zero bytes is never recoverable
    automatically. The diagnostic holds cooperative locks during verification,
    but this plan is NOT an atomic snapshot or a recovery transaction.
    """
    report = diagnose_authenticated(store, keys=keys)
    status = report["status"]
    prefix = report["valid_prefix_bytes"]
    eligible = (
        status == RECOVERABLE_STATUS
        and report["valid_records"] > 0
        and prefix > 0
        and report["error_offset"] == prefix
    )
    return {
        "diagnostic": report,
        "manual_review_eligible": eligible,
        "automatic_repair_allowed": False,
        "recommended_action": (
            "Preserve original bytes; acquire exclusive maintenance lock; "
            "revalidate integrity and keyring; create a verified backup; "
            "require explicit operator approval before any restoration."
            if eligible else
            "Do not repair; investigate the diagnostic status and retain original bytes."
        ),
        "warning": "Plan is advisory and can become stale if the file changes.",
    }
