"""Privacy-preserving diagnostics for supervised recovery decisions.

No file paths, receipts, hashes, keys, exception messages or memory records
are included in emitted events. Diagnostics are best-effort and read-only.
"""
from __future__ import annotations

from datetime import datetime, timezone

ALLOWED_REASONS = frozenset({
    "invalid_input", "snapshot_verification_error", "snapshot_not_verified",
    "source_verification_error", "source_stale", "snapshot_and_source_verified",
})


def make_recovery_event(decision: dict, *, clock=None) -> dict:
    """Produce a bounded, non-sensitive event from a gate decision."""
    if not isinstance(decision, dict):
        raise ValueError("decision must be a dictionary")
    reason = decision.get("reason")
    if type(reason) is not str or reason not in ALLOWED_REASONS:
        reason = "unrecognized_reason"
    status = "review_required" if (
        decision.get("status") == "review_required"
        and decision.get("eligible_for_review") is True
        and decision.get("automatic_repair_allowed") is False
        and reason == "snapshot_and_source_verified"
    ) else "blocked"
    instant = clock() if clock is not None else datetime.now(timezone.utc)
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise ValueError("clock must return timezone-aware datetime")
    return {
        "schema_version": 1,
        "timestamp_utc": instant.astimezone(timezone.utc).isoformat(),
        "component": "snapshot_recovery_gate",
        "status": status,
        "reason": reason,
        "automatic_repair_allowed": False,
    }


def emit_recovery_event(decision: dict, sink, *, clock=None) -> bool:
    """Best-effort emission; a failed sink never changes recovery decisions."""
    if not callable(sink):
        return False
    try:
        sink(make_recovery_event(decision, clock=clock))
        return True
    except Exception:
        return False
