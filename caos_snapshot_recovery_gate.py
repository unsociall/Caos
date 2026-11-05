"""Read-only recovery eligibility gate for CAOS snapshots.

Diagnostic only: restoration requires explicit approval and revalidation
under an exclusive maintenance lock.
"""
from __future__ import annotations

from caos_snapshot_authenticated_verify import verify_authenticated_snapshot
from caos_recovery_precondition import verify_recovery_precondition


def assess_snapshot_recovery(store, expected_source: dict, signed_receipt: dict,
                             key: bytes) -> dict:
    """Fail closed on invalid inputs or malformed verifier responses."""
    denied = {"status": "blocked", "eligible_for_review": False,
              "automatic_repair_allowed": False}
    if not isinstance(expected_source, dict) or not isinstance(signed_receipt, dict):
        return {**denied, "reason": "invalid_input"}
    try:
        snapshot = verify_authenticated_snapshot(signed_receipt, key)
    except (OSError, ValueError, TypeError, KeyError):
        return {**denied, "reason": "snapshot_verification_error"}
    if not isinstance(snapshot, dict) or snapshot.get("verified") is not True or snapshot.get("authenticated") is not True:
        return {**denied, "reason": "snapshot_not_verified"}
    try:
        source = verify_recovery_precondition(store, expected_source)
    except (OSError, ValueError, TypeError, KeyError):
        return {**denied, "reason": "source_verification_error"}
    if not isinstance(source, dict) or source.get("matches") is not True:
        return {**denied, "reason": "source_stale"}
    return {"status": "review_required", "eligible_for_review": True,
            "automatic_repair_allowed": False,
            "reason": "snapshot_and_source_verified"}
