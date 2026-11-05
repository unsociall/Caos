"""Fail-closed authenticated snapshot verification for CAOS.

Authenticates receipt metadata before opening the snapshot. Read-only.
A successful check is NOT authorization to restore memory.
"""
from __future__ import annotations

from pathlib import Path

from caos_snapshot_receipt_auth import verify_signed_snapshot_receipt
from caos_snapshot_verify import verify_memory_snapshot


def verify_authenticated_snapshot(receipt: dict, key: bytes,
                                  snapshot_path: str | Path | None = None) -> dict:
    """Verify HMAC and snapshot bytes; reject path overrides.

    Path overrides could redirect a valid signed receipt to a different file.
    The signed snapshot_path is always the path used for verification.
    """
    denied = {"status": "invalid_authentication", "verified": False,
              "automatic_repair_allowed": False}
    if not verify_signed_snapshot_receipt(receipt, key):
        return denied
    signed_path = receipt["snapshot_path"]
    if snapshot_path is not None and str(snapshot_path) != signed_path:
        return {"status": "path_mismatch", "verified": False,
                "automatic_repair_allowed": False}
    result = verify_memory_snapshot(receipt)
    result["authenticated"] = bool(result["verified"])
    result["automatic_repair_allowed"] = False
    return result
