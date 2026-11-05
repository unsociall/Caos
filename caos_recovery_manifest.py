"""Read-only, portable recovery evidence manifest for CAOS.

This module does not create backups or authorize restoration.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from caos_memory_fingerprint import fingerprint_memory
from caos_memory_store import MemoryStore
from caos_recovery_precondition import verify_recovery_precondition


def build_recovery_manifest(store: MemoryStore) -> dict[str, Any]:
    """Capture a fingerprint as JSON-serializable advisory evidence."""
    fingerprint = fingerprint_memory(store)
    return {
        "schema_version": 1,
        "kind": "caos.recovery.evidence",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fingerprint,
        "automatic_repair_allowed": False,
    }


def validate_recovery_manifest(store: MemoryStore, manifest: Any) -> dict[str, Any]:
    """Fail closed for malformed, unsupported or stale manifests."""
    if not isinstance(manifest, dict):
        return {"status": "invalid_manifest", "matches": False, "automatic_repair_allowed": False}
    if (type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1
            or manifest.get("kind") != "caos.recovery.evidence"
            or manifest.get("automatic_repair_allowed") is not False
            or not isinstance(manifest.get("fingerprint"), dict)):
        return {"status": "invalid_manifest", "matches": False, "automatic_repair_allowed": False}
    created = manifest.get("created_utc")
    if not isinstance(created, str):
        return {"status": "invalid_manifest", "matches": False, "automatic_repair_allowed": False}
    try:
        timestamp = datetime.fromisoformat(created)
    except ValueError:
        return {"status": "invalid_manifest", "matches": False, "automatic_repair_allowed": False}
    if timestamp.tzinfo is None or timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        return {"status": "invalid_manifest", "matches": False, "automatic_repair_allowed": False}
    return verify_recovery_precondition(store, manifest["fingerprint"])


def manifest_to_json(manifest: dict[str, Any]) -> str:
    """Serialize evidence without writing to the memory or disk."""
    return json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
