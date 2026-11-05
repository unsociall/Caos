"""Authenticate CAOS snapshot receipts without storing or exposing the key.

HMAC authenticates the receipt metadata, not the memory records themselves.
No snapshot or source file is modified. The caller manages the secret key.
"""
from __future__ import annotations

import hashlib
import hmac
import json


_FIELDS = ("status", "usable", "snapshot_path", "size_bytes", "sha256")


def _payload(receipt: dict) -> bytes:
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be an object")
    if (receipt.get("status") != "created" or receipt.get("usable") is not True
            or not isinstance(receipt.get("snapshot_path"), str)
            or not receipt["snapshot_path"]
            or type(receipt.get("size_bytes")) is not int
            or receipt["size_bytes"] < 0
            or not isinstance(receipt.get("sha256"), str)
            or len(receipt["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in receipt["sha256"])):
        raise ValueError("invalid snapshot receipt")
    return json.dumps({k: receipt[k] for k in _FIELDS},
                      sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def sign_snapshot_receipt(receipt: dict, key: bytes) -> dict:
    """Return a new signed receipt; never mutate the supplied receipt."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")
    payload = _payload(receipt)
    result = {k: receipt[k] for k in _FIELDS}
    result["authentication"] = {
        "algorithm": "HMAC-SHA256",
        "version": 1,
        "mac": hmac.new(key, b"CAOS-SNAPSHOT-RECEIPT-v1\0" + payload,
                        hashlib.sha256).hexdigest(),
    }
    result["automatic_repair_allowed"] = False
    return result


def verify_signed_snapshot_receipt(receipt: dict, key: bytes) -> bool:
    """Fail closed for malformed or altered receipts; no I/O."""
    if not isinstance(key, bytes) or len(key) < 32:
        return False
    try:
        payload = _payload(receipt)
        auth = receipt.get("authentication")
        if not isinstance(auth, dict) or set(auth) != {"algorithm", "version", "mac"}:
            return False
        mac = auth["mac"]
        if (auth["algorithm"] != "HMAC-SHA256"
                or type(auth["version"]) is not int or auth["version"] != 1
                or not isinstance(mac, str) or len(mac) != 64
                or any(c not in "0123456789abcdef" for c in mac)):
            return False
        expected = hmac.new(key, b"CAOS-SNAPSHOT-RECEIPT-v1\0" + payload,
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, expected)
    except (ValueError, KeyError, TypeError):
        return False
