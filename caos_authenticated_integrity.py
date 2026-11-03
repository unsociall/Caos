"""Optional authenticated integrity for CAOS memory records (stdlib only).

HMAC protects against changes by parties without the secret key. It does not
encrypt memory or protect against replay, deletion, or key compromise.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping

from caos_integrity import _payload

DOMAIN = b"CAOS:memory:hmac-sha256:v1\x00"
TAG_FIELD = "auth_tag"
KEY_ID_FIELD = "auth_key_id"


def _key(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("secret must be bytes of at least 32 bytes")
    return secret


def authenticate(record: Mapping[str, Any], *, secret: bytes, key_id: str) -> dict[str, Any]:
    """Return a new authenticated record. Never overwrite existing tags."""
    _key(secret)
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise ValueError("invalid key id")
    if TAG_FIELD in record or KEY_ID_FIELD in record:
        raise ValueError("record already has authentication metadata")
    result = dict(record)
    result[KEY_ID_FIELD] = key_id
    result[TAG_FIELD] = hmac.new(secret, DOMAIN + key_id.encode("utf-8") + b"\x00" + _payload(record), hashlib.sha256).hexdigest()
    return result


def verify_authenticated(record: Mapping[str, Any], *, keys: Mapping[str, bytes]) -> bool:
    """Fail closed: never accept an unauthenticated record or unknown key."""
    try:
        key_id = record.get(KEY_ID_FIELD)
        tag = record.get(TAG_FIELD)
        if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            return False
        if not isinstance(tag, str) or len(tag) != 64:
            return False
        secret = keys.get(key_id)
        if secret is None:
            return False
        _key(secret)
        expected = hmac.new(secret, DOMAIN + key_id.encode("utf-8") + b"\x00" + _payload(record), hashlib.sha256).hexdigest()
        return hmac.compare_digest(tag, expected)
    except (ValueError, TypeError, UnicodeError):
        return False
