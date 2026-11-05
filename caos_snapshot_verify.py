"""Read-only verification of a CAOS memory snapshot against its creation receipt.

SHA-256 establishes byte identity, not authenticity of memory records.
No restoration or deletion is performed.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def verify_memory_snapshot(receipt: dict, snapshot_path: str | Path | None = None) -> dict:
    """Verify a snapshot's bytes against the expected size and SHA-256.

    Fail closed on malformed receipts, symlinks, missing files or concurrent
    changes observed through file metadata. Never follow a symlink at open.
    """
    failure = {"status": "invalid_receipt", "verified": False,
               "automatic_repair_allowed": False}
    if not isinstance(receipt, dict):
        return failure
    expected_hash = receipt.get("sha256")
    expected_size = receipt.get("size_bytes")
    if (receipt.get("status") != "created" or receipt.get("usable") is not True
            or type(expected_size) is not int or expected_size < 0
            or not isinstance(expected_hash, str) or len(expected_hash) != 64
            or any(c not in "0123456789abcdef" for c in expected_hash)):
        return failure
    path_value = snapshot_path if snapshot_path is not None else receipt.get("snapshot_path")
    if not isinstance(path_value, (str, Path)) or not str(path_value):
        return failure
    path = Path(path_value)
    try:
        if path.is_symlink():
            return {"status": "unsafe_path", "verified": False,
                    "automatic_repair_allowed": False}
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            import stat
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                return {"status": "unsafe_path", "verified": False,
                        "automatic_repair_allowed": False}
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            after = os.fstat(fd)
            try:
                current = os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            stable = (current is not None
                      and (before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
                      and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                      == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                      and size == after.st_size)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return {"status": "unavailable", "verified": False,
                "automatic_repair_allowed": False}
    verified = (stable and size == expected_size
                and hmac.compare_digest(digest.hexdigest(), expected_hash))
    return {"status": "verified" if verified else "mismatch",
            "verified": verified, "automatic_repair_allowed": False,
            "size_bytes": size, "sha256": digest.hexdigest()}
