"""Regression tests for combined HMAC and byte verification."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from caos_snapshot_receipt_auth import sign_snapshot_receipt
from caos_snapshot_authenticated_verify import verify_authenticated_snapshot


class AuthenticatedSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "memory.jsonl"
        self.data = b'{"id":1}\n'
        self.path.write_bytes(self.data)
        self.key = b"k" * 32
        receipt = {"status": "created", "usable": True,
                   "snapshot_path": str(self.path),
                   "size_bytes": len(self.data),
                   "sha256": hashlib.sha256(self.data).hexdigest()}
        self.signed = sign_snapshot_receipt(receipt, self.key)

    def test_valid_receipt_and_snapshot(self):
        result = verify_authenticated_snapshot(self.signed, self.key)
        self.assertTrue(result["verified"])
        self.assertTrue(result["authenticated"])
        self.assertFalse(result["automatic_repair_allowed"])

    def test_wrong_key(self):
        result = verify_authenticated_snapshot(self.signed, b"z" * 32)
        self.assertEqual(result["status"], "invalid_authentication")

    def test_modified_receipt(self):
        changed = dict(self.signed, size_bytes=999)
        self.assertFalse(verify_authenticated_snapshot(changed, self.key)["verified"])

    def test_same_size_modified_bytes(self):
        self.path.write_bytes(b"x" * len(self.data))
        self.assertEqual(verify_authenticated_snapshot(self.signed, self.key)["status"],
                         "mismatch")

    def test_path_override_rejected(self):
        other = Path(self.temp.name) / "other.jsonl"
        other.write_bytes(self.data)
        result = verify_authenticated_snapshot(self.signed, self.key, other)
        self.assertEqual(result["status"], "path_mismatch")

    def test_missing_snapshot(self):
        self.path.unlink()
        self.assertEqual(verify_authenticated_snapshot(self.signed, self.key)["status"],
                         "unavailable")


if __name__ == "__main__":
    unittest.main()
