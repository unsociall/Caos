"""Read-only snapshot verification regression tests."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from caos_snapshot_verify import verify_memory_snapshot


class SnapshotVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "snapshot.jsonl"
        self.data = b'{"record":1}\\n'
        self.path.write_bytes(self.data)
        self.receipt = {"status": "created", "usable": True,
                        "snapshot_path": str(self.path),
                        "size_bytes": len(self.data),
                        "sha256": hashlib.sha256(self.data).hexdigest()}

    def test_matching_snapshot(self):
        result = verify_memory_snapshot(self.receipt)
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["verified"])
        self.assertFalse(result["automatic_repair_allowed"])

    def test_same_size_tampering(self):
        self.path.write_bytes(b"x" * len(self.data))
        self.assertEqual(verify_memory_snapshot(self.receipt)["status"], "mismatch")

    def test_missing_snapshot(self):
        self.path.unlink()
        self.assertEqual(verify_memory_snapshot(self.receipt)["status"], "unavailable")

    def test_invalid_receipt(self):
        self.assertEqual(verify_memory_snapshot({})["status"], "invalid_receipt")
        self.assertEqual(verify_memory_snapshot({**self.receipt, "size_bytes": True})["status"], "invalid_receipt")

    def test_symlink_is_rejected(self):
        link = Path(self.tmp.name) / "link"
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(verify_memory_snapshot(self.receipt, link)["status"], "unsafe_path")

    def test_does_not_modify_snapshot(self):
        verify_memory_snapshot(self.receipt)
        self.assertEqual(self.path.read_bytes(), self.data)


if __name__ == "__main__":
    unittest.main()
