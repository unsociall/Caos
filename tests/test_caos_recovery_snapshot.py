"""Regression tests for fingerprint-bound, read-only recovery assessment."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from caos_memory_store import MemoryStore
from caos_recovery_snapshot import assess_recovery_snapshot


class RecoverySnapshotTests(unittest.TestCase):
    def test_incomplete_tail_is_stable_but_never_auto_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"a" * 32, key_id="v1")
            store.append("first", "intact")
            path.write_bytes(path.read_bytes() + b'{"incomplete":')
            original = path.read_bytes()
            result = assess_recovery_snapshot(store)
            self.assertEqual(result["status"], "stable")
            self.assertTrue(result["plan"]["manual_review_eligible"])
            self.assertFalse(result["automatic_repair_allowed"])
            self.assertEqual(result["fingerprint"]["size_bytes"], len(original))
            self.assertEqual(path.read_bytes(), original)

    def test_missing_memory_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "missing.jsonl",
                                secret=b"b" * 32, key_id="v1")
            result = assess_recovery_snapshot(store)
            self.assertEqual(result["status"], "unavailable")
            self.assertIsNone(result["plan"])
            self.assertFalse(result["automatic_repair_allowed"])

    def test_changed_fingerprint_discards_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"c" * 32, key_id="v1")
            store.append("first", "intact")
            from caos_memory_fingerprint import fingerprint_memory
            first = fingerprint_memory(store)
            second = dict(first, sha256="0" * 64)
            with patch("caos_recovery_snapshot.fingerprint_memory",
                       side_effect=[first, second]):
                result = assess_recovery_snapshot(store)
            self.assertEqual(result["status"], "stale")
            self.assertIsNone(result["plan"])
            self.assertFalse(result["automatic_repair_allowed"])


if __name__ == "__main__":
    unittest.main()
