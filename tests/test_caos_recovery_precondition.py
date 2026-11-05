"""Regression tests for non-mutating recovery precondition checks."""
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore
from caos_memory_fingerprint import fingerprint_memory
from caos_recovery_precondition import verify_recovery_precondition


class RecoveryPreconditionTests(unittest.TestCase):
    def test_unchanged_memory_matches_without_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "memory.jsonl"
            store = MemoryStore(path, secret=b"k" * 32, key_id="v1")
            store.append("event", "one")
            before = path.read_bytes()
            expected = fingerprint_memory(store)
            result = verify_recovery_precondition(store, expected)
            self.assertEqual(result["status"], "match")
            self.assertTrue(result["matches"])
            self.assertFalse(result["automatic_repair_allowed"])
            self.assertEqual(path.read_bytes(), before)

    def test_changed_memory_is_stale(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "memory.jsonl"
            store = MemoryStore(path, secret=b"k" * 32, key_id="v1")
            store.append("event", "one")
            expected = fingerprint_memory(store)
            store.append("event", "two")
            before = path.read_bytes()
            result = verify_recovery_precondition(store, expected)
            self.assertEqual(result["status"], "stale")
            self.assertFalse(result["matches"])
            self.assertEqual(path.read_bytes(), before)

    def test_malformed_expected_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            store = MemoryStore(Path(folder) / "memory.jsonl",
                                secret=b"k" * 32, key_id="v1")
            for expected in ({}, {"status": "ok", "sha256": "bad", "size_bytes": 1},
                             {"status": "ok", "sha256": "0" * 64, "size_bytes": True}):
                result = verify_recovery_precondition(store, expected)
                self.assertEqual(result["status"], "invalid_precondition")
                self.assertFalse(result["automatic_repair_allowed"])


if __name__ == "__main__":
    unittest.main()
