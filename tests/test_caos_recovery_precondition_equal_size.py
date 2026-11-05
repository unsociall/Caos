"""Regression tests: recovery preflight must reject equal-length tampering.

The preflight is read-only and never authorizes restoration.
"""
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore
from caos_memory_fingerprint import fingerprint_memory
from caos_recovery_precondition import verify_recovery_precondition


class EqualLengthTamperTests(unittest.TestCase):
    def test_equal_length_mutation_is_stale(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "memory.jsonl"
            store = MemoryStore(path, secret=b"k" * 32, key_id="v1")
            store.append("event", "one")
            expected = fingerprint_memory(store)
            self.assertEqual(expected["status"], "ok")
            original = path.read_bytes()
            # Change one byte without changing the file length.
            index = original.index(b"one")
            altered = original[:index] + b"two" + original[index + 3:]
            self.assertEqual(len(altered), len(original))
            path.write_bytes(altered)
            result = verify_recovery_precondition(store, expected)
            self.assertEqual(result["status"], "stale")
            self.assertFalse(result["matches"])
            self.assertFalse(result["automatic_repair_allowed"])
            self.assertEqual(path.read_bytes(), altered)

    def test_same_size_replaced_file_is_stale(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "memory.jsonl"
            store = MemoryStore(path, secret=b"k" * 32, key_id="v1")
            store.append("event", "one")
            expected = fingerprint_memory(store)
            original = path.read_bytes()
            replacement = path.with_name("replacement.jsonl")
            replacement.write_bytes(original.replace(b"one", b"two", 1))
            self.assertEqual(replacement.stat().st_size, len(original))
            replacement.replace(path)
            result = verify_recovery_precondition(store, expected)
            self.assertEqual(result["status"], "stale")
            self.assertFalse(result["automatic_repair_allowed"])
            self.assertEqual(path.read_bytes(), original.replace(b"one", b"two", 1))


if __name__ == "__main__":
    unittest.main()
