"""Regression coverage for the read-only CAOS memory fingerprint."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore
from caos_memory_fingerprint import fingerprint_memory


class MemoryFingerprintTests(unittest.TestCase):
    def test_missing_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl", secret=b"a" * 32, key_id="v1")
            result = fingerprint_memory(store)
            self.assertEqual(result["status"], "missing")
            self.assertIsNone(result["sha256"])

    def test_fingerprint_matches_exact_bytes_without_rewriting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"b" * 32, key_id="v1")
            store.append("one", "hello")
            original = path.read_bytes()
            result = fingerprint_memory(store)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["size_bytes"], len(original))
            self.assertEqual(result["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(path.read_bytes(), original)

    def test_corrupted_tail_is_fingerprinted_not_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"c" * 32, key_id="v1")
            store.append("one", "hello")
            original = path.read_bytes() + b'{"partial":'
            path.write_bytes(original)
            result = fingerprint_memory(store)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
