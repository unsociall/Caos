"""Regression tests for authenticated-memory key selection and rotation.

The diagnostic must never silently fall back to the store secret when an
explicit verification keyring is provided.
"""
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class DiagnosticKeyringTests(unittest.TestCase):
    def test_explicit_matching_keyring_accepts_record(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl",
                                secret=b"a" * 32, key_id="key-v1")
            store.append("one", "remember")
            original = store.path.read_bytes()
            result = diagnose_authenticated(store, keys={"key-v1": b"a" * 32})
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["valid_records"], 1)
            self.assertEqual(result["valid_prefix_bytes"], len(original))
            self.assertEqual(store.path.read_bytes(), original)

    def test_missing_key_does_not_fall_back_to_store_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl",
                                secret=b"a" * 32, key_id="key-v1")
            store.append("one", "remember")
            original = store.path.read_bytes()
            result = diagnose_authenticated(store, keys={"key-v2": b"b" * 32})
            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 0)
            self.assertEqual(result["valid_prefix_bytes"], 0)
            self.assertEqual(result["error_offset"], 0)
            self.assertEqual(store.path.read_bytes(), original)

    def test_wrong_key_for_matching_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl",
                                secret=b"a" * 32, key_id="key-v1")
            store.append("one", "remember")
            original = store.path.read_bytes()
            result = diagnose_authenticated(store, keys={"key-v1": b"c" * 32})
            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 0)
            self.assertEqual(result["error_offset"], 0)
            self.assertEqual(store.path.read_bytes(), original)


    def test_mixed_historical_keys_verify_without_rewriting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            old = MemoryStore(path, secret=b"a" * 32, key_id="key-v1")
            new = MemoryStore(path, secret=b"b" * 32, key_id="key-v2")
            old.append("first", "historical")
            new.append("second", "current")
            original = path.read_bytes()
            result = diagnose_authenticated(new, keys={
                "key-v1": b"a" * 32, "key-v2": b"b" * 32})
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["valid_records"], 2)
            self.assertEqual(result["valid_prefix_bytes"], len(original))
            self.assertEqual(path.read_bytes(), original)

    def test_retired_historical_key_fails_at_first_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            MemoryStore(path, secret=b"a" * 32, key_id="key-v1").append(
                "first", "historical")
            current = MemoryStore(path, secret=b"b" * 32, key_id="key-v2")
            current.append("second", "current")
            original = path.read_bytes()
            result = diagnose_authenticated(current, keys={"key-v2": b"b" * 32})
            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 0)
            self.assertEqual(result["error_offset"], 0)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
