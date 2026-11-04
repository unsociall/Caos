"""Regression: explicit keyrings must fail closed across key generations."""
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class KeyringBoundaryTests(unittest.TestCase):
    def test_empty_explicit_keyring_never_uses_store_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl",
                                secret=b"a" * 32, key_id="key-v1")
            store.append("one", "remember")
            before = store.path.read_bytes()
            result = diagnose_authenticated(store, keys={})
            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 0)
            self.assertEqual(result["valid_prefix_bytes"], 0)
            self.assertEqual(result["error_offset"], 0)
            self.assertEqual(store.path.read_bytes(), before)

    def test_missing_new_key_preserves_authenticated_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            old = MemoryStore(path, secret=b"a" * 32, key_id="key-v1")
            old.append("first", "historical")
            prefix = path.read_bytes()
            current = MemoryStore(path, secret=b"b" * 32, key_id="key-v2")
            current.append("second", "current")
            before = path.read_bytes()
            result = diagnose_authenticated(current, keys={"key-v1": b"a" * 32})
            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 1)
            self.assertEqual(result["valid_prefix_bytes"], len(prefix))
            self.assertEqual(result["error_offset"], len(prefix))
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
