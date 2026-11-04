import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore
from caos_authenticated_diagnostic import diagnose_authenticated


class AuthenticatedDiagnosticTests(unittest.TestCase):
    def test_valid_records(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "memory.jsonl", secret=b"test-secret", key_id="test")
            store.append("one", "hello")
            store.append("two", "world")
            result = diagnose_authenticated(store)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["valid_records"], 2)
            self.assertEqual(result["valid_prefix_bytes"], store.path.stat().st_size)

    def test_tamper_is_detected_without_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "memory.jsonl", secret=b"test-secret", key_id="test")
            store.append("one", "hello")
            prefix = store.path.read_bytes()
            store.append("two", "world")
            tampered = store.path.read_bytes().replace(b"world", b"other")
            store.path.write_bytes(tampered)
            result = diagnose_authenticated(store)
            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 1)
            self.assertEqual(result["error_offset"], len(prefix))
            self.assertEqual(store.path.read_bytes(), tampered)

    def test_partial_tail(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "memory.jsonl", secret=b"test-secret", key_id="test")
            store.append("one", "hello")
            with store.path.open("ab") as f:
                f.write(b'{"partial":')
            self.assertEqual(diagnose_authenticated(store)["status"], "unterminated_tail")

    def test_missing_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as d:
            store = MemoryStore(Path(d) / "memory.jsonl", secret=b"test-secret", key_id="test")
            self.assertEqual(diagnose_authenticated(store)["status"], "missing")
            self.assertFalse(store.path.exists())
            self.assertTrue(store.path.with_name(store.path.name + ".lock").exists())


if __name__ == "__main__":
    unittest.main()
