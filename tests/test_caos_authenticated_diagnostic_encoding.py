"""Regression tests for authenticated JSONL diagnostics on invalid UTF-8."""
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class AuthenticatedDiagnosticEncodingTests(unittest.TestCase):
    def test_invalid_utf8_after_valid_record_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("one", "valid record")
            prefix = path.read_bytes()
            with path.open("ab") as output:
                output.write(b'{"value":"\xff"}\n')
            original = path.read_bytes()

            result = diagnose_authenticated(store)

            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 1)
            self.assertEqual(result["valid_prefix_bytes"], len(prefix))
            self.assertEqual(result["error_offset"], len(prefix))
            self.assertEqual(path.read_bytes(), original)

    def test_invalid_utf8_first_record_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            original = b'{"value":"\xfe"}\n'
            path.write_bytes(original)

            result = diagnose_authenticated(store)

            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 0)
            self.assertEqual(result["valid_prefix_bytes"], 0)
            self.assertEqual(result["error_offset"], 0)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
