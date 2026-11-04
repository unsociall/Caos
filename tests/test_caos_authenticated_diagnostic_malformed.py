"""Regression: malformed authenticated memory is diagnosed without mutation."""
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class AuthenticatedDiagnosticMalformedTests(unittest.TestCase):
    def test_malformed_second_line_preserves_file_and_reports_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("one", "valid record")
            prefix = path.read_bytes()
            self.assertTrue(prefix.endswith(b"\n"))
            malformed = b'{"broken":\n'
            with path.open("ab") as output:
                output.write(malformed)
            original = path.read_bytes()

            outcome = diagnose_authenticated(store)

            self.assertEqual(outcome["status"], "invalid_or_unauthenticated")
            self.assertEqual(outcome["valid_records"], 1)
            self.assertEqual(outcome["valid_prefix_bytes"], len(prefix))
            self.assertEqual(outcome["error_offset"], len(prefix))
            self.assertEqual(path.read_bytes(), original)

    def test_unterminated_tail_is_not_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("one", "valid record")
            prefix = path.read_bytes()
            with path.open("ab") as output:
                output.write(b'{"partial": true')
            original = path.read_bytes()

            outcome = diagnose_authenticated(store)

            self.assertEqual(outcome["status"], "unterminated_tail")
            self.assertEqual(outcome["valid_records"], 1)
            self.assertEqual(outcome["valid_prefix_bytes"], len(prefix))
            self.assertEqual(outcome["error_offset"], len(prefix))
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
