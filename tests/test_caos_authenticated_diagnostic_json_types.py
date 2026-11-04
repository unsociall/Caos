"""Reject JSONL records whose top-level JSON value is not an object.

A syntactically valid JSON scalar or array is not a CAOS authenticated record.
The diagnostic must preserve the original file without attempting recovery.
"""
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class AuthenticatedDiagnosticJsonTypesTests(unittest.TestCase):
    def test_non_object_first_record_is_rejected_without_mutation(self):
        for payload in (b'null\n', b'true\n', b'42\n',
                        b'"text"\n', b'[]\n', b'[{"value": 1}]\n'):
            with self.subTest(payload=payload):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "memory.jsonl"
                    store = MemoryStore(path, secret=b"test-secret", key_id="test")
                    path.write_bytes(payload)

                    result = diagnose_authenticated(store)

                    self.assertEqual(result["status"], "invalid_or_unauthenticated")
                    self.assertEqual(result["valid_records"], 0)
                    self.assertEqual(result["valid_prefix_bytes"], 0)
                    self.assertEqual(result["error_offset"], 0)
                    self.assertEqual(path.read_bytes(), payload)

    def test_non_object_after_authenticated_prefix_preserves_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("one", "valid record")
            prefix = path.read_bytes()
            original = prefix + b'[]\n'
            path.write_bytes(original)

            result = diagnose_authenticated(store)

            self.assertEqual(result["status"], "invalid_or_unauthenticated")
            self.assertEqual(result["valid_records"], 1)
            self.assertEqual(result["valid_prefix_bytes"], len(prefix))
            self.assertEqual(result["error_offset"], len(prefix))
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
