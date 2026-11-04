"""Regression coverage for concurrent mutations on diagnostic failure paths."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import caos_authenticated_diagnostic as diagnostic
from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class DiagnosticErrorRaceTests(unittest.TestCase):
    def test_invalid_record_without_race_preserves_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            path.write_bytes(b'{"invalid":true}\n')
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            self.assertEqual(diagnose_authenticated(store)["status"],
                             "invalid_or_unauthenticated")

    def test_in_place_mutation_on_invalid_record_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("one", "valid")
            original = diagnostic.verify_authenticated

            def mutate(record, *, keys):
                result = original(record, keys=keys)
                with path.open("ab") as stream:
                    stream.write(b'{"broken":true}\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                return False

            with patch.object(diagnostic, "verify_authenticated",
                              side_effect=mutate):
                result = diagnose_authenticated(store)
            self.assertEqual(result["status"], "file_modified")

    def test_replacement_on_invalid_record_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("one", "valid")
            replacement = Path(tmp) / "replacement.jsonl"
            replacement.write_bytes(b'{"broken":true}\n')

            def replace_and_fail(record, *, keys):
                os.replace(replacement, path)
                return False

            with patch.object(diagnostic, "verify_authenticated",
                              side_effect=replace_and_fail):
                result = diagnose_authenticated(store)
            self.assertEqual(result["status"], "path_replaced")


if __name__ == "__main__":
    unittest.main()
