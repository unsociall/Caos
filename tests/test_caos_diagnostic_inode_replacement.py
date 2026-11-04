"""Regression: detect a non-cooperating atomic replacement during a scan."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from caos_memory_store import MemoryStore
from caos_authenticated_diagnostic import diagnose_authenticated
import caos_authenticated_diagnostic as diagnostic


class DiagnosticInodeReplacementTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX inode replacement semantics")
    def test_noncooperating_replacement_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("first", "original")
            replacement_path = Path(directory) / "replacement.jsonl"
            replacement = MemoryStore(replacement_path, secret=b"test-secret", key_id="test")
            replacement.append("second", "replacement")
            replacement_bytes = replacement_path.read_bytes()
            original_verify = diagnostic.verify_authenticated
            replaced = False

            def replace_after_validation(record, *, keys):
                nonlocal replaced
                result = original_verify(record, keys=keys)
                if not replaced:
                    os.replace(replacement_path, path)
                    replaced = True
                return result

            with patch.object(diagnostic, "verify_authenticated", side_effect=replace_after_validation):
                result = diagnose_authenticated(store)

            self.assertTrue(replaced)
            self.assertEqual(result["status"], "path_replaced")
            self.assertEqual(result["valid_records"], 1)
            self.assertEqual(path.read_bytes(), replacement_bytes)

    def test_unchanged_file_still_reports_ok(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl",
                                secret=b"test-secret", key_id="test")
            store.append("first", "original")
            self.assertEqual(diagnose_authenticated(store)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
