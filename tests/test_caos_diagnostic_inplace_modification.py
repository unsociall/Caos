"""Regression tests for in-place changes during authenticated memory scans."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import caos_authenticated_diagnostic as diagnostic
from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore


class InPlaceModificationTests(unittest.TestCase):
    def test_in_place_append_during_scan_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("first", "original")
            original_verify = diagnostic.verify_authenticated
            changed = False

            def append_after_validation(record, *, keys):
                nonlocal changed
                result = original_verify(record, keys=keys)
                if not changed:
                    with path.open("ab") as stream:
                        stream.write(b"unverified-extra-record\\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    changed = True
                return result

            with patch.object(diagnostic, "verify_authenticated",
                              side_effect=append_after_validation):
                result = diagnose_authenticated(store)
            self.assertTrue(changed)
            # The extra line is invalid, so the scanner may reject it before
            # reaching EOF; both outcomes must refuse a clean result.
            self.assertNotEqual(result["status"], "ok")

    def test_same_inode_timestamp_change_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("first", "original")
            original_verify = diagnostic.verify_authenticated

            def touch_after_validation(record, *, keys):
                result = original_verify(record, keys=keys)
                stat = path.stat()
                os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))
                return result

            with patch.object(diagnostic, "verify_authenticated",
                              side_effect=touch_after_validation):
                result = diagnose_authenticated(store)
            self.assertEqual(result["status"], "file_modified")

    def test_unchanged_file_is_ok(self):
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryStore(Path(directory) / "memory.jsonl",
                                secret=b"test-secret", key_id="test")
            store.append("first", "original")
            self.assertEqual(diagnose_authenticated(store)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
