"""Regression tests for reader/writer sidecar coordination."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import caos_consistent_reader
from caos_memory_store import MemoryStore


class ReaderSidecarTests(unittest.TestCase):
    def test_missing_memory_does_not_create_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test")
            self.assertEqual(store.read_all(), [])
            self.assertFalse(Path(str(path) + ".lock").exists())

    def test_reader_opens_sidecar_before_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test")
            store.append("one", "value")
            original = caos_consistent_reader.os.open
            opened = []

            def spy_open(p, flags, *args, **kwargs):
                opened.append(str(p))
                return original(p, flags, *args, **kwargs)

            with patch.object(caos_consistent_reader.os, "open", side_effect=spy_open):
                self.assertEqual(len(store.read_all()), 1)
            self.assertEqual(opened[:2], [str(path) + ".lock", str(path)])


if __name__ == "__main__":
    unittest.main()
