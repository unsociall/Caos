"""Regression tests for the stable writer-sidecar lock."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import caos_memory_store
from caos_memory_store import MemoryStore


class SidecarLockTests(unittest.TestCase):
    def test_append_creates_persistent_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test-key")
            store.append("one", "a")
            sidecar = path.with_name(path.name + ".lock")
            self.assertTrue(sidecar.is_file())
            inode = sidecar.stat().st_ino
            store.append("two", "b")
            self.assertEqual(sidecar.stat().st_ino, inode)
            self.assertEqual(len(store.read_all()), 2)

    def test_writer_holds_sidecar_before_opening_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test-key")
            original = caos_memory_store.os.open
            opened = []

            def spy_open(p, flags, *args, **kwargs):
                opened.append(str(p))
                return original(p, flags, *args, **kwargs)

            with patch.object(caos_memory_store.os, "open", side_effect=spy_open):
                store.append("one", "a")
            self.assertEqual(opened[:2], [str(path) + ".lock", str(path)])


if __name__ == "__main__":
    unittest.main()
