"""Regression tests for path replacement during a CAOS append."""
import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import caos_memory_store
from caos_memory_store import MemoryIntegrityError, MemoryStore


class PathReplacementTests(unittest.TestCase):
    def test_replaced_path_is_rejected_without_writing_old_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            detached = Path(tmp) / "detached.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test-key")
            store.append("seed", "original")
            original = path.read_bytes()
            real_lock = caos_memory_store._exclusive_lock

            @contextlib.contextmanager
            def replace_after_lock(fd):
                with real_lock(fd):
                    path.rename(detached)
                    path.write_bytes(b"replacement\\n")
                    yield

            with patch.object(caos_memory_store, "_exclusive_lock", replace_after_lock):
                with self.assertRaisesRegex(MemoryIntegrityError, "path replaced"):
                    store.append("next", "must not write")
            self.assertEqual(detached.read_bytes(), original)
            self.assertEqual(path.read_bytes(), b"replacement\\n")

    def test_normal_append_still_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MemoryStore(Path(tmp) / "memory.jsonl",
                                secret=b"x" * 32, key_id="test-key")
            store.append("one", "a")
            store.append("two", "b")
            self.assertEqual([r["id"] for r in store.read_all()], ["one", "two"])


if __name__ == "__main__":
    unittest.main()
