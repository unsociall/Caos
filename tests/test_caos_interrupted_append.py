"""Regression tests for interrupted JSONL writes; never repair data implicitly."""
import os
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryIntegrityError, MemoryStore


class InterruptedAppendTests(unittest.TestCase):
    def test_partial_tail_blocks_future_appends_without_mutating_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test")
            store.append("before", "preserved")
            with path.open("ab") as stream:
                stream.write(b'{"id":"interrupted"')
                stream.flush()
                os.fsync(stream.fileno())
            damaged = path.read_bytes()
            with self.assertRaisesRegex(MemoryIntegrityError, "unterminated tail"):
                store.append("after", "must not be written")
            self.assertEqual(path.read_bytes(), damaged)
            self.assertTrue(damaged.startswith(b'{"') or b'"before"' in damaged)

    def test_complete_record_remains_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test")
            store.append("before", "preserved")
            self.assertEqual([r["id"] for r in store.read_all()], ["before"])


if __name__ == "__main__":
    unittest.main()
