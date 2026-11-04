"""Regression: interrupted JSONL append must never be silently repaired."""
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryIntegrityError, MemoryStore


class InterruptedAppendTests(unittest.TestCase):
    def test_partial_tail_is_reported_and_append_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"a" * 32, key_id="key-v1")
            store.append("first", "intact")
            prefix = path.read_bytes()
            # Simulate a crash after a partial write, not a valid JSONL record.
            tail = b'{"id":"interrupted"'
            with path.open("ab") as stream:
                stream.write(tail)
            before = path.read_bytes()
            report = diagnose_authenticated(store)
            self.assertEqual(report["status"], "unterminated_tail")
            self.assertEqual(report["valid_records"], 1)
            self.assertEqual(report["valid_prefix_bytes"], len(prefix))
            self.assertEqual(report["error_offset"], len(prefix))
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(MemoryIntegrityError):
                store.append("second", "must not append")
            self.assertEqual(path.read_bytes(), before)

    def test_partial_first_record_blocks_append(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"b" * 32, key_id="key-v1")
            path.write_bytes(b'{"schema_version":1')
            before = path.read_bytes()
            report = diagnose_authenticated(store)
            self.assertEqual(report["status"], "unterminated_tail")
            self.assertEqual(report["valid_records"], 0)
            self.assertEqual(report["valid_prefix_bytes"], 0)
            self.assertEqual(report["error_offset"], 0)
            with self.assertRaises(MemoryIntegrityError):
                store.append("new", "blocked")
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
