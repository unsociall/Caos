"""Regression tests for opt-in, non-overwriting memory snapshots."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from caos_memory_snapshot import create_memory_snapshot


class MemorySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "memory.jsonl"
        self.payload = b'{"record":1}\n'
        self.source.write_bytes(self.payload)
        self.store = type("Store", (), {"path": self.source})()
        self.destination = Path(self.tmp.name) / "snapshot.jsonl"

    def test_snapshot_copies_bytes_without_modifying_source(self):
        result = create_memory_snapshot(self.store, self.destination)
        self.assertEqual(result["status"], "created")
        self.assertTrue(result["usable"])
        self.assertFalse(result["automatic_repair_allowed"])
        self.assertEqual(self.destination.read_bytes(), self.payload)
        self.assertEqual(self.source.read_bytes(), self.payload)
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())

    def test_existing_destination_is_never_overwritten(self):
        self.destination.write_bytes(b"protected")
        with self.assertRaises(FileExistsError):
            create_memory_snapshot(self.store, self.destination)
        self.assertEqual(self.destination.read_bytes(), b"protected")
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_source_as_destination_is_rejected(self):
        with self.assertRaises(ValueError):
            create_memory_snapshot(self.store, self.source)
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_missing_source_does_not_create_snapshot(self):
        self.source.unlink()
        with self.assertRaises(FileNotFoundError):
            create_memory_snapshot(self.store, self.destination)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
