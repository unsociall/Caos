import json
import concurrent.futures
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryIntegrityError, MemoryStore


class MemoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "memory.jsonl"
        self.secret = b"x" * 32
        self.store = MemoryStore(self.path, secret=self.secret, key_id="test-key")

    def test_append_roundtrip_and_unicode(self):
        self.store.append("a", "Olá 🌌")
        self.store.append("b", "second")
        records = self.store.read_all()
        self.assertEqual([r["content"] for r in records], ["Olá 🌌", "second"])

    def test_empty_store_does_not_create_file(self):
        self.assertEqual(self.store.read_all(), [])
        self.assertFalse(self.path.exists())

    def test_tampering_fails_closed(self):
        self.store.append("a", "original")
        data = json.loads(self.path.read_text())
        data["content"] = "tampered"
        self.path.write_text(json.dumps(data) + "\n")
        with self.assertRaises(MemoryIntegrityError):
            self.store.read_all()

    def test_wrong_key_fails_closed(self):
        self.store.append("a", "original")
        with self.assertRaises(MemoryIntegrityError):
            self.store.read_all(keys={"test-key": b"y" * 32})

    def test_truncated_line_fails_closed(self):
        self.path.write_text('{"id":')
        with self.assertRaises(MemoryIntegrityError):
            self.store.read_all()

    def test_complete_json_without_newline_is_not_committed(self):
        self.store.append("a", "complete")
        self.path.write_bytes(self.path.read_bytes().rstrip(b"\n"))
        with self.assertRaisesRegex(MemoryIntegrityError, "unterminated record"):
            self.store.read_all()

    def test_append_rejects_unterminated_tail_without_modifying_file(self):
        self.store.append("a", "first")
        self.path.write_bytes(self.path.read_bytes().rstrip(b"\n"))
        before = self.path.read_bytes()
        with self.assertRaisesRegex(MemoryIntegrityError, "unterminated tail"):
            self.store.append("b", "second")
        self.assertEqual(self.path.read_bytes(), before)

    def test_append_accepts_existing_complete_tail(self):
        self.store.append("a", "first")
        self.store.append("b", "second")
        self.assertEqual(len(self.store.read_all()), 2)

    def test_invalid_utf8_is_rejected(self):
        self.path.write_bytes(bytes([0xff, 0x0a]))
        with self.assertRaisesRegex(MemoryIntegrityError, "invalid UTF-8"):
            self.store.read_all()

    def test_existing_file_not_overwritten(self):
        self.store.append("a", "first")
        before = self.path.read_bytes()
        self.store.append("b", "second")
        self.assertTrue(self.path.read_bytes().startswith(before))

    def test_concurrent_writers_preserve_all_records(self):
        def write_one(i):
            MemoryStore(self.path, secret=self.secret, key_id="test-key").append(str(i), f"value-{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write_one, range(40)))
        records = self.store.read_all()
        self.assertEqual(len(records), 40)
        self.assertEqual({r["id"] for r in records}, {str(i) for i in range(40)})

    def test_invalid_key_rejected(self):
        with self.assertRaises(ValueError):
            MemoryStore(self.path, secret=b"short", key_id="test")


if __name__ == "__main__":
    unittest.main()
