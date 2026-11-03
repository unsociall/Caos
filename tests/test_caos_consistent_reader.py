import concurrent.futures
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore, MemoryIntegrityError
from caos_consistent_reader import read_consistent


class ConsistentReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "memory.jsonl"
        self.store = MemoryStore(self.path, secret=b"x" * 32, key_id="test-key")

    def test_missing_file_not_created(self):
        self.assertEqual(read_consistent(self.store), [])
        self.assertFalse(self.path.exists())

    def test_roundtrip(self):
        self.store.append("one", "Olá")
        self.assertEqual(read_consistent(self.store)[0]["content"], "Olá")

    def test_corrupt_tail_fails_closed(self):
        self.store.append("one", "valid")
        with self.path.open("ab") as f:
            f.write(b'{"id":')
        with self.assertRaises(MemoryIntegrityError):
            read_consistent(self.store)

    def test_store_read_all_delegates_to_locked_reader(self):
        self.store.append("one", "first")
        self.assertEqual(self.store.read_all(), read_consistent(self.store))
        self.assertEqual(self.store.read_all()[0]["id"], "one")

    def test_store_read_all_rejects_corrupt_tail(self):
        self.store.append("one", "valid")
        with self.path.open("ab") as stream:
            stream.write(b'{"partial":')
        with self.assertRaises(MemoryIntegrityError):
            self.store.read_all()

    def test_concurrent_readers_and_writer(self):
        def write(i):
            self.store.append(str(i), "value")
        def read(_):
            return len(read_consistent(self.store))
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(write, i) for i in range(25)]
            futures += [pool.submit(read, i) for i in range(25)]
            for future in futures:
                future.result()
        self.assertEqual(len(read_consistent(self.store)), 25)


if __name__ == "__main__":
    unittest.main()
