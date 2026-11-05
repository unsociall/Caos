import sqlite3
import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from caos_sqlite_write_coordinator import guarded_sqlite_write, maintenance_lock

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "memory.sqlite"
        self.lock = Path(self.temp.name) / "memory.lock"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE memory (value INTEGER NOT NULL)")

    def values(self):
        with sqlite3.connect(self.db) as conn:
            return [row[0] for row in conn.execute("SELECT value FROM memory ORDER BY value")]

    def test_commit(self):
        self.assertEqual(guarded_sqlite_write(self.db, self.lock, lambda c: c.execute("INSERT INTO memory VALUES (?)", (4,))), 1)
        self.assertEqual(self.values(), [4])

    def test_rollback(self):
        def fail(cursor):
            cursor.execute("INSERT INTO memory VALUES (?)", (3,))
            raise RuntimeError("failure")
        with self.assertRaises(RuntimeError):
            guarded_sqlite_write(self.db, self.lock, fail)
        self.assertEqual(self.values(), [])

    def test_concurrent_writes(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: guarded_sqlite_write(self.db, self.lock, lambda c: c.execute("INSERT INTO memory VALUES (?)", (n,))), range(12)))
        self.assertEqual(self.values(), list(range(12)))

    def test_symlink_lock_rejected(self):
        target = Path(self.temp.name) / "target"
        target.touch()
        self.lock.symlink_to(target)
        with self.assertRaises(OSError):
            guarded_sqlite_write(self.db, self.lock, lambda c: None)

    def test_missing_database(self):
        with self.assertRaises(FileNotFoundError):
            guarded_sqlite_write(self.db.with_name("missing.db"), self.lock, lambda c: None)

    def test_timeout(self):
        with maintenance_lock(self.lock):
            with self.assertRaises(TimeoutError):
                guarded_sqlite_write(self.db, self.lock, lambda c: None, timeout=0.01)

if __name__ == "__main__":
    unittest.main()
