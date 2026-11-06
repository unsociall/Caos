import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from caos_sqlite_integrity_gate import inspect_memory_database
from caos_sqlite_write_coordinator import guarded_sqlite_write, maintenance_lock


class IntegrityGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "memory.db"
        self.lock = Path(self.tmp.name) / "maintenance.lock"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE memory (value TEXT)")

    def test_valid_db(self):
        result = inspect_memory_database(self.db, self.lock)
        self.assertTrue(result["ok"])
        self.assertEqual(result["diagnostics"], ["ok"])

    def test_missing_db(self):
        with self.assertRaises(FileNotFoundError):
            inspect_memory_database(self.db.with_name("missing.db"), self.lock)

    def test_symlink_db(self):
        alias = self.db.with_name("alias.db")
        alias.symlink_to(self.db)
        with self.assertRaises(FileNotFoundError):
            inspect_memory_database(alias, self.lock)

    def test_waits_for_writer(self):
        ready = threading.Event()
        release = threading.Event()

        def writer():
            with maintenance_lock(self.lock):
                ready.set()
                release.wait(2)

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            self.assertTrue(ready.wait(2))
            with self.assertRaises(TimeoutError):
                inspect_memory_database(self.db, self.lock, timeout=0.03)
        finally:
            release.set()
            thread.join()

    def test_write_then_check(self):
        guarded_sqlite_write(
            self.db, self.lock,
            lambda cur: cur.execute("INSERT INTO memory(value) VALUES (?)", ("x",))
        )
        self.assertTrue(inspect_memory_database(self.db, self.lock)["ok"])
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM memory").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
