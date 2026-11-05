"""Regression tests: python -m unittest discover -s tests -p 'test_caos_sqlite_write_boundary.py'"""
import sqlite3
import unittest

from caos_sqlite_write_boundary import execute_guarded_callback


class WriteBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE memory (id INTEGER PRIMARY KEY, value TEXT)")
        self.db.execute("BEGIN IMMEDIATE")

    def tearDown(self):
        self.db.close()

    def test_parameterized_write(self):
        execute_guarded_callback(self.db, lambda w: w.execute(
            "INSERT INTO memory(value) VALUES (?)", ("safe",)))
        self.assertEqual(self.db.execute("SELECT value FROM memory").fetchone()[0], "safe")
        self.assertTrue(self.db.in_transaction)

    def test_no_transaction_controls(self):
        for sql in ("COMMIT", "ROLLBACK", "BEGIN", "PRAGMA journal_mode=WAL",
                    "INSERT INTO memory(value) VALUES ('x'); COMMIT",
                    "INSERT INTO memory(value) VALUES ('x') -- comment"):
            with self.subTest(sql=sql), self.assertRaises(ValueError):
                execute_guarded_callback(self.db, lambda w: w.execute(sql))

    def test_callback_cannot_commit_via_facade(self):
        with self.assertRaises(AttributeError):
            execute_guarded_callback(self.db, lambda w: w.commit())
        self.assertTrue(self.db.in_transaction)

    def test_requires_active_transaction(self):
        self.db.rollback()
        with self.assertRaises(RuntimeError):
            execute_guarded_callback(self.db, lambda w: None)

    def test_invalid_parameters(self):
        with self.assertRaises(TypeError):
            execute_guarded_callback(self.db, lambda w: w.execute(
                "INSERT INTO memory(value) VALUES (?)", {"value": "x"}))


if __name__ == "__main__":
    unittest.main()
