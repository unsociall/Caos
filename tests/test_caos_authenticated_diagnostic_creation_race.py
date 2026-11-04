"""Regression: missing memory is checked only after acquiring the sidecar lock."""
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore, _exclusive_lock
from caos_authenticated_diagnostic import diagnose_authenticated


def _diagnose_worker(path, started, finished, results):
    store = MemoryStore(path, secret=b"test-secret", key_id="test")
    started.set()
    try:
        results.put(diagnose_authenticated(store))
    finally:
        finished.set()


class ConcurrentCreationTests(unittest.TestCase):
    def test_creation_while_diagnostic_waits_for_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "memory.jsonl"
            fixture = MemoryStore(root / "fixture.jsonl", secret=b"test-secret", key_id="test")
            fixture.append("one", "created under lock")
            fixture_bytes = fixture.path.read_bytes()
            lock_path = path.with_name(path.name + ".lock")
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            ctx = mp.get_context("spawn")
            started = ctx.Event()
            finished = ctx.Event()
            results = ctx.Queue()
            worker = None
            try:
                with _exclusive_lock(lock_fd):
                    worker = ctx.Process(target=_diagnose_worker, args=(str(path), started, finished, results))
                    worker.start()
                    self.assertTrue(started.wait(10), "worker did not start")
                    # Allow the child to reach the lock; it must not finish yet.
                    time.sleep(0.3)
                    self.assertFalse(finished.is_set(), "diagnostic returned before lock release")
                    with path.open("xb") as target:
                        target.write(fixture_bytes)
                        target.flush()
                        os.fsync(target.fileno())
                worker.join(10)
                self.assertFalse(worker.is_alive(), "diagnostic hung after lock release")
                self.assertEqual(worker.exitcode, 0)
                self.assertTrue(finished.is_set(), "worker did not signal completion")
                outcome = results.get(timeout=3)
                self.assertEqual(outcome["status"], "ok")
                self.assertEqual(outcome["valid_records"], 1)
                self.assertEqual(path.read_bytes(), fixture_bytes)
            finally:
                if worker is not None and worker.is_alive():
                    worker.terminate()
                    worker.join(5)
                os.close(lock_fd)


if __name__ == "__main__":
    unittest.main()
