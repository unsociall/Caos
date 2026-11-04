"""Regression: authenticated diagnostic must wait for cooperative writers."""
import multiprocessing as mp
import os
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore, _exclusive_lock
from caos_authenticated_diagnostic import diagnose_authenticated


def _hold_sidecar(path, ready, release):
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with _exclusive_lock(fd):
            ready.set()
            if not release.wait(10):
                raise TimeoutError("test coordinator did not release sidecar")
    finally:
        os.close(fd)


def _diagnose(path, started, output):
    store = MemoryStore(path, secret=b"test-secret", key_id="test")
    started.set()
    output.put(diagnose_authenticated(store))


@unittest.skipIf(os.name == "nt", "POSIX flock semantics required")
class AuthenticatedDiagnosticConcurrencyTests(unittest.TestCase):
    def test_diagnostic_waits_for_sidecar_release(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"test-secret", key_id="test")
            store.append("first", "original")
            ctx = mp.get_context("spawn")
            ready, release, started = (ctx.Event() for _ in range(3))
            output = ctx.Queue()
            holder = ctx.Process(target=_hold_sidecar, args=(path, ready, release))
            reader = ctx.Process(target=_diagnose, args=(path, started, output))
            try:
                holder.start()
                self.assertTrue(ready.wait(5), "holder failed to acquire lock")
                reader.start()
                self.assertTrue(started.wait(5), "diagnostic process did not start")
                # Reader cannot complete while holder owns exclusive lock.
                with self.assertRaises(__import__("queue").Empty):
                    output.get(timeout=0.3)
                release.set()
                result = output.get(timeout=8)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["valid_records"], 1)
                reader.join(5)
                holder.join(5)
                self.assertEqual(reader.exitcode, 0)
                self.assertEqual(holder.exitcode, 0)
            finally:
                release.set()
                for proc in (reader, holder):
                    if proc.pid is not None and proc.is_alive():
                        proc.terminate()
                    if proc.pid is not None:
                        proc.join(5)


if __name__ == "__main__":
    unittest.main()
