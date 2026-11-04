"""Regression: diagnostic reads the replacement after a cooperative atomic swap."""
import multiprocessing as mp
import os
import queue
import tempfile
import unittest
from pathlib import Path

from caos_authenticated_diagnostic import diagnose_authenticated
from caos_memory_store import MemoryStore, _exclusive_lock


def _replace_under_lock(path, ready, release):
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with _exclusive_lock(fd):
            ready.set()
            if not release.wait(10):
                raise TimeoutError("replacement coordinator timeout")
            os.replace(str(path) + ".replacement", path)
    finally:
        os.close(fd)


def _run_diagnostic(path, started, result):
    try:
        store = MemoryStore(path, secret=b"test-secret", key_id="test")
        started.set()
        result.put(("ok", diagnose_authenticated(store)))
    except Exception as exc:
        result.put(("error", repr(exc)))


@unittest.skipIf(os.name == "nt", "POSIX advisory locking regression")
class DiagnosticReplacementTests(unittest.TestCase):
    def test_diagnostic_sees_replacement_after_lock_release(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            original = MemoryStore(path, secret=b"test-secret", key_id="test")
            original.append("old", "before")
            replacement_path = Path(str(path) + ".replacement")
            replacement = MemoryStore(replacement_path, secret=b"test-secret", key_id="test")
            replacement.append("new1", "after")
            replacement.append("new2", "after")
            replacement_bytes = replacement_path.read_bytes()
            ctx = mp.get_context("spawn")
            ready, release, started = (ctx.Event() for _ in range(3))
            results = ctx.Queue()
            writer = ctx.Process(target=_replace_under_lock, args=(path, ready, release))
            reader = ctx.Process(target=_run_diagnostic, args=(path, started, results))
            try:
                writer.start()
                self.assertTrue(ready.wait(5), "writer did not acquire sidecar")
                reader.start()
                self.assertTrue(started.wait(5), "reader did not start")
                with self.assertRaises(queue.Empty):
                    results.get(timeout=0.3)
                release.set()
                kind, result = results.get(timeout=8)
                self.assertEqual(kind, "ok", result)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["valid_records"], 2)
                self.assertEqual(result["valid_prefix_bytes"], len(replacement_bytes))
                self.assertEqual(path.read_bytes(), replacement_bytes)
                writer.join(5)
                reader.join(5)
                self.assertEqual(writer.exitcode, 0)
                self.assertEqual(reader.exitcode, 0)
            finally:
                release.set()
                for process in (reader, writer):
                    if process.pid is not None and process.is_alive():
                        process.terminate()
                    if process.pid is not None:
                        process.join(5)


if __name__ == "__main__":
    unittest.main()
