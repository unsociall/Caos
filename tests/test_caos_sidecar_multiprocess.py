"""Cross-process regression for sidecar reader/writer coordination (POSIX)."""
import multiprocessing as mp
import os
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore


def _hold_writer_lock(path, acquired, release):
    import fcntl
    fd = os.open(str(path) + ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        acquired.set()
        if not release.wait(10):
            raise TimeoutError("parent did not release writer lock")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_worker(path, started, finished, result):
    store = MemoryStore(path, secret=b"x" * 32, key_id="test")
    started.set()
    try:
        result.put(("ok", len(store.read_all())))
    except Exception as exc:
        result.put(("error", repr(exc)))
    finally:
        finished.set()


@unittest.skipUnless(os.name == "posix", "requires POSIX flock")
class SidecarMultiprocessTests(unittest.TestCase):
    def test_reader_waits_for_writer_sidecar_lock(self):
        ctx = mp.get_context("spawn")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            MemoryStore(path, secret=b"x" * 32, key_id="test").append("one", "value")
            acquired, release = ctx.Event(), ctx.Event()
            started, finished = ctx.Event(), ctx.Event()
            result = ctx.Queue()
            writer = ctx.Process(target=_hold_writer_lock, args=(path, acquired, release))
            reader = None
            try:
                writer.start()
                self.assertTrue(acquired.wait(10), "writer did not acquire sidecar")
                reader = ctx.Process(target=_read_worker, args=(path, started, finished, result))
                reader.start()
                self.assertTrue(started.wait(10), "reader did not start")
                self.assertFalse(finished.wait(0.3), "reader bypassed writer sidecar")
            finally:
                release.set()
                if reader is not None:
                    reader.join(10)
                    if reader.is_alive():
                        reader.terminate()
                        reader.join()
                writer.join(10)
                if writer.is_alive():
                    writer.terminate()
                    writer.join()
            self.assertEqual(writer.exitcode, 0)
            self.assertIsNotNone(reader)
            self.assertEqual(reader.exitcode, 0)
            self.assertEqual(result.get(timeout=2), ("ok", 1))


if __name__ == "__main__":
    unittest.main()
