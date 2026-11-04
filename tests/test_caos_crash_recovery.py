"""Regression: kernel releases an abandoned POSIX sidecar lock after a crash.

All operations use a temporary memory store. A bounded subprocess prevents
an indefinitely blocked append from hanging the test suite.
"""
import multiprocessing as mp
import os
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore


def _crash_while_locked(lock_path, acquired):
    import fcntl
    fd = os.open(lock_path, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    acquired.set()
    os._exit(73)  # Deliberate child-only crash.


def _append_after_crash(path):
    store = MemoryStore(path, secret=b"x" * 32, key_id="test")
    store.append("after", "recoverable")


@unittest.skipUnless(os.name == "posix", "requires POSIX flock")
class CrashRecoveryTests(unittest.TestCase):
    def test_abandoned_sidecar_lock_is_released_on_process_exit(self):
        ctx = mp.get_context("spawn")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test")
            store.append("before", "preserved")
            acquired = ctx.Event()
            child = ctx.Process(
                target=_crash_while_locked,
                args=(str(path) + ".lock", acquired),
            )
            child.start()
            try:
                self.assertTrue(acquired.wait(10), "child never acquired lock")
                child.join(10)
                self.assertFalse(child.is_alive(), "crashing child did not exit")
                self.assertEqual(child.exitcode, 73)
            finally:
                if child.is_alive():
                    child.terminate()
                    child.join(5)

            writer = ctx.Process(target=_append_after_crash, args=(path,))
            writer.start()
            try:
                writer.join(10)
                self.assertFalse(
                    writer.is_alive(),
                    "append blocked after crash: sidecar lock not released",
                )
                self.assertEqual(writer.exitcode, 0, "recovery writer failed")
            finally:
                if writer.is_alive():
                    writer.terminate()
                    writer.join(5)

            records = store.read_all()
            self.assertEqual([r["id"] for r in records], ["before", "after"])


if __name__ == "__main__":
    unittest.main()
