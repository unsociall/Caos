"""Verify that a crashed writer cannot permanently strand the sidecar lock.

POSIX flock locks are released by the kernel when the process exits.
This test does not modify existing memory files or kill external processes.
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
    os._exit(73)  # Deliberate child-only crash: skip Python cleanup.


@unittest.skipUnless(os.name == "posix", "requires POSIX flock")
class CrashRecoveryTests(unittest.TestCase):
    def test_abandoned_sidecar_lock_is_released_on_process_exit(self):
        ctx = mp.get_context("spawn")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.jsonl"
            store = MemoryStore(path, secret=b"x" * 32, key_id="test")
            store.append("before", "preserved")
            lock_path = str(path) + ".lock"
            acquired = ctx.Event()
            child = ctx.Process(target=_crash_while_locked, args=(lock_path, acquired))
            child.start()
            try:
                self.assertTrue(acquired.wait(10), "child never acquired lock")
                child.join(10)
                self.assertFalse(child.is_alive(), "child did not exit")
                self.assertEqual(child.exitcode, 73)
                # An orphaned advisory lock would hang this append.
                store.append("after", "recoverable")
                records = store.read_all()
                self.assertEqual([r["id"] for r in records], ["before", "after"])
            finally:
                if child.is_alive():
                    child.terminate()
                    child.join(5)


if __name__ == "__main__":
    unittest.main()
