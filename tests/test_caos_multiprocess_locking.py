"""Cross-process regression tests for cooperative CAOS JSONL locking.

Run: python -m unittest tests/test_caos_multiprocess_locking.py
No persistent user files are touched.
"""
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore


def _writer(path, start, count, gate, output):
    try:
        store = MemoryStore(path, secret=b"x" * 32, key_id="test-key")
        if not gate.wait(10):
            raise TimeoutError("start gate timed out")
        for i in range(start, start + count):
            store.append(str(i), "value")
        output.put(None)
    except BaseException as exc:
        output.put(repr(exc))



def _reader(path, gate, output, attempts):
    try:
        store = MemoryStore(path, secret=b"x" * 32, key_id="test-key")
        if not gate.wait(10):
            raise TimeoutError("start gate timed out")
        observed = []
        for _ in range(attempts):
            snapshot = store.read_all()
            ids = [record["id"] for record in snapshot]
            if len(ids) != len(set(ids)):
                raise AssertionError("duplicate record in snapshot")
            observed.append(len(ids))
            time.sleep(0.002)
        output.put(("reader", observed))
    except BaseException as exc:
        output.put(("error", repr(exc)))


class MultiprocessLockingTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX locking regression")
    def test_independent_process_writers(self):
        ctx = mp.get_context("spawn")
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "memory.jsonl")
            gate = ctx.Event()
            output = ctx.Queue()
            workers = [
                ctx.Process(target=_writer, args=(path, i * 30, 30, gate, output))
                for i in range(4)
            ]
            for worker in workers:
                worker.start()
            try:
                gate.set()
                for worker in workers:
                    worker.join(30)
                for worker in workers:
                    self.assertFalse(worker.is_alive(), "writer timed out")
                    self.assertEqual(worker.exitcode, 0)
                self.assertEqual([output.get(timeout=3) for _ in workers], [None] * 4)
                records = MemoryStore(path, secret=b"x" * 32, key_id="test-key").read_all()
                self.assertEqual(len(records), 120)
                self.assertEqual({record["id"] for record in records}, {str(i) for i in range(120)})
            finally:
                for worker in workers:
                    if worker.is_alive():
                        worker.terminate()
                        worker.join(5)


    @unittest.skipUnless(os.name == "posix", "POSIX locking regression")
    def test_reader_writer_process_snapshots(self):
        ctx = mp.get_context("spawn")
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "memory.jsonl")
            MemoryStore(path, secret=b"x" * 32, key_id="test-key").append("seed", "value")
            gate = ctx.Event()
            output = ctx.Queue()
            workers = [
                ctx.Process(target=_writer, args=(path, i * 20, 20, gate, output))
                for i in range(2)
            ]
            readers = [
                ctx.Process(target=_reader, args=(path, gate, output, 35))
                for _ in range(2)
            ]
            processes = workers + readers
            for process in processes:
                process.start()
            try:
                gate.set()
                results = [output.get(timeout=35) for _ in processes]
                for process in processes:
                    process.join(10)
                    self.assertEqual(process.exitcode, 0)
                self.assertEqual(results.count(None), 2)
                samples = [value for kind, value in results if kind == "reader"]
                self.assertEqual(len(samples), 2)
                for sample in samples:
                    self.assertEqual(len(sample), 35)
                    self.assertTrue(all(1 <= size <= 41 for size in sample))
                    self.assertEqual(sample, sorted(sample))
                records = MemoryStore(path, secret=b"x" * 32, key_id="test-key").read_all()
                self.assertEqual(len(records), 41)
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(5)


if __name__ == "__main__":
    unittest.main()
