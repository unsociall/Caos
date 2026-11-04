"""Recovery planning must fail closed and never rewrite original bytes."""
import tempfile
import unittest
from pathlib import Path

from caos_memory_store import MemoryStore
from caos_recovery_plan import plan_authenticated_recovery


class RecoveryPlanTests(unittest.TestCase):
    def test_incomplete_tail_requires_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"a" * 32, key_id="v1")
            store.append("first", "intact")
            prefix = path.read_bytes()
            path.write_bytes(prefix + b'{"id":"partial"')
            before = path.read_bytes()
            plan = plan_authenticated_recovery(store)
            self.assertTrue(plan["manual_review_eligible"])
            self.assertFalse(plan["automatic_repair_allowed"])
            self.assertEqual(plan["diagnostic"]["valid_prefix_bytes"], len(prefix))
            self.assertEqual(path.read_bytes(), before)

    def test_partial_first_record_is_not_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"b" * 32, key_id="v1")
            path.write_bytes(b'{"id":"partial"')
            before = path.read_bytes()
            plan = plan_authenticated_recovery(store)
            self.assertFalse(plan["manual_review_eligible"])
            self.assertEqual(path.read_bytes(), before)

    def test_wrong_key_blocks_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"c" * 32, key_id="v1")
            store.append("first", "intact")
            path.write_bytes(path.read_bytes() + b'{"id":"partial"')
            before = path.read_bytes()
            plan = plan_authenticated_recovery(store, keys={"v1": b"d" * 32})
            self.assertFalse(plan["manual_review_eligible"])
            self.assertEqual(plan["diagnostic"]["status"], "invalid_or_unauthenticated")
            self.assertEqual(path.read_bytes(), before)

    def test_clean_memory_does_not_need_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.jsonl"
            store = MemoryStore(path, secret=b"e" * 32, key_id="v1")
            store.append("first", "intact")
            before = path.read_bytes()
            plan = plan_authenticated_recovery(store)
            self.assertFalse(plan["manual_review_eligible"])
            self.assertEqual(plan["diagnostic"]["status"], "ok")
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
