"""Regression tests for the read-only CAOS recovery eligibility gate."""
import unittest
from unittest.mock import patch
from caos_snapshot_recovery_gate import assess_snapshot_recovery

MODULE = "caos_snapshot_recovery_gate"


class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.store = object()
        self.source = {"status": "ok", "sha256": "a" * 64, "size_bytes": 2}
        self.receipt = {"status": "created"}
        self.key = b"k" * 32

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_both_verified_requires_review(self, snapshot, source):
        snapshot.return_value = {"verified": True, "authenticated": True}
        source.return_value = {"matches": True}
        result = assess_snapshot_recovery(self.store, self.source, self.receipt, self.key)
        self.assertEqual(result["status"], "review_required")
        self.assertTrue(result["eligible_for_review"])
        self.assertFalse(result["automatic_repair_allowed"])

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_bad_snapshot_never_reads_source(self, snapshot, source):
        snapshot.return_value = {"verified": False, "authenticated": False}
        result = assess_snapshot_recovery(self.store, self.source, self.receipt, self.key)
        self.assertEqual(result["reason"], "snapshot_not_verified")
        source.assert_not_called()

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_stale_source_blocks(self, snapshot, source):
        snapshot.return_value = {"verified": True, "authenticated": True}
        source.return_value = {"matches": False}
        self.assertEqual(assess_snapshot_recovery(
            self.store, self.source, self.receipt, self.key)["reason"], "source_stale")

    def test_invalid_input_blocks(self):
        result = assess_snapshot_recovery(self.store, None, self.receipt, self.key)
        self.assertFalse(result["eligible_for_review"])

    @patch(MODULE + ".verify_authenticated_snapshot", side_effect=OSError("unavailable"))
    def test_verifier_exception_blocks(self, _):
        result = assess_snapshot_recovery(self.store, self.source, self.receipt, self.key)
        self.assertEqual(result["reason"], "snapshot_verification_error")


if __name__ == "__main__":
    unittest.main()
