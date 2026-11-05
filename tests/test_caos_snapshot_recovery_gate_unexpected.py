"""Unexpected verifier errors must never authorize recovery."""
import unittest
from unittest.mock import patch
from caos_snapshot_recovery_gate import assess_snapshot_recovery

MODULE = "caos_snapshot_recovery_gate"


class UnexpectedVerifierErrorTests(unittest.TestCase):
    def setUp(self):
        self.args = (object(), {"status": "ok"}, {"receipt": True}, b"key")

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_snapshot_unexpected_error_blocks_before_source(self, snapshot, source):
        snapshot.side_effect = RuntimeError("unexpected backend failure")
        result = assess_snapshot_recovery(*self.args)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "snapshot_verification_error")
        self.assertIs(result["eligible_for_review"], False)
        self.assertIs(result["automatic_repair_allowed"], False)
        source.assert_not_called()

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_source_unexpected_error_blocks(self, snapshot, source):
        snapshot.return_value = {"verified": True, "authenticated": True}
        source.side_effect = RuntimeError("unexpected backend failure")
        result = assess_snapshot_recovery(*self.args)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "source_verification_error")
        self.assertIs(result["eligible_for_review"], False)
        self.assertIs(result["automatic_repair_allowed"], False)


if __name__ == "__main__":
    unittest.main()
