"""Fail-closed tests for malformed recovery verifier responses."""
import unittest
from unittest.mock import patch
from caos_snapshot_recovery_gate import assess_snapshot_recovery

MODULE = "caos_snapshot_recovery_gate"


class MalformedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.args = (object(), {"status": "ok"}, {"receipt": True}, b"key")

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_malformed_snapshot_response_blocks_before_source(self, snapshot, source):
        for value in (None, [], True, "verified", 1):
            with self.subTest(value=value):
                snapshot.return_value = value
                result = assess_snapshot_recovery(*self.args)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["reason"], "snapshot_not_verified")
                self.assertFalse(result["automatic_repair_allowed"])
        source.assert_not_called()

    @patch(MODULE + ".verify_recovery_precondition")
    @patch(MODULE + ".verify_authenticated_snapshot")
    def test_malformed_source_response_blocks(self, snapshot, source):
        snapshot.return_value = {"verified": True, "authenticated": True}
        for value in (None, [], True, "match", 1):
            with self.subTest(value=value):
                source.return_value = value
                result = assess_snapshot_recovery(*self.args)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["reason"], "source_stale")
                self.assertFalse(result["eligible_for_review"])


if __name__ == "__main__":
    unittest.main()
