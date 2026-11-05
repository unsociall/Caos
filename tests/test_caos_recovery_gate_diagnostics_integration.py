"""Regression tests for optional privacy-safe recovery diagnostics."""
import unittest
from unittest.mock import patch
from caos_snapshot_recovery_gate import assess_snapshot_recovery


class RecoveryGateDiagnosticsTests(unittest.TestCase):
    def test_success_emits_sanitized_event(self):
        events = []
        with patch("caos_snapshot_recovery_gate.verify_authenticated_snapshot",
                   return_value={"verified": True, "authenticated": True}), \
             patch("caos_snapshot_recovery_gate.verify_recovery_precondition",
                   return_value={"matches": True}):
            result = assess_snapshot_recovery(None, {"secret": "source-secret"},
                                              {"secret": "receipt-secret"}, b"key",
                                              diagnostic_sink=events.append)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["reason"], "snapshot_and_source_verified")
        self.assertNotIn("source-secret", str(events))
        self.assertNotIn("receipt-secret", str(events))

    def test_failed_sink_does_not_change_decision(self):
        def broken(_event):
            raise RuntimeError("sink unavailable")
        result = assess_snapshot_recovery(None, None, {}, b"key",
                                          diagnostic_sink=broken)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["automatic_repair_allowed"])

    def test_verifier_exception_emits_blocked(self):
        events = []
        with patch("caos_snapshot_recovery_gate.verify_authenticated_snapshot",
                   side_effect=RuntimeError("sensitive details")):
            result = assess_snapshot_recovery(None, {}, {}, b"key",
                                              diagnostic_sink=events.append)
        self.assertEqual(result["reason"], "snapshot_verification_error")
        self.assertEqual(events[0]["status"], "blocked")
        self.assertNotIn("sensitive details", str(events))


if __name__ == "__main__":
    unittest.main()
