"""Regression tests for privacy-preserving recovery diagnostics."""
import unittest
from datetime import datetime, timezone
from caos_recovery_diagnostics import make_recovery_event, emit_recovery_event


class RecoveryDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.clock = lambda: datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

    def test_allowlisted_fields_only(self):
        event = make_recovery_event({
            "status": "blocked", "reason": "source_stale",
            "secret_key": "DO_NOT_LEAK", "path": "/private/memory.jsonl",
            "exception": "sensitive exception",
        }, clock=self.clock)
        self.assertEqual(set(event), {
            "schema_version", "timestamp_utc", "component", "status",
            "reason", "automatic_repair_allowed"
        })
        self.assertNotIn("DO_NOT_LEAK", repr(event))
        self.assertNotIn("/private/", repr(event))

    def test_unknown_reason_is_normalized(self):
        event = make_recovery_event({"status": "blocked", "reason": "secret"}, clock=self.clock)
        self.assertEqual(event["reason"], "unrecognized_reason")

    def test_review_requires_all_invariants(self):
        valid = {"status": "review_required", "eligible_for_review": True,
                 "automatic_repair_allowed": False, "reason": "snapshot_and_source_verified"}
        self.assertEqual(make_recovery_event(valid, clock=self.clock)["status"], "review_required")
        valid["automatic_repair_allowed"] = True
        self.assertEqual(make_recovery_event(valid, clock=self.clock)["status"], "blocked")

    def test_sink_failure_is_contained(self):
        def broken(_):
            raise OSError("write failed")
        self.assertFalse(emit_recovery_event({"reason": "source_stale"}, broken, clock=self.clock))

    def test_sink_receives_sanitized_event(self):
        events = []
        self.assertTrue(emit_recovery_event({"reason": "invalid_input", "key": "secret"}, events.append, clock=self.clock))
        self.assertNotIn("secret", repr(events))
        self.assertEqual(len(events), 1)

    def test_naive_clock_rejected(self):
        with self.assertRaises(ValueError):
            make_recovery_event({}, clock=lambda: datetime(2026, 11, 5))


if __name__ == "__main__":
    unittest.main()
