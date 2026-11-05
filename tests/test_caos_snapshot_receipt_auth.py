"""Regression tests for authenticated CAOS snapshot receipts."""
import copy
import unittest

from caos_snapshot_receipt_auth import (
    sign_snapshot_receipt, verify_signed_snapshot_receipt,
)


class ReceiptAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.key = b"K" * 32
        self.receipt = {
            "status": "created", "usable": True,
            "snapshot_path": "/tmp/caos-snapshot.jsonl",
            "size_bytes": 12, "sha256": "a" * 64,
        }

    def test_roundtrip_does_not_mutate_input(self):
        original = copy.deepcopy(self.receipt)
        signed = sign_snapshot_receipt(self.receipt, self.key)
        self.assertTrue(verify_signed_snapshot_receipt(signed, self.key))
        self.assertEqual(self.receipt, original)
        self.assertFalse(signed["automatic_repair_allowed"])

    def test_tampering_is_rejected(self):
        signed = sign_snapshot_receipt(self.receipt, self.key)
        for field, value in (("size_bytes", 13), ("sha256", "b" * 64),
                             ("snapshot_path", "/tmp/other")):
            altered = copy.deepcopy(signed)
            altered[field] = value
            self.assertFalse(verify_signed_snapshot_receipt(altered, self.key))

    def test_wrong_key_and_malformed_auth(self):
        signed = sign_snapshot_receipt(self.receipt, self.key)
        self.assertFalse(verify_signed_snapshot_receipt(signed, b"Z" * 32))
        signed["authentication"]["version"] = True
        self.assertFalse(verify_signed_snapshot_receipt(signed, self.key))

    def test_invalid_key_and_receipt(self):
        with self.assertRaises(ValueError):
            sign_snapshot_receipt(self.receipt, b"short")
        self.assertFalse(verify_signed_snapshot_receipt({}, self.key))
        self.assertFalse(verify_signed_snapshot_receipt(self.receipt, b"short"))


if __name__ == "__main__":
    unittest.main()
