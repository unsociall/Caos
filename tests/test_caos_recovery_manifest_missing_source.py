"""Regression coverage for recovery manifests when source memory disappears.

These tests never restore or truncate memory.
"""
import tempfile
import unittest
from pathlib import Path

from caos_recovery_manifest import build_recovery_manifest, validate_recovery_manifest


class RecoveryManifestMissingSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "memory.jsonl"
        self.store = type("Store", (), {"path": self.path})()

    def test_missing_source_manifest_cannot_be_validated(self):
        manifest = build_recovery_manifest(self.store)
        self.assertEqual(manifest["fingerprint"]["status"], "missing")
        result = validate_recovery_manifest(self.store, manifest)
        self.assertEqual(result["status"], "invalid_precondition")
        self.assertFalse(result["matches"])
        self.assertFalse(result["automatic_repair_allowed"])
        self.assertFalse(self.path.exists())

    def test_source_removed_after_manifest_is_stale(self):
        self.path.write_bytes(b'{"id":1}\n')
        manifest = build_recovery_manifest(self.store)
        self.path.unlink()
        result = validate_recovery_manifest(self.store, manifest)
        self.assertEqual(result["status"], "stale")
        self.assertFalse(result["matches"])
        self.assertFalse(result["automatic_repair_allowed"])
        self.assertFalse(self.path.exists())

    def test_source_created_after_missing_manifest_remains_invalid(self):
        manifest = build_recovery_manifest(self.store)
        self.path.write_bytes(b'{"id":2}\n')
        before = self.path.read_bytes()
        result = validate_recovery_manifest(self.store, manifest)
        self.assertEqual(result["status"], "invalid_precondition")
        self.assertFalse(result["matches"])
        self.assertFalse(result["automatic_repair_allowed"])
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
