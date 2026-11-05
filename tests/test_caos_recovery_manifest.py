"""Regression tests for read-only recovery evidence."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from caos_recovery_manifest import (
    build_recovery_manifest, validate_recovery_manifest, manifest_to_json
)


class RecoveryManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "memory.jsonl"
        self.path.write_bytes(b'{"example":1}\n')
        self.store = type("Store", (), {"path": self.path})()

    def test_roundtrip_unchanged(self):
        before = self.path.read_bytes()
        manifest = build_recovery_manifest(self.store)
        parsed = json.loads(manifest_to_json(manifest))
        result = validate_recovery_manifest(self.store, parsed)
        self.assertEqual(result["status"], "match")
        self.assertFalse(result["automatic_repair_allowed"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_equal_size_mutation_is_stale(self):
        manifest = build_recovery_manifest(self.store)
        self.path.write_bytes(b'{"example":2}\n')
        result = validate_recovery_manifest(self.store, manifest)
        self.assertEqual(result["status"], "stale")
        self.assertFalse(result["matches"])

    def test_malformed_and_future_schema_fail_closed(self):
        manifest = build_recovery_manifest(self.store)
        for candidate in (None, [], {}, {**manifest, "schema_version": 2},
                          {**manifest, "automatic_repair_allowed": True},
                          {**manifest, "fingerprint": []}):
            with self.subTest(candidate=candidate):
                result = validate_recovery_manifest(self.store, candidate)
                self.assertEqual(result["status"], "invalid_manifest")
                self.assertFalse(result["automatic_repair_allowed"])


if __name__ == "__main__":
    unittest.main()
