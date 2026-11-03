import unittest

from caos_integrity import digest, seal, verify


class MemoryIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.record = {"id": "mem-1", "content": "Olá, CAOS", "schema_version": 1}

    def test_valid_record(self):
        self.assertTrue(verify(seal(self.record)))

    def test_tampered_content(self):
        sealed = seal(self.record)
        sealed["content"] = "alterado"
        self.assertFalse(verify(sealed))

    def test_missing_hash(self):
        self.assertFalse(verify(self.record))

    def test_unsupported_schema(self):
        sealed = seal(self.record)
        sealed["schema_version"] = 2
        self.assertFalse(verify(sealed))

    def test_canonical_key_order(self):
        self.assertEqual(digest(self.record), digest(dict(reversed(list(self.record.items())))))

    def test_no_overwrite(self):
        with self.assertRaises(ValueError):
            seal(seal(self.record))


if __name__ == "__main__":
    unittest.main()
