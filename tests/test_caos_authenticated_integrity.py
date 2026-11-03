import unittest

from caos_authenticated_integrity import authenticate, verify_authenticated


class AuthenticatedIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.secret = b"a" * 32
        self.keys = {"key-1": self.secret}
        self.record = {"id": "mem-1", "content": "Olá", "schema_version": 1}

    def test_valid(self):
        self.assertTrue(verify_authenticated(authenticate(self.record, secret=self.secret, key_id="key-1"), keys=self.keys))

    def test_modified_content(self):
        record = authenticate(self.record, secret=self.secret, key_id="key-1")
        record["content"] = "adulterado"
        self.assertFalse(verify_authenticated(record, keys=self.keys))

    def test_wrong_key(self):
        record = authenticate(self.record, secret=self.secret, key_id="key-1")
        self.assertFalse(verify_authenticated(record, keys={"key-1": b"b" * 32}))

    def test_unknown_key_id(self):
        record = authenticate(self.record, secret=self.secret, key_id="key-1")
        record["auth_key_id"] = "other"
        self.assertFalse(verify_authenticated(record, keys=self.keys))

    def test_no_tag(self):
        self.assertFalse(verify_authenticated(self.record, keys=self.keys))

    def test_short_key(self):
        with self.assertRaises(ValueError):
            authenticate(self.record, secret=b"short", key_id="key-1")

    def test_no_overwrite(self):
        record = authenticate(self.record, secret=self.secret, key_id="key-1")
        with self.assertRaises(ValueError):
            authenticate(record, secret=self.secret, key_id="key-1")

    def test_key_rotation(self):
        old = authenticate(self.record, secret=self.secret, key_id="key-1")
        new = authenticate(self.record, secret=b"c" * 32, key_id="key-2")
        keys = {"key-1": self.secret, "key-2": b"c" * 32}
        self.assertTrue(verify_authenticated(old, keys=keys))
        self.assertTrue(verify_authenticated(new, keys=keys))


if __name__ == "__main__":
    unittest.main()
