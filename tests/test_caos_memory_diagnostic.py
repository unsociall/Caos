import tempfile
import unittest
from pathlib import Path

from caos_memory_diagnostic import diagnose_jsonl


class DiagnosticTests(unittest.TestCase):
    def test_clean_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "memory.jsonl"
            p.write_bytes(b'{"id":"a"}\n{"id":"b"}\n')
            self.assertEqual(diagnose_jsonl(p), {
                "status": "ok", "valid_prefix_bytes": p.stat().st_size,
                "valid_records": 2, "error_offset": None})

    def test_partial_tail_is_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "memory.jsonl"
            data = b'{"id":"a"}\n{"id":'
            p.write_bytes(data)
            result = diagnose_jsonl(p)
            self.assertEqual(result["status"], "unterminated_tail")
            self.assertEqual(result["valid_prefix_bytes"], len(b'{"id":"a"}\n'))
            self.assertEqual(result["error_offset"], len(b'{"id":"a"}\n'))
            self.assertEqual(p.read_bytes(), data)

    def test_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "memory.jsonl"
            p.write_bytes(b'{"id":"a"}\n\xff\n')
            self.assertEqual(diagnose_jsonl(p)["status"], "invalid_record")

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "memory.jsonl"
            p.touch()
            self.assertEqual(diagnose_jsonl(p)["valid_records"], 0)


if __name__ == "__main__":
    unittest.main()
