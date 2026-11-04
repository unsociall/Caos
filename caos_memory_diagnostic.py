"""Read-only JSONL tail diagnostic for CAOS memory.

Never repairs, truncates or authenticates records. Use the authenticated
reader separately to establish trust in any syntactically valid record.
"""
from __future__ import annotations

import json
from pathlib import Path


def diagnose_jsonl(path: str | Path) -> dict:
    """Locate the first malformed line without changing the source file.

    Offsets are byte offsets. The valid prefix is only *syntactically* valid;
    it is not necessarily HMAC-authenticated or semantically trustworthy.
    """
    source = Path(path)
    valid_end = 0
    count = 0
    with source.open("rb") as stream:
        while True:
            start = stream.tell()
            line = stream.readline()
            if not line:
                return {"status": "ok", "valid_prefix_bytes": valid_end,
                        "valid_records": count, "error_offset": None}
            if not line.endswith(b"\n"):
                return {"status": "unterminated_tail", "valid_prefix_bytes": valid_end,
                        "valid_records": count, "error_offset": start}
            try:
                record = json.loads(line.decode("utf-8"))
                if not isinstance(record, dict):
                    raise ValueError("JSONL record must be an object")
            except (UnicodeDecodeError, ValueError):
                return {"status": "invalid_record", "valid_prefix_bytes": valid_end,
                        "valid_records": count, "error_offset": start}
            valid_end = stream.tell()
            count += 1
