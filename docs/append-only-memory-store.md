# CAOS append-only authenticated memory store (experimental)

Opt-in prototype: `caos_memory_store.MemoryStore`. Python standard library only; suitable for Python 3.11+ on Termux, PC and Linux servers. No migration, modification or discovery of existing CAOS databases is performed.

Usage:
```python
import os
from caos_memory_store import MemoryStore
key = bytes.fromhex(os.environ["CAOS_MEMORY_KEY_HEX"])  # 32+ random bytes
store = MemoryStore("data/memory-v1.jsonl", secret=key, key_id="local-v1")
store.append("observation-1", "example")
assert store.read_all()[0]["content"] == "example"
```

Keep the key outside the repository and backups containing public files. Losing the key makes records unverifiable. Existing files are never truncated by the API. Reads reject corrupted or unauthenticated records and return no partial result.

**Known limitations:** this is not a production database. Concurrent writers, network filesystems, partial writes, record deletion/reordering, replay, disk exhaustion, large-memory streaming, encryption at rest, key management and migration are not solved. A single append may be interrupted and leave a truncated final line; manual recovery from a verified backup is required. HMAC authenticates content but does not encrypt it. Avoid sensitive content until encryption and lifecycle controls are added.

Next: integrate via a reviewed adapter into the actual CAOS persistence API, then add process-level locking, authenticated sequence chaining, and recovery tooling with explicit operator approval.
