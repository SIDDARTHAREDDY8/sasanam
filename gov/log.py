"""Append-only, hash-chained action log.

Each entry is stored as one JSON line. The entry's hash is
SHA-256(previous_hash + canonical_json(entry_without_hash)), which makes the
log tamper-evident: changing any historical entry breaks every later hash.

verify_chain() replays the file and reports OK or the first broken entry.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path

GENESIS = "GENESIS"


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _canonical(entry):
    payload = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _entry_hash(prev_hash, canonical):
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class ActionLog:
    """Append-only JSONL log with hash chaining. Resumes an existing file."""

    def __init__(self, path):
        self.path = Path(path)
        self.refresh()

    def refresh(self):
        """Re-read the file tail so this instance sees entries written by
        other processes (e.g. the approval CLI)."""
        self._seq = 0
        self._prev = GENESIS
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                self._seq = int(entry["seq"])
                self._prev = entry["hash"]

    def append(self, event):
        """Append an event dict; returns the stored entry (with seq/hash)."""
        self.refresh()
        self._seq += 1
        entry = {"seq": self._seq, "ts": _utcnow(), "prev_hash": self._prev}
        entry.update(event)
        entry["hash"] = _entry_hash(self._prev, _canonical(entry))
        self._prev = entry["hash"]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True, default=str) + "\n")
        return entry


def read_entries(path):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def verify_chain(path):
    """Replay the chain. Returns (ok, broken_seq_or_None, entry_count)."""
    p = Path(path)
    if not p.exists():
        return False, None, 0
    prev = GENESIS
    count = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        count += 1
        if entry.get("prev_hash") != prev:
            return False, entry.get("seq"), count
        if entry.get("hash") != _entry_hash(prev, _canonical(entry)):
            return False, entry.get("seq"), count
        prev = entry["hash"]
    return True, None, count
