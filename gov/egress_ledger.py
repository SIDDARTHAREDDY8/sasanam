"""Per-principal egress ledger: tamper-evident cross-run record of outbound
``api_call`` shapes (F10).

Per-run guards cannot see a low-and-slow campaign: three fresh runs, each
sending one innocent-looking credential fragment, are each individually
clean. This ledger gives the engine content-aware cross-run memory: every
``api_call`` attempt that passes DLP is recorded (endpoint, param
count/size/entropy bucket, timestamp, principal, run) in a hash-chained
JSONL file — the same tamper-evidence pattern as the action log
(``gov/log.py``), minus the HMAC key (the ledger is a heuristic signal,
not an authorization artifact; a forged ledger entry can only cause a
spurious approval QUEUE, never an execution).

The ledger lives NEXT TO the runs directory (e.g. ``runs/``), shared by
all runs of a deployment; the path is configurable and tests point it at
temp dirs. A deployment that wants no cross-run memory can point it at a
per-run path (the test harness default).

The campaign rule itself is heuristic and FAIL-SAFE: K small
high-entropy-ish fragments to the SAME endpoint from the SAME principal
across >= 2 distinct runs within a time window -> ``require_approval``
(flag ``cross_run_campaign``). It never denies. See
``ToolExecutor._check_cross_run_campaign`` for the thresholds.
"""

import hashlib
import json
import time
from pathlib import Path

_LEDGER_VERSION = 1
_GENESIS_HASH = "0" * 64

# Campaign thresholds (see _check_cross_run_campaign in gov/executor.py).
# A "fragment" is a small, information-dense payload: total string param
# bytes <= _FRAGMENT_MAX_BYTES with at least one string value at
# _FRAGMENT_MIN_ENTROPY bits/char. K fragments from >= 2 distinct runs to
# the same endpoint within the window queue the K-th attempt.
FRAGMENT_MAX_BYTES = 64
FRAGMENT_MIN_ENTROPY = 1.8
CAMPAIGN_K = 3
CAMPAIGN_WINDOW_SECS = 24 * 3600


class EgressLedger:
    """Append-only hash-chained JSONL of outbound api_call shapes."""

    def __init__(self, path):
        self.path = Path(path)
        self._prev = self._tail_hash()

    # -- chaining ------------------------------------------------------

    def _tail_hash(self):
        prev = _GENESIS_HASH
        if not self.path.exists():
            return prev
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return prev
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            prev = entry.get("entry_hash") or prev
        return prev

    def append(self, shape):
        """Record one api_call shape; returns the chained record."""
        # Re-read the tail so sequential executors sharing one path keep
        # a single chain (each executor appends rarely; no locking).
        self._prev = self._tail_hash()
        body = dict(shape)
        body["v"] = _LEDGER_VERSION
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(
            (self._prev + canonical).encode("utf-8")).hexdigest()
        record = dict(body)
        record["prev_hash"] = self._prev
        record["entry_hash"] = entry_hash
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        self._prev = entry_hash
        return record

    def verify(self):
        """True iff every entry's prev_hash links to the previous hash."""
        prev = _GENESIS_HASH
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False
            body = {k: v for k, v in entry.items()
                    if k not in ("prev_hash", "entry_hash")}
            canonical = json.dumps(body, sort_keys=True,
                                   separators=(",", ":"))
            if hashlib.sha256(
                    (prev + canonical).encode("utf-8")).hexdigest() != \
                    entry.get("entry_hash"):
                return False
            prev = entry["entry_hash"]
        return True

    # -- campaign query --------------------------------------------------

    def fragments(self, principal, endpoint, window_secs=CAMPAIGN_WINDOW_SECS,
                  now=None):
        """Fragment-shaped entries for principal+endpoint inside the window."""
        if not self.path.exists():
            return []
        now = time.time() if now is None else now
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if (entry.get("principal") == principal
                    and entry.get("endpoint") == endpoint
                    and entry.get("fragment") is True
                    and now - float(entry.get("ts", 0)) <= window_secs):
                out.append(entry)
        return out

    def campaign_hit(self, principal, endpoint,
                     window_secs=CAMPAIGN_WINDOW_SECS, now=None,
                     k=CAMPAIGN_K):
        """True when >= k fragments from >= 2 distinct runs are in window.

        The K-th fragment (counting the just-recorded current attempt) is
        what queues. Requiring >= 2 distinct runs keeps single-run
        identical-call bursts (the loop guard's territory) out of this
        rule's reach.
        """
        frags = self.fragments(principal, endpoint, window_secs, now)
        if len(frags) < k:
            return False
        return len({f.get("run_id") for f in frags}) >= 2
