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
high-entropy-ish fragments to the SAME registered domain from the SAME
principal across >= 2 distinct runs within a time window ->
``require_approval`` (flag ``cross_run_campaign``). It never denies. See
``ToolExecutor._check_cross_run_campaign`` for the thresholds.

F13: the campaign KEY normalizes the endpoint to its registered domain
(last two hostname labels), so subdomain rotation
(shard0/shard1/shard2.collector.example) lands in ONE bucket. The exact
endpoint string stays in the ledger record for forensics.

F14: a STRUCTURAL campaign signal sits alongside the fragment-shape
signal: same principal + same registered domain + same param KEY SET
across >= K distinct runs inside the window -> ``require_approval``
(flag ``structural_campaign``), regardless of payload size or entropy.
Thin-spread only: a run that repeats the structure K+ times in one run
is bursty repetition (the loop guard's territory), not low-and-slow.

F15: principal-scoped sensitive-read taint. A ``sensitive_read`` entry
records that a principal's run ingested DLP-sensitive content; a fresh
executor for the SAME principal inherits the taint while the mark is
unexpired (24h TTL). Different principals never share taint.
"""

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urlparse

_LEDGER_VERSION = 1
_GENESIS_HASH = "0" * 64

# Campaign thresholds (see _check_cross_run_campaign in gov/executor.py).
# A "fragment" is a small, information-dense payload: total string param
# bytes <= _FRAGMENT_MAX_BYTES with at least one string value at
# _FRAGMENT_MIN_ENTROPY bits/char. K fragments from >= 2 distinct runs to
# the same registered domain within the window queue the K-th attempt.
FRAGMENT_MAX_BYTES = 64
FRAGMENT_MIN_ENTROPY = 1.8
CAMPAIGN_K = 3
CAMPAIGN_WINDOW_SECS = 24 * 3600

# F15: how long a principal-scoped sensitive-read mark keeps fresh runs
# of the same principal tainted. Documented, not tuned: long enough to
# cover a confederate two-hop inside one operator session, short enough
# that a stale mark cannot taint the principal forever. Out-of-band
# exfil the engine never sees is still out of scope.
SENSITIVE_TAINT_TTL_SECS = 24 * 3600


def registered_domain(endpoint):
    """Registered domain of an endpoint URL (F13 heuristic).

    Lowercase the hostname and keep the last two labels, so
    ``shard0.collector.example`` and ``shard1.collector.example`` both
    key as ``collector.example``. Documented limits: this is a naive
    heuristic, NOT a public-suffix-list lookup — multi-label suffixes
    (``example.co.uk`` -> ``co.uk``) and bare IPs (``10.0.0.1`` ->
    ``0.1``) normalize oddly but deterministically; single-label hosts
    (``api``) pass through unchanged. Only the campaign KEY normalizes;
    the exact endpoint string stays in the ledger record for forensics.
    """
    try:
        host = (urlparse(endpoint or "").hostname or "")
    except Exception:
        host = ""
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


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

    @staticmethod
    def _entry_domain(entry):
        """Registered domain for one ledger entry (F13).

        New entries carry ``campaign_domain`` (written by
        ``ToolExecutor._api_call_shape``); older entries fall back to
        normalizing their exact ``endpoint`` string, so the rotation fix
        applies to history already on disk.
        """
        domain = entry.get("campaign_domain")
        if domain:
            return domain
        return registered_domain(entry.get("endpoint") or "")

    def fragments(self, principal, endpoint, window_secs=CAMPAIGN_WINDOW_SECS,
                  now=None):
        """Fragment-shaped entries for principal+endpoint inside the window.

        F13: the endpoint is normalized to its registered domain before
        keying, so ``shard0.collector.example`` and
        ``shard1.collector.example`` land in the SAME campaign bucket.
        """
        if not self.path.exists():
            return []
        now = time.time() if now is None else now
        domain = registered_domain(endpoint)
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
                    and self._entry_domain(entry) == domain
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
        rule's reach. F13: keying is on the registered domain, not the
        exact endpoint string.
        """
        frags = self.fragments(principal, endpoint, window_secs, now)
        if len(frags) < k:
            return False
        return len({f.get("run_id") for f in frags}) >= 2

    def structural_campaign_hit(self, principal, domain, param_keys,
                                window_secs=CAMPAIGN_WINDOW_SECS, now=None,
                                k=CAMPAIGN_K):
        """F14: True when >= k api_call entries share (principal, domain,
        param_keys) across >= k distinct runs inside the window.

        The STRUCTURAL campaign signal: it does not look at payload size
        or entropy at all, so oversize padding and sub-entropy encodings
        (unary) still trip it — the attacks it was built for repeat the
        same call structure thinly across runs. A run counts only when
        it contributed FEWER than k matching calls: a single run that
        repeats the structure k+ times is bursty repetition (the loop
        guard's territory), not low-and-slow. Empty key sets never match
        (a param-less call carries no exfil payload). Heuristic,
        queue-only, fail-safe — same contract as campaign_hit.
        """
        if not self.path.exists():
            return False
        if not principal or not domain or not param_keys:
            return False
        now = time.time() if now is None else now
        wanted = sorted(param_keys)
        per_run = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("tool") != "api_call":
                continue
            if entry.get("principal") != principal:
                continue
            if self._entry_domain(entry) != domain:
                continue
            keys = entry.get("param_keys")
            if not keys or sorted(keys) != wanted:
                continue
            try:
                ts = float(entry.get("ts", 0))
            except (TypeError, ValueError):
                continue
            if now - ts > window_secs:
                continue
            run_id = entry.get("run_id")
            per_run.setdefault(run_id, 0)
            per_run[run_id] += 1
        thin_runs = [r for r, n in per_run.items() if n < k]
        return len(thin_runs) >= k

    # -- principal-scoped sensitive-read taint (F15) ------------------------

    def taint_mark(self, principal, run_id, now=None):
        """Persist a sensitive-read mark for *principal* (F15).

        Records that this principal's run ingested DLP-sensitive
        content. A fresh executor for the SAME principal inherits the
        taint while the mark is unexpired (see ``taint_active``);
        different principals never share taint. The mark rides the same
        hash chain as the egress entries (a forged mark can only cause a
        spurious approval QUEUE, never an execution).
        """
        if not principal:
            return None
        return self.append({
            "kind": "sensitive_read",
            "ts": time.time() if now is None else now,
            "principal": principal,
            "run_id": run_id,
        })

    def taint_active(self, principal, ttl_secs=SENSITIVE_TAINT_TTL_SECS,
                     now=None):
        """True when *principal* has an unexpired sensitive-read mark."""
        if not self.path.exists() or not principal:
            return False
        now = time.time() if now is None else now
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if (entry.get("kind") == "sensitive_read"
                    and entry.get("principal") == principal):
                try:
                    ts = float(entry.get("ts", 0))
                except (TypeError, ValueError):
                    continue
                if now - ts <= ttl_secs:
                    return True
        return False
