"""Cross-run taint ledger (row 13, wave-139 lane 1).

Row-13 residual: the rare-token tracker (gov/rare_token.py) and the
read->novel-egress behavioral flag (wave-137) are per-run. An agent
that reads a sensitive document in run 1 and egresses in run 2 is
invisible to both tiers. This module is the durable read-side taint:
it persists what was READ, keyed by stable agent identity, so a
later run's egress check can consult prior runs' taint.

Privacy contract (wave-136 extended to durable storage; PINNED by
tests/test_taint_ledger.py::PrivacyInvariantTest and the x6 battery
probe — the ledger file on disk is scanned for raw token strings):
- The ledger stores, per (agent_id, source_id): ``observed_at``,
  ``rare_token_count``, and opaque per-token commitments. It NEVER
  stores token strings, raw document text, or payload text. Token
  strings exist in memory only transiently while commitments are
  computed, and never in results, audit events, or the file.
- A commitment is ``HMAC-SHA256(deployment_key, domain || agent_id ||
  source_id || token)``. It is an opaque digest: it supports
  cross-run overlap COUNTING (recompute the digest for each payload
  token, count intersections) without ever revealing the token.
  Only counts and document IDs are human-meaningful in the file.
- The deployment key comes from the existing key-provider seam
  (``gov.keyprovider.resolve_active_key``), never hardcoded, and may
  be overridden explicitly at construction. An unprovisioned
  deployment fails LOUD (``NoKeyConfiguredError`` propagates) rather
  than recording unblinded taint — wave-81 discipline.

How it is used:
- ``RareTokenTracker(taint_ledger=...)`` records each token-bearing
  read into the ledger (``observe_read``) and, at each egress,
  ``check_egress`` consults the ledger for taint from prior runs:
  blinded-commitment overlap drives the SAME verdict ladder as the
  in-run path (allow / flag / require_approval), and the behavioral
  tier fires on prior-run reads too (zero content overlap + concrete
  novel destination + >=1 token-bearing doc read in a prior run).
  Triage flags never block (wave-137 contract preserved).
- TTL/expiry is operator policy: ``ttl_seconds`` (default 7 days).
  Expired records are invisible to ``taint_for`` and reaped by
  ``sweep``. ``purge(agent_id=None)`` is the explicit deletion API.

On-disk format (adapted from gov/intent_ledger.py's trust pattern,
reusing gov/chained_store.canonical/sha256_hex): one JSONL file with
a header record, chained taint records (``prev``/``digest`` linkage),
and a footer carrying ``chain_tip`` + ``file_digest``. Fail-closed:
a damaged file raises ``TaintPersistenceError`` and is never
silently accepted as a clean history. Writes are atomic (tmp file +
os.replace).

Honest ceilings (documented, not hidden):
- TTL is operator policy and attacker-visible in effect: an attacker
  who knows the TTL can wait it out. Tune the TTL to the threat
  model, not to convenience.
- Cross-run identity depends on a STABLE agent identity: a fresh
  agent id per run defeats the ledger (same boundary as the drift
  lane's per-agent profiles and the intent ledger's principal).
- Key rotation blinds prior taint: commitments are keyed, so a
  rotated deployment key makes old records unverifiable (they read
  as zero overlap until they expire). This is the price of
  brute-force-resistant blinding.
- The ledger persists READ-taint, not destination history: the
  behavioral tier's destination-novelty check stays per-run. A
  destination established before a sensitive read in run 1 is novel
  again in run 2 (pinned EXPECTED in evals/cross_run_taint_probes.py
  x7). Destination persistence is explicit future work.
- Single-writer assumption: concurrent writers to one ledger file
  are not safe (last-writer-wins on os.replace). One writer per
  ledger file; the operator owns the path.
- Reads the operator never reports are invisible (same coverage
  ceiling as the in-run tracker: only reads through the governed
  tool boundary auto-observe (wave-141); direct filesystem access
  outside the governed API stays invisible by construction).

$0 spend, stdlib only, deterministic (commitments are deterministic
given the key; TTL tests inject ``observed_at``/``now``).
"""

import hmac
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from .chained_store import canonical, sha256_hex
from . import keyprovider as _keyprovider
from .rare_token import MAX_DOCS_PER_AGENT, MAX_TOKENS_PER_DOC

__all__ = [
    "TaintLedger",
    "TaintPersistenceError",
    "TAINT_LEDGER_VERSION",
    "DEFAULT_TAINT_TTL_SECONDS",
]

TAINT_LEDGER_VERSION = "taint-ledger/1.0"

#: Default taint time-to-live: 7 days. Operator policy — tune to the
#: threat model (an attacker who knows the TTL can wait it out).
DEFAULT_TAINT_TTL_SECONDS = 7 * 24 * 3600

#: HMAC domain separation for token commitments.
_COMMIT_DOMAIN = b"taint-commit-v1"

#: Chain genesis marker.
_GENESIS = "genesis"


class TaintPersistenceError(Exception):
    """Raised when the taint ledger cannot be saved or loaded.

    Fail-closed: a damaged file is never silently accepted as a
    clean history.
    """


def _coerce_ts(value, name):
    """Coerce an ISO-8601 string or datetime to an ISO-8601 string."""
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    if isinstance(value, str):
        # Validate it parses; store the canonical form.
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            raise TaintPersistenceError(
                "%s is not a parseable ISO-8601 timestamp: %r"
                % (name, value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    raise TaintPersistenceError(
        "%s must be an ISO-8601 string or datetime, got %r"
        % (name, type(value).__name__))


def _parse_ts(iso):
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class TaintLedger:
    """Durable read-side taint, keyed by stable agent identity.

    ``path`` is the single JSONL ledger file (created on first
    save). ``ttl_seconds`` is the operator-configurable taint
    lifetime — a construction-time policy; the header records the
    TTL at write time for audit, but the constructor value governs
    reads (an operator may legitimately retune TTL between runs).
    ``hmac_key`` overrides the key-provider seam
    (bytes); when None, ``gov.keyprovider.resolve_active_key()``
    supplies it and an unprovisioned deployment raises
    ``NoKeyConfiguredError`` fail-closed.
    """

    def __init__(self, path, ttl_seconds=DEFAULT_TAINT_TTL_SECONDS,
                 hmac_key=None):
        if (not isinstance(ttl_seconds, (int, float))
                or ttl_seconds <= 0):
            raise ValueError("ttl_seconds must be a positive number")
        if hmac_key is None:
            key_bytes, _epoch = _keyprovider.resolve_active_key()
        else:
            key_bytes = bytes(hmac_key)
            if not key_bytes:
                raise ValueError("hmac_key must be non-empty bytes")
        self._path = str(path)
        self._ttl = timedelta(seconds=ttl_seconds)
        self._ttl_seconds = ttl_seconds
        self._key = key_bytes
        # agent_id -> {source_id: record dict}
        self._agents = {}
        if os.path.exists(self._path):
            self._load()

    # -- commitments ------------------------------------------------
    def blinded_token(self, agent_id, source_id, token):
        """Opaque HMAC-SHA256 commitment for one token.

        Deterministic given the key: the same (agent, source, token)
        always yields the same digest, so cross-run overlap can be
        counted without ever storing the token string. The digest
        reveals nothing without the deployment key.
        """
        msg = (_COMMIT_DOMAIN + b"\x00"
               + str(agent_id).encode("utf-8") + b"\x00"
               + str(source_id).encode("utf-8") + b"\x00"
               + str(token).encode("utf-8"))
        return hmac.new(self._key, msg, sha256).hexdigest()

    # -- reads ------------------------------------------------------
    def observe(self, agent_id, source_id, rare_tokens, observed_at=None):
        """Record one read source's taint.

        ``rare_tokens`` is an iterable of token STRINGS (in-memory
        only — only counts, doc ids, and opaque commitments are
        persisted). Reads carrying zero rare tokens are NOT recorded
        (they contribute to neither the content tier nor the
        behavioral tier). Re-observing the same (agent, source)
        replaces the record (re-read re-taints, refreshing the TTL).
        Expired records are swept first so the file stays bounded.
        Returns a dict with counts/ids only.
        """
        agent_id = str(agent_id)
        source_id = str(source_id)
        tokens = sorted({str(t) for t in (rare_tokens or ()) if t})
        if len(tokens) > MAX_TOKENS_PER_DOC:
            tokens = tokens[:MAX_TOKENS_PER_DOC]
        if not tokens:
            return {"observed": True, "agent_id": agent_id,
                    "source_id": source_id, "rare_token_count": 0,
                    "ledger_recorded": False,
                    "reason": "no_rare_tokens"}
        self.sweep()
        docs = self._agents.setdefault(agent_id, {})
        docs[source_id] = {
            "source_id": source_id,
            "observed_at": _coerce_ts(observed_at, "observed_at"),
            "rare_token_count": len(tokens),
            "commitments": sorted(
                self.blinded_token(agent_id, source_id, t)
                for t in tokens),
        }
        while len(docs) > MAX_DOCS_PER_AGENT:
            docs.pop(next(iter(docs)))
        self.save()
        return {"observed": True, "agent_id": agent_id,
                "source_id": source_id,
                "rare_token_count": len(tokens),
                "ledger_recorded": True}

    # -- queries ----------------------------------------------------
    def _live(self, record, now):
        age = now - _parse_ts(record["observed_at"])
        return age <= self._ttl

    def taint_for(self, agent_id, now=None):
        """Live (unexpired) taint records for one agent.

        Returns a list of dicts with source_id, observed_at,
        rare_token_count, and commitments — counts, doc ids, and
        opaque digests only; never token strings. ``now`` accepts a
        datetime or ISO-8601 string (test seam for TTL determinism).
        """
        agent_id = str(agent_id)
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        out = []
        for source_id in sorted(self._agents.get(agent_id, {})):
            rec = self._agents[agent_id][source_id]
            if self._live(rec, now_dt):
                out.append({"source_id": source_id,
                            "observed_at": rec["observed_at"],
                            "rare_token_count": rec["rare_token_count"],
                            "commitments": list(rec["commitments"])})
        return out

    def live_source_ids(self, agent_id, now=None):
        """Sorted source ids with live taint for one agent."""
        return [r["source_id"] for r in self.taint_for(agent_id, now=now)]

    # -- expiry / deletion ------------------------------------------
    def sweep(self, now=None):
        """Delete expired records. Returns the count removed."""
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        removed = 0
        for agent_id in list(self._agents):
            docs = self._agents[agent_id]
            for source_id in list(docs):
                if not self._live(docs[source_id], now_dt):
                    del docs[source_id]
                    removed += 1
            if not docs:
                del self._agents[agent_id]
        if removed:
            self.save()
        return removed

    def purge(self, agent_id=None):
        """Explicit deletion API.

        ``purge(agent_id)`` removes that agent's taint;
        ``purge()`` clears the whole ledger. Returns the count of
        records removed. The deletion is persisted immediately.
        """
        removed = 0
        if agent_id is None:
            for docs in self._agents.values():
                removed += len(docs)
            self._agents = {}
        else:
            docs = self._agents.pop(str(agent_id), {})
            removed = len(docs)
        self.save()
        return removed

    # -- persistence --------------------------------------------------
    def save(self):
        """Persist the ledger atomically (tmp file + os.replace)."""
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        lines = []
        header = {"record": "header",
                  "taint_ledger": TAINT_LEDGER_VERSION,
                  "created_at": datetime.now(timezone.utc).isoformat(),
                  "ttl_seconds": self._ttl_seconds}
        lines.append(canonical(header))
        prev = _GENESIS
        for agent_id in sorted(self._agents):
            for source_id in sorted(self._agents[agent_id]):
                rec = self._agents[agent_id][source_id]
                body = {"record": "taint",
                        "agent_id": agent_id,
                        "source_id": source_id,
                        "observed_at": rec["observed_at"],
                        "rare_token_count": rec["rare_token_count"],
                        "commitments": list(rec["commitments"]),
                        "prev": prev}
                body["digest"] = sha256_hex(canonical(body))
                prev = body["digest"]
                lines.append(canonical(body))
        file_digest = sha256_hex("\n".join(lines))
        footer = {"record": "footer", "chain_tip": prev,
                  "file_digest": file_digest}
        lines.append(canonical(footer))
        fd, tmp = tempfile.mkstemp(dir=parent, prefix=".taint-ledger-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                raw_lines = [ln.rstrip("\n") for ln in fh]
        except OSError as e:
            raise TaintPersistenceError(
                "cannot read taint ledger %r: %s" % (self._path, e))
        lines = [ln for ln in raw_lines if ln.strip()]
        if not lines:
            raise TaintPersistenceError(
                "taint ledger %r is empty: refusing to treat as clean "
                "history" % self._path)
        try:
            records = [json.loads(ln) for ln in lines]
        except ValueError as e:
            raise TaintPersistenceError(
                "taint ledger %r has a corrupt line: %s" % (self._path, e))
        header = records[0]
        if (not isinstance(header, dict)
                or header.get("record") != "header"
                or header.get("taint_ledger") != TAINT_LEDGER_VERSION):
            raise TaintPersistenceError(
                "taint ledger %r has a bad header: refusing to treat "
                "as clean history" % self._path)
        footer = records[-1]
        if not isinstance(footer, dict) or footer.get("record") != "footer":
            raise TaintPersistenceError(
                "taint ledger %r is missing its footer: refusing to "
                "treat as clean history" % self._path)
        agents = {}
        prev = _GENESIS
        for entry in records[1:-1]:
            if not isinstance(entry, dict) or entry.get("record") != "taint":
                raise TaintPersistenceError(
                    "taint ledger %r has a non-taint record: refusing "
                    "to treat as clean history" % self._path)
            for field in ("agent_id", "source_id", "observed_at",
                          "rare_token_count", "commitments", "prev",
                          "digest"):
                if field not in entry:
                    raise TaintPersistenceError(
                        "taint ledger %r record is missing %r: refusing "
                        "to treat as clean history" % (self._path, field))
            if entry["prev"] != prev:
                raise TaintPersistenceError(
                    "taint ledger %r chain linkage broken at %r: "
                    "refusing to treat as clean history"
                    % (self._path, entry.get("source_id")))
            body = {k: v for k, v in entry.items() if k != "digest"}
            if sha256_hex(canonical(body)) != entry["digest"]:
                raise TaintPersistenceError(
                    "taint ledger %r record digest mismatch at %r: "
                    "refusing to treat as clean history"
                    % (self._path, entry.get("source_id")))
            prev = entry["digest"]
            # Re-validate the timestamp parses (fail-closed on garbage).
            _parse_ts(entry["observed_at"])
            agents.setdefault(str(entry["agent_id"]), {})[
                str(entry["source_id"])] = {
                    "source_id": str(entry["source_id"]),
                    "observed_at": entry["observed_at"],
                    "rare_token_count": int(entry["rare_token_count"]),
                    "commitments": [str(c)
                                    for c in entry["commitments"]],
                }
        if footer.get("chain_tip") != prev:
            raise TaintPersistenceError(
                "taint ledger %r footer chain_tip mismatch: refusing "
                "to treat as clean history" % self._path)
        if footer.get("file_digest") != sha256_hex(
                "\n".join(lines[:-1])):
            raise TaintPersistenceError(
                "taint ledger %r footer file_digest mismatch: refusing "
                "to treat as clean history" % self._path)
        self._agents = agents

    def verify_chain(self):
        """Re-verify the on-disk chain. Returns True; raises
        ``TaintPersistenceError`` on any damage (fail-closed)."""
        if not os.path.exists(self._path):
            raise TaintPersistenceError(
                "taint ledger %r does not exist" % self._path)
        saved = self._agents
        try:
            self._agents = {}
            self._load()
        finally:
            self._agents = saved
        return True
