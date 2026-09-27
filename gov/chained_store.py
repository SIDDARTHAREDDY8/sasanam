"""Shared hash-chained JSONL store base (wave-134 cleanup).

``gov.drift.DriftStore`` and ``gov.framing.FramingStore`` were built as
independent copies of the same durable per-agent profile store: one
JSONL file per agent under a store directory, every record
hash-chained (``prev_digest`` linkage, SHA-256 over the canonical
record), audit emitted BEFORE local mutation (F167 lesson -- a logging
failure leaves the store unchanged), fail-closed chain verification.

This module extracts the shared machinery into ``ChainedStore`` so the
two stores are thin subclasses. The on-disk format is UNCHANGED:
records are written with the same canonical JSON (sorted keys, no
whitespace), the same digest construction, and the same audit-event
shape, so data written by the pre-extraction code verifies under the
new code and vice versa. No migration, no new API -- the subclasses
keep their exact public signatures (``__init__(store_dir, audit=None)``,
``record_run(agent_id, principal, fingerprint, audit=None)``,
``runs(agent_id)``, ``verify_chain(agent_id)``) and their exact record
schemas (``drift_version`` vs ``framing_version`` version keys,
``drift_run_recorded`` vs ``framing_run_recorded`` audit events).

$0, stdlib only, deterministic.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "ChainedStore",
    "canonical",
    "sha256_hex",
    "utcnow_iso",
    "sanitize_agent",
]

_AGENT_RE = re.compile(r"[^A-Za-z0-9_-]+")


def canonical(obj):
    """Canonical JSON for hashing (stable key order, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=repr)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def sanitize_agent(agent_id):
    s = _AGENT_RE.sub("_", str(agent_id)).strip("_")[:64]
    if not s:
        raise ValueError("agent_id sanitizes to empty, got %r" % (agent_id,))
    return s


class ChainedStore:
    """Durable per-agent cross-run profile store (hash-chained JSONL).

    One JSONL file per agent under ``store_dir``. Every record is
    hash-chained (``prev_digest`` linkage, SHA-256 over the canonical
    record): ``verify_chain`` rejects tampered payloads, dropped
    records, and broken linkage. Audit runs BEFORE local mutation
    (F167 lesson): a logging failure leaves the store unchanged.

    Subclass contract (class attributes):
    - ``_record_version_key``: version field name, e.g. "drift_version".
    - ``_record_version``: version value, e.g. 1.
    - ``_record_event``: audit event name, e.g. "drift_run_recorded".
    - ``_fingerprint_cls``: accepted fingerprint type for ``record_run``.
    """

    _record_version_key = None
    _record_version = 1
    _record_event = None
    _fingerprint_cls = None

    def __init__(self, store_dir, audit=None):
        self.store_dir = Path(store_dir)
        self._audit = audit
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._heads = {}  # agent_id -> last digest (cache)

    def _path(self, agent_id):
        return self.store_dir / (sanitize_agent(agent_id) + ".jsonl")

    def _head(self, agent_id):
        if agent_id not in self._heads:
            runs = self._read_all(agent_id)
            self._heads[agent_id] = runs[-1]["digest"] if runs else ""
        return self._heads[agent_id]

    def _read_all(self, agent_id):
        p = self._path(agent_id)
        if not p.exists():
            return []
        records = []
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def _append_chained(self, agent_id, record, audit_event, auditor):
        """Link, digest, audit-before-mutation, then write.

        The audit callable runs BEFORE the file write; an audit failure
        aborts the append (fail-closed) and the head cache is untouched.
        Returns the stored record.
        """
        prev = self._head(agent_id)
        record["prev_digest"] = prev
        record["digest"] = sha256_hex(canonical(
            {k: v for k, v in record.items() if k != "digest"}))
        if auditor is not None:
            event = dict(audit_event)
            event["digest"] = record["digest"]
            event["prev_digest"] = prev
            auditor(event)
        with self._path(agent_id).open("a", encoding="utf-8") as f:
            f.write(canonical(record) + "\n")
        self._heads[agent_id] = record["digest"]
        return record

    def record_run(self, agent_id, principal, fingerprint, audit=None):
        """Append one run's fingerprint. Returns the stored record.

        The audit event is appended BEFORE the file write; an audit
        failure aborts the record (fail-closed). ``audit`` overrides the
        construction-time audit callable for this call.
        """
        if not isinstance(fingerprint, self._fingerprint_cls):
            raise TypeError("fingerprint must be a %s, got %r"
                            % (self._fingerprint_cls.__name__,
                               type(fingerprint).__name__))
        auditor = self._audit if audit is None else audit
        record = {
            self._record_version_key: self._record_version,
            "agent_id": str(agent_id),
            "principal": str(principal),
            "recorded_at": utcnow_iso(),
            "fingerprint": fingerprint.to_dict(),
        }
        audit_event = {
            "event": self._record_event,
            "agent_id": str(agent_id),
            "principal": str(principal),
            "run_id": fingerprint.run_id,
            "run_seq": fingerprint.run_seq,
        }
        return self._append_chained(agent_id, record, audit_event, auditor)

    def runs(self, agent_id):
        """All stored run records for the agent, oldest first."""
        return self._read_all(agent_id)

    def verify_chain(self, agent_id):
        """True iff the agent's chain is intact (digests + linkage)."""
        prev = ""
        for rec in self._read_all(agent_id):
            if rec.get("prev_digest") != prev:
                return False
            digest = rec.get("digest")
            if digest != sha256_hex(canonical(
                    {k: v for k, v in rec.items() if k != "digest"})):
                return False
            prev = digest
        return True
