"""Shared hash-chained JSONL store base (wave-134 cleanup).

``gov.drift.DriftStore`` and ``gov.framing.FramingStore`` were built as
independent copies of the same durable per-agent profile store: one
JSONL file per agent under a store directory, every record
hash-chained (``prev_digest`` linkage; new records carry a keyed
HMAC-SHA256 digest, pre-upgrade records the legacy unkeyed SHA-256),
audit emitted BEFORE local mutation (F167 lesson -- a logging
failure leaves the store unchanged), fail-closed chain verification.

This module extracts the shared machinery into ``ChainedStore`` so the
two stores are thin subclasses.

Row-9 keyed chains: new records are chained with HMAC-SHA256 under the
deployment key (``chain_keyed: true`` on the record), resolved through
``gov.keyprovider`` — the same idiom as the audit log
(``gov.log._active_key``): configured env key -> configured keyring
file -> LOUD ``NoKeyConfiguredError`` in every mode. There is no
dev-key fallback and no silent unkeyed append: without a configured
key, appends refuse. Records written before the keyed upgrade carry no
``chain_keyed`` marker and verify under the legacy unkeyed scheme, so
old chains verify without migration and mixed chains (legacy tail +
keyed appends) verify per-record. The MAC is domain-separated per
record schema (derived from each subclass's declared version key —
no schema changes needed).

Honest ceilings: a full-file rewrite to the legacy unkeyed format is
indistinguishable from a genuine pre-upgrade chain (backward
compatibility costs this); key rotation invalidates chains keyed
under the old key (the epoch is recorded on every keyed record for
visibility, as in the audit log) — rotation is a re-initialization
event for these stores.

$0, stdlib only, deterministic.
"""

import hashlib
import hmac
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
    "resolve_chain_key",
    "chain_domain",
    "keyed_digest",
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


def resolve_chain_key():
    """Deployment key for chain MACs — the keyprovider idiom, not a new one.

    Same resolution as the audit log (``gov.log._active_key``):
    configured env key -> configured keyring file -> LOUD
    ``NoKeyConfiguredError`` in every deployment mode. No dev-key
    fallback exists anywhere on this path (wave-81 deleted it from
    ``gov/``); configured keys are operator-chosen and used as-is.

    Returns ``(key_bytes, key_epoch)``.
    """
    # Lazy import: gov/keyprovider.py imports gov/keys.py at its top
    # level, and gov/keys.py imports gov/log.py at its top level, so a
    # top-level import here would risk a cycle. By call time all three
    # modules are fully initialized (mirrors gov/log.py's own guard).
    from . import keyprovider as _kp
    return _kp.resolve_active_key()


def chain_domain(schema_name):
    """Domain separation for the keyed chain MAC, per record schema.

    DriftStore and FramingStore declare their schemas in
    ``gov/drift.py`` and ``gov/framing.py``; the domain is derived from
    the declared version key so the chains get distinct MAC domains
    without touching those declarations. ``gov.drift.PopulationStore``
    uses ``"population"``.
    """
    return (b"gov-chained-store/v1\x00"
            + str(schema_name).encode("ascii", "replace") + b"\x00")


def keyed_digest(record, key, domain):
    """HMAC-SHA256 MAC of one record (the keyed chain scheme).

    Covers the canonical record minus ``digest`` itself, prefixed with
    the domain separator. ``chain_keyed`` and ``key_epoch`` are part of
    the record, so they are covered too — stripping the scheme marker
    breaks the MAC.
    """
    body = canonical({k: v for k, v in record.items() if k != "digest"})
    return hmac.new(key, domain + body.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _no_key_error():
    """The keyprovider's fail-closed exception (lazy import, see above)."""
    from .keys import NoKeyConfiguredError
    return NoKeyConfiguredError


class ChainedStore:
    """Durable per-agent cross-run profile store (hash-chained JSONL).

    One JSONL file per agent under ``store_dir``. Every record is
    hash-chained (``prev_digest`` linkage): new records carry
    ``chain_keyed: true`` and a HMAC-SHA256 digest under the deployment
    key (see :func:`resolve_chain_key`); pre-upgrade records carry the
    legacy unkeyed SHA-256 digest and still verify. ``verify_chain``
    selects the scheme per record and rejects tampered payloads,
    dropped records, and broken linkage. Audit runs BEFORE local
    mutation (F167 lesson): a logging failure leaves the store
    unchanged.

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

    def _domain(self):
        """MAC domain for this store kind (derived from the record
        schema's version key — distinct per subclass)."""
        return chain_domain(self._record_version_key)

    def _append_chained(self, agent_id, record, audit_event, auditor):
        """Link, digest, audit-before-mutation, then write.

        The digest is the keyed HMAC scheme: the deployment key is
        resolved here and ``NoKeyConfiguredError`` propagates
        (fail-closed — an append without a configured key refuses
        loudly, never silently falls back to the unkeyed scheme).

        The audit callable runs BEFORE the file write; an audit failure
        aborts the append (fail-closed) and the head cache is untouched.
        Returns the stored record.
        """
        key, epoch = resolve_chain_key()
        prev = self._head(agent_id)
        record["prev_digest"] = prev
        record["chain_keyed"] = True
        record["key_epoch"] = epoch
        record["digest"] = keyed_digest(record, key, self._domain())
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
        """True iff the agent's chain is intact (digests + linkage).

        The digest scheme is selected per record: records carrying
        ``chain_keyed: true`` verify under the HMAC scheme (the key is
        resolved; if no key is configured a keyed record cannot verify
        and the chain fails closed), older records verify under the
        legacy unkeyed scheme. Mixed chains verify per-record.
        """
        prev = ""
        for rec in self._read_all(agent_id):
            if rec.get("prev_digest") != prev:
                return False
            digest = rec.get("digest")
            if rec.get("chain_keyed"):
                try:
                    key, _epoch = resolve_chain_key()
                except _no_key_error():
                    # A keyed record with no key configured cannot be
                    # verified: fail closed, never treat as intact.
                    return False
                expect = keyed_digest(rec, key, self._domain())
            else:
                expect = sha256_hex(canonical(
                    {k: v for k, v in rec.items() if k != "digest"}))
            if not isinstance(digest, str) or \
                    not hmac.compare_digest(digest, expect):
                return False
            prev = digest
        return True
