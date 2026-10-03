"""Bi-temporal agent memory store (graphiti/cognee pattern).

Pattern lineage: getzep/graphiti (Apache-2.0, STEAL) -- every memory
mutation is a supersession record: conflicts CLOSE old edges, history
is never deleted; topoteretes/cognee (Apache-2.0, ADAPT) -- cognee's
documented gap (no per-item "no longer true" representation) becomes
our hard requirement: retraction is a SIGNED TOMBSTONE, never a
delete. Mechanisms only; no vendored code; stdlib only.

Standing design rule: "Recollection is a claim, not a fact." Every
recalled item carries source-episode provenance, a temporal validity
window (closed, never deleted), and a corroboration count
(Admiralty-style reliability grading).

Two record kinds:

* **Episodes** -- immutable source records
  ``{episode_id, agent_id, content_digest, source_principal,
  recorded_at, signature}``. Content is stored as DIGESTS; raw
  content is deployment-owned and never enters the store. Episodes
  are idempotent: re-recording the identical body returns the same
  episode id.

* **Semantic facts** -- bi-temporal claims, each carrying
  ``{fact_id, statement_digest, source_episode_ids[], valid_at,
  invalid_at, created_at, expired_at, retain_until,
  reliability_grade, corroboration_count}``:

  - ``valid_at`` / ``invalid_at`` = when the fact was true IN THE
    WORLD (None ``invalid_at`` = still claimed true);
  - ``created_at`` / ``expired_at`` = when the record was live IN
    THE STORE (None ``expired_at`` = still live).
  - A conflicting write SUPERSEDES: it closes the old record
    (``invalid_at`` set, ``expired_at`` set) and opens a new one.
    Both remain queryable through ``history`` -- history is never
    deleted (graphiti rule).
  - RETRACTION is a signed tombstone: a retraction record signed by
    the claim's source key or a named archivist role closes the
    fact's validity window. The fact's digest remains in history.
    THERE IS NO DELETE API -- a delete-shaped call does not exist
    (``AttributeError``, not a coded refusal: deletion is not a
    governed operation, it is an absent one).

Recall is bi-temporal: ``recall(statement_key, at)`` returns the
record live at instant ``at`` -- ``valid_at <= at < invalid_at``
(None = open) AND ``created_at <= at < expired_at``. A retracted
fact refuses ``memory-store-tombstoned`` at ANY instant (the claim
is withdrawn, not time-boxed); a lapsed retention schedule refuses
``memory-store-retention-lapsed`` (loud, never silently vanished).

Reliability grading is Admiralty-style: source reliability A-F x
information credibility 1-6, declared by the recorder at write
time and returned verbatim (``"C3"``). The store does not invent
grades. ``corroboration_count`` is COMPUTED: the number of distinct
source principals across the key's records that assert the same
statement digest -- a convention, documented as such.

All instants are caller-supplied (freshness markers, not a clock);
this module orders events, it never calls a clock. In-memory per
store (wave-292 decay precedent): not distributed consensus.

THREAT MODEL:

* The source key is the trust anchor for its records; archivist
  keys are the trust anchor for retractions. A compromised source
  key can write false facts -- compromised-host class; signatures
  from OTHER keys refuse coded ``memory-store-unsigned-retraction``.
* Episode content is digest-only: the store proves WHAT was
  claimed and WHEN, never the raw content.
* Record counts are bounded (``_MAX_EPISODES`` / ``_MAX_FACTS``);
  overflow refuses loud ``memory-store-invalid`` -- there is no
  silent eviction (F367-class residual is closed here by a bound).
"""

import hashlib
import json
import re

from gov import ed25519

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1774 -> 1774; wave-298 merge -> 1780).
# ---------------------------------------------------------------------------

MEM_EXPIRED = "memory-store-expired"
MEM_INVALID = "memory-store-invalid"
MEM_RETENTION_LAPSED = "memory-store-retention-lapsed"
MEM_TOMBSTONED = "memory-store-tombstoned"
MEM_UNSIGNED_RETRACTION = "memory-store-unsigned-retraction"

_DOMAIN = "memory_store"

__all__ = [
    "MemoryStore",
    "MemoryStoreError",
    "MEM_EXPIRED",
    "MEM_INVALID",
    "MEM_RETENTION_LAPSED",
    "MEM_TOMBSTONED",
    "MEM_UNSIGNED_RETRACTION",
]

# Bounded identifier grammar (coord-lease / supervision precedent).
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

_EPISODE_FIELDS = ("agent_id", "content_digest", "source_principal",
                   "source_pubkey", "recorded_at")
_FACT_FIELDS = ("statement_key", "statement_digest", "source_episode_ids",
                "source_principal", "source_pubkey", "valid_at",
                "retain_until", "reliability", "credibility", "created_at")
_TOMBSTONE_FIELDS = ("statement_key", "retractor_principal",
                     "retractor_pubkey", "retracted_at")

_RELIABILITY = tuple("ABCDEF")
_MIN_CREDIBILITY = 1
_MAX_CREDIBILITY = 6

_MAX_EPISODES = 8192   # bounded store: overflow refuses loud, never
_MAX_FACTS = 8192      # silently evicts (F367-class residual closed)


class MemoryStoreError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = MEM_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise MemoryStoreError(detail, code=code)


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(MEM_INVALID, "memory material is not canonicalizable "
                           "(circular or non-JSON structure)")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _sig_ok(pubkey_hex, signature_hex, message):
    """True only on exact verification success (wave-243 lesson:
    ``ed25519.verify`` is bool-returning; check ``is True``)."""
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    return ed25519.verify(pub, message, sig) is True


def _check_id(value, what="id"):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(MEM_INVALID,
              "%s must match [a-z][a-z0-9-]{0,63}; got %r" % (what, value))


def _check_digest(value, what="digest"):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(MEM_INVALID,
              "%s must be 64 lowercase hex chars" % what)


def _check_pubkey_hex(value, what="public key"):
    _check_digest(value, what)


def _check_principal(value, what="principal"):
    _check_id(value, what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(MEM_INVALID, "%s must be a non-negative int" % what)


def _check_grade(reliability, credibility):
    if reliability not in _RELIABILITY:
        _fail(MEM_INVALID,
              "reliability must be one of A-F (Admiralty source "
              "reliability); got %r" % (reliability,))
    if (not isinstance(credibility, int) or isinstance(credibility, bool)
            or not (_MIN_CREDIBILITY <= credibility <= _MAX_CREDIBILITY)):
        _fail(MEM_INVALID,
              "credibility must be an int %d..%d (Admiralty information "
              "credibility); got %r"
              % (_MIN_CREDIBILITY, _MAX_CREDIBILITY, credibility))


class MemoryStore:
    """In-memory bi-temporal memory store for one verifier plane.

    ``archivists`` maps archivist role names to ed25519 public keys
    (64 lowercase hex); archivists may sign retractions for claims
    they did not author.
    """

    def __init__(self, archivists=None):
        self._episodes = {}
        self._facts = {}       # fact_id -> record (frozen dict)
        self._by_key = {}      # statement_key -> [fact_id ...] in write order
        self._tombstones = {}  # statement_key -> tombstone record
        self._seq = 0
        self._archivists = {}
        if archivists:
            if not isinstance(archivists, dict):
                _fail(MEM_INVALID, "archivists must be a dict of "
                                   "name -> pubkey hex")
            for name, pubkey in archivists.items():
                _check_id(name, "archivist name")
                _check_pubkey_hex(pubkey, "archivist public key")
                self._archivists[name] = pubkey

    # -- episodes ----------------------------------------------------

    def record_episode(self, agent_id, content_digest, source_principal,
                       source_pubkey_hex, signature_hex, recorded_at):
        """Record an immutable source episode. Idempotent: the same
        body returns the same episode id."""
        _check_id(agent_id, "agent_id")
        _check_digest(content_digest, "content_digest")
        _check_principal(source_principal, "source_principal")
        _check_pubkey_hex(source_pubkey_hex, "source public key")
        _check_ts(recorded_at, "recorded_at")
        if not isinstance(signature_hex, str) or not _HEX128_RE.match(
                signature_hex):
            _fail(MEM_INVALID, "episode signature must be 128 "
                                "lowercase hex chars")
        body = {
            "agent_id": agent_id,
            "content_digest": content_digest,
            "source_principal": source_principal,
            "source_pubkey": source_pubkey_hex,
            "recorded_at": recorded_at,
        }
        if not _sig_ok(source_pubkey_hex, signature_hex,
                       _canonical(body)):
            _fail(MEM_INVALID, "episode signature does not verify "
                               "against the declared source key")
        episode_id = _digest(body)
        if episode_id not in self._episodes:
            if len(self._episodes) >= _MAX_EPISODES:
                _fail(MEM_INVALID, "episode store is full (%d); "
                                   "overflow refuses loud, never "
                                   "silently evicts" % _MAX_EPISODES)
            record = dict(body)
            record["episode_id"] = episode_id
            record["signature"] = signature_hex
            self._episodes[episode_id] = record
        return episode_id

    # -- facts -------------------------------------------------------

    def record_fact(self, statement_key, statement_digest,
                    source_episode_ids, source_principal,
                    source_pubkey_hex, signature_hex, valid_at,
                    recorded_at, retain_until=None,
                    reliability="C", credibility=3):
        """Record a semantic fact. A conflicting open record for the
        same statement key is SUPERSEDED (closed, never deleted);
        both remain queryable through ``history``."""
        _check_id(statement_key, "statement_key")
        _check_digest(statement_digest, "statement_digest")
        if (not isinstance(source_episode_ids, (list, tuple))
                or not source_episode_ids):
            _fail(MEM_INVALID, "source_episode_ids must be a non-empty "
                               "list of episode ids")
        episode_ids = sorted(set(source_episode_ids))
        for eid in episode_ids:
            if not isinstance(eid, str) or eid not in self._episodes:
                _fail(MEM_INVALID, "source episode %r is not a recorded "
                                   "episode -- facts must cite provenance"
                                   % (eid,))
        _check_principal(source_principal, "source_principal")
        _check_pubkey_hex(source_pubkey_hex, "source public key")
        _check_ts(valid_at, "valid_at")
        _check_ts(recorded_at, "recorded_at")
        if retain_until is not None:
            _check_ts(retain_until, "retain_until")
            if retain_until <= recorded_at:
                _fail(MEM_INVALID, "retain_until must be after "
                                   "recorded_at -- a retention schedule "
                                   "that is already lapsed at write time "
                                   "is a malformed declaration")
        _check_grade(reliability, credibility)
        if not isinstance(signature_hex, str) or not _HEX128_RE.match(
                signature_hex):
            _fail(MEM_INVALID, "fact signature must be 128 lowercase "
                                "hex chars")
        body = {
            "statement_key": statement_key,
            "statement_digest": statement_digest,
            "source_episode_ids": episode_ids,
            "source_principal": source_principal,
            "source_pubkey": source_pubkey_hex,
            "valid_at": valid_at,
            "retain_until": retain_until,
            "reliability": reliability,
            "credibility": credibility,
            "created_at": recorded_at,
        }
        if not _sig_ok(source_pubkey_hex, signature_hex,
                       _canonical(body)):
            _fail(MEM_INVALID, "fact signature does not verify against "
                               "the declared source key")
        if len(self._facts) >= _MAX_FACTS:
            _fail(MEM_INVALID, "fact store is full (%d); overflow "
                               "refuses loud, never silently evicts"
                    % _MAX_FACTS)
        # Supersession (graphiti rule): close every still-open record
        # for this key. The old claim held in the world until the new
        # claim's valid_at; a backdated correction (new valid_at <=
        # old valid_at) closes the old claim at its own start --
        # it was never true.
        for fid in self._by_key.get(statement_key, []):
            old = self._facts[fid]
            if old["expired_at"] is None:
                closed = dict(old)
                closed["invalid_at"] = (valid_at if valid_at > old["valid_at"]
                                        else old["valid_at"])
                closed["expired_at"] = recorded_at
                self._facts[fid] = closed
        self._seq += 1
        fact_id = _digest({"seq": self._seq, "body": body})
        record = dict(body)
        record["fact_id"] = fact_id
        record["invalid_at"] = None
        record["expired_at"] = None
        record["signature"] = signature_hex
        self._facts[fact_id] = record
        self._by_key.setdefault(statement_key, []).append(fact_id)
        return fact_id

    # -- retraction --------------------------------------------------

    def retract_fact(self, statement_key, retractor_principal,
                     retractor_pubkey_hex, signature_hex, at):
        """Retract a claim via a SIGNED TOMBSTONE. The retractor must
        be the claim's ORIGINAL source key (the first writer under
        this statement key -- authorship does not migrate to later
        superseding writers) or a named archivist. The tombstone
        closes the fact's validity window; the fact's digest remains
        in history. There is no un-retract and no delete."""
        _check_id(statement_key, "statement_key")
        _check_principal(retractor_principal, "retractor_principal")
        _check_pubkey_hex(retractor_pubkey_hex, "retractor public key")
        _check_ts(at, "retracted_at")
        if not isinstance(signature_hex, str) or not _HEX128_RE.match(
                signature_hex):
            _fail(MEM_UNSIGNED_RETRACTION, "retraction signature must be "
                                           "128 lowercase hex chars")
        fids = self._by_key.get(statement_key)
        if not fids:
            _fail(MEM_INVALID, "no fact recorded for statement key %r"
                    % (statement_key,))
        if statement_key in self._tombstones:
            _fail(MEM_TOMBSTONED, "statement key %r is already retracted "
                                  "-- retraction is a tombstone, not a "
                                  "toggle" % (statement_key,))
        body = {
            "statement_key": statement_key,
            "retractor_principal": retractor_principal,
            "retractor_pubkey": retractor_pubkey_hex,
            "retracted_at": at,
        }
        # The authorized retractor key is the claim's ORIGINAL source
        # key -- the first record written under this statement key.
        # Authorship is fixed at first write and does NOT migrate to
        # later superseding writers (F374: a conflicting writer must
        # never inherit retraction authority over another
        # principal's claim, and the original author must not lose
        # it). Named archivist keys may retract any claim.
        original = self._facts[fids[0]]
        authorized = {original["source_pubkey"]}
        authorized.update(self._archivists.values())
        if (retractor_pubkey_hex not in authorized
                or not _sig_ok(retractor_pubkey_hex, signature_hex,
                               _canonical(body))):
            _fail(MEM_UNSIGNED_RETRACTION, "retraction is not signed by "
                                           "the claim's source key or a "
                                           "named archivist -- refused")
        tombstone_id = _digest(body)
        tombstone = dict(body)
        tombstone["tombstone_id"] = tombstone_id
        tombstone["closed_fact_ids"] = list(fids)
        tombstone["signature"] = signature_hex
        for fid in fids:
            rec = self._facts[fid]
            if rec["expired_at"] is None:
                closed = dict(rec)
                closed["invalid_at"] = at
                closed["expired_at"] = at
                self._facts[fid] = closed
        self._tombstones[statement_key] = tombstone
        return tombstone_id

    # -- recall / history --------------------------------------------

    def _corroboration(self, statement_key, statement_digest):
        """Distinct source principals across the key's records that
        assert the same statement digest. A convention: corroboration
        is counted, not proven."""
        seen = set()
        for fid in self._by_key.get(statement_key, []):
            rec = self._facts[fid]
            if rec["statement_digest"] == statement_digest:
                seen.add(rec["source_principal"])
        return len(seen)

    def _present(self, rec):
        """The recall-shaped view of one record (the claim, not the
        fact): provenance + temporal window + grade + corroboration."""
        out = {
            "fact_id": rec["fact_id"],
            "statement_key": rec["statement_key"],
            "statement_digest": rec["statement_digest"],
            "source_episode_ids": list(rec["source_episode_ids"]),
            "source_principal": rec["source_principal"],
            "valid_at": rec["valid_at"],
            "invalid_at": rec["invalid_at"],
            "created_at": rec["created_at"],
            "expired_at": rec["expired_at"],
            "retain_until": rec["retain_until"],
            "reliability_grade": "%s%d" % (rec["reliability"],
                                           rec["credibility"]),
            "corroboration_count": self._corroboration(
                rec["statement_key"], rec["statement_digest"]),
            "tombstoned": False,
        }
        return out

    def _retention_ok(self, rec, at):
        if rec["retain_until"] is not None and rec["retain_until"] <= at:
            _fail(MEM_RETENTION_LAPSED, "record %s lapsed its declared "
                                       "retention schedule at %d -- "
                                       "refused loud, never silently "
                                       "vanished"
                    % (rec["fact_id"][:12], rec["retain_until"]))

    def recall(self, statement_key, at):
        """Return the claim live at instant ``at``. Bi-temporal:
        ``valid_at <= at < invalid_at`` AND
        ``created_at <= at < expired_at`` (None = open). A retracted
        fact refuses at any instant; a lapsed retention refuses
        loud."""
        _check_id(statement_key, "statement_key")
        _check_ts(at, "at")
        fids = self._by_key.get(statement_key)
        if not fids:
            _fail(MEM_INVALID, "no fact recorded for statement key %r"
                    % (statement_key,))
        if statement_key in self._tombstones:
            _fail(MEM_TOMBSTONED, "statement key %r was retracted -- "
                                  "the claim is withdrawn, not "
                                  "time-boxed" % (statement_key,))
        best = None
        for fid in fids:
            rec = self._facts[fid]
            world_open = (rec["valid_at"] <= at
                          and (rec["invalid_at"] is None
                               or at < rec["invalid_at"]))
            store_open = (rec["created_at"] <= at
                          and (rec["expired_at"] is None
                               or at < rec["expired_at"]))
            if world_open and store_open:
                if best is None or rec["created_at"] > best["created_at"]:
                    best = rec
        if best is None:
            _fail(MEM_EXPIRED, "no live record for %r at instant %d -- "
                               "the claim's validity window does not "
                               "cover it" % (statement_key, at))
        self._retention_ok(best, at)
        return self._present(best)

    def history(self, statement_key, at):
        """Every record ever written for the key, oldest first, with
        the tombstone appended last when present. Nothing is ever
        deleted; a lapsed retention schedule refuses loud."""
        _check_id(statement_key, "statement_key")
        _check_ts(at, "at")
        fids = self._by_key.get(statement_key)
        if not fids:
            _fail(MEM_INVALID, "no fact recorded for statement key %r"
                    % (statement_key,))
        out = []
        for fid in fids:
            rec = self._facts[fid]
            self._retention_ok(rec, at)
            out.append(self._present(rec))
        tomb = self._tombstones.get(statement_key)
        if tomb is not None:
            view = dict(tomb)
            view["tombstoned"] = True
            out.append(view)
        return out
