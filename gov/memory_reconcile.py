"""Memory reconciliation seam + poisoning defenses (mem0/qdrant patterns).

Pattern lineage: mem0ai/mem0 (STEAL, Apache-2.0) -- ADD/UPDATE/DELETE/NOOP
reconciliation vocabulary, per-agent namespacing, per-memory history;
qdrant/qdrant (ADAPT, Apache-2.0) -- memory-poisoning defense checklist
(payload metadata, mandatory tenant predicate, snapshot-before-mutation,
tombstones excluded from recall). Mechanisms only; no vendored code;
stdlib only.

Wave-297 design rule honored: *"Recollection is a claim, not a fact."*
Every recalled item carries source-episode provenance, a temporal
validity window (closed, never deleted), and a corroboration count
(Admiralty-style reliability grading). Retraction is a signed tombstone.
Recall queries carry a mandatory tenant/scope predicate; writes pass the
ADD/UPDATE/DELETE/NOOP reconciliation seam; retention schedules declare
expiry at write time.

This module is a DECISION layer, like ``gov/supervision.py`` and
``gov/coordination_lease.py``: ``reconcile`` returns a signed
reconciliation decision record; the actual application of that decision
to the memory store is deployment-owned (lane 2, ``gov/memory_store.py``,
built in parallel this wave -- see MERGE-SEAM below).

MERGE-SEAM (for the wave-298 merge coordinator -- lane 2 builds
``gov/memory_store.py`` in parallel; this module deliberately does NOT
import it. The merge seam is a record-shape contract: this module
defines, consumes, and emits records in the shape ``memory-record/v1``:

    {"schema": "memory-record/v1",
     "fact_id": <64 lowercase hex>,   # sha256 of canonical
                                      # (namespace, key, value_digest,
                                      #  written_at, supersedes)
     "namespace": <agent id>,         # [a-z][a-z0-9-]{0,63}
     "key": <str, 1..256 chars>,      # e.g. "user/preference/theme"
     "value_digest": <64 lowercase hex>,  # digest of the (redacted) value;
                                      # raw values never enter this module
     "state": "active" | "tombstoned",
     "written_at": <non-negative int>,    # freshness marker, caller-supplied
     "supersedes": <64 hex fact_id | None>,
     "snapshot_digest": <64 hex | None>,  # prior-state snapshot on
                                      # UPDATE/DELETE (qdrant checklist)
     "provenance": {"source_principal": <agent id>,
                    "reliability": <grade>,   # A1/A2/B1/B2/C1/C2/C3/D4
                    "corroborations": <non-negative int>,
                    "ingested_at": <non-negative int>},
     "expires_at": <non-negative int | None>}  # retention declared at
                                      # write time (wave-297 design rule)

A WRITE CANDIDATE is the same shape with ``state`` unset and one extra
field ``"op"`` in {"add", "update", "delete"}; candidates are signed by
the writing principal's key over the canonical JSON of the record.
Lane 2's store must either adopt this exact shape or provide an adapter
that converts its native records into it before calling
``reconcile``/``recall``; the merge coordinator adapts one side and
re-runs this lane's battery + tests.

The reconciliation vocabulary (mem0):

* ``ADD`` -- new fact, no conflict with any live fact under the key;
* ``UPDATE`` -- supersedes an existing active fact; the old record is
  CLOSED (superseded_by set), never deleted; the decision carries a
  snapshot digest of the prior state;
* ``DELETE`` -- retraction request; emits a SIGNED TOMBSTONE. The old
  record is never removed; tombstoned facts are excluded from recall;
* ``NOOP`` -- duplicate or already-confirmed fact; nothing changes.

Every reconciliation decision is itself a signed, digest-bound record
with provenance (which existing fact, which principal decided, why).

Per-agent namespacing (mem0): memory lives in namespaces named by agent
id. A namespace is DECLARED up front with its owner public key (closed
inventory -- undeclared namespaces refuse
``memory-reconcile-unauthorized-namespace``). Writes are owner-key only.
Cross-namespace RECALL requires a declared, signed sharing grant that is
bounded, time-boxed, and revocable; recall without a live grant refuses
coded.

Poisoning defenses (qdrant checklist, adapted):

* payload metadata on every item (source principal, ingestion instant,
  reliability grade);
* MANDATORY tenant/scope predicate on every recall -- a recall without
  a scope refuses ``memory-reconcile-scope-missing`` (there is no
  default scope);
* snapshot-before-mutation: every UPDATE/DELETE decision carries a
  snapshot digest of the prior state; a mutation request without one
  refuses ``memory-reconcile-invalid``;
* tombstoned items are excluded from recall (recall over a tombstoned
  fact refuses ``memory-reconcile-invalid``);
* write-rate bound per source principal (bounded, fail-closed --
  exceeded refuses ``memory-reconcile-invalid``);
* conflict-evidence requirement: an UPDATE that contradicts a
  HIGH-reliability fact (grade A1/A2/B1/B2) requires corroboration
  count >= 2 or a signed archivist override, else refuses
  ``memory-reconcile-poison-refused``.

THREAT MODEL:

* The reconciler seed is the trust anchor (signs decisions and
  tombstones). The reconciler is in-memory per verifier (wave-292
  decay precedent): two verifiers do not share reconciliation state,
  so this is per-coordinator-plane reconciliation, not distributed
  consensus.
* ``written_at`` / ``ingested_at`` / ``decided_at`` are freshness
  markers, not a clock. Callers pass explicit instants; this module
  orders events, it does not run a clock.
* A compromised namespace-owner key can write poisoned facts into its
  OWN namespace -- the compromised-host class; the reconciliation
  record proves what was claimed, by whom, with what evidence, so a
  third party can re-verify. Forged writes from OTHER keys refuse
  coded ``memory-reconcile-invalid``. The poisoning defenses bound
  what even the owner can do (rate, evidence, snapshots).
"""

import hashlib
import json
import re

from gov import ed25519

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1769 -> 1774; wave-298 merge -> 1780).
# ---------------------------------------------------------------------------

RC_INVALID = "memory-reconcile-invalid"
RC_SCOPE_MISSING = "memory-reconcile-scope-missing"
RC_UNAUTH_NS = "memory-reconcile-unauthorized-namespace"
RC_POISON = "memory-reconcile-poison-refused"
RC_CONFLICT = "memory-reconcile-conflict-unresolved"

_DOMAIN = "memory_reconcile"

# ---------------------------------------------------------------------------
# Reconciliation vocabulary (mem0).
# ---------------------------------------------------------------------------

RC_ADD = "ADD"
RC_UPDATE = "UPDATE"
RC_DELETE = "DELETE"
RC_NOOP = "NOOP"
_DECISIONS = (RC_ADD, RC_UPDATE, RC_DELETE, RC_NOOP)
_OPS = ("add", "update", "delete")

# ---------------------------------------------------------------------------
# Bounded identifier grammar (coord-lease / supervision precedent).
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# Record bounds: there is no unbounded memory record.
_MAX_KEY_LEN = 256
_MAX_NAMESPACES = 1024       # closed inventory bound
_MAX_FACTS_PER_NAMESPACE = 10000
_MAX_GRANTS = 1024           # bounded sharing-grant inventory
_MAX_GRANT_TTL = 30 * 86400  # 30 days; there is no unbounded grant
_MAX_WRITES = 10000          # per-principal write bound, per window
_MIN_WRITES = 1
_MIN_WINDOW = 60
_MAX_WINDOW = 86400          # 24h; there is no unbounded rate window
_GRADES = ("A1", "A2", "B1", "B2", "C1", "C2", "C3", "D4")
_HIGH_RELIABILITY = ("A1", "A2", "B1", "B2")  # Admiralty-style: high grades
_MIN_CORROBORATIONS = 2      # to contradict a high-reliability fact
_STATES = ("active", "tombstoned")

_SCHEMA = "memory-record/v1"
_CANDIDATE_FIELDS = ("schema", "namespace", "key", "value_digest",
                     "written_at", "supersedes", "provenance",
                     "expires_at", "op")
_RECORD_FIELDS = ("schema", "fact_id", "namespace", "key", "value_digest",
                  "state", "written_at", "supersedes", "snapshot_digest",
                  "provenance", "expires_at")
_DECISION_FIELDS = ("schema", "decision", "fact_id", "supersedes",
                    "snapshot_digest", "reason", "decided_by",
                    "decided_at", "record_digest")
_GRANT_FIELDS = ("schema", "grant_id", "owner_namespace", "grantee_namespace",
                 "not_before", "not_after")


class MemoryReconcileError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = RC_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise MemoryReconcileError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def _emit_event(event, fields):
    """Returns True if a sink consumed the event, False when no sink is
    wired or the sink raised. Never raises (F345-class)."""
    if _EMIT is None:
        return False
    try:
        _EMIT(event, fields)
        return True
    except Exception:
        return False


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(RC_INVALID, "memory material is not canonicalizable "
                          "(circular or non-JSON structure)")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _sig_ok(pubkey_hex, signature_hex, message):
    """True only on exact verification success (wave-243 lesson:
    ``ed25519.verify`` is bool-returning; check ``is True``)."""
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    ok = ed25519.verify(pub, message, sig)
    return ok is True


def _check_id(value, what="id"):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(RC_INVALID,
              "%s must match [a-z][a-z0-9-]{0,63}; got %r" % (what, value))


def _check_hex64(value, what):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(RC_INVALID,
              "%s must be 64 lowercase hex chars" % what)


def _check_seed(value, what="reconciler seed"):
    if not isinstance(value, bytes) or len(value) != 32:
        _fail(RC_INVALID, "%s must be 32 raw bytes" % what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(RC_INVALID, "%s must be a non-negative int" % what)


def _check_opt_ts(value, what):
    if value is not None:
        _check_ts(value, what)


def _check_grade(value):
    if value not in _GRADES:
        _fail(RC_INVALID,
              "reliability grade must be one of %s; got %r"
              % ("/".join(_GRADES), value))


def _check_provenance(prov):
    if not isinstance(prov, dict):
        _fail(RC_INVALID, "provenance must be a dict")
    _check_id(prov.get("source_principal"), "provenance.source_principal")
    _check_grade(prov.get("reliability"))
    corr = prov.get("corroborations")
    if not isinstance(corr, int) or isinstance(corr, bool) or corr < 0:
        _fail(RC_INVALID, "provenance.corroborations must be a "
                          "non-negative int")
    _check_ts(prov.get("ingested_at"), "provenance.ingested_at")
    extra = set(prov) - {"source_principal", "reliability",
                         "corroborations", "ingested_at"}
    if extra:
        _fail(RC_INVALID, "provenance carries unexpected fields: %r"
              % sorted(extra))


def _check_candidate_shape(cand):
    """Validate a write candidate's shape (unsigned content)."""
    if not isinstance(cand, dict):
        _fail(RC_INVALID, "candidate must be a dict")
    extra = set(cand) - set(_CANDIDATE_FIELDS) - {"signature"}
    if extra:
        _fail(RC_INVALID, "candidate carries unexpected fields: %r"
              % sorted(extra))
    if cand.get("schema") != _SCHEMA:
        _fail(RC_INVALID, "candidate schema must be %r" % _SCHEMA)
    _check_id(cand.get("namespace"), "namespace")
    key = cand.get("key")
    if not isinstance(key, str) or not (1 <= len(key) <= _MAX_KEY_LEN):
        _fail(RC_INVALID, "key must be a string of 1..%d chars"
              % _MAX_KEY_LEN)
    _check_hex64(cand.get("value_digest"), "value_digest")
    _check_ts(cand.get("written_at"), "written_at")
    sup = cand.get("supersedes")
    if sup is not None:
        _check_hex64(sup, "supersedes")
    _check_provenance(cand.get("provenance"))
    _check_opt_ts(cand.get("expires_at"), "expires_at")
    if cand.get("op") not in _OPS:
        _fail(RC_INVALID, "op must be one of %s" % "/".join(_OPS))


def _unsigned(candidate):
    """The candidate body covered by the writer's signature."""
    return {k: candidate[k] for k in _CANDIDATE_FIELDS if k in candidate}


def _unsigned_record(record):
    return {k: record[k] for k in _RECORD_FIELDS if k in record}


def _unsigned_decision(decision):
    return {k: decision[k] for k in _DECISION_FIELDS if k in decision}


def _unsigned_grant(grant):
    return {k: grant[k] for k in _GRANT_FIELDS if k in grant}


def _fact_id(namespace, key, value_digest, written_at, supersedes):
    return _digest({"namespace": namespace, "key": key,
                    "value_digest": value_digest,
                    "written_at": written_at,
                    "supersedes": supersedes})


class MemoryReconciler:
    """Decision-layer memory reconciliation (mem0 vocabulary, qdrant
    poisoning defenses). In-memory per verifier; returns signed
    decisions -- application to the store is deployment-owned."""

    def __init__(self, seed, reconciler_id,
                 max_writes_per_principal=100,
                 write_window_seconds=3600):
        _check_seed(seed)
        _check_id(reconciler_id, "reconciler_id")
        if (not isinstance(max_writes_per_principal, int)
                or isinstance(max_writes_per_principal, bool)
                or not _MIN_WRITES <= max_writes_per_principal <= _MAX_WRITES):
            _fail(RC_INVALID,
                  "max_writes_per_principal must be bounded %d..%d; there "
                  "is no unbounded write rate"
                  % (_MIN_WRITES, _MAX_WRITES))
        if (not isinstance(write_window_seconds, int)
                or isinstance(write_window_seconds, bool)
                or not _MIN_WINDOW <= write_window_seconds <= _MAX_WINDOW):
            _fail(RC_INVALID,
                  "write_window_seconds must be bounded %d..%d seconds; "
                  "there is no unbounded window"
                  % (_MIN_WINDOW, _MAX_WINDOW))
        self._seed = seed
        self._reconciler_id = reconciler_id
        self._max_writes = max_writes_per_principal
        self._window = write_window_seconds
        self._namespaces = {}        # namespace -> owner pubkey hex
        self._facts = {}             # (namespace, key) -> list of records
        self._grants = {}            # grant_id -> grant record
        self._revoked = set()        # revoked grant_ids
        self._write_times = {}       # principal -> [instants]
        self._archivist_pubkey = None

    # -- signing ------------------------------------------------------
    def _pubkey_hex(self):
        return ed25519.publickey(self._seed).hex()

    def _sign(self, body):
        return ed25519.sign(self._seed, _canonical(body)).hex()

    # -- namespace inventory (closed) ---------------------------------
    def declare_namespace(self, namespace, owner_pubkey_hex):
        """Declare a namespace with its owner public key. Closed
        inventory: undeclared namespaces cannot be written or read."""
        _check_id(namespace, "namespace")
        if not isinstance(owner_pubkey_hex, str) or not _HEX64_RE.match(
                owner_pubkey_hex):
            _fail(RC_INVALID, "owner public key must be 64 lowercase hex")
        if namespace in self._namespaces:
            _fail(RC_INVALID, "namespace %r already declared" % namespace)
        if len(self._namespaces) >= _MAX_NAMESPACES:
            _fail(RC_INVALID, "namespace inventory is bounded at %d"
                  % _MAX_NAMESPACES)
        self._namespaces[namespace] = owner_pubkey_hex
        _emit_event("namespace-declared", {"namespace": namespace})

    def declare_archivist(self, archivist_pubkey_hex):
        """Declare the archivist key that may sign high-reliability
        contradiction overrides (mem0-style trusted curator)."""
        if not isinstance(archivist_pubkey_hex, str) or not _HEX64_RE.match(
                archivist_pubkey_hex):
            _fail(RC_INVALID, "archivist public key must be 64 lowercase "
                              "hex")
        self._archivist_pubkey = archivist_pubkey_hex

    # -- sharing grants (bounded, time-boxed, revocable) ---------------
    def grant_sharing(self, owner_namespace, grantee_namespace,
                      not_before, not_after, owner_seed):
        """The owner of a namespace signs a sharing grant for another
        namespace. Bounded TTL; revocable via ``revoke_grant``."""
        _check_id(owner_namespace, "owner_namespace")
        _check_id(grantee_namespace, "grantee_namespace")
        if owner_namespace not in self._namespaces:
            _fail(RC_UNAUTH_NS, "owner namespace %r is not declared"
                  % owner_namespace)
        _check_seed(owner_seed, "owner seed")
        _check_ts(not_before, "not_before")
        _check_ts(not_after, "not_after")
        if not not_before < not_after:
            _fail(RC_INVALID, "grant window must be non-empty")
        if not_after - not_before > _MAX_GRANT_TTL:
            _fail(RC_INVALID, "grant TTL is bounded at %d seconds; there "
                              "is no unbounded grant" % _MAX_GRANT_TTL)
        if len(self._grants) >= _MAX_GRANTS:
            _fail(RC_INVALID, "grant inventory is bounded at %d"
                  % _MAX_GRANTS)
        if ed25519.publickey(owner_seed).hex() != \
                self._namespaces[owner_namespace]:
            _fail(RC_UNAUTH_NS, "grant must be signed by the namespace "
                                "owner's key")
        grant_id = _digest({"owner": owner_namespace,
                            "grantee": grantee_namespace,
                            "not_before": not_before,
                            "not_after": not_after})[:32]
        grant = {"schema": "memory-sharing-grant/v1",
                 "grant_id": grant_id,
                 "owner_namespace": owner_namespace,
                 "grantee_namespace": grantee_namespace,
                 "not_before": not_before,
                 "not_after": not_after}
        grant["signature"] = ed25519.sign(
            owner_seed, _canonical(_unsigned_grant(grant))).hex()
        self._grants[grant_id] = grant
        _emit_event("sharing-granted",
                    {"grant_id": grant_id,
                     "owner": owner_namespace, "grantee": grantee_namespace})
        return dict(grant)

    def revoke_grant(self, grant_id, owner_seed):
        """Revoke a sharing grant; revocation is owner-signed and loud."""
        _check_seed(owner_seed, "owner seed")
        grant = self._grants.get(grant_id)
        if grant is None:
            _fail(RC_INVALID, "unknown grant %r" % grant_id)
        if ed25519.publickey(owner_seed).hex() != \
                self._namespaces[grant["owner_namespace"]]:
            _fail(RC_UNAUTH_NS, "revocation must be signed by the "
                                "namespace owner's key")
        self._revoked.add(grant_id)
        _emit_event("sharing-revoked", {"grant_id": grant_id})

    def _verify_presented_grant(self, owner_namespace, grantee_namespace,
                                grant, at):
        """Verify a bearer sharing grant presented at recall time (F376).

        The grant is verified against the owner namespace's DECLARED
        owner key (not against any caller-supplied key), its window, and
        the live grant inventory (revocation honored). A bare namespace
        string never authorizes cross-namespace reads.
        """
        if not isinstance(grant, dict):
            _fail(RC_UNAUTH_NS, "cross-namespace recall requires "
                                "presenting the signed sharing grant")
        extra = set(grant) - set(_GRANT_FIELDS) - {"signature"}
        if extra:
            _fail(RC_UNAUTH_NS, "grant carries unexpected fields: %r"
                  % sorted(extra))
        if grant.get("schema") != "memory-sharing-grant/v1":
            _fail(RC_UNAUTH_NS, "grant schema must be "
                                "memory-sharing-grant/v1")
        if grant.get("owner_namespace") != owner_namespace:
            _fail(RC_UNAUTH_NS, "presented grant is not issued by "
                                "namespace %r" % owner_namespace)
        if grant.get("grantee_namespace") != grantee_namespace:
            _fail(RC_UNAUTH_NS, "presented grant is not issued to %r"
                  % grantee_namespace)
        gid = grant.get("grant_id")
        if not isinstance(gid, str) or not gid:
            _fail(RC_UNAUTH_NS, "grant_id must be a non-empty string")
        _check_ts(grant.get("not_before"), "grant.not_before")
        _check_ts(grant.get("not_after"), "grant.not_after")
        owner_pubkey = self._namespaces.get(owner_namespace)
        sig = grant.get("signature")
        if not isinstance(sig, str) or not _sig_ok(
                owner_pubkey, sig, _canonical(_unsigned_grant(grant))):
            _fail(RC_UNAUTH_NS, "grant signature does not verify against "
                                "the owner namespace's declared key")
        nb, na = grant["not_before"], grant["not_after"]
        if not nb <= at < na:
            _fail(RC_UNAUTH_NS, "grant window does not cover the recall "
                                "instant")
        live = self._grants.get(gid)
        if live is None or gid in self._revoked:
            _fail(RC_UNAUTH_NS, "grant %r is not live (unknown or "
                                "revoked)" % gid)
        if live.get("signature") != sig:
            _fail(RC_UNAUTH_NS, "presented grant does not match the live "
                                "inventory record")

    # -- write-rate bound ----------------------------------------------
    def _check_write_rate(self, principal, at):
        times = self._write_times.get(principal, [])
        lo = at - self._window
        times = [t for t in times if lo < t <= at]
        if len(times) >= self._max_writes:
            _fail(RC_INVALID,
                  "write rate bound exceeded for principal %r "
                  "(%d writes in %d seconds); bounded, fail-closed"
                  % (principal, self._max_writes, self._window))
        times.append(at)
        self._write_times[principal] = times

    # -- record assembly ------------------------------------------------
    def _latest(self, namespace, key):
        hist = self._facts.get((namespace, key), [])
        return hist[-1] if hist else None

    def _assemble_record(self, candidate, state, snapshot_digest):
        fid = _fact_id(candidate["namespace"], candidate["key"],
                       candidate["value_digest"], candidate["written_at"],
                       candidate.get("supersedes"))
        return {
            "schema": _SCHEMA,
            "fact_id": fid,
            "namespace": candidate["namespace"],
            "key": candidate["key"],
            "value_digest": candidate["value_digest"],
            "state": state,
            "written_at": candidate["written_at"],
            "supersedes": candidate.get("supersedes"),
            "snapshot_digest": snapshot_digest,
            "provenance": dict(candidate["provenance"]),
            "expires_at": candidate.get("expires_at"),
        }

    def _decision(self, decision, record, supersedes, snapshot_digest,
                  reason, at):
        body = {
            "schema": "memory-reconcile-decision/v1",
            "decision": decision,
            "fact_id": record["fact_id"],
            "supersedes": supersedes,
            "snapshot_digest": snapshot_digest,
            "reason": reason,
            "decided_by": self._reconciler_id,
            "decided_at": at,
            "record_digest": _digest(_unsigned_record(record)),
        }
        out = dict(body)
        out["signature"] = self._sign(_unsigned_decision(out))
        _emit_event("reconcile-decision",
                    {"decision": decision, "fact_id": record["fact_id"],
                     "namespace": record["namespace"]})
        return out

    # -- the reconciliation seam ---------------------------------------
    def reconcile(self, candidate, existing_facts, policy, at):
        """The reconciliation seam (mem0 vocabulary). Every write
        passes through here and receives exactly one of ADD / UPDATE /
        DELETE / NOOP. Returns a signed reconciliation decision
        record; the store applies it.

        ``candidate``: a signed write candidate (``memory-record/v1``
        shape + ``op`` + ``signature`` by the namespace owner's key).
        ``existing_facts``: the store's current history for the key
        (list of ``memory-record/v1`` records; may be empty). The
        store's history must agree with this reconciler's own
        inventory or the decision refuses ``memory-reconcile-invalid``.
        ``policy``: {"archivist_override": <sig hex | None>} -- a
        signed archivist override permitting contradiction of a
        high-reliability fact.
        ``at``: caller-supplied instant (freshness marker).
        """
        _check_candidate_shape(candidate)
        _check_ts(at, "at")
        if not isinstance(existing_facts, list):
            _fail(RC_INVALID, "existing_facts must be a list")
        if not isinstance(policy, dict):
            _fail(RC_INVALID, "policy must be a dict")

        ns = candidate["namespace"]
        if ns not in self._namespaces:
            _fail(RC_UNAUTH_NS, "namespace %r is not declared" % ns)
        owner_pubkey = self._namespaces[ns]

        # Writer authentication: the candidate must be signed by the
        # namespace owner's key. Cross-namespace or foreign-key writes
        # refuse -- compromised-host class is bounded to the owner's
        # own namespace.
        sig = candidate.get("signature")
        if not isinstance(sig, str):
            _fail(RC_INVALID, "candidate carries no signature")
        if not _sig_ok(owner_pubkey, sig, _canonical(_unsigned(candidate))):
            _fail(RC_UNAUTH_NS, "candidate is not signed by the namespace "
                                "owner's key")

        principal = candidate["provenance"]["source_principal"]
        # F375: the write-rate bound is keyed on the authenticated
        # namespace-owner key (whose signature was just verified above)
        # IN ADDITION TO the self-reported provenance string. The owner
        # signs every candidate, so rotating the source_principal string
        # no longer evades the bound; distinct owners keep independent
        # budgets. Both keys must pass.
        self._check_write_rate("owner:" + owner_pubkey, at)
        self._check_write_rate("principal:" + principal, at)

        key = candidate["key"]
        hist = list(existing_facts)
        for rec in hist:
            if not isinstance(rec, dict) or rec.get("schema") != _SCHEMA:
                _fail(RC_INVALID, "existing fact is not memory-record/v1")
        mine = self._latest(ns, key)
        # The store and the reconciler must agree on history; a
        # divergent history is a fork, refused loud (no silent merge).
        if (mine is None) != (not hist):
            _fail(RC_INVALID, "store history diverges from reconciler "
                              "inventory for (%r, %r)" % (ns, key))
        if mine is not None and hist and \
                hist[-1].get("fact_id") != mine["fact_id"]:
            _fail(RC_INVALID, "store history diverges from reconciler "
                              "inventory for (%r, %r)" % (ns, key))

        op = candidate["op"]
        if op == "delete":
            return self._decide_delete(candidate, hist, at)
        latest = hist[-1] if hist else None
        if latest is None:
            if op != "add":
                _fail(RC_INVALID, "op %r has no existing fact to act on"
                      % op)
            return self._decide_add(candidate, at)
        if latest.get("state") == "tombstoned":
            # Tombstones are never resurrected in place: a write after
            # retraction is a NEW fact (ADD), superseding the tombstone.
            if op != "add":
                _fail(RC_INVALID, "op %r on a tombstoned key; only a new "
                                  "ADD is accepted" % op)
            return self._decide_add(candidate, at,
                                    supersedes=latest["fact_id"])
        if latest["value_digest"] == candidate["value_digest"]:
            return self._decide_noop(candidate, latest, at)
        if op == "add":
            _fail(RC_CONFLICT, "an active fact already exists under key "
                               "%r with a different value; ADD is not a "
                               "supersession -- use op=update or retract "
                               "first" % key)
        return self._decide_update(candidate, latest, policy, at)

    def _decide_add(self, candidate, at, supersedes=None):
        record = self._assemble_record(candidate, "active", None)
        if supersedes is not None:
            record["supersedes"] = supersedes
            record["fact_id"] = _fact_id(
                candidate["namespace"], candidate["key"],
                candidate["value_digest"], candidate["written_at"],
                supersedes)
        self._store_record(record)
        return self._decision(RC_ADD, record, supersedes, None,
                              "new fact; no conflicting live fact", at)

    def _decide_noop(self, candidate, latest, at):
        record = self._assemble_record(candidate, "active", None)
        record["fact_id"] = latest["fact_id"]
        record["supersedes"] = latest.get("supersedes")
        return self._decision(RC_NOOP, record, latest.get("supersedes"),
                              None, "duplicate/confirmed fact; nothing "
                              "changes", at)

    def _decide_update(self, candidate, latest, policy, at):
        # Snapshot-before-mutation (qdrant checklist): the decision
        # carries a digest of the prior state. A mutation request that
        # cannot name the state it supersedes refuses.
        snapshot_digest = _digest(_unsigned_record(latest))
        if candidate.get("supersedes") != latest["fact_id"]:
            _fail(RC_INVALID, "UPDATE must name supersedes=<latest "
                              "fact_id>; snapshot-before-mutation is "
                              "mandatory")
        # Conflict-evidence requirement (qdrant checklist): an UPDATE
        # that contradicts a HIGH-reliability fact needs corroboration
        # >= 2 or a signed archivist override -- otherwise it is
        # refused as poison.
        if latest["provenance"]["reliability"] in _HIGH_RELIABILITY:
            corr = candidate["provenance"]["corroborations"]
            override = policy.get("archivist_override")
            ok_override = (
                isinstance(override, str)
                and self._archivist_pubkey is not None
                and _sig_ok(self._archivist_pubkey, override,
                            _canonical(_unsigned(candidate))))
            if corr < _MIN_CORROBORATIONS and not ok_override:
                _fail(RC_POISON,
                      "UPDATE contradicts a high-reliability fact "
                      "(grade %s) without corroboration >= %d or a signed "
                      "archivist override; refused as poison"
                      % (latest["provenance"]["reliability"],
                         _MIN_CORROBORATIONS))
        record = self._assemble_record(candidate, "active", snapshot_digest)
        record["supersedes"] = latest["fact_id"]
        record["fact_id"] = _fact_id(
            candidate["namespace"], candidate["key"],
            candidate["value_digest"], candidate["written_at"],
            latest["fact_id"])
        self._store_record(record)
        return self._decision(RC_UPDATE, record, latest["fact_id"],
                              snapshot_digest,
                              "supersedes %s; prior state closed, never "
                              "deleted" % latest["fact_id"], at)

    def _decide_delete(self, candidate, hist, at):
        latest = hist[-1] if hist else None
        if latest is None:
            _fail(RC_INVALID, "DELETE names no existing fact")
        if latest.get("state") == "tombstoned":
            _fail(RC_INVALID, "fact %s is already tombstoned"
                  % latest["fact_id"])
        if candidate.get("supersedes") != latest["fact_id"]:
            _fail(RC_INVALID, "DELETE must name supersedes=<latest "
                              "fact_id>; snapshot-before-mutation is "
                              "mandatory")
        snapshot_digest = _digest(_unsigned_record(latest))
        tomb = self._assemble_record(candidate, "tombstoned",
                                     snapshot_digest)
        tomb["fact_id"] = latest["fact_id"]
        tomb["supersedes"] = latest["fact_id"]
        tomb["value_digest"] = latest["value_digest"]
        self._store_record(tomb)
        return self._decision(RC_DELETE, tomb, latest["fact_id"],
                              snapshot_digest,
                              "retraction is a signed tombstone; the "
                              "record is never removed", at)

    def _store_record(self, record):
        ns, key = record["namespace"], record["key"]
        if (ns, key) not in self._facts and \
                sum(1 for h in self._facts if h[0] == ns) >= \
                _MAX_FACTS_PER_NAMESPACE:
            _fail(RC_INVALID, "fact inventory for namespace %r is bounded "
                              "at %d keys" % (ns, _MAX_FACTS_PER_NAMESPACE))
        self._facts.setdefault((ns, key), []).append(record)

    # -- recall (mandatory scope) ---------------------------------------
    def recall(self, scope, caller_namespace, at, grant=None):
        """Recall facts under a MANDATORY scope predicate (qdrant
        checklist). ``scope`` is {"namespace": <id>, "key": <str>} --
        a recall without a scope refuses ``memory-reconcile-scope-missing``
        (there is no default scope). Tombstoned facts are excluded from
        recall.

        Caller identity (F376): ``caller_namespace`` MUST be the
        deployment-authenticated identity of the caller -- this module
        is a decision layer and cannot authenticate callers itself; a
        bare string is never trusted beyond that precondition.

        Cross-namespace recall additionally requires the caller to
        PRESENT the signed sharing grant (bearer-grant model):
        ``grant`` is verified against the owner namespace's DECLARED
        owner key, its window, and the live grant inventory (revocation
        honored). Without a presented grant, cross-namespace recall
        refuses ``memory-reconcile-unauthorized-namespace`` -- a
        self-asserted grantee name is never sufficient."""
        if not isinstance(scope, dict) or not scope.get("namespace") \
                or not scope.get("key"):
            _fail(RC_SCOPE_MISSING,
                  "recall requires a scope predicate "
                  '{"namespace": ..., "key": ...}; there is no default '
                  "scope")
        _check_id(caller_namespace, "caller_namespace")
        _check_ts(at, "at")
        ns, key = scope["namespace"], scope["key"]
        _check_id(ns, "scope.namespace")
        if not isinstance(key, str) or not (1 <= len(key) <= _MAX_KEY_LEN):
            _fail(RC_SCOPE_MISSING, "scope key must be a string of "
                                    "1..%d chars" % _MAX_KEY_LEN)
        if ns not in self._namespaces:
            _fail(RC_UNAUTH_NS, "scope namespace %r is not declared" % ns)
        if caller_namespace != ns:
            self._verify_presented_grant(ns, caller_namespace, grant, at)
        rec = self._latest(ns, key)
        if rec is None:
            _fail(RC_INVALID, "no fact under key %r in namespace %r"
                  % (key, ns))
        if rec.get("state") == "tombstoned":
            _fail(RC_INVALID, "fact %s is tombstoned; tombstones are "
                              "excluded from recall" % rec["fact_id"])
        _emit_event("recall", {"namespace": ns, "key": key,
                               "fact_id": rec["fact_id"]})
        return json.loads(json.dumps(rec))  # deep copy, store stays frozen

    # -- decision re-verification (evidence re-execution) ----------------
    def verify_decision(self, decision):
        """Re-verify a reconciliation decision's signature against this
        reconciler's key. Forged or malformed decisions refuse
        ``memory-reconcile-invalid`` -- a verifier replays the refusal
        without the engine."""
        if not isinstance(decision, dict):
            _fail(RC_INVALID, "decision must be a dict")
        extra = set(decision) - set(_DECISION_FIELDS) - {"signature"}
        if extra:
            _fail(RC_INVALID, "decision carries unexpected fields: %r"
                  % sorted(extra))
        if decision.get("schema") != "memory-reconcile-decision/v1":
            _fail(RC_INVALID, "decision schema must be "
                              "memory-reconcile-decision/v1")
        if decision.get("decision") not in _DECISIONS:
            _fail(RC_INVALID, "decision must be one of %s"
                  % "/".join(_DECISIONS))
        for f in ("fact_id", "record_digest"):
            _check_hex64(decision.get(f), f)
        sup = decision.get("supersedes")
        if sup is not None:
            _check_hex64(sup, "supersedes")
        snap = decision.get("snapshot_digest")
        if snap is not None:
            _check_hex64(snap, "snapshot_digest")
        _check_id(decision.get("decided_by"), "decided_by")
        _check_ts(decision.get("decided_at"), "decided_at")
        if not isinstance(decision.get("reason"), str) or \
                not decision["reason"]:
            _fail(RC_INVALID, "decision reason must be a non-empty string")
        sig = decision.get("signature")
        if not isinstance(sig, str):
            _fail(RC_INVALID, "decision carries no signature")
        if not _sig_ok(self._pubkey_hex(), sig,
                       _canonical(_unsigned_decision(decision))):
            _fail(RC_INVALID, "decision signature does not verify")
        return True
