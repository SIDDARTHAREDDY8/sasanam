"""Signed CRDT shared state for agent coordination (automerge pattern).

Pattern lineage: automerge/automerge (MIT) -- a change DAG with actor
IDs and deterministic merge; forks become first-class objects rather
than conflicts to resolve by overwriting. Mechanisms only; no vendored
code; stdlib only.

The automerge gap this module fixes: automerge asserts authorship, it
does not sign it. Every change here carries an Ed25519 signature over
(actor_id, seq, payload, parent digests, author public key) -- a fork
with a forged signature refuses coded ``coord-state-forgery`` instead
of merging.

Standing design rule this module enforces: "shared state merges, never
overwrites." Concretely:

* changes are content-addressed (sha256 of the signed envelope);
* ``StateDag.merge`` is UNION-only -- a signed change is never
  deleted, replaced, or shadowed by the merge. An attempt to present
  a different change for an already-used (actor_id, seq) slot refuses
  coded ``coord-state-overwrite``;
* replaying an already-ingested change is idempotent (no-op), never
  a second application;
* merge is deterministic: ``sorted(changes, key=(seq, actor_id,
  digest))``; two merge orders produce the same merged head;
* forks are first-class: ``merge`` returns ``(merged_head,
  fork_records)`` where each fork record names its tip, its deepest
  common base, and the changes exclusive to that branch.

Every actor's changes carry a strictly increasing per-actor sequence
number (seq). A gap refuses coded ``coord-state-invalid``
(fail-closed: the DAG cannot verify continuity it has not seen).
Bounds are mandatory: max changes per DAG, max payload bytes, max
depth -- over-bound refuses coded ``coord-state-bound`` at ingest.

Composition points (documented here; this lane is self-contained and
changes no existing API):

* ``gov/coordination_lease.py`` scope registry: a lease acquisition /
  renewal / release can be mirrored as a signed ``{"op": "set",
  "key": "lease/<scope>/holder", "value": ...}`` change authored by
  the fencing-token holder's key. The lease's own fencing-token
  ordering stays the write authority; the DAG is the durable,
  mergeable audit of who held what, when.
* ``gov/revocation_status.py`` registry mirror: issue / rotate /
  revoke events mirror as ``{"op": "set", "key":
  "revocation/<rid>/status", "value": "active|rotated|revoked"}``
  changes authored by the registry key. Verifiers that cannot reach
  the registry can verify the mirror head instead (offline
  verification, wave-292 precedent).

THREAT MODEL:

* The ``trusted_pubkeys`` set given to ``StateDag`` is the trust
  anchor. A change signed by a key outside the set refuses coded
  (``coord-state-invalid``); a change with a bad signature refuses
  coded ``coord-state-forgery``.
* The DAG is in-memory per verifier (wave-292 decay precedent): two
  verifiers do not share DAG state, so this is per-coordinator-plane
  shared state, not distributed consensus.
* ``checked_at`` is freshness, not a clock. Changes carry no
  wall-clock trust; ordering comes from (seq, actor_id, digest).
* A compromised author key can author changes -- the
  compromised-host class; the DAG proves what was authorized, not
  who holds keys. Revocation of a compromised key is the
  wave-292 revocation registry's job, mirrored here as a status
  change.
"""

import hashlib
import json
import re

from gov import ed25519

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1742 -> 1746).
# ---------------------------------------------------------------------------

STATE_OVERWRITE = "coord-state-overwrite"
STATE_BOUND = "coord-state-bound"
STATE_FORGERY = "coord-state-forgery"
STATE_INVALID = "coord-state-invalid"

_DOMAIN = "coord-state"

# Actor ids and state keys share the bounded identifier grammar used
# across the coordination plane (coordination_lease precedent).
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

# Bounded: the DAG cannot grow without limit (DoS resistance).
_MAX_CHANGES = 1024
_MAX_PAYLOAD_BYTES = 4096
_MAX_DEPTH = 256
_MAX_PARENTS = 8

# Payload op vocabulary. "set" only: the DAG is append-only, and state
# keys merge by deterministic fold; there is no delete op because a
# deletion would hide a signed change's effect without a signed
# record -- to clear a key, set it to null.
_OP_SET = "set"
_MAX_KEY_LEN = 64
_MAX_STR_VALUE_LEN = 256


class CoordinationStateError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = STATE_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise CoordinationStateError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def _emit_event(event, fields):
    """Returns True if a sink consumed the event, False when no sink
    is wired or the sink raised. Never raises (F345-class)."""
    if _EMIT is None:
        return False
    try:
        _EMIT(event, fields)
        return True
    except Exception:
        # F345-class trade-off: a broken sink can never break ingest
        # or verification.
        return False


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(STATE_INVALID, "coord-state: change material is not "
                             "canonicalizable (circular or non-JSON "
                             "structure); no bare traceback escapes")


def _check_actor_id(value, what="actor id"):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(STATE_INVALID,
              "coord-state: %s must match [a-z][a-z0-9-]{0,63}; got %r"
              % (what, value))


def _check_seq(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(STATE_INVALID,
              "coord-state: seq must be a positive int; got %r" % (value,))


def _check_hex64(value, what):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(STATE_INVALID,
              "coord-state: %s must be 64 lowercase hex chars; got %r"
              % (what, value))


def _check_parents(value):
    if not isinstance(value, list):
        _fail(STATE_INVALID,
              "coord-state: parents must be a list of digests; got %r"
              % (value,))
    if len(value) > _MAX_PARENTS:
        _fail(STATE_BOUND,
              "coord-state: %d parents exceeds bound %d"
              % (len(value), _MAX_PARENTS))
    for p in value:
        _check_hex64(p, "parent digest")
    if len(set(value)) != len(value):
        _fail(STATE_INVALID,
              "coord-state: duplicate parent digests: %r" % (value,))


def _check_payload(value):
    if not isinstance(value, dict):
        _fail(STATE_INVALID,
              "coord-state: payload must be a dict; got %r" % (value,))
    if value.get("op") != _OP_SET:
        _fail(STATE_INVALID,
              "coord-state: only op %r is supported; got %r"
              % (_OP_SET, value.get("op")))
    key = value.get("key")
    if (not isinstance(key, str) or len(key) > _MAX_KEY_LEN
            or not _ID_RE.match(key)):
        _fail(STATE_INVALID,
              "coord-state: payload key must match [a-z][a-z0-9-]{0,63} "
              "(max %d); got %r" % (_MAX_KEY_LEN, key))
    if "value" not in value:
        _fail(STATE_INVALID,
              "coord-state: payload is missing 'value'; got %r" % (value,))
    val = value["value"]
    if isinstance(val, str) and len(val) > _MAX_STR_VALUE_LEN:
        _fail(STATE_BOUND,
              "coord-state: string value exceeds %d chars"
              % _MAX_STR_VALUE_LEN)
    if not (val is None or isinstance(val, (str, int, float, bool))):
        _fail(STATE_INVALID,
              "coord-state: payload value must be a JSON scalar; got %r"
              % (val,))
    if len(_canonical(value)) > _MAX_PAYLOAD_BYTES:
        _fail(STATE_BOUND,
              "coord-state: payload exceeds %d bytes"
              % _MAX_PAYLOAD_BYTES)


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


def _signed_message(body):
    """The bytes the author signs: everything that makes the change
    what it is."""
    return _canonical({
        "actor_id": body["actor_id"],
        "seq": body["seq"],
        "parents": body["parents"],
        "payload": body["payload"],
        "author_pubkey": body["author_pubkey"],
    })


def change_digest(change):
    """Content address of a change: sha256 over the signed envelope.
    The signature itself is not hashed (it is verification material,
    not identity). Validates shape first so malformed input refuses
    coded, never with a bare KeyError (F351 contract)."""
    _validate_change_shape(change)
    body = {k: change[k] for k in
            ("actor_id", "seq", "parents", "payload", "author_pubkey",
             "signature")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def sign_change(author_seed, actor_id, seq, payload, parents=()):
    """Author a change. Fails coded on malformed inputs; the returned
    dict is ingest-ready."""
    if not isinstance(author_seed, (bytes, bytearray)) \
            or len(author_seed) != 32:
        _fail(STATE_INVALID,
              "coord-state: author_seed must be 32 bytes")
    _check_actor_id(actor_id)
    _check_seq(seq)
    _check_parents(list(parents))
    _check_payload(payload)
    pubkey_hex = ed25519.publickey(bytes(author_seed)).hex()
    body = {
        "actor_id": actor_id,
        "seq": seq,
        "parents": list(parents),
        "payload": payload,
        "author_pubkey": pubkey_hex,
    }
    sig = ed25519.sign(bytes(author_seed), _signed_message(body)).hex()
    change = dict(body)
    change["signature"] = sig
    change["digest"] = change_digest(change)
    return change


def _validate_change_shape(change):
    """Structural validation shared by ingest and verify. Returns the
    validated body fields. Fails coded; never raises bare."""
    if not isinstance(change, dict):
        _fail(STATE_INVALID,
              "coord-state: change must be a dict; got %r" % (change,))
    for field in ("actor_id", "seq", "parents", "payload",
                  "author_pubkey", "signature"):
        if field not in change:
            _fail(STATE_INVALID,
                  "coord-state: change is missing field %r" % (field,))
    _check_actor_id(change["actor_id"])
    _check_seq(change["seq"])
    _check_parents(change["parents"])
    _check_payload(change["payload"])
    _check_hex64(change["author_pubkey"], "author public key")
    sig = change["signature"]
    if not isinstance(sig, str) or not _HEX128_RE.match(sig):
        _fail(STATE_INVALID,
              "coord-state: signature must be 128 lowercase hex chars")
    # A carried "digest" field is ignored: the digest is always
    # recomputed from content by verify_change/ingest.


def verify_change(change, trusted_pubkeys):
    """Stateless verification of one change against a trusted key set.

    Returns ``(True, {"digest": ...})`` on success; raises
    ``CoordinationStateError`` coded on any failure. Does NOT check
    seq continuity or DAG bounds -- that is ``StateDag.ingest``.
    """
    _validate_change_shape(change)
    author = change["author_pubkey"]
    if author not in trusted_pubkeys:
        _fail(STATE_INVALID,
              "coord-state: author key is not trusted: %.16s..." % author)
    body = {k: change[k] for k in
            ("actor_id", "seq", "parents", "payload", "author_pubkey")}
    if not _sig_ok(author, change["signature"], _signed_message(body)):
        _fail(STATE_FORGERY,
              "coord-state: signature does not verify under the claimed "
              "author key (%.16s...); change refused" % author)
    digest = change_digest(change)
    # Cycles are impossible by construction: the digest commits to the
    # parent list, so a change referencing its own (recomputed) digest
    # would require a sha256 fixed point. Unknown parents are kept as
    # the pending frontier (missing_parents), never as a cycle.
    return True, {"digest": digest}


class StateDag:
    """An in-memory signed change DAG (per-verifier, wave-292 decay
    precedent). Ingest is fail-closed and coded; merge is union-only
    and deterministic."""

    def __init__(self, registry_id, trusted_pubkeys):
        _check_actor_id(registry_id, what="registry id")
        if not isinstance(trusted_pubkeys, (set, frozenset, list, tuple)):
            _fail(STATE_INVALID,
                  "coord-state: trusted_pubkeys must be a set/list/tuple")
        trusted = set()
        for k in trusted_pubkeys:
            _check_hex64(k, "trusted public key")
            trusted.add(k)
        if not trusted:
            _fail(STATE_INVALID,
                  "coord-state: trusted_pubkeys must not be empty")
        self.registry_id = registry_id
        self.trusted_pubkeys = frozenset(trusted)
        self._changes = {}      # digest -> change dict
        self._last_seq = {}     # actor_id -> highest ingested seq
        self._children = {}     # digest -> set of digests that list it
        self._depth = {}        # digest -> longest parent chain length

    # -- ingest ------------------------------------------------------

    def ingest(self, change):
        """Ingest one change. Returns ``{"digest", "applied",
        "duplicate"}``. Replay of an ingested change is an idempotent
        no-op (``applied`` False, ``duplicate`` True). Every refusal
        is coded; nothing unverifiable enters the DAG."""
        ok, detail = verify_change(change, self.trusted_pubkeys)
        assert ok is True
        digest = detail["digest"]
        if digest in self._changes:
            return {"digest": digest, "applied": False, "duplicate": True}
        actor = change["actor_id"]
        seq = change["seq"]
        last = self._last_seq.get(actor, 0)
        if seq <= last:
            # The actor's (actor_id, seq) slot is already taken by a
            # different change: an overwrite attempt, never a merge.
            _fail(STATE_OVERWRITE,
                  "coord-state: seq %d for actor %r already ingested "
                  "with a different digest -- overwriting a signed "
                  "change is refused" % (seq, actor))
        if seq > last + 1:
            _fail(STATE_INVALID,
                  "coord-state: seq gap for actor %r: last ingested %d, "
                  "got %d -- continuity unverifiable" % (actor, last, seq))
        if len(self._changes) + 1 > _MAX_CHANGES:
            _fail(STATE_BOUND,
                  "coord-state: DAG already holds %d changes (bound %d)"
                  % (len(self._changes), _MAX_CHANGES))
        # Depth is computed over the full ancestry, INCLUDING parents
        # that arrive later: ingesting a chain in reverse order (leaf
        # first, ancestors later) must not evade the bound. Compute
        # tentative depths for the new change and all of its
        # transitive children BEFORE mutating anything.
        parents_map = {d: ch["parents"]
                       for d, ch in self._changes.items()}
        parents_map[digest] = list(change["parents"])
        affected = [digest]
        seen = {digest}
        stack = [digest]
        while stack:
            cur = stack.pop()
            for child in self._children.get(cur, ()):
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
                    affected.append(child)
        memo = {d: dep for d, dep in self._depth.items()
                if d not in seen}

        def _dep(d):
            if d in memo:
                return memo[d]
            dd = 0
            for p in parents_map.get(d, ()):
                if p in parents_map:
                    dd = max(dd, _dep(p) + 1)
            memo[d] = dd
            return dd

        for d in affected:
            if _dep(d) > _MAX_DEPTH:
                _fail(STATE_BOUND,
                      "coord-state: change depth %d exceeds bound %d "
                      "(chain via %.16s...)" % (_dep(d), _MAX_DEPTH, d))
        stored = {
            "actor_id": actor,
            "seq": seq,
            "parents": list(change["parents"]),
            "payload": change["payload"],
            "author_pubkey": change["author_pubkey"],
            "signature": change["signature"],
            "digest": digest,
        }
        self._changes[digest] = stored
        self._last_seq[actor] = seq
        for d in affected:
            self._depth[d] = memo[d]
        for p in stored["parents"]:
            self._children.setdefault(p, set()).add(digest)
        _emit_event("coord-state-ingest", {
            "registry_id": self.registry_id,
            "digest": digest,
            "actor_id": actor,
            "seq": seq,
        })
        return {"digest": digest, "applied": True, "duplicate": False}

    # -- reads -------------------------------------------------------

    def __len__(self):
        return len(self._changes)

    def get(self, digest):
        return self._changes.get(digest)

    def all_changes(self):
        """All changes in deterministic order: (seq, actor_id,
        digest)."""
        return [self._changes[d] for d in
                sorted(self._changes,
                       key=lambda d: (self._changes[d]["seq"],
                                      self._changes[d]["actor_id"], d))]

    def heads(self):
        """Digests not referenced as a parent by any ingested change."""
        return sorted(d for d in self._changes
                      if d not in self._children or not self._children[d])

    def missing_parents(self):
        """Parent digests referenced but not ingested -- the pending
        frontier after an offline-fork merge."""
        missing = set()
        for ch in self._changes.values():
            for p in ch["parents"]:
                if p not in self._changes:
                    missing.add(p)
        return sorted(missing)

    def _ancestors(self, digest):
        seen = set()
        stack = [digest]
        while stack:
            d = stack.pop()
            if d in seen or d not in self._changes:
                continue
            seen.add(d)
            stack.extend(self._changes[d]["parents"])
        return seen

    def _change_key(self, digest):
        ch = self._changes[digest]
        return (ch["seq"], ch["actor_id"], digest)

    # -- merge -------------------------------------------------------

    def merge(self, peer):
        """Union-merge another StateDag. Deterministic and
        order-independent: the merged set is the union, and the
        merged head is the max head by (seq, actor_id, digest).

        Returns ``(merged_head, fork_records)``. ``fork_records`` is
        ``[]`` when the union has a single head; otherwise one record
        per non-winning head::

            {"tip": <digest>, "base": <deepest common ancestor digest
             or None>, "changes": [<digests exclusive to that fork>]}
        """
        if not isinstance(peer, StateDag):
            _fail(STATE_INVALID,
                  "coord-state: merge peer must be a StateDag; got %r"
                  % (peer,))
        for ch in peer.all_changes():
            # Full ingest: forged, malformed, over-bound, or
            # overwriting peer changes refuse coded -- a hostile peer
            # can never poison the merge.
            self.ingest(ch)
        heads = self.heads()
        merged_head = max(heads, key=self._change_key)
        merged_anc = self._ancestors(merged_head)
        forks = []
        for tip in sorted(heads):
            if tip == merged_head:
                continue
            tip_anc = self._ancestors(tip)
            common = (tip_anc & merged_anc) - {tip}
            base = max(common, key=self._change_key) if common else None
            exclusive = sorted(tip_anc - merged_anc)
            forks.append({"tip": tip, "base": base, "changes": exclusive})
        _emit_event("coord-state-merge", {
            "registry_id": self.registry_id,
            "merged_head": merged_head,
            "forks": len(forks),
            "changes": len(self._changes),
        })
        return merged_head, forks

    # -- materialization ---------------------------------------------

    def materialize(self):
        """Fold the DAG into a state dict, deterministically: changes
        apply in (seq, actor_id, digest) order; later sets win. The
        fold is a view -- it never mutates the DAG."""
        state = {}
        for ch in self.all_changes():
            payload = ch["payload"]
            state[payload["key"]] = payload["value"]
        return state
