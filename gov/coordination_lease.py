"""Lease-bound authority for agent coordination roles (etcd pattern).

Pattern lineage: etcd-io/etcd (Apache-2.0) -- leases (authority
expires by default), CAS transactions, election recipe, fencing
tokens. Mechanisms only; no vendored code; stdlib only.

Standing design rule this module enforces: "Authority is leased,
never held -- every grant carries an expiry and a fencing token;
shared state merges, never overwrites."

A coordination role (``anchor-sequencer``, ``delegation-issuer``,
``issuance-monitor-runner``) is held under a ``Lease``:

* the lease carries a MANDATORY expiry (``not_after``) -- there is
  no standing authority; an expired lease is unusable at every seam
  (pre-decay fail-closed, wave-292 precedent);
* every generation of the lease carries a monotonically-increasing
  ``fencing_token`` -- every mutation a holder makes carries its
  token, and a write with a stale token refuses coded
  ``coord-lease-fencing`` (zombie writes die);
* leases are signed by the issuing authority; ``verify_lease``
  checks the signature, expiry, and the canonical shape -- every
  refusal is coded.

Composition points (documented here; this lane is self-contained
and changes no existing API):

* wave-292 delegation decay: a delegation issuer SHOULD hold an
  unexpired lease for its scope before issuing; delegation TTLs
  stay the deployment-owned freshness rule, leases add "who may
  issue at all".
* wave-293 key succession: a leadership handoff when a lease
  expires naturally composes with ``gov/key_succession.py`` --
  the successor's signing key should enter through the ceremony
  (none -> preparing -> prepared -> completing -> completed)
  before the first lease is granted to it; the old leader's
  retired key then refuses LOUD via
  ``keysuccession-retired-reuse``. Until that wiring lands, the
  fencing-token epoch ordering (strictly increasing across
  generations) is what distinguishes the new leader's writes from
  the old leader's zombie writes.

THREAT MODEL:

* The issuing authority's seed is the trust anchor. The manager is
  in-memory per verifier (wave-292 decay precedent): two
  verifiers do not share lease state, so this is
  per-coordinator-plane coordination, not distributed consensus.
* ``issued_at`` / ``checked_at`` / ``not_after`` are freshness
  markers, not a clock. Verifiers bound lease age in policy; this
  module records times, it does not run a clock.
* A compromised authority seed can mint leases -- the
  compromised-host class; the lease proves what was authorized,
  not who holds keys.
"""

import hashlib
import json
import re
import time
from collections.abc import Mapping

from gov import ed25519

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1730 -> 1734).
# ---------------------------------------------------------------------------

LEASE_DENIED = "coord-lease-denied"
LEASE_EXPIRED = "coord-lease-expired"
LEASE_FENCING = "coord-lease-fencing"
LEASE_INVALID = "coord-lease-invalid"

_DOMAIN = "coord-lease"

# Scope: bounded identifier grammar; holder: same grammar.
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_MAX_SCOPE_LEN = 64

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

_MIN_TTL = 1            # 1 second
_MAX_TTL = 30 * 86400  # 30 days; there is no unbounded lease


# ---------------------------------------------------------------------------
# Delegation binding (wave-300): a lease grant may be issued AS a
# delegation receipt (the receipt binds the fencing token's
# authority). The binding is declared at acquire time, stored on the
# in-memory grant record (manager-side, unsigned -- the manager's
# memory is deployment-owned), and enforced at check_write: the
# presented revocation state must show the bound receipt live.
#
# A bound grant presented WITHOUT revocation state refuses
# fail-closed coded ``coord-lease-fencing`` -- authority that cannot
# be shown live is dead authority. Revocation beats expiry in the
# check order (the revocation module's own refusal order).
# ---------------------------------------------------------------------------

_BINDING_FIELDS = ("receipt_id", "revocation_list_digest")


def _check_delegation_binding(value):
    """Validate the optional delegation binding declared at acquire.

    Shape: {"receipt_id": <64 hex>, "revocation_list_digest": <64 hex>}.
    Unknown keys refuse -- the binding is a closed contract."""
    if not isinstance(value, dict):
        _fail(LEASE_INVALID,
              "delegation_binding must be a dict with %r" % (_BINDING_FIELDS,))
    extra = set(value) - set(_BINDING_FIELDS)
    if extra:
        _fail(LEASE_INVALID,
              "delegation_binding has unknown keys: %r" % (sorted(extra),))
    for field in _BINDING_FIELDS:
        v = value.get(field)
        if not isinstance(v, str) or not _HEX64_RE.match(v):
            _fail(LEASE_INVALID,
                  "delegation_binding[%r] must be 64 lowercase hex chars"
                  % (field,))


class CoordinationLeaseError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = LEASE_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise CoordinationLeaseError(detail, code=code)


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
        # F345-class trade-off: a broken sink can never break the
        # lease or verification.
        return False


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(LEASE_INVALID, "lease material is not canonicalizable "
                             "(circular or non-JSON structure)")


def _check_scope(value):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(LEASE_INVALID,
              "scope must match [a-z][a-z0-9-]{0,63}; got %r" % (value,))


def _check_holder(value):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(LEASE_INVALID,
              "holder_id must match [a-z][a-z0-9-]{0,63}; got %r" % (value,))


def _check_pubkey_hex(value, what="authority public key"):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(LEASE_INVALID,
              "%s must be 64 lowercase hex chars" % what)


def _check_seed(value, what="authority seed"):
    if not isinstance(value, bytes) or len(value) != 32:
        _fail(LEASE_INVALID, "%s must be 32 raw bytes" % what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(LEASE_INVALID, "%s must be a non-negative int" % what)


def _check_ttl(value):
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(LEASE_INVALID, "ttl_seconds must be an int number of seconds")
    if value < _MIN_TTL or value > _MAX_TTL:
        _fail(LEASE_INVALID,
              "ttl_seconds must be bounded: %d..%d seconds; there is no "
              "unbounded lease" % (_MIN_TTL, _MAX_TTL))


def _check_token(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(LEASE_INVALID, "fencing_token must be a positive int")


def _check_extra(value):
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(LEASE_INVALID, "extra_seconds must be an int number of seconds")
    if value < _MIN_TTL or value > _MAX_TTL:
        _fail(LEASE_INVALID,
              "extra_seconds must be bounded: %d..%d seconds" %
              (_MIN_TTL, _MAX_TTL))


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


def _lease_digest(lease):
    body = {k: lease[k] for k in
            ("scope", "holder_id", "issued_at", "not_after",
             "fencing_token", "authority_pubkey")}
    return hashlib.sha256(_canonical(body)).hexdigest()


class LeaseManager:
    """In-memory lease registry for one coordinator plane.

    ``_leases`` maps scope -> list of granted lease records (every
    grant is retained; records are never evicted by a later grant --
    F367). ``_epochs`` maps scope -> highest fencing token ever
    issued (monotonic across generations, never reset -- this is
    what makes zombie writes fail even after expiry and re-acquire).

    Grants for one scope must not overlap in time: a new grant
    whose ``[issued_at, not_after)`` overlaps any stored grant
    refuses coded ``coord-lease-denied``. Non-overlapping grants
    (including future-dated ones) QUEUE alongside the live record
    instead of evicting it, so a future-dated ``issued_at`` can
    never silently kill the currently-live lease's writes. Lookups
    (``_live`` / ``_require_live``) resolve the single lease
    covering the queried instant.
    """

    def __init__(self):
        self._leases = {}
        self._epochs = {}

    # -- acquisition ----------------------------------------------------

    def acquire(self, scope, ttl_seconds, holder_id, authority_seed=None,
                issued_at=None, delegation_binding=None):
        """Grant ``scope`` to ``holder_id`` for ``ttl_seconds``.

        Refuses coded ``coord-lease-invalid`` for malformed inputs
        (including zero/negative/unbounded TTL); coded
        ``coord-lease-denied`` when the new grant's
        ``[issued_at, not_after)`` overlaps any already-granted
        lease on the scope. Non-overlapping grants QUEUE: a
        future-dated ``issued_at`` is granted alongside -- never
        instead of -- the currently-live lease, so it cannot
        silently evict the live holder's record (F367). Returns the
        signed lease dict.

        ``delegation_binding`` (optional, wave-300): when the grant
        is issued AS a delegation receipt, declare
        ``{"receipt_id": <64 hex>, "revocation_list_digest": <64
        hex>}``. The binding is stored on the in-memory grant
        record and enforced at ``check_write``: the presented
        revocation state must show the bound receipt live, or the
        write refuses coded ``coord-lease-fencing``. Grants without
        a binding behave exactly as before.
        """
        _check_scope(scope)
        _check_ttl(ttl_seconds)
        _check_holder(holder_id)
        if authority_seed is None:
            _fail(LEASE_INVALID,
                  "acquire requires the issuing authority seed")
        _check_seed(authority_seed)
        if issued_at is None:
            issued_at = int(time.time())
        else:
            _check_ts(issued_at, "issued_at")
        if delegation_binding is not None:
            _check_delegation_binding(delegation_binding)
        not_after = issued_at + ttl_seconds

        for old in self._leases.get(scope, []):
            if issued_at < old["not_after"] and \
                    old["issued_at"] < not_after:
                _fail(LEASE_DENIED,
                      "scope %r overlaps the grant to %r covering "
                      "[%d, %d) (fencing token %d); authority is "
                      "leased, never held" %
                      (scope, old["holder_id"], old["issued_at"],
                       old["not_after"], old["fencing_token"]))

        authority_pubkey = ed25519.publickey(authority_seed).hex()
        token = self._epochs.get(scope, 0) + 1
        body = {
            "scope": scope,
            "holder_id": holder_id,
            "issued_at": issued_at,
            "not_after": not_after,
            "fencing_token": token,
            "authority_pubkey": authority_pubkey,
        }
        sig = ed25519.sign(authority_seed, _canonical(body)).hex()
        lease = dict(body)
        lease["signature"] = sig
        if delegation_binding is not None:
            # Manager-side, unsigned: the manager's memory is
            # deployment-owned. verify_lease ignores extra fields,
            # so bound leases still verify statelessly.
            lease["delegation_binding"] = dict(delegation_binding)
        # F367: the grant is RETAINED, never evicting. A future-dated
        # non-overlapping grant queues alongside the live record.
        self._leases.setdefault(scope, []).append(lease)
        self._epochs[scope] = token
        _emit_event("coord-lease-acquired",
                    {"scope": scope, "holder_id": holder_id,
                     "not_after": lease["not_after"],
                     "fencing_token": token,
                     "lease_digest": _lease_digest(lease),
                     "delegation_binding":
                         lease.get("delegation_binding")})
        return lease

    # -- renewal ----------------------------------------------------------

    def renew(self, scope, fencing_token, holder_id, extra_seconds,
              authority_seed=None, checked_at=None):
        """Extend the live lease's expiry; the generation does NOT
        advance (renew keeps the token). Requires the CURRENT
        fencing token: a stale token refuses coded
        ``coord-lease-fencing``; a wrong holder refuses coded
        ``coord-lease-invalid``; an expired lease refuses coded
        ``coord-lease-expired`` (no renewal of the dead). The
        extension must not overlap a queued future grant on the
        scope -- that refuses coded ``coord-lease-denied``
        (F367: renewal cannot steal a queued future)."""
        _check_scope(scope)
        _check_token(fencing_token)
        _check_holder(holder_id)
        _check_extra(extra_seconds)
        if authority_seed is None:
            _fail(LEASE_INVALID, "renew requires the issuing authority seed")
        _check_seed(authority_seed)
        if checked_at is None:
            checked_at = int(time.time())
        else:
            _check_ts(checked_at, "checked_at")

        lease = self._require_live(scope, checked_at)
        if fencing_token != lease["fencing_token"]:
            _fail(LEASE_FENCING,
                  "renew denied: fencing token %d is not the current "
                  "token %d for scope %r" %
                  (fencing_token, lease["fencing_token"], scope))
        if lease["holder_id"] != holder_id:
            _fail(LEASE_INVALID,
                  "renew denied: holder %r is not the lease holder %r" %
                  (holder_id, lease["holder_id"]))

        authority_pubkey = ed25519.publickey(authority_seed).hex()
        if authority_pubkey != lease["authority_pubkey"]:
            _fail(LEASE_INVALID,
                  "renew denied: authority key mismatch")
        new_not_after = lease["not_after"] + extra_seconds
        for other in self._leases.get(scope, []):
            if other is lease:
                continue
            if lease["issued_at"] < other["not_after"] and \
                    other["issued_at"] < new_not_after:
                _fail(LEASE_DENIED,
                      "renew denied: extending to %d would overlap the "
                      "queued grant to %r covering [%d, %d) (fencing "
                      "token %d); renewal cannot steal a queued future" %
                      (new_not_after, other["holder_id"],
                       other["issued_at"], other["not_after"],
                       other["fencing_token"]))
        body = {
            "scope": scope,
            "holder_id": holder_id,
            "issued_at": lease["issued_at"],
            "not_after": new_not_after,
            "fencing_token": lease["fencing_token"],
            "authority_pubkey": authority_pubkey,
        }
        sig = ed25519.sign(authority_seed, _canonical(body)).hex()
        renewed = dict(body)
        renewed["signature"] = sig
        if lease.get("delegation_binding") is not None:
            # Renewal extends the same generation: the delegation
            # binding rides along (same token, same authority).
            renewed["delegation_binding"] = dict(lease["delegation_binding"])
        self._leases[scope].remove(lease)
        self._leases[scope].append(renewed)
        _emit_event("coord-lease-renewed",
                    {"scope": scope, "holder_id": holder_id,
                     "not_after": renewed["not_after"],
                     "fencing_token": renewed["fencing_token"],
                     "lease_digest": _lease_digest(renewed),
                     "delegation_binding":
                         renewed.get("delegation_binding")})
        return renewed

    # -- write authorization -----------------------------------------------

    def check_write(self, scope, fencing_token, holder_id, checked_at=None,
                    delegation_context=None):
        """Authorize one mutation under the lease. Every mutation
        carries its fencing token: a stale token (zombie write, or a
        replayed token from an older generation) refuses coded
        ``coord-lease-fencing``; an expired lease refuses coded
        ``coord-lease-expired`` BEFORE any state change (pre-decay
        fail-closed). Returns True.

        ``delegation_context`` (optional, wave-300; per-delegator
        revoker sets wave-302 / F379): required when the live grant
        carries a ``delegation_binding``. Shape::

            {"revokers": {delegator_id: <gov.delegation_revocation.DelegationRevoker>},
             "chain":   [<root-first receipts, leaf last>],
             "trust_roots": [...] }   # native gov/delegation.py receipts
            # -- or --
            {"revokers": {delegator_id: <DelegationRevoker>},
             "chain":   [...],
             "keyring": {delegator_id: pubkey_hex}}  # local-shape receipts

        The legacy ``{"revoker": <DelegationRevoker>}`` single-revoker
        shape is still accepted and means
        ``{revoker.delegator_id: revoker}`` (the revoker must speak
        for the chain root, as wave-300). Every chain member's
        revocation is checked against ITS delegator's list, each
        with per-revoker anti-substitution: the presented revoker
        must hold the member delegator's own key (pubkey in
        ``trust_roots`` for the root / equal to the receipt's
        ``delegator_pubkey`` for native members, equal to the
        keyring entry for local-shape members) and its
        ``delegator_id`` must match. A member with no presented
        revoker refuses fail-closed. The presented chain must
        terminate at the bound ``receipt_id``. This stops a
        substituted revoker while letting each delegator's newer
        revocations take effect without re-acquire. A bound grant
        presented WITHOUT (complete) revocation state refuses
        fail-closed coded ``coord-lease-fencing`` -- authority that
        cannot be shown live for every hop is dead authority. A
        ``delegation-revoked`` refusal maps onto
        ``coord-lease-fencing``; a ``delegation-expired`` refusal
        maps onto ``coord-lease-expired``; other delegation
        defects refuse coded ``coord-lease-invalid``. Grants
        without a binding behave exactly as before.
        """
        _check_scope(scope)
        _check_token(fencing_token)
        _check_holder(holder_id)
        if checked_at is None:
            checked_at = int(time.time())
        else:
            _check_ts(checked_at, "checked_at")

        lease = self._require_live(scope, checked_at)
        # Fencing first: a stale token is refused as a fencing event
        # even when the presenter is the old (zombie) holder. The
        # holder check applies only to the current token.
        if fencing_token != lease["fencing_token"]:
            _fail(LEASE_FENCING,
                  "write denied: fencing token %d is stale; current "
                  "token for scope %r is %d (zombie writes die)" %
                  (fencing_token, scope, lease["fencing_token"]))
        if lease["holder_id"] != holder_id:
            _fail(LEASE_INVALID,
                  "write denied: holder %r is not the lease holder %r" %
                  (holder_id, lease["holder_id"]))
        binding = lease.get("delegation_binding")
        if binding is not None:
            self._check_delegation_binding_live(binding,
                                                delegation_context,
                                                checked_at)
        return True

    def _check_delegation_binding_live(self, binding, delegation_context,
                                       checked_at):
        """Enforce a delegation binding at write time (wave-300;
        per-delegator revoker sets wave-302 / F379).

        Fail-closed at every step: missing state, a substituted
        revoker, a chain that does not terminate at the bound
        receipt, or a revoked receipt all refuse. Revocation beats
        expiry, matching the revocation module's refusal order.

        F379: revocation state is per-delegator. The context carries
        either the legacy ``{"revoker": <DelegationRevoker>}`` shape
        (normalized to a one-entry mapping keyed by its
        delegator_id; the single revoker must still speak for the
        chain ROOT, exactly as wave-300) or the new
        ``{"revokers": {delegator_id: <DelegationRevoker>}}``
        mapping. Every chain member's revocation is checked against
        ITS delegator's list, each with per-revoker
        anti-substitution -- a multi-hop chain bound at the leaf
        can no longer hide an intermediate delegator's revocation
        behind the root's clean list. A member whose delegator has
        no presented revoker refuses fail-closed: authority that
        cannot be shown live for every hop is dead authority.
        """
        from gov import delegation_revocation as _rev  # lazy: no cycle
        if not isinstance(delegation_context, dict):
            _fail(LEASE_FENCING,
                  "write denied: grant is delegation-bound but no "
                  "revocation state was presented (fail closed)")
        # Normalize revokers to a per-delegator mapping (F379).
        # The legacy single-revoker shape keeps wave-300 semantics:
        # wrong-type refuses fail-closed; a revoker that does not
        # speak for the chain root is a substitution attempt.
        _legacy = None
        revokers = delegation_context.get("revokers")
        if revokers is None:
            _legacy = delegation_context.get("revoker")
            if not isinstance(_legacy, _rev.DelegationRevoker):
                _fail(LEASE_FENCING,
                      "write denied: grant is delegation-bound but the "
                      "delegator's revocation list was not presented "
                      "(fail closed)")
        elif not isinstance(revokers, dict) or not revokers or any(
                not isinstance(_k, str)
                or not isinstance(_v, _rev.DelegationRevoker)
                for _k, _v in revokers.items()):
            _fail(LEASE_FENCING,
                  "write denied: revokers must be a non-empty "
                  "delegator_id -> DelegationRevoker mapping "
                  "(fail closed)")
        # Anti-substitution: the presented revoker(s) must speak for
        # the receipts' own delegators -- ALWAYS checked, never
        # skipped on a digest match. (A digest-only check is
        # insufficient: an empty attacker-controlled revoker has
        # the same list digest as an empty legitimate one.) The
        # receipt signatures then anchor the trust roots/keyring:
        # a caller-supplied keyring naming the wrong key fails
        # signature verification inside the revocation module.
        # The bound revocation_list_digest is recorded for audit
        # and lets deployments pin exact list state if desired.
        chain = delegation_context.get("chain")
        if not isinstance(chain, list) or not chain:
            _fail(LEASE_INVALID,
                  "write denied: delegation_context chain must be a "
                  "non-empty root-first receipt list")
        leaf = chain[-1]
        leaf_id = leaf.get("receipt_id") if isinstance(leaf, Mapping) \
            else None
        if leaf_id != binding["receipt_id"]:
            _fail(LEASE_INVALID,
                  "write denied: presented chain does not terminate "
                  "at the bound receipt_id")
        root = chain[0]
        root_delegator = root.get("delegator_id") \
            if isinstance(root, Mapping) else None
        if _legacy is not None:
            if _legacy.delegator_id != root_delegator:
                _fail(LEASE_INVALID,
                      "write denied: presented revocation list is not "
                      "the bound receipt's delegator's own list")
            revokers = {_legacy.delegator_id: _legacy}
        if "trust_roots" in delegation_context:
            _native = True
        elif "keyring" in delegation_context:
            _native = False
        else:
            _fail(LEASE_INVALID,
                  "write denied: delegation_context needs "
                  "trust_roots (native receipts) or keyring "
                  "(local-shape receipts)")
        # F379 per-member revocation: each chain member is checked
        # against ITS delegator's revocation list, with
        # per-revoker anti-substitution. Native receipts carry
        # their delegator's pubkey (signature-verified downstream
        # by verify_chain); the root's key must additionally sit
        # in trust_roots. Local-shape receipts bind through the
        # keyring. A member with no presented revoker refuses
        # fail-closed -- a multi-hop chain presented with only the
        # root's list can no longer pass on the root's clean list
        # while an intermediate delegator's revocation stays
        # invisible.
        for _i, _receipt in enumerate(chain):
            if not isinstance(_receipt, Mapping):
                _fail(LEASE_INVALID,
                      "write denied: chain member %d is not a receipt "
                      "mapping" % (_i,))
            _did = _receipt.get("delegator_id")
            if not isinstance(_did, str) or not _did:
                _fail(LEASE_INVALID,
                      "write denied: chain member %d has no "
                      "delegator_id" % (_i,))
            _r = revokers.get(_did)
            if _r is None:
                _fail(LEASE_FENCING,
                      "write denied: no revocation state presented "
                      "for delegator %r (fail closed)" % (_did,))
            if _r.delegator_id != _did:
                _fail(LEASE_INVALID,
                      "write denied: revoker filed under %r does not "
                      "speak for delegator %r"
                      % (_r.delegator_id, _did))
            if _native:
                _dpk = _receipt.get("delegator_pubkey")
                if not isinstance(_dpk, str) \
                        or _r.pubkey_hex.lower() != _dpk.lower():
                    _fail(LEASE_INVALID,
                          "write denied: presented revocation list "
                          "is not the delegator's own list")
                if _i == 0 and _r.pubkey_hex not in \
                        delegation_context["trust_roots"]:
                    _fail(LEASE_INVALID,
                          "write denied: presented revocation list "
                          "is not the bound receipt's delegator's "
                          "own list")
            elif delegation_context["keyring"].get(_did) != \
                    _r.pubkey_hex:
                _fail(LEASE_INVALID,
                      "write denied: presented revocation list "
                      "is not the delegator's own list")
            _rid = _receipt.get("receipt_id")
            if isinstance(_rid, str) and _rid in _r.revoked_targets():
                _fail(LEASE_FENCING,
                      "write denied: delegation receipt %s revoked; "
                      "the fencing token's authority is dead" %
                      _rid[:16])
        # Full chain liveness (signatures, linkage, expiry) through
        # the existing single-revoker path, keyed on the root
        # delegator's revoker. Per-member revocation above already
        # passed; the call below re-checks the root member
        # harmlessly and performs the chain verification.
        revoker = revokers[root_delegator]
        try:
            from gov import delegation as _dg  # lazy: no cycle
            _chain_errors = (_rev.RevocationError, _dg.DelegationError)
        except ImportError:
            _chain_errors = (_rev.RevocationError,)
        try:
            if "trust_roots" in delegation_context:
                revoker.assert_live_native(
                    chain, checked_at,
                    delegation_context["trust_roots"])
            elif "keyring" in delegation_context:
                revoker.is_live(chain, checked_at,
                                delegation_context["keyring"])
            else:
                _fail(LEASE_INVALID,
                      "write denied: delegation_context needs "
                      "trust_roots (native receipts) or keyring "
                      "(local-shape receipts)")
        except _chain_errors as exc:
            # Both modules' errors are coded (F351); getattr keeps
            # the mapping total even for unforeseen codes.
            code = getattr(exc, "code", None)
            if code == _rev.RV_REVOKED:
                _fail(LEASE_FENCING,
                      "write denied: delegation receipt %s revoked; "
                      "the fencing token's authority is dead" %
                      binding["receipt_id"][:16])
            if code == _rev.EXP:
                _fail(LEASE_EXPIRED,
                      "write denied: delegation receipt expired")
            _fail(LEASE_INVALID,
                  "write denied: delegation liveness check failed "
                  "(%s)" % (code,))

    # -- release -----------------------------------------------------------

    def release(self, scope, fencing_token, holder_id):
        """Voluntarily surrender the lease; the scope becomes
        acquirable again for the surrendered interval (the next
        generation takes a HIGHER fencing token -- the epoch never
        resets). Requires the token and the holder of the granted
        lease being surrendered; other queued grants on the scope
        are untouched."""
        _check_scope(scope)
        _check_token(fencing_token)
        _check_holder(holder_id)
        leases = self._leases.get(scope, [])
        lease = None
        for cand in leases:
            if cand["fencing_token"] == fencing_token:
                lease = cand
                break
        if lease is None:
            if not leases:
                _fail(LEASE_INVALID,
                      "release denied: no lease on scope %r" % (scope,))
            _fail(LEASE_FENCING,
                  "release denied: fencing token %d is not a granted "
                  "token on scope %r" % (fencing_token, scope))
        if lease["holder_id"] != holder_id:
            _fail(LEASE_INVALID,
                  "release denied: holder %r is not the lease holder %r" %
                  (holder_id, lease["holder_id"]))
        leases.remove(lease)
        _emit_event("coord-lease-released",
                    {"scope": scope, "holder_id": holder_id,
                     "fencing_token": fencing_token})
        return True

    # -- helpers -----------------------------------------------------------

    def _live(self, scope, checked_at):
        """The single granted lease covering ``checked_at``
        (``issued_at <= checked_at < not_after``), or None. Grants
        never overlap, so at most one lease covers any instant;
        defensively the latest-issued covering lease wins."""
        best = None
        for lease in self._leases.get(scope, []):
            if lease["issued_at"] <= checked_at < lease["not_after"]:
                if best is None or lease["issued_at"] > best["issued_at"]:
                    best = lease
        return best

    def _require_live(self, scope, checked_at):
        leases = self._leases.get(scope, [])
        if not leases:
            _fail(LEASE_EXPIRED,
                  "no live lease on scope %r" % (scope,))
        lease = self._live(scope, checked_at)
        if lease is None:
            holders = sorted({l["holder_id"] for l in leases})
            _fail(LEASE_EXPIRED,
                  "no granted lease on scope %r covers %d (holders "
                  "on record: %s); authority expires by default -- "
                  "re-acquire" %
                  (scope, checked_at, ",".join(holders)))
        return lease


# ---------------------------------------------------------------------------
# Stateless verification (the verifier's seam -- no manager needed).
# ---------------------------------------------------------------------------

def verify_lease(lease, authority_pubkey_hex, checked_at=None):
    """Verify a lease envelope against the issuing authority's public
    key. Checks, in order: canonical shape (coded
    ``coord-lease-invalid``), signature (coded
    ``coord-lease-invalid``), expiry (coded ``coord-lease-expired``
    -- refused at every use, pre-decay fail-closed). Returns
    ``(True, detail)`` with the fencing token, scope, holder, and
    remaining seconds. Nothing returns a bare False."""
    if not isinstance(lease, dict):
        _fail(LEASE_INVALID, "lease must be a dict")
    _check_pubkey_hex(authority_pubkey_hex)
    if checked_at is None:
        checked_at = int(time.time())
    else:
        _check_ts(checked_at, "checked_at")

    body = {}
    for key in ("scope", "holder_id", "issued_at", "not_after",
                "fencing_token", "authority_pubkey"):
        if key not in lease:
            _fail(LEASE_INVALID, "lease missing field %r" % (key,))
        body[key] = lease[key]
    signature = lease.get("signature")
    if not isinstance(signature, str) or not _HEX128_RE.match(signature):
        _fail(LEASE_INVALID,
              "lease must carry a 128-hex signature")

    _check_scope(body["scope"])
    _check_holder(body["holder_id"])
    _check_ts(body["issued_at"], "issued_at")
    _check_ts(body["not_after"], "not_after")
    _check_token(body["fencing_token"])
    _check_pubkey_hex(body["authority_pubkey"], "lease authority key")
    if body["not_after"] <= body["issued_at"]:
        _fail(LEASE_INVALID, "lease expiry must be after issuance")
    if body["authority_pubkey"] != authority_pubkey_hex:
        _fail(LEASE_INVALID, "lease authority key does not match the "
                             "expected authority")

    if not _sig_ok(authority_pubkey_hex, signature, _canonical(body)):
        _fail(LEASE_INVALID, "lease signature does not verify under the "
                             "authority key")
    if checked_at >= body["not_after"]:
        _fail(LEASE_EXPIRED,
              "lease on scope %r expired at %d; authority expires by "
              "default" % (body["scope"], body["not_after"]))
    return True, {
        "scope": body["scope"],
        "holder_id": body["holder_id"],
        "fencing_token": body["fencing_token"],
        "remaining_seconds": body["not_after"] - checked_at,
    }
