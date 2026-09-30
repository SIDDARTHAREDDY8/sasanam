"""Finality-bound revocation (wave-243 lane B).

ADAPT of the mechanism in draft-das-finality-bound-revocation -00,
patterns only: the das ref-impls are NOASSERTION-licensed, so this
module is an original implementation of the mechanism described in
prose -- no draft text vendored, no upstream code imported.

Mechanism: bind each authorization at issue time to a revocation
basis/epoch. Immediately before the protected consequence commits,
the Finality Sink performs an ATOMIC check-and-commit against that
basis: a revocation that became applicable between issue and commit
refuses; a store mutation landing mid-check is detected and refused
(the TOCTOU falsifier); a binding that was not re-derived from
issuer trust refuses; a store that cannot offer the atomic check
protocol is never trusted.

Honest residuals:
- The binding digest is tamper-EVIDENT (sha256 over canonical
  binding fields plus the issuer trust anchor), not an issuer
  signature. An in-process forger that rewrites the whole record
  can recompute it. Origin proof needs issuer-signed bindings;
  that is out of scope here.
- Atomicity is single-node: the in-memory store guards the
  check-and-commit with a monotonic sequence counter and a lock.
  Distributed atomicity remains deployment-owned.
- The revocation store is in-memory; persistence and shared
  atomicity are deployment-owned (same boundary as the
  consumption ledger).

Stdlib only. Deterministic. Clock arrives as an explicit ``now``.
"""

import hashlib
import json
import threading

from gov import exception_ttl as _exception_ttl
from gov import stale_authority as _stale_authority

REVOCATION_APPLICABLE = "revocation-applicable"
REVOCATION_BASIS_MALFORMED = "revocation-basis-malformed"
REVOCATION_BASIS_TAMPERED = "revocation-basis-tampered"
REVOCATION_CHECK_UNSEALED = "revocation-check-unsealed"
REVOCATION_SINK_NONATOMIC = "revocation-sink-nonatomic"

_AUTHORIZATION_TYPE = "finality-bound-authorization"


class FinalityBoundError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(FinalityBoundError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise FinalityBoundError(code, detail)


def _is_epoch(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _non_empty_str(value):
    return isinstance(value, str) and bool(value)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _binding_digest(binding, issuer_trust_anchor):
    return hashlib.sha256(_canonical({
        "binding": binding,
        "issuer_trust_anchor": issuer_trust_anchor,
    })).hexdigest()


class RevocationStore(object):
    """In-memory revocation-basis store with an atomic-check protocol.

    Each basis maps to ``None`` (live) or the epoch at which it was
    revoked. Every mutation bumps a monotonic sequence counter under
    a lock. The Finality Sink reads the counter before and after the
    revocation read; a counter change between the two reads means the
    store mutated mid-check and the commit decision is refused
    (``revocation-check-unsealed``).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._bases = {}
        self._seq = 0

    def register_basis(self, basis_id):
        """Register a live revocation basis."""
        if not _non_empty_str(basis_id):
            _refuse(REVOCATION_BASIS_MALFORMED,
                    "basis_id must be a non-empty string")
        with self._lock:
            if basis_id in self._bases:
                _refuse(REVOCATION_BASIS_MALFORMED,
                        "basis_id already registered: %r" % (basis_id,))
            self._bases[basis_id] = None
            self._seq += 1

    def revoke(self, basis_id, epoch, now):
        """Revoke a basis, applicable from ``epoch``."""
        if not _non_empty_str(basis_id):
            _refuse(REVOCATION_BASIS_MALFORMED,
                    "basis_id must be a non-empty string")
        if not _is_epoch(epoch):
            _refuse(REVOCATION_BASIS_MALFORMED,
                    "revocation epoch must be numeric, got %r" % (epoch,))
        if not _is_epoch(now):
            _refuse(REVOCATION_BASIS_MALFORMED,
                    "now must be numeric, got %r" % (now,))
        with self._lock:
            if basis_id not in self._bases:
                _refuse(REVOCATION_BASIS_MALFORMED,
                        "revocation of unknown basis_id: %r" % (basis_id,))
            self._bases[basis_id] = epoch
            self._seq += 1

    def revocation_epoch(self, basis_id):
        """Return the revocation epoch, or None while the basis is live."""
        with self._lock:
            try:
                return self._bases[basis_id]
            except KeyError:
                _refuse(REVOCATION_BASIS_MALFORMED,
                        "check on unknown basis_id: %r" % (basis_id,))

    def begin_check(self):
        """Open the atomic check window; returns the store sequence."""
        with self._lock:
            return self._seq

    def end_check(self):
        """Close the atomic check window; returns the store sequence."""
        with self._lock:
            return self._seq


def issue_authorization(subject, action, basis_id, issuer_trust_anchor,
                        store, now, authority_id=None, minted_at=None):
    """Issue an authorization bound to a revocation basis/epoch.

    The binding records the basis id, the revocation epoch observed
    at issue (None while the basis is live), the issuer trust anchor
    the binding is derived from, and a digest over the canonical
    binding bytes. The basis must already be registered in ``store``.
    """
    if not _non_empty_str(subject):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "subject must be a non-empty string")
    if not _non_empty_str(action):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "action must be a non-empty string")
    if not _non_empty_str(basis_id):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "basis_id must be a non-empty string")
    if not _non_empty_str(issuer_trust_anchor):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "issuer_trust_anchor must be a non-empty string")
    if not _is_epoch(now):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "now must be numeric, got %r" % (now,))
    epoch_at_issue = store.revocation_epoch(basis_id)
    binding = {
        "subject": subject,
        "action": action,
        "basis_id": basis_id,
        "revocation_epoch_at_issue": epoch_at_issue,
        "issued_at": now,
    }
    return {
        "type": _AUTHORIZATION_TYPE,
        "binding": binding,
        "issuer_trust_anchor": issuer_trust_anchor,
        "binding_digest": _binding_digest(binding, issuer_trust_anchor),
        "authority_id": authority_id,
        "minted_at": minted_at,
    }


def _validate_authorization(authorization):
    if not isinstance(authorization, dict):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "authorization is not a dict: %r"
                % (type(authorization).__name__,))
    if authorization.get("type") != _AUTHORIZATION_TYPE:
        _refuse(REVOCATION_BASIS_MALFORMED,
                "not a finality-bound authorization: %r"
                % (authorization.get("type"),))
    binding = authorization.get("binding")
    if not isinstance(binding, dict):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "authorization binding is not a dict")
    anchor = authorization.get("issuer_trust_anchor")
    if not _non_empty_str(anchor):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "issuer_trust_anchor missing or empty")
    digest = authorization.get("binding_digest")
    if not _non_empty_str(digest):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "binding_digest missing or empty")
    for field in ("subject", "action", "basis_id", "issued_at"):
        if field not in binding:
            _refuse(REVOCATION_BASIS_MALFORMED,
                    "binding field %r missing" % (field,))
    return binding, anchor, digest


def _store_implements_atomic_protocol(store):
    return all(callable(getattr(store, name, None))
               for name in ("begin_check", "end_check",
                            "revocation_epoch"))


def finality_sink_commit(authorization, store, now, exception=None,
                         scope=""):
    """Atomically check-and-commit an authorization.

    Refusals:
    - ``revocation-basis-malformed``: the authorization record or the
      basis reference is structurally wrong.
    - ``revocation-basis-tampered``: the recomputed binding digest
      disagrees with the claimed digest; the binding was not
      re-derived from issuer trust.
    - ``revocation-sink-nonatomic``: the store does not implement the
      atomic check protocol; the sink fails closed rather than
      check-then-act.
    - ``revocation-check-unsealed``: the store mutated between the
      check and the commit decision (TOCTOU); refused.
    - ``revocation-applicable``: the bound basis is revoked at commit
      time; the protected consequence must not commit.

    Optional integrations (reused, not duplicated):
    - when the authorization cites ``authority_id``/``minted_at``,
      the wave-242 stale-authority lapse registry is consulted and
      its refusal propagates.
    - when ``exception`` is given, the wave-242 exception-TTL
      declaration is consumed for ``scope`` and its refusal
      propagates (an expired exception no longer shields).

    Returns a commit receipt dict when the consequence may commit.
    """
    binding, anchor, digest = _validate_authorization(authorization)
    if _binding_digest(binding, anchor) != digest:
        _refuse(REVOCATION_BASIS_TAMPERED,
                "recomputed binding digest disagrees with the claimed "
                "binding_digest for basis %r; the binding was not "
                "re-derived from issuer trust" % (binding["basis_id"],))
    if not _is_epoch(now):
        _refuse(REVOCATION_BASIS_MALFORMED,
                "now must be numeric, got %r" % (now,))
    if not _store_implements_atomic_protocol(store):
        _refuse(REVOCATION_SINK_NONATOMIC,
                "revocation store %r does not implement the atomic "
                "check protocol (begin_check/end_check/"
                "revocation_epoch); the Finality Sink fails closed "
                "rather than check-then-act"
                % (type(store).__name__,))
    # Optional wave-242 integrations: stale authority, exception TTL.
    authority_id = authorization.get("authority_id")
    if authority_id is not None:
        _stale_authority.check_authority(authority_id,
                                         authorization.get("minted_at"))
    if exception is not None:
        _exception_ttl.consume_exception(exception, now=now, scope=scope)
    # Atomic check-and-commit.
    seq0 = store.begin_check()
    basis_epoch = store.revocation_epoch(binding["basis_id"])
    seq1 = store.end_check()
    if seq1 != seq0:
        _refuse(REVOCATION_CHECK_UNSEALED,
                "revocation store mutated between the check and the "
                "commit decision (seq %r -> %r); the check-and-commit "
                "was not atomic" % (seq0, seq1))
    if basis_epoch is not None and basis_epoch <= now:
        _refuse(REVOCATION_APPLICABLE,
                "revocation basis %r is revoked (epoch %r <= now %r); "
                "the protected consequence must not commit"
                % (binding["basis_id"], basis_epoch, now))
    return {
        "committed": True,
        "subject": binding["subject"],
        "action": binding["action"],
        "basis_id": binding["basis_id"],
        "basis_revocation_epoch": basis_epoch,
        "checked_at": now,
        "atomic_sequence": seq1,
    }
