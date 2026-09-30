#!/usr/bin/env python3
"""One-use, mission-bound ARAP permit leases.

ADAPT of the mission-bound-authorization pattern (wave-220
prospecting): a permit lease binds an ARAP approval to the exact request
parameters it was issued for, so a stolen or replayed approval cannot
authorize different parameters.

The ``parameter_digest`` of a permit issued for an ARAP request reuses
the wave-219 ARAP ``context_binding`` (``hmac-sha256-v1:<hex>`` over the
declared per-field digests, domain ``sasanam-arap-context/v1:``) — one
digest scheme for one context, no second domain invented. The only
digest this module computes itself is :func:`parameter_digest` for
non-ARAP parameter dicts, under the distinct
``sasanam-permit-lease/v1:`` domain.

Rules (all fail closed, all refusals carry machine-readable codes):

* A lease is one-use: the first successful ``redeem`` consumes it; a
  second redeem refuses ``permit-reused``.
* ``redeem`` checks in the order: used -> expired -> digest -> scope.
  An expired or consumed permit answers ``permit-expired`` /
  ``permit-reused`` even for a wrong digest, so probes learn nothing
  about the recorded digest (no equality oracle).
* A digest that does not constant-time-match the recorded
  ``parameter_digest`` refuses ``permit-digest-mismatch``.
* No-downgrade: ``PermitLease.check_scope(request_scope, grant_scope)``
  refuses a request broader than the grant with
  ``permit-downgrade-refused``. Scopes are conservative dicts of
  ``dimension -> set of values``; unknown shapes refuse. Narrowing is
  accepted.
* Two layers, not one: the parameter_digest pins the EXACT parameters
  (a matching digest means the presented parameters are bit-identical
  to the approved ones — widening without changing the digest is
  impossible), while check_scope enforces the grant's scope envelope
  whenever a scope is presented at redeem time. ``redeem`` keeps the
  spec's ``redeem(parameter_digest)`` shape: callers redeeming on
  behalf of a concrete request SHOULD pass that request's scope so the
  envelope is checked. A bearer of the exact digest redeems without a
  scope claim — the digest itself is the capability, and its custody
  is the deployment's job.
* A permit is never issued for unbound parameters: ``issue_for_arap``
  requires the request's ``context_binding`` (authoring bug
  ``ValueError`` otherwise); the transition wiring skips loudly with an
  ``arap_permit_skipped`` audit entry instead.
* In-memory only. Registry history dying with the process is a
  documented deployment boundary, same as the wave-219 seen-version
  floors: persistence across restarts is the deployer's job.
* Optional exact-target revocation (wave-222, ``gov/revocation.py``):
  ``PermitRegistry(..., revocation_registry=rl)`` checks the lease's
  recorded parameter digest on every redeem, AFTER the digest check
  (no revocation oracle for wrong digests) and BEFORE the scope
  check; a revoked digest refuses ``permit-revoked`` even when the
  lease is otherwise valid, without consuming the lease. When the
  registry is absent, redeem behaves exactly as before.
* Optional per-request attenuation (wave-223, ``gov/attenuation.py``):
  ``PermitLease.redeem(..., attenuation=None,
  require_attenuation=False)`` — a requester-signed block with a
  <=600s TTL that may only narrow the grant. A missing block under a
  required policy refuses ``attenuation-missing``; a presented block
  binds (``attenuation-unverifiable`` / ``attenuation-lease-mismatch``
  / ``attenuation-ttl-refused`` / ``attenuation-expired`` /
  ``attenuation-widening-refused``) BEFORE the scope check, and
  additionally constrains ``request_scope`` to the narrowed scope.
  No policy and no block behaves exactly as before: the block is a
  sealed constraint, never a credential, and never upgrades
  authority.
* Optional live parent re-verification (wave-225,
  ``gov/reverify.py``): ``PermitLease.redeem(...,
  reverify_at_use=True, use_verifier=..., use_record=...)`` — the
  parent record is re-verified at use time (signature, revocation,
  liveness) after the digest check and before any binding; a
  missing or invalid re-verification refuses ``reverify-required``.
  Default False: the legacy path runs exactly as before.

Stdlib only. No network. $0.
"""

import json
import time
import uuid
from hashlib import sha256
from hmac import compare_digest

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class PermitError(Exception):
    """Base class for all permit-lease refusals. ``code`` is
    machine-readable."""

    code = "permit-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class PermitReusedError(PermitError):
    """A consumed (one-use) permit was presented again."""

    code = "permit-reused"


class PermitDigestMismatchError(PermitError):
    """The presented parameter digest does not match the recorded one."""

    code = "permit-digest-mismatch"


class PermitExpiredError(PermitError):
    """The permit's validity window has closed."""

    code = "permit-expired"


class PermitUnknownError(PermitError):
    """No permit with this id was ever issued by this registry."""

    code = "permit-unknown"


class PermitRevokedError(PermitError):
    """The lease's parameter digest was revoked by exact-target
    revocation (``gov/revocation.py``) before redemption."""

    code = "permit-revoked"


class PermitDowngradeRefusedError(PermitError):
    """The request scope is broader than (or not comparable to) the
    grant scope — a downgrade was attempted."""

    code = "permit-downgrade-refused"


# ----------------------------------------------------------------------
# Parameter digests.
# ----------------------------------------------------------------------

_LEASE_DOMAIN = "sasanam-permit-lease/v1:"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"), default=str)


def parameter_digest(params):
    """Canonical digest of a parameter dict for non-ARAP callers.

    ARAP callers must NOT use this: their ``parameter_digest`` is the
    request's ``context_binding`` (one digest scheme per context). This
    exists for future non-ARAP grant shapes only. Malformed input is a
    caller bug (TypeError/ValueError), not an attack shape.
    """
    if not isinstance(params, dict):
        raise TypeError("parameter_digest requires a dict of parameters")
    return "sha256:" + sha256(
        (_LEASE_DOMAIN + _canonical(params)).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Scopes (conservative, closed shape).
# ----------------------------------------------------------------------


def _normalize_scope(scope, where):
    """Normalize a scope to {dimension: frozenset(values)}.

    Accepted shapes: dict with string keys, values a string or a
    list/tuple/set/frozenset of strings. Anything else is a
    conservative ``permit-downgrade-refused`` — scope data is runtime
    data, never trusted enough for a bare TypeError escape.
    """
    if not isinstance(scope, dict):
        raise PermitDowngradeRefusedError(
            "permit-downgrade-refused: %s scope must be a dict, got %s"
            % (where, type(scope).__name__))
    out = {}
    for dim, values in scope.items():
        if not isinstance(dim, str):
            raise PermitDowngradeRefusedError(
                "permit-downgrade-refused: %s scope dimension names must be "
                "strings" % where)
        if isinstance(values, str):
            items = [values]
        elif isinstance(values, (list, tuple, set, frozenset)):
            # Validate element types BEFORE any set() call: unhashable
            # values (dicts, sets, lists) must refuse conservatively,
            # never escape as a bare TypeError.
            items = list(values)
        else:
            raise PermitDowngradeRefusedError(
                "permit-downgrade-refused: %s scope dimension %r has an "
                "uncomparable shape" % (where, dim))
        if not items or any(not isinstance(v, str) or not v
                            for v in items):
            raise PermitDowngradeRefusedError(
                "permit-downgrade-refused: %s scope dimension %r must hold "
                "non-empty strings" % (where, dim))
        out[dim] = frozenset(items)
    return out


def _check_grant_scope_shape(grant_scope):
    """Authoring-side validation of a grant scope: malformed grants are
    a deployment bug (ValueError), caught at issue time, never at
    redeem time."""
    try:
        return _normalize_scope(grant_scope, "grant")
    except PermitDowngradeRefusedError as exc:
        raise ValueError("malformed grant_scope: %s" % exc) from exc


# ----------------------------------------------------------------------
# The lease.
# ----------------------------------------------------------------------


def _audit_refused(audit, permit_id, code):
    """One shared shape for every refused-redemption audit entry."""
    if audit is not None:
        audit({"event": "permit_redeem_refused",
               "permit_id": permit_id, "code": code})


class PermitLease:
    """A one-use permit bound to an exact ``parameter_digest``.

    Constructed via :meth:`issue` or :meth:`issue_for_arap`; the
    constructor validates but ``issue_for_arap`` is the ARAP seam.
    """

    def __init__(self, permit_id, *, params_digest, grant_scope,
                 issued_at, expires_at, audit=None):
        if not isinstance(permit_id, str) or not permit_id:
            raise ValueError("permit_id must be a non-empty string")
        if not isinstance(params_digest, str) or not params_digest:
            raise ValueError("params_digest must be a non-empty string")
        grant_scope = _check_grant_scope_shape(grant_scope)
        issued_at = float(issued_at)
        expires_at = float(expires_at)
        if not expires_at > issued_at:
            raise ValueError("expires_at must be after issued_at")
        self.permit_id = permit_id
        self.parameter_digest = params_digest
        self.grant_scope = grant_scope
        self.issued_at = issued_at
        self.expires_at = expires_at
        self._used = False
        self._audit = audit

    @classmethod
    def issue(cls, permit_id, *, params_digest, grant_scope,
              ttl_s=3600, now=None, audit=None):
        """Issue a lease for an opaque parameter digest."""
        now_fn = now or time.time
        issued = float(now_fn())
        ttl = float(ttl_s)
        if not ttl > 0:
            raise ValueError("ttl_s must be positive")
        lease = cls(permit_id, params_digest=params_digest,
                    grant_scope=grant_scope, issued_at=issued,
                    expires_at=issued + ttl, audit=audit)
        if audit is not None:
            audit({"event": "permit_issued", "permit_id": permit_id,
                   "parameter_digest": params_digest,
                   "issued_at": issued, "expires_at": issued + ttl})
        return lease

    @classmethod
    def issue_for_arap(cls, request, *, permit_id=None, grant_scope=None,
                       ttl_s=3600, now=None, audit=None):
        """Issue a lease bound to an ARAP request's parameters.

        The ``parameter_digest`` is the request's ``context_binding``
        (the wave-219 HMAC over the declared per-field digests) — the
        exact parameters the approver saw, integrity-bound at approval
        time. A request with no ``context_binding`` has unbound
        parameters and cannot receive a mission-bound permit: that is
        an authoring bug (ValueError), never a silent downgrade.

        ``grant_scope`` defaults to the request's subject/resource/
        action triple; an explicit grant may only narrow.
        """
        binding = request.get("context_binding")
        if not binding:
            raise ValueError(
                "issue_for_arap requires a request with an integrity-bound "
                "context_binding; unbound parameters cannot receive a "
                "mission-bound permit")
        if grant_scope is None:
            grant_scope = {"subject": {request.get("subject")},
                           "resource": {request.get("resource")},
                           "action": {request.get("action")}}
        permit_id = permit_id or ("permit-" + uuid.uuid4().hex[:16])
        return cls.issue(permit_id, params_digest=binding,
                         grant_scope=grant_scope, ttl_s=ttl_s, now=now,
                         audit=audit)

    @property
    def used(self):
        return self._used

    def expired(self, now=None):
        now_fn = now or time.time
        return float(now_fn()) >= self.expires_at

    @staticmethod
    def check_scope(request_scope, grant_scope):
        """Refuse a request broader than its grant (no-downgrade).

        Every dimension present in the request must exist in the grant
        with the request's values a subset of the grant's. Dimensions
        absent from the request are narrowing (accepted). Unknown
        shapes — non-dict scopes, unknown dimensions, uncomparable
        values — refuse with ``permit-downgrade-refused``. Returns
        True when the request fits inside the grant.
        """
        req = _normalize_scope(request_scope, "request")
        grant = _normalize_scope(grant_scope, "grant")
        for dim, values in req.items():
            if dim not in grant:
                raise PermitDowngradeRefusedError(
                    "permit-downgrade-refused: request scope dimension %r "
                    "is not in the grant" % (dim,))
            if not values <= grant[dim]:
                raise PermitDowngradeRefusedError(
                    "permit-downgrade-refused: request scope %r=%s widens "
                    "grant %s" % (dim, sorted(values),
                                  sorted(grant[dim])))
        return True

    def _refuse(self, exc):
        _audit_refused(self._audit, self.permit_id, exc.code)
        raise exc

    def redeem(self, presented_digest, *, request_scope=None, now=None,
               revocation_registry=None, attenuation=None,
               require_attenuation=False, reverify_at_use=False,
               use_verifier=None, use_record=None):
        """Consume the lease for the exact recorded parameters.

        Check order is fixed — attenuation-missing, used, expired,
        digest, revocation, use-time re-verification, attenuation-bind,
        scope — so a caller that never presented a block learns nothing
        about the lease, a consumed or expired permit never confirms or
        denies a digest, revocation/attenuation are checked only after
        the presented digest proved correct (no revocation or
        attenuation oracle for wrong digests), and the live
        re-verification runs before any binding that could narrow the
        outcome. ``revocation_registry`` is an
        optional exact-target revocation source
        (``gov/revocation.py`` or any object with
        ``check(digest) -> "revoked" | "active"``); when None the
        legacy path runs exactly as before. ``attenuation`` is an
        optional requester-signed attenuation block
        (``gov/attenuation.py``); when ``require_attenuation`` is set
        and no block is presented, redeem refuses
        ``attenuation-missing``. A bound block additionally constrains
        ``request_scope`` to its narrowed scope — inside the grant
        but outside the narrowed scope refuses
        ``attenuation-widening-refused``. A revoked lease refuses
        ``permit-revoked`` even when otherwise valid, and the refused
        redeem does not consume the lease.
        ``reverify_at_use`` is the optional live parent re-verification
        (``gov/reverify.py``): when True, ``use_verifier`` must be a
        ``UseTimeVerifier`` and ``use_record`` the use envelope for
        the parent being consumed; a missing verifier/record — or a
        re-verification that does not hold — refuses
        ``reverify-required`` (the inner reverify code is preserved in
        the detail). Default False: the legacy path is byte-identical.
        On success the lease is marked used and a grant record is
        returned; the grant is the only proof of redemption. The
        grant carries an ``attenuation`` sub-record only when a block
        was bound — the no-attenuation grant is byte-identical to the
        legacy shape.
        """
        now_fn = now or time.time
        at = float(now_fn())
        narrowed = None
        _att = None
        _rvf = None
        if attenuation is not None or require_attenuation:
            from . import attenuation as _att  # lazy: circular import
            if attenuation is None:
                self._refuse(_att.AttenuationMissingError(
                    "attenuation-missing: this redeem policy requires a "
                    "requester-signed attenuation block"))
        if reverify_at_use:
            from . import reverify as _rvf  # lazy: optional seam
            if use_verifier is None or use_record is None:
                self._refuse(_rvf.ReverifyRequiredError(
                    "reverify-required: this redeem policy requires a "
                    "live use-time re-verification; verifier or use "
                    "record is missing"))
        if self._used:
            self._refuse(PermitReusedError(
                "permit-reused: permit %r was already consumed; one-use "
                "permits do not re-authorize" % (self.permit_id,)))
        if self.expired(now_fn):
            self._refuse(PermitExpiredError(
                "permit-expired: permit %r expired at %r"
                % (self.permit_id, self.expires_at)))
        if not isinstance(presented_digest, str) or not compare_digest(
                presented_digest, self.parameter_digest):
            self._refuse(PermitDigestMismatchError(
                "permit-digest-mismatch: presented parameters do not match "
                "the parameters this permit was issued for"))
        if (revocation_registry is not None
                and revocation_registry.check(self.parameter_digest)
                != "active"):
            self._refuse(PermitRevokedError(
                "permit-revoked: permit %r targets a revoked digest; the "
                "approval it bound is no longer good"
                % (self.permit_id,)))
        if _rvf is not None:
            # Live parent re-verification at use time: the parent
            # record is re-checked — signature, revocation, liveness —
            # right here, never inherited from an earlier check. The
            # check runs after the digest proved correct so no
            # verification outcome leaks for wrong digests.
            try:
                use_verifier.verify_at_use(use_record)
            except _rvf.ReverifyError as exc:
                self._refuse(_rvf.ReverifyRequiredError(
                    "reverify-required: use-time re-verification did "
                    "not hold (%s)" % (exc.code,)))
            if self._audit is not None:
                self._audit({"event": "reverify_bound",
                             "permit_id": self.permit_id,
                             "parent_digest": use_record.get(
                                 "parent_digest")})
        if _att is not None and attenuation is not None:
            # Bound only after the digest proved correct: a block can
            # never be used as a digest oracle (no attenuation validity
            # signal for wrong digests).
            narrowed = _att.bind(attenuation, self, now=now_fn)
            if self._audit is not None:
                self._audit({"event": "attenuation_bound",
                             "permit_id": self.permit_id,
                             "requester_id": attenuation["requester_id"],
                             "narrowed_scope":
                                 attenuation["narrowed_scope"]})
        if request_scope is not None:
            try:
                self.check_scope(request_scope, self.grant_scope)
            except PermitDowngradeRefusedError as exc:
                self._refuse(exc)
            if narrowed is not None:
                try:
                    self.check_scope(request_scope, narrowed)
                except PermitDowngradeRefusedError as exc:
                    self._refuse(_att.AttenuationWideningRefusedError(
                        "attenuation-widening-refused: request scope %r "
                        "exceeds the attenuation's narrowed scope" % (
                            request_scope,)))
        self._used = True
        grant = {"permit_id": self.permit_id,
                 "parameter_digest": self.parameter_digest,
                 "granted_at": at}
        if narrowed is not None:
            grant["attenuation"] = {
                "requester_id": attenuation["requester_id"],
                "narrowed_scope": attenuation["narrowed_scope"]}
        if self._audit is not None:
            self._audit({"event": "permit_redeemed",
                         "permit_id": self.permit_id,
                         "granted_at": at})
        return grant


# ----------------------------------------------------------------------
# Registry.
# ----------------------------------------------------------------------


class PermitRegistry:
    """In-memory registry of issued leases (deployment-owned).

    ``now`` is an injectable clock (seconds since epoch) for
    determinism; ``audit`` receives the permit_issued / permit_redeemed
    / permit_redeem_refused entries. ``revocation_registry`` is an
    optional exact-target revocation source (``gov/revocation.py`` or
    any object with ``check(digest) -> "revoked" | "active"``) checked
    on every redeem; when None, redeem behaves exactly as before.
    """

    def __init__(self, *, audit=None, now=None, revocation_registry=None):
        self._leases = {}
        self._audit = audit
        self._now = now or time.time
        self._revocation_registry = revocation_registry

    def issue(self, permit_id, *, params_digest, grant_scope,
              ttl_s=3600):
        if permit_id in self._leases:
            raise ValueError("duplicate permit_id %r" % (permit_id,))
        lease = PermitLease.issue(
            permit_id, params_digest=params_digest,
            grant_scope=grant_scope, ttl_s=ttl_s, now=self._now,
            audit=self._audit)
        self._leases[permit_id] = lease
        return lease

    def issue_for_arap(self, request, *, permit_id=None, grant_scope=None,
                       ttl_s=3600):
        lease = PermitLease.issue_for_arap(
            request, permit_id=permit_id, grant_scope=grant_scope,
            ttl_s=ttl_s, now=self._now, audit=self._audit)
        if lease.permit_id in self._leases:
            raise ValueError(
                "duplicate permit_id %r" % (lease.permit_id,))
        self._leases[lease.permit_id] = lease
        return lease

    def redeem(self, permit_id, presented_digest, *, request_scope=None,
               attenuation=None, require_attenuation=False,
               reverify_at_use=False, use_verifier=None,
               use_record=None):
        lease = self._leases.get(permit_id)
        if lease is None:
            exc = PermitUnknownError(
                "permit-unknown: no permit %r was issued by this registry"
                % (permit_id,))
            _audit_refused(self._audit, permit_id, exc.code)
            raise exc
        return lease.redeem(presented_digest, request_scope=request_scope,
                            now=self._now,
                            revocation_registry=self._revocation_registry,
                            attenuation=attenuation,
                            require_attenuation=require_attenuation,
                            reverify_at_use=reverify_at_use,
                            use_verifier=use_verifier,
                            use_record=use_record)


# ----------------------------------------------------------------------
# Additive wiring for gov/arap.py transition().
# ----------------------------------------------------------------------


def maybe_issue_for_transition(req, lease_registry, ttl_s, audit=None):
    """Issue a mission-bound permit when an approval lands.

    Called from ``gov.arap.transition`` when ``lease_registry`` is
    supplied and the transition is to ``"approved"``. Requests without
    an integrity-bound ``context_binding`` get NO permit — the skip is
    loud (``arap_permit_skipped`` audit entry when ``audit`` is
    supplied), never silent. Returns the lease, or None when skipped.
    """
    binding = req.get("context_binding")
    if not binding:
        if audit is not None:
            audit({"event": "arap_permit_skipped",
                   "request_id": req.get("request_id"),
                   "reason": "no-context-binding"})
        return None
    lease = lease_registry.issue_for_arap(req, ttl_s=ttl_s)
    req["permit_id"] = lease.permit_id
    return lease


__all__ = [
    "PermitError",
    "PermitReusedError",
    "PermitDigestMismatchError",
    "PermitExpiredError",
    "PermitUnknownError",
    "PermitDowngradeRefusedError",
    "PermitLease",
    "PermitRegistry",
    "parameter_digest",
    "maybe_issue_for_transition",
]
