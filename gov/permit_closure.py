#!/usr/bin/env python3
"""Permit/closure pre/post attestation split (wave-236).

Re-derived from the convergent direction in draft-saha-aadp-bound-permit
(-00, bound permit pre-dispatch) and the wave-236 prospectus W236-7:
a decision is attested in two halves that must agree.

* PRE-DISPATCH: ``issue_permit(decision, request_bytes, scope)`` seals a
  Permit whose ``request_digest`` binds the CANONICAL request bytes.
  Canonicalization is JCS (``json.dumps`` with sorted keys, no
  whitespace, ASCII) for request bytes that parse as JSON; non-JSON
  bytes are bound byte-exact. Dispatch against different actual bytes
  refuses ``permit-binding-mismatch``; dispatch with no permit at all
  refuses ``dispatch-without-permit``.
* POST-EXECUTION: ``issue_closure(permit, outcome_digest, effects)``
  seals a Closure record bound to the Permit's digest. A Closure
  presented without its matching Permit refuses
  ``closure-permit-absent``; a Closure whose bound permit digest does
  not match the presented Permit's refuses ``closure-permit-mismatch``;
  a Closure whose claimed effects exceed the Permit's scope refuses
  ``closure-scope-widened`` -- a closure may narrow (a subset of the
  permitted effects) but never widen the permit's scope.

"Signed" here means digest-bound sealed records whose digests recompute
over the sealed body (tamper-evidence via the same idiom as
``gov/bound_permit.py``); a deployment may carry these records under
DSSE envelopes where signature semantics are required. Shape and
tamper refusals reuse the existing ``permit-malformed`` /
``permit-tampered`` codes (no redefinition).

Honest residuals: the module binds digests of caller-supplied decision,
request bytes, and outcome digests; it does not prove the request was
executed or that the outcome digest is truthful -- a closure attests
what the caller reports post-execution, and the verifier's narrowing
check is what makes a widened claim unacceptable. Narrowing is
enforced over flat effect vocabularies (strings); richer scope shapes
are refused as malformed rather than interpreted. Nothing here proves
execution happened; the attestation proves what was bound, in which
order, and that the two halves agree.

Stdlib only. Deterministic: no randomness; the only clock reads are
``time.time()`` for ``issued_at`` stamps and default record ids (copies
are never re-verified against the clock). No network. $0.
"""

import hashlib
import hmac
import json
import time

_PERMIT_CLOSURE_DOMAIN = b"sasanam-permit-closure-v1:"
_PERMIT_VERSION = 1
_CLOSURE_VERSION = 1
_HEX64 = "0123456789abcdef"
_PERMIT_FIELDS = ("version", "permit_id", "issued_at", "decision_digest",
                  "request_digest", "scope", "scope_digest")
_CLOSURE_FIELDS = ("version", "closure_id", "permit_digest",
                   "outcome_digest", "effects", "effects_digest")

# Refusal codes (module-level, w228 vocabulary idiom 2).
BINDING_MISMATCH = "permit-binding-mismatch"
DISPATCH_WITHOUT_PERMIT = "dispatch-without-permit"
CLOSURE_PERMIT_ABSENT = "closure-permit-absent"
CLOSURE_PERMIT_MISMATCH = "closure-permit-mismatch"
CLOSURE_SCOPE_WIDENED = "closure-scope-widened"
_MALFORMED = "permit-malformed"   # existing taxonomy entry, reused
_TAMPERED = "permit-tampered"     # existing taxonomy entry, reused


class PermitClosureError(Exception):
    """Base error: carries no string ``code`` itself (w228 audited)."""


class _PermitMalformed(PermitClosureError):
    code = _MALFORMED


class _PermitTampered(PermitClosureError):
    code = _TAMPERED


class _PermitBindingMismatch(PermitClosureError):
    code = BINDING_MISMATCH


class _DispatchWithoutPermit(PermitClosureError):
    code = DISPATCH_WITHOUT_PERMIT


class _ClosurePermitAbsent(PermitClosureError):
    code = CLOSURE_PERMIT_ABSENT


class _ClosurePermitMismatch(PermitClosureError):
    code = CLOSURE_PERMIT_MISMATCH


class _ClosureScopeWidened(PermitClosureError):
    code = CLOSURE_SCOPE_WIDENED


# ----------------------------------------------------------------------
# Internals.
# ----------------------------------------------------------------------


def _is_bare_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in _HEX64 for c in value)


def _canonical_dumps(obj):
    """JCS: sorted keys, compact separators, ASCII. Independent of the
    caller's wire shape."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical_request_bytes(request_bytes):
    """Bind the canonical request bytes.

    Request bytes that parse as JSON are canonicalized with JCS so
    that byte-different but semantically identical wire shapes (key
    order, whitespace) still bind. Bytes that do not parse as JSON are
    bound byte-exact (opaque payloads).
    """
    if not isinstance(request_bytes, (bytes, bytearray)):
        raise _PermitMalformed(
            "permit-malformed: request_bytes must be bytes")
    raw = bytes(request_bytes)
    if not raw:
        raise _PermitMalformed(
            "permit-malformed: request_bytes must be non-empty")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return raw
    return _canonical_dumps(parsed).encode("utf-8")


def _decision_digest(decision):
    try:
        raw = _canonical_dumps(decision).encode("utf-8")
    except (TypeError, ValueError):
        raise _PermitMalformed(
            "permit-malformed: decision is not JSON-serializable")
    return _digest_bytes(raw)


def _scope_digest(scope):
    return _digest_bytes(_canonical_dumps(sorted(scope)).encode("utf-8"))


def _check_effect_list(items, field, allow_empty):
    """Validate a list of unique non-empty effect strings."""
    if not isinstance(items, (list, tuple)):
        raise _PermitMalformed(
            "permit-malformed: %s must be a list of effect strings"
            % (field,))
    if not items and not allow_empty:
        raise _PermitMalformed(
            "permit-malformed: %s must be non-empty" % (field,))
    for effect in items:
        if not isinstance(effect, str) or not effect:
            raise _PermitMalformed(
                "permit-malformed: %s effects must be non-empty "
                "strings" % (field,))
    if len(set(items)) != len(items):
        raise _PermitMalformed(
            "permit-malformed: %s effects must be unique" % (field,))
    return list(items)


def _check_scope(scope):
    return _check_effect_list(scope, "scope", allow_empty=False)


def _check_effects(effects):
    return _check_effect_list(effects, "effects", allow_empty=True)


def _check_permit_id(permit_id, field):
    if not isinstance(permit_id, str) or not permit_id:
        raise _PermitMalformed(
            "permit-malformed: %r must be a non-empty string" % (field,))


def _body_digest(body):
    h = hashlib.sha256(_PERMIT_CLOSURE_DOMAIN)
    h.update(_canonical_dumps(body).encode("utf-8"))
    return h.hexdigest()


# ----------------------------------------------------------------------
# Permits: pre-dispatch attestation.
# ----------------------------------------------------------------------


def issue_permit(decision, request_bytes, scope, permit_id=None,
                 issued_at=None):
    """Seal a Permit binding the decision to the canonical request
    bytes, pre-dispatch.

    ``decision`` is a JSON-serializable record (its digest is pinned,
    the record itself is caller-held). ``request_bytes`` are the exact
    bytes the dispatcher must send; their digest binds the JCS
    canonical form. ``scope`` is the permitted effect vocabulary (a
    non-empty list of unique strings). Returns the sealed permit dict.
    """
    pid = permit_id or "permit-%d" % int(time.time() * 1000)
    _check_permit_id(pid, "permit_id")
    scope = _check_scope(scope)
    canonical = _canonical_request_bytes(request_bytes)
    body = {
        "version": _PERMIT_VERSION,
        "permit_id": pid,
        "issued_at": issued_at if issued_at is not None else time.time(),
        "decision_digest": _decision_digest(decision),
        "request_digest": _digest_bytes(canonical),
        "scope": scope,
        "scope_digest": _scope_digest(scope),
    }
    return dict(body, permit_digest=_body_digest(body))


def verify_permit(permit):
    """Verify a presented permit: shape, then digest recomputation.

    Refuses ``permit-malformed`` (wrong shape) and ``permit-tampered``
    (a digest does not recompute: the record was edited after issue).
    Returns True when valid. Detects edits to the permit record, not
    lies in the original decision (the decision is caller-held; its
    digest is pinned here).
    """
    if not isinstance(permit, dict):
        raise _PermitMalformed(
            "permit-malformed: permit must be a dict")
    for field in _PERMIT_FIELDS + ("permit_digest",):
        if field not in permit:
            raise _PermitMalformed(
                "permit-malformed: missing field %r" % (field,))
    if permit.get("version") != _PERMIT_VERSION:
        raise _PermitMalformed(
            "permit-malformed: unsupported permit version")
    _check_permit_id(permit["permit_id"], "permit_id")
    if not isinstance(permit["issued_at"], (int, float)):
        raise _PermitMalformed(
            "permit-malformed: issued_at must be a number")
    for field in ("decision_digest", "request_digest", "scope_digest",
                  "permit_digest"):
        if not _is_bare_digest(permit[field]):
            raise _PermitMalformed(
                "permit-malformed: %r must be a bare 64-hex digest"
                % (field,))
    scope = _check_scope(permit["scope"])
    if _scope_digest(scope) != permit["scope_digest"]:
        raise _PermitTampered(
            "permit-tampered: scope digest does not recompute over the "
            "permitted scope; the permit was edited after issue")
    body = {k: permit[k] for k in _PERMIT_FIELDS}
    if not hmac.compare_digest(_body_digest(body), permit["permit_digest"]):
        raise _PermitTampered(
            "permit-tampered: permit digest does not recompute over the "
            "permit body; the permit was edited after issue")
    return True


def dispatch(permit, request_bytes):
    """Authorize dispatch of ``request_bytes`` under ``permit``.

    A permit that fails ``verify_permit`` never reaches the binding
    check (refuses ``permit-tampered`` for an edited record,
    ``permit-malformed`` for a wrong shape). Dispatch with no permit
    refuses ``dispatch-without-permit``. Actual bytes whose canonical
    digest differs from the Permit's bound digest refuse
    ``permit-binding-mismatch``. Returns True when the bytes bind.
    """
    if permit is None:
        raise _DispatchWithoutPermit(
            "dispatch-without-permit: dispatch attempted with no "
            "permit; the permit must be issued pre-dispatch")
    verify_permit(permit)  # tampered permit never reaches dispatch
    canonical = _canonical_request_bytes(request_bytes)
    if not hmac.compare_digest(_digest_bytes(canonical),
                               permit["request_digest"]):
        raise _PermitBindingMismatch(
            "permit-binding-mismatch: dispatched request bytes do not "
            "match the bytes bound in the permit; refusing")
    return True


# ----------------------------------------------------------------------
# Closures: post-execution attestation.
# ----------------------------------------------------------------------


def issue_closure(permit, outcome_digest, effects, closure_id=None,
                  closed_at=None):
    """Seal a Closure record bound to the Permit's digest.

    ``outcome_digest`` is the caller's bare 64-hex digest of the
    execution outcome; ``effects`` are the effects the caller reports
    as taken. The closure attests what is reported; whether the
    effects are acceptable is decided by ``verify_closure``, which
    enforces narrowing against the Permit's scope. Returns the sealed
    closure dict.
    """
    if permit is None:
        raise _ClosurePermitAbsent(
            "closure-permit-absent: closure attempted with no permit; "
            "a closure must bind to an issued permit")
    verify_permit(permit)  # a closure can only bind a valid permit
    if not _is_bare_digest(outcome_digest):
        raise _PermitMalformed(
            "permit-malformed: outcome_digest must be a bare 64-hex "
            "digest")
    effects = _check_effects(effects)
    cid = closure_id or "closure-%d" % int(time.time() * 1000)
    _check_permit_id(cid, "closure_id")
    body = {
        "version": _CLOSURE_VERSION,
        "closure_id": cid,
        "permit_digest": permit["permit_digest"],
        "outcome_digest": outcome_digest,
        "effects": effects,
        "effects_digest": _digest_bytes(
            _canonical_dumps(sorted(effects)).encode("utf-8")),
    }
    return dict(body, closure_digest=_body_digest(body))


def verify_closure(closure, permit):
    """Verify a presented Closure against its Permit.

    Refuses ``permit-malformed`` (wrong shape) and ``permit-tampered``
    (edited after issue), ``closure-permit-absent`` (no permit
    presented), ``closure-permit-mismatch`` (the closure's bound
    permit digest does not match the presented permit), and
    ``closure-scope-widened`` (the closure's effects exceed the
    permit's scope: a closure may narrow, never widen). Returns True
    when the two halves agree.
    """
    if not isinstance(closure, dict):
        raise _PermitMalformed(
            "permit-malformed: closure must be a dict")
    for field in _CLOSURE_FIELDS + ("closure_digest",):
        if field not in closure:
            raise _PermitMalformed(
                "permit-malformed: missing field %r" % (field,))
    if closure.get("version") != _CLOSURE_VERSION:
        raise _PermitMalformed(
            "permit-malformed: unsupported closure version")
    _check_permit_id(closure["closure_id"], "closure_id")
    if not _is_bare_digest(closure["permit_digest"]):
        raise _PermitMalformed(
            "permit-malformed: permit_digest must be a bare 64-hex "
            "digest")
    if not _is_bare_digest(closure["outcome_digest"]):
        raise _PermitMalformed(
            "permit-malformed: outcome_digest must be a bare 64-hex "
            "digest")
    effects = _check_effects(closure["effects"])
    if _digest_bytes(
            _canonical_dumps(sorted(effects)).encode("utf-8")
    ) != closure["effects_digest"]:
        raise _PermitTampered(
            "permit-tampered: effects digest does not recompute; the "
            "closure was edited after issue")
    body = {k: closure[k] for k in _CLOSURE_FIELDS}
    if not hmac.compare_digest(_body_digest(body), closure["closure_digest"]):
        raise _PermitTampered(
            "permit-tampered: closure digest does not recompute over "
            "the closure body; the closure was edited after issue")
    if permit is None:
        raise _ClosurePermitAbsent(
            "closure-permit-absent: closure presented without its "
            "matching permit; the two halves must be presented "
            "together")
    verify_permit(permit)  # the permit half must itself be intact
    if not hmac.compare_digest(closure["permit_digest"],
                               permit["permit_digest"]):
        raise _ClosurePermitMismatch(
            "closure-permit-mismatch: closure binds a different "
            "permit digest than the presented permit; refusing")
    scope = _check_scope(permit["scope"])
    widened = [e for e in effects if e not in set(scope)]
    if widened:
        raise _ClosureScopeWidened(
            "closure-scope-widened: closure claims effects outside the "
            "permit's scope (%s); a closure may narrow, never widen"
            % (", ".join(sorted(widened))[:120],))
    return True
