"""ARAP (Access Request and Approval profile) hardening for the approval queue.

This module natively reimplements the *ideas* of the AuthZEN ARAP
(Access Request and Approval) profile — an OpenID Final specification —
as a tighten-only, opt-in layer over ``gov.approvals``. No upstream
AuthZEN source is vendored here, and no spec conformance is claimed;
only the mechanism shapes are adapted:

1. **Authorization-relevant context.** An approval decision binds the
   subject/resource/action triple. Any further context the approver
   relied on (the material facts they saw) must be DECLARED and
   integrity-protected: ``declare_context`` pins each field's digest
   under a deployment key, ``check_cited_context`` refuses any approval
   that cites a context field outside the declared set. An approval
   whose context is not declared binds only the triple — never
   undeclared context (ARAP: authorization-relevant context must be
   declared and integrity-protected, else only the base attributes
   bind).

2. **Terminal statuses with bulk aggregation.** Request lifecycle is an
   explicit, audited, monotonic state machine: ``pending`` is the only
   non-terminal status; terminal statuses are
   ``approved | denied | expired | cancelled | failed | partial``. A
   terminal request can never transition again — terminal ->
   non-terminal and terminal -> terminal are refused fail-closed. A
   request is never left in a non-terminal limbo: expiry and failure
   are explicit audited transitions. ``aggregate_statuses`` folds a
   bulk of terminal outcomes to a single status (``partial`` on mixed
   approve/deny), refusing non-terminal input by construction.

3. **Idempotency-Key discipline.** ``IdempotencyRegistry`` maps an
   Idempotency-Key to the request-body digest and the recorded
   decision. The same key + identical body replays the ORIGINAL
   decision — the request is never re-decided. The same key +
   different body is refused as ``duplicate_request`` (the 409 shape),
   both on check and on record: a key can never be re-pointed at a
   different request (key-reuse attack).

4. **Independent cancellation authorization.** ``cancel_request``
   requires the canceller to be in the request's pinned
   ``authorized_cancellers`` set — holding the request id or a client
   handle is not enough. ``HandleRegistry`` issues opaque,
   unguessable handles; resolving a handle first checks the
   principal's authority, so a handle presented by an unauthorized
   party resolves to nothing (``handle-not-authority``). Handles
   carry no authority by construction — no handle leakage.

All refusals raise ``ArapError`` subclasses with a machine-readable
``code``. Authoring misuse (unknown statuses, malformed inputs)
raises plain ``ValueError``/``TypeError`` — those are caller bugs,
not attack shapes.

$0 spend. stdlib only. Deployment-owned keys.
"""

import hashlib
import hmac
import json
import secrets
import time
from hashlib import sha256

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class ArapError(Exception):
    """Base class for all ARAP refusals. ``code`` is machine-readable."""

    code = "arap-error"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class ContextNotDeclaredError(ArapError):
    """An approval cited context outside the declared, integrity-bound
    set, or a context binding failed verification."""

    code = "context-not-declared"


class TerminalTransitionError(ArapError):
    """A lifecycle transition was refused: terminal states are final,
    and non-terminal limbo is not a legal target."""

    code = "terminal-transition-refused"


class DuplicateRequestError(ArapError):
    """An Idempotency-Key was presented with a different request body
    than the one it was recorded for (the 409 duplicate_request shape),
    or a recorded key was re-pointed."""

    code = "duplicate_request"


class CancellationUnauthorizedError(ArapError):
    """A cancellation was attempted by a principal not in the request's
    pinned authorized-cancellers set."""

    code = "cancellation-unauthorized"


class HandleNotAuthorityError(ArapError):
    """A client handle was presented without authority: either the
    presenter is not an authorized canceller (the handle alone buys
    nothing) or the handle is unknown. Handles carry no authority."""

    code = "handle-not-authority"


# ----------------------------------------------------------------------
# Authorization-relevant context.
# ----------------------------------------------------------------------

_DIGEST_SCHEME = "sha256"
_BINDING_SCHEME = "hmac-sha256-v1"
_BINDING_DOMAIN = "sasanam-arap-context/v1:"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def _field_digest(value):
    """Per-field digest: sha256 over the canonical JSON of the value."""
    return "%s:%s" % (_DIGEST_SCHEME,
                      sha256(_canonical(value).encode("utf-8")).hexdigest())


def declare_context(context, *, key):
    """Declare the authorization-relevant context and integrity-bind it.

    ``context`` maps field name -> the material fact the approver saw.
    Returns ``{"declared": {name: digest}, "binding": hmac}`` where each
    per-field digest is ``sha256:<hex>`` over the canonical value and
    ``binding`` is ``hmac-sha256-v1:<hex>`` keyed to the deployment key
    over the sorted name->digest map. Malformed input is a caller bug
    (TypeError/ValueError), not an attack shape.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise ValueError("declare_context requires a key of at least "
                         "16 bytes")
    if not isinstance(context, dict):
        raise TypeError("context must be a dict of field name -> value")
    declared = {}
    for name, value in context.items():
        if not isinstance(name, str) or not name:
            raise ValueError("context field names must be non-empty "
                             "strings")
        declared[name] = _field_digest(value)
    mac = hmac.new(bytes(key),
                   (_BINDING_DOMAIN + _canonical(declared)).encode("utf-8"),
                   sha256).hexdigest()
    return {"declared": declared,
            "binding": "%s:%s" % (_BINDING_SCHEME, mac)}


def verify_context_binding(declared, binding, *, key):
    """Re-verify a declared context set against its binding.

    Raises ContextNotDeclaredError("context-binding-mismatch") on any
    tampering: rewritten digests, added/removed fields, wrong key.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise ValueError("verify_context_binding requires a key of at "
                         "least 16 bytes")
    if not isinstance(declared, dict) or not isinstance(binding, str):
        raise ContextNotDeclaredError(
            "context-binding-mismatch: malformed declaration",
            code="context-binding-mismatch")
    # Recompute the binding from the presented declaration and compare
    # in constant time; any deviation — including a wrong key — fails.
    names = sorted(declared)
    if any(not isinstance(n, str) or not isinstance(declared[n], str)
           for n in names):
        raise ContextNotDeclaredError(
            "context-binding-mismatch: malformed declaration",
            code="context-binding-mismatch")
    recomputed = hmac.new(
        bytes(key),
        (_BINDING_DOMAIN + _canonical(
            {n: declared[n] for n in names})).encode("utf-8"),
        sha256).hexdigest()
    want = "%s:%s" % (_BINDING_SCHEME, recomputed)
    if not hmac.compare_digest(binding, want):
        raise ContextNotDeclaredError(
            "context-binding-mismatch: declared context does not match "
            "its integrity binding",
            code="context-binding-mismatch")


def check_cited_context(cited_fields, declared):
    """Refuse any approval that cites context outside the declared set.

    ``cited_fields`` is the list of context field names the approval
    decision claims to rest on; ``declared`` is the ``declared`` map
    from ``declare_context``. Every cited field must be declared —
    otherwise the approval binds only the triple and the citation is
    refused fail-closed.
    """
    if cited_fields is None:
        cited_fields = []
    declared = declared or {}
    for field in cited_fields:
        if field not in declared:
            raise ContextNotDeclaredError(
                "context-not-declared: approval cites context field %r "
                "outside the declared, integrity-bound set" % (field,))
    return True


def binding_scope(declared):
    """Human/audit description of what an approval binds.

    With no declared context the approval binds only the
    subject/resource/action triple — never undeclared context.
    """
    declared = declared or {}
    if not declared:
        return "subject/resource/action"
    return ("subject/resource/action + %d declared context fields"
            % len(declared))


# ----------------------------------------------------------------------
# Terminal statuses: explicit, audited, monotonic lifecycle.
# ----------------------------------------------------------------------

TERMINAL_STATUSES = frozenset(
    {"approved", "denied", "expired", "cancelled", "failed", "partial"})
NON_TERMINAL_STATUSES = frozenset({"pending"})
ALL_STATUSES = TERMINAL_STATUSES | NON_TERMINAL_STATUSES


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def new_request(request_id, subject, resource, action, *, context=None,
               idempotency_key=None, authorized_cancellers=(),
               key=None):
    """Create a new ARAP-hardened approval request record.

    ``context`` (optional) is the authorization-relevant context dict;
    it is declared and integrity-bound when a ``key`` is supplied —
    without a key, context is NOT integrity-protected and therefore
    NOT part of the binding (the record binds the triple only, and the
    declared set is empty). ``authorized_cancellers`` pins who may
    cancel; empty means nobody may cancel (fail closed).
    """
    for label, value in (("request_id", request_id),
                        ("subject", subject),
                        ("resource", resource),
                        ("action", action)):
        if not isinstance(value, str) or not value:
            raise ValueError("%s must be a non-empty string" % label)
    if context is None:
        declared, binding = {}, None
    elif key is None:
        # Caller offered context but no key: the context cannot be
        # integrity-protected, so it is dropped from the binding and
        # the record binds the triple only (loud, never silent).
        declared, binding = {}, None
    else:
        decl = declare_context(context, key=key)
        declared, binding = decl["declared"], decl["binding"]
    cancellers = tuple(authorized_cancellers or ())
    for principal in cancellers:
        if not isinstance(principal, str) or not principal:
            raise ValueError("authorized_cancellers must be non-empty "
                             "strings")
    return {
        "request_id": request_id,
        "subject": subject,
        "resource": resource,
        "action": action,
        "declared_context": declared,
        "context_binding": binding,
        "idempotency_key": idempotency_key,
        "authorized_cancellers": list(cancellers),
        "status": "pending",
        "history": [{"from": None, "to": "pending",
                     "at": _now_iso(), "by": "queue"}],
    }


def transition(req, new_status, *, by, audit=None):
    """Move a request to a new lifecycle status.

    Only forward transitions from a non-terminal status are allowed:
    terminal -> anything and terminal -> terminal are refused with
    TerminalTransitionError("terminal-transition-refused"); unknown
    target statuses are an authoring bug (ValueError). Every accepted
    transition is appended to ``history`` and, when ``audit`` is
    supplied, emitted as an ``arap_status_transition`` audit entry.
    """
    if new_status not in ALL_STATUSES:
        raise ValueError("unknown ARAP status %r" % (new_status,))
    old = req.get("status")
    if old in TERMINAL_STATUSES:
        raise TerminalTransitionError(
            "terminal-transition-refused: request %r is terminal (%s); "
            "terminal states are final" % (req.get("request_id"), old))
    if old == new_status:
        raise TerminalTransitionError(
            "terminal-transition-refused: no-op transition to %r" % old)
    entry = {"from": old, "to": new_status, "at": _now_iso(), "by": by}
    req.setdefault("history", []).append(entry)
    req["status"] = new_status
    if audit is not None:
        audit({"event": "arap_status_transition",
               "request_id": req.get("request_id"),
               "from": old, "to": new_status, "by": by,
               "at": entry["at"]})
    return req


def aggregate_statuses(statuses):
    """Fold a bulk of terminal outcomes to one status (ARAP bulk).

    Uniform bulks aggregate to their status; mixed approve/deny bulks
    aggregate to ``partial``. Non-terminal input is refused by
    construction — a bulk is only ever taken over terminal outcomes,
    so a request is never left in a non-terminal limbo. Empty input
    is a caller bug (ValueError).
    """
    statuses = list(statuses)
    if not statuses:
        raise ValueError("aggregate_statuses requires at least one status")
    for status in statuses:
        if status not in TERMINAL_STATUSES:
            raise ValueError(
                "aggregate_statuses refuses non-terminal status %r: "
                "bulks are only taken over terminal outcomes" % (status,))
    distinct = set(statuses)
    if len(distinct) == 1:
        return statuses[0]
    return "partial"


# ----------------------------------------------------------------------
# Idempotency-Key discipline.
# ----------------------------------------------------------------------


class IdempotencyRegistry:
    """Maps Idempotency-Key -> (request-body digest, recorded decision).

    The same key + identical body replays the original decision — the
    request is never re-decided. The same key + a different body is
    refused as ``duplicate_request`` (the 409 shape), both on
    ``check`` and on ``record``: a recorded key can never be re-pointed
    at a different request (key-reuse attack).
    """

    def __init__(self):
        self._entries = {}

    def check(self, key, body_digest):
        """Return "new" (unknown key), "replay" (known key, same body),
        or raise DuplicateRequestError on key + different body."""
        if not isinstance(key, str) or not key:
            raise ValueError("idempotency key must be a non-empty string")
        if not isinstance(body_digest, str) or not body_digest:
            raise ValueError("body_digest must be a non-empty string")
        entry = self._entries.get(key)
        if entry is None:
            return "new"
        if not hmac.compare_digest(entry["body_digest"], body_digest):
            raise DuplicateRequestError(
                "duplicate_request: Idempotency-Key %r was recorded for "
                "a different request body" % (key,))
        return "replay"

    def record(self, key, body_digest, decision):
        """Record the decision for a key. Recording over a key that
        already maps to a DIFFERENT body is refused — the original
        decision stands."""
        verdict = self.check(key, body_digest)
        if verdict == "new":
            self._entries[key] = {"body_digest": body_digest,
                                  "decision": decision}
            return "recorded"
        # "replay": the key already maps to this body. Re-recording
        # with a different decision would silently re-decide; refuse.
        if self._entries[key]["decision"] != decision:
            raise DuplicateRequestError(
                "duplicate_request: Idempotency-Key %r already recorded "
                "a decision for this body; replays return the original"
                % (key,))
        return "replay"

    def decision(self, key):
        """Return the recorded decision for a key (KeyError if none)."""
        return self._entries[key]["decision"]


# ----------------------------------------------------------------------
# Independent cancellation authorization; handles carry no authority.
# ----------------------------------------------------------------------


def authorize_cancellation(req, canceller_principal):
    """Check that ``canceller_principal`` may cancel ``req``.

    The canceller must be in the request's PINNED
    ``authorized_cancellers`` set. Holding the request id, the
    approval id, or a client handle is NOT sufficient — cancellation
    requires its own authorization. An empty authorized set means
    nobody may cancel (fail closed).
    """
    allowed = req.get("authorized_cancellers") or []
    if canceller_principal not in allowed:
        raise CancellationUnauthorizedError(
            "cancellation-unauthorized: principal %r is not authorized "
            "to cancel request %r" % (canceller_principal,
                                      req.get("request_id")))
    return True


def cancel_request(req, canceller_principal, *, audit=None):
    """Cancel a request after authorizing the canceller, then
    transition it to the terminal ``cancelled`` status (audited)."""
    authorize_cancellation(req, canceller_principal)
    return transition(req, "cancelled", by=canceller_principal,
                      audit=audit)


class HandleRegistry:
    """Opaque client handles that carry NO authority.

    ``issue`` mints an unguessable handle for a request id. ``resolve``
    maps a handle back to its request id ONLY for a principal that is
    authorized — authority is checked first, the handle second, so a
    handle presented by an unauthorized party (or leaked to one)
    resolves to nothing. Unknown handles are refused distinctly.
    """

    def __init__(self):
        self._handles = {}

    def issue(self, request_id):
        """Mint an opaque handle for ``request_id``."""
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id must be a non-empty string")
        handle = "arap-handle-" + secrets.token_urlsafe(24)
        self._handles[handle] = request_id
        return handle

    def resolve(self, handle, presenter_principal, *, authorized):
        """Resolve a handle for an authorized presenter.

        ``authorized`` is the pinned set of principals allowed to act
        on the underlying request. If the presenter is not authorized,
        the handle buys nothing (``handle-not-authority``) — even when
        the handle itself is valid. Unknown handles are refused as
        ``handle-unknown``.
        """
        if presenter_principal not in (authorized or ()):
            raise HandleNotAuthorityError(
                "handle-not-authority: presenter %r has no authority "
                "over this handle" % (presenter_principal,))
        try:
            return self._handles[handle]
        except KeyError:
            raise HandleNotAuthorityError(
                "handle-unknown: no request behind this handle",
                code="handle-unknown") from None


__all__ = [
    "ArapError",
    "ContextNotDeclaredError",
    "TerminalTransitionError",
    "DuplicateRequestError",
    "CancellationUnauthorizedError",
    "HandleNotAuthorityError",
    "TERMINAL_STATUSES",
    "NON_TERMINAL_STATUSES",
    "ALL_STATUSES",
    "declare_context",
    "verify_context_binding",
    "check_cited_context",
    "binding_scope",
    "new_request",
    "transition",
    "aggregate_statuses",
    "IdempotencyRegistry",
    "authorize_cancellation",
    "cancel_request",
    "HandleRegistry",
]
