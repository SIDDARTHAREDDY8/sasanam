"""gov.governed_exceptions -- checkov-pattern governed exception primitive.

Exceptions as first-class, justified, scoped, expiring data. A policy
check that would otherwise FAIL can be suppressed only through a
declared exception, and suppression reports SKIPPED with the exception
digest attached -- never PASSED, never silent.

Pattern lineage: bridgecrewio/checkov (Apache-2.0; verified in the
wave-284 prospectus, ``child-b-supplychain-identity.md``). ADAPT, not
vendored: the suppression-with-mandatory-justification primitive
(``checkov:skip=<check_id>:<comment>`` reporting SKIPPED with the
comment surfaced), the check registry (registered checks with id, name,
category, severity, rationale), and the baseline ratchet
(``--create-baseline``: freeze today's state, fail only on new drift)
are reimplemented here in stdlib-only Python as contract shapes.
Checkov's IaC parsers and its heavyweight dependency tree are NOT
adopted (F75 supply-chain lesson). No checkov code is vendored.

Design convergences honored here: checkov's inline suppression, the
conftest exception-outcome workflow, and wave-283's DefectDojo
``risk_accepted`` all point at the same shape -- exceptions are data
with mandatory justification, an approver, a bounded expiry, and a
resource/tool/policy scope. There are no permanent exceptions.

Composition with gov.finding_lifecycle: an exception may reference a
finding (``exception-suppressed`` annotation), but it can never close
one. The finding stays OPEN; there is no code path from an exception
to a finding-state transition. The ``close_finding_via_exception``
escape hatch exists only to refuse LOUD -- it is the probe target for
that invariant, not a feature.

All refusals are LOUD: coded GovernExceptionError, never silent.
Audit: every grant / deny / expire / revoke emits an event carrying the
exception digest. The in-process audit list is the default sink;
deployments wire their HMAC audit log via ``set_emit`` (opt-in, like
the nsjail sandbox-policy layer); broken sinks are recorded via
``sink_errors()`` rather than failing silently.
"""

import hashlib
import json
import re
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXCEPTION_FORMAT = "sasanam-governed-exception/v1"
BASELINE_FORMAT = "sasanam-exception-baseline/v1"

#: Maximum exception lifetime: 90 days. No permanent exceptions.
MAX_EXCEPTION_TTL_SECONDS = 90 * 24 * 3600

#: Minimum justification length: a justification must say something.
MIN_JUSTIFICATION_CHARS = 20

#: Closed scope vocabulary (checkov suppressions are resource-scoped).
SCOPE_KINDS = frozenset({"resource", "tool", "policy"})

CHECK_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
CHECK_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

# Decision-code vocabulary (registered in gov/decision_codes.py).
# ``exception-expired`` predates this lane (policy-exception seam) and is
# reused here: the refusal semantics are identical.
UNKNOWN_CHECK = "exception-unknown-check"
DUPLICATE_CHECK = "exception-duplicate-check"
DECLARATION_INVALID = "exception-declaration-invalid"
JUSTIFICATION_MISSING = "exception-justification-missing"
UNAPPROVED_APPROVER = "exception-unapproved-approver"
EXPIRY_INVALID = "exception-expiry-invalid"
EXPIRED = "exception-expired"
SCOPE_MISMATCH = "exception-scope-mismatch"
BASELINE_DRIFT = "exception-baseline-drift"
DUPLICATE = "exception-duplicate"
CLOSE_REFUSED = "exception-close-refused"
UNKNOWN_DIGEST = "exception-unknown-digest"

__all__ = [
    "EXCEPTION_FORMAT",
    "BASELINE_FORMAT",
    "MAX_EXCEPTION_TTL_SECONDS",
    "MIN_JUSTIFICATION_CHARS",
    "SCOPE_KINDS",
    "GovernExceptionError",
    "CheckRegistry",
    "ExceptionStore",
    "Exception",
    "set_emit",
    "sink_errors",
]


class GovernExceptionError(ValueError):
    """LOUD coded refusal for the governed-exception seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _normalize_scope(scope):
    """Validate a scope; return [kind, value]. Refuses LOUD."""
    if (not isinstance(scope, (tuple, list)) or len(scope) != 2
            or scope[0] not in SCOPE_KINDS
            or not isinstance(scope[1], str) or not scope[1]):
        raise GovernExceptionError(
            "exception scope must be (kind, value) with kind in %s and a "
            "non-empty value; got %r" % (sorted(SCOPE_KINDS), scope),
            code=SCOPE_MISMATCH)
    return [scope[0], scope[1]]


def _declaration_digest(check_id, scope, justification, approver, expiry_ts,
                        finding_number):
    """Deterministic digest over the semantic declaration.

    ``created_at`` is intentionally EXCLUDED: a semantically identical
    re-grant one second later must collide with the existing grant
    (honest duplicate detection -- a duplicate refusal that only
    catches byte-identical replays is vacuous). A re-grant with a
    different justification, approver, expiry, scope, or finding is a
    different declaration and gets a different digest.
    """
    try:
        norm_scope = _normalize_scope(scope)
    except GovernExceptionError:
        norm_scope = ["invalid", str(scope)]
    return _digest({
        "format": EXCEPTION_FORMAT,
        "check_id": check_id,
        "scope": norm_scope,
        "justification": justification,
        "approver": approver,
        "expiry_ts": expiry_ts,
        "finding_number": finding_number,
    })


# ---------------------------------------------------------------------------
# Opt-in audit sink (deployment wires the HMAC audit log here)
# ---------------------------------------------------------------------------

_emit_sinks = []

#: Broken-sink records: a sink that raised is recorded here instead of
#: failing silently, so audit loss is observable. The in-process audit
#: list remains the primary record; sinks are best-effort by design.
_sink_errors = []


def set_emit(fn):
    """Register an opt-in audit sink. Returns an unregister callable."""
    _emit_sinks.append(fn)

    def _unregister():
        try:
            _emit_sinks.remove(fn)
        except ValueError:
            pass

    return _unregister


def sink_errors():
    """Records of sinks that raised while emitting (observable, not silent)."""
    return list(_sink_errors)


def _emit(event):
    for fn in list(_emit_sinks):
        try:
            fn(event)
        except Exception as e:
            # A broken sink must not break the exception seam, but the
            # failure is recorded -- never swallowed silently.
            _sink_errors.append({"sink": repr(fn), "error": str(e)[:200],
                                 "event": event.get("event")})


# ---------------------------------------------------------------------------
# Check registry (checkov's registry shape)
# ---------------------------------------------------------------------------

class CheckRegistry:
    """Registered policy checks: id, name, category, severity, rationale.

    Mirrors checkov's check registry -- every check is a registered
    object with a stable id (``SAS_*``), not an ad-hoc string.
    """

    def __init__(self):
        self._checks = {}

    def register(self, check_id, name, category, severity, rationale,
                 resource_types):
        """Register a check. Duplicate ids and malformed declarations
        refuse LOUD."""
        if not isinstance(check_id, str) or not CHECK_ID_RE.match(check_id):
            raise GovernExceptionError(
                "check id must match %s; got %r"
                % (CHECK_ID_RE.pattern, check_id),
                code=UNKNOWN_CHECK)
        if check_id in self._checks:
            raise GovernExceptionError(
                "check %r is already registered" % (check_id,),
                code=DUPLICATE_CHECK)
        if not isinstance(name, str) or not name:
            raise GovernExceptionError("check name must be non-empty",
                                       code=DECLARATION_INVALID)
        if not isinstance(category, str) or not category:
            raise GovernExceptionError(
                "check category must be a non-empty string",
                code=DECLARATION_INVALID)
        if severity not in CHECK_SEVERITIES:
            raise GovernExceptionError(
                "check severity must be one of %s; got %r"
                % (sorted(CHECK_SEVERITIES), severity),
                code=DECLARATION_INVALID)
        if not isinstance(rationale, str) or len(rationale) < 10:
            raise GovernExceptionError(
                "check rationale must explain the check (>= 10 chars)",
                code=DECLARATION_INVALID)
        if (not isinstance(resource_types, (list, tuple))
                or not resource_types
                or not all(isinstance(r, str) and r
                           for r in resource_types)):
            raise GovernExceptionError(
                "check resource_types must be a non-empty list of strings",
                code=DECLARATION_INVALID)
        self._checks[check_id] = {
            "check_id": check_id,
            "name": name,
            "category": category,
            "severity": severity,
            "rationale": rationale,
            "resource_types": list(resource_types),
        }
        return self._checks[check_id]

    def __contains__(self, check_id):
        return check_id in self._checks

    def get(self, check_id):
        return self._checks.get(check_id)

    def all(self):
        return dict(self._checks)


# ---------------------------------------------------------------------------
# Exception record
# ---------------------------------------------------------------------------

class Exception:
    """One granted exception: justified, scoped, expiring data."""

    def __init__(self, check_id, scope, justification, approver, expiry_ts,
                 created_at, finding_number, digest):
        self.check_id = check_id
        self.scope = tuple(scope)
        self.justification = justification
        self.approver = approver
        self.expiry_ts = expiry_ts
        self.created_at = created_at
        self.finding_number = finding_number
        self.digest = digest
        self.status = "live"
        self.revoked_at = None
        self.revoke_reason = None

    def is_live(self, now):
        return self.status == "live" and self.expiry_ts > now

    def to_dict(self):
        return {
            "format": EXCEPTION_FORMAT,
            "check_id": self.check_id,
            "scope": list(self.scope),
            "justification": self.justification,
            "approver": self.approver,
            "expiry_ts": self.expiry_ts,
            "created_at": self.created_at,
            "finding_number": self.finding_number,
            "digest": self.digest,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Exception store
# ---------------------------------------------------------------------------

class ExceptionStore:
    """Grant / evaluate / revoke / baseline exceptions.

    Suppression semantics are SKIPPED-never-PASSED: a suppressed check
    reports SKIPPED with the exception digest attached; it never
    reports PASSED and never vanishes from output.
    """

    def __init__(self, registry):
        if not isinstance(registry, CheckRegistry):
            raise GovernExceptionError(
                "ExceptionStore needs a CheckRegistry", code=UNKNOWN_CHECK)
        self._registry = registry
        self._approvers = None  # unset: fail closed, no grants possible
        self._exceptions = {}  # digest -> Exception
        self._finding_refs = {}  # finding_number -> [digest]
        self._audit = []

    # -- configuration ----------------------------------------------------

    def set_approvers(self, approvers):
        """Set the principals allowed to approve exceptions.

        Until this is called with a non-empty list, every grant
        refuses LOUD: exceptions are never open by default.
        """
        if (not isinstance(approvers, (list, tuple)) or not approvers
                or not all(isinstance(a, str) and a for a in approvers)):
            raise GovernExceptionError(
                "approvers must be a non-empty list of principal strings",
                code=UNAPPROVED_APPROVER)
        self._approvers = list(approvers)

    # -- audit ------------------------------------------------------------

    def _audit_event(self, event, digest, detail, now):
        entry = {"event": event, "exception_digest": digest,
                 "at": now, "detail": detail}
        self._audit.append(entry)
        _emit(entry)

    def audit_events(self):
        return list(self._audit)

    # -- grant ------------------------------------------------------------

    def grant(self, check_id, scope, justification, approver, expiry_ts,
              created_at, finding_number=None, now=None):
        """Grant an exception. Every validation failure refuses LOUD
        with a coded error AND is recorded as a denied audit event."""
        now = time.time() if now is None else now
        digest = _declaration_digest(check_id, scope, justification,
                                     approver, expiry_ts, finding_number)

        def _deny(code, message):
            self._audit_event("denied", digest, {"code": code}, now)
            raise GovernExceptionError(message, code=code)

        if check_id not in self._registry:
            _deny(UNKNOWN_CHECK,
                  "cannot grant exception: check %r is not registered"
                  % (check_id,))
        if self._approvers is None or approver not in self._approvers:
            _deny(UNAPPROVED_APPROVER,
                  "cannot grant exception: approver %r is not an approved "
                  "exception approver" % (approver,))
        if (not isinstance(justification, str)
                or len(justification) < MIN_JUSTIFICATION_CHARS):
            _deny(JUSTIFICATION_MISSING,
                  "cannot grant exception: justification is mandatory "
                  "(>= %d chars)" % (MIN_JUSTIFICATION_CHARS,))
        try:
            norm_scope = _normalize_scope(scope)
        except GovernExceptionError as e:
            _deny(e.code, str(e))
        if (not isinstance(created_at, (int, float))
                or created_at > now):
            _deny(DECLARATION_INVALID,
                  "cannot grant exception: created_at must be a timestamp "
                  "not in the future")
        if (not isinstance(expiry_ts, (int, float))
                or expiry_ts <= now
                or expiry_ts > now + MAX_EXCEPTION_TTL_SECONDS):
            _deny(EXPIRY_INVALID,
                  "cannot grant exception: expiry must be in the future "
                  "and within %d seconds (no permanent exceptions)"
                  % (MAX_EXCEPTION_TTL_SECONDS,))
        if digest in self._exceptions:
            _deny(DUPLICATE,
                  "exception %s... is already granted" % digest[:16])

        exc = Exception(check_id, norm_scope, justification, approver,
                        expiry_ts, created_at, finding_number, digest)
        self._exceptions[digest] = exc
        if finding_number is not None:
            self._finding_refs.setdefault(finding_number, []).append(digest)
        self._audit_event("granted", digest,
                          {"check_id": check_id,
                           "scope": norm_scope,
                           "finding_number": finding_number}, now)
        return exc

    # -- evaluate ---------------------------------------------------------

    def _covering(self, check_id, scope, now):
        """Return (live_exception, expired_exception) for an exact
        (check_id, scope) match. Expired matches are never silent."""
        live = None
        expired = None
        for exc in self._exceptions.values():
            if exc.check_id != check_id or list(exc.scope) != list(scope):
                continue
            if exc.is_live(now):
                live = exc
            else:
                expired = exc
        return live, expired

    def _mark_expired(self, exc, now):
        """Transition a live-but-past-expiry exception to ``expired``.

        Emits the dedicated ``expired`` audit event. Natural expiry is
        not a denial; it is the clock doing its job. Called before the
        EXPIRED refusal so the audit trail distinguishes the two.
        """
        if exc.status == "live" and exc.expiry_ts <= now:
            exc.status = "expired"
            self._audit_event("expired", exc.digest,
                              {"check_id": exc.check_id,
                               "expiry_ts": exc.expiry_ts}, now)

    def sweep_expired(self, now=None):
        """Mark every live-but-past-expiry exception as ``expired``.

        An exception that expires without being evaluated still emits
        its ``expired`` audit event -- expiry is never silent. Returns
        the digests that transitioned.
        """
        now = time.time() if now is None else now
        swept = []
        for exc in self._exceptions.values():
            before = exc.status
            self._mark_expired(exc, now)
            if before == "live" and exc.status == "expired":
                swept.append(exc.digest)
        return swept

    def evaluate(self, check_id, scope, predicate, now=None):
        """Evaluate a check under the exception store.

        Returns {"status": "SKIPPED", "exception_digest": ...} when a
        live exception covers the scope; {"status": "PASSED"} /
        {"status": "FAILED"} from the predicate otherwise. A covering
        but expired/revoked exception refuses LOUD (exception-expired) --
        it never silently falls through to the predicate.
        """
        now = time.time() if now is None else now
        if check_id not in self._registry:
            raise GovernExceptionError(
                "cannot evaluate: check %r is not registered" % (check_id,),
                code=UNKNOWN_CHECK)
        norm_scope = _normalize_scope(scope)
        live, expired = self._covering(check_id, norm_scope, now)
        if live is not None:
            return {"status": "SKIPPED", "exception_digest": live.digest}
        if expired is not None:
            # Record the natural expiry first (dedicated "expired" event),
            # then refuse LOUD -- the evaluation itself is denied.
            self._mark_expired(expired, now)
            self._audit_event("denied", expired.digest,
                              {"code": EXPIRED,
                               "reason": "covering exception is expired or "
                                         "revoked"}, now)
            raise GovernExceptionError(
                "check %r scope %r: the covering exception %s... is "
                "expired or revoked; re-grant explicitly"
                % (check_id, norm_scope, expired.digest[:16]),
                code=EXPIRED)
        return {"status": "PASSED" if predicate() else "FAILED"}

    def evaluate_scoped(self, check_id, exception_scope, eval_scope,
                        now=None):
        """Explicit cross-scope guard: an exception covers ONLY its own
        scope. Evaluating it against a foreign scope refuses LOUD.

        Deliberately NOT called by ``evaluate()``: a scope the store
        knows nothing about is simply inapplicable (the predicate
        runs), while THIS guard is for callers that hold a specific
        exception and must prove the evaluation scope is exactly the
        exception's scope before applying it. Different questions,
        different answers.
        """
        norm_exc = _normalize_scope(exception_scope)
        norm_eval = _normalize_scope(eval_scope)
        if norm_exc != norm_eval:
            raise GovernExceptionError(
                "exception scope %r does not cover evaluation scope %r"
                % (norm_exc, norm_eval),
                code=SCOPE_MISMATCH)
        return {"scope_match": True}

    # -- revoke -----------------------------------------------------------

    def revoke(self, digest, approver, reason, now=None):
        """Revoke a granted exception. The record is kept (audit trail);
        the exception stops covering evaluations."""
        now = time.time() if now is None else now
        exc = self._exceptions.get(digest)
        if exc is None:
            raise GovernExceptionError(
                "cannot revoke: unknown exception digest", code=UNKNOWN_DIGEST)
        if self._approvers is None or approver not in self._approvers:
            raise GovernExceptionError(
                "cannot revoke: approver %r is not an approved exception "
                "approver" % (approver,),
                code=UNAPPROVED_APPROVER)
        if exc.status == "revoked":
            # Idempotent: the desired end-state already holds. Returning
            # without a second "revoked" event keeps the audit trail
            # truthful (one revocation per digest).
            return exc
        exc.status = "revoked"
        exc.revoked_at = now
        exc.revoke_reason = reason
        self._audit_event("revoked", digest,
                          {"approver": approver, "reason": reason}, now)
        return exc

    # -- baseline ratchet -------------------------------------------------

    def create_baseline(self, now=None):
        """Pin the current live exception set. Drift beyond this
        baseline refuses LOUD via check_baseline."""
        now = time.time() if now is None else now
        digests = sorted(d for d, e in self._exceptions.items()
                         if e.status == "live")
        body = {"format": BASELINE_FORMAT, "created_at": now,
                "exception_digests": digests}
        body["baseline_digest"] = _digest(body)
        return body

    def check_baseline(self, baseline, now=None):
        """Refuse LOUD if the live set drifted beyond the baseline or
        the baseline document itself was tampered with."""
        now = time.time() if now is None else now
        if (not isinstance(baseline, dict)
                or baseline.get("format") != BASELINE_FORMAT
                or not isinstance(baseline.get("exception_digests"), list)):
            raise GovernExceptionError(
                "baseline document is malformed", code=BASELINE_DRIFT)
        body = {k: v for k, v in baseline.items() if k != "baseline_digest"}
        if _digest(body) != baseline.get("baseline_digest"):
            raise GovernExceptionError(
                "baseline digest mismatch: the baseline was tampered with",
                code=BASELINE_DRIFT)
        live = sorted(d for d, e in self._exceptions.items()
                      if e.status == "live")
        # Natural expiry is expected, not drift: a pinned exception that
        # reached the end of its bounded TTL still accounts for its
        # baseline slot. Early revocation, removal, or a new grant do
        # not -- those refuse LOUD as drift.
        accounted = sorted(d for d, e in self._exceptions.items()
                           if e.status in ("live", "expired"))
        if accounted != sorted(baseline["exception_digests"]):
            raise GovernExceptionError(
                "exception set drifted beyond the pinned baseline: "
                "%d accounted vs %d pinned"
                % (len(accounted), len(baseline["exception_digests"])),
                code=BASELINE_DRIFT)
        return {"baseline_ok": True, "live": len(live)}

    # -- finding composition (annotations only, never state changes) ------

    def link_finding(self, digest, finding_number, registry=None, now=None):
        """Record that an exception references a finding.

        Real composition with gov.finding_lifecycle: when a finding
        registry is passed, the ``exception-suppressed`` annotation is
        written onto the finding's own ``scan_notes`` -- the finding
        record carries the suppression, not just the store's side
        index. The finding's state is never touched: it stays OPEN.
        There is no code path here that mutates finding state.
        """
        now = time.time() if now is None else now
        if digest not in self._exceptions:
            raise GovernExceptionError(
                "cannot link: unknown exception digest", code=UNKNOWN_DIGEST)
        if registry is not None:
            finding = registry.get(finding_number)
            if finding is None:
                raise GovernExceptionError(
                    "cannot link: unknown finding %r" % (finding_number,),
                    code=UNKNOWN_DIGEST)
            finding.scan_notes.append({
                "kind": "exception-suppressed",
                "exception_digest": digest,
                "at": now,
            })
        refs = self._finding_refs.setdefault(finding_number, [])
        if digest not in refs:
            refs.append(digest)
        return {"finding_number": finding_number, "exception_digest": digest}

    def finding_annotations(self, finding_number):
        """Exception digests suppressing checks for a finding."""
        return list(self._finding_refs.get(finding_number, []))

    def close_finding_via_exception(self, digest, finding_number, actor):
        """There is no path from an exception to a closed finding.

        This method exists only to refuse LOUD: any caller attempting
        to close a finding through the exception seam gets a coded
        refusal, and the attempt is audited as denied.
        """
        now = time.time()
        self._audit_event("denied", digest,
                          {"code": CLOSE_REFUSED,
                           "reason": "exceptions cannot close findings",
                           "finding_number": finding_number,
                           "actor": actor}, now)
        raise GovernExceptionError(
            "refused: an exception can only annotate a finding as "
            "exception-suppressed; it can never close finding %r"
            % (finding_number,),
            code=CLOSE_REFUSED)
