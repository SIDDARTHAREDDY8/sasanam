"""Verifier-side evidence-admission policy (trust-policy language).

Pattern: the notaryproject/notation *verifier-side trust-policy language*
(as specified in the notaryproject/notaryproject spec repo), adapted as
pattern only (no code copied; Apache-2.0; clean-room stdlib-only Python):

* a **trust ladder** ``strict > permissive > audit > skip`` applied per
  policy scope (which evidence kinds are admitted under which level);
* **per-check overrides**: named checks within a scope may be raised or
  lowered one or more levels, but never past the **integrity floor**;
* a **non-overridable integrity floor**: some checks (signature
  validity, digest binding) can never be lowered below ``strict`` --
  the policy document, a per-check override, and the ``skip`` level
  alike cannot move them;
* **fail-closed on no-applicable-policy**: evidence with no matching
  scope is refused, never defaulted -- unless the policy author
  explicitly declares a ``default_level`` (an explicit choice, not a
  silent default).

Identity is the pinned-key identity Sasanam already uses everywhere
else -- NOT X.509 (the X.509-only identity of notation proper is a
trap we deliberately do not follow).

Scope: admission is the gate BEFORE appraisal. It decides whether
evidence ENTERS the appraisal pipeline; :mod:`gov.trust_vector`
grades it. Admission consults :func:`gov.evidence_provenance.verify_provenance`
as one of its checks, and routes operator accept-at-risk decisions
through :mod:`gov.governed_exceptions` (a governed exception can
never override the integrity floor).

This is the EVIDENCE half of admission. The ARTIFACT half -- admitting
build artifacts into a deployment pipeline (sigstore/policy-controller
pattern) -- lives in :mod:`gov.admission_policy`. The two modules share
the ``admission-*`` decision-code prefix but disjoint code names and
fundamentally different seams; do not merge them.

Honest limitations: this language is admission-only. It admits or
refuses evidence; it never grades it (grading is the trust vector's
job). Check outcomes are computed by the caller at the seam
(:func:`run_default_checks` wires the real provenance verifier for
known evidence kinds); admission itself is pure policy application.
"""

import copy
import hashlib
import hmac
import json
import os
from types import MappingProxyType

from gov import evidence_provenance as _prov

# ---------------------------------------------------------------------------
# Decision-code vocabulary (registered in gov/decision_codes.py).
# ---------------------------------------------------------------------------

POLICY_INVALID = "admission-policy-invalid"
NO_APPLICABLE_POLICY = "admission-no-applicable-policy"
REFUSED = "admission-refused"
CHECK_FAILED = "admission-check-failed"
FLOOR_VIOLATED = "admission-integrity-floor-violated"
AT_RISK_ACCEPTED = "admission-at-risk-accepted"
EXCEPTION_REFUSED = "admission-exception-refused"

#: Check id used with gov/governed_exceptions.py for accept-at-risk.
ACCEPT_RISK_CHECK_ID = "SAS_ADMISSION_ACCEPT_RISK"

POLICY_FORMAT = "admission-policy/1"

# The trust ladder, ordered.
STRICT = 3
PERMISSIVE = 2
AUDIT = 1
SKIP = 0

_LEVEL_NAMES = {
    "strict": STRICT,
    "permissive": PERMISSIVE,
    "audit": AUDIT,
    "skip": SKIP,
}
_LEVEL_BY_RANK = {v: k for k, v in _LEVEL_NAMES.items()}

#: Checks that can never be lowered below strict. The floor is
#: non-overridable: not by the policy document, not by a per-check
#: override, and not by the skip level (the floor still runs at strict
#: under skip).
INTEGRITY_FLOOR = frozenset({"signature-valid", "digest-binds"})

#: The named-check registry. Descriptions are human-readable; the floor
#: column is machine-enforced at compile time.
#:
#: F348: the registry is FROZEN at import (MappingProxyType) -- deleting
#: or replacing entries in-process raised the floor silently (the old
#: plain dict let ``del CHECKS["signature-valid"]`` remove the floor from
#: the admit() loop entirely). As defense in depth, admit() also refuses
#: LOUD when the registry no longer carries every INTEGRITY_FLOOR check
#: (e.g. the module attribute was rebound), so registry tampering fails
#: closed instead of skipping the floor.
_CHECKS = {
    "signature-valid": "envelope/checkpoint signature verifies under "
                       "the pinned key",
    "digest-binds": "the claimed artifact digest binds to the artifact",
    "provenance-present": "the provenance envelope verifies "
                         "(verify_provenance)",
    "builder-allowlisted": "builder.id is in the pinned builder "
                           "allowlist",
    "endorsement-independent": "endorsements are independently sourced",
    "witness-quorum": "the transparency-log witness quorum is satisfied",
    "freshness": "the TSA token is fresh (genTime within the skew "
                 "bound)",
}
CHECKS = MappingProxyType(_CHECKS)


class AdmissionError(Exception):
    """Loud admission failure. ``code`` is the machine-readable
    failure mode.

    F349: when raised by :func:`admit` for a REFUSE verdict, the error
    carries the refuse decision record admit() itself produced
    (``err.decision``), registered in-process (see ``_REFUSE_REGISTRY``).
    :func:`admit_at_risk` consumes that record -- never a
    caller-synthesized dict."""

    def __init__(self, message, code):
        super(AdmissionError, self).__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message
        self.decision = None


def _fail(code, detail):
    raise AdmissionError(detail, code=code)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Policy document
# ---------------------------------------------------------------------------

class AdmissionPolicy(object):
    """A compiled, digest-bound evidence-admission policy document."""

    def __init__(self, policy_id, scopes, default_level, digest, doc):
        self.policy_id = policy_id
        # scopes: list of (scope_pattern, level_rank, overrides_dict)
        self.scopes = list(scopes)
        self.default_level = default_level
        self.digest = digest
        self.doc = dict(doc)


def _norm_level(name, where):
    if not isinstance(name, str) or name not in _LEVEL_NAMES:
        _fail(POLICY_INVALID,
              "%s: level must be one of %s, got %r"
              % (where, sorted(_LEVEL_NAMES), name))
    return _LEVEL_NAMES[name]


def _validate_scope_entry(entry, idx):
    where = "scopes[%d]" % (idx,)
    if not isinstance(entry, dict):
        _fail(POLICY_INVALID, "%s must be a mapping" % (where,))
    pattern = entry.get("scope")
    if not isinstance(pattern, str) or not pattern:
        _fail(POLICY_INVALID,
              "%s needs a non-empty scope pattern" % (where,))
    level = _norm_level(entry.get("level"), where + ".level")
    overrides = entry.get("checks", {})
    if not isinstance(overrides, dict):
        _fail(POLICY_INVALID, "%s.checks must be a mapping" % (where,))
    norm_overrides = {}
    for check, lname in overrides.items():
        if check not in CHECKS:
            _fail(POLICY_INVALID,
                  "%s.checks: unknown check %r" % (where, check))
        orank = _norm_level(lname, "%s.checks[%r]" % (where, check))
        norm_overrides[check] = orank
    return (pattern, level, norm_overrides)


def _check_floor(scopes, default_level):
    """The integrity floor is non-overridable: no per-check override may
    lower a floor check below strict. The scope level itself is fine --
    the floor always RUNS at strict regardless of scope level (see
    :func:`_effective_level`); only an explicit override that moves a
    floor check is a compile-time refusal."""
    for pattern, level, overrides in scopes:
        for check in INTEGRITY_FLOOR:
            if check in overrides and overrides[check] < STRICT:
                _fail(POLICY_INVALID,
                      "integrity floor: check %r is lowered to %s at "
                      "scope %r; floor checks can never run below strict"
                      % (check, _LEVEL_BY_RANK[overrides[check]], pattern))


def compile_policy(doc):
    """Validate an admission-policy document and bind its digest.
    Every malformed document -- and every document that tries to move
    the integrity floor -- refuses LOUD."""
    if not isinstance(doc, dict):
        _fail(POLICY_INVALID, "policy document must be a mapping")
    if doc.get("format") != POLICY_FORMAT:
        _fail(POLICY_INVALID,
              "policy format must be %r" % (POLICY_FORMAT,))
    policy_id = doc.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        _fail(POLICY_INVALID, "policy needs a non-empty policy_id")
    raw_scopes = doc.get("scopes")
    if not isinstance(raw_scopes, list) or not raw_scopes:
        _fail(POLICY_INVALID,
              "policy needs a non-empty scopes list (a vacuous policy "
              "admits nothing and means nothing)")
    scopes = [_validate_scope_entry(e, i) for i, e in enumerate(raw_scopes)]
    default_level = None
    if "default_level" in doc:
        default_level = _norm_level(doc["default_level"], "default_level")
    _check_floor(scopes, default_level)
    digest = _digest(doc)
    return AdmissionPolicy(policy_id, scopes, default_level, digest,
                           dict(doc))


def _scope_matches(pattern, kind):
    """Exact match, or prefix match on ``prefix/`` boundaries."""
    if pattern == kind:
        return True
    return kind.startswith(pattern.rstrip("/") + "/")


def _find_scope(policy, kind):
    """Longest matching scope wins. Returns (pattern, level, overrides)
    or None when nothing matches and no default_level is declared."""
    best = None
    best_len = -1
    for pattern, level, overrides in policy.scopes:
        if _scope_matches(pattern, kind) and len(pattern) > best_len:
            best = (pattern, level, overrides)
            best_len = len(pattern)
    if best is not None:
        return best
    if policy.default_level is not None:
        return ("(default)", policy.default_level, {})
    return None


def _effective_level(check, scope_level, overrides):
    """The integrity floor always runs at strict, even under skip."""
    if check in INTEGRITY_FLOOR:
        return STRICT
    return overrides.get(check, scope_level)


# ---------------------------------------------------------------------------
# Pinning (the sandbox-layer precedent)
# ---------------------------------------------------------------------------

def pin_admission_policy(policy_id, digest, pinpath):
    """Pin a compiled policy digest. Additive: existing pins are kept."""
    pins = {}
    if os.path.exists(pinpath):
        with open(pinpath, encoding="utf-8") as fh:
            pins = json.load(fh)
    if not isinstance(pins, dict):
        _fail(POLICY_INVALID, "pin store is corrupt")
    pins[policy_id] = digest
    tmp = pinpath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(pins, fh, sort_keys=True)
    os.replace(tmp, pinpath)


def load_admission_pins(pinpath):
    with open(pinpath, encoding="utf-8") as fh:
        pins = json.load(fh)
    if not isinstance(pins, dict):
        _fail(POLICY_INVALID, "pin store is corrupt")
    return pins


def _check_policy_use(policy, pins):
    if pins is None:
        return
    pinned = pins.get(policy.policy_id)
    if pinned is None:
        _fail(POLICY_INVALID,
              "admission policy %r is not pinned" % (policy.policy_id,))
    # F351d: hmac.compare_digest with a non-str pinned digest raises a
    # raw TypeError. Refuse LOUD and coded before comparing.
    if not isinstance(pinned, str):
        _fail(POLICY_INVALID,
              "admission policy %r pin is not a digest string"
              % (policy.policy_id,))
    live = _digest(policy.doc)
    if not hmac.compare_digest(live, pinned):
        _fail(POLICY_INVALID,
              "admission policy %r drifted from its pin"
              % (policy.policy_id,))


# ---------------------------------------------------------------------------
# Check outcomes
# ---------------------------------------------------------------------------

def _check_evidence_shape(evidence):
    if not isinstance(evidence, dict):
        _fail(CHECK_FAILED, "evidence must be a mapping")
    kind = evidence.get("kind")
    if not isinstance(kind, str) or not kind:
        _fail(CHECK_FAILED, "evidence needs a non-empty kind")
    digest = evidence.get("artifact_digest")
    if not isinstance(digest, str) or not digest:
        _fail(CHECK_FAILED, "evidence needs an artifact_digest")
    return kind


def run_default_checks(evidence, builder_policy=None,
                       allow_unverified_materials=False):
    """Compute check outcomes with the real verifier seams for known
    evidence kinds. Returns a dict check_name -> bool. Unknown kinds
    return an empty dict -- the caller must supply outcomes for them.

    For the ``provenance`` kind with an ``envelope`` present, this runs
    :func:`gov.evidence_provenance.verify_provenance` and derives the
    ``provenance-present``, ``builder-allowlisted``, ``signature-valid``
    and ``digest-binds`` outcomes from it (a passing verification
    implies all four; a failure marks them failed with the verifier's
    code recorded)."""
    kind = evidence.get("kind") if isinstance(evidence, dict) else None
    outcomes = {}
    if kind == "provenance":
        envelope = evidence.get("envelope")
        try:
            if builder_policy is None:
                # No builder policy: we cannot verify allowlisting, so
                # every check that needs it fails closed.
                outcomes = {"provenance-present": False,
                            "builder-allowlisted": False,
                            "signature-valid": False,
                            "digest-binds": False}
            else:
                _prov.verify_provenance(
                    envelope, builder_policy,
                    allow_unverified_materials=allow_unverified_materials)
                claim = envelope.get("provenance") or {}
                binds = (claim.get("artifact", {}).get("digest")
                         == evidence.get("artifact_digest"))
                outcomes = {"provenance-present": True,
                            "builder-allowlisted": True,
                            "signature-valid": True,
                            "digest-binds": bool(binds)}
        except Exception:  # noqa: BLE001
            # The verifier refuses LOUD; here we translate to a failed
            # outcome so admission can refuse with ITS code. Fail
            # closed, never fail open.
            outcomes = {"provenance-present": False,
                        "builder-allowlisted": False,
                        "signature-valid": False,
                        "digest-binds": False}
    return outcomes


# ---------------------------------------------------------------------------
# The admission decision
# ---------------------------------------------------------------------------

def _decision(verdict, policy, scope_desc, level_rank, check_results,
              warnings, would_refuse_under=None, floor_failed=()):
    record = {
        "verdict": verdict,
        "policy_id": policy.policy_id,
        "scope": scope_desc,
        "level": _LEVEL_BY_RANK[level_rank],
        "check_results": dict(check_results),
        "warnings": list(warnings),
        "floor_failed": list(floor_failed),
    }
    if would_refuse_under is not None:
        record["would_refuse_under"] = would_refuse_under
    record["decision_digest"] = _digest(
        {k: v for k, v in record.items() if k != "decision_digest"})
    return record


#: F349: in-process registry of refuse decisions produced by admit().
#: admit() registers a private copy of every refuse decision at raise
#: time; admit_at_risk only accepts decisions found here, so a
#: caller-synthesized dict can never reach the floor gate. The registry
#: copy (not the error-carried record) is authoritative, so post-hoc
#: mutation of ``err.decision`` does not move the gate. Bounded to the
#: most recent entries.
_REFUSE_REGISTRY = {}
_REFUSE_REGISTRY_MAX = 1024


def _register_refuse(record):
    digest = record.get("decision_digest")
    if not isinstance(digest, str) or not digest:
        return
    _REFUSE_REGISTRY[digest] = copy.deepcopy(record)
    while len(_REFUSE_REGISTRY) > _REFUSE_REGISTRY_MAX:
        _REFUSE_REGISTRY.pop(next(iter(_REFUSE_REGISTRY)))


def _refuse_decision(code, policy, scope_desc, scope_level, results,
                     warnings, floor_failed, message):
    """Build a REFUSE decision, register it in-process, and raise it on
    the AdmissionError. The decision rides on the exception
    (``err.decision``) so admit_at_risk consumes admit()'s own record --
    the floor-failed state is mechanism-bound, never caller input."""
    record = _decision("REFUSE", policy, scope_desc, scope_level, results,
                       warnings, floor_failed=floor_failed)
    _register_refuse(record)
    err = AdmissionError(message, code=code)
    err.decision = record
    raise err


def admit(evidence, policy, check_outcomes, pins=None):
    """Apply the admission policy to one evidence record.

    ``check_outcomes`` maps check names to booleans, computed by the
    caller at the seam (see :func:`run_default_checks`). Returns an
    admission decision record (verdict ADMIT, ADMIT-AUDIT, or REFUSE --
    REFUSE raises :class:`AdmissionError` instead of returning).
    """
    if not isinstance(check_outcomes, dict):
        _fail(CHECK_FAILED, "check_outcomes must be a mapping")
    # F348: the floor is enforced independently of the mutable CHECKS
    # registry name. If the registry no longer carries every floor
    # check (deleted entries, or the module attribute rebound), fail
    # closed instead of silently running without the floor.
    missing = [c for c in INTEGRITY_FLOOR if c not in CHECKS]
    if missing:
        _fail(CHECK_FAILED,
              "admission check registry is missing floor check(s) %r: "
              "refusing rather than admitting without the floor"
              % (sorted(missing),))
    _check_policy_use(policy, pins)
    kind = _check_evidence_shape(evidence)
    found = _find_scope(policy, kind)
    if found is None:
        _fail(NO_APPLICABLE_POLICY,
              "evidence kind %r matches no policy scope and no "
              "default_level is declared: refused, never defaulted"
              % (kind,))
    scope_desc, scope_level, overrides = found

    # Determine which checks run at this scope: every check whose
    # effective level is above SKIP, plus the floor (always).
    results = {}
    failures = []
    strict_failures = []
    floor_failed = []
    for check in sorted(CHECKS):
        level = _effective_level(check, scope_level, overrides)
        if level == SKIP:
            continue
        if check not in check_outcomes:
            _fail(CHECK_FAILED,
                  "no outcome supplied for check %r (scope %r): "
                  "cannot run the check, refusing"
                  % (check, scope_desc))
        passed = bool(check_outcomes[check])
        results[check] = passed
        if not passed:
            if check in INTEGRITY_FLOOR:
                floor_failed.append(check)
            elif level == STRICT:
                # A per-check override raised to strict.
                strict_failures.append(check)
            else:
                failures.append(check)

    if floor_failed:
        _refuse_decision(
            FLOOR_VIOLATED, policy, scope_desc, scope_level, results, [],
            floor_failed,
            "integrity floor check(s) %r failed for kind %r: refused; "
            "the floor is never overridable"
            % (sorted(floor_failed), kind))

    if strict_failures:
        _refuse_decision(
            REFUSED, policy, scope_desc, scope_level, results, [],
            floor_failed,
            "evidence kind %r refused: check(s) %r failed at their "
            "effective strict level"
            % (kind, sorted(strict_failures)))

    if not failures:
        return _decision("ADMIT", policy, scope_desc, scope_level,
                         results, [], floor_failed=floor_failed)

    if scope_level == PERMISSIVE:
        # Permissive admits on non-floor failures, but the warnings are
        # recorded on the decision -- never silent.
        warnings = ["check %r failed under permissive level"
                    % (c,) for c in failures]
        return _decision("ADMIT", policy, scope_desc, scope_level,
                         results, warnings, floor_failed=floor_failed)

    if scope_level == AUDIT:
        # Audit admits but records the would-refuse verdict -- the
        # prospective evidence the rollout needs.
        return _decision("ADMIT-AUDIT", policy, scope_desc, scope_level,
                         results, [], would_refuse_under="strict",
                         floor_failed=floor_failed)

    # STRICT (and anything else): refuse LOUD.
    _refuse_decision(
        REFUSED, policy, scope_desc, scope_level, results, [],
        floor_failed,
        "evidence kind %r refused at strict: failed check(s) %r"
        % (kind, sorted(failures)))


def admit_at_risk(admission_error, exception_store, now=None):
    """Accept a REFUSE decision at operator risk through a LIVE governed
    exception (check ``SAS_ADMISSION_ACCEPT_RISK``, scope
    ``("policy", policy_id)``). The decision record is UNCHANGED; the
    returned record carries the exception digest (SKIPPED-shaped, never
    an upgrade).

    F349: the refusal must be the :class:`AdmissionError` that
    :func:`admit` itself raised. Its decision record was registered
    in-process at raise time, and the floor gate reads the REGISTERED
    record -- never any caller-supplied field. A synthesized dict, an
    error without a decision, or a decision admit() never produced all
    refuse LOUD with ``admission-exception-refused``. Post-hoc mutation
    of ``err.decision`` does not move the gate (the registry holds a
    private copy).

    A refusal caused by the integrity floor can NEVER be accepted at
    risk -- it refuses LOUD with ``admission-exception-refused``.
    """
    if not isinstance(admission_error, AdmissionError):
        _fail(EXCEPTION_REFUSED,
              "admit_at_risk requires the AdmissionError raised by "
              "admit(); a refusal decision cannot be synthesized")
    decision = getattr(admission_error, "decision", None)
    if not isinstance(decision, dict) or decision.get("verdict") != "REFUSE":
        _fail(EXCEPTION_REFUSED,
              "admit_at_risk only applies to REFUSE decisions raised "
              "by admit()")
    digest = decision.get("decision_digest")
    registered = (_REFUSE_REGISTRY.get(digest)
                  if isinstance(digest, str) else None)
    if not isinstance(registered, dict):
        _fail(EXCEPTION_REFUSED,
              "this refusal decision was not produced by this process's "
              "admit(): cannot accept it at risk")
    if registered.get("floor_failed"):
        _fail(EXCEPTION_REFUSED,
              "the integrity floor failed (%r): no exception can ever "
              "admit evidence past the floor"
              % (registered["floor_failed"],))
    policy_id = registered.get("policy_id")
    if not policy_id:
        _fail(EXCEPTION_REFUSED,
              "refuse_decision carries no policy_id")
    if exception_store is None or not hasattr(exception_store, "evaluate"):
        _fail(EXCEPTION_REFUSED,
              "exception_store must provide evaluate()")
    result = exception_store.evaluate(
        ACCEPT_RISK_CHECK_ID, ("policy", policy_id),
        lambda: False, now=now)
    if not isinstance(result, dict) or result.get("status") != "SKIPPED":
        _fail(EXCEPTION_REFUSED,
              "no live exception covers admission policy %r"
              % (policy_id,))
    record = {
        "verdict": "ADMIT-AT-RISK",
        "policy_id": policy_id,
        "refused_decision_digest": digest,
        "exception_digest": result["exception_digest"],
        "floor_failed": [],
    }
    record["decision_digest"] = _digest(
        {k: v for k, v in record.items() if k != "decision_digest"})
    return record
