"""Declarative controls-as-code profiles (wave-257 lane 2).

inspec/inspec ADAPT -- the declarative controls DSL pattern (named
control + impact + title + desc + executable assertion producing
structured results that map to controls). Pattern only; no InSpec
code, and never the >=5.0 packaged binary (Chef EULA trap).

A profile is a plain Python dict (stdlib-only: no YAML)::

    {
        "id": "PROF-001",
        "title": "Permit lifecycle profile",
        "description": "...",            # optional
        "check_version": "1",            # optional, default "1"
        "controls": [
            {"id": "C1", "impact": 0.9, "title": "...",
             "desc": "...", "check": <callable>},
        ],
    }

Checks are callables supplied by the profile author AT RUNTIME.
Serialized / call-by-name checks (a string naming a check) are
refused: there is no eval of stored strings anywhere in this module.

Fail-closed evaluation:
  - validate_profile() refuses malformed profiles BEFORE any check
    runs: non-dict shapes, unknown top-level/control keys (a typo
    must never silently change what gets checked), empty control
    lists (no vacuous profile), duplicate control ids, impact
    outside [0.0, 1.0] or non-numeric (bool is not a number),
    non-callable checks.
  - run_profile() evaluates each check against its OWN pristine
    per-control deep copy of the evidence snapshot (F225 lesson:
    checks are isolated from each other; F212 lesson: caller data
    is never mutated).
    A check returning falsy becomes a FAIL result; a check raising
    becomes an ERROR result with exception_info -- never a crash of
    the whole evaluation. Every control yields exactly one result.
  - Impact -> severity: >= 0.7 high, >= 0.4 medium, < 0.4 low.
    The severity is machine-coded per control result.

Composition with the compliance emitter:
  - emit_profile_results(profile_results, ...) builds a
    compliance-emitter control source: passing controls map to a
    control-profile-check-passed code mapping; each failing/errored
    control maps to a finding (ref derived deterministically from
    the profile digest + control id) with the impact-weighted
    severity in the rationale. The emitter is UNTOUCHED.
  - emit_profile_results re-validates the caller-supplied
    profile_results fail-closed before use: five top-level keys, and
    (F227) every per-result record must be a dict carrying
    control_id, status, reason, impact, severity, digest -- a
    malformed record is refused with control-profile-malformed, so
    no raw KeyError/TypeError escapes the seam.
  - The default findings index is built from this run's own
    verdicts (fail/error -> "open"); a deployment-supplied index is
    merged over it -- the deployment owns the index (the emitter's
    stated honest boundary) and must list the generated refs itself
    if it replaces the default.
  - quality_gate=True runs gov/evidence_quality.evaluate() first
    and refuses with control-profile-gate-failed (naming the failed
    expectations) before the emitter ever runs. F226: an
    EvidenceQualityError raised inside evaluate() (e.g.
    evidence-quality-empty-evidence) is wrapped -- only
    ControlProfileError escapes this seam, never the raw
    EvidenceQualityError.

Determinism + honest boundaries:
  - profile_digest() is sha256 over the canonical declared profile:
    ids, impacts, titles, descriptions, and per-check
    (qualname + check_version). It does NOT bind the check
    bytecode: a deployment that swaps a function body behind the
    same name silently breaks the binding. This residual is pinned
    by the battery (p_check_swap_behind_same_name_undetected) and
    carried in the emitter rationale -- never hidden.

Stdlib only. No enforcement path is touched.
"""

import copy
import hashlib
import json
from datetime import datetime, timezone

from gov import compliance_emitter
from gov import evidence_quality

__all__ = [
    "ControlProfileError",
    "emit_profile_results",
    "profile_digest",
    "run_profile",
    "severity_for_impact",
    "validate_profile",
]

MALFORMED = "control-profile-malformed"
DUPLICATE_CONTROL = "control-profile-duplicate-control-id"
EMPTY = "control-profile-empty"
EVIDENCE_MALFORMED = "control-profile-evidence-malformed"
GATE_FAILED = "control-profile-gate-failed"
INVALID_IMPACT = "control-profile-invalid-impact"
NON_CALLABLE_CHECK = "control-profile-non-callable-check"
UNKNOWN_KEY = "control-profile-unknown-key"
CHECK_PASSED = "control-profile-check-passed"

_EXPORT_MODULE = "gov/control_profiles.py"

_MAX_ID = 64
_MAX_TITLE = 200
_MAX_TEXT = 2000
_REPR_LIMIT = 500

_TOP_LEVEL_KEYS = ("id", "title", "description", "check_version",
                   "controls")
_CONTROL_KEYS = ("id", "impact", "title", "desc", "check")
# Per-result keys emit_profile_results indexes (F227). Every record
# in a run_profile() result carries exactly these (plus check,
# check_version, exception_info, which the emitter never reads); the
# seam re-validates them fail-closed before use so a malformed
# caller-built record is refused with control-profile-malformed
# instead of escaping a raw KeyError.
_RESULT_KEYS = ("control_id", "status", "reason", "impact",
                "severity", "digest")


class ControlProfileError(Exception):
    """Fail-closed control-profile refusal carrying a taxonomy code."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise ControlProfileError("%s: %s" % (code, detail), code)


def _check_str(value, what, limit=_MAX_TITLE, code=MALFORMED):
    if not isinstance(value, str) or not value.strip() \
            or len(value) > limit:
        _refuse(code, "%s must be a non-empty string <= %d chars"
                % (what, limit))
    return value


def _check_id(value, what):
    return _check_str(value, what, limit=_MAX_ID)


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def severity_for_impact(impact):
    """Impact -> severity: >= 0.7 high, >= 0.4 medium, else low."""
    if impact >= 0.7:
        return "high"
    if impact >= 0.4:
        return "medium"
    return "low"


def _validate_control(control, seen_ids):
    if not isinstance(control, dict):
        _refuse(MALFORMED, "control must be a dict")
    unknown = set(control) - set(_CONTROL_KEYS)
    if unknown:
        _refuse(UNKNOWN_KEY,
                "control has unknown keys %r (want %r)"
                % (sorted(unknown), list(_CONTROL_KEYS)))
    cid = _check_id(control.get("id"), "control id")
    if cid in seen_ids:
        _refuse(DUPLICATE_CONTROL,
                "duplicate control id %r" % (cid,))
    seen_ids.add(cid)
    impact = control.get("impact")
    if isinstance(impact, bool) or not isinstance(impact, (int, float)):
        _refuse(INVALID_IMPACT,
                "control %r impact must be a number in [0.0, 1.0], "
                "got %r" % (cid, impact))
    # NaN / infinities are not impact values.
    if not 0.0 <= impact <= 1.0 or impact != impact:
        _refuse(INVALID_IMPACT,
                "control %r impact %r is outside [0.0, 1.0]"
                % (cid, impact))
    title = _check_str(control.get("title"), "control %r title" % cid)
    desc = _check_str(control.get("desc"), "control %r desc" % cid,
                      limit=_MAX_TEXT)
    check = control.get("check")
    if isinstance(check, str):
        _refuse(NON_CALLABLE_CHECK,
                "control %r check is a string (serialized/call-by-name "
                "checks are refused; checks must be callables supplied "
                "at runtime -- no eval of stored strings)" % (cid,))
    if not callable(check):
        _refuse(NON_CALLABLE_CHECK,
                "control %r check is not callable (got %r)"
                % (cid, type(check).__name__))
    return {
        "id": cid,
        "impact": float(impact),
        "title": title,
        "desc": desc,
        "check": check,
    }


def validate_profile(profile):
    """Validate a control profile; return a normalized copy.

    Checks are kept by reference (callables cannot be deep-copied);
    everything else is copied. Raises ControlProfileError
    (fail-closed) on any violation -- no check runs until the whole
    profile validates.
    """
    if not isinstance(profile, dict):
        _refuse(MALFORMED, "profile must be a dict")
    unknown = set(profile) - set(_TOP_LEVEL_KEYS)
    if unknown:
        _refuse(UNKNOWN_KEY,
                "profile has unknown keys %r (want %r)"
                % (sorted(unknown), list(_TOP_LEVEL_KEYS)))
    pid = _check_id(profile.get("id"), "profile id")
    title = _check_str(profile.get("title"), "profile title")
    description = profile.get("description", "")
    if description and not isinstance(description, str):
        _refuse(MALFORMED, "profile description must be a string")
    if description and len(description) > _MAX_TEXT:
        _refuse(MALFORMED, "profile description must be <= %d chars"
                % (_MAX_TEXT,))
    check_version = profile.get("check_version", "1")
    if not isinstance(check_version, str) or not check_version \
            or len(check_version) > _MAX_ID:
        _refuse(MALFORMED,
                "profile check_version must be a non-empty string "
                "<= %d chars" % (_MAX_ID,))
    controls = profile.get("controls")
    if not isinstance(controls, list):
        _refuse(MALFORMED, "profile controls must be a list")
    if not controls:
        _refuse(EMPTY,
                "profile %r has no controls; a vacuous profile "
                "must never pass" % (pid,))
    seen_ids = set()
    normalized_controls = [_validate_control(c, seen_ids)
                           for c in controls]
    return {
        "id": pid,
        "title": title,
        "description": description,
        "check_version": check_version,
        "controls": normalized_controls,
    }


def _check_identity(control):
    """Declared check identity bound into the digest: qualname +
    the profile's declared check_version (NOT the bytecode -- see
    the module's honest-boundary note)."""
    check = control["check"]
    return getattr(check, "__qualname__",
                   type(check).__name__)


def _declared_profile(profile):
    """The declared profile the digest binds: everything except the
    live check objects."""
    return {
        "id": profile["id"],
        "title": profile["title"],
        "description": profile["description"],
        "check_version": profile["check_version"],
        "controls": [
            {
                "id": c["id"],
                "impact": c["impact"],
                "title": c["title"],
                "desc": c["desc"],
                "check": _check_identity(c),
                "check_version": profile["check_version"],
            }
            for c in profile["controls"]
        ],
    }


def profile_digest(profile):
    """sha256 hex over the canonical DECLARED profile.

    Binds control ids, impacts, and check (qualname + declared
    version). Honest boundary: NOT the check bytecode -- a swapped
    function body behind the same name is not detected (pinned by
    the battery).
    """
    normalized = validate_profile(profile)
    return hashlib.sha256(
        _canonical_bytes(_declared_profile(normalized))).hexdigest()


def _control_digest(profile_digest_hex, control_id, status, reason):
    return hashlib.sha256(_canonical_bytes({
        "profile_digest": profile_digest_hex,
        "control_id": control_id,
        "status": status,
        "reason": reason,
    })).hexdigest()


def _interpret_check_result(value):
    """Checks return truthy/falsy, or (truthy/falsy, reason-str).

    A (value, reason) pair whose reason is not a string is check
    misbehavior: refused fail-closed so an intended failure can never
    silently record as a pass.
    """
    if isinstance(value, (tuple, list)) and len(value) == 2:
        if not isinstance(value[1], str):
            _refuse(MALFORMED,
                    "check returned a (value, reason) pair with a "
                    "non-string reason (%r); reason must be a string"
                    % (type(value[1]).__name__,))
        return bool(value[0]), value[1][: _REPR_LIMIT]
    return bool(value), None


def run_profile(profile, evidence_snapshot):
    """Evaluate every control against the evidence snapshot.

    Returns the profile result record: success, per-control results
    (exactly one per control, in order), statistics, meta.
    Fail-closed: a raising check becomes an ERROR result with
    exception_info -- never a crash. Caller data is never mutated
    (F212); each control's check receives a pristine per-control
    deep copy of the snapshot (copy.deepcopy: unbounded depth,
    cycle-safe via its memo dict), so a mutating check cannot
    poison later controls' evidence views (F225).
    """
    normalized = validate_profile(profile)
    if not isinstance(evidence_snapshot, dict):
        _refuse(EVIDENCE_MALFORMED,
                "evidence snapshot must be a dict")
    try:
        pristine = copy.deepcopy(evidence_snapshot)
    except Exception as exc:
        _refuse(EVIDENCE_MALFORMED,
                "evidence snapshot cannot be safely copied (%s: %s); "
                "refusing rather than evaluating over caller-owned "
                "mutable state" % (type(exc).__name__, str(exc)
                                   [: _REPR_LIMIT]))
    digest = hashlib.sha256(
        _canonical_bytes(_declared_profile(normalized))).hexdigest()
    results = []
    for control in normalized["controls"]:
        cid = control["id"]
        severity = severity_for_impact(control["impact"])
        try:
            # F225: each control evaluates against its OWN pristine
            # per-control deep copy of the snapshot, so a check that
            # mutates its view cannot poison later controls' views.
            # Bound: copy.deepcopy -- unbounded depth, cycle-safe via
            # its memo dict; the up-front copy above already proved
            # the snapshot copyable, so this only fails on
            # environmental (e.g. memory) faults, recorded as an
            # ERROR result for this control -- never a crash.
            view = copy.deepcopy(pristine)
            raw = control["check"](view)
            ok, reason = _interpret_check_result(raw)
            if ok:
                status = "pass"
                reason = reason or "check passed"
            else:
                status = "fail"
                reason = reason or "check returned a falsy value"
            record = {
                "control_id": cid,
                "impact": control["impact"],
                "severity": severity,
                "check": _check_identity(control),
                "check_version": normalized["check_version"],
                "status": status,
                "reason": reason,
                "exception_info": None,
                "digest": _control_digest(digest, cid, status,
                                          reason),
            }
        except Exception as exc:  # fail-closed: error, never crash
            reason = "check raised %s: %s" % (
                type(exc).__name__, str(exc)[: _REPR_LIMIT])
            record = {
                "control_id": cid,
                "impact": control["impact"],
                "severity": severity,
                "check": _check_identity(control),
                "check_version": normalized["check_version"],
                "status": "error",
                "reason": reason,
                "exception_info": {
                    "raised": type(exc).__name__,
                    "message": str(exc)[: _REPR_LIMIT],
                },
                "digest": _control_digest(digest, cid, "error",
                                          reason),
            }
        results.append(record)
    passed = sum(1 for r in results if r["status"] == "pass")
    total = len(results)
    return {
        "profile_id": normalized["id"],
        "profile_title": normalized["title"],
        "profile_digest": digest,
        "success": passed == total,
        "results": results,
        "statistics": {
            "evaluated_controls": total,
            "passed_controls": passed,
            "failed_controls": sum(
                1 for r in results if r["status"] == "fail"),
            "errored_controls": sum(
                1 for r in results if r["status"] == "error"),
            "success_percent": (100.0 * passed / total
                                if total else 0.0),
        },
        "meta": {
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "module": _EXPORT_MODULE,
        },
    }


def _finding_ref(profile_results, control_id):
    """Deterministic finding ref for a failing control (<= 64 chars,
    the emitter's finding-id bound). The full control id rides in
    the rationale."""
    raw = hashlib.sha256(_canonical_bytes({
        "profile_digest": profile_results["profile_digest"],
        "control_id": control_id,
    })).hexdigest()[:16]
    return "profile-finding-%s" % (raw,)


def _default_findings_index(profile_results):
    index = {}
    for r in profile_results["results"]:
        if r["status"] in ("fail", "error"):
            index[_finding_ref(profile_results,
                               r["control_id"])] = "open"
    return index


def emit_profile_results(profile_results, fmt="json", findings=None,
                         quality_gate=False, quality_expectations=None,
                         quality_evidence=None):
    """Emit a compliance-emitter artifact for a profile result.

    Composition: builds a compliance-emitter control source -- one
    control-profile-check-passed code mapping when any control
    passed, plus one finding mapping per failing/errored control
    (impact-weighted severity in the rationale) -- and delegates to
    gov.compliance_emitter.emit(). The emitter is not modified.

    With quality_gate=True, gov/evidence_quality.evaluate() runs
    first and refuses with control-profile-gate-failed (naming the
    failed expectations) before the emitter ever runs. F226 seam
    contract: an EvidenceQualityError raised by evaluate() is wrapped
    via _refuse(GATE_FAILED, ...) so only ControlProfileError
    escapes -- never the raw EvidenceQualityError.

    F227 seam contract: per-result records are re-validated
    fail-closed before any per-result key is used -- every record
    must be a dict carrying control_id, status, reason, impact,
    severity, digest; a malformed caller-built record is refused
    with control-profile-malformed (no new taxonomy code) so no raw
    KeyError/TypeError escapes this seam.

    profile_results must be the dict returned by run_profile() (its
    shape is re-validated fail-closed here).
    """
    if not isinstance(profile_results, dict):
        _refuse(MALFORMED,
                "profile_results must be a run_profile() result dict")
    for key in ("profile_id", "profile_title", "profile_digest",
                "success", "results"):
        if key not in profile_results:
            _refuse(MALFORMED,
                    "profile_results is missing key %r" % (key,))
    if quality_gate:
        if quality_expectations is None or quality_evidence is None:
            _refuse(MALFORMED,
                    "quality_gate=True requires quality_expectations "
                    "and quality_evidence (a vacuous gate must never "
                    "pass)")
        try:
            report = evidence_quality.evaluate(quality_expectations,
                                               quality_evidence)
        except evidence_quality.EvidenceQualityError as exc:
            _refuse(GATE_FAILED,
                    "quality gate could not be evaluated (%s: %s); "
                    "refusing emission rather than emitting past the "
                    "gate" % (exc.code, str(exc)[: _REPR_LIMIT]))
        if not report["success"]:
            failed = [r["expectation_type"]
                      for r in report["results"] if not r["success"]]
            _refuse(GATE_FAILED,
                    "quality gate refused emission; failed "
                    "expectations: %s" % (", ".join(failed),))
    results = profile_results["results"]
    # F227 seam contract: per-result records are re-validated
    # fail-closed BEFORE any per-result key is indexed. run_profile()
    # always emits dict records carrying _RESULT_KEYS; a caller-built
    # record that is not a dict or is missing any of these keys is
    # refused with control-profile-malformed -- no raw KeyError or
    # TypeError escapes this seam. The check is status-agnostic (it
    # runs before the pass/fail split) so the pass-mapping path, the
    # findings-mapping loop, and _default_findings_index() all see
    # only validated records.
    if not isinstance(results, list):
        _refuse(MALFORMED,
                "profile_results['results'] must be a list of "
                "result records")
    for i, r in enumerate(results):
        if not isinstance(r, dict):
            _refuse(MALFORMED,
                    "profile_results['results'][%d] must be a "
                    "result record dict" % (i,))
        for key in _RESULT_KEYS:
            if key not in r:
                _refuse(MALFORMED,
                        "profile_results['results'][%d] is missing "
                        "key %r" % (i, key))
    passed = [r for r in results if r["status"] == "pass"]
    failed = [r for r in results if r["status"] in ("fail", "error")]
    mappings = []
    if passed:
        mappings.append({
            "kind": "code",
            "ref": CHECK_PASSED,
            "rationale": (
                "%d of %d controls passed their checks; profile "
                "digest %s. Checks ran as the declared callables: "
                "the digest binds check qualname + declared "
                "version, not check bytecode -- a swapped function "
                "body behind the same name is not detected."
                % (len(passed), len(results),
                   profile_results["profile_digest"])),
        })
    for r in failed:
        mappings.append({
            "kind": "finding",
            "ref": _finding_ref(profile_results, r["control_id"]),
            "rationale": (
                "control %s %s: %s; impact %.2f -> severity %s; "
                "control digest %s."
                % (r["control_id"], r["status"], r["reason"],
                   r["impact"], r["severity"], r["digest"])),
        })
    if findings is None:
        index = _default_findings_index(profile_results)
    else:
        if not isinstance(findings, dict):
            _refuse(MALFORMED,
                    "findings index must be a dict of "
                    "finding_id -> open|closed")
        index = dict(_default_findings_index(profile_results))
        index.update(findings)
    source = {
        "id": profile_results["profile_id"],
        "title": "Control profile results: %s"
                 % (profile_results["profile_title"],),
        "description": (
            "Machine-evaluated control profile. success=%s, %d of "
            "%d controls passed; profile digest %s. Emission proves "
            "the profile ran over the supplied evidence snapshot; it "
            "does not re-verify that snapshot, and the default "
            "findings index reflects this run's own verdicts, not "
            "authenticated state."
            % (profile_results["success"], len(passed),
               len(results), profile_results["profile_digest"])),
        "mappings": mappings,
    }
    return compliance_emitter.emit(source, fmt, findings=index)
