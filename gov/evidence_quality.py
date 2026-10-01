"""Declarative evidence-quality expectations (wave-256 lane 3).

great-expectations ADAPT -- the Expectation/result-shape pattern
(named declarative assertion evaluated to a typed result record that
doubles as an audit artifact). Pattern only; no great-expectations
code and none of its pandas/Spark machinery.

The evidence pipeline (collection -> signing -> bundling) gets a
machine-checkable quality vocabulary evaluated between stages. The
compliance emitter (wave-254) refuses unlinked claims and dangling
refs but does NOT re-verify the evidence it runs over (its stated
honest boundary); these expectations are the structural-quality
half an auditor can evaluate independently.

Closed expectation vocabulary:
  - expect_evidence_monotonic: sequence numbers strictly increasing.
  - expect_chain_intact: hash chain verifies (digest recomputation +
    prev linkage; genesis prev is None/absent).
  - expect_bundle_complete: every artifact_ref resolves in the
    supplied artifact store.
  - expect_fields_present: every item carries all required fields.
  - expect_timestamps_ordered: timestamps non-decreasing.

Fail-closed evaluation:
  - Unknown expectation_type -> evidence-quality-unknown-expectation
    (refusal, never a silent skip).
  - Malformed expectation shape/kwargs -> evidence-quality-malformed.
  - Malformed evidence shape -> evidence-quality-evidence-malformed.
  - Empty evidence -> evidence-quality-empty-evidence (refusal).
    This is the dual of the empty-expectation rule: a vacuous gate
    must never pass, on either axis.
  - An empty expectation list is refused: a vacuous gate must never
    pass.
  - An internal evaluator error on one expectation becomes a FAILED
    result with exception_info -- never a silent pass, never a
    whole-batch crash. The gate then refuses (fail-closed).
  - F220/F221: nesting depth is bounded iteratively (200, the shared
    F218/F219 contract) BEFORE any deepcopy, and every deepcopy is
    guarded -- raw TypeError/RecursionError from hostile caller
    objects becomes a machine-coded refusal, never a raw escape.

Design decision (F222): empty evidence is REFUSED, not scored as
per-expectation FAILED results. The finding allowed either; refusal
was chosen because (a) it is the same anti-vacuity principle the
module already applies to empty expectation lists, (b) "no evidence
presented" is a pipeline-outage signal, a distinct and louder state
than "evidence checked and failed", and (c) FAILED results with
zero items evaluated could be misread as benign. An auditor seeing
evidence-quality-empty-evidence knows the pipeline dropped
everything; an auditor seeing FAILED results knows checks ran and
found problems.

Composition with the compliance emitter:
  - emit_with_quality_gate(source, fmt, expectations, evidence, ...)
    runs evaluate() first and refuses with
    evidence-quality-gate-failed (naming the failed expectations)
    when any expectation fails; on success it delegates to
    gov.compliance_emitter.emit(). The emitter itself is untouched.

Immutability: evaluate() deep-copies caller inputs; a caller's
expectations/evidence can never be mutated through this module
(F212 lesson).

Stdlib only. No enforcement path is touched.
"""

import copy
import hashlib
import json
from datetime import datetime, timezone

from gov import compliance_emitter

__all__ = [
    "EXPECTATION_TYPES",
    "EvidenceQualityError",
    "emit_with_quality_gate",
    "evaluate",
    "validate_expectation",
]

EXPECTATION_TYPES = (
    "expect_evidence_monotonic",
    "expect_chain_intact",
    "expect_bundle_complete",
    "expect_fields_present",
    "expect_timestamps_ordered",
)

MALFORMED = "evidence-quality-malformed"
EVIDENCE_MALFORMED = "evidence-quality-evidence-malformed"
EMPTY_EVIDENCE = "evidence-quality-empty-evidence"
UNKNOWN_EXPECTATION = "evidence-quality-unknown-expectation"
GATE_FAILED = "evidence-quality-gate-failed"

_EXPORT_MODULE = "gov/evidence_quality.py"


# ---------------------------------------------------------------------------
# Nesting-depth and deepcopy guards (F220/F221)
# ---------------------------------------------------------------------------

# Real evidence items and expectation metadata are flat (depth < 10 in
# the existing suites); nothing legitimate approaches this bound. One
# shared contract across seams: F218 (permit journal), F219
# (approval policy), F220/F221 (this module).
_MAX_NESTING_DEPTH = 200


def _nesting_depth(obj):
    """Iterative nesting depth of dict/list/tuple containers.

    Never recurses (an explicit stack), so a hostile deeply-nested
    input cannot blow the interpreter stack here. Cycle-safe via a
    seen-set: a cyclic input is reported at its first-repeat depth
    and is refused by the caller's bound check.
    """
    max_depth = 0
    seen = set()
    stack = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if depth > max_depth:
            max_depth = depth
        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, (list, tuple)):
            children = current
        else:
            continue
        for child in children:
            if isinstance(child, (dict, list, tuple)):
                stack.append((child, depth + 1))
    return max_depth


def _check_depth(obj, code, what):
    """Fail closed before any deepcopy (F221): deepcopy recurses, so
    the bound must be enforced on the caller's object first."""
    if _nesting_depth(obj) > _MAX_NESTING_DEPTH:
        _refuse(code, "%s nesting depth exceeds the %d bound"
                % (what, _MAX_NESTING_DEPTH))


def _safe_deepcopy(obj, code, what):
    """Deep-copy caller input, mapping raw stdlib failures to machine
    codes.

    F220: deepcopy-hostile caller objects (e.g. threading.Lock)
    escape raw TypeError from copy.deepcopy; the machine-code
    contract requires an evidence-quality-* refusal instead.
    F221: the defensive except RecursionError (the iterative depth
    bound above is the primary defense).
    F229: a hostile __deepcopy__ may raise ANY exception
    (RuntimeError, KeyError, OSError, custom Exception subclasses);
    the trailing except Exception maps every remaining case to the
    caller's machine code. Except Exception catches nothing in
    BaseException, so KeyboardInterrupt and SystemExit still
    propagate raw, as required.
    """
    try:
        return copy.deepcopy(obj)
    except RecursionError:
        _refuse(code, "%s too deeply nested for a safe copy" % (what,))
    except (TypeError, ValueError, AttributeError, copy.Error):
        _refuse(code, "%s is not a copyable plain-data shape"
                % (what,))
    except Exception:
        # F229: map every remaining hostile exception to the EXISTING
        # machine code (no new codes), following the F220 mapping
        # convention above. _refuse() raises EvidenceQualityError
        # (an Exception), but it runs in the except arm, not inside
        # the try, so nothing is masked.
        _refuse(code, "%s is not a copyable plain-data shape"
                % (what,))


class EvidenceQualityError(Exception):
    """Fail-closed evidence-quality refusal carrying a taxonomy code."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise EvidenceQualityError("%s: %s" % (code, detail), code)


def _check_str(value, what, code=MALFORMED):
    if not isinstance(value, str) or not value:
        _refuse(code, "%s must be a non-empty string" % (what,))
    return value


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Expectation validation (fail-closed, fail-fast)
# ---------------------------------------------------------------------------

def _kw_str(kwargs, name, default, raw):
    value = kwargs.get(name, default)
    if not isinstance(value, str) or not value:
        _refuse(MALFORMED,
                "%s kwarg %r must be a non-empty string" % (raw, name))
    return value


def _kw_bool(kwargs, name, default, raw):
    value = kwargs.get(name, default)
    if not isinstance(value, bool):
        _refuse(MALFORMED,
                "%s kwarg %r must be a bool" % (raw, name))
    return value


def _normalize_kwargs(exp_type, kwargs):
    """Validate kwargs against the closed per-type schema; apply
    defaults. Unknown kwarg names are refused: a typo must never
    silently change what gets checked."""
    if not isinstance(kwargs, dict):
        _refuse(MALFORMED, "expectation kwargs must be a dict")
    if exp_type == "expect_evidence_monotonic":
        allowed = {"sequence_field", "strict"}
        unknown = set(kwargs) - allowed
        if unknown:
            _refuse(MALFORMED,
                    "expect_evidence_monotonic: unknown kwargs %r"
                    % (sorted(unknown),))
        return {
            "sequence_field": _kw_str(
                kwargs, "sequence_field", "seq", exp_type),
            "strict": _kw_bool(kwargs, "strict", True, exp_type),
        }
    if exp_type == "expect_chain_intact":
        allowed = {"digest_field", "prev_field", "body_fields"}
        unknown = set(kwargs) - allowed
        if unknown:
            _refuse(MALFORMED,
                    "expect_chain_intact: unknown kwargs %r"
                    % (sorted(unknown),))
        body_fields = kwargs.get("body_fields")
        if body_fields is not None:
            if not isinstance(body_fields, list) or not body_fields \
                    or not all(isinstance(f, str) and f
                               for f in body_fields):
                _refuse(MALFORMED,
                        "expect_chain_intact kwarg 'body_fields' must "
                        "be a non-empty list of strings or omitted")
            body_fields = list(body_fields)
        return {
            "digest_field": _kw_str(
                kwargs, "digest_field", "digest", exp_type),
            "prev_field": _kw_str(
                kwargs, "prev_field", "prev_digest", exp_type),
            "body_fields": body_fields,
        }
    if exp_type == "expect_bundle_complete":
        allowed = {"items_field", "ref_field", "artifacts"}
        unknown = set(kwargs) - allowed
        if unknown:
            _refuse(MALFORMED,
                    "expect_bundle_complete: unknown kwargs %r"
                    % (sorted(unknown),))
        if "artifacts" not in kwargs or \
                not isinstance(kwargs["artifacts"], dict):
            _refuse(MALFORMED,
                    "expect_bundle_complete requires kwarg "
                    "'artifacts' (dict ref -> artifact)")
        return {
            "items_field": _kw_str(
                kwargs, "items_field", "items", exp_type),
            "ref_field": _kw_str(
                kwargs, "ref_field", "artifact_ref", exp_type),
            # F220: guarded -- a deepcopy-hostile artifact value must
            # refuse evidence-quality-malformed, never escape raw
            # TypeError.
            "artifacts": _safe_deepcopy(
                kwargs["artifacts"], MALFORMED,
                "expect_bundle_complete kwarg 'artifacts'"),
        }
    if exp_type == "expect_fields_present":
        allowed = {"required_fields"}
        unknown = set(kwargs) - allowed
        if unknown:
            _refuse(MALFORMED,
                    "expect_fields_present: unknown kwargs %r"
                    % (sorted(unknown),))
        fields = kwargs.get("required_fields")
        if not isinstance(fields, list) or not fields \
                or not all(isinstance(f, str) and f for f in fields):
            _refuse(MALFORMED,
                    "expect_fields_present requires kwarg "
                    "'required_fields' (non-empty list of strings)")
        return {"required_fields": list(fields)}
    # expect_timestamps_ordered
    allowed = {"time_field"}
    unknown = set(kwargs) - allowed
    if unknown:
        _refuse(MALFORMED,
                "expect_timestamps_ordered: unknown kwargs %r"
                % (sorted(unknown),))
    return {
        "time_field": _kw_str(kwargs, "time_field", "issued_at",
                              exp_type),
    }


def validate_expectation(expectation):
    """Validate one expectation; return a normalized deep copy.

    Raises EvidenceQualityError (fail-closed) on any violation.
    """
    if not isinstance(expectation, dict):
        _refuse(MALFORMED, "expectation must be a dict")
    if "expectation_type" not in expectation:
        _refuse(MALFORMED,
                "expectation is missing 'expectation_type'")
    exp_type = expectation["expectation_type"]
    if not isinstance(exp_type, str):
        _refuse(MALFORMED,
                "expectation_type must be a string")
    if exp_type not in EXPECTATION_TYPES:
        _refuse(UNKNOWN_EXPECTATION,
                "expectation_type %r not in %r"
                % (exp_type, EXPECTATION_TYPES))
    normalized = {
        "expectation_type": exp_type,
        "kwargs": _normalize_kwargs(
            exp_type, expectation.get("kwargs", {})),
    }
    meta = expectation.get("meta", {})
    if not isinstance(meta, dict):
        _refuse(MALFORMED, "expectation meta must be a dict")
    # F220/F221: guarded deepcopy -- hostile meta refuses
    # evidence-quality-malformed, never escapes raw TypeError or
    # RecursionError.
    normalized["meta"] = _safe_deepcopy(
        meta, MALFORMED, "expectation meta")
    return normalized


# ---------------------------------------------------------------------------
# Evidence shape guards
# ---------------------------------------------------------------------------

def _require_item_list(evidence, exp_type):
    if not isinstance(evidence, list):
        _refuse(EVIDENCE_MALFORMED,
                "%s: evidence must be a list of dicts" % (exp_type,))
    for i, item in enumerate(evidence):
        if not isinstance(item, dict):
            _refuse(EVIDENCE_MALFORMED,
                    "%s: evidence item %d is not a dict" % (exp_type, i))
    if len(evidence) == 0:
        _refuse(EMPTY_EVIDENCE,
                "%s: evidence is empty; a vacuous gate must never "
                "pass" % (exp_type,))
    return evidence


def _require_bundle(evidence, exp_type, items_field):
    if not isinstance(evidence, dict):
        _refuse(EVIDENCE_MALFORMED,
                "%s: bundle evidence must be a dict" % (exp_type,))
    items = evidence.get(items_field)
    if not isinstance(items, list):
        _refuse(EVIDENCE_MALFORMED,
                "%s: bundle field %r must be a list" % (exp_type,
                                                       items_field))
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            _refuse(EVIDENCE_MALFORMED,
                    "%s: bundle item %d is not a dict" % (exp_type, i))
    if len(items) == 0:
        _refuse(EMPTY_EVIDENCE,
                "%s: bundle has no items; a vacuous gate must never "
                "pass" % (exp_type,))
    return items


# ---------------------------------------------------------------------------
# Evaluators: each returns (success, observed_value, details)
# ---------------------------------------------------------------------------

def _eval_monotonic(kwargs, evidence):
    field = kwargs["sequence_field"]
    strict = kwargs["strict"]
    items = _require_item_list(evidence, "expect_evidence_monotonic")
    values = []
    for i, item in enumerate(items):
        value = item.get(field)
        # bool is not a sequence number; reject it explicitly.
        if isinstance(value, bool) or \
                not isinstance(value, (int, float)):
            return (False, None,
                    {"reason": "non-numeric sequence value",
                     "index": i, "field": field})
        values.append(value)
    for i in range(1, len(values)):
        if strict and not values[i] > values[i - 1]:
            return (False, values,
                    {"reason": "sequence not strictly increasing",
                     "index": i, "previous": values[i - 1],
                     "current": values[i]})
        if not strict and not values[i] >= values[i - 1]:
            return (False, values,
                    {"reason": "sequence decreased",
                     "index": i, "previous": values[i - 1],
                     "current": values[i]})
    return (True, values,
            {"count": len(values), "strict": strict, "field": field})


def _eval_chain(kwargs, evidence):
    digest_field = kwargs["digest_field"]
    prev_field = kwargs["prev_field"]
    body_fields = kwargs["body_fields"]
    items = _require_item_list(evidence, "expect_chain_intact")
    prev_digest = None
    for i, item in enumerate(items):
        digest = item.get(digest_field)
        if not isinstance(digest, str) or not digest:
            return (False, None,
                    {"reason": "missing digest", "index": i,
                     "field": digest_field})
        prev = item.get(prev_field)
        if i == 0:
            if prev not in (None, ""):
                return (False, None,
                        {"reason": "genesis entry carries a prev link",
                         "index": 0})
        elif prev != prev_digest:
            return (False, None,
                    {"reason": "prev link mismatch", "index": i,
                     "expected_prev": prev_digest, "actual_prev": prev})
        if body_fields is None:
            body = {k: v for k, v in item.items()
                    if k not in (digest_field, prev_field)}
        else:
            body = {k: item[k] for k in body_fields if k in item}
        recomputed = hashlib.sha256(
            _canonical_bytes(body)).hexdigest()
        if recomputed != digest:
            return (False, None,
                    {"reason": "digest mismatch (tampered body?)",
                     "index": i})
        prev_digest = digest
    return (True, prev_digest,
            {"count": len(items), "tip_digest": prev_digest})


def _eval_bundle(kwargs, evidence):
    items = _require_bundle(evidence, "expect_bundle_complete",
                            kwargs["items_field"])
    ref_field = kwargs["ref_field"]
    artifacts = kwargs["artifacts"]
    missing = []
    for i, item in enumerate(items):
        ref = item.get(ref_field)
        if not isinstance(ref, str) or not ref:
            return (False, None,
                    {"reason": "item carries no artifact ref",
                     "index": i, "field": ref_field})
        if ref not in artifacts:
            missing.append(ref)
    if missing:
        return (False, None,
                {"reason": "dangling artifact refs",
                 "missing_refs": sorted(set(missing))})
    return (True, len(items),
            {"count": len(items), "resolved_refs": len(items)})


def _eval_fields(kwargs, evidence):
    items = _require_item_list(evidence, "expect_fields_present")
    required = kwargs["required_fields"]
    absent = []
    for i, item in enumerate(items):
        for field in required:
            if field not in item:
                absent.append({"index": i, "field": field})
    if absent:
        return (False, None,
                {"reason": "required fields absent",
                 "absent": absent})
    return (True, len(items),
            {"count": len(items), "required_fields": required})


def _eval_timestamps(kwargs, evidence):
    field = kwargs["time_field"]
    items = _require_item_list(evidence, "expect_timestamps_ordered")
    stamps = []
    for i, item in enumerate(items):
        raw = item.get(field)
        if not isinstance(raw, str) or not raw:
            return (False, None,
                    {"reason": "missing timestamp", "index": i,
                     "field": field})
        try:
            stamps.append(datetime.fromisoformat(
                raw.replace("Z", "+00:00")))
        except ValueError:
            return (False, None,
                    {"reason": "unparseable timestamp", "index": i,
                     "value": raw})
    for i in range(1, len(stamps)):
        if stamps[i] < stamps[i - 1]:
            return (False, [str(s) for s in stamps],
                    {"reason": "timestamps out of order",
                     "index": i})
    return (True, [s.isoformat() for s in stamps],
            {"count": len(stamps), "field": field})


_EVALUATORS = {
    "expect_evidence_monotonic": _eval_monotonic,
    "expect_chain_intact": _eval_chain,
    "expect_bundle_complete": _eval_bundle,
    "expect_fields_present": _eval_fields,
    "expect_timestamps_ordered": _eval_timestamps,
}


# ---------------------------------------------------------------------------
# evaluate()
# ---------------------------------------------------------------------------

def evaluate(expectations, evidence):
    """Evaluate every expectation against the evidence.

    Returns the ValidationResult dict: success, per-expectation
    results (exactly one per expectation, in order), statistics,
    meta. Fail-closed: refusals propagate; an internal evaluator
    error becomes a FAILED result with exception_info, never a
    silent pass.
    """
    if not isinstance(expectations, list) or not expectations:
        _refuse(MALFORMED,
                "expectations must be a non-empty list")
    # F221: bound nesting BEFORE any deepcopy -- deepcopy recurses,
    # so the bound must be enforced on the caller's objects first.
    _check_depth(expectations, MALFORMED, "expectations")
    _check_depth(evidence, EVIDENCE_MALFORMED, "evidence")
    normalized = [validate_expectation(e) for e in expectations]
    # F220/F221: guarded deepcopy -- deepcopy-hostile caller objects
    # refuse with a machine code, never escape raw TypeError or
    # RecursionError.
    evidence = _safe_deepcopy(
        evidence, EVIDENCE_MALFORMED, "evidence")
    results = []
    for exp in normalized:
        exp_type = exp["expectation_type"]
        evaluator = _EVALUATORS[exp_type]
        try:
            success, observed, details = evaluator(exp["kwargs"],
                                                   evidence)
            record = {
                "expectation_type": exp_type,
                "kwargs": copy.deepcopy(exp["kwargs"]),
                "meta": copy.deepcopy(exp["meta"]),
                "success": bool(success),
                "result": {"observed_value": observed,
                           "details": details},
                "exception_info": None,
            }
        except EvidenceQualityError:
            raise
        except Exception as exc:  # fail-closed: failed, never skipped
            record = {
                "expectation_type": exp_type,
                "kwargs": copy.deepcopy(exp["kwargs"]),
                "meta": copy.deepcopy(exp["meta"]),
                "success": False,
                "result": {"observed_value": None, "details": {}},
                "exception_info": {
                    "raised": type(exc).__name__,
                    "message": str(exc)[:500],
                },
            }
        results.append(record)
    successful = sum(1 for r in results if r["success"])
    total = len(results)
    return {
        "success": successful == total,
        "results": results,
        "statistics": {
            "evaluated_expectations": total,
            "successful_expectations": successful,
            "unsuccessful_expectations": total - successful,
            "success_percent": (100.0 * successful / total
                                if total else 0.0),
        },
        "meta": {
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "module": _EXPORT_MODULE,
        },
    }


# ---------------------------------------------------------------------------
# Quality gate in front of the compliance emitter
# ---------------------------------------------------------------------------

def emit_with_quality_gate(source, fmt, expectations, evidence,
                           findings=None, generated_at=None):
    """Run the quality gate, then emit.

    Refuses with evidence-quality-gate-failed (naming the failed
    expectations) when any expectation fails. On success delegates
    to gov.compliance_emitter.emit(). The emitter is not modified.
    """
    report = evaluate(expectations, evidence)
    if not report["success"]:
        failed = [r["expectation_type"] for r in report["results"]
                  if not r["success"]]
        _refuse(GATE_FAILED,
                "quality gate refused emission; failed expectations: "
                "%s" % (", ".join(failed),))
    return compliance_emitter.emit(source, fmt, findings=findings,
                                   generated_at=generated_at)
