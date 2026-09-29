"""Decision+diagnostics contract (wave-206 lane C, Cedar/AVP ADAPT).

Wave-205 prospecting section 2 returned ADAPT for Cedar/AVP's
authorization response contract: the authorizer returns not just the
decision but ``{decision, determining policies, errors}`` -- the
*reasons* a decision was reached. Our decision-log v2 has
``decision_id`` and replay capture but does not record *which policies
determined the decision*. This module closes that gap, stdlib-only,
re-implemented (nothing vendored; Cedar/AVP Apache-2.0, no trap):

* :func:`decide_with_diagnostics` evaluates a
  :class:`gov.perm_loader.PermModel` and returns a **decision record**
  with exactly the five spec'd top-level keys::

      {"decision": "allow|deny|require_approval|no-decision",
       "decision_id": "<content-derived hex64 binding the whole record>",
       "determining_policies": [{"screen", "policy_index", "policy_id",
                                 "effect"}, ...],
       "errors": [{"code", "message"}, ...],
       "residuals": {"decision_holds_iff": str|None,
                     "unknown_entities": [...],
                     "default_used": bool,
                     "bindings": {"record_version": 1,
                                  "request_digest": "<hex64>",
                                  "perm": {"model_digest",
                                           "policy_digest",
                                           "composition_digest",
                                           "function_set_digest"}}}}

  The binding/versioning material lives in ``residuals["bindings"]``
  so the record stays self-verifying (cross-request and cross-pack
  swap detection) without widening the five-key contract.

  "Which policies determined this decision" is mandatory: a record
  whose decision came from a screen names the exact matched rows
  (indices are stable within one pinned ``policy_digest``, which the
  record carries). A row's ``policy_id`` is the row's own ``id``
  column when the policy schema declares one, else
  ``"<screen>[<index>]"``.

* The **explicit NoDecision path** (Cedar's ``is_authorized_partial``
  ADAPT): when no screen fires, the caller chooses between the
  composition's ``default_verdict`` (recorded with
  ``residuals.default_used=True``) and an explicit ``"no-decision"``
  verdict carrying ``residuals.unknown_entities`` (the request
  attributes no loaded policy row could decide on -- Cedar's
  "what I would need to finish deciding") and
  ``residuals.decision_holds_iff`` (the honest residual: the decision
  would hold iff a matching policy row were loaded). No silent
  default: the two paths are different records and verify
  differently.

* Forgery resistance: ``decision_id`` is content-derived over the
  canonical record (decision + determining policies + errors +
  residuals + request digest + perm digests). Editing
  ``determining_policies`` post-hoc breaks the id; swapping a record
  across requests breaks ``request_digest``; swapping across packs
  breaks the ``perm`` digests. :func:`verify_decision_record`
  re-derives all of it.

* The ``errors`` slot: the narrow PERM engine raises on internal
  errors (fail-closed) rather than recording them, so
  engine-produced records always carry ``errors: []``. The slot is
  part of the contract for composed/partial evaluations (e.g. a
  caller merging sub-decisions) and is shape-validated, never
  silently dropped.

* V2 wiring: :func:`build_diagnostic_event` builds a
  ``gov.decision_log_v2`` event carrying the record under the
  additive ``diagnostics`` key (bound by the v2 ``decision_id``;
  absent on legacy events). ``decision_log_v2`` stays gov-import-free:
  it shape-checks the block only; semantic verification is
  :func:`verify_diagnostic_event` here.

HONEST CEILINGS:

* ``policy_index`` stability is per ``policy_digest`` only. Reorder
  the policy rows and the indices name different rows -- the record
  binds the digest so the reordering is visible, not silent.
* ``decision_id`` is a binding, not a signature (same ceiling as the
  v2 event id): post-hoc edit detection comes from the hash-chained
  audit log the event is appended to.
* ``unknown_entities`` names request attributes, not Cedar entity
  refs: PERM requests are flat attribute snapshots, so "what I would
  need" is the attribute set no row covered. It is an honest analog,
  not a port.
* The Cedar ``symcc`` safety/liveness/sanity triple is NOT here --
  that is the pack red-team lint lane's job (wave-206 slate item 3).

$0 spend, synthetic/local deterministic only. No network.
"""

import copy
import hashlib
import json

from . import decision_log_v2 as _dlv
from . import perm_loader as _pl

__all__ = [
    "RECORD_VERSION",
    "DECISIONS",
    "DiagnosticsError",
    "RecordBuildError",
    "RecordVerifyError",
    "build_decision_record",
    "verify_decision_record",
    "decide_with_diagnostics",
    "no_decision_record",
    "build_diagnostic_event",
    "verify_diagnostic_event",
]

#: Record schema version.
RECORD_VERSION = 1

#: Decision vocabulary. ``no-decision`` is the explicit partial-
#: evaluation outcome, never a silent default.
DECISIONS = ("allow", "deny", "require_approval", "no-decision")


class DiagnosticsError(Exception):
    """Base for all decision-diagnostics errors (loud, fail-closed)."""


class RecordBuildError(DiagnosticsError):
    """The decision record could not be built (bad caller inputs)."""


class RecordVerifyError(DiagnosticsError):
    """Decision-record verification failed (structural / binding)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


# ---------------------------------------------------------------------------
# Determining-policy extraction (per effect semantics)
# ---------------------------------------------------------------------------

def _determining_rows(effect, matched, effect_value):
    """The matched rows that determined the outcome, as
    ``[(index, eft), ...]`` in policy order.

    ``matched``: ``[{"index", "effect"}, ...]`` from
    :meth:`PermModel.decide_traced`. The extraction is per effect
    expression: for allow-override the allow rows determined it; for
    deny-override firing on a matched deny, the deny rows did; for
    deny-override firing on *absence* of deny, the determination is
    the absence itself (empty list -- honest, not padded).
    """
    allow_rows = [(m["index"], m["effect"]) for m in matched
                  if m["effect"] == "allow"]
    deny_rows = [(m["index"], m["effect"]) for m in matched
                 if m["effect"] == "deny"]
    if effect == _pl.EFFECT_ALLOW_OVERRIDE:
        return allow_rows if effect_value else []
    if effect == _pl.EFFECT_DENY_OVERRIDE:
        if effect_value:
            # Fired on absence-of-deny: no row determined the
            # decision; the empty list says exactly that.
            return []
        return deny_rows
    if effect == _pl.EFFECT_ALLOW_AND_DENY:
        return allow_rows if effect_value else []
    if effect == _pl.EFFECT_PRIORITY:
        if effect_value and matched:
            first = matched[0]
            return [(first["index"], first["effect"])]
        return []
    raise RecordBuildError(
        "cannot extract determining rows for unknown effect %r"
        % (effect,))


def _row_policy_id(model, screen_name, index):
    """Stable-ish row identity: the row's own ``id`` column when the
    policy schema declares one, else ``"<screen>[<index>]"``. Indices
    are stable only within one pinned policy_digest (carried by the
    record's bindings), which is stated, not hidden. Uses the public
    PermModel.policy_row accessor -- never the private _policies."""
    row = model.policy_row(screen_name, index)
    rid = row.get("id")
    if isinstance(rid, str) and rid:
        return rid
    return "%s[%d]" % (screen_name, index)


def _deciding_entry(trace):
    """The trace entry that decided, or raise in-taxonomy. ``next()``
    without a default would leak a bare StopIteration if the
    decide_traced invariant ever broke; fail-closed instead."""
    deciding = next((t for t in trace if t["decided"]), None)
    if deciding is None:
        raise RecordBuildError(
            "decide_traced returned no deciding entry for a "
            "screen-fired verdict")
    return deciding


def _unknown_entities_for(request):
    """The request attributes no loaded policy row could decide on,
    as ``[{kind, name, value}, ...]`` in stable key order. Shared by
    the no-decision fork and the explicit no-decision constructor."""
    return [{"kind": "request_attribute",
             "name": name, "value": value}
            for name, value in sorted(request.items(),
                                      key=lambda kv: str(kv[0]))]


# ---------------------------------------------------------------------------
# Record build / verify
# ---------------------------------------------------------------------------

#: The record's top-level contract -- exactly these keys, no more.
#: Binding/versioning material lives in ``residuals["bindings"]`` so
#: the top-level shape stays the spec'd five.
_RECORD_KEYS = frozenset({"decision", "decision_id",
                          "determining_policies", "errors", "residuals"})

#: Allowed ``residuals`` keys. ``bindings`` carries the request/pack
#: digests the decision is bound to plus the record version; the rest
#: is the residual evidence the spec names (``default_used`` labels
#: the composition-default fork vs the explicit ``no-decision`` one).
_RESIDUAL_KEYS = frozenset({"decision_holds_iff", "unknown_entities",
                            "default_used", "bindings"})

_PERM_DIGEST_KEYS = ("model_digest", "policy_digest",
                     "composition_digest", "function_set_digest")


def _check_record_shape(record, what):
    if not isinstance(record, dict):
        raise RecordBuildError("%s must be a dict" % what)
    unknown = set(record) - _RECORD_KEYS
    if unknown:
        raise RecordBuildError(
            "%s carries unknown top-level keys: %s"
            % (what, sorted(unknown)))
    missing = _RECORD_KEYS - set(record)
    if missing:
        raise RecordBuildError(
            "%s missing top-level keys: %s" % (what, sorted(missing)))
    if record.get("decision") not in DECISIONS:
        raise RecordBuildError(
            "%s decision must be one of %s" % (what, list(DECISIONS)))
    det = record.get("determining_policies")
    if not isinstance(det, list):
        raise RecordBuildError(
            "%s determining_policies must be a list" % what)
    for i, entry in enumerate(det):
        where = "%s determining_policies[%d]" % (what, i)
        if not isinstance(entry, dict):
            raise RecordBuildError("%s must be a dict" % where)
        for key in ("screen", "policy_index", "policy_id", "effect"):
            if key not in entry:
                raise RecordBuildError("%s missing %r" % (where, key))
        if not isinstance(entry["screen"], str) or not entry["screen"]:
            raise RecordBuildError("%s screen malformed" % where)
        if (isinstance(entry["policy_index"], bool)
                or not isinstance(entry["policy_index"], int)
                or entry["policy_index"] < 0):
            raise RecordBuildError("%s policy_index malformed" % where)
        if not isinstance(entry["policy_id"], str) \
                or not entry["policy_id"]:
            raise RecordBuildError("%s policy_id malformed" % where)
        if entry["effect"] not in ("allow", "deny"):
            raise RecordBuildError("%s effect malformed" % where)
    errors = record.get("errors")
    if not isinstance(errors, list):
        raise RecordBuildError("%s errors must be a list" % what)
    for i, err in enumerate(errors):
        where = "%s errors[%d]" % (what, i)
        if not isinstance(err, dict) or not isinstance(
                err.get("code"), str) or not isinstance(
                err.get("message"), str):
            raise RecordBuildError(
                "%s must be {code: str, message: str}" % where)
    residuals = record.get("residuals")
    if not isinstance(residuals, dict):
        raise RecordBuildError("%s residuals must be a dict" % what)
    unknown = set(residuals) - _RESIDUAL_KEYS
    if unknown:
        raise RecordBuildError(
            "%s residuals carries unknown keys: %s"
            % (what, sorted(unknown)))
    missing = _RESIDUAL_KEYS - set(residuals)
    if missing:
        raise RecordBuildError(
            "%s residuals missing keys: %s" % (what, sorted(missing)))
    holds = residuals.get("decision_holds_iff")
    if holds is not None and not isinstance(holds, str):
        raise RecordBuildError(
            "%s residuals.decision_holds_iff must be str|null" % what)
    unknown_entities = residuals.get("unknown_entities")
    if not isinstance(unknown_entities, list):
        raise RecordBuildError(
            "%s residuals.unknown_entities must be a list" % what)
    for u in unknown_entities:
        where = "%s residuals.unknown_entities[]" % what
        if not isinstance(u, dict) or not isinstance(u.get("name"), str):
            raise RecordBuildError("%s entries must be {name: str, ...}"
                                   % where)
    if not isinstance(residuals.get("default_used"), bool):
        raise RecordBuildError(
            "%s residuals.default_used must be a bool" % what)
    # Bindings: the version + digests this decision is bound to. Kept
    # inside residuals so the top-level contract stays five keys; the
    # v2 shape gate (gov/decision_log_v2._check_diagnostics_shape)
    # mirrors this structure -- keep the two in sync.
    bindings = residuals.get("bindings")
    if not isinstance(bindings, dict):
        raise RecordBuildError(
            "%s residuals.bindings must be a dict" % what)
    if bindings.get("record_version") != RECORD_VERSION:
        raise RecordBuildError(
            "%s residuals.bindings.record_version must be %d"
            % (what, RECORD_VERSION))
    if not _is_hex64(bindings.get("request_digest")):
        raise RecordBuildError(
            "%s residuals.bindings.request_digest is not 64-char hex"
            % what)
    perm = bindings.get("perm")
    if not isinstance(perm, dict):
        raise RecordBuildError(
            "%s residuals.bindings.perm must be a dict" % what)
    for key in _PERM_DIGEST_KEYS:
        if not _is_hex64(perm.get(key)):
            raise RecordBuildError(
                "%s residuals.bindings.perm.%s is not 64-char hex"
                % (what, key))
    if not _is_hex64(record.get("decision_id")):
        raise RecordBuildError(
            "%s decision_id is not 64-char hex" % what)


def _decision_id_for(record):
    """Content-derived id: sha256 over the canonical record minus
    ``decision_id`` itself."""
    preimage = {k: v for k, v in record.items() if k != "decision_id"}
    return _sha256_hex(_canonical(preimage))


def build_decision_record(*, decision, determining_policies,
                          request_digest, perm, errors=(),
                          residuals=None):
    """Build a validated decision record with a content-derived
    ``decision_id``. The record has exactly the five spec'd top-level
    keys ``{decision, decision_id, determining_policies, errors,
    residuals}``; the binding/versioning material (``request_digest``,
    the ``perm`` digests, ``record_version``) is carried in
    ``residuals["bindings"]`` so the record stays self-verifying
    without widening the contract. ``determining_policies`` / ``errors``
    / ``residuals`` / ``perm`` are validated strictly; ``request_digest``
    and the ``perm`` digests must be 64-char hex. Raises
    RecordBuildError loud -- a record without traceable determining
    policies for a screen-fired decision is a caller bug, not a
    default.
    """
    if residuals is None:
        residuals = {}
    residuals = copy.deepcopy(residuals)
    residuals.setdefault("decision_holds_iff", None)
    residuals.setdefault("unknown_entities", [])
    residuals.setdefault("default_used", False)
    residuals["bindings"] = {
        "record_version": RECORD_VERSION,
        "request_digest": request_digest,
        "perm": copy.deepcopy(perm),
    }
    record = {
        "decision": decision,
        "determining_policies": copy.deepcopy(list(determining_policies)),
        "errors": copy.deepcopy(list(errors)),
        "residuals": residuals,
    }
    # Shape-check before id computation so the id is never minted
    # over a malformed record; decision_id filled in after.
    record["decision_id"] = "0" * 64
    _check_record_shape(record, "decision record")
    record["decision_id"] = _decision_id_for(record)
    _check_record_shape(record, "decision record")
    return record


def verify_decision_record(record, *, request=None, perm_model=None):
    """Verify a decision record. Recomputes ``decision_id`` over the
    canonical record (bindings included -- they live in
    ``residuals["bindings"]``); optionally rebinds the bound
    ``request_digest`` against ``request`` and the bound ``perm``
    digests against ``perm_model`` (a :class:`PermModel`). Returns
    True; raises RecordVerifyError -- never silent."""
    if not isinstance(record, dict):
        raise RecordVerifyError("record is not a dict")
    try:
        _check_record_shape(record, "decision record")
    except RecordBuildError as exc:
        raise RecordVerifyError("malformed decision record: %s" % (exc,))
    bindings = record["residuals"]["bindings"]
    recomputed = _decision_id_for(record)
    if record["decision_id"] != recomputed:
        raise RecordVerifyError(
            "decision_id MISMATCH: recorded=%s recomputed=%s -- the "
            "record was edited after id computation (forged determining "
            "policies fail closed)" % (record["decision_id"], recomputed))
    if request is not None:
        try:
            want = _sha256_hex(_canonical(request))
        except (TypeError, ValueError) as exc:
            raise RecordVerifyError(
                "request is not JSON-canonicalizable: %s" % (exc,))
        if bindings["request_digest"] != want:
            raise RecordVerifyError(
                "request_digest MISMATCH -- the record does not belong "
                "to this request (cross-request record swap fails "
                "closed)")
    if perm_model is not None:
        section = perm_model.bom_perm_section()
        for key in _PERM_DIGEST_KEYS:
            if bindings["perm"][key] != section[key]:
                raise RecordVerifyError(
                    "perm.%s MISMATCH -- the record was produced under a "
                    "different model/policy pack (cross-pack record swap "
                    "fails closed)" % (key,))
    return True


# ---------------------------------------------------------------------------
# decide_with_diagnostics / no_decision_record
# ---------------------------------------------------------------------------

def _request_digest_for(request):
    try:
        return _sha256_hex(_canonical(request))
    except (TypeError, ValueError) as exc:
        raise RecordBuildError(
            "request is not JSON-canonicalizable: %s" % (exc,))


def decide_with_diagnostics(model, request, *,
                            default_as_no_decision=False):
    """Evaluate ``model`` and return a decision record.

    The determining policies are the matched rows of the deciding
    screen, extracted per the screen's effect semantics -- never
    inferred. When no screen fires: with
    ``default_as_no_decision=False`` the composition's
    ``default_verdict`` is returned with
    ``residuals.default_used=True``; with True an explicit
    ``"no-decision"`` record is returned carrying
    ``unknown_entities`` (the request attributes no loaded policy row
    could decide on) and ``decision_holds_iff``. The two paths are
    different records -- no silent default.
    """
    if not isinstance(model, _pl.PermModel):
        raise RecordBuildError("model must be a PermModel")
    verdict, screen, trace = model.decide_traced(request)
    perm = model.bom_perm_section()
    req_digest = _request_digest_for(request)
    if screen != "default":
        deciding = _deciding_entry(trace)
        rows = _determining_rows(deciding["effect"],
                                 deciding["matched"],
                                 deciding["effect_value"])
        determining = [{
            "screen": deciding["screen"],
            "policy_index": idx,
            "policy_id": _row_policy_id(model, deciding["screen"], idx),
            "effect": eft,
        } for idx, eft in rows]
        return build_decision_record(
            decision=verdict,
            determining_policies=determining,
            request_digest=req_digest,
            perm=perm,
            residuals={"decision_holds_iff": None,
                       "unknown_entities": [],
                       "default_used": False})
    # No screen fired: the explicit fork. default_used=True says "the
    # composition default decided this"; no-decision says "nobody
    # decided this -- here is what is missing".
    if default_as_no_decision:
        return build_decision_record(
            decision="no-decision",
            determining_policies=[],
            request_digest=req_digest,
            perm=perm,
            residuals={
                "decision_holds_iff":
                    "no policy row matched this request; the decision "
                    "would hold iff a policy row matching these request "
                    "attributes were loaded",
                "unknown_entities": _unknown_entities_for(request),
                "default_used": False,
            })
    return build_decision_record(
        decision=verdict,
        determining_policies=[],
        request_digest=req_digest,
        perm=perm,
        residuals={
            "decision_holds_iff":
                "no screen fired; the composition default_verdict "
                "(%s) decided this" % (verdict,),
            "unknown_entities": [],
            "default_used": True,
        })


def no_decision_record(*, model, request, reason):
    """Build an explicit no-decision record for a caller that declines
    to decide (partial-evaluation analog). ``reason`` is the
    human/auditor-facing residual text. ``unknown_entities`` names the
    request attributes the evaluator would need a policy for."""
    if not isinstance(model, _pl.PermModel):
        raise RecordBuildError("model must be a PermModel")
    if not isinstance(reason, str) or not reason:
        raise RecordBuildError("reason must be a non-empty string")
    # Validate the request against the model's schema so the
    # unknown_entities list is over a real request shape (fail-closed
    # on malformed input, like decide()).
    model.decide_traced(request)
    return build_decision_record(
        decision="no-decision",
        determining_policies=[],
        request_digest=_request_digest_for(request),
        perm=model.bom_perm_section(),
        residuals={"decision_holds_iff": reason,
                   "unknown_entities": _unknown_entities_for(request),
                   "default_used": False})


# ---------------------------------------------------------------------------
# decision-log v2 wiring
# ---------------------------------------------------------------------------

def build_diagnostic_event(*, record, raw_body, erased=(), masked=(),
                           replay_fn, replay_inputs, replay_verdict,
                           replay_complete=True):
    """Build a v2 decision event carrying ``record`` under the additive
    ``diagnostics`` key. The v2 ``decision`` block is derived from the
    record (kind ``policy-authorization``); the v2 ``decision_id``
    binds the diagnostics block. ``verify_decision_record`` must pass
    on ``record`` first (fail-closed before the event is built)."""
    verify_decision_record(record)
    determining = record["determining_policies"]
    if determining:
        reason = "determining: " + ", ".join(
            "%s:%s" % (p["screen"], p["policy_id"]) for p in determining)
    elif record["decision"] == "no-decision":
        reason = "no-decision: %s" % (
            record["residuals"]["decision_holds_iff"] or "no residual")
    else:
        reason = "default used: %s" % (
            record["residuals"]["decision_holds_iff"] or "no residual")
    decision = {
        "kind": "policy-authorization",
        "effect": record["decision"],
        "policy_id": "perm-policy:" + record["residuals"]["bindings"][
            "perm"]["policy_digest"][:16],
        "reason": reason,
    }
    return _dlv.build_event(
        decision=decision, raw_body=raw_body, erased=erased,
        masked=masked, replay_fn=replay_fn, replay_inputs=replay_inputs,
        replay_verdict=replay_verdict, replay_complete=replay_complete,
        diagnostics=copy.deepcopy(record))


def verify_diagnostic_event(event, *, request=None, perm_model=None):
    """Verify a v2 event AND its diagnostics block: the v2 layers
    (shape, decision_id, redaction, replay) plus the record's
    decision_id binding and optional request/pack rebinding. Returns
    True; raises loudly."""
    _dlv.verify_event(event)
    record = event.get("diagnostics")
    if not isinstance(record, dict):
        raise RecordVerifyError(
            "event carries no diagnostics block -- a diagnostic event "
            "without its record fails closed")
    verify_decision_record(record, request=request, perm_model=perm_model)
    return True
