"""Break-first probes for falco-style alert discipline over the wave-261
detector schema.

Wave-262 feature lane 2 (falcosecurity/falco ADAPT -- the *alert discipline*
only: fixed priority ladder, first-class exception blocks, maturity tiers,
override semantics. Pattern only; no falco code vendored, linked, or
translated. Falco's license lives at COPYING, Apache-2.0.)

Recombination onto gov/detectors.py (additive -- wave-261 definitions keep
loading and behaving identically):
- `priority`: fixed ladder (emergency/alert/critical/error/warning/notice/
  informational/debug, falco's order, most severe first). Every *alert*
  carries a declared ladder value; a detector without a declared priority
  is never inflated (no silent default to critical) -- its matches are
  journaled as observations.
- `exceptions`: named allowlist blocks (fields/comps/values tuples) attached
  to a detector, evaluated separately from the rule condition (never `and
  not` clauses buried in predicates). Each block is independently
  overridable/disablable by deployment policy without touching the rule;
  a disabled exception fails closed to alert (and the re-arming is
  journaled, never silent).
- `maturity`: stable / experimental / deprecated. Experimental detectors
  observe only (cannot gate enforcement decisions); deprecated detectors
  refuse to load with a machine code.
- `AlertSink`: matched detector + exception evaluation -> structured alert
  record (detector, priority, maturity, matched event digest, exception
  decision) appended to the journal; exception-matched events are journaled
  as suppressed-with-reason, never silently dropped.

Method (tdd skill, red-before-green; diagnosing-bugs break-first): each probe
is a falsifiable break attempt written BEFORE the implementation. Verdicts:
  HELD  -- the defect is refused or handled as specified.
  GAP   -- the defect is present (pre-fix state).
  ERROR -- harness bug; fix the harness, never the product.

Targets (base 8bf6c418, taxonomy pin 1106 -> 1110):
- gov/detectors.py -- additive alert-discipline extensions + AlertSink.
- gov/decision_codes.py -- four new machine codes (domain `detector`,
  severity medium, evidence ['detector-definition'], reverify ['recompute'],
  sorted position): detector-deprecated, detector-exception-malformed,
  detector-unknown-maturity, detector-unknown-priority.

Pin change: 1106 -> 1110. Value-token-only repoint across tests/ + evals/
(wave-256 lesson); source-literal uniqueness asserted (wave-260 lesson:
duplicate "code" literals are invisible to len(TAXONOMY)).

Deterministic across runs (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail closed).
Green check is depth-1: runs the adjacent w261 detector battery with
GOV_SKIP_GREEN=1 in the child env; honors GOV_SKIP_GREEN=1 by recording a
skip instead of spawning (combinatorial-nesting lesson).
"""

import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402 (taxonomy pin below)

try:
    from gov import detectors as det  # noqa: E402
    _HAVE_DET = True
except ImportError:
    det = None  # noqa: F841
    _HAVE_DET = False

# Wave-262 feature lane 2: +4 detector-* machine codes -> 1106 -> 1110.
# Assert on the deduped dict AND on raw source literals (wave-260 lesson).
TAXONOMY_PIN = 1742  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*)

_NEW_CODES = ("detector-deprecated", "detector-exception-malformed",
              "detector-unknown-maturity", "detector-unknown-priority")

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _gap(detail=""):
    return ("GAP", detail)


def _need_alert():
    """GAP unless the alert-discipline surface exists (red-first guard)."""
    if not _HAVE_DET:
        return _gap("gov/detectors.py missing")
    if not hasattr(det, "AlertSink"):
        return _gap("no alert discipline: AlertSink absent "
                    "(falco alert half not implemented)")
    return None


def _base_def(name="probe-det", **kw):
    d = {
        "name": name,
        "version": "1.0.0",
        "description": "probe detector",
        "event_selector": {"type": "probe_event"},
        "predicates": [{"field": "flag", "op": "eq", "value": True}],
        "produces": {"event_name": name + "_fired",
                     "event_schema_version": "1.0.0", "fields": {}},
        "threat": {"severity": "low", "description": "probe"},
        "subscribes": [],
    }
    d.update(kw)
    return d


def _exc_block(name="allow-ci", **kw):
    b = {"name": name,
         "description": "probe exception block",
         "fields": ["host"],
         "comps": ["eq"],
         "values": [["ci.internal.example"]]}
    b.update(kw)
    return b


def _sink(engine, **kw):
    return det.AlertSink(engine, **kw)


def _refused_with(fn, want_code):
    """Run fn(); return (True, "") if it raises DetectorRegistrationError
    with want_code, else (False, reason)."""
    try:
        fn()
    except det.DetectorRegistrationError as exc:
        if exc.code == want_code:
            return True, ""
        return False, "wrong machine code: %s (want %s)" % (
            exc.code, want_code)
    except Exception as exc:  # noqa: BLE001 -- harness reports, never dies
        return False, "wrong exception type: %r" % (exc,)
    return False, "no refusal at all"


# ------------------------------------------------------------ probes

@probe("taxonomy_pin_1110_and_source_literals")
def _p_pin():
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        return _gap("TAXONOMY has %d entries, want pin %d" % (n, TAXONOMY_PIN))
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    for code in _NEW_CODES:
        literal = '"code": \'%s\'' % code
        occ = src.count(literal)
        if occ != 1:
            return _gap("source literal %r occurs %d times (want exactly 1)"
                        % (literal, occ))
    return _held("pin 1110; 4 new detector-* code literals unique in source")


@probe("priority_ladder_accepted")
def _p_ladder():
    r = _need_alert()
    if r:
        return r
    ladder = getattr(det, "PRIORITY_LADDER", None)
    if not ladder:
        return _gap("no PRIORITY_LADDER: fixed ladder absent")
    if tuple(ladder) != ("emergency", "alert", "critical", "error",
                         "warning", "notice", "informational", "debug"):
        return _gap("ladder is not falco's fixed order: %r" % (ladder,))
    eng = det.DetectorEngine()
    defs = [_base_def(name="lad-%d" % i, priority=p)
            for i, p in enumerate(ladder)]
    try:
        eng.register_all(defs)
    except det.DetectorRegistrationError as exc:
        return _gap("ladder value refused: %s" % (exc,))
    if len(eng.detectors) != 8:
        return _gap("only %d/8 ladder detectors registered"
                    % len(eng.detectors))
    return _held("all 8 fixed-ladder priorities register")


@probe("unknown_priority_refused")
def _p_unknown_priority():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    for bad in ("CRITICAL", "urgent", "", "info", 5, None.__class__):
        ok, why = _refused_with(
            lambda b=bad: eng.register(_base_def(priority=b)),
            "detector-unknown-priority")
        if not ok:
            return _gap("priority %r: %s" % (bad, why))
    if eng.detectors:
        return _gap("refused batch left residue: %r"
                    % (list(eng.detectors),))
    return _held("unknown priorities refused loudly "
                 "(detector-unknown-priority), no residue")


@probe("priority_not_inflated")
def _p_no_inflation():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="noprio"))  # stable, no priority declared
    sink = _sink(eng)
    produced = sink.process({"type": "probe_event", "flag": True})
    if len(produced) != 1:
        return _gap("no production: %r" % (produced,))
    recs = sink.journal_entries()
    if len(recs) != 1:
        return _gap("match not journaled: %d records" % len(recs))
    rec = recs[0]
    if rec["record_type"] == "alert" and rec["priority"] == "critical":
        return _gap("INFLATED: priority-less detector defaulted to critical")
    if rec["record_type"] != "observation":
        return _gap("priority-less match must be an observation, got %r"
                    % (rec["record_type"],))
    if rec["priority"] is not None:
        return _gap("priority must stay undeclared (None), got %r"
                    % (rec["priority"],))
    if "priority" not in (rec["reason"] or ""):
        return _gap("reason must name the missing priority: %r"
                    % (rec["reason"],))
    return _held("priority-less detector: observation, priority None, "
                 "never inflated to critical")


@probe("exception_suppression_journaled")
def _p_suppressed():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="with-exc", priority="warning",
                            exceptions=[_exc_block()]))
    sink = _sink(eng)
    produced = sink.process({"type": "probe_event", "flag": True,
                             "host": "ci.internal.example"})
    # Detection (Tracee half) is unaffected by suppression: the produced
    # event still flows; only the ALERT is suppressed (Falco half).
    if len(produced) != 1:
        return _gap("suppression dropped the produced event: %r" % (produced,))
    recs = sink.journal_entries()
    if len(recs) != 1:
        return _gap("suppressed match not journaled exactly once: %d"
                    % len(recs))
    rec = recs[0]
    if rec["record_type"] != "suppressed":
        return _gap("want record_type 'suppressed', got %r"
                    % (rec["record_type"],))
    ed = rec["exception_decision"]
    if ed["matched"] != ["allow-ci"] or ed["suppressing_exception"]\
            != "allow-ci" or ed["decision"] != "suppressed":
        return _gap("exception_decision wrong: %r" % (ed,))
    if "allow-ci" not in (rec["reason"] or ""):
        return _gap("suppression reason must name the exception: %r"
                    % (rec["reason"],))
    if rec["event_digest"] != produced[0]["produced_from"]:
        return _gap("event_digest != digest of the matched event")
    if len(rec["event_digest"]) != 64:
        return _gap("event_digest not 64-hex")
    # The non-exceptional twin must alert.
    produced2 = sink.process({"type": "probe_event", "flag": True,
                              "host": "evil.example"})
    recs2 = sink.journal_entries()
    if len(produced2) != 1 or len(recs2) != 2:
        return _gap("twin event mishandled")
    twin = recs2[1]
    if twin["record_type"] != "alert" or twin["priority"] != "warning":
        return _gap("twin must alert at declared priority: %r" % (twin,))
    if twin["exception_decision"]["decision"] != "no-suppression":
        return _gap("twin exception decision wrong: %r"
                    % (twin["exception_decision"],))
    return _held("exception match -> suppressed-with-reason journaled; "
                 "detection intact; twin alerts at declared priority")


@probe("exception_malformed_refused")
def _p_exc_malformed():
    r = _need_alert()
    if r:
        # Pre-fix the whole definition is refused as an unknown key; the
        # alert-discipline machine code is what is missing.
        if not _HAVE_DET:
            return r
        eng = det.DetectorEngine()
        try:
            eng.register(_base_def(exceptions=[_exc_block()]))
        except det.DetectorRegistrationError as exc:
            if exc.code == "detector-exception-malformed":
                return _held("unreachable pre-fix")
            return _gap("malformed-exception discipline absent "
                        "(got %s, want detector-exception-malformed)"
                        % exc.code)
        return _gap("exceptions block silently accepted pre-fix")
    variants = {
        "fields_comps_mismatch": _exc_block(comps=["eq", "eq"]),
        "comps_values_mismatch": _exc_block(values=[["a"], ["b"]]),
        "unknown_comp": _exc_block(comps=["contains"]),
        "dunder_path": _exc_block(fields=["__class__"]),
        "bad_path_shape": _exc_block(fields=["a..b"]),
        "duplicate_names": [_exc_block(name="dup"), _exc_block(name="dup")],
        "values_not_scalar_list": _exc_block(values=["nope"]),
        "values_empty_list": _exc_block(values=[[]]),
        "values_nested_dict": _exc_block(values=[[{"k": "v"}]]),
        "exceptions_not_a_list": "nope",
        "block_not_a_dict": ["nope"],
        "bad_name": _exc_block(name="Bad Name!"),
        "unknown_block_key": _exc_block(sneaky=True),
    }
    for vname, exc in variants.items():
        eng = det.DetectorEngine()
        blocks = exc if isinstance(exc, list) else [exc]
        if vname == "exceptions_not_a_list":
            blocks = "nope"
        elif vname == "block_not_a_dict":
            blocks = ["nope"]
        ok, why = _refused_with(
            lambda b=blocks: eng.register(_base_def(exceptions=b)),
            "detector-exception-malformed")
        if not ok:
            return _gap("variant %s: %s" % (vname, why))
        if eng.detectors:
            return _gap("variant %s left residue" % vname)
    return _held("13 malformed exception shapes refused loudly "
                 "(detector-exception-malformed), no residue")


@probe("disabled_exception_fails_closed_to_alert")
def _p_disabled_exc():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="pol-det", priority="error",
                            exceptions=[_exc_block()]))
    policy = {"exceptions": {"pol-det": {"allow-ci": {"enabled": False}}}}
    try:
        sink = _sink(eng, policy=policy)
    except Exception as exc:  # noqa: BLE001 -- harness reports
        return _gap("policy rejected: %r" % (exc,))
    produced = sink.process({"type": "probe_event", "flag": True,
                             "host": "ci.internal.example"})
    if len(produced) != 1:
        return _gap("no production: %r" % (produced,))
    recs = sink.journal_entries()
    if len(recs) != 1:
        return _gap("not journaled: %d" % len(recs))
    rec = recs[0]
    # Fails CLOSED to alert: the disabled exception cannot suppress.
    if rec["record_type"] != "alert":
        return _gap("disabled exception must fail closed to alert, got %r"
                    % (rec["record_type"],))
    ed = rec["exception_decision"]
    # ... and the re-arming must not be silent.
    if ed["disabled_but_matched"] != ["allow-ci"]:
        return _gap("re-arming is silent: disabled_but_matched=%r" % (ed,))
    if ed["suppressing_exception"] is not None:
        return _gap("disabled exception suppressed anyway: %r" % (ed,))
    return _held("disabled exception fails closed to alert; re-arming "
                 "journaled in disabled_but_matched")


@probe("policy_value_override")
def _p_policy_override():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="ovr-det", priority="notice",
                            exceptions=[_exc_block()]))
    policy = {"exceptions":
              {"ovr-det": {"allow-ci": {"values": [["other.example"]]}}}}
    try:
        sink = _sink(eng, policy=policy)
    except Exception as exc:  # noqa: BLE001
        return _gap("policy rejected: %r" % (exc,))
    # Old value no longer suppresses...
    sink.process({"type": "probe_event", "flag": True,
                  "host": "ci.internal.example"})
    # ...new value does.
    sink.process({"type": "probe_event", "flag": True,
                  "host": "other.example"})
    recs = sink.journal_entries()
    if len(recs) != 2:
        return _gap("want 2 records, got %d" % len(recs))
    if recs[0]["record_type"] != "alert":
        return _gap("overridden-away value must alert, got %r"
                    % (recs[0]["record_type"],))
    if recs[1]["record_type"] != "suppressed":
        return _gap("override value must suppress, got %r"
                    % (recs[1]["record_type"],))
    # Unknown names in policy are LOUD (a typo must not silently do
    # nothing -- that would be fail-open).
    for bad_policy in ({"exceptions": {"nope-det": {"allow-ci": {}}}},
                       {"exceptions":
                        {"ovr-det": {"nope-exc": {"enabled": False}}}},
                       {"bogus-top": {}}):
        try:
            _sink(det.DetectorEngine(), policy=bad_policy)
        except det.AlertPolicyError:
            continue
        except Exception as exc:  # noqa: BLE001
            return _gap("bad policy raised %r, want AlertPolicyError"
                        % (exc,))
        return _gap("bad policy silently accepted: %r" % (bad_policy,))
    return _held("policy overrides exception values without touching the "
                 "rule; unknown names refused loudly (AlertPolicyError)")


@probe("experimental_observation_only")
def _p_experimental():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="exp-det", priority="critical",
                            maturity="experimental"))
    eng.register(_base_def(name="stable-det", priority="critical"))
    sink = _sink(eng)
    sink.process({"type": "probe_event", "flag": True})
    recs = sink.journal_entries()
    by_det = {rec["detector"]: rec for rec in recs}
    if set(by_det) != {"exp-det", "stable-det"}:
        return _gap("want both detectors journaled, got %r"
                    % (sorted(by_det),))
    exp_rec = by_det["exp-det"]
    if exp_rec["record_type"] != "observation":
        return _gap("experimental match must be an observation, got %r"
                    % (exp_rec["record_type"],))
    if "experimental" not in (exp_rec["reason"] or ""):
        return _gap("observation reason must name experimental maturity")
    if exp_rec["maturity"] != "experimental":
        return _gap("maturity not recorded: %r" % (exp_rec["maturity"],))
    if by_det["stable-det"]["record_type"] != "alert":
        return _gap("stable twin must alert")
    # Enforcement gating: experimental can never gate; unknown fails closed.
    if sink.may_gate_enforcement("exp-det") is not False:
        return _gap("experimental detector may gate enforcement")
    if sink.may_gate_enforcement("stable-det") is not True:
        return _gap("stable detector may not gate enforcement")
    if sink.may_gate_enforcement("nope") is not False:
        return _gap("unknown detector may gate enforcement (fail-open)")
    return _held("experimental = observation-only, cannot gate enforcement; "
                 "stable gates; unknown fails closed")


@probe("deprecated_refused")
def _p_deprecated():
    r = _need_alert()
    if r:
        if not _HAVE_DET:
            return r
        eng = det.DetectorEngine()
        try:
            eng.register(_base_def(maturity="deprecated"))
        except det.DetectorRegistrationError as exc:
            if exc.code == "detector-deprecated":
                return _held("unreachable pre-fix")
            return _gap("deprecated discipline absent (got %s)" % exc.code)
        return _gap("deprecated detector loaded silently")
    eng = det.DetectorEngine()
    ok, why = _refused_with(
        lambda: eng.register(_base_def(maturity="deprecated")),
        "detector-deprecated")
    if not ok:
        return _gap("deprecated: %s" % why)
    if eng.detectors:
        return _gap("deprecated load left residue")
    ok2, why2 = _refused_with(
        lambda: eng.register(_base_def(maturity="beta")),
        "detector-unknown-maturity")
    if not ok2:
        return _gap("unknown maturity: %s" % why2)
    return _held("deprecated refuses to load (detector-deprecated); "
                 "unknown maturity refused (detector-unknown-maturity)")


@probe("chained_exception_evaluation")
def _p_chained():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(
        name="chain-base",
        produces={"event_name": "base_fired", "event_schema_version": "1.0.0",
                  "fields": {"agent": {"from_field": "agent_id"}}}))
    eng.register(_base_def(
        name="chain-child", priority="error",
        event_selector={"produced_by": "chain-base"},
        predicates=[{"field": "fields.agent", "op": "exists"}],
        produces={"event_name": "child_fired",
                  "event_schema_version": "1.0.0", "fields": {}},
        exceptions=[_exc_block(name="svc-allow", fields=["fields.agent"],
                               comps=["eq"], values=[["svc-account"]])],
        subscribes=["chain-base"]))
    sink = _sink(eng)
    produced = sink.process({"type": "probe_event", "flag": True,
                             "agent_id": "svc-account"})
    if len(produced) != 2:
        return _gap("chain did not fire twice: %r" % (produced,))
    recs = sink.journal_entries()
    if len(recs) != 2:
        return _gap("want 2 journal records, got %d" % len(recs))
    child_recs = [rec for rec in recs if rec["detector"] == "chain-child"]
    if len(child_recs) != 1:
        return _gap("child not journaled once")
    child_rec = child_recs[0]
    if child_rec["record_type"] != "suppressed":
        return _gap("child exception on produced fields must suppress, "
                    "got %r" % (child_rec["record_type"],))
    child_produced = [p for p in produced
                      if p["detector"] == "chain-child"][0]
    if child_rec["event_digest"] != child_produced["produced_from"]:
        return _gap("child digest != digest of the matched produced event")
    if "_engine_stamp" in json.dumps(child_rec):
        return _gap("internal stamp leaked into the alert record")
    return _held("exceptions evaluate over chained produced events; "
                 "suppression journaled with the produced-event digest")


@probe("journal_durability")
def _p_durable():
    r = _need_alert()
    if r:
        return r
    tmpd = tempfile.mkdtemp(prefix="w262-alert-journal-")
    path = os.path.join(tmpd, "alerts.jsonl")
    eng = det.DetectorEngine()
    eng.register(_base_def(name="dur-det", priority="warning"))
    sink = _sink(eng, journal_path=path)
    sink.process({"type": "probe_event", "flag": True})
    sink.process({"type": "probe_event", "flag": True})
    mem = sink.journal_entries()
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if len(lines) != len(mem):
        return _gap("journal file has %d lines, memory has %d"
                    % (len(lines), len(mem)))
    for i, line in enumerate(lines):
        if json.loads(line) != mem[i]:
            return _gap("line %d differs from memory" % i)
        if json.loads(line)["seq"] != i:
            return _gap("line %d seq wrong" % i)
    return _held("every record appended to the durable JSONL journal "
                 "(seq-ordered, byte-equal to memory)")


@probe("alert_record_shape")
def _p_record_shape():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="shape-det", priority="critical"))
    sink = _sink(eng)
    sink.process({"type": "probe_event", "flag": True})
    recs = sink.journal_entries()
    if len(recs) != 1:
        return _gap("want 1 record, got %d" % len(recs))
    rec = recs[0]
    want_keys = {"record_type", "seq", "detector", "detector_version",
                 "priority", "maturity", "event_digest",
                 "exception_decision", "reason"}
    if set(rec.keys()) != want_keys:
        return _gap("record keys wrong: %r" % (sorted(rec.keys()),))
    if not (rec["record_type"] == "alert" and rec["seq"] == 0
            and rec["detector"] == "shape-det"
            and rec["detector_version"] == "1.0.0"
            and rec["priority"] == "critical"
            and rec["maturity"] == "stable"
            and rec["reason"] is None):
        return _gap("record fields wrong: %r" % (rec,))
    if len(rec["event_digest"]) != 64 or any(
            ch not in "0123456789abcdef" for ch in rec["event_digest"]):
        return _gap("event_digest not 64-hex")
    # F243 (wave-264): the exception decision now also carries the
    # effective exception values and the policy revision in force, so
    # a widening values-override is attributable from the record
    # alone. Schema pin repointed from the wave-262 shape.
    want_ed = {"evaluated", "matched", "disabled_but_matched",
               "suppressing_exception", "decision", "effective_values",
               "policy_revision"}
    if set(rec["exception_decision"].keys()) != want_ed:
        return _gap("exception_decision keys wrong: %r"
                    % (sorted(rec["exception_decision"].keys()),))
    if rec["exception_decision"] != {
            "evaluated": [], "matched": [], "disabled_but_matched": [],
            "suppressing_exception": None, "decision": "no-suppression",
            "effective_values": {}, "policy_revision": 0}:
        return _gap("exception_decision wrong: %r"
                    % (rec["exception_decision"],))
    return _held("alert record schema exact (F243: effective_values + "
                 "policy_revision); declared priority carried verbatim; "
                 "exception decision explicit")


@probe("w261_additivity")
def _p_additivity():
    r = _need_alert()
    if r:
        return r
    eng = det.DetectorEngine()
    try:
        eng.register_all(det.SAMPLE_DETECTORS)  # wave-261, untouched
    except det.DetectorRegistrationError as exc:
        return _gap("wave-261 sample detectors no longer load: %s" % (exc,))
    if len(eng.detectors) != 4:
        return _gap("want 4 sample detectors, got %d" % len(eng.detectors))
    # Detection behavior identical to wave-261 (Tracee half untouched).
    produced = eng.process({"type": "credential_swap", "agent_id": "agent-7",
                            "host": "evil.example", "credential_id": "cred-1"})
    if len(produced) != 1 or produced[0]["event_name"] !=\
            "credential_swap_outside_allowlist":
        return _gap("detection behavior changed: %r" % (produced,))
    # Alert half: no declared priority -> observation, never inflated.
    sink = _sink(eng)
    sink.process({"type": "credential_swap", "agent_id": "agent-7",
                  "host": "evil.example", "credential_id": "cred-1"})
    recs = sink.journal_entries()
    if len(recs) != 1:
        return _gap("sample match not journaled: %d" % len(recs))
    rec = recs[0]
    if rec["record_type"] != "observation" or rec["priority"] is not None:
        return _gap("priority-less sample must be an observation: %r"
                    % (rec,))
    if rec["maturity"] != "stable":
        return _gap("maturity must default to stable, got %r"
                    % (rec["maturity"],))
    for name in eng.detectors:
        if sink.may_gate_enforcement(name) is not True:
            return _gap("stable sample %r may not gate" % (name,))
    return _held("wave-261 definitions load/process identically; alert "
                 "half treats them as stable, priority-undeclared "
                 "observations (no inflation)")


def _green_check_adjacent():
    """Depth-1 green check: the adjacent w261 detector battery.

    Honors GOV_SKIP_GREEN=1 by recording a skip instead of spawning
    (combinatorial-nesting lesson: never nest battery mains).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "depth-1 green check skipped by convention "
                        "(evals/w261_detector_probes.py standalone)")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="w262-green-")
    env["TMPDIR"] = tmpd
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, os.path.join(repo_root, "evals",
                                     "w261_detector_probes.py")],
        cwd=repo_root, env=env, capture_output=True, text=True,
        timeout=600)
    tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
    tail = tail[-1:] or [""]
    return ("PASS" if proc.returncode == 0 else "FAIL",
            "adjacent w261 battery rc=%d %s" % (proc.returncode, tail[0]))


def main():
    results = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- harness must not die
            verdict, detail = ("ERROR", "%r" % (exc,))
        results.append((name, verdict, detail))
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("w262 alert-discipline probes: %d/%d HELD "
          "(GOV_DEPLOYMENT_MODE=%s)" % (
              held, len(results),
              os.environ.get("GOV_DEPLOYMENT_MODE", "<unset>")))
    for name, verdict, detail in results:
        print("  [%s] %s %s" % (verdict, name,
                                ("-- " + detail) if detail else ""))
    gverdict, gdetail = _green_check_adjacent()
    print("  [%s] green_check_adjacent_w261 -- %s" % (gverdict, gdetail))
    bad = [r for r in results if r[1] != "HELD"]
    if bad:
        print("FAIL: %d probe(s) not HELD" % (len(bad),))
        return 1
    if gverdict == "FAIL":
        print("FAIL: adjacent green check failed")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
