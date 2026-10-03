"""Break-first probes for the wave-261 declarative detector schema.

Wave-261 feature lane 3 (tracee ADAPT: declarative chained detectors;
schema + composition semantics only -- no tracee code). Stdlib only.
Deterministic across runs (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail closed).

Targets (base c2a1fc02, taxonomy pin 1092 -> 1096):
- gov/detectors.py -- declarative detector definitions (data, never code),
  closed predicate DSL, registration-time validation with machine codes,
  subscription-chain auto-resolution, produced-event trust boundary,
  per-detector error isolation with journaling.

Method (tdd skill, red-before-green): each probe is a falsifiable break
attempt written BEFORE the module. Verdicts:
  HELD -- the attack/defect is refused or handled as specified.
  GAP  -- the defect is present (pre-fix state).
  ERROR -- harness bug; fix the harness, never the product.

Pin change: 1092 -> 1096. Four new machine codes (domain `detector`):
detector-cycle, detector-duplicate-name, detector-malformed,
detector-unknown-predicate. Value-token-only note for the merge
coordinator: this battery asserts the post-lane count; all older
batteries still pin 1092 and must be repointed at merge.
"""

import os
import sys

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

# Wave-261 feature lane 3: +4 detector-* machine codes -> 1092 -> 1096.
# Assert on the deduped dict AND on raw source literals (wave-260 lesson:
# duplicate "code" literals are invisible to len(TAXONOMY)).
TAXONOMY_PIN = 1869  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

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


def _error(detail=""):
    return ("ERROR", detail)


def _need_det():
    if not _HAVE_DET:
        return ("GAP", "gov/detectors.py absent (red baseline)")
    return None


def _base_def(name="p1", **over):
    d = {
        "name": name,
        "version": "1.0.0",
        "description": "probe detector",
        "event_selector": {"type": "probe_event"},
        "predicates": [{"field": "flag", "op": "eq", "value": True}],
        "produces": {
            "event_name": "probe_fired",
            "event_schema_version": "1.0.0",
            "fields": {"flag": {"from_field": "flag"}},
        },
        "threat": {"severity": "low", "description": "probe"},
        "subscribes": [],
    }
    d.update(over)
    return d


def _is_refusal(exc, code):
    return (isinstance(exc, det.DetectorRegistrationError)
            and exc.code == code)


# ---------------------------------------------------------------- pin

@probe("taxonomy_pin_1096")
def _p_pin():
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        return _gap("taxonomy has %d keys, pin is %d" % (n, TAXONOMY_PIN))
    # Source-literal check (wave-260 lesson): duplicate "code" literals
    # are invisible to len(TAXONOMY).
    import re
    src = open(os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "..", "gov",
        "decision_codes.py")).read()
    lits = re.findall(r'"code": \'(detector-[a-z-]+)\'', src)
    # Wave-262 alert lane: +4 detector-* codes (detector-deprecated,
    # detector-exception-malformed, detector-unknown-maturity,
    # detector-unknown-priority) -- the expected literal set grows.
    if sorted(set(lits)) != ["detector-cycle", "detector-deprecated",
                             "detector-duplicate-name",
                             "detector-exception-malformed",
                             "detector-malformed",
                             "detector-unknown-maturity",
                             "detector-unknown-predicate",
                             "detector-unknown-priority"]:
        return _gap("detector-* source literals wrong: %r" % (lits,))
    if len(lits) != 8:
        return _gap("detector-* literal duplicated in source: %r" % (lits,))
    return _held("1110 keys; 8 detector-* literals, each exactly once")


# ------------------------------------------------- injection / dsl

@probe("predicate_injection_dunder")
def _p_dunder():
    r = _need_det()
    if r:
        return r
    bad_paths = ["__class__", "a.__class__", "a.__class__.__bases__",
                 "__proto__", "a.__dict__", "__class__.__mro__"]
    for path in bad_paths:
        d = _base_def(name="inj-%d" % abs(hash(path)),
                      predicates=[{"field": path, "op": "eq",
                                   "value": "x"}])
        try:
            det.DetectorEngine().register(d)
        except Exception as exc:  # noqa: BLE001 -- any refusal counts
            if _is_refusal(exc, det.CODE_UNKNOWN_PREDICATE):
                continue
            return _error("wrong refusal for %r: %r" % (path, exc))
        return _gap("dunder path accepted at registration: %r" % (path,))
    # Eval-time: even a hand-built detector must not traverse.
    eng = det.DetectorEngine()
    eng.register(_base_def(name="ok"))
    clean = eng.process({"type": "probe_event", "flag": True})
    dirty = eng.process({"type": "probe_event", "flag": True,
                         "__class__": "polluted"})
    if ([e["event_name"] for e in clean]
            != [e["event_name"] for e in dirty]):
        return _gap("dunder key in event influenced matching")
    return _held("dunder/proto paths refused at registration; "
                 "dunder event keys inert at eval")


@probe("predicate_path_shape")
def _p_path_shape():
    r = _need_det()
    if r:
        return r
    bad = [".a", "a.", "a..b", "", "a b", "a-b", "a/b",
           "a." * 9 + "b",  # depth > 8
           "x" * 200]        # length > 128
    for path in bad:
        d = _base_def(name="shape-%d" % abs(hash(path)),
                      predicates=[{"field": path, "op": "eq",
                                   "value": "x"}])
        try:
            det.DetectorEngine().register(d)
        except Exception as exc:  # noqa: BLE001
            if _is_refusal(exc, det.CODE_UNKNOWN_PREDICATE):
                continue
            return _error("wrong refusal for %r: %r" % (path, exc))
        return _gap("malformed path accepted: %r" % (path,))
    return _held("malformed field paths refused loudly")


@probe("unknown_predicate_op")
def _p_unknown_op():
    r = _need_det()
    if r:
        return r
    for i, op in enumerate(["eval", "regex", "cel", "lambda", "exec",
                           "EVAL", ""]):
        d = _base_def(name="op-%d" % i,
                      predicates=[{"field": "flag", "op": op,
                                   "value": True}])
        try:
            det.DetectorEngine().register(d)
        except Exception as exc:  # noqa: BLE001
            if _is_refusal(exc, det.CODE_UNKNOWN_PREDICATE):
                continue
            return _error("wrong refusal for op %r: %r" % (op, exc))
        return _gap("unknown op accepted: %r" % (op,))
    return _held("closed op vocabulary enforced (no eval/regex/cel)")


@probe("predicate_operand_shape")
def _p_operand_shape():
    r = _need_det()
    if r:
        return r
    bad_preds = [
        {"field": "flag", "op": "in", "value": "notalist"},
        {"field": "flag", "op": "in", "value": []},
        {"field": "flag", "op": "exists", "value": True},
        {"field": "flag", "op": "gt", "other_field": "__class__"},
        {"field": "flag", "op": "eq"},  # neither value nor other_field
        {"field": "flag", "op": "eq", "value": 1, "other_field": "x"},
    ]
    for i, p in enumerate(bad_preds):
        d = _base_def(name="operand-%d" % i, predicates=[p])
        try:
            det.DetectorEngine().register(d)
        except Exception as exc:  # noqa: BLE001
            if _is_refusal(exc, det.CODE_UNKNOWN_PREDICATE):
                continue
            return _error("wrong refusal for %r: %r" % (p, exc))
        return _gap("malformed operand accepted: %r" % (p,))
    return _held("operand shapes validated at registration")


# ------------------------------------------- registration validation

@probe("malformed_definitions")
def _p_malformed():
    r = _need_det()
    if r:
        return r
    bad = [
        ("no-name", {k: v for k, v in _base_def().items()
                     if k != "name"}),
        ("bad-name", _base_def(name="UPPER CASE!")),
        ("bad-version", _base_def(version="1.0")),
        ("no-predicates", _base_def(
            predicates=[])),
        ("predicates-not-list", _base_def(
            predicates={"field": "flag", "op": "eq", "value": 1})),
        ("bad-produces-version", _base_def(produces={
            "event_name": "x", "event_schema_version": "v1",
            "fields": {}})),
        ("bad-mitre", _base_def(threat={"mitre": ["T999"],
                                       "severity": "high",
                                       "description": "x"})),
        ("bad-selector-key", _base_def(
            event_selector={"type": "x", "host": "y"})),
        ("not-a-dict", ["nope"]),
    ]
    for label, d in bad:
        try:
            det.DetectorEngine().register(d)
        except Exception as exc:  # noqa: BLE001
            if _is_refusal(exc, det.CODE_MALFORMED):
                continue
            return _error("wrong refusal for %s: %r" % (label, exc))
        return _gap("malformed definition accepted: %s" % (label,))
    return _held("9 malformed shapes refused with detector-malformed")


@probe("duplicate_name")
def _p_duplicate():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="dup"))
    try:
        eng.register(_base_def(name="dup"))
    except Exception as exc:  # noqa: BLE001
        if not _is_refusal(exc, det.CODE_DUPLICATE_NAME):
            return _error("wrong refusal: %r" % (exc,))
    else:
        return _gap("duplicate name accepted")
    if len(eng.detectors) != 1:
        return _gap("duplicate registration mutated engine state")
    return _held("duplicate name refused; engine state unchanged")


@probe("dangling_subscription")
def _p_dangling():
    r = _need_det()
    if r:
        return r
    d = _base_def(name="dang", subscribes=["ghost"])
    try:
        det.DetectorEngine().register(d)
    except Exception as exc:  # noqa: BLE001
        if _is_refusal(exc, det.CODE_MALFORMED):
            return _held("dangling subscription refused "
                         "with detector-malformed")
        return _error("wrong refusal: %r" % (exc,))
    return _gap("dangling subscription accepted")


@probe("registration_atomicity")
def _p_atomic():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    good = _base_def(name="good")
    bad = _base_def(name="bad!!")
    try:
        eng.register_all([good, bad])
    except Exception as exc:  # noqa: BLE001
        if not _is_refusal(exc, det.CODE_MALFORMED):
            return _error("wrong refusal: %r" % (exc,))
    else:
        return _gap("bad batch accepted")
    if eng.detectors:
        return _gap("partial batch registered (not atomic): %r"
                    % (list(eng.detectors),))
    return _held("register_all is atomic: all-or-nothing")


# ------------------------------------------------- chains / cycles

@probe("subscription_cycle")
def _p_cycle():
    r = _need_det()
    if r:
        return r
    a = _base_def(name="cyc-a", subscribes=["cyc-b"],
                  event_selector={"produced_by": "cyc-b"})
    b = _base_def(name="cyc-b", subscribes=["cyc-a"],
                  event_selector={"produced_by": "cyc-a"})
    eng = det.DetectorEngine()
    try:
        eng.register_all([a, b])
    except Exception as exc:  # noqa: BLE001
        if not _is_refusal(exc, det.CODE_CYCLE):
            return _error("wrong refusal for 2-cycle: %r" % (exc,))
    else:
        return _gap("2-cycle accepted")
    if eng.detectors:
        return _gap("cyclic batch partially registered")
    # Self-subscription is a 1-cycle.
    s = _base_def(name="self", subscribes=["self"],
                  event_selector={"produced_by": "self"})
    try:
        det.DetectorEngine().register_all([s])
    except Exception as exc:  # noqa: BLE001
        if _is_refusal(exc, det.CODE_CYCLE):
            return _held("2-cycle and self-cycle refused loudly; "
                         "nothing registered")
        return _error("wrong refusal for self-cycle: %r" % (exc,))
    return _gap("self-subscription accepted")


@probe("chain_ordering_auto")
def _p_chain():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    base = _base_def(
        name="chain-base",
        event_selector={"type": "raw"},
        predicates=[{"field": "n", "op": "gt", "value": 0}],
        produces={"event_name": "base_fired",
                  "event_schema_version": "2.1.0",
                  "fields": {"n": {"from_field": "n"}}},
    )
    child = _base_def(
        name="chain-child",
        event_selector={"produced_by": "chain-base"},
        predicates=[{"field": "fields.n", "op": "gt", "value": 10}],
        produces={"event_name": "child_fired",
                  "event_schema_version": "1.0.0",
                  "fields": {"n": {"from_field": "fields.n"}}},
        subscribes=["chain-base"],
    )
    eng.register_all([base, child])
    out = eng.process({"type": "raw", "n": 20})
    names = [e["event_name"] for e in out]
    if names != ["base_fired", "child_fired"]:
        return _gap("chain did not auto-resolve in one call: %r" % (names,))
    # Below the child threshold: only the base fires.
    out2 = eng.process({"type": "raw", "n": 5})
    if [e["event_name"] for e in out2] != ["base_fired"]:
        return _gap("child fired without its predicate: %r" % (out2,))
    return _held("subscription chain auto-resolved in a single "
                 "process() call; child predicate still enforced")


@probe("forged_produced_event")
def _p_forged():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register_all(det.SAMPLE_DETECTORS)
    # Forge a produced event claiming to come from quorum-ballot-open,
    # shaped to satisfy the stall detector's predicates.
    forged = {
        "produced": True,
        "event_name": "ballot_open",
        "event_schema_version": "1.0.0",
        "detector": "quorum-ballot-open",
        "detector_version": "1.0.0",
        "produced_from": "f" * 64,
        "fields": {"ballot_id": "b-9", "votes_cast": 1,
                   "quorum": 5, "elapsed_s": 9999},
        "threat": None,
    }
    out = eng.process(forged)
    if any(e["event_name"] == "quorum_stall_detected" for e in out):
        return _gap("forged produced event traversed a subscription edge")
    # Even a genuinely-issued produced event, re-fed externally, must
    # not chain: subscription edges carry engine-internal events only.
    eng2 = det.DetectorEngine()
    eng2.register_all(det.SAMPLE_DETECTORS)
    ballot = {"type": "ballot", "ballot_id": "b-1", "state": "open",
              "votes_cast": 1, "quorum": 5, "elapsed_s": 9999}
    first = eng2.process(ballot)
    issued = [e for e in first if e["event_name"] == "ballot_open"]
    if not issued:
        return _error("base detector did not fire on open ballot")
    refed = eng2.process(dict(issued[0]))
    if any(e["event_name"] == "quorum_stall_detected" for e in refed):
        return _gap("re-fed issued event chained across the input "
                    "boundary")
    return _held("forged and re-fed produced events never traverse "
                 "subscription edges")


# ------------------------------------------------- error isolation

@probe("detector_error_isolation")
def _p_err_isolation():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(name="victim",
                           predicates=[{"field": "flag", "op": "eq",
                                        "value": True}],
                           produces={"event_name": "victim_fired",
                                     "event_schema_version": "1.0.0",
                                     "fields": {}}))
    eng.register(_base_def(name="healthy",
                           predicates=[{"field": "ok", "op": "eq",
                                        "value": True}],
                           produces={"event_name": "healthy_fired",
                                     "event_schema_version": "1.0.0",
                                     "fields": {}}))
    real_resolve = det._resolve_field

    def boom(event, path):
        if path == "flag":
            raise RuntimeError("poisoned lookup")
        return real_resolve(event, path)

    det._resolve_field = boom
    try:
        produced = eng.process_stream([
            {"type": "probe_event", "flag": True, "ok": True},
            {"type": "probe_event", "flag": True, "ok": True},
        ])
    finally:
        det._resolve_field = real_resolve
    stats = eng.stats()
    if stats["detector_errors"] != 2:
        return _gap("errors counted = %d, want 2" % stats["detector_errors"])
    names = [e["event_name"] for e in produced]
    if names.count("healthy_fired") != 2:
        return _gap("healthy detector starved by victim error: %r"
                    % (names,))
    if names.count("victim_fired") != 0:
        return _gap("erroring detector still produced")
    journal = eng.journal_entries()
    if len(journal) != 2 or not all(
            j["type"] == "detector_error" and j["detector"] == "victim"
            and len(j.get("event_digest", "")) == 64 for j in journal):
        return _gap("error journal malformed: %r" % (journal,))
    if stats["events_seen"] != 2:
        return _gap("stream dropped events: %r" % (stats,))
    return _held("per-detector errors counted+journaled; stream and "
                 "healthy detectors unaffected")


@probe("process_rejects_nondict")
def _p_nondict():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def())
    for bad in ["nope", None, 42, ["type"]]:
        try:
            eng.process(bad)
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001
            return _error("wrong exception for %r: %r" % (bad, exc))
        else:
            return _gap("non-dict event silently accepted: %r" % (bad,))
    return _held("non-dict events refused loudly (TypeError)")


# ------------------------------------------------- samples

@probe("sample_cred_swap")
def _p_cred():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register_all(det.SAMPLE_DETECTORS)
    evil = {"type": "credential_swap", "agent_id": "agent-7",
            "host": "evil.example", "credential_id": "cred-1"}
    out = eng.process(evil)
    if len(out) != 1:
        return _gap("cred-swap detector misfired: %r" % (out,))
    e = out[0]
    if (e["event_name"] != "credential_swap_outside_allowlist"
            or e["event_schema_version"] != "1.0.0"
            or e["fields"].get("host") != "evil.example"
            or e["fields"].get("agent_id") != "agent-7"
            or e["threat"].get("mitre") != ["T1550"]):
        return _gap("produced event shape wrong: %r" % (e,))
    ok = {"type": "credential_swap", "agent_id": "agent-7",
          "host": "vault.internal.example", "credential_id": "cred-1"}
    if eng.process(ok):
        return _gap("allowlisted host fired the detector")
    missing = {"type": "credential_swap", "agent_id": "agent-7"}
    if eng.process(missing):
        return _gap("missing host fired the detector (false positive)")
    return _held("credential-swap detector: fires off-allowlist only, "
                 "versioned event, T1550 tagged")


@probe("sample_policy_rollback")
def _p_rollback():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register_all(det.SAMPLE_DETECTORS)
    rb = {"type": "policy_version_observed", "policy_id": "p-1",
          "observed_version": 3, "expected_min_version": 7}
    out = eng.process(rb)
    if len(out) != 1 or out[0]["event_name"] != "policy_rollback_detected":
        return _gap("rollback not detected: %r" % (out,))
    if out[0]["threat"].get("mitre") != ["T1562"]:
        return _gap("rollback threat metadata wrong: %r" % (out[0],))
    fine = {"type": "policy_version_observed", "policy_id": "p-1",
            "observed_version": 7, "expected_min_version": 7}
    if eng.process(fine):
        return _gap("equal versions flagged as rollback")
    return _held("policy-version rollback detected via field-to-field "
                 "comparison; T1562 tagged")


@probe("sample_quorum_stall_chain")
def _p_stall():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register_all(det.SAMPLE_DETECTORS)
    stalled = {"type": "ballot", "ballot_id": "b-1", "state": "open",
               "votes_cast": 1, "quorum": 5, "elapsed_s": 9999}
    out = eng.process(stalled)
    names = [e["event_name"] for e in out]
    if names != ["ballot_open", "quorum_stall_detected"]:
        return _gap("stall chain wrong: %r" % (names,))
    stall = [e for e in out if e["event_name"]
             == "quorum_stall_detected"][0]
    if stall["fields"].get("ballot_id") != "b-1":
        return _gap("stall provenance lost: %r" % (stall,))
    fresh = {"type": "ballot", "ballot_id": "b-2", "state": "open",
             "votes_cast": 1, "quorum": 5, "elapsed_s": 10}
    names2 = [e["event_name"] for e in eng.process(fresh)]
    if names2 != ["ballot_open"]:
        return _gap("fresh ballot flagged stalled: %r" % (names2,))
    closed = {"type": "ballot", "ballot_id": "b-3", "state": "closed",
              "votes_cast": 1, "quorum": 5, "elapsed_s": 9999}
    if eng.process(closed):
        return _gap("closed ballot produced events")
    return _held("quorum stall detected through the subscription chain "
                 "in one pass; no false positives")


# ------------------------------------------------- produced shape

@probe("produced_event_schema")
def _p_shape():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(
        name="shp",
        produces={"event_name": "shp_fired",
                  "event_schema_version": "3.2.1",
                  "fields": {"a": {"from_field": "flag"},
                             "b": {"literal": "fixed"},
                             "c": {"from_field": "absent.deep"}}},
    ))
    out = eng.process({"type": "probe_event", "flag": True})
    if len(out) != 1:
        return _gap("no production: %r" % (out,))
    e = out[0]
    want_keys = {"produced", "event_name", "event_schema_version",
                 "detector", "detector_version", "produced_from",
                 "fields", "threat"}
    if set(e.keys()) != want_keys:
        return _gap("produced keys wrong: %r" % (sorted(e.keys()),))
    if not (e["produced"] is True and e["detector"] == "shp"
            and e["detector_version"] == "1.0.0"
            and e["event_schema_version"] == "3.2.1"):
        return _gap("produced provenance wrong: %r" % (e,))
    if len(e["produced_from"]) != 64 or any(
            ch not in "0123456789abcdef" for ch in e["produced_from"]):
        return _gap("produced_from not a 64-hex digest")
    if e["fields"] != {"a": True, "b": "fixed", "c": None}:
        return _gap("field mapping wrong: %r" % (e["fields"],))
    if "_engine_stamp" in e:
        return _gap("internal stamp leaked to caller")
    return _held("produced events are versioned, provenance-stamped, "
                 "schema-stable (missing -> null)")


@probe("missing_field_no_false_positive")
def _p_missing():
    r = _need_det()
    if r:
        return r
    eng = det.DetectorEngine()
    eng.register(_base_def(
        name="m1",
        predicates=[{"field": "nope", "op": "eq", "value": 1}]))
    eng.register(_base_def(
        name="m2", event_selector={"type": "probe_event"},
        predicates=[{"field": "nope", "op": "ne", "value": 1}],
        produces={"event_name": "m2_fired",
                  "event_schema_version": "1.0.0", "fields": {}}))
    eng.register(_base_def(
        name="m3",
        predicates=[{"field": "nope", "op": "gt", "value": 1}],
        produces={"event_name": "m3_fired",
                  "event_schema_version": "1.0.0", "fields": {}}))
    eng.register(_base_def(
        name="m4",
        predicates=[{"field": "nope", "op": "startswith",
                     "value": "x"}],
        produces={"event_name": "m4_fired",
                  "event_schema_version": "1.0.0", "fields": {}}))
    eng.register(_base_def(
        name="m5",
        predicates=[{"field": "nope", "op": "not_exists"}],
        produces={"event_name": "m5_fired",
                  "event_schema_version": "1.0.0", "fields": {}}))
    out = eng.process({"type": "probe_event", "flag": True})
    names = sorted(e["event_name"] for e in out)
    # m1..m4 must not fire (missing field never matches a value
    # predicate, ne included); m5 (not_exists) fires.
    if names != ["m5_fired"]:
        return _gap("missing-field semantics wrong: %r" % (names,))
    return _held("missing fields never match value predicates "
                 "(ne included); exists/not_exists explicit")


def main():
    results = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- harness must not die
            verdict, detail = ("ERROR", "%r" % (exc,))
        results.append((name, verdict, detail))
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("w261 detector probes: %d/%d HELD "
          "(GOV_DEPLOYMENT_MODE=%s)" % (
              held, len(results),
              os.environ.get("GOV_DEPLOYMENT_MODE", "<unset>")))
    for name, verdict, detail in results:
        print("  [%s] %s %s" % (verdict, name,
                                ("-- " + detail) if detail else ""))
    bad = [r for r in results if r[1] != "HELD"]
    if bad:
        print("FAIL: %d probe(s) not HELD" % (len(bad),))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
