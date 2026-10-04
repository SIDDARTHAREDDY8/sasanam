#!/usr/bin/env python3
"""Break-first closure battery for F243/F244 (wave-264 lane B).

Targets (base 7fa1114729d3374e71eb0b88e43698c4b919f142, pin 1151):
A. F243 (LOW): gov/detectors.py deployment-policy values-overrides were
   invisible in alert records -- AlertSink._record journaled the
   exception decision but not the EFFECTIVE exception values after the
   policy override, so a widening override silently re-armed the rule.
   Fixed: alert records carry the effective exception values (plus a
   policy-overridden flag) and the policy revision in force, so a
   widening override is attributable from the record alone.
B. F244 (LOW): gov/detectors.py DetectorEngine.detectors returned
   dict(self._detectors) -- a shallow copy whose values were the LIVE
   validated definition dicts, so runtime mutation bypassed every
   load-time LOUD refusal with no journal. Fixed: deep copies; mutating
   the returned structure cannot change engine/sink behavior.
C. F175 regression pin: evals/f143mem_break.py (p8) runs in the green
   check; F175's send_email fingerprint closure must stay effective.

Method (diagnosing-bugs skill): red-first at the public seams. Each
probe BREAKs on the pre-fix code (verified) and HELDs post-fix.
Verdicts: HELD (gap closed / control holds), BREAK (defect present),
ERROR (harness bug -- fix the harness). No BASELINE here: controls
stay HELD on both.

Stdlib only. Deterministic (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail
closed). Green checks are depth-1 and honor GOV_SKIP_GREEN=1.
"""

import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov import decision_codes
from gov import detectors as det

TAXONOMY_PIN = 2006 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


# ------------------------------------------------------------ fixtures

def _det_base(name="w264-det", **kw):
    d = {"name": name, "version": "1.0.0",
         "description": "w264 probe detector",
         "event_selector": {"type": "probe_event"},
         "predicates": [{"field": "flag", "op": "eq", "value": True}],
         "produces": {"event_name": name + "_fired",
                      "event_schema_version": "1.0.0", "fields": {}},
         "subscribes": [],
         "threat": {"severity": "low", "description": "probe"}}
    d.update(kw)
    return d


def _exc_block(**kw):
    b = {"name": "allow-ci", "description": "probe exception",
         "fields": ["host"], "comps": ["startswith"],
         "values": [["ci.internal.example"]]}
    b.update(kw)
    return b


# ----------------------------------------------------------------- F243

@probe("f243/widening-override-attributable")
def _p_override_visible():
    """F243: a deployment-policy values override that widens an
    exception must be attributable from the alert record alone.

    BREAK (pre-fix): 'suppressed' record names the exception but the
    record cannot show the widening -- no effective values, no policy
    revision, no override flag. HELD (fixed): exception_decision
    carries effective_values {exc: {values, policy_overridden}} and
    policy_revision, and they describe the WIDENED values."""
    eng = det.DetectorEngine()
    eng.register(_det_base(priority="notice", exceptions=[_exc_block()]))
    # startswith + [""] matches every string host: total re-arm.
    sink = det.AlertSink(
        eng, policy={"exceptions":
                     {"w264-det": {"allow-ci": {"values": [[""]]}}}})
    sink.process({"type": "probe_event", "flag": True,
                  "host": "attacker.example"})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "suppressed":
        return ("ERROR", "widening override did not suppress: %r"
                % rec["record_type"])
    exc = rec["exception_decision"]
    eff = exc.get("effective_values")
    rev = exc.get("policy_revision")
    if not isinstance(eff, dict) or "allow-ci" not in eff:
        return _break(
            "suppressed record carries no effective_values for the "
            "matched exception: keys=%r -- the widening is invisible"
            % sorted(exc.keys()))
    got = eff["allow-ci"]
    if got.get("values") != [[""]] or not got.get("policy_overridden"):
        return _break(
            "effective_values does not describe the widened values: "
            "%r" % (got,))
    if not isinstance(rev, int):
        return _break(
            "record carries no policy revision in force: %r" % (rev,))
    return _held(
        "suppression attributable from the record alone: effective "
        "values %r (policy_overridden=True), policy_revision=%d"
        % (got["values"], rev))


@probe("f243/disable-path-still-journaled")
def _p_disable_control():
    """Control (HELD on both): disabling an exception still fails
    closed to alert and journals disabled_but_matched -- the F243 fix
    must not regress the never-silent disable path."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w264-dis", priority="notice",
                           exceptions=[_exc_block()]))
    sink = det.AlertSink(
        eng, policy={"exceptions":
                     {"w264-dis": {"allow-ci": {"enabled": False}}}})
    sink.process({"type": "probe_event", "flag": True,
                  "host": "ci.internal.example"})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "alert":
        return ("ERROR", "disabled exception suppressed: %r"
                % rec["record_type"])
    dbm = rec["exception_decision"].get("disabled_but_matched")
    if dbm != ["allow-ci"]:
        return ("ERROR", "disabled_but_matched wrong: %r" % (dbm,))
    return _held("disable fails closed to alert; re-arming journaled")


@probe("f243/policy-revision-tracked")
def _p_revision_tracked():
    """F243: records must carry the policy revision in force, and a
    set_policy must move the revision so an auditor can tell which
    policy produced which record.

    BREAK (pre-fix): no policy_revision key at all -- an auditor
    cannot tell whether the record came before or after a policy
    change. HELD (fixed): revision present, increments on
    set_policy, records track it."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w264-rev", priority="notice",
                           exceptions=[_exc_block()]))
    sink = det.AlertSink(eng)
    sink.process({"type": "probe_event", "flag": True,
                  "host": "attacker.example"})
    r0 = sink.journal_entries()[-1]["exception_decision"].get(
        "policy_revision")
    sink.set_policy({"exceptions":
                     {"w264-rev": {"allow-ci": {"values": [[""]]}}}})
    sink.process({"type": "probe_event", "flag": True,
                  "host": "attacker.example"})
    recs = sink.journal_entries()
    r1 = recs[-1]["exception_decision"].get("policy_revision")
    if not isinstance(r0, int) or not isinstance(r1, int):
        return _break(
            "records carry no policy revision (r0=%r, r1=%r): a policy "
            "change is undiscoverable from the journal" % (r0, r1))
    if r1 != r0 + 1:
        return _break(
            "policy revision did not advance on set_policy: %r -> %r"
            % (r0, r1))
    if recs[0]["record_type"] != "alert":
        return ("ERROR", "pre-policy record should alert: %r"
                % recs[0]["record_type"])
    if recs[-1]["record_type"] != "suppressed":
        return ("ERROR", "post-policy record should suppress: %r"
                % recs[-1]["record_type"])
    return _held("policy_revision %d -> %d across set_policy; records "
                 "track the policy in force" % (r0, r1))


# ----------------------------------------------------------------- F244

@probe("f244/maturity-mutation-no-effect")
def _p_maturity_mutation():
    """F244: mutating the dict returned by DetectorEngine.detectors
    must not change engine/sink behavior.

    BREAK (pre-fix): maturity stable->experimental flips
    may_gate_enforcement True->False and turns the next match into an
    observation. HELD (fixed): the mutation is against a copy; the
    sink still gates and still alerts."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w264-mut", priority="critical"))
    sink = det.AlertSink(eng)
    if not sink.may_gate_enforcement("w264-mut"):
        return ("ERROR", "stable detector cannot gate?")
    eng.detectors["w264-mut"]["maturity"] = "experimental"
    if not sink.may_gate_enforcement("w264-mut"):
        return _break(
            "runtime maturity flip via detectors[...] flipped gating "
            "True->False: the accessor leaks the live definition")
    sink.process({"type": "probe_event", "flag": True})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] != "alert":
        return _break(
            "runtime maturity flip turned the match into %r: live "
            "definition mutated through the accessor"
            % rec["record_type"])
    # The accessor must also return a FRESH copy each time: mutating
    # one return must not poison the next.
    first = eng.detectors["w264-mut"]
    first["maturity"] = "experimental"
    if eng.detectors["w264-mut"]["maturity"] != "stable":
        return _break("mutation of one accessor return leaked into the "
                      "next access")
    return _held("accessor returns deep copies; runtime maturity flip "
                 "has no effect on gating or records")


@probe("f244/exceptions-rewrite-no-effect")
def _p_exceptions_rewrite():
    """F244: rewriting exceptions through the accessor must not
    suppress alerts (no validation, no journal).

    BREAK (pre-fix): exceptions rewritten at runtime suppress without
    load-time validation. HELD (fixed): the live definition is
    untouched, the match still alerts."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w264-mut2", priority="notice",
                           exceptions=[_exc_block()]))
    sink = det.AlertSink(eng)
    eng.detectors["w264-mut2"]["exceptions"] = [
        {"name": "allow-ci", "fields": ["host"], "comps": ["startswith"],
         "values": [[""]]}]
    sink.process({"type": "probe_event", "flag": True,
                  "host": "attacker.example"})
    rec = sink.journal_entries()[-1]
    if rec["record_type"] == "suppressed":
        return _break(
            "runtime exception rewrite suppressed the alert with no "
            "validation and no journal: live definitions reachable "
            "through the accessor")
    if rec["record_type"] != "alert":
        return ("ERROR", "expected alert, got %r" % rec["record_type"])
    return _held("runtime exception rewrite had no effect; match "
                 "still alerts")


@probe("f244/deep-nested-mutation-no-effect")
def _p_nested_mutation():
    """F244: the pre-fix accessor was only a SHALLOW copy -- deep
    mutation (predicates list, nested dicts) also reached the live
    definition. BREAK (pre-fix): flipping the predicate value through
    detectors[...] un-matches the detector. HELD (fixed): still
    matches, still alerts."""
    eng = det.DetectorEngine()
    eng.register(_det_base(name="w264-mut3", priority="notice"))
    sink = det.AlertSink(eng)
    eng.detectors["w264-mut3"]["predicates"][0]["value"] = "no-match"
    sink.process({"type": "probe_event", "flag": True})
    recs = sink.journal_entries()
    if not recs:
        return _break(
            "deep mutation through detectors[...] un-matched the "
            "detector: the shallow copy leaked live nested state")
    if recs[-1]["record_type"] != "alert":
        return ("ERROR", "expected alert, got %r" % recs[-1]["record_type"])
    return _held("deep nested mutation had no effect; match still "
                 "alerts")


# ------------------------------------------------------------ green check

def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w262_alert_probes.py", "w263_redteam_probes.py",
                "f143mem_break.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w264-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600)
        except Exception as e:  # noqa: BLE001
            notes.append((battery, "ERROR: %s" % e))
            continue
        tail = (proc.stdout or "").strip().splitlines()[-1:]
        notes.append((battery, "exit=%d %s"
                      % (proc.returncode,
                         tail[0][:100] if tail else "")))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d"
              % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-8s %-45s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-35s %s" % (name, note))
    print("HELD %d / BREAK %d / ERROR %d over %d probes"
          % (held, breaks, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
