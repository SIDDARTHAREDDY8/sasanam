"""Wave-288 red-first battery: verifier-side evidence admission policy.

Base: wave-287 merge add3e92 (gov/evidence_admission.py absent).
Post-build: all probes HELD.

Pattern: notaryproject/notation verifier-side trust-policy language
(strict/permissive/audit/skip ladder, non-overridable integrity floor,
fail-closed on no-applicable-policy), clean-room stdlib-only.

Run:
  mkdir -p /var/tmp/g288-admission && TMPDIR=/var/tmp/g288-admission \
    ~/workspace/.gov-venv/bin/python evals/w288_admission_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g288-admission2 \
    ~/workspace/.gov-venv/bin/python evals/w288_admission_probes.py
"""

import os
import re
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*); Wave-288 lane 7: pin 1684 -> 1691 (+7 admission-*); Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*)
TAXONOMY_PIN = 1780  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _need_module():
    """Import the module under test; on the base tree this BREAKs."""
    try:
        from gov import evidence_admission as ap
        return ap, None
    except ImportError as e:
        return None, e


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def p_import():
    ap, err = _need_module()
    if ap is None:
        return _record("import", "BREAK",
                       "gov/evidence_admission.py absent: %r" % (err,))
    _record("import", "HELD", "module imports")


def _policy_doc():
    return {
        "format": "admission-policy/1",
        "policy_id": "adm-test-1",
        "scopes": [
            {"scope": "provenance", "level": "strict"},
            {"scope": "inclusion-receipt", "level": "permissive"},
            {"scope": "checkpoint", "level": "audit"},
            {"scope": "bundle", "level": "skip"},
        ],
    }


def p_ladder_order():
    ap, err = _need_module()
    if ap is None:
        return _record("ladder-order", "BREAK", "module absent")
    if not (ap.STRICT > ap.PERMISSIVE > ap.AUDIT > ap.SKIP):
        return _record("ladder-order", "BREAK",
                       "level ladder not strictly ordered")
    _record("ladder-order", "HELD", "strict > permissive > audit > skip")


def _ev(kind):
    return {"kind": kind, "artifact_digest": "d" * 64, "envelope": None}


def _full(fails=()):
    """All-check outcome dict, True except the named failures."""
    return dict((c, c not in fails) for c in (
        "signature-valid", "digest-binds", "provenance-present",
        "builder-allowlisted", "endorsement-independent",
        "witness-quorum", "freshness"))


def p_strict_refuses():
    ap, err = _need_module()
    if ap is None:
        return _record("strict-refuses", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    try:
        ap.admit(_ev("provenance"), pol,
                 _full(fails=("signature-valid",)))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "admission-integrity-floor-violated":
            return _record("strict-refuses", "HELD",
                           "floor failure refused coded")
        return _record("strict-refuses", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("strict-refuses", "BREAK",
            "strict scope admitted a failed floor check")


def p_no_policy_refuses():
    ap, err = _need_module()
    if ap is None:
        return _record("no-policy-refuses", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    try:
        ap.admit(_ev("trust-vector"), pol, _full())
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "admission-no-applicable-policy":
            return _record("no-policy-refuses", "HELD",
                           "uncovered kind refused coded")
        return _record("no-policy-refuses", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("no-policy-refuses", "BREAK",
            "evidence with no applicable policy was admitted")


def p_floor_nonoverridable_at_compile():
    ap, err = _need_module()
    if ap is None:
        return _record("floor-compile", "BREAK", "module absent")
    doc = _policy_doc()
    doc["scopes"].append({"scope": "x", "level": "permissive",
                          "checks": {"signature-valid": "audit"}})
    try:
        ap.compile_policy(doc)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "admission-policy-invalid":
            return _record("floor-compile", "HELD",
                           "floor-lowering policy refused at compile")
        return _record("floor-compile", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("floor-compile", "BREAK",
            "policy lowering signature-valid below strict compiled")


def p_skip_still_runs_floor():
    ap, err = _need_module()
    if ap is None:
        return _record("skip-floor", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    # bundle scope is "skip": non-floor checks don't run, but the
    # integrity floor must still run and refuse on failure.
    try:
        ap.admit(_ev("bundle"), pol, _full(fails=("signature-valid",)))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "admission-integrity-floor-violated":
            return _record("skip-floor", "HELD",
                           "skip scope still ran the floor")
        return _record("skip-floor", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("skip-floor", "BREAK",
            "skip scope admitted a failed floor check")


def p_permissive_warns():
    ap, err = _need_module()
    if ap is None:
        return _record("permissive-warns", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    d = ap.admit(_ev("inclusion-receipt"), pol,
                 _full(fails=("freshness",)))
    if d["verdict"] == "ADMIT" and d.get("warnings"):
        return _record("permissive-warns", "HELD",
                       "permissive admits with recorded warnings")
    _record("permissive-warns", "BREAK",
            "permissive verdict/warnings wrong: %r" % (d,))


def p_audit_records_would_refuse():
    ap, err = _need_module()
    if ap is None:
        return _record("audit-records", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    d = ap.admit(_ev("checkpoint"), pol,
                 _full(fails=("witness-quorum",)))
    if (d["verdict"] == "ADMIT-AUDIT"
            and d.get("would_refuse_under") == "strict"):
        return _record("audit-records", "HELD",
                       "audit admits with would-refuse record")
    _record("audit-records", "BREAK",
            "audit verdict/record wrong: %r" % (d,))


def p_override_raise_bounded():
    ap, err = _need_module()
    if ap is None:
        return _record("override-raise", "BREAK", "module absent")
    doc = _policy_doc()
    doc["scopes"].append({"scope": "y", "level": "permissive",
                          "checks": {"freshness": "strict"}})
    pol = ap.compile_policy(doc)
    try:
        ap.admit(_ev("y"), pol, _full(fails=("freshness",)))
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "admission-refused":
            return _record("override-raise", "HELD",
                           "raised override enforced at strict")
        return _record("override-raise", "BREAK",
                       "wrong refusal code: %s" % (e,))
    _record("override-raise", "BREAK", "raised override not enforced")


def p_missing_outcome_fails_closed():
    ap, err = _need_module()
    if ap is None:
        return _record("missing-outcome", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    try:
        ap.admit(_ev("provenance"), pol, {"digest-binds": True})
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code in ("admission-check-failed", "admission-refused"):
            return _record("missing-outcome", "HELD",
                           "missing outcome fails closed: %s" % (code,))
        return _record("missing-outcome", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("missing-outcome", "BREAK",
            "admitted without a floor-check outcome")


def p_exception_at_risk():
    ap, err = _need_module()
    if ap is None:
        return _record("exception-at-risk", "BREAK", "module absent")
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register(ap.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                 "admission", "medium",
                 "accept a refused admission at operator risk",
                 ["admission-policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["ops"])
    pol = ap.compile_policy(_policy_doc())
    # A non-floor refusal (strict scope, non-floor check fails). admit
    # raises on REFUSE carrying the decision it produced; admit_at_risk
    # consumes that error (F349: the floor gate reads the registered
    # record, never a caller-synthesized dict).
    try:
        ap.admit(_ev("provenance"), pol,
                 _full(fails=("provenance-present",)))
    except ap.AdmissionError as e:
        if getattr(e, "code", None) != "admission-refused":
            return _record("exception-at-risk", "BREAK",
                           "expected admission-refused, got %s"
                           % (getattr(e, "code", type(e).__name__),))
        refuse_err = e
    else:
        return _record("exception-at-risk", "BREAK",
                       "expected REFUSE, admission did not refuse")
    import time as _t
    now = _t.time()
    store.grant(ap.ACCEPT_RISK_CHECK_ID, ("policy", "adm-test-1"),
                "accepting at risk for this test run, operator review",
                "ops", now + 3600, now)
    r = ap.admit_at_risk(refuse_err, store, now=now)
    if r["verdict"] != "ADMIT-AT-RISK" or "exception_digest" not in r:
        return _record("exception-at-risk", "BREAK",
                       "at-risk acceptance wrong: %r" % (r,))
    _record("exception-at-risk", "HELD",
            "live exception accepts at risk with digest")


def p_exception_cannot_override_floor():
    ap, err = _need_module()
    if ap is None:
        return _record("exception-floor", "BREAK", "module absent")
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register(ap.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                 "admission", "medium",
                 "accept a refused admission at operator risk",
                 ["admission-policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["ops"])
    pol = ap.compile_policy(_policy_doc())
    try:
        ap.admit(_ev("provenance"), pol,
                 _full(fails=("signature-valid",)))
    except ap.AdmissionError as e:
        # F349: pass the error admit() itself raised -- the floor gate
        # reads the registered record, not the dict below.
        import time as _t
        now = _t.time()
        store.grant(ap.ACCEPT_RISK_CHECK_ID, ("policy", "adm-test-1"),
                    "accepting at risk for this test run, operator review",
                    "ops", now + 3600, now)
        try:
            ap.admit_at_risk(e, store, now=now)
        except Exception as e2:  # noqa: BLE001
            code = getattr(e2, "code", type(e2).__name__)
            if code == "admission-exception-refused":
                return _record("exception-floor", "HELD",
                               "floor refusal can never be exceptioned")
            return _record("exception-floor", "BREAK",
                           "wrong refusal code: %s" % (code,))
        return _record("exception-floor", "BREAK",
                       "exception overrode the integrity floor")
    _record("exception-floor", "BREAK",
            "expected initial REFUSE, admission did not refuse")


def p_pin_drift():
    ap, err = _need_module()
    if ap is None:
        return _record("pin-drift", "BREAK", "module absent")
    d = tempfile.mkdtemp(prefix="w288-adm-")
    pinpath = os.path.join(d, "pins.json")
    pol = ap.compile_policy(_policy_doc())
    ap.pin_admission_policy("adm-test-1", pol.digest, pinpath)
    pins = ap.load_admission_pins(pinpath)
    # Tamper with the compiled document after pinning.
    pol.doc["scopes"].append({"scope": "z", "level": "skip"})
    try:
        ap.admit(_ev("provenance"), pol, _full(), pins=pins)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "admission-policy-invalid":
            return _record("pin-drift", "HELD",
                           "drifted policy refused against pin")
        return _record("pin-drift", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("pin-drift", "BREAK",
            "drifted policy admitted against a stale pin")


def p_compose_provenance():
    ap, err = _need_module()
    if ap is None:
        return _record("compose-provenance", "BREAK", "module absent")
    pol = ap.compile_policy(_policy_doc())
    # A provenance envelope that fails verification must not be
    # laundered through admission: the check outcome is computed with
    # the real verifier seam.
    ev = _ev("provenance")
    ev["envelope"] = {"provenance": {"x": 1}}  # malformed envelope
    outcomes = ap.run_default_checks(ev, builder_policy=None)
    if outcomes.get("provenance-present") is not False:
        return _record("compose-provenance", "BREAK",
                       "malformed provenance not marked failed: %r"
                       % (outcomes,))
    try:
        ap.admit(ev, pol, outcomes)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code in ("admission-refused", "admission-check-failed"):
            return _record("compose-provenance", "HELD",
                           "failed provenance check refuses: %s" % (code,))
        return _record("compose-provenance", "BREAK",
                       "wrong refusal code: %s" % (code,))
    _record("compose-provenance", "BREAK",
            "admitted evidence whose provenance check failed")


def p_default_level_explicit_only():
    ap, err = _need_module()
    if ap is None:
        return _record("default-level", "BREAK", "module absent")
    doc = {"format": "admission-policy/1", "policy_id": "adm-d",
           "scopes": [{"scope": "provenance", "level": "strict"}],
           "default_level": "audit"}
    pol = ap.compile_policy(doc)
    # Audit level with a failing check: admits but records the
    # would-refuse verdict.
    d = ap.admit(_ev("checkpoint"), pol, _full(fails=("freshness",)))
    if not (d["verdict"] == "ADMIT-AUDIT" and d["scope"] == "(default)"
            and d.get("would_refuse_under") == "strict"):
        return _record("default-level", "BREAK",
                       "default_level mishandled: %r" % (d,))
    # And: a policy WITHOUT default_level still refuses uncovered kinds.
    doc2 = {"format": "admission-policy/1", "policy_id": "adm-d2",
            "scopes": [{"scope": "provenance", "level": "strict"}]}
    pol2 = ap.compile_policy(doc2)
    try:
        ap.admit(_ev("checkpoint"), pol2, _full())
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "admission-no-applicable-policy":
            return _record("default-level", "HELD",
                           "explicit default applies; absence fails closed")
        return _record("default-level", "BREAK",
                       "wrong refusal code: %s" % (e,))
    _record("default-level", "BREAK",
            "admitted without default_level or scope")


def _green_checks():
    if SKIP_GREEN:
        return
    import subprocess
    checks = [
        "evals/w287_ear_probes.py",
        "evals/w285_exceptions_probes.py",
        "evals/w287_provenance_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_import()
    p_ladder_order()
    p_strict_refuses()
    p_no_policy_refuses()
    p_floor_nonoverridable_at_compile()
    p_skip_still_runs_floor()
    p_permissive_warns()
    p_audit_records_would_refuse()
    p_override_raise_bounded()
    p_missing_outcome_fails_closed()
    p_exception_at_risk()
    p_exception_cannot_override_floor()
    p_pin_drift()
    p_compose_provenance()
    p_default_level_explicit_only()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w288_admission: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
