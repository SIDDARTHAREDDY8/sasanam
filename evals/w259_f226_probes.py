"""Break-first F226 closure battery: emit_profile_results(quality_gate=True)
must wrap EvidenceQualityError as ControlProfileError.

Wave-259 lane B (F226 closure). Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

F226 (LOW, OPEN at write time): emit_profile_results(quality_gate=True)
calls gov/evidence_quality.evaluate() directly. After the F222 closure,
empty quality evidence raises
EvidenceQualityError(evidence-quality-empty-evidence) from inside
evaluate(), and it propagates raw through the control-profiles public
seam instead of being wrapped as ControlProfileError with a
control-profile-* machine code. A caller catching only
ControlProfileError misses this refusal entirely. Same defect class as
F220/F221/F224 (wrong error type at a public seam).

Close-when (from FINDINGS.md): (1) emit_profile_results with
quality_gate=True over empty quality evidence raises
ControlProfileError with a control-profile-* machine code; (2) these
probes BREAK (raw EvidenceQualityError escapes) on the old code and
HELD (ControlProfileError) on the fixed code, in both staging and
`env -u GOV_DEPLOYMENT_MODE`; (3) adjacent suites green
(tests.test_control_profiles, w257 profiles battery, w258_f222
probes).

Fix choice (wrapping preferred): the wrap reuses the existing
control-profile-gate-failed code -- the code the standing regression
pin probe profiles/quality-gate-names-failed-expectations already
expects for a refusing gate -- and names the wrapped
evidence-quality-* code in the refusal message. No new taxonomy code;
pin stays 1080.

Method (diagnosing-bugs skill): each probe is falsifiable. Verdicts:
HELD (wrapped ControlProfileError) or BREAK (raw EvidenceQualityError
escapes, or a wrong code / missing wrap).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import control_profiles as cp  # noqa: E402
from gov import evidence_quality as eq  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = 2027 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)




def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _control(cid, check, impact=0.9):
    return {"id": cid, "impact": impact, "title": "t-%s" % (cid,),
            "desc": "d-%s" % (cid,), "check": check}


def _results():
    prof = {"id": "P-F226", "title": "f226-probe",
            "controls": [_control("C1", lambda snap: True)]}
    return cp.run_profile(prof, {"e": 1})


def _monotonic_exp():
    return {"expectation_type": "expect_evidence_monotonic",
            "kwargs": {}}


def _gate_call(evidence, expectations=None):
    return cp.emit_profile_results(
        _results(), fmt="json", quality_gate=True,
        quality_expectations=(expectations if expectations is not None
                              else [_monotonic_exp()]),
        quality_evidence=evidence)


def _expect_wrapped(fn, want_inner_code, what):
    """The F226 envelope check: a quality-module refusal must surface
    as ControlProfileError(control-profile-gate-failed) naming the
    wrapped evidence-quality-* code -- never as a raw
    EvidenceQualityError."""
    try:
        fn()
    except cp.ControlProfileError as exc:
        if exc.code != "control-profile-gate-failed":
            return _break("%s: wrong envelope code %s (want "
                          "control-profile-gate-failed)"
                          % (what, exc.code))
        if want_inner_code not in str(exc):
            return _break("%s: wrapped code %s not named in refusal "
                          "%r" % (what, want_inner_code, str(exc)[:80]))
        return _held("%s wrapped as control-profile-gate-failed "
                     "(%s)" % (what, want_inner_code))
    except eq.EvidenceQualityError as exc:
        return _break("raw EvidenceQualityError(%s) escaped the "
                      "control-profiles seam" % (exc.code,))
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("%s: gate passed on refusing input" % (what,))


def p_empty_quality_evidence_wrapped():
    # F226 core: empty quality evidence raises
    # evidence-quality-empty-evidence inside evaluate(); it must not
    # escape raw through emit_profile_results(quality_gate=True).
    return _expect_wrapped(
        lambda: _gate_call([]),
        "evidence-quality-empty-evidence",
        "empty quality evidence")


def p_malformed_quality_expectation_wrapped():
    # Defense in depth: a malformed expectation (unknown type) also
    # raises EvidenceQualityError from inside evaluate(); the seam
    # must wrap it too, not just the empty-evidence shape.
    bad = [{"expectation_type": "nope_unknown", "kwargs": {}}]
    return _expect_wrapped(
        lambda: _gate_call([{"seq": 1}], bad),
        "evidence-quality-unknown-expectation",
        "malformed quality expectation")


def p_failed_expectation_still_gate_failed():
    # Control (no regression): a genuinely failing expectation still
    # refuses with control-profile-gate-failed naming the failed
    # expectation type -- the pre-existing path, unchanged by the
    # wrap.
    try:
        _gate_call([{"seq": 2}, {"seq": 1}])
    except cp.ControlProfileError as exc:
        if exc.code != "control-profile-gate-failed":
            return _break("wrong code %s" % (exc.code,))
        if "expect_evidence_monotonic" not in str(exc):
            return _break("failed expectation not named: %r"
                          % (str(exc)[:80],))
        return _held("failing expectation still gate-failed, named")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("failing gate emitted")


def p_clean_evidence_still_emits():
    # Control (no regression): clean evidence still passes the gate
    # and emits.
    try:
        art = _gate_call([{"seq": 1}, {"seq": 2}])
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("clean gate raised %s" % type(exc).__name__)
    if "control-profile-check-passed" in art:
        return _held("clean evidence emits")
    return _break("clean gate emitted without pass mapping")


def p_gate_failed_registered_in_taxonomy():
    # The envelope code on the wrapped refusal is a registered
    # control-profile-* taxonomy code (machine-code contract).
    entry = decision_codes.TAXONOMY.get("control-profile-gate-failed")
    if entry is None:
        return _break("control-profile-gate-failed not in TAXONOMY")
    if entry.get("domain") != "control-profile":
        return _break("wrong domain %r" % (entry.get("domain"),))
    return _held("gate-failed registered, domain=control-profile")


PROBES = [p_empty_quality_evidence_wrapped,
          p_malformed_quality_expectation_wrapped,
          p_failed_expectation_still_gate_failed,
          p_clean_evidence_still_emits,
          p_gate_failed_registered_in_taxonomy]


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    suites = [
        ("tests.test_control_profiles", "/var/tmp/g259-f226-green-cp"),
        ("tests.test_evidence_quality", "/var/tmp/g259-f226-green-eq"),
    ]
    for suite, td in suites:
        os.makedirs(td, exist_ok=True)
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = td
        cmd = [sys.executable, "-m", "unittest", suite]
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
        print("GREEN CHECK: %s green" % (suite,))
    return True


def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))
    held, broken = 0, 0
    for fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        else:
            broken += 1
        print("%-42s %-6s %s" % (fn.__name__, verdict, detail))
    ok = green_check()
    print("probes=%d held=%d broken=%d green=%s"
          % (len(PROBES), held, broken, "OK" if ok else "FAIL"))
    return 0 if (broken == 0 and ok) else 1


if __name__ == "__main__":
    sys.exit(main())
