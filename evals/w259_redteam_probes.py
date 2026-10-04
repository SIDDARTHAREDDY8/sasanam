"""Break-first red-team battery for the wave-259 seams.

Wave-259 independent red-team lane. Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets (base 894a1628, taxonomy pin 1080):
- gov/control_profiles.py -- F225 seam (per-control evidence
  isolation; cross-check only, filed OPEN), malformed caller-built
  result records at the emit_profile_results seam (F227), the
  quality-gate error envelope (F226 seam; cross-check only, filed
  OPEN).
- gov/evidence_quality.py -- hostile __deepcopy__ escaping the
  _safe_deepcopy guard (F229), _nesting_depth DAG-approximation
  residual, F220/F221/F222 regression pins.
- gov/short_lived_credentials.py -- path-dependent `now` validation
  in verify() (F228), F223/F224 regression pins, documented
  boundaries (past-numeric now test hook, shared unknown code).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual), BREAK (genuine defect -> filed as a finding
F227+), BASELINE (filed-open finding F225/F226 reproduced on this
base -- NOT new findings), ERROR (harness bug -- fix the harness,
never the product).
"""

import copy
import json
import os
import statistics
import sys
import tempfile
import threading
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import control_profiles as cp  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import evidence_quality as eq  # noqa: E402
from gov import short_lived_credentials as slc  # noqa: E402

# Wave-259 base pin. If the count moves, the delta must be explained
# by a landed taxonomy change -- never repoint blindly.
TAXONOMY_PIN = 2020 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w259rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


def _profile(checks):
    return {"id": "P1", "title": "t",
            "controls": [{"id": "C%d" % i, "impact": 0.9,
                          "title": "c", "desc": "d", "check": c}
                         for i, c in enumerate(checks)]}


def _issuer():
    return slc.CredentialIssuer(
        os.path.join(_tmpdir(), "c.journal"), key=b"0" * 32)


# ---------------------------------------------------------------------------
# F225 seam cross-check (filed OPEN -- baseline, not a new finding)
# ---------------------------------------------------------------------------

@probe("baseline/f225-cross-control-snapshot-contamination")
def _b_f225():
    seen = {}

    def mutator(snap):
        snap["poisoned"] = True
        return True, "ok"

    def reader(snap):
        seen["poisoned"] = snap.get("poisoned", False)
        return True, "ok"

    cp.run_profile(_profile([mutator, reader]), {"evidence": 1})
    if seen.get("poisoned"):
        return _baseline("F225 reproduces on this base: check C0 "
                         "mutated the snapshot seen by C1 (closure "
                         "lane pending)")
    return _baseline("F225 no longer reproduces: checks see "
                     "isolated snapshots")


# ---------------------------------------------------------------------------
# F226 seam cross-check (filed OPEN -- baseline, not a new finding)
# ---------------------------------------------------------------------------

@probe("baseline/f226-quality-gate-empty-evidence-envelope")
def _b_f226_empty():
    res = cp.run_profile(_profile([lambda s: True]), {"e": 1})
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    try:
        cp.emit_profile_results(res, fmt="json", quality_gate=True,
                                quality_expectations=exps,
                                quality_evidence=[])
        return _baseline("gate passed unexpectedly")
    except cp.ControlProfileError as e:
        return _baseline("F226 closed on this tree: ControlProfileError "
                         "%s" % e.code)
    except eq.EvidenceQualityError as e:
        return _baseline("F226 reproduces on this base: raw "
                         "EvidenceQualityError(%s) escapes the "
                         "control-profiles seam (closure lane pending)"
                         % e.code)


@probe("baseline/f226-quality-gate-unknown-expectation-envelope")
def _b_f226_unknown_exp():
    res = cp.run_profile(_profile([lambda s: True]), {"e": 1})
    exps = [{"expectation_type": "expect_no_such_thing",
             "kwargs": {}}]
    try:
        cp.emit_profile_results(res, fmt="json", quality_gate=True,
                                quality_expectations=exps,
                                quality_evidence=[{"seq": 1}])
        return _baseline("gate passed unexpectedly")
    except cp.ControlProfileError as e:
        return _baseline("F226 class closed on this tree: "
                         "ControlProfileError %s" % e.code)
    except eq.EvidenceQualityError as e:
        return _baseline("F226 class breadth: unknown expectation "
                         "type also leaks raw EvidenceQualityError(%s) "
                         "through emit_profile_results"
                         % e.code)


# ---------------------------------------------------------------------------
# F227: emit_profile_results escapes raw KeyError on malformed
# caller-built result records
# ---------------------------------------------------------------------------

def _fake_results(results):
    return {"profile_id": "P1", "profile_title": "t",
            "profile_digest": "00" * 32, "success": False,
            "results": results}


@probe("profiles/malformed-results-missing-control-id-keyerror")
def _p_f227_control_id():
    fake = _fake_results([{
        "status": "fail", "impact": 0.9, "severity": "high",
        "check": "f", "check_version": "1", "reason": "x",
        "exception_info": None, "digest": "11" * 32,
        # no "control_id"
    }])
    try:
        cp.emit_profile_results(fake, fmt="json")
        return _held("no exception (unexpected)")
    except KeyError as e:
        return _break("raw KeyError %r escapes emit_profile_results "
                      "instead of ControlProfileError; the seam "
                      "claims shape is 're-validated fail-closed'"
                      % (e,))
    except cp.ControlProfileError as e:
        return _held("machine-coded refusal: %s" % e.code)


@probe("profiles/malformed-results-missing-reason-keyerror")
def _p_f227_reason():
    fake = _fake_results([{
        "control_id": "C0", "status": "fail",
        # missing "reason", "impact", "severity", "digest"
    }])
    try:
        cp.emit_profile_results(fake, fmt="json")
        return _held("no exception (unexpected)")
    except KeyError as e:
        return _break("raw KeyError %r escapes emit_profile_results "
                      "instead of ControlProfileError" % (e,))
    except cp.ControlProfileError as e:
        return _held("machine-coded refusal: %s" % e.code)


# ---------------------------------------------------------------------------
# F228: verify() `now`-validation is path-dependent
# ---------------------------------------------------------------------------

@probe("credentials/now-validation-path-dependent")
def _p_f228():
    iss = _issuer()
    c = iss.issue("agent-a", "read:docs", 60)
    cid, sec = c["credential_id"], c["secret"]

    def code_of(fn):
        try:
            fn()
            return "NO-EXC"
        except slc.CredentialError as e:
            return e.code

    unknown_path = code_of(
        lambda: iss.verify("no-such-id", "x", now="yesterday"))
    mismatch_path = code_of(
        lambda: iss.verify(cid, "wrong-secret", now="yesterday"))
    good_path = code_of(
        lambda: iss.verify(cid, sec, now="yesterday"))
    if unknown_path != slc.MALFORMED_CODE or\
            mismatch_path != slc.MALFORMED_CODE:
        return _break("non-numeric now is not refused as malformed "
                      "on every verify() path: unknown-id -> %s, "
                      "secret-mismatch -> %s, good-secret -> %s "
                      "(F224 close-when (1) requires malformed on "
                      "verify())"
                      % (unknown_path, mismatch_path, good_path))
    return _held("non-numeric now refused as malformed on all "
                 "verify() paths")


# ---------------------------------------------------------------------------
# F229: hostile __deepcopy__ escapes _safe_deepcopy's guard
# ---------------------------------------------------------------------------

class _HostileCopy:
    """deepcopy-hostile object raising outside _safe_deepcopy's
    mapped tuple (TypeError/ValueError/AttributeError/copy.Error)
    and outside RecursionError."""
    def __deepcopy__(self, memo):
        raise RuntimeError("boom-from-deepcopy")


@probe("evidence/hostile-deepcopy-runtimeerror-raw-escape")
def _p_f229_evidence():
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    try:
        eq.evaluate(exps, [{"seq": 1, "obj": _HostileCopy()}])
        return _held("no exception (unexpected)")
    except RuntimeError as e:
        return _break("raw RuntimeError escapes evaluate(): %s "
                      "(F220 class -- _safe_deepcopy maps only four "
                      "exception types + RecursionError)"
                      % str(e)[:60])
    except eq.EvidenceQualityError as e:
        return _held("machine-coded refusal: %s" % e.code)


@probe("evidence/hostile-deepcopy-meta-runtimeerror-raw-escape")
def _p_f229_meta():
    exp = {"expectation_type": "expect_fields_present",
           "kwargs": {"required_fields": ["a"]},
           "meta": {"obj": _HostileCopy()}}
    try:
        eq.validate_expectation(exp)
        return _held("no exception (unexpected)")
    except RuntimeError as e:
        return _break("raw RuntimeError escapes validate_expectation() "
                      "via meta deepcopy: %s" % str(e)[:60])
    except eq.EvidenceQualityError as e:
        return _held("machine-coded refusal: %s" % e.code)


# ---------------------------------------------------------------------------
# HELD: F220/F221/F222 regression pins (closed findings)
# ---------------------------------------------------------------------------

@probe("evidence/deepcopy-lock-machine-coded")
def _h_f220():
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    try:
        eq.evaluate(exps, [{"seq": 1, "lock": threading.Lock()}])
        return _held("no exception (unexpected)")
    except TypeError:
        return _break("F220 REGRESSION: raw TypeError escapes again")
    except eq.EvidenceQualityError as e:
        return _held("F220 holds: machine-coded %s" % e.code)


@probe("evidence/depth-boundary-200-accepted-201-refused")
def _h_f221():
    def nest(depth):
        # Evidence must stay a list of dicts (the evaluator's shape
        # contract); the deep nesting rides inside the item so the
        # depth bound -- not the shape check -- is what we exercise.
        obj = {"leaf": 1}
        for _ in range(depth):
            obj = [obj]
        return [{"leaf": obj}]

    exps = [{"expectation_type": "expect_fields_present",
             "kwargs": {"required_fields": ["leaf"]}}]
    # nest(198): outer dict at depth 1, 198 list levels, inner
    # dict at depth 200 -- the inclusive bound. Must be accepted.
    try:
        eq.evaluate(exps, nest(198))
    except eq.EvidenceQualityError as e:
        return _break("F221 REGRESSION: depth-200 evidence refused: %s"
                      % e.code)
    except RecursionError:
        return _break("F221 REGRESSION: raw RecursionError at depth 200")
    # nest(199): inner dict at depth 201 -- must refuse machine-coded
    try:
        eq.evaluate(exps, nest(199))
        return _break("depth-201 evidence evaluated without refusal")
    except RecursionError:
        return _break("F221 REGRESSION: raw RecursionError escapes")
    except eq.EvidenceQualityError as e:
        return _held("F221 holds: 200 accepted, 201 refused "
                     "machine-coded (%s)" % e.code)


@probe("evidence/empty-evidence-refused")
def _h_f222():
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    try:
        r = eq.evaluate(exps, [])
        if r["success"]:
            return _break("F222 REGRESSION: empty evidence passes")
        return _held("empty evidence evaluated but not success "
                     "(unexpected shape)")
    except eq.EvidenceQualityError as e:
        if e.code == "evidence-quality-empty-evidence":
            return _held("F222 holds: empty evidence refused "
                         "machine-coded")
        return _break("wrong code %s" % e.code)


@probe("evidence/dag-depth-approximation-defensive-catch")
def _h_dag_depth():
    # _nesting_depth under-measures shared substructure (seen-set is
    # global, not per-path): s is first visited via the shallow
    # shortcut (depth 1), so its 150-deep subtree is measured at
    # depths 2..151, and the 200-wrapper chain around it measures at
    # most 200 -- the bound PASSES while the true longest path is
    # 351. deepcopy then needs ~351 levels of interpreter frames and
    # must still land in the defensive RecursionError catch, never
    # escape raw.
    sub = []
    s = sub
    for _ in range(150):
        s = [s]
    long = s
    for _ in range(200):
        long = [long]
    root = [long, s]  # LIFO: s popped first (shallow), skipped deep
    measured = eq._nesting_depth(root)
    exps = [{"expectation_type": "expect_fields_present",
             "kwargs": {"required_fields": ["leaf"]}}]
    try:
        eq.evaluate(exps, root)
        detail = "no exception (unexpected)"
    except RecursionError:
        return _break("raw RecursionError escapes despite the "
                      "defensive catch (measured depth %d)" % measured)
    except eq.EvidenceQualityError as e:
        detail = "machine-coded %s" % e.code
    except Exception as e:  # noqa: BLE001 -- probe records the type
        return _break("unexpected %s escapes" % type(e).__name__)
    return _held("defensive catch holds under bound-fooling DAG "
                 "(measured %d, true 351): %s" % (measured, detail))


# ---------------------------------------------------------------------------
# HELD: F223/F224 regression pins (closed findings)
# ---------------------------------------------------------------------------

@probe("credentials/timing-delta-within-noise")
def _h_f223():
    # Lighter re-pin of the F223 closure: unknown-id vs
    # secret-mismatch refusal paths must be timing-indistinguishable
    # within noise (bar: systematic delta <= 1000 ns).
    iss = _issuer()
    c = iss.issue("agent-a", "read:docs", 60)
    cid, sec = c["credential_id"], c["secret"]

    def attempt(known):
        t0 = time.perf_counter_ns()
        try:
            if known:
                iss.verify(cid, "wrong-secret")
            else:
                iss.verify("0" * 32, "wrong-secret")
        except slc.CredentialError:
            pass
        return time.perf_counter_ns() - t0

    for _ in range(50):  # warmup
        attempt(True)
        attempt(False)

    def med(known, n=200):
        return statistics.median(attempt(known) for _ in range(n))

    medians = sorted((med(False), med(True)) for _ in range(3))
    delta = medians[1][0] - medians[1][1]
    if abs(delta) > 1000:
        return _break("F223 REGRESSION: systematic delta %d ns > "
                      "1000 ns bar" % delta)
    return _held("F223 holds: unknown-vs-mismatch delta %d ns "
                 "within noise" % delta)


@probe("credentials/now-malformed-on-good-path")
def _h_f224_good():
    iss = _issuer()
    c = iss.issue("agent-a", "read:docs", 60)
    try:
        iss.verify(c["credential_id"], c["secret"], now="yesterday")
        return _break("non-numeric now accepted on the good path")
    except slc.CredentialError as e:
        if e.code == slc.MALFORMED_CODE:
            return _held("F224 holds: non-numeric now refused "
                         "machine-coded on the good path")
        return _break("wrong code %s" % e.code)
    try:
        iss.expire_due(now="yesterday")
        return _break("non-numeric now accepted by expire_due")
    except slc.CredentialError as e:
        if e.code == slc.MALFORMED_CODE:
            return _held("F224 holds: expire_due refuses non-numeric "
                         "now machine-coded")
        return _break("wrong code %s" % e.code)


@probe("credentials/past-now-is-test-hook")
def _h_past_now():
    iss = _issuer()
    c = iss.issue("agent-a", "read:docs", 60)
    past = c["issued_at"] - 100  # numeric past: honored by design
    try:
        r = iss.verify(c["credential_id"], c["secret"], now=past)
        if r["credential_id"] == c["credential_id"]:
            return _held("documented: past numeric now honored "
                         "(caller is the trusted deployment)")
        return _break("wrong credential returned")
    except slc.CredentialError as e:
        return _break("past numeric now refused: %s" % e.code)


@probe("credentials/unknown-and-mismatch-share-code")
def _h_shared_code():
    iss = _issuer()
    c = iss.issue("agent-a", "read:docs", 60)

    def code_of(fn):
        try:
            fn()
            return "NO-EXC"
        except slc.CredentialError as e:
            return e.code

    a = code_of(lambda: iss.verify("0" * 32, "x"))
    b = code_of(lambda: iss.verify(c["credential_id"], "wrong"))
    if a == b == slc.UNKNOWN_CODE:
        return _held("API-level claim holds: both paths refuse %s"
                     % a)
    return _break("codes diverge: %s vs %s" % (a, b))


# ---------------------------------------------------------------------------
# HELD: documented control-profile boundaries
# ---------------------------------------------------------------------------

@probe("profiles/fabricated-wellformed-results-emit")
def _h_fabricated():
    fake = _fake_results([{
        "control_id": "C0", "impact": 0.9, "severity": "high",
        "check": "f", "check_version": "1", "status": "pass",
        "reason": "forged", "exception_info": None,
        "digest": "11" * 32}])
    fake["success"] = True
    art = cp.emit_profile_results(fake, fmt="json")
    if art:
        return _held("documented: deployment is the trust boundary; "
                     "a deployment forging its own results deceives "
                     "only itself")
    return _break("well-formed fabricated results refused")


@probe("profiles/non-string-reason-becomes-error-not-pass")
def _h_reason_pair():
    def bad_reason(snap):
        return (True, 123)  # non-string reason: check misbehavior

    res = cp.run_profile(_profile([bad_reason]), {"e": 1})
    st = res["results"][0]["status"]
    if st == "pass":
        return _break("non-string reason recorded as a PASS")
    if st == "error":
        return _held("documented: check misbehavior becomes an "
                     "ERROR result, never a pass")
    return _held("unexpected status %s (not a pass)" % st)


@probe("profiles/evidence-non-dict-refused")
def _h_evidence_shape():
    try:
        cp.run_profile(_profile([lambda s: True]), ["not", "a", "dict"])
        return _break("non-dict evidence accepted")
    except cp.ControlProfileError as e:
        if e.code == "control-profile-evidence-malformed":
            return _held("non-dict evidence refused machine-coded")
        return _break("wrong code %s" % e.code)


@probe("profiles/quality-gate-failed-names-expectations")
def _h_gate_failed():
    # The non-F226 path: a genuinely failing gate must refuse with
    # control-profile-gate-failed naming the failed expectations.
    res = cp.run_profile(_profile([lambda s: True]), {"e": 1})
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    evidence = [{"seq": 2}, {"seq": 1}]  # not monotonic -> FAILED
    try:
        cp.emit_profile_results(res, fmt="json", quality_gate=True,
                                quality_expectations=exps,
                                quality_evidence=evidence)
        return _break("failing gate did not refuse")
    except cp.ControlProfileError as e:
        if e.code == "control-profile-gate-failed" and\
                "expect_evidence_monotonic" in str(e):
            return _held("gate refuses machine-coded, naming the "
                         "failed expectation")
        return _break("wrong code/message: %s" % e.code)
    except eq.EvidenceQualityError as e:
        return _break("F226 class: raw EvidenceQualityError(%s) "
                      "escapes on the gate-failed path too" % e.code)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent closed-finding batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns).

    NOTE: evals/w258_redteam_probes.py is deliberately NOT in this
    list: its F225/F226 standing pins (profiles/
    cross-control-snapshot-contamination, profiles/
    quality-gate-names-failed-expectations) are expected-BREAK/ERROR
    on this base because F225/F226 are OPEN. The merge coordinator
    should re-run it on the merged tree -- the F225/F226 closure
    lanes' success criterion is that battery going green (modulo the
    F226 pin's expected code, see REPORT.md).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w258_f220f221_probes.py",
                    "evals/w258_f222_probes.py",
                    "evals/w258_f223f224_probes.py",
                    "evals/w257_profiles_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or\
                [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, baselines, errors,
                               len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
