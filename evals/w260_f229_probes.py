"""Break-first F229 closure battery: a hostile __deepcopy__ raising any
exception type must be machine-coded, never escape raw.

Wave-260 lane C (F229 closure). Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

F229 (LOW, OPEN at write time): _safe_deepcopy() in
gov/evidence_quality.py maps only (TypeError, ValueError,
AttributeError, copy.Error) plus RecursionError. A deepcopy-hostile
caller object whose __deepcopy__ raises anything else -- verified
RuntimeError, KeyError, OSError, and a custom Exception subclass --
escapes RAW from the public evaluate() / validate_expectation()
seams. Same defect class as F220 (raw hostile exception at a public
seam; the machine-code contract is "never a raw escape"). Fail-closed
in effect (the exception aborts before any result), wrong error type.

Close-when (from FINDINGS.md): (1) _safe_deepcopy() maps ALL
exceptions raised by hostile caller objects to the machine codes
(e.g. a broad except Exception arm alongside the RecursionError
arm), so no raw exception from __deepcopy__ escapes evaluate() /
validate_expectation(); (2) these probes BREAK (raw exception) on
the old code and HELD (machine-coded refusal) on the fixed code, in
both staging and `env -u GOV_DEPLOYMENT_MODE`; (3) adjacent suites
green (tests.test_evidence_quality, w256 evidence-quality battery).

Method (diagnosing-bugs skill): each probe is falsifiable. Verdicts:
HELD (machine-coded refusal) or BREAK (raw exception or acceptance).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import evidence_quality as eq  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = 2012 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)




def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _expect_code(exc, want, what):
    if exc.code == want:
        return _held("%s refused with %s" % (what, want))
    return _break("%s refused with wrong code %s (want %s)"
                  % (what, exc.code, want))


class _CustomHostile(Exception):
    """Custom Exception subclass -- outside _safe_deepcopy's mapped
    tuple and outside RecursionError."""


def _hostile(exc_factory, *args):
    """Build a deepcopy-hostile object whose __deepcopy__ raises the
    given exception."""
    class _H(object):
        def __deepcopy__(self, memo):
            raise exc_factory(*args)
    return _H()


def _f229_runtimeerror_evidence():
    # F229: hostile __deepcopy__ raising RuntimeError escapes raw
    # from evaluate() instead of
    # evidence-quality-evidence-malformed.
    try:
        eq.evaluate([{"expectation_type": "expect_fields_present",
                      "kwargs": {"required_fields": ["seq"]}}],
                    [{"seq": 1, "obj": _hostile(RuntimeError,
                                                "boom-from-deepcopy")}])
    except RuntimeError as exc:
        return _break("raw RuntimeError escaped evaluate(): %s"
                      % (str(exc)[:60],))
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.EVIDENCE_MALFORMED,
                            "hostile evidence")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile evidence evaluated")


def _f229_keyerror_evidence():
    # F229: KeyError from __deepcopy__ is likewise outside the mapped
    # tuple (verified on base: escapes raw).
    try:
        eq.evaluate([{"expectation_type": "expect_fields_present",
                      "kwargs": {"required_fields": ["seq"]}}],
                    [{"seq": 1, "obj": _hostile(KeyError, "nope")}])
    except KeyError as exc:
        return _break("raw KeyError escaped evaluate(): %s"
                      % (str(exc)[:60],))
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.EVIDENCE_MALFORMED,
                            "hostile evidence")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile evidence evaluated")


def _f229_oserror_meta():
    # F229: OSError from __deepcopy__ in the expectation meta escapes
    # raw from validate_expectation() instead of
    # evidence-quality-malformed.
    exp = {"expectation_type": "expect_fields_present",
           "kwargs": {"required_fields": ["a"]},
           "meta": {"obj": _hostile(OSError, "disk gone")}}
    try:
        eq.validate_expectation(exp)
    except OSError as exc:
        return _break("raw OSError escaped validate_expectation(): "
                      "%s" % (str(exc)[:60],))
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.MALFORMED, "hostile meta")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile meta validated")


def _f229_custom_exc_artifact():
    # F229: a custom Exception subclass from __deepcopy__ in the
    # artifacts mapping escapes raw from validate_expectation()
    # instead of evidence-quality-malformed.
    exp = {"expectation_type": "expect_bundle_complete",
           "kwargs": {"artifacts": {"a": _hostile(_CustomHostile,
                                                  "custom-boom")}}}
    try:
        eq.validate_expectation(exp)
    except _CustomHostile as exc:
        return _break("raw _CustomHostile escaped "
                      "validate_expectation(): %s" % (str(exc)[:60],))
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.MALFORMED, "hostile artifact")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile artifacts validated")


def _legit_still_evaluates():
    # Control: ordinary evidence still evaluates to a real report.
    report = eq.evaluate(
        [{"expectation_type": "expect_fields_present",
          "kwargs": {"required_fields": ["seq"]}}],
        [{"seq": 1}, {"seq": 2}])
    if report["success"] and report["statistics"][
            "evaluated_expectations"] == 1:
        return _held("legit evidence evaluated, success=True")
    return _break("legit evidence mis-evaluated: %r"
                  % (report["success"],))


PROBES = [_f229_runtimeerror_evidence, _f229_keyerror_evidence,
          _f229_oserror_meta, _f229_custom_exc_artifact,
          _legit_still_evaluates]


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_evidence_quality"],
        [sys.executable, "evals/w256_evidence_quality_probes.py"],
        [sys.executable, "evals/w258_f220f221_probes.py"],
        [sys.executable, "evals/w258_f222_probes.py"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g260c-green"
    os.makedirs(td, exist_ok=True)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: evidence_quality + w256 + w258_f220f221 + "
          "w258_f222 green")
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
        print("%-28s %-6s %s" % (fn.__name__, verdict, detail))
    ok = green_check()
    print("probes=%d held=%d broken=%d green=%s"
          % (len(PROBES), held, broken, "OK" if ok else "FAIL"))
    return 0 if (broken == 0 and ok) else 1


if __name__ == "__main__":
    sys.exit(main())
