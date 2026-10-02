"""Break-first F220/F221 closure battery: no raw stdlib exception may
escape any public gov/evidence_quality.py seam.

Wave-258 lane 1 (F220/F221 closure). Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`).

F220 (LOW, OPEN at write time): evaluate() calls copy.deepcopy(evidence)
BEFORE any shape validation, and _normalize_kwargs() deep-copies the
caller-supplied artifacts mapping. A deepcopy-hostile object (e.g. a
threading.Lock) escapes raw TypeError: cannot pickle '_thread.lock'
object instead of an evidence-quality-* machine code. Same defect class
as F218. Fail-closed in effect, wrong error type.

F221 (LOW, OPEN at write time): copy.deepcopy(evidence) recurses
unboundedly; a deeply-nested evidence payload escapes raw
RecursionError instead of a machine code. Same defect class as
F218/F219 -- this module has no depth bound and no catch.

Close-when (from FINDINGS.md): (1) no raw TypeError escapes
evaluate()/validate_expectation() on deepcopy-hostile caller input --
shapes are validated before deepcopy, or deepcopy is guarded and
mapped to the evidence/malformed machine codes; (2) no raw
RecursionError escapes on deeply-nested evidence -- an iterative depth
bound before deepcopy (F218-style) or a guarded deepcopy mapped to a
machine code; (3) these probes BREAK (raw exception) on the old code
and HELD (machine-coded refusal) on the fixed code, in both staging
and `env -u GOV_DEPLOYMENT_MODE`; (4) adjacent suites green.

Method (diagnosing-bugs skill): each probe is falsifiable. Verdicts:
HELD (machine-coded refusal) or BREAK (raw exception or acceptance).
"""

import os
import sys
import threading

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import evidence_quality as eq  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = 1641  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _expect_code(exc, want, what):
    if exc.code == want:
        return _held("%s refused with %s" % (what, want))
    return _break("%s refused with wrong code %s (want %s)"
                  % (what, exc.code, want))


def _good_exp():
    return {"expectation_type": "expect_fields_present",
            "kwargs": {"required_fields": ["seq"]}}


def _deep_dict(depth):
    deep = {"leaf": 1}
    for _ in range(depth):
        deep = {"n": deep}
    return deep


_DEEP = 10000  # copy.deepcopy raises RecursionError well below this.


def _f220_hostile_evidence():
    # F220: a deepcopy-hostile object in the evidence list escapes raw
    # TypeError from evaluate() instead of
    # evidence-quality-evidence-malformed.
    try:
        eq.evaluate([_good_exp()], [{"seq": 1}, threading.Lock()])
    except TypeError as exc:
        return _break("raw TypeError escaped evaluate(): %s"
                      % (str(exc)[:60],))
    except RecursionError:
        return _break("raw RecursionError escaped evaluate()")
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.EVIDENCE_MALFORMED,
                            "hostile evidence")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile evidence evaluated")


def _f220_hostile_artifact():
    # F220: a deepcopy-hostile artifact value escapes raw TypeError
    # from _normalize_kwargs()/validate_expectation() instead of
    # evidence-quality-malformed.
    exp = {"expectation_type": "expect_bundle_complete",
           "kwargs": {"artifacts": {"a": threading.Lock()}}}
    try:
        eq.validate_expectation(exp)
    except TypeError as exc:
        return _break("raw TypeError escaped validate_expectation(): "
                      "%s" % (str(exc)[:60],))
    except RecursionError:
        return _break("raw RecursionError escaped")
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.MALFORMED, "hostile artifact")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile artifacts validated")


def _f220_hostile_meta():
    # F220: a deepcopy-hostile expectation meta escapes raw TypeError
    # from validate_expectation() instead of
    # evidence-quality-malformed.
    exp = dict(_good_exp())
    exp["meta"] = {"m": threading.Lock()}
    try:
        eq.validate_expectation(exp)
    except TypeError as exc:
        return _break("raw TypeError escaped validate_expectation(): "
                      "%s" % (str(exc)[:60],))
    except RecursionError:
        return _break("raw RecursionError escaped")
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.MALFORMED, "hostile meta")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("hostile meta validated")


def _f221_deep_evidence():
    # F221: a deeply-nested evidence payload escapes raw
    # RecursionError from evaluate()'s deepcopy instead of an
    # evidence-quality-evidence-malformed refusal (F218-style bound).
    try:
        eq.evaluate([_good_exp()], [{"seq": 1, "deep": _deep_dict(
            _DEEP)}])
    except RecursionError:
        return _break("raw RecursionError escaped evaluate()")
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.EVIDENCE_MALFORMED,
                            "deep evidence")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep evidence evaluated")


def _f221_deep_meta():
    # F221 defense-in-depth: a deeply-nested expectation meta must not
    # escape raw RecursionError from validate_expectation()'s
    # deepcopy either.
    exp = dict(_good_exp())
    exp["meta"] = {"m": _deep_dict(_DEEP)}
    try:
        eq.validate_expectation(exp)
    except RecursionError:
        return _break("raw RecursionError escaped "
                      "validate_expectation()")
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.MALFORMED, "deep meta")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep meta validated")


def _boundary_200_201():
    # The shared 200 bound (F218/F219 contract): depth 200 is
    # accepted (evaluated, not refused), depth 201 is refused with a
    # machine code. Note _deep_dict(N) under {"d": ...} inside the
    # item dict measures 2+N, so 198 -> 200 and 199 -> 201.
    try:
        eq.evaluate([_good_exp()],
                    [{"seq": 1, "d": _deep_dict(198)}])
    except eq.EvidenceQualityError as exc:
        return _break("depth-200 evidence refused (%s)" % exc.code)
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s at depth 200" % type(exc).__name__)
    try:
        eq.evaluate([_good_exp()],
                    [{"seq": 1, "d": _deep_dict(199)}])
    except eq.EvidenceQualityError as exc:
        return _expect_code(exc, eq.EVIDENCE_MALFORMED,
                            "depth-201 evidence")
    except Exception as exc:  # noqa: BLE001 -- probe harness
        return _break("raw %s at depth 201" % type(exc).__name__)
    return _break("depth-201 evidence evaluated")


def _legit_still_evaluates():
    # Control: ordinary evidence still evaluates to a real report.
    report = eq.evaluate([_good_exp()],
                         [{"seq": 1}, {"seq": 2}])
    if report["success"] and report["statistics"][
            "evaluated_expectations"] == 1:
        return _held("legit evidence evaluated, success=True")
    return _break("legit evidence mis-evaluated: %r"
                  % (report["success"],))


PROBES = [_f220_hostile_evidence, _f220_hostile_artifact,
          _f220_hostile_meta, _f221_deep_evidence, _f221_deep_meta,
          _boundary_200_201, _legit_still_evaluates]


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_evidence_quality"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g258-f220f221-green"
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
    print("GREEN CHECK: test_evidence_quality green")
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
