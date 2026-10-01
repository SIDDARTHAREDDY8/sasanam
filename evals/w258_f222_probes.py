"""Break-first battery for F222 closure (wave-258 lane 2).

F222: evaluate() refused an empty EXPECTATION list ("a vacuous gate
must never pass") but empty EVIDENCE passed every expectation type
vacuously: expect_evidence_monotonic, expect_chain_intact,
expect_fields_present, expect_timestamps_ordered over [], and
expect_bundle_complete over {"items": []}, all returned success=True.

Closure: empty evidence is refused with the machine code
evidence-quality-empty-evidence -- the same anti-vacuity principle
as the empty-expectation rule. Red-first: each probe BREAKs
(vacuous success=True) on the wave-257 base, HELDs (machine-coded
refusal) on the fixed module.

Related prospectus gap: none (red-team filing). Next free: F225.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1080  # Wave-258 F222: pin -> 1080.

try:
    from gov import decision_codes
    from gov import evidence_quality as eq
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

if HAVE_MODULE:
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, \
        "taxonomy drift: %d != %d" % (  # Wave-258 F222: pin -> 1080.
            len(decision_codes.TAXONOMY), TAXONOMY_PIN)

PROBES = []
EMPTY_CODE = "evidence-quality-empty-evidence"


def probe(fn):
    PROBES.append(fn)
    return fn


def _expect(exp_type, kwargs=None):
    return {"expectation_type": exp_type,
            "kwargs": kwargs or {}}


def _vacuous_break(exp_type, kwargs, evidence):
    """True when empty evidence passes the expectation vacuously."""
    try:
        rep = eq.evaluate([_expect(exp_type, kwargs)], evidence)
    except eq.EvidenceQualityError:
        return False
    return bool(rep["success"])


def _refused_with(exp_type, kwargs, evidence, code):
    """True when the expectation refuses with the given machine code."""
    try:
        eq.evaluate([_expect(exp_type, kwargs)], evidence)
    except eq.EvidenceQualityError as exc:
        return exc.code == code
    except Exception:
        return False
    return False


@probe
def p_empty_monotonic_vacuous():
    # F222: [] through expect_evidence_monotonic must not succeed.
    if _vacuous_break("expect_evidence_monotonic", {}, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_evidence_monotonic", {}, [], EMPTY_CODE) else \
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_chain_vacuous():
    if _vacuous_break("expect_chain_intact", {}, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_chain_intact", {}, [], EMPTY_CODE) else \
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_fields_vacuous():
    kwargs = {"required_fields": ["a"]}
    if _vacuous_break("expect_fields_present", kwargs, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_fields_present", kwargs, [], EMPTY_CODE) else \
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_timestamps_vacuous():
    if _vacuous_break("expect_timestamps_ordered", {}, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_timestamps_ordered", {}, [], EMPTY_CODE) else \
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_bundle_vacuous():
    kwargs = {"artifacts": {"r": {}}}
    evidence = {"items": []}
    if _vacuous_break("expect_bundle_complete", kwargs, evidence):
        return "BREAK(F222: vacuous success on empty bundle)"
    return "HELD" if _refused_with(
        "expect_bundle_complete", kwargs, evidence, EMPTY_CODE) else \
        "BREAK(F222: empty bundle neither succeeds nor is refused)"


@probe
def p_empty_gate_refuses():
    # The gate must refuse, never emit, on empty evidence.
    source = {
        "id": "SAS-F222-001",
        "title": "F222 gate probe",
        "description": "Empty evidence must not pass the gate.",
        "mappings": [
            {"kind": "code", "ref": "evidence-quality-gate-failed",
             "rationale": "gate refusal path"},
        ],
    }
    try:
        eq.emit_with_quality_gate(
            source, "json",
            [_expect("expect_evidence_monotonic")], [])
    except eq.EvidenceQualityError as exc:
        return "HELD" if exc.code == EMPTY_CODE else \
            "BREAK(F222: gate refused with wrong code %r)" % (exc.code,)
    except Exception as exc:
        return "BREAK(F222: gate raised raw %r)" % (type(exc).__name__,)
    return "BREAK(F222: gate emitted on empty evidence)"


@probe
def p_nonempty_monotonic_still_passes():
    # Anti-overcorrection: real evidence still evaluates.
    items = [{"seq": 1}, {"seq": 2}, {"seq": 3}]
    try:
        rep = eq.evaluate([_expect("expect_evidence_monotonic")],
                          items)
    except eq.EvidenceQualityError as exc:
        return "BREAK(overcorrection: %r)" % (exc.code,)
    return "HELD" if rep["success"] else "BREAK(regression: failed)"


@probe
def p_nonempty_bundle_still_passes():
    items = [{"artifact_ref": "r"}]
    try:
        rep = eq.evaluate(
            [_expect("expect_bundle_complete",
                     {"artifacts": {"r": {"kind": "blob"}}})],
            {"items": items})
    except eq.EvidenceQualityError as exc:
        return "BREAK(overcorrection: %r)" % (exc.code,)
    return "HELD" if rep["success"] else "BREAK(regression: failed)"


@probe
def p_new_code_in_taxonomy():
    # The refusal must be machine-coded, not ad hoc.
    if EMPTY_CODE not in decision_codes.TAXONOMY:
        return "BREAK(%r not in taxonomy)" % (EMPTY_CODE,)
    try:
        decision_codes.code_for(EMPTY_CODE)
    except Exception:
        return "BREAK(code_for does not resolve %r)" % (EMPTY_CODE,)
    return "HELD"


@probe
def p_malformed_none_still_refused():
    # None evidence is malformed (pre-existing guard), not empty.
    try:
        eq.evaluate([_expect("expect_evidence_monotonic")], None)
    except eq.EvidenceQualityError as exc:
        return "HELD" if exc.code == \
            "evidence-quality-evidence-malformed" else \
            "BREAK(wrong code %r)" % (exc.code,)
    return "BREAK(None evidence evaluated)"


@probe
def p_empty_expectations_still_refused():
    # The original anti-vacuity rule is untouched.
    try:
        eq.evaluate([], [{"seq": 1}])
    except eq.EvidenceQualityError as exc:
        return "HELD" if exc.code == "evidence-quality-malformed" \
            else "BREAK(wrong code %r)" % (exc.code,)
    return "BREAK(empty expectations evaluated)"


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    import tempfile
    repo = os.path.join(os.path.dirname(__file__), "..")
    td = tempfile.mkdtemp(prefix="w258f222-green-", dir="/var/tmp")
    os.makedirs(td, exist_ok=True)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = td
    adj = [
        [sys.executable, "-m", "unittest",
         "tests.test_evidence_quality"],
        [sys.executable, "evals/w256_evidence_quality_probes.py"],
    ]
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: evidence_quality + w256 battery green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-36s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d" % (held, brk, gap,
                                                 len(results)))
    ok = green_check()
    return held, brk, gap, ok


if __name__ == "__main__":
    held, brk, gap, ok = main()
    sys.exit(0 if (gap or (held, brk, gap) == (len(PROBES), 0, 0)) and ok
             else 1)
