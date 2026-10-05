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

TAXONOMY_PIN = 2069 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*)



try:
    from gov import decision_codes
    from gov import evidence_quality as eq
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

if HAVE_MODULE:
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN,\
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
        "expect_evidence_monotonic", {}, [], EMPTY_CODE) else\
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_chain_vacuous():
    if _vacuous_break("expect_chain_intact", {}, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_chain_intact", {}, [], EMPTY_CODE) else\
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_fields_vacuous():
    kwargs = {"required_fields": ["a"]}
    if _vacuous_break("expect_fields_present", kwargs, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_fields_present", kwargs, [], EMPTY_CODE) else\
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_timestamps_vacuous():
    if _vacuous_break("expect_timestamps_ordered", {}, []):
        return "BREAK(F222: vacuous success on empty evidence)"
    return "HELD" if _refused_with(
        "expect_timestamps_ordered", {}, [], EMPTY_CODE) else\
        "BREAK(F222: empty evidence neither succeeds nor is refused)"


@probe
def p_empty_bundle_vacuous():
    kwargs = {"artifacts": {"r": {}}}
    evidence = {"items": []}
    if _vacuous_break("expect_bundle_complete", kwargs, evidence):
        return "BREAK(F222: vacuous success on empty bundle)"
    return "HELD" if _refused_with(
        "expect_bundle_complete", kwargs, evidence, EMPTY_CODE) else\
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
        return "HELD" if exc.code == EMPTY_CODE else\
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
        return "HELD" if exc.code ==\
            "evidence-quality-evidence-malformed" else\
            "BREAK(wrong code %r)" % (exc.code,)
    return "BREAK(None evidence evaluated)"


@probe
def p_empty_expectations_still_refused():
    # The original anti-vacuity rule is untouched.
    try:
        eq.evaluate([], [{"seq": 1}])
    except eq.EvidenceQualityError as exc:
        return "HELD" if exc.code == "evidence-quality-malformed"\
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
