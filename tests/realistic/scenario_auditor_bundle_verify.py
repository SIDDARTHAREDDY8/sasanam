"""scenario_auditor_bundle_verify: the auditor's lens on a tampered bundle.

Builds a genuine evidence bundle (the F173 F1a fixture shape), applies
the F1a tamper — strips inclusion bundles for seqs 2 and 4, adjusts the
unsigned coverage counts, recomputes only the unsigned BUNDLE_DIGEST —
then runs tools/evidence-verify AS A SUBPROCESS, exactly the way an
external auditor runs it, asserting exit 1 with the V7 failure visible.

The genuine-bundle fixture machinery is reused from
evals/evidence_bundle_tamper.py (honestly labeled); the tamper and the
verifier invocation are this scenario's own. Deterministic, $0 spend,
synthetic/local only.

Contract: run() returns a dict of checks on success, raises on failure.
"""

SCENARIO = {
    "id": "auditor-bundle-verify",
    "title": "Auditor bundle-verify: F173 F1a-tampered bundle fails V7 "
             "via tools/evidence-verify",
}


def run():
    from evals.evidence_bundle_tamper import (
        _assemble, _redigest, _rewrite, _read_json, _run, _pin_args,
        OPERATOR,
    )

    checks = {}

    # Genuine bundle, built and sealed with the fixed synthetic operator
    # key (deterministic fixture).
    fx = _assemble("auditor", OPERATOR)
    bundle_dir = fx["dir"]

    # Control: the genuine bundle verifies as the auditor would see it.
    code, out, _err = _run(bundle_dir, *_pin_args())
    checks["genuine_bundle_verifies"] = (
        code == 0 and "verdict: VERIFIED" in out)
    assert checks["genuine_bundle_verifies"], \
        "genuine-bundle control failed: exit=%r out=%r" % (code, out[-400:])

    # F1a tamper: strip inclusion bundles for seqs 2 and 4 with a
    # fabricated reason, adjust the unsigned coverage counts, recompute
    # only the unsigned BUNDLE_DIGEST (no keys touched).
    manifest = _read_json(bundle_dir, "manifest.json")
    n = 0
    for ib in manifest["inclusion_bundles"]:
        if ib["seq"] in (2, 4):
            ib["bundle"] = None
            ib["unavailable_reason"] = \
                "inclusion service unavailable (simulated strip)"
            n += 1
    checks["tampers_applied"] = (n == 2)
    assert checks["tampers_applied"], \
        "F1a fixture shape changed: expected 2 strippable seqs, got %d" % n
    manifest["inclusion_coverage"]["with_bundle"] -= n
    _rewrite(bundle_dir, "manifest.json", manifest)
    _redigest(bundle_dir)

    # The auditor's run: standalone verifier, pinned operator key.
    code, out, _err = _run(bundle_dir, *_pin_args())
    checks["tampered_exit_1"] = (code == 1)
    checks["v7_failure_visible"] = ("V7" in out)
    checks["not_verified"] = ("verdict: VERIFIED" not in out)
    assert checks["tampered_exit_1"], \
        "tampered bundle did not fail: exit=%r out=%r" % (code, out[-400:])
    assert checks["v7_failure_visible"], \
        "V7 failure not visible in verifier output: %r" % (out[-400:],)
    assert checks["not_verified"], \
        "tampered bundle still verifies: %r" % (out[-400:],)

    return {"scenario": SCENARIO["id"], "checks": checks}
