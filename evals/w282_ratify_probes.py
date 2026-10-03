"""Wave-282 lane 6 red-first battery: notaryproject/ratify mechanism ADAPT.

Gap (base a858be2): Sasanam has per-call grant derivation (capability_grants)
and evidence bundles, but no VERIFICATION framework for the artifacts that
feed them -- no per-artifact-type any/all policy combinator over pluggable
verifiers, no nested VerifierResult report tree sealed as admission evidence,
and no admission-before-binding gate: a tool's metadata is never ratified
before it is bound into the grant graph (checks happen lazily at call time).

Red-first: on base every capability probe BREAKs (gov.ratify absent; the
taxonomy pin expects the 4 new ratify-* codes). After the build: verifiers
produce nested VerifierResult trees, any/all policies roll up fail-closed,
verifier crashes and missing verifiers fail closed, the admission gate
refuses unratified tools with a coded refusal, ratification verdicts chain
into the HMAC audit log, and the evidence package re-verifies standalone
(including a VSA naming its package digest).

Pattern lineage: notaryproject/ratify (Apache-2.0, LICENSE bytes verified
by the wave-281 prospecting lane) -- the per-artifact-type any/all policy
combinator over per-verifier boolean reports, the recursive nested
VerifierResult report tree (Subject/IsSuccess/Name/Results/NestedResults/
ArtifactType), and the external-data-provider admission pattern (refuse to
bind unless ratified). Clean-room stdlib re-implementation of the MECHANISMS
only; no ratify code vendored. Do not confuse with the unrelated
identities-ai/ratify-protocol project.
"""

import hashlib
import json
import os
import re
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w282-ratify")
os.environ.setdefault("TMPDIR", "/var/tmp/g282-ratify")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-281 merge pin 1563 -> 1567 (+4 ratify-* codes).
TAXONOMY_PIN = 1857  # Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_RESULTS = []

PLUGIN_META = ("guardrail-evidence", "direct", "held-vs-expected")
PROBE_METADATA = {}


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs(probe_id):
    try:
        from gov import ratify as R
        return R
    except ImportError:
        _record(probe_id, "BREAK", "gov.ratify absent on base")
        return None


def _literals():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "gov", "decision_codes.py"),
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
    _record("pin-taxonomy", "HELD", "1588/1588/0 sorted")


def p_module_present():
    R = _needs("p-module-present")
    if R is None:
        return
    for name in ("SUBJECT_KINDS", "ARTIFACT_TYPES", "COMBINATORS",
                 "verifier_result", "SignatureVerifier", "DigestVerifier",
                 "ProvenanceVerifier", "SbomVerifier", "LicenseVerifier",
                 "VulnReportVerifier",
                 "VerificationPolicy", "PolicyEnforcer", "check_admission",
                 "RatificationWriter", "ratification_evidence_package",
                 "verify_ratification_package"):
        if not hasattr(R, name):
            return _record("p-module-present", "BREAK",
                           "missing public name %r" % (name,))
    _record("p-module-present", "HELD", "public surface present")


def _sig_setup(R, subject=b"tool-def-bytes"):
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed)
    sig = ed25519.sign(seed, subject)
    return subject, pub.hex(), sig.hex()


def p_any_combinator():
    R = _needs("p-any-combinator")
    if R is None:
        return
    subject, pub_hex, sig_hex = _sig_setup(R)
    good = R.SignatureVerifier("sig-good", pubkey_hex=pub_hex,
                               signature_hex=sig_hex)
    bad = R.SignatureVerifier("sig-bad", pubkey_hex=pub_hex,
                              signature_hex="00" * 64)
    policy = R.VerificationPolicy({"signature": "any"})
    root = R.PolicyEnforcer().verify(
        subject="tool:x", subject_kind="tool-definition",
        subject_bytes=subject, metadata={},
        verifiers=[good, bad], policy=policy)
    if root["is_success"] is not True:
        return _record("p-any-combinator", "BREAK",
                       "any-of-two (one good) must succeed")
    if len(root["nested_results"]) < 1:
        return _record("p-any-combinator", "BREAK",
                       "root carries no nested results")
    _record("p-any-combinator", "HELD", "any rollup succeeds")


def p_all_combinator():
    R = _needs("p-all-combinator")
    if R is None:
        return
    subject = b"tool-def-bytes"
    good = R.DigestVerifier(
        "digest-good",
        expected_hex=hashlib.sha256(subject).hexdigest())
    bad = R.DigestVerifier("digest-bad", expected_hex="00" * 32)
    policy = R.VerificationPolicy({"digest": "all"})
    enforcer = R.PolicyEnforcer()
    ok = enforcer.verify(subject="tool:x", subject_kind="tool-definition",
                         subject_bytes=subject, metadata={},
                         verifiers=[good], policy=policy)
    fail = enforcer.verify(subject="tool:x", subject_kind="tool-definition",
                           subject_bytes=subject, metadata={},
                           verifiers=[good, bad], policy=policy)
    if ok["is_success"] is not True:
        return _record("p-all-combinator", "BREAK",
                       "all-good must succeed")
    if fail["is_success"] is not False:
        return _record("p-all-combinator", "BREAK",
                       "all with one bad must fail")
    _record("p-all-combinator", "HELD", "all rollup fail-closed")


def p_unknown_combinator_refused():
    R = _needs("p-unknown-combinator-refused")
    if R is None:
        return
    try:
        R.VerificationPolicy({"signature": "sometimes"})
    except Exception as e:  # noqa: BLE001 - must be a ValueError
        if isinstance(e, ValueError):
            return _record("p-unknown-combinator-refused", "HELD",
                           "unknown combinator refused fail-fast")
        return _record("p-unknown-combinator-refused", "BREAK",
                       "wrong exception type %r" % (e,))
    _record("p-unknown-combinator-refused", "BREAK",
            "unknown combinator silently accepted")


def p_nested_report_rollup():
    R = _needs("p-nested-report-rollup")
    if R is None:
        return
    subject = b"tool-def-bytes"
    dv = R.DigestVerifier(
        "digest-ok", expected_hex=hashlib.sha256(subject).hexdigest())
    sv = R.SbomVerifier("sbom-ok")
    policy = R.VerificationPolicy({"digest": "all", "sbom": "all"})
    root = R.PolicyEnforcer().verify(
        subject="tool:x", subject_kind="tool-definition",
        subject_bytes=subject,
        metadata={"sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5",
                           "components": []}},
        verifiers=[dv, sv], policy=policy)
    if root["is_success"] is not True:
        return _record("p-nested-report-rollup", "BREAK",
                       "expected success")
    kinds = {n["name"] for n in root["nested_results"]}
    if kinds != {"digest", "sbom"}:
        return _record("p-nested-report-rollup", "BREAK",
                       "per-type nodes missing: %r" % (sorted(kinds),))
    for node in root["nested_results"]:
        if not node["nested_results"]:
            return _record("p-nested-report-rollup", "BREAK",
                           "type node %r has no verifier leaves"
                           % (node["name"],))
    _record("p-nested-report-rollup", "HELD",
            "nested tree folds per-type then root")


def p_verifier_crash_fail_closed():
    R = _needs("p-verifier-crash-fail-closed")
    if R is None:
        return

    class Boom(R.Verifier):
        artifact_type = "digest"

        def __init__(self):
            super(Boom, self).__init__("boom")

        def verify(self, subject_bytes, metadata):
            raise RuntimeError("kaboom")

    policy = R.VerificationPolicy({"digest": "all"})
    root = R.PolicyEnforcer().verify(
        subject="tool:x", subject_kind="tool-definition",
        subject_bytes=b"abc", metadata={}, verifiers=[Boom()],
        policy=policy)
    if root["is_success"] is not False:
        return _record("p-verifier-crash-fail-closed", "BREAK",
                       "crashed verifier must fail closed")
    blob = json.dumps(root, sort_keys=True)
    if "ratify-verifier-error" not in blob:
        return _record("p-verifier-crash-fail-closed", "BREAK",
                       "verifier-error code not in report")
    _record("p-verifier-crash-fail-closed", "HELD",
            "crash -> fail-closed with machine code")


def p_missing_verifier_fail_closed():
    R = _needs("p-missing-verifier-fail-closed")
    if R is None:
        return
    policy = R.VerificationPolicy({"provenance": "all"})
    root = R.PolicyEnforcer().verify(
        subject="tool:x", subject_kind="tool-definition",
        subject_bytes=b"abc", metadata={}, verifiers=[],
        policy=policy)
    if root["is_success"] is not False:
        return _record("p-missing-verifier-fail-closed", "BREAK",
                       "required type with no verifier must fail closed")
    _record("p-missing-verifier-fail-closed", "HELD",
            "missing verifier fails closed")


def _good_report(R, subject_str="tool:x", subject_kind="tool-definition"):
    subject = b"tool-def-bytes"
    dv = R.DigestVerifier(
        "digest-ok", expected_hex=hashlib.sha256(subject).hexdigest())
    policy = R.VerificationPolicy({"digest": "all"})
    return R.PolicyEnforcer().verify(
        subject=subject_str, subject_kind=subject_kind,
        subject_bytes=subject, metadata={}, verifiers=[dv],
        policy=policy)


def p_admission_unratified_refused():
    R = _needs("p-admission-unratified-refused")
    if R is None:
        return
    report = _good_report(R)
    report = dict(report, is_success=False)
    try:
        R.check_admission(tool="tool:x", report=report)
    except Exception as e:
        code = getattr(e, "code", "")
        if code == "ratify-unratified-tool-refused":
            return _record("p-admission-unratified-refused", "HELD",
                           "coded refusal")
        return _record("p-admission-unratified-refused", "BREAK",
                       "wrong code %r" % (code,))
    _record("p-admission-unratified-refused", "BREAK",
            "unratified tool admitted")


def p_admission_ratified_ok():
    R = _needs("p-admission-ratified-ok")
    if R is None:
        return
    report = _good_report(R)
    try:
        ok = R.check_admission(tool="tool:x", report=report)
    except Exception as e:
        return _record("p-admission-ratified-ok", "BREAK",
                       "ratified tool refused: %r" % (e,))
    if ok is not True:
        return _record("p-admission-ratified-ok", "BREAK",
                       "admission must return True")
    _record("p-admission-ratified-ok", "HELD", "ratified tool admitted")


def p_admission_absent_report_refused():
    R = _needs("p-admission-absent-report-refused")
    if R is None:
        return
    try:
        R.check_admission(tool="tool:x", report=None)
    except Exception as e:
        code = getattr(e, "code", "")
        if code == "ratify-admission-unverifiable":
            return _record("p-admission-absent-report-refused", "HELD",
                           "absent report refused fail-closed")
        return _record("p-admission-absent-report-refused", "BREAK",
                       "wrong code %r" % (code,))
    _record("p-admission-absent-report-refused", "BREAK",
            "absent report admitted")


def p_admission_subject_mismatch_refused():
    R = _needs("p-admission-subject-mismatch-refused")
    if R is None:
        return
    report = _good_report(R)
    try:
        R.check_admission(tool="tool:other", report=report)
    except Exception as e:
        code = getattr(e, "code", "")
        if code == "ratify-unratified-tool-refused":
            return _record("p-admission-subject-mismatch-refused", "HELD",
                           "subject mismatch refused")
        return _record("p-admission-subject-mismatch-refused", "BREAK",
                       "wrong code %r" % (code,))
    _record("p-admission-subject-mismatch-refused", "BREAK",
            "subject mismatch admitted")


def p_signature_verifier():
    R = _needs("p-signature-verifier")
    if R is None:
        return
    from gov import ed25519
    subject = b"tool-def-bytes"
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed)
    good_sig = ed25519.sign(seed, subject)
    forged_sig = ed25519.sign(secrets.token_bytes(32), subject)
    good = R.SignatureVerifier("sig", pubkey_hex=pub.hex(),
                               signature_hex=good_sig.hex())
    forged = R.SignatureVerifier("sig", pubkey_hex=pub.hex(),
                                 signature_hex=forged_sig.hex())
    r_good = good.verify(subject, {})
    r_forged = forged.verify(subject, {})
    if r_good["is_success"] is not True:
        return _record("p-signature-verifier", "BREAK",
                       "good signature must verify")
    if r_forged["is_success"] is not False:
        return _record("p-signature-verifier", "BREAK",
                       "forged signature must fail")
    _record("p-signature-verifier", "HELD",
            "ed25519 verify contract honored (exact bool)")


def p_evidence_package_verifies():
    R = _needs("p-evidence-package-verifies")
    if R is None:
        return
    report = _good_report(R)
    pkg = R.ratification_evidence_package(report)
    if R.verify_ratification_package(pkg) is not True:
        return _record("p-evidence-package-verifies", "BREAK",
                       "fresh package must verify")
    tampered = dict(pkg)
    tampered["report"] = dict(pkg["report"], is_success=False)
    if R.verify_ratification_package(tampered) is not False:
        return _record("p-evidence-package-verifies", "BREAK",
                       "tampered package must not verify")
    if R.verify_ratification_package({"nope": 1}) is not False:
        return _record("p-evidence-package-verifies", "BREAK",
                       "malformed package must not verify")
    _record("p-evidence-package-verifies", "HELD",
            "digest-bound standalone verification")


def p_audit_chained():
    R = _needs("p-audit-chained")
    if R is None:
        return
    from gov.log import ActionLog, read_entries
    from tests.keyfixture import provision_test_key
    provision_test_key()
    d = tempfile.mkdtemp(prefix="ratify-audit-")
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    writer = R.RatificationWriter(log)
    report = _good_report(R)
    entry = writer.record("tool:x", "tool-definition", report)
    entries = read_entries(os.path.join(d, "audit.jsonl"))
    found = [e for e in entries
             if e.get("record_type") == "ratification-verdict"]
    if not found:
        return _record("p-audit-chained", "BREAK",
                       "no ratification-verdict in log")
    if found[-1].get("report_digest") != entry.get("report_digest"):
        return _record("p-audit-chained", "BREAK",
                       "report digest not chained")
    _record("p-audit-chained", "HELD", "verdict chained at decision time")


def p_vsa_composition():
    R = _needs("p-vsa-composition")
    if R is None:
        return
    from gov import provenance_policy as pp
    from gov import bundle_vsa as bv
    report = _good_report(R)
    pkg = R.ratification_evidence_package(report)
    issuer = pp.VSAIssuer("ratify-test-issuer", secrets.token_bytes(32))
    vsa = bv.issue_bundle_vsa(
        issuer=issuer, bundle_digest=pkg["package_digest"],
        policy_id="ratification-policy", verified_level="SLSA_BUILD_LEVEL_2")
    ok = bv.verify_bundle_vsa(
        vsa, verifier_pubkey_hex=issuer.public_key_hex,
        expected_bundle_digest=pkg["package_digest"])
    if not isinstance(ok, dict) or ok != vsa:
        return _record("p-vsa-composition", "BREAK",
                       "VSA over package digest must verify")
    vsa_subject = vsa.get("subject", {}).get("digest", {}).get("sha256")
    if vsa_subject != pkg["package_digest"]:
        return _record("p-vsa-composition", "BREAK",
                       "VSA subject is not the package digest")
    _record("p-vsa-composition", "HELD", "VSA names the package digest")


def _derive_setup(R):
    from gov import capability_grants as cg
    d = tempfile.mkdtemp(prefix="ratify-grants-")
    root = os.path.join(d, "fsroot")
    os.makedirs(root)
    policy = cg.GrantPolicy(fs_root=root)
    policy.bind_file("read-logs", "logs/app.log", ["read"])
    manifest = {"skill_id": "skill:reporter",
                "capabilities": {"filesystem": ["read-logs"]}}
    approval = {"approval_id": "appr-1", "record_digest": "ab" * 32}
    registry = cg.GrantRegistry()
    return cg, manifest, policy, approval, registry


def p_derive_grants_hook():
    R = _needs("p-derive-grants-hook")
    if R is None:
        return
    cg, manifest, policy, approval, registry = _derive_setup(R)
    good = _good_report_for_skill(R, "skill:reporter")
    bad = dict(good, is_success=False)
    # (a) ratified binds
    try:
        cg.derive_grants(verified_manifest=manifest, grant_policy=policy,
                         approval=approval, decision_id="d-1",
                         registry=registry, ratify_report=good)
    except Exception as e:
        return _record("p-derive-grants-hook", "BREAK",
                       "ratified bind refused: %r" % (e,))
    # (b) unratified refuses
    try:
        cg.derive_grants(verified_manifest=manifest, grant_policy=policy,
                         approval=approval, decision_id="d-2",
                         registry=registry, ratify_report=bad)
    except cg.GrantRefused:
        pass
    except Exception as e:
        return _record("p-derive-grants-hook", "BREAK",
                       "wrong exception %r" % (e,))
    else:
        return _record("p-derive-grants-hook", "BREAK",
                       "unratified tool bound into the grant graph")
    # (c) absent hook: unchanged legacy behavior
    try:
        cg.derive_grants(verified_manifest=manifest, grant_policy=policy,
                         approval=approval, decision_id="d-3",
                         registry=registry)
    except Exception as e:
        return _record("p-derive-grants-hook", "BREAK",
                       "legacy path changed: %r" % (e,))
    _record("p-derive-grants-hook", "HELD",
            "admission gate at the binding seam")


def _good_report_for_skill(R, skill_id):
    return _good_report(R, subject_str=skill_id,
                        subject_kind="skill-bundle")


def p_vuln_report_verifier():
    R = _needs("p-vuln-report-verifier")
    if R is None:
        return
    v = R.VulnReportVerifier("vuln")
    clean = v.verify(b"x", {"vuln_report": {
        "scanner": "unit", "findings": [
            {"id": "CVE-1", "severity": "low", "status": "open"},
            {"id": "CVE-2", "severity": "critical", "status": "fixed"}]}})
    dirty = v.verify(b"x", {"vuln_report": {
        "scanner": "unit", "findings": [
            {"id": "CVE-3", "severity": "critical", "status": "open"}]}})
    absent = v.verify(b"x", {})
    if clean["is_success"] is not True:
        return _record("p-vuln-report-verifier", "BREAK",
                       "clean report must pass")
    if dirty["is_success"] is not False:
        return _record("p-vuln-report-verifier", "BREAK",
                       "unaddressed critical must fail closed")
    if absent["is_success"] is not False:
        return _record("p-vuln-report-verifier", "BREAK",
                       "absent report must fail closed")
    _record("p-vuln-report-verifier", "HELD",
            "vuln report fail-closed on criticals")


def p_license_verifier():
    R = _needs("p-license-verifier")
    if R is None:
        return
    v = R.LicenseVerifier("lic", allowlist=("Apache-2.0", "MIT"))
    ok = v.verify(b"x", {"license": "Apache-2.0"})
    bad = v.verify(b"x", {"license": "GPL-3.0"})
    if ok["is_success"] is not True or bad["is_success"] is not False:
        return _record("p-license-verifier", "BREAK",
                       "allowlist enforcement wrong")
    _record("p-license-verifier", "HELD", "license allowlist fail-closed")


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIPPED", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    checks = (["-m", "unittest", "tests.test_decision_codes"],
              ["-m", "unittest", "tests.test_capability_grants"])
    for argv in checks:
        r = subprocess.run([sys.executable] + argv,
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        tail = (r.stderr or r.stdout)[-200:].replace("\n", " | ")
        _record("green-check:" + argv[-1],
                "HELD" if r.returncode == 0 else "ERROR", tail)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_taxonomy_pin, p_module_present, p_any_combinator,
                  p_all_combinator, p_unknown_combinator_refused,
                  p_nested_report_rollup, p_verifier_crash_fail_closed,
                  p_missing_verifier_fail_closed,
                  p_admission_unratified_refused, p_admission_ratified_ok,
                  p_admission_absent_report_refused,
                  p_admission_subject_mismatch_refused,
                  p_signature_verifier, p_license_verifier,
                  p_vuln_report_verifier,
                  p_evidence_package_verifies, p_audit_chained,
                  p_vsa_composition, p_derive_grants_hook):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w282_ratify: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    for r in _RESULTS:
        print("  [%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    mism = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    return 1 if (n_break or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
