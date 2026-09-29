#!/usr/bin/env python3
"""Red-first battery for the wave-215 identity-policy DSL (sigstore-python
``verify/policy.py`` STEAL: per-certificate identity policy with
NON-VACUOUS AnyOf/AllOf).

RED-FIRST DISCIPLINE: this battery was written BEFORE ``gov/identity_policy.py``
existed. On the pristine tree every probe must ERROR (module absent) or BREAK;
on the fixed tree every probe must HELD. A probe that cannot break on pristine
is a tautology and must be deleted.

Public seams under test:
  - ``gov.identity_policy``: PolicyVerdict contract {pass, fail, error},
    typed predicates (OIDCIssuer / Identity / ExtensionEquals / ClaimEquals /
    ClaimIn), AnyOf / AllOf with empty-combinator authoring-error
    fail-closed, UnsafeAllow self-announcing, parse_policy, check_admission.
  - ``gov.sign_deploy_namespaces.NamespaceRegistry.promote``:
    tighten-only opt-in identity_policy gate (``identity-policy-refused``).
  - ``gov.evidence_verify.verify_bundle``: opt-in V19 identity-policy check
    over a transport-digest-bound ``identity.json``.
"""

import os
import sys
import warnings

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# NOTE: gov.identity_policy does NOT exist on the pristine tree. The import
# below is deliberately unconditional: pristine ImportError is the genuine
# red (every probe errors), not a battery bug.
import gov.identity_policy as ip  # noqa: E402


_GOOD_CLAIMS = {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:acme/app:ref:refs/heads/main",
    "sans": {
        "rfc822Name": ["build@acme.example"],
        "uri": ["https://github.com/acme/app"],
        "otherName": [],
    },
    "extensions": {
        "1.3.6.1.4.1.99999.1.1": "prod",
        "1.3.6.1.4.1.99999.1.2": "sha256:abc",
    },
}

_ISSUER = "https://token.actions.githubusercontent.com"


def _ok(claims=None):
    return dict(_GOOD_CLAIMS) if claims is None else claims


# -- combinator vacuity -------------------------------------------------------

def probe_empty_anyof_is_authoring_error():
    try:
        ip.AnyOf()
    except ip.PolicyAuthoringError:
        return "HELD", "AnyOf() refuses at construction"
    return "BREAK", "AnyOf() allowed an empty conjunction"


def probe_empty_allof_is_authoring_error():
    try:
        ip.AllOf()
    except ip.PolicyAuthoringError:
        return "HELD", "AllOf() refuses at construction"
    return "BREAK", "AllOf() allowed an empty conjunction"


def probe_empty_combinator_spec_is_authoring_error():
    for spec in ({"anyOf": []}, {"allOf": []}):
        try:
            ip.parse_policy(spec)
        except ip.PolicyAuthoringError:
            continue
        return "BREAK", "parse_policy(%r) did not refuse" % (spec,)
    return "HELD", "empty combinator specs refused"


# -- typed predicates ---------------------------------------------------------

def probe_oidc_issuer_match_and_mismatch():
    pol = ip.OIDCIssuer(_ISSUER)
    v = pol.verify(_ok())
    if v.verdict != "pass":
        return "BREAK", "matching issuer did not pass: %s" % (v,)
    bad = dict(_GOOD_CLAIMS, iss="https://evil.example")
    v = pol.verify(bad)
    if v.verdict == "fail" and v.code == "oidc-issuer-mismatch":
        return "HELD", "issuer mismatch fails with named code"
    return "BREAK", "issuer mismatch not refused: %s" % (v,)


def probe_identity_san_membership():
    for san in ("build@acme.example", "https://github.com/acme/app"):
        pol = ip.Identity(san)
        v = pol.verify(_ok())
        if v.verdict != "pass":
            return "BREAK", "SAN %r not accepted: %s" % (san, v)
    return "HELD", "rfc822Name and uri SAN membership accepted"


def probe_identity_wrong_issuer_fails():
    pol = ip.Identity("build@acme.example", issuer=_ISSUER)
    bad = dict(_GOOD_CLAIMS, iss="https://evil.example")
    v = pol.verify(bad)
    if v.verdict == "fail" and v.code == "identity-issuer-mismatch":
        return "HELD", "wrong issuer fails with named code"
    return "BREAK", "wrong issuer not refused: %s" % (v,)


def probe_identity_not_in_sans_fails():
    pol = ip.Identity("mallory@evil.example")
    v = pol.verify(_ok())
    if v.verdict == "fail" and v.code == "identity-not-in-sans":
        return "HELD", "unknown identity fails with named code"
    return "BREAK", "unknown identity not refused: %s" % (v,)


def probe_extension_equals_match_and_mismatch():
    pol = ip.ExtensionEquals("1.3.6.1.4.1.99999.1.1", "prod")
    v = pol.verify(_ok())
    if v.verdict != "pass":
        return "BREAK", "matching extension did not pass: %s" % (v,)
    bad = dict(_GOOD_CLAIMS,
               extensions={"1.3.6.1.4.1.99999.1.1": "dev"})
    v = pol.verify(bad)
    if v.verdict == "fail" and v.code == "extension-mismatch":
        return "HELD", "extension mismatch fails with named code"
    return "BREAK", "extension mismatch not refused: %s" % (v,)


def probe_extension_bad_oid_is_authoring_error():
    for bad_oid in ("", "not-an-oid", None, 42):
        try:
            ip.ExtensionEquals(bad_oid, "v")
        except ip.PolicyAuthoringError:
            continue
        return "BREAK", "bad oid %r accepted" % (bad_oid,)
    return "HELD", "malformed extension OIDs refused at construction"


def probe_claim_equals_path():
    pol = ip.ClaimEquals("sub", "repo:acme/app:ref:refs/heads/main")
    if pol.verify(_ok()).verdict != "pass":
        return "BREAK", "matching claim path did not pass"
    v = pol.verify(dict(_GOOD_CLAIMS, sub="repo:acme/other:x"))
    if v.verdict == "fail" and v.code == "claim-equals-mismatch":
        return "HELD", "claim path mismatch fails with named code"
    return "BREAK", "claim path mismatch not refused: %s" % (v,)


def probe_claim_in_empty_values_is_authoring_error():
    try:
        ip.ClaimIn("sub", [])
    except ip.PolicyAuthoringError:
        return "HELD", "ClaimIn with empty values refused (vacuity guard)"
    return "BREAK", "ClaimIn([]) allowed an empty value set"


# -- combinators ---------------------------------------------------------------

def probe_allof_one_failing_fails_closed():
    pol = ip.AllOf(ip.OIDCIssuer(_ISSUER),
                   ip.Identity("mallory@evil.example"))
    v = pol.verify(_ok())
    if v.verdict == "fail":
        return "HELD", "AllOf fails closed on one failing child: %s" % v.code
    return "BREAK", "AllOf passed despite a failing child: %s" % (v,)


def probe_anyof_pipeline_branches():
    branch_a = ip.AllOf(ip.OIDCIssuer(_ISSUER),
                        ip.Identity("build@acme.example"))
    branch_b = ip.AllOf(ip.OIDCIssuer("https://other.example"),
                        ip.Identity("release@other.example"))
    pol = ip.AnyOf(branch_a, branch_b)
    if pol.verify(_ok()).verdict != "pass":
        return "BREAK", "matching pipeline branch did not pass"
    wrong = dict(_GOOD_CLAIMS, iss="https://evil.example",
                 sans={"rfc822Name": ["mallory@evil.example"],
                       "uri": [], "otherName": []})
    v = pol.verify(wrong)
    if v.verdict == "fail" and v.code == "anyof-no-match":
        return "HELD", "wrong cert fails every branch with named code"
    return "BREAK", "wrong cert not refused by AnyOf: %s" % (v,)


def probe_policy_against_wrong_cert_fails():
    pol = ip.AllOf(
        ip.OIDCIssuer(_ISSUER),
        ip.Identity("build@acme.example"),
        ip.ExtensionEquals("1.3.6.1.4.1.99999.1.1", "prod"),
    )
    wrong = dict(_GOOD_CLAIMS, iss="https://evil.example")
    v = pol.verify(wrong)
    if v.verdict == "fail":
        return "HELD", "wrong-cert policy evaluation fails: %s" % v.code
    return "BREAK", "policy passed against a wrong cert: %s" % (v,)


# -- vacuity contract ----------------------------------------------------------

def probe_unsafe_allow_self_announces():
    pol = ip.UnsafeAllow("battery self-announcement probe")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        v1 = pol.verify(_ok())
        v2 = pol.verify(_ok())
    if v1.verdict != "pass" or v2.verdict != "pass":
        return "BREAK", "UnsafeAllow did not pass: %s %s" % (v1, v2)
    announced = [w for w in caught
                 if "UnsafeAllow" in str(w.message)]
    if len(announced) < 2:
        return "BREAK", "UnsafeAllow did not self-announce on every use"
    if v1.code != "pass-vacuous":
        return "BREAK", "vacuous pass not distinctly coded: %s" % v1.code
    return "HELD", "UnsafeAllow passes loudly, coded pass-vacuous"


def probe_vacuous_only_allof_is_declared():
    pol = ip.AllOf(ip.UnsafeAllow("declared insecure branch"))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        v = pol.verify(_ok())
    if v.verdict == "pass" and v.code == "pass-vacuous":
        return "HELD", "vacuous-only pass carries the declared code"
    return "BREAK", "vacuous pass was silent: %s" % (v,)


def probe_non_vacuous_pass_is_plain_pass():
    pol = ip.AllOf(ip.OIDCIssuer(_ISSUER))
    v = pol.verify(_ok())
    if v.verdict == "pass" and v.code == "pass":
        return "HELD", "non-vacuous pass is plain pass"
    return "BREAK", "non-vacuous pass miscoded: %s" % (v,)


# -- error contract ------------------------------------------------------------

def probe_malformed_claims_is_error():
    pol = ip.OIDCIssuer(_ISSUER)
    v = pol.verify("not-a-claims-document")
    if v.verdict == "error" and v.code == "claims-malformed":
        return "HELD", "malformed claims yield error, not fail"
    return "BREAK", "malformed claims not an error: %s" % (v,)


def probe_missing_san_section_is_error():
    pol = ip.Identity("build@acme.example")
    claims = {"iss": _ISSUER}
    v = pol.verify(claims)
    if v.verdict == "error" and v.code == "claims-section-missing":
        return "HELD", "missing SAN section yields error (fail-closed)"
    return "BREAK", "missing SAN section not an error: %s" % (v,)


def probe_parse_policy_unknown_key_is_authoring_error():
    try:
        ip.parse_policy({"bogusPredicate": 1})
    except ip.PolicyAuthoringError:
        pass
    else:
        return "BREAK", "unknown predicate key accepted"
    spec = {"allOf": [
        {"oidcIssuer": _ISSUER},
        {"identity": {"identity": "build@acme.example"}},
        {"extension": {"oid": "1.3.6.1.4.1.99999.1.1", "value": "prod"}},
    ]}
    pol = ip.parse_policy(spec)
    if pol.verify(_ok()).verdict != "pass":
        return "BREAK", "parsed nested spec did not pass on good claims"
    return "HELD", "unknown keys refused; nested spec round-trips"


def probe_check_admission_raises_on_fail_and_error():
    pol = ip.OIDCIssuer(_ISSUER)
    rep = ip.check_admission(_ok(), pol)
    if rep.get("verdict") != "pass":
        return "BREAK", "check_admission did not report pass"
    bad = dict(_GOOD_CLAIMS, iss="https://evil.example")
    try:
        ip.check_admission(bad, pol)
    except ip.PolicyViolation as e:
        if e.code != "oidc-issuer-mismatch":
            return "BREAK", "violation miscoded: %s" % e.code
    else:
        return "BREAK", "check_admission did not raise on fail"
    try:
        ip.check_admission("garbage", pol)
    except ip.PolicyViolation as e:
        if e.code != "claims-malformed":
            return "BREAK", "error-path violation miscoded: %s" % e.code
    else:
        return "BREAK", "check_admission did not raise on error"
    return "HELD", "fail and error both raise PolicyViolation"


# -- wiring: promotion artifact admission -------------------------------------

def _stage_and_sign(reg):
    from gov.signing import Ed25519Signer
    s1 = Ed25519Signer(bytes.fromhex("71" * 32))
    s2 = Ed25519Signer(bytes.fromhex("72" * 32))
    from gov.signing import Ed25519Verifier
    verifiers = [Ed25519Verifier(s.public_key) for s in (s1, s2)]
    return (s1, s2), verifiers


def probe_promote_identity_gate_admits_and_denies():
    from gov import sign_deploy_namespaces as sdn
    (s1, s2), verifiers = _stage_and_sign(None)
    pol = ip.AllOf(ip.OIDCIssuer(_ISSUER),
                   ip.Identity("build@acme.example"))

    def fresh_reg():
        return sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)

    # admit: matching claims
    reg = fresh_reg()
    reg.stage("b/ok", b"bytes")
    reg.sign("b/ok", [s1, s2])
    out = reg.promote("b/ok", operator_ids=["op-a", "op-b"],
                      identity_policy=pol, identity_claims=_ok())
    if out["status"] != "promoted":
        return "BREAK", "matching identity claims did not promote"

    # deny: mismatched claims
    reg = fresh_reg()
    reg.stage("b/bad", b"bytes")
    reg.sign("b/bad", [s1, s2])
    bad = dict(_GOOD_CLAIMS, iss="https://evil.example")
    try:
        reg.promote("b/bad", operator_ids=["op-a", "op-b"],
                    identity_policy=pol, identity_claims=bad)
    except sdn.NamespaceError as e:
        if e.code != "identity-policy-refused":
            return "BREAK", "denial miscoded: %s" % e.code
    else:
        return "BREAK", "mismatched identity claims promoted"
    denied = [e for e in reg.audit if e["op"] == "promotion-denied"]
    if not denied or "identity-policy" not in denied[0]["detail"]:
        return "BREAK", "denial not audit-logged"

    # fail closed: policy configured, claims absent
    reg = fresh_reg()
    reg.stage("b/noclaims", b"bytes")
    reg.sign("b/noclaims", [s1, s2])
    try:
        reg.promote("b/noclaims", operator_ids=["op-a", "op-b"],
                    identity_policy=pol)
    except sdn.NamespaceError as e:
        if e.code == "identity-policy-refused":
            return "HELD", "gate admits/denies/fails-closed, denial audited"
        return "BREAK", "absent-claims denial miscoded: %s" % e.code
    return "BREAK", "absent claims promoted under a configured policy"


def probe_promote_legacy_byte_identical_without_policy():
    from gov import sign_deploy_namespaces as sdn
    (s1, s2), verifiers = _stage_and_sign(None)
    reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
    reg.stage("b/legacy", b"bytes")
    reg.sign("b/legacy", [s1, s2])
    out = reg.promote("b/legacy", operator_ids=["op-a", "op-b"])
    if out["status"] != "promoted":
        return "BREAK", "legacy promote broke"
    promoted = [e for e in reg.audit if e["op"] == "promoted"]
    if not promoted[0]["detail"].startswith("signed_by="):
        return "BREAK", "legacy audit detail changed"
    if "identity" in promoted[0]["detail"]:
        return "BREAK", "legacy path mentions identity policy"
    return "HELD", "legacy promote byte-identical without a policy"


# -- wiring: evidence-bundle verification -------------------------------------

def _assemble_bundle(tmpdir):
    """Build a real sealed bundle (fixture pattern from
    tests/test_evidence_verify.py), return bundle_dir."""
    import tempfile
    from tests.keyfixture import provision_test_key, scrub_key_env
    restore = scrub_key_env()
    provision_test_key()
    try:
        from gov.signing import Ed25519Signer
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        tmp = tempfile.mkdtemp(dir=tmpdir)
        log_path = os.path.join(tmp, "audit.log")
        signer = Ed25519Signer(bytes.fromhex("11" * 32))
        log = ActionLog(log_path, signer=signer,
                        deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_version": "p1",
                    "policy_hash": "h" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True})
        eb = EvidenceBundle(log_path,
                            exported_at="2026-09-26T00:00:00+00:00",
                            operator_id="w215-battery")
        payload = eb.build()
        manifest = eb.seal(payload, signer=signer)
        log_evidence_bundle_receipt(
            manifest, ActionLog(log_path, signer=signer,
                               deployment_mode="staging"),
            signer=signer)
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        out = os.path.join(tmp, "bundle")
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out
    finally:
        restore()


def _redigest(bundle_dir):
    from gov.safeguard_bundle import compute_bundle_digest
    digest = compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w") as f:
        f.write(digest + "\n")


def _write_identity(bundle_dir, claims):
    import json
    with open(os.path.join(bundle_dir, "identity.json"), "w") as f:
        json.dump(claims, f, sort_keys=True, indent=2)
        f.write("\n")
    _redigest(bundle_dir)


def _policy():
    return ip.AllOf(ip.OIDCIssuer(_ISSUER),
                    ip.Identity("build@acme.example"))


def probe_bundle_identity_check_pass_and_fail(tmpdir):
    from gov import evidence_verify as ev
    bundle_dir = _assemble_bundle(tmpdir)
    _write_identity(bundle_dir, _ok())
    code, checks, _summary = ev.verify_bundle(
        bundle_dir, pins=[], identity_policy=_policy())
    v19 = [c for c in checks if c.id == "V19"]
    failed = [c.id for c in checks if c.status == "fail"]
    # pins=[] -> SELF_CONSISTENT (exit 2) is the honest ceiling here;
    # what matters is V19 passing and nothing else failing.
    if code not in (0, 2) or not v19 or v19[0].status != "pass" or failed:
        return "BREAK", ("matching identity.json did not pass V19 "
                         "(code %s, failed %s)" % (code, failed))
    _write_identity(bundle_dir, dict(_GOOD_CLAIMS, iss="https://evil.example"))
    code, checks, _summary = ev.verify_bundle(
        bundle_dir, pins=[], identity_policy=_policy())
    v19 = [c for c in checks if c.id == "V19"]
    if code == 0 or not v19 or v19[0].status != "fail":
        return "BREAK", "tampered identity.json did not fail V19 (code %s)" % code
    return "HELD", "V19 passes on match, fails on tamper"


def probe_bundle_no_identity_json_fails_closed(tmpdir):
    from gov import evidence_verify as ev
    bundle_dir = _assemble_bundle(tmpdir)
    code, checks, _summary = ev.verify_bundle(
        bundle_dir, pins=[], identity_policy=_policy())
    v19 = [c for c in checks if c.id == "V19"]
    if code == 0 or not v19 or v19[0].status != "fail":
        return "BREAK", "policy without identity.json did not fail closed"
    if "no identity" not in v19[0].detail.lower():
        return "BREAK", "fail-closed detail unclear: %r" % v19[0].detail
    return "HELD", "policy without identity.json fails closed"


def probe_bundle_no_policy_legacy_unchanged(tmpdir):
    from gov import evidence_verify as ev
    bundle_dir = _assemble_bundle(tmpdir)
    code, checks, _summary = ev.verify_bundle(bundle_dir, pins=[])
    ids = [c.id for c in checks]
    if any(i == "V19" for i in ids):
        return "BREAK", "V19 ran without a configured policy"
    if code not in (0, 2):
        return "BREAK", "legacy bundle verify changed (code %s)" % code
    return "HELD", "no policy -> legacy check list, SELF_CONSISTENT ceiling"


# -- runner --------------------------------------------------------------------

PROBES = [
    ("empty-anyof-is-authoring-error", probe_empty_anyof_is_authoring_error),
    ("empty-allof-is-authoring-error", probe_empty_allof_is_authoring_error),
    ("empty-combinator-spec-refused", probe_empty_combinator_spec_is_authoring_error),
    ("oidc-issuer-match-mismatch", probe_oidc_issuer_match_and_mismatch),
    ("identity-san-membership", probe_identity_san_membership),
    ("identity-wrong-issuer-fails", probe_identity_wrong_issuer_fails),
    ("identity-not-in-sans-fails", probe_identity_not_in_sans_fails),
    ("extension-equals", probe_extension_equals_match_and_mismatch),
    ("extension-bad-oid-refused", probe_extension_bad_oid_is_authoring_error),
    ("claim-equals-path", probe_claim_equals_path),
    ("claim-in-empty-values-refused", probe_claim_in_empty_values_is_authoring_error),
    ("allof-one-failing-fails-closed", probe_allof_one_failing_fails_closed),
    ("anyof-pipeline-branches", probe_anyof_pipeline_branches),
    ("policy-against-wrong-cert-fails", probe_policy_against_wrong_cert_fails),
    ("unsafe-allow-self-announces", probe_unsafe_allow_self_announces),
    ("vacuous-only-allof-declared", probe_vacuous_only_allof_is_declared),
    ("non-vacuous-pass-is-plain", probe_non_vacuous_pass_is_plain_pass),
    ("malformed-claims-is-error", probe_malformed_claims_is_error),
    ("missing-san-section-is-error", probe_missing_san_section_is_error),
    ("parse-policy-unknown-key-refused", probe_parse_policy_unknown_key_is_authoring_error),
    ("check-admission-raises", probe_check_admission_raises_on_fail_and_error),
    ("promote-identity-gate", probe_promote_identity_gate_admits_and_denies),
    ("promote-legacy-unchanged", probe_promote_legacy_byte_identical_without_policy),
    ("bundle-v19-pass-fail", probe_bundle_identity_check_pass_and_fail),
    ("bundle-no-identity-json-fails-closed", probe_bundle_no_identity_json_fails_closed),
    ("bundle-no-policy-legacy", probe_bundle_no_policy_legacy_unchanged),
]

_BUNDLE_PROBES = {
    "bundle-v19-pass-fail",
    "bundle-no-identity-json-fails-closed",
    "bundle-no-policy-legacy",
}


def _green_check():
    """Depth-1 adjacent gate: run the promotion/namespace unit suite once,
    honoring GOV_SKIP_GREEN (record a skip instead of recursing)."""
    if os.environ.get("GOV_SKIP_GREEN"):
        return [("green-check-skipped", "SKIP",
                 "GOV_SKIP_GREEN set: adjacent suite not re-run")]
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    cmd = [sys.executable, "-m", "unittest",
           "tests.test_sign_deploy_namespaces", "-v"]
    try:
        p = subprocess.run(cmd, cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True, timeout=600)
    except Exception as e:  # noqa: BLE001
        return [("green-check-adjacent", "ERROR", "subprocess: %r" % (e,))]
    if p.returncode == 0:
        return [("green-check-adjacent", "HELD",
                 "test_sign_deploy_namespaces green")]
    tail = (p.stderr or p.stdout)[-500:]
    return [("green-check-adjacent", "BREAK",
             "adjacent suite red: %s" % tail)]


def main():
    import tempfile
    results = []
    tmpdir = tempfile.mkdtemp(prefix="w215-battery-")
    for name, fn in PROBES:
        try:
            if name in _BUNDLE_PROBES:
                status, detail = fn(tmpdir)
            else:
                status, detail = fn()
        except Exception as e:  # noqa: BLE001 - hostile red must not crash
            status, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        results.append((name, status, detail))
    results.extend(_green_check())

    held = sum(1 for _n, s, _d in results if s == "HELD")
    brk = sum(1 for _n, s, _d in results if s == "BREAK")
    err = sum(1 for _n, s, _d in results if s == "ERROR")
    gap = sum(1 for _n, s, _d in results if s == "GAP")
    skip = sum(1 for _n, s, _d in results if s == "SKIP")
    print("w215 identity-policy battery: %d HELD / %d BREAK / %d ERROR / "
          "%d GAP / %d SKIP" % (held, brk, err, gap, skip))
    for name, status, detail in results:
        if status != "HELD":
            print("  [%s] %s: %s" % (status, name, detail))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
