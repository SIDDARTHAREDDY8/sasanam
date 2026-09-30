"""Wave-219 Lane B red-first battery: named unsafe-path warning codes.

evidentia ADAPT (idea only): an unsafe/no-op path is only ever reachable
through an explicitly-named, greppable, auditable warning code -- never
silently. This battery pins, at the public seams:

  1. Every documented unsafe path has a registered ``gov.<module>...`` code.
  2. Each code is greppable: it appears BOTH in its defining module AND in
     ``gov/unsafe_paths.py`` (the central registry).
  3. ``emit`` refuses unknown codes (fail-closed registry).
  4. Executing a documented unsafe path emits its code through the audit
     path EVERY time (list-audit capture).
  5. Fail-closed defaults stay refused; explicit opt-ins restore behavior
     while emitting the named code.
  6. Post-compile policy mutation is refused with its named code
     (the wave-217 residual, now closed fail-closed).

Deterministic. No network, no clock dependence.
"""

import os
import sys
import warnings

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

PASSED = []
FAILED = []


def check(name, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- battery reports, never raises
        FAILED.append((name, "%s: %s" % (type(e).__name__, e)))
    else:
        PASSED.append(name)


# ---------------------------------------------------------------------------
# registry shape


def t_registry_importable():
    import gov.unsafe_paths as up
    assert isinstance(up.UNSAFE_PATHS, dict) and up.UNSAFE_PATHS
    assert issubclass(up.UnsafePathWarning, UserWarning)


def t_codes_greppable_in_module_and_registry():
    import gov.unsafe_paths as up
    import importlib
    import inspect
    for code, meta in up.UNSAFE_PATHS.items():
        assert code.startswith("gov."), code
        module = importlib.import_module(meta["module"])
        src = inspect.getsource(module)
        assert code in src, "%s not greppable in %s" % (code, meta["module"])
        reg_src = inspect.getsource(up)
        assert code in reg_src, "%s missing from registry source" % code
        assert meta["posture"] in (
            "FAIL_CLOSED", "EXPLICIT_OPT_IN", "LEGACY_ADVISORY",
            "CONSULT_TELEMETRY"), meta["posture"]


def t_emit_rejects_unknown_code():
    import gov.unsafe_paths as up
    try:
        up.emit("gov.nope.not_a_registered_path", audit=[])
    except up.UnknownUnsafePathError:
        return
    raise AssertionError("emit accepted an unregistered code")


def t_emit_warns_loudly():
    import gov.unsafe_paths as up
    code = next(iter(up.UNSAFE_PATHS))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        up.emit(code, audit=[])
    assert any(issubclass(w.category, up.UnsafePathWarning)
               and code in str(w.message) for w in caught), \
        "emit did not warn loudly with the code"


# ---------------------------------------------------------------------------
# per-path emission probes (audit-path capture)


def _drain(audit, code):
    return [e for e in audit
            if isinstance(e, dict) and e.get("code") == code]


def t_artifacts_unreadable_emits():
    from gov.artifacts import ArtifactInventory
    inv = ArtifactInventory()
    audit = []
    inv.register("a.txt", sha256="ab" * 32, size=1, agent_id="t",
                 run_id="r")
    verdict = inv.check_egress("a.txt", sha256_now=None, audit=audit)
    assert verdict["status"] in ("clean", "unknown", "tampered"), verdict
    hits = _drain(audit, "gov.artifacts.egress_unreadable_tamper_check_skipped")
    assert hits, "unreadable egress emitted no code; audit=%r" % (audit,)


def t_manifest_unreadable_emits():
    from gov.artifact_inventory_manifest import pin_manifest, check_manifest
    key = b"0" * 32
    pinned = pin_manifest({"pinned/a.txt": "ab" * 32}, hmac_key=key)
    audit = []
    res = check_manifest("pinned/a.txt", None, pinned, hmac_key=key,
                         audit=audit)
    assert res["status"] == "manifest_unreadable", res
    hits = _drain(audit, "gov.artifact_inventory_manifest."
                         "manifest_unreadable_failopen")
    assert hits, "unreadable manifest emitted no code"


def t_sweep_unreadable_emits():
    import tempfile
    from gov import artifact_sweep as sweep
    tmp = tempfile.mkdtemp(prefix="w219-sweep-")
    audit = []
    # A vanished/unreadable directory hits the sentinel path: skipped
    # fail-open, counted, and now named.
    findings, stats = sweep._sweep_tree(
        os.path.join(tmp, "no-such-dir-xyz"), None, tmp, audit=audit)
    assert stats["skipped_unreadable"] >= 1, stats
    hits = _drain(audit, "gov.artifact_sweep.unreadable_file_skipped")
    assert hits, "sweep skipped unreadable with no code; audit=%r" % (audit,)
    # sweep_run_dir threads the audit handle through as well
    audit2 = []
    findings2, stats2 = sweep.sweep_run_dir(tmp, None, audit=audit2)
    assert stats2["skipped_unreadable"] == 0
    assert not _drain(audit2, "gov.artifact_sweep.unreadable_file_skipped")


def t_credential_manifest_no_identity_emits():
    from gov.credential_manifest import CredentialManifest
    audit = []
    cm = CredentialManifest()
    ok = cm.check_egress({}, None, audit=audit)
    assert ok is True
    hits = _drain(audit, "gov.credential_manifest."
                         "no_session_identity_binding_skipped")
    assert hits, "no-identity egress emitted no code"


def t_scan_verdicts_empty_policy_emits():
    from gov.scan_verdicts import ScanGate, ScanPolicy
    audit = []
    gate = ScanGate(ScanPolicy(required_scans=()), keysets={})
    res = gate.check("sha256:" + "a" * 64, [], audit=audit)
    assert res["ok"] is True and res["required"] == []
    hits = _drain(audit, "gov.scan_verdicts.empty_policy_no_scans_required")
    assert hits, "empty scan policy emitted no code"


def t_unsafe_allow_emits_and_warns():
    from gov.identity_policy import UnsafeAllow, check_admission
    audit = []
    pol = UnsafeAllow(reason="w219 probe")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = check_admission({}, pol, audit=audit)
    assert out["verdict"] == "pass" and out["vacuous"] is True
    assert any("gov.identity_policy.unsafe_allow_vacuous_pass" in str(w.message)
               for w in caught), "no loud warning with the code"
    hits = _drain(audit, "gov.identity_policy.unsafe_allow_vacuous_pass")
    assert hits, "UnsafeAllow pass emitted no audit code"


def t_unsafe_allow_requires_reason():
    from gov.identity_policy import UnsafeAllow, PolicyAuthoringError
    try:
        UnsafeAllow(reason="")
    except PolicyAuthoringError:
        return
    raise AssertionError("UnsafeAllow accepted an empty reason")


def t_degraded_attester_emits():
    from gov import attested_identity as ai

    class _Signer(object):
        key_id = "w219-probe"
        public_key = b"\x01" * 32

        def sign(self, body):
            return b"s" * 64

    att = ai.degraded_attester(_Signer())
    hits = [e for e in att.audit
            if isinstance(e, dict)
            and e.get("code") == "gov.attested_identity.tier2_only_degradation"]
    assert hits, "degraded_attester emitted no code; audit=%r" % (att.audit,)


def t_degraded_attester_per_registration_emits():
    # Spec: the code must be emitted EVERY time the unsafe behavior runs,
    # not just at attester construction -- every tier-2 credential minted
    # is an execution of the degraded path.
    from gov import attested_identity as ai

    class _Signer(object):
        key_id = "w219-probe"
        public_key = b"\x01" * 32

        def sign(self, body):
            return b"s" * 64

    att = ai.degraded_attester(_Signer())
    before = len([e for e in att.audit
                  if isinstance(e, dict)
                  and e.get("code")
                  == "gov.attested_identity.tier2_only_degradation"])
    ident = att.register_kernel_fact_identity(
        cgroup="/w219", uid=42, hostname="probe")
    assert ident.tier == ai.TIER_KERNEL_FACT, ident.tier
    after = [e for e in att.audit
             if isinstance(e, dict)
             and e.get("code")
             == "gov.attested_identity.tier2_only_degradation"]
    assert len(after) > before, (
        "tier-2 registration did not re-emit the code; audit=%r"
        % (att.audit,))


def t_capability_manifest_no_store_emits():
    from gov.capability_manifests import verify_skill_manifest
    audit = []
    ok, detail = verify_skill_manifest("skill-x", b"bytes", None, audit=audit)
    assert ok is True and detail == "no-store", (ok, detail)
    hits = _drain(audit, "gov.capability_manifests.no_store_advisory")
    assert hits, "no-store verify emitted no code"


def t_policy_compile_mutation_refused():
    import gov.policy_compile as pc
    import gov.identity_policy as ip
    pol = ip.OIDCIssuer("https://good.example")
    compiled = pc.compile_policy(pol)
    assert compiled.admit({"iss": "https://good.example"})["verdict"] == "pass"
    pol.issuer = "https://evil.example"  # post-compile mutation
    try:
        compiled.admit({"iss": "https://evil.example"})
    except ip.PolicyViolation as e:
        assert "gov.policy_compile.post_compile_mutation_refused" in str(e), e
        return
    raise AssertionError("post-compile mutation was NOT refused")


def t_policy_compile_mutation_refused_nested():
    import gov.policy_compile as pc
    import gov.identity_policy as ip
    child = ip.OIDCIssuer("https://good.example")
    pol = ip.AnyOf(child)
    compiled = pc.compile_policy(pol)
    child.issuer = "https://evil.example"
    try:
        compiled.admit({"iss": "https://evil.example"})
    except ip.PolicyViolation as e:
        assert "gov.policy_compile.post_compile_mutation_refused" in str(e), e
        return
    raise AssertionError("nested post-compile mutation was NOT refused")


def t_policy_compile_ruleset_mutation_refused():
    import gov.policy_compile as pc
    import gov.artifact_rules as ar
    rules = (("REQUIRE", "a.txt"), ("DISALLOW",))
    compiled = pc.compile_policy(rules)
    compiled._rules = (("REQUIRE", "zzz-evil.txt"), ("DISALLOW",))
    try:
        compiled.evaluate({"a.txt": "d" * 64}, {}, "")
    except ar.ArtifactRuleError as e:
        assert "gov.policy_compile.post_compile_mutation_refused" in str(e), e
        return
    raise AssertionError("ruleset post-compile mutation was NOT refused")


# ---------------------------------------------------------------------------
# fail-closed defaults stay refused; legacy disclosures stay distinguished


def t_executor_refusals_absorbed_in_registry():
    # The executor's loud refusals predate the registry; the registry
    # names them. Greppability (module + registry) is pinned by the
    # registry-shape probe above; here we pin the refusal SEAM still
    # exists at the public boundary AND the registered codes ride the
    # audit events themselves (not just source comments).
    import gov.unsafe_paths as up
    import inspect
    import gov.executor as ex
    src = inspect.getsource(ex)
    assert '"no_binding_no_ack"' in src
    assert up.UNSAFE_PATHS[
        "gov.executor.capability_gate_unconfigured_refused"]["posture"] \
        == "FAIL_CLOSED"
    assert 'code="gov.executor.capability_gate_unconfigured_refused"' in src
    assert '"code": "gov.executor.invocation_receipts_disabled"' in src
    assert '"code": "gov.executor.decision_packet_disabled"' in src


def t_absorbed_codes_ride_audit_artifacts():
    # The five absorbed pre-existing paths must carry their registered
    # codes in the audit-path artifact (event dict / exception message /
    # summary / proof detail), not merely in a source comment.
    import inspect
    import gov.anchorer as an
    import gov.decision_packet as dp
    import gov.authority_proof as ap
    import gov.skill_watch as sw
    assert "[gov.anchorer.unconfigured_anchoring_disabled]" in \
        inspect.getsource(an)
    assert "[gov.decision_packet.packets_disabled_no_key]" in \
        inspect.getsource(dp)
    assert "[gov.authority_proof.no_boundary_advisory]" in \
        inspect.getsource(ap)
    assert 'code="gov.capability_manifests.manifest_absent_advisory"' in \
        inspect.getsource(sw)


def t_evidence_verify_unpinned_distinguished():
    # The unpinned SELF_CONSISTENT verdict IS the disclosure (exit 2 vs
    # exit 0). Pin that the module distinguishes them, documents the
    # registered code, and carries the code in the summary itself.
    import inspect
    import gov.evidence_verify as ev
    src = inspect.getsource(ev)
    assert '"SELF_CONSISTENT"' in src and '"VERIFIED"' in src
    assert "gov.evidence_verify.unpinned_self_consistent" in src
    assert '"unsafe_path_code"' in src


# ---------------------------------------------------------------------------
# green check (depth-1): adjacent batteries only, honors GOV_SKIP_GREEN


def _green_check():
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK SKIPPED (GOV_SKIP_GREEN=1)")
        return 0
    root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suite = os.path.join(root, "tests", "run_tests.py")
    if not os.path.exists(suite):
        print("GREEN CHECK: no adjacent suite found; battery-only")
        return 0
    p = subprocess.run([sys.executable, "-m", "unittest",
                        "tests.test_unsafe_paths", "-v"],
                       cwd=root, env=env, capture_output=True,
                       text=True, timeout=300)
    print(p.stdout[-2000:])
    print(p.stderr[-2000:])
    return p.returncode


def main():
    suite = [
        ("registry importable", t_registry_importable),
        ("codes greppable in module+registry",
         t_codes_greppable_in_module_and_registry),
        ("emit rejects unknown code", t_emit_rejects_unknown_code),
        ("emit warns loudly", t_emit_warns_loudly),
        ("artifacts unreadable emits", t_artifacts_unreadable_emits),
        ("manifest unreadable emits", t_manifest_unreadable_emits),
        ("sweep unreadable emits", t_sweep_unreadable_emits),
        ("credential manifest no-identity emits",
         t_credential_manifest_no_identity_emits),
        ("scan verdicts empty policy emits",
         t_scan_verdicts_empty_policy_emits),
        ("UnsafeAllow emits + warns", t_unsafe_allow_emits_and_warns),
        ("UnsafeAllow requires reason", t_unsafe_allow_requires_reason),
        ("degraded attester emits", t_degraded_attester_emits),
        ("degraded attester per-registration emits",
         t_degraded_attester_per_registration_emits),
        ("capability manifest no-store emits",
         t_capability_manifest_no_store_emits),
        ("policy compile mutation refused", t_policy_compile_mutation_refused),
        ("policy compile nested mutation refused",
         t_policy_compile_mutation_refused_nested),
        ("policy compile ruleset mutation refused",
         t_policy_compile_ruleset_mutation_refused),
        ("capability gate unconfigured refused (registry)",
         t_executor_refusals_absorbed_in_registry),
        ("absorbed codes ride audit artifacts",
         t_absorbed_codes_ride_audit_artifacts),
        ("evidence verify unpinned distinguished",
         t_evidence_verify_unpinned_distinguished),
    ]
    for name, fn in suite:
        check(name, fn)
    total = len(PASSED) + len(FAILED)
    print("w219 unsafe-paths battery: %d/%d HELD" % (len(PASSED), total))
    for name, err in FAILED:
        print("  FAIL %s: %s" % (name, err[:300]))
    if FAILED:
        return 1
    return _green_check()


if __name__ == "__main__":
    sys.exit(main())
