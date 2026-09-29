#!/usr/bin/env python3
"""Break-first battery for gov/claim_bounds.py (wave-209 lane A).

The narrow-claims discipline (W3C VC "verifiable != true", SCITT
"receipts prove action/principal/policy/verdict, not correctness",
TEE "platform+image, never behavior") becomes a MANDATORY primitive:
every evidence bundle must declare claim bounds, and the offline
verifier refuses boundless or overstated bundles.

Red-first: on pristine 53c7974 the module is absent -> every probe is a
genuine GAP (ImportError). On the fixed tree all probes must HOLD,
twice, under `env -u GOV_DEPLOYMENT_MODE` as well.

Probe list:
  1. module_importable
  2. boundless_bounds_refused            (validate_bounds({}) names the field)
  3. empty_does_not_prove_refused        (degenerate honesty dodge)
  4. proves_does_not_prove_disjoint      (token in both -> refused, named)
  5. overlap_refuses_broader_claim        (token outside proves -> named)
  6. overlap_accepts_covered_claims
  7. assignment_exact_set                (missing/extra section, stray token)
  8. vc_bridge_consistent                (VC claimBounds -> canonical schema)
  9. bundle_end_to_end_v18_green          (genuine bundle: V18 present + ok)
 10. boundless_bundle_refused             (stripped bounds -> V18 names claim_bounds)
 11. overstated_section_refused          (stray token in assignment -> V18 names it)
 12. empty_does_not_prove_bundle_refused
 13. determinism (probes 2-8 re-run; verdict change = ERROR)

$0 spend. No network. stdlib only.
"""

import copy
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                # Pristine tree: the module does not exist. Genuine red.
                _RESULTS.append((name, "GAP", "module absent: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "BROKEN", str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                % (type(e).__name__, str(e)[:300])))
                return
            _RESULTS.append((name, "HELD", detail))
        return run
    return deco


def _need_bounds_module():
    import gov.claim_bounds as cb  # noqa: F401
    return cb


@_probe("module_importable")
def p_import():
    cb = _need_bounds_module()
    assert callable(cb.validate_bounds), "validate_bounds missing"
    assert callable(cb.claims_within_bounds), "claims_within_bounds missing"
    assert callable(cb.validate_claim_assignment), \
        "validate_claim_assignment missing"
    assert callable(cb.default_bundle_bounds), "default_bundle_bounds missing"
    assert issubclass(cb.ClaimBoundsError, Exception)
    return "schema + error vocabulary present"


@_probe("boundless_bounds_refused")
def p_boundless():
    cb = _need_bounds_module()
    try:
        cb.validate_bounds({})
    except cb.ClaimBoundsError as e:
        assert "proves" in str(e), "error must name the missing field: %s" % e
        return "refused, names 'proves'"
    raise AssertionError("boundless bounds accepted")


@_probe("empty_does_not_prove_refused")
def p_empty_dnp():
    cb = _need_bounds_module()
    good = cb.default_bundle_bounds()
    bad = dict(good)
    bad["does_not_prove"] = []
    try:
        cb.validate_bounds(bad)
    except cb.ClaimBoundsError as e:
        assert "does_not_prove" in str(e), \
            "error must name does_not_prove: %s" % e
        return "empty does_not_prove refused (degenerate honesty dodge)"
    raise AssertionError("empty does_not_prove accepted")


@_probe("proves_does_not_prove_disjoint")
def p_disjoint():
    cb = _need_bounds_module()
    good = cb.default_bundle_bounds()
    bad = dict(good)
    bad["does_not_prove"] = list(good["does_not_prove"]) + [good["proves"][0]]
    try:
        cb.validate_bounds(bad)
    except cb.ClaimBoundsError as e:
        assert good["proves"][0] in str(e), \
            "error must name the incoherent token: %s" % e
        return "incoherent token refused, named"
    raise AssertionError("proves/d does_not_prove overlap accepted")


@_probe("overlap_refuses_broader_claim")
def p_overlap_broader():
    cb = _need_bounds_module()
    proves = ["recorded-events-integrity", "event-inclusion"]
    try:
        cb.claims_within_bounds("evidence[0]", ["truth-of-recorded-events"],
                                proves)
    except cb.ClaimBoundsError as e:
        assert "truth-of-recorded-events" in str(e), \
            "error must name the stray token: %s" % e
        return "broader claim refused, token named"
    raise AssertionError("broader-than-proves claim accepted")


@_probe("overlap_accepts_covered_claims")
def p_overlap_ok():
    cb = _need_bounds_module()
    proves = ["recorded-events-integrity", "event-inclusion"]
    cb.claims_within_bounds("evidence[0]", ["event-inclusion"], proves)
    cb.claims_within_bounds("evidence[1]", [], proves)
    return "covered claims accepted"


@_probe("assignment_exact_set")
def p_assignment():
    cb = _need_bounds_module()
    sections = _nine_sections()
    good = cb.default_bundle_bounds()
    proves = good["proves"]
    ok_assign = cb.default_claim_assignment(sections, proves,
                                            discovery_present=True)
    cb.validate_claim_assignment(ok_assign, sections, proves)
    # Missing section -> refused.
    missing = dict(ok_assign)
    missing.pop("decisions")
    try:
        cb.validate_claim_assignment(missing, sections, proves)
    except cb.ClaimBoundsError as e:
        assert "decisions" in str(e)
    else:
        raise AssertionError("missing section accepted")
    # Extra section -> refused (no smuggled claim surface).
    extra = dict(ok_assign)
    extra["backdoor"] = ["recorded-events-integrity"]
    try:
        cb.validate_claim_assignment(extra, sections, proves)
    except cb.ClaimBoundsError as e:
        assert "backdoor" in str(e)
    else:
        raise AssertionError("extra section accepted")
    # Stray token -> refused, named.
    stray = copy.deepcopy(ok_assign)
    stray["citations"].append("truth-of-recorded-events")
    try:
        cb.validate_claim_assignment(stray, sections, proves)
    except cb.ClaimBoundsError as e:
        assert "truth-of-recorded-events" in str(e), \
            "stray token must be named: %s" % e
    else:
        raise AssertionError("stray token accepted")
    return "exact-set + token membership enforced"


@_probe("v18_parity_with_canonical")
def p_parity():
    """The V18 rules are deliberately duplicated inside
    gov/evidence_verify.py (the standalone verifier cannot import the
    repo). This probe runs an edge-case corpus through BOTH
    implementations and fails on any verdict divergence -- the
    regression guard against rule drift."""
    import types
    cb = _need_bounds_module()
    from gov import evidence_verify as ev
    sections = _nine_sections() + ["discovery"]
    good = cb.default_bundle_bounds()
    proves = good["proves"]
    good_assign = cb.default_claim_assignment(sections, proves,
                                              discovery_present=True)

    def v18_verdict(bounds, assignment):
        payload = {"sections_meta": {}}
        for s in sections:
            payload[s] = {}
        if bounds is not None:
            payload["claim_bounds"] = bounds
        if assignment is not None:
            payload["claim_assignment"] = assignment
        ctx = types.SimpleNamespace(payload=payload)
        return ev.v18_claim_bounds(ctx).status == "pass"

    def canon_verdict(bounds, assignment):
        try:
            norm = cb.validate_bounds(bounds)
            if assignment is None:
                raise cb.ClaimBoundsError("missing assignment")
            cb.validate_claim_assignment(assignment, sections,
                                         norm["proves"])
        except cb.ClaimBoundsError:
            return False
        return True

    cases = [("good", good, good_assign)]
    b = dict(good)
    del b["proves"]
    cases.append(("missing-proves", b, good_assign))
    b = dict(good)
    b["does_not_prove"] = []
    cases.append(("empty-does_not_prove", b, good_assign))
    b = dict(good)
    b["does_not_prove"] = (list(good["does_not_prove"])
                           + [good["proves"][0]])
    cases.append(("incoherent-token", b, good_assign))
    b = dict(good)
    b["proves"] = good["proves"] + [good["proves"][0]]
    cases.append(("duplicate-token", b, good_assign))
    b = dict(good)
    b["mystery"] = ["x"]
    cases.append(("unknown-field", b, good_assign))
    b = dict(good)
    b["proves"] = "not-a-list"
    cases.append(("non-list-proves", b, good_assign))
    b = dict(good)
    b["proves"] = [""]
    cases.append(("empty-token", b, good_assign))
    cases.append(("no-bounds", None, good_assign))
    cases.append(("no-assignment", good, None))
    a = dict(good_assign)
    del a["decisions"]
    cases.append(("missing-section", good, a))
    a = dict(good_assign)
    a["backdoor"] = ["recorded-events-integrity"]
    cases.append(("extra-section", good, a))
    a = copy.deepcopy(good_assign)
    a["citations"] = a["citations"] + ["truth-of-recorded-events"]
    cases.append(("stray-token", good, a))
    a = dict(good_assign)
    a["policy"] = []
    cases.append(("empty-section-claims", good, a))

    diverged = []
    for name, bounds, assignment in cases:
        cv = canon_verdict(bounds, assignment)
        vv = v18_verdict(bounds, assignment)
        if cv != vv:
            diverged.append("%s: canonical=%s v18=%s" % (name, cv, vv))
    assert not diverged, "verdict divergence: %s" % "; ".join(diverged)
    return ("%d edge cases agree across both implementations"
            % len(cases))


@_probe("vc_bridge_consistent")
def p_vc_bridge():
    cb = _need_bounds_module()
    from gov import vc_bundle
    vc_bounds = vc_bundle._build_claim_bounds(None)  # defaults
    canon = cb.from_vc_bounds(vc_bounds)
    norm = cb.validate_bounds(canon)  # must not raise
    assert norm["does_not_prove"], "bridge must preserve non-empty dnp"
    # Custom VC bounds round-trip through the same bridge.
    custom = vc_bundle._build_claim_bounds(
        {"proves": ["a-proven-thing"],
         "doesNotProve": ["a-not-proven-thing"]})
    canon2 = cb.from_vc_bounds(custom)
    assert "a-proven-thing" in canon2["proves"]
    assert "a-not-proven-thing" in canon2["does_not_prove"]
    return "VC claimBounds validate under the canonical schema"


def _nine_sections():
    return ["bundle_meta", "log_slice", "policy", "decisions", "approvals",
            "citations", "benchmark", "kms_attestation",
            "retention_manifest"]


# ---------------------------------------------------------------- bundle end
# to end: genuine bundles through EvidenceBundle + verify_bundle.

def _build_test_bundle(tmp, mutate=None):
    """Build a genuine bundle; optionally mutate payload pre-seal."""
    from tests.keyfixture import provision_test_key, scrub_key_env
    from gov.signing import Ed25519Signer
    from gov.log import ActionLog
    from gov.evidence_bundle import EvidenceBundle, log_evidence_bundle_receipt

    restore = scrub_key_env()
    try:
        provision_test_key()
        signer = Ed25519Signer(bytes.fromhex("11" * 32))
        log_path = os.path.join(tmp, "audit.log")
        log = ActionLog(log_path, signer=signer,
                        deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_version": "p1",
                    "policy_hash": "h" * 16, "policy_path": "policies/p1.yaml",
                    "pinned": True})
        for i in range(3):
            log.append({"event": "tool_call", "decision": "allow",
                        "tool": "tool-%d" % i})
        eb = EvidenceBundle(log_path,
                            exported_at="2026-09-26T00:00:00+00:00",
                            operator_id="claim-bounds-battery")
        payload = eb.build()
        if mutate:
            mutate(payload)
        manifest = eb.seal(payload, signer=signer)
        log_evidence_bundle_receipt(
            manifest, ActionLog(log_path, signer=signer,
                                deployment_mode="staging"), signer=signer)
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        out = os.path.join(tmp, "bundle")
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out
    finally:
        restore()


def _v18(bundle_dir):
    from gov.evidence_verify import verify_bundle
    code, checks, _summary = verify_bundle(bundle_dir)
    v18 = [c for c in checks if c.id == "V18"]
    assert v18, "V18 check missing from verify_bundle"
    return code, v18[0]


@_probe("bundle_end_to_end_v18_green")
def p_e2e():
    tmp = tempfile.mkdtemp(prefix="cb-e2e-")
    bundle_dir = _build_test_bundle(tmp)
    code, v18 = _v18(bundle_dir)
    assert v18.status == "pass", "genuine bundle V18 not ok: %s" % v18.detail
    assert code in (0, 2), "genuine bundle exit %d" % code
    return "V18 ok on genuine bundle (exit %d)" % code


@_probe("boundless_bundle_refused")
def p_boundless_bundle():
    tmp = tempfile.mkdtemp(prefix="cb-nobounds-")

    def strip(payload):
        payload.pop("claim_bounds", None)
        payload.pop("claim_assignment", None)

    bundle_dir = _build_test_bundle(tmp, mutate=strip)
    _code, v18 = _v18(bundle_dir)
    assert v18.status == "fail", \
        "boundless bundle not refused: %s" % v18.detail
    assert "claim_bounds" in v18.detail, \
        "V18 must name claim_bounds: %s" % v18.detail
    return "boundless bundle refused, claim_bounds named"


@_probe("overstated_section_refused")
def p_overstated_bundle():
    tmp = tempfile.mkdtemp(prefix="cb-over-")

    def overstate(payload):
        payload["claim_assignment"]["decisions"].append(
            "truth-of-recorded-events")

    bundle_dir = _build_test_bundle(tmp, mutate=overstate)
    _code, v18 = _v18(bundle_dir)
    assert v18.status == "fail", \
        "overstated bundle not refused: %s" % v18.detail
    assert "truth-of-recorded-events" in v18.detail, \
        "V18 must name the stray token: %s" % v18.detail
    return "overstated section refused, token named"


@_probe("empty_does_not_prove_bundle_refused")
def p_empty_dnp_bundle():
    tmp = tempfile.mkdtemp(prefix="cb-emptydnp-")

    def empty_dnp(payload):
        payload["claim_bounds"]["does_not_prove"] = []

    bundle_dir = _build_test_bundle(tmp, mutate=empty_dnp)
    _code, v18 = _v18(bundle_dir)
    assert v18.status == "fail", \
        "empty does_not_prove bundle not refused: %s" % v18.detail
    assert "does_not_prove" in v18.detail, \
        "V18 must name does_not_prove: %s" % v18.detail
    return "empty does_not_prove refused at the bundle seam"


def green_check():
    """Depth-1 green check: honors GOV_SKIP_GREEN; never spawns another
    battery's main. Standalone run: adjacent unit suite smoke."""
    if GREEN_SKIP:
        return {"green_check": "skipped (GOV_SKIP_GREEN=1)"}
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_claim_bounds", "-v"],
        cwd=REPO, capture_output=True, text=True, timeout=600)
    ok = r.returncode == 0
    return {"green_check": "pass" if ok else "FAIL",
            "detail": (r.stdout + r.stderr)[-1500:]}


def main():
    probes = [p_import, p_boundless, p_empty_dnp, p_disjoint,
              p_overlap_broader, p_overlap_ok, p_assignment, p_parity,
              p_vc_bridge,
              p_e2e, p_boundless_bundle, p_overstated_bundle,
              p_empty_dnp_bundle]
    # Each probe runs twice: verdict change between runs is an ERROR.
    first = {}
    for p in probes:
        p()
    for name, status, detail in _RESULTS:
        first[name] = (status, detail)
    _RESULTS.clear()
    for p in probes:
        p()
    final = []
    for name, status, detail in _RESULTS:
        prev_status, _prev = first[name]
        if status != prev_status:
            final.append((name, "ERROR",
                          "non-deterministic: %s then %s"
                          % (prev_status, status)))
        else:
            final.append((name, status, detail))
    held = sum(1 for _n, s, _d in final if s == "HELD")
    gap = sum(1 for _n, s, _d in final if s == "GAP")
    broken = sum(1 for _n, s, _d in final if s == "BROKEN")
    errors = sum(1 for _n, s, _d in final if s == "ERROR")
    print("claim_bounds probes: %d/%d HELD, %d GAP, %d BROKEN, %d ERROR"
          % (held, len(final), gap, broken, errors))
    for name, status, detail in final:
        print("  [%s] %s: %s" % (status, name, detail))
    gc = green_check()
    print("green_check: %s" % gc["green_check"])
    result = {"probes": [{"name": n, "status": s, "detail": d}
                         for n, s, d in final],
              "summary": {"held": held, "gap": gap, "broken": broken,
                          "error": errors},
              "green_check": gc}
    print(json.dumps(result["summary"]))
    if broken or errors or (held == 0 and gap == 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
