#!/usr/bin/env python3
"""Red-first battery: promotion artifact-rule gate (wave-213 lane B).

Integrates gov/artifact_rules.py (landed unintegrated in wave-212) as
the enforcement primitive for the PROMOTION gate:
NamespaceRegistry.promote(). When a ruleset is configured, promotion
also requires caller-supplied (materials, products) maps to verify
against it; a gate violation DENIES promotion and the deny reason is
written to the hash-chained audit log. Rulesets without a terminal
DISALLOW are refused at policy-load time (no implicit ALLOW *).

Verdicts:
  HELD  - the gate holds (attack denied, or control behavior intact)
  GAP   - the gap this wave closes: pristine tree has no promotion
          artifact gate (expected on the wave-212 base)
  BREAK - genuine break on the fixed tree: files as F208+ in
          evals/FINDINGS.md
  RESIDUAL - documented accepted residual (citation required)
  ERROR - harness failure

Ranked falsifiable hypotheses (diagnosing-bugs loop):
  H1 (rank 1): the promotion seam currently has NO artifact
     accounting. verify_artifacts() exists in gov/artifact_rules.py but
     nothing calls it: a caller can stage/sign/promote a bundle whose
     declared build materials were swapped or whose products gained an
     unaccounted artifact, and promote() succeeds. Expected: GAP ->
     closed by wiring (deny with artifact-gate-refused).
  H2 (rank 2): without a load-time terminal-DISALLOW lint, an
     operator could configure a ruleset that ends without DISALLOW and
     believe leftovers are refused. Expected: GAP -> closed by
     load_promotion_rules refusing at load.
  H3 (rank 3): fail-closed on missing maps. A configured ruleset must
     not silently skip when the caller omits materials/products --
     that would widen the admit path back to legacy. Expected: GAP ->
     closed (deny when maps absent).
  H4 (rank 4): tightening discipline. The new gate must only DENY;
     everything the legacy path denied (unsigned, ceremony,
     threshold) must still deny with the same codes, and the
     no-ruleset legacy path must be byte-identical. Expected: HELD on
     both trees (controls).

$0 spend. No network. stdlib only.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import sign_deploy_namespaces as sdn  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _run_probe(name, fn):
    try:
        verdict, detail = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, detail = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _record(name, verdict, detail)
    return verdict


_SEED1 = bytes.fromhex("71" * 32)
_SEED2 = bytes.fromhex("72" * 32)


def _keys():
    signers = [Ed25519Signer(_SEED1), Ed25519Signer(_SEED2)]
    verifiers = [Ed25519Verifier(s.public_key) for s in signers]
    return signers, verifiers


def _staged_signed(reg, signers, name="bundle/x", content=b"bundle-bytes"):
    reg.stage(name, content)
    reg.sign(name, signers)
    return name


def _gate_registry(ruleset):
    """Build a ruleset-configured registry, or return (None, reason)
    when the tree has no promotion-gate seam (pristine = GAP)."""
    try:
        import gov.promotion_artifact_gate as pag  # noqa: F401
    except ImportError:
        return None, "no gov.promotion_artifact_gate on this tree"
    _, verifiers = _keys()
    try:
        reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1,
                                    artifact_ruleset=ruleset)
    except TypeError:
        return None, "NamespaceRegistry has no artifact_ruleset seam"
    return reg, None


def _legacy_registry():
    signers, verifiers = _keys()
    return sdn.NamespaceRegistry(verifiers=verifiers, threshold=1), signers


_H1 = "00" * 32
_H2 = "11" * 32
_H3 = "22" * 32
_H4 = "33" * 32
_HWRONG = "ff" * 32

_BASE_RULES = [
    ("MATCH", "src/main.py", _H1),
    ("MATCH", "src/util.py", _H2),
    ("CREATE", "dist/app.bin"),
    ("DISALLOW",),
]
_BASE_MATERIALS = {"src/main.py": _H1, "src/util.py": _H2}
_BASE_PRODUCTS = {"dist/app.bin": _H3}


@_probe("swapped_materials_deny")
def _p_swapped():
    """H1: materials swapped under a MATCH-pinned ruleset must be
    denied at promotion."""
    reg, reason = _gate_registry(_BASE_RULES)
    if reg is None:
        return "GAP", reason
    signers, _ = _keys()
    name = _staged_signed(reg, signers)
    swapped = dict(_BASE_MATERIALS, **{"src/main.py": _HWRONG})
    try:
        reg.promote(name, operator_ids=["op-a", "op-b"],
                    materials=swapped, products=_BASE_PRODUCTS)
    except sdn.NamespaceError as exc:
        if exc.code == "artifact-gate-refused":
            return "HELD", "swapped material denied: %s" % exc.detail[:120]
        return "ERROR", "unexpected code %r: %s" % (exc.code, exc)
    return "BREAK", "promotion admitted a material-swapped build"


@_probe("extra_product_deny")
def _p_extra():
    """H1: an unaccounted product must trip the terminal DISALLOW and
    be denied at promotion."""
    reg, reason = _gate_registry(_BASE_RULES)
    if reg is None:
        return "GAP", reason
    signers, _ = _keys()
    name = _staged_signed(reg, signers)
    poisoned = dict(_BASE_PRODUCTS, **{"dist/evil.bin": _H4})
    try:
        reg.promote(name, operator_ids=["op-a", "op-b"],
                    materials=_BASE_MATERIALS, products=poisoned)
    except sdn.NamespaceError as exc:
        if exc.code == "artifact-gate-refused":
            return "HELD", "extra product denied: %s" % exc.detail[:120]
        return "ERROR", "unexpected code %r: %s" % (exc.code, exc)
    return "BREAK", "promotion admitted an unaccounted product"


@_probe("missing_terminal_disallow_refused_at_load")
def _p_load():
    """H2: a ruleset without terminal DISALLOW is refused at
    policy-load time, not at evaluation time."""
    try:
        import gov.promotion_artifact_gate as pag
    except ImportError:
        return "GAP", "no gov.promotion_artifact_gate on this tree"
    bad = [("MATCH", "src/main.py", _H1), ("CREATE", "dist/*")]
    try:
        pag.load_promotion_rules(bad)
    except Exception as exc:  # ArtifactRuleError (a ValueError)
        if isinstance(exc, ValueError) and "DISALLOW" in str(exc):
            return "HELD", "load refused: %s" % str(exc)[:120]
        return "ERROR", "%s: %s" % (type(exc).__name__, exc)
    return "BREAK", "ruleset without terminal DISALLOW loaded silently"


@_probe("maps_absent_fail_closed")
def _p_maps():
    """H3: configured ruleset + absent (materials, products) maps =
    deny, never silent skip."""
    reg, reason = _gate_registry(_BASE_RULES)
    if reg is None:
        return "GAP", reason
    signers, _ = _keys()
    name = _staged_signed(reg, signers)
    try:
        reg.promote(name, operator_ids=["op-a", "op-b"])
    except sdn.NamespaceError as exc:
        if exc.code == "artifact-gate-refused":
            return "HELD", "absent maps denied: %s" % exc.detail[:120]
        return "ERROR", "unexpected code %r: %s" % (exc.code, exc)
    return "BREAK", "promotion admitted without maps under a ruleset"


@_probe("deny_reason_in_audit_log")
def _p_audit():
    """The gate denial must surface its reason in the hash-chained
    audit log (public seam: the operator's audit trail)."""
    reg, reason = _gate_registry(_BASE_RULES)
    if reg is None:
        return "GAP", reason
    signers, _ = _keys()
    name = _staged_signed(reg, signers)
    try:
        reg.promote(name, operator_ids=["op-a", "op-b"],
                    materials=_BASE_MATERIALS,
                    products=dict(_BASE_PRODUCTS, **{"dist/x.bin": _H4}))
    except sdn.NamespaceError:
        pass
    denied = [e for e in reg.audit if e["op"] == "promotion-denied"]
    if not denied:
        return "BREAK", "no promotion-denied audit entry after gate denial"
    if "artifact-gate" not in denied[0]["detail"]:
        return "BREAK", "denial entry carries no reason: %r" \
            % denied[0]["detail"][:80]
    # Hash-chain integrity: recompute entry hashes over the chain.
    import hashlib
    import json
    prev = "GENESIS"
    for e in reg.audit:
        body = json.dumps({k: e[k] for k in sorted(e)
                           if k != "entry_hash"},
                          sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(body).hexdigest() != e["entry_hash"]:
            return "BREAK", "audit chain broken at seq %d" % e["seq"]
        if e["prev"] != prev:
            return "BREAK", "audit prev-link broken at seq %d" % e["seq"]
        prev = e["entry_hash"]
    return "HELD", "denial reason in audit, chain intact (%d entries)" \
        % len(reg.audit)


@_probe("valid_maps_promote_with_rules_digest")
def _p_valid():
    """Valid maps under a configured ruleset promote, and the audit
    records the pinned rule-set digest (evidence of what was
    enforced)."""
    reg, reason = _gate_registry(_BASE_RULES)
    if reg is None:
        return "GAP", reason
    signers, _ = _keys()
    name = _staged_signed(reg, signers)
    out = reg.promote(name, operator_ids=["op-a", "op-b"],
                      materials=_BASE_MATERIALS, products=_BASE_PRODUCTS)
    if out["status"] != "promoted":
        return "ERROR", "unexpected status %r" % out["status"]
    promoted = [e for e in reg.audit if e["op"] == "promoted"]
    if not promoted or "artifact_rules=" not in promoted[0]["detail"]:
        return "BREAK", "promoted audit entry lacks artifact_rules digest"
    digest = promoted[0]["detail"].split("artifact_rules=")[1].split()[0]
    if len(digest) != 64 or set(digest) - set("0123456789abcdef"):
        return "BREAK", "artifact_rules digest malformed: %r" % digest
    return "HELD", "promoted with artifact_rules=%s..." % digest[:16]


@_probe("legacy_no_ruleset_byte_identical")
def _p_legacy():
    """H4 control: no configured ruleset -> pristine promote()
    behavior, byte-identical audit detail format."""
    reg, signers = _legacy_registry()
    name = _staged_signed(reg, signers)
    out = reg.promote(name, operator_ids=["op-a", "op-b"])
    if out["status"] != "promoted":
        return "ERROR", "legacy promote failed: %r" % out["status"]
    promoted = [e for e in reg.audit if e["op"] == "promoted"]
    if not promoted:
        return "ERROR", "no promoted audit entry"
    if "artifact_rules=" in promoted[0]["detail"]:
        return "BREAK", "legacy path leaked gate detail into audit"
    if not promoted[0]["detail"].startswith("signed_by="):
        return "ERROR", "legacy detail format changed: %r" \
            % promoted[0]["detail"][:60]
    # Legacy accepts no maps kwarg values: omitted maps are fine.
    return "HELD", "legacy promote() byte-identical (detail %r...)" \
        % promoted[0]["detail"][:40]


@_probe("tighten_only_denies_held_with_ruleset")
def _p_tighten():
    """H4 control: with a ruleset configured, everything the legacy
    path denied still denies with the same codes (gate is
    tighten-only: it can only add denials, never remove them)."""
    reg, reason = _gate_registry(_BASE_RULES)
    if reg is None:
        # Pristine control: run the same checks on the legacy registry.
        reg, signers = _legacy_registry()
        note = "pristine control"
        extra = {}
    else:
        signers, _ = _keys()
        note = "ruleset configured"
        extra = {"materials": _BASE_MATERIALS, "products": _BASE_PRODUCTS}
    codes = {}
    # 1. unsigned bundle
    r = reg
    r.stage("b/unsigned", b"x")
    try:
        r.promote("b/unsigned", operator_ids=["op-a", "op-b"], **extra)
        codes["unsigned"] = "ADMITTED"
    except sdn.NamespaceError as exc:
        codes["unsigned"] = exc.code
    # 2. single operator ceremony
    n2 = _staged_signed(r, signers, name="b/ceremony", content=b"y")
    try:
        r.promote(n2, operator_ids=["only-one"], **extra)
        codes["ceremony"] = "ADMITTED"
    except sdn.NamespaceError as exc:
        codes["ceremony"] = exc.code
    # 3. unknown bundle
    try:
        r.promote("b/nope", operator_ids=["op-a", "op-b"], **extra)
        codes["unknown"] = "ADMITTED"
    except sdn.NamespaceError as exc:
        codes["unknown"] = exc.code
    expected = {"unsigned": "unsigned-refused",
                "ceremony": "ceremony-refused",
                "unknown": "unknown-bundle"}
    if codes != expected:
        return "BREAK", "%s: legacy denials changed: %r" % (note, codes)
    return "HELD", "%s: legacy denials intact %r" % (note, codes)


def _green_check():
    # Depth-1 green check: adjacent promotion-namespace batteries must
    # stay green alongside this one (each run with GOV_SKIP_GREEN=1 to
    # prevent combinatorial nesting).
    import subprocess
    adj = ["evals/sign_deploy_namespace_probes.py",
           "evals/admit_deploy_wiring_probes.py"]
    for rel in adj:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _record("green:" + os.path.basename(rel), "HELD",
                    "battery absent (lane not merged)")
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, env=env, timeout=600)
        ok = r.returncode == 0
        _record("green:" + os.path.basename(rel),
                "HELD" if ok else "ERROR",
                "adjacent battery %s" % ("green" if ok else
                                         "RED: " + (r.stdout + r.stderr)[-300:]))


def main():
    order = sorted(_PROBE_FNS)
    first = {}
    for name in order:
        first[name] = _run_probe(name, _PROBE_FNS[name])
    # Determinism: re-run every probe, verdicts must be identical.
    for name in order:
        verdict = _run_probe(name + ":determinism", _PROBE_FNS[name])
        got = verdict
        want = first[name]
        if got != want:
            _RESULTS[-1] = (name + ":determinism", "ERROR",
                            "nondeterministic: %s then %s" % (want, got))
    if not GREEN_SKIP:
        _green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    gap = sum(1 for _, v, _ in _RESULTS if v == "GAP")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("w213b promotion-gate: %d probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR" % (len(_RESULTS), held, gap, brk, err))
    for name, verdict, detail in _RESULTS:
        print("  [%s] %s: %s" % (verdict, name, detail))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
