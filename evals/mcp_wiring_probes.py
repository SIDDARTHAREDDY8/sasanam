#!/usr/bin/env python3
"""Wave-198 lane E: red-first probes for the MCP token-claims executor wiring.

The wave-196 lane A built keyset-attested MCP ToolAnnotations and the
``authority_proof.check(..., mcp_tool_registry=..., token_claims=...)``
seam, but the executor never threaded token claims into either
``check()`` call site -- enforcement was live at the library seam only,
dead at the executor seam. This battery proves the gap on the pristine
tree (base d933dd1) and proves the closure on the fixed tree.

Red-first contract:
  - On pristine d933dd1: the ENFORCE probes FAIL (gap demonstrated:
    a scope-missing identity token is NOT refused at the executor
    seam), the LEGACY probes PASS.
  - On the fixed tree: ALL probes PASS.

Each probe asserts the DESIRED end state. Outcome vocabulary:
  PASS = desired behavior holds; FAIL = gap present (expected on
  pristine for the ENFORCE probes); ERROR = harness problem.

Deterministic; synthetic/local only; $0 spend.
"""

import hashlib
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "wave198-mcp-wiring")

LANE_ROOT = Path(__file__).resolve().parents[1]
_lane_tree = LANE_ROOT / "tree"
TREE = str(_lane_tree if _lane_tree.is_dir() else LANE_ROOT)
for _p in (TREE, os.path.join(TREE, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import authority_proof as ap  # noqa: E402
from gov import mcp_annotations as ma  # noqa: E402
from gov.keyset import new_keyset  # noqa: E402
from harness import make_run  # noqa: E402

ISSUER = "https://dex.sasanam.internal"
SCOPE = "mcp:files:read"
READ_ONLY = {"read_only_hint": True, "destructive_hint": False,
             "idempotent_hint": True, "open_world_hint": False}

_records = []


def _record(name, outcome, detail=""):
    _records.append((name, outcome, detail))


def _seed(tag):
    return hashlib.sha256(b"mcp-wiring-probes:" + tag.encode()).digest()


def _registry(scopes=(SCOPE,)):
    ks, _ = new_keyset(_seed("wks"), purpose=ma.ATTESTATION_PURPOSE)
    stmt = ma.attest_tool_annotations(
        ks, "files::read", dict(READ_ONLY), _seed("wks"),
        required_scopes=list(scopes), at=1790000000)
    reg, refused = ma.build_tool_registry([stmt], ks.to_dict())
    assert refused == [], refused
    return reg


def _claims(agent_id, scope, exp_offset=3600):
    now = int(time.time())
    return {"iss": ISSUER, "sub": agent_id,
            "aud": "sasanam-policy-engine", "iat": now - 60,
            "exp": now + exp_offset, "jti": "probe-jti-%s" % agent_id,
            "principal": "org1", "role": "coder", "agent_scope": scope}


def _boundary():
    return ap.boundary_from_dict(
        {"boundary_id": "probe", "version": "1",
         "mcp_servers": ["files"],
         "mcp_tools": ["files::read", "files::write"],
         "mcp_max_arg_bytes": 4096})


def _policy():
    src = Path(TREE, "policies", "default.yaml").read_text()
    src = src.replace(
        "coder: [read_file, write_file, delete_file, api_call, "
        "install_package]",
        "coder: [read_file, write_file, delete_file, api_call, "
        "install_package, mcp_call]")
    path = Path(tempfile.mkdtemp(prefix="mcp-wiring-probe-pol-"),
                "policy.yaml")
    path.write_text(src)
    return str(path)


def _wired(agent_id, scope):
    """Build an executor with boundary+registry installed and an
    identity minted with the given token scope. Returns (ctx, ex,
    ident). Raises _SeamAbsent on the pristine tree."""
    ctx = make_run(policy_path=_policy())
    ex = ctx["executor"]
    if not hasattr(ex, "set_mcp_tool_registry"):
        raise _SeamAbsent("executor has no set_mcp_tool_registry")
    ident = ex.mint_identity(agent_id, "coder", "org1",
                             token_claims=_claims(agent_id, scope))
    ex.set_authority_boundary(_boundary())
    ex.set_mcp_tool_registry(_registry())
    return ctx, ex, ident


class _SeamAbsent(Exception):
    pass


def _authority_denied(result):
    return (result.get("status") == "denied"
            and result.get("policy_id") == "authority-boundary")


# ------------------------------------------------------------------
# ENFORCE probes: FAIL on pristine (gap), PASS on fixed.
# ------------------------------------------------------------------

def p_seam_exists():
    """The executor exposes the registry seam and records verified
    claims at mint."""
    try:
        ctx, ex, ident = _wired("p1", SCOPE)
    except _SeamAbsent as e:
        _record("p_seam_exists", "FAIL", str(e))
        return
    got = ex._mcp_token_claims_for("p1")
    if got is None or got.get("agent_scope") != SCOPE:
        _record("p_seam_exists", "FAIL",
                "claims not recorded at mint: %r" % (got,))
        return
    _record("p_seam_exists", "PASS", "registry seam + claim recording live")


def p_scope_miss_denied_at_call():
    """Core promise: scope-missing token -> denied at the executor
    pre-decision seam with exceeds_boundary naming the scope."""
    try:
        ctx, ex, ident = _wired("p2", "mcp:other")
    except _SeamAbsent:
        # Pristine gap, demonstrated end-to-end (not just "method
        # missing"): the library seam already refuses this exact
        # action, but the executor never asks it.
        direct = ap.check(
            {"tool": "mcp_call",
             "args": {"server": "files", "name": "read",
                     "arguments": {}}},
            {}, _boundary(),
            mcp_tool_registry=_registry(),
            token_claims=_claims("p2", "mcp:other"))
        ctx2 = make_run(policy_path=_policy())
        ex2 = ctx2["executor"]
        ident2 = ex2.mint_identity("p2", "coder", "org1",
                                   token_claims=_claims("p2", "mcp:other"))
        ex2.set_authority_boundary(_boundary())
        r = ex2.call(ident2, "mcp_call", server="files", name="read",
                     arguments={})
        _record("p_scope_miss_denied_at_call", "FAIL",
                "gap: library check()=%s but executor call not "
                "authority-refused (policy_id=%r)"
                % (direct.verdict, r.get("policy_id")))
        return
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={})
    if not _authority_denied(r):
        _record("p_scope_miss_denied_at_call", "FAIL",
                "scope-missing token not refused: %r" % (r,))
        return
    denials = [e for e in ctx["read_log"]()
               if isinstance(e, dict)
               and e.get("flag") == "authority_boundary_refused"]
    proof = denials[0]["authority_proof"]
    if (proof["verdict"] != "exceeds_boundary"
            or SCOPE not in proof["counterexample"]["reason"]):
        _record("p_scope_miss_denied_at_call", "FAIL",
                "wrong proof shape: %r" % (proof,))
        return
    _record("p_scope_miss_denied_at_call", "PASS",
            "exceeds_boundary, scope named in counterexample")


def p_exact_match_required():
    """Substring/prefix scopes must not satisfy a required scope."""
    try:
        ctx, ex, ident = _wired("p3", "mcp:files:readwrite")
    except _SeamAbsent:
        _record("p_exact_match_required", "FAIL",
                "seam absent (gap)")
        return
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={})
    if _authority_denied(r):
        _record("p_exact_match_required", "PASS",
                "superstring scope refused")
    else:
        _record("p_exact_match_required", "FAIL",
                "superstring scope accepted: %r" % (r,))


def p_expired_claims_denied():
    """A token expired since mint fails closed at check time."""
    try:
        ctx, ex, ident = _wired("p4", SCOPE)
    except _SeamAbsent:
        _record("p_expired_claims_denied", "FAIL", "seam absent (gap)")
        return
    ex._mcp_token_claims["p4"]["exp"] = int(time.time()) - 600
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={})
    if _authority_denied(r):
        _record("p_expired_claims_denied", "PASS", "expired token refused")
    else:
        _record("p_expired_claims_denied", "FAIL",
                "expired token not refused: %r" % (r,))


def p_no_token_fails_closed():
    """Registry installed, identity minted with no token: scoped
    tools fail closed."""
    ctx = make_run(policy_path=_policy())
    ex = ctx["executor"]
    if not hasattr(ex, "set_mcp_tool_registry"):
        _record("p_no_token_fails_closed", "FAIL", "seam absent (gap)")
        return
    ident = ex.mint_identity("p5", "coder", "org1")
    ex.set_authority_boundary(_boundary())
    ex.set_mcp_tool_registry(_registry())
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={})
    if _authority_denied(r):
        _record("p_no_token_fails_closed", "PASS",
                "token-less identity refused fail-closed")
    else:
        _record("p_no_token_fails_closed", "FAIL",
                "token-less identity not refused: %r" % (r,))


def p_sweep_reproof():
    """TOCTOU: registry installed after approval -> the sweep's
    execution-time re-proof refuses the scope-missing call."""
    try:
        _wired("p6", "mcp:other")
    except _SeamAbsent:
        _record("p_sweep_reproof", "FAIL", "seam absent (gap)")
        return
    from gov.policy import PolicyDecision
    from gov.approvals import sanitize_preview_text
    import gov.policy as _policy_mod
    _policy_mod.KNOWN_TOOLS.add("mcp_call")
    try:
        src = Path(TREE, "policies", "default.yaml").read_text()
        src = src.replace(
            "coder: [read_file, write_file, delete_file, api_call, "
            "install_package]",
            "coder: [read_file, write_file, delete_file, api_call, "
            "install_package, mcp_call]")
        src += ("\n  - id: test-allow-mcp\n"
                "    description: Probe-only allow for the sweep test.\n"
                "    effect: allow\n"
                "    match:\n"
                "      tool: [mcp_call]\n"
                "    reason: probe-only\n")
        path = Path(tempfile.mkdtemp(prefix="mcp-wiring-probe-swp-"),
                    "policy.yaml")
        path.write_text(src)
        ctx = make_run(policy_path=str(path))
        ex = ctx["executor"]
        ident = ex.mint_identity("p6", "coder", "org1",
                                 token_claims=_claims("p6", "mcp:other"))
        ex.set_authority_boundary(_boundary())
        _args = {"server": "files", "name": "read", "arguments": {}}
        _preview = sanitize_preview_text(ex._preview("mcp_call", _args))
        aid = ctx["approvals"].queue(
            {"tool": "mcp_call", "args": _args,
             "identity": ident.as_dict(),
             "agent_justification": None, "redactions": []},
            PolicyDecision("require_approval", "probe-only",
                           policy_id="probe-queue-mcp", flag="probe_queue"),
            "agent_direct", _preview, caller_identity=ident,
            policy_hash=ex.policy.policy_hash)
        ctx["approvals"].decide(aid, True, reason="probe",
                                decided_by="human-operator")
        ex.set_mcp_tool_registry(_registry())
        ex.execute_approved()
        refused = [e for e in ctx["read_log"]()
                   if isinstance(e, dict)
                   and e.get("flag") == "authority_boundary_exceeded"]
        if len(refused) == 1:
            _record("p_sweep_reproof", "PASS",
                    "sweep re-proof refused scope-missing call")
        else:
            _record("p_sweep_reproof", "FAIL",
                    "sweep did not refuse: %d refusals" % len(refused))
    finally:
        _policy_mod.KNOWN_TOOLS.discard("mcp_call")


# ------------------------------------------------------------------
# LEGACY / NO-REGRESSION probes: PASS on both trees.
# ------------------------------------------------------------------

def p_scope_hit_passes_seam():
    """Exact scope present -> the authority seam does not refuse."""
    try:
        ctx, ex, ident = _wired("p7", SCOPE + " mcp:other")
    except _SeamAbsent:
        # Pristine: no enforcement exists, so trivially not refused.
        _record("p_scope_hit_passes_seam", "PASS",
                "pristine: no authority refusal (no enforcement)")
        return
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={})
    if _authority_denied(r):
        _record("p_scope_hit_passes_seam", "FAIL",
                "scope-present token refused: %r" % (r,))
    else:
        _record("p_scope_hit_passes_seam", "PASS",
                "scope-present token passes the authority seam")


def p_no_registry_legacy():
    """No registry configured: scope-missing token is NOT refused at
    the authority seam (legacy behavior preserved)."""
    ctx = make_run(policy_path=_policy())
    ex = ctx["executor"]
    ident = ex.mint_identity("p8", "coder", "org1",
                             token_claims=_claims("p8", "mcp:other"))
    ex.set_authority_boundary(_boundary())
    r = ex.call(ident, "mcp_call", server="files", name="read",
                arguments={})
    if _authority_denied(r):
        _record("p_no_registry_legacy", "FAIL",
                "legacy path changed: %r" % (r,))
    else:
        _record("p_no_registry_legacy", "PASS",
                "no-registry legacy path unchanged")


def p_unattested_no_scope_requirement():
    """Attestation can only tighten: an unattested pair is not
    refused for scopes even with a registry installed."""
    try:
        ctx, ex, ident = _wired("p9", "mcp:other")
    except _SeamAbsent:
        _record("p_unattested_no_scope_requirement", "PASS",
                "pristine: no enforcement to regress")
        return
    r = ex.call(ident, "mcp_call", server="files", name="write",
                arguments={})
    if _authority_denied(r):
        _record("p_unattested_no_scope_requirement", "FAIL",
                "unattested pair refused: %r" % (r,))
    else:
        _record("p_unattested_no_scope_requirement", "PASS",
                "unattested pair requires no scopes")


# ------------------------------------------------------------------
# Green check (depth-1 per convention; honors GOV_SKIP_GREEN=1).
# ------------------------------------------------------------------

def _green_check():
    """Adjacent batteries: the wave-177 MCP battery must stay 20/20,
    plus the MCP/authority/identity unit suites. Depth-1: children run
    with GOV_SKIP_GREEN=1 so their own green checks do not nest."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green_check",
                "SKIP",
                "GOV_SKIP_GREEN=1; standalone run still checks itself")
        return
    batteries = [
        "evals/authority_mcp_graphql_battery.py",
    ]
    suites = [
        ["-m", "unittest", "tests.test_mcp_annotations"],
        ["-m", "unittest", "tests.test_mcp_wiring"],
        ["-m", "unittest", "tests.test_authority_proof"],
        ["-m", "unittest", "tests.test_authority_proof_mcp_graphql"],
        ["-m", "unittest", "tests.test_identity_token"],
        ["-m", "unittest", "tests.test_provisioner"],
    ]
    for battery in batteries:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="mcp-wiring-green-")
        p = subprocess.run(
            [sys.executable, str(Path(TREE, battery))],
            cwd=TREE, env=env, capture_output=True, text=True,
            timeout=900)
        tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
        _record("green_check_%s" % Path(battery).stem,
                "PASS" if p.returncode == 0 else "FAIL",
                "exit=%d tail=%r" % (p.returncode, " | ".join(tail)))
    for suite in suites:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="mcp-wiring-green-")
        p = subprocess.run(
            [sys.executable] + suite,
            cwd=TREE, env=env, capture_output=True, text=True,
            timeout=900)
        tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
        _record("green_check_%s" % suite[-1].split(".")[-1],
                "PASS" if p.returncode == 0 else "FAIL",
                "exit=%d tail=%r" % (p.returncode, " | ".join(tail)))


def _run_all():
    probes = [
        p_seam_exists,
        p_scope_miss_denied_at_call,
        p_exact_match_required,
        p_expired_claims_denied,
        p_no_token_fails_closed,
        p_sweep_reproof,
        p_scope_hit_passes_seam,
        p_no_registry_legacy,
        p_unattested_no_scope_requirement,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001 -- red must be loud
            _record(probe.__name__, "ERROR", "%s: %s" % (
                type(e).__name__, e))


def main():
    # Twice in-process: the two passes must agree exactly.
    _run_all()
    first = list(_records)
    del _records[:]
    _run_all()
    second = list(_records)
    del _records[:]
    stable = (first == second)
    _records.extend(second)
    _green_check()
    print("== wave-198 lane E: MCP token-claims executor wiring ==")
    n_pass = n_fail = n_err = n_skip = 0
    for name, outcome, detail in _records:
        print("%-42s %-6s %s" % (name, outcome, detail))
        if outcome == "PASS":
            n_pass += 1
        elif outcome == "FAIL":
            n_fail += 1
        elif outcome == "SKIP":
            n_skip += 1
        else:
            n_err += 1
    print("pass=%d fail=%d errors=%d skipped=%d twice_stable=%s"
          % (n_pass, n_fail, n_err, n_skip, stable))
    bad = (n_fail > 0 or n_err > 0 or not stable
           or any(o == "FAIL" for _, o, _ in _records))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
