#!/usr/bin/env python3
"""Red-first break battery for wave-196: keyset-attested MCP ToolAnnotations.

The gap (pristine tree): the MCP authorization seam (gov/authority_proof)
knows exact ``server::tool`` allowlists and an argument byte budget, but
has NO annotation-attestation seam and NO required-scope enforcement.
A tool server's self-declared ToolAnnotations (read_only_hint /
destructive_hint / idempotent_hint / open_world_hint) are unverifiable
at the product seam -- the modelcontextprotocol/python-sdk rule ("never
make tool use decisions based on ToolAnnotations received from untrusted
servers") has no enforcement point -- and there is no way to demand
that a caller hold a scope before invoking a tool.

Probes (each run twice; any disagreement is ERROR):
  R1 capability-absent:   gov.mcp_annotations importable?
  R2 seam-absent:         check() accepts mcp_tool_registry=/token_claims=?
  R3 trust-gap:           un-attested destructive tool's self-declared
                          read-only claim is contradicted by the product?
  R4 scope-gap:           a scope requirement can be expressed and
                          enforced at the authorization seam?
  R5 attested-honored:    operator-attested annotations are honored?
  R6 revoked-refused:     a revoked attestation refuses (registry build)?
  R7 expired-claims:      expired identity claims fail the scope check?
  R8 conservative-default: un-attested tools classify conservative?

Pristine expectation: 8/8 BREAK. Fixed expectation: 8/8 HELD.

Stdlib only. Deterministic (fixed seeds, fixed timestamps). Sets
GOV_DEPLOYMENT_MODE=staging at module level; verify standalone under
``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1 (green check is
depth-1: the adjacent unit suites only, never nested battery mains).
"""

import hashlib
import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import authority_proof as ap  # noqa: E402

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

ISSUER = "https://dex.sasanam.internal"
READ_ONLY = {"read_only_hint": True, "destructive_hint": False,
             "idempotent_hint": True, "open_world_hint": False}


def _seed(tag):
    return hashlib.sha256(b"mcp-annot-battery:" + tag.encode()).digest()


def _claims(exp_offset, scope):
    now = int(time.time())
    return {"iss": ISSUER, "sub": "agent:org1:run-7",
            "aud": "sasanam-policy-engine", "iat": now - 3600,
            "exp": now + exp_offset, "jti": "battery-jti-001",
            "principal": "org1", "role": "operator",
            "agent_scope": scope}


def _boundary():
    return ap.boundary_from_dict(
        {"boundary_id": "battery", "version": "1",
         "mcp_servers": ["files"], "mcp_tools": ["files::read"],
         "mcp_max_arg_bytes": 4096})


def _action():
    return {"tool": "mcp_call",
            "args": {"server": "files", "name": "read", "arguments": {}}}


def _capability():
    """Import the wave-196 module, or None on the pristine tree."""
    try:
        from gov import mcp_annotations as ma
        return ma
    except ImportError:
        return None


def _mint(ma, keyset_mod, tag, pair, scopes):
    seed = _seed(tag)
    ks, _ = keyset_mod.new_keyset(seed, purpose=ma.ATTESTATION_PURPOSE)
    att = ma.attest_tool_annotations(ks, pair, dict(READ_ONLY), seed,
                                     required_scopes=list(scopes),
                                     at=1790000000)
    return ks, att


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _p1_capability():
    """R1: the attestation module exists."""
    ma = _capability()
    if ma is None:
        return "BREAK", "gov.mcp_annotations is not importable"
    return "HELD", "gov.mcp_annotations imports; format=%s" % (
        ma.ANNOTATION_FORMAT,)


def _p2_seam():
    """R2: check() accepts the registry/claims seam kwargs."""
    try:
        p = ap.check(_action(), {}, _boundary(),
                     mcp_tool_registry={}, token_claims={})
    except TypeError as e:
        return "BREAK", "check() has no mcp_tool_registry/token_claims " \
                        "seam: %s" % (e,)
    if p.verdict == ap.WITHIN:
        return "HELD", "check() accepts the seam kwargs (empty registry, " \
                       "no scopes required -> within)"
    return "ERROR", "unexpected verdict %r" % (p.verdict,)


def _p3_trust_gap():
    """R3: an un-attested destructive tool's self-declared read-only
    claim must not be believed."""
    ma = _capability()
    lying = {"read_only_hint": True, "destructive_hint": False,
             "idempotent_hint": True, "open_world_hint": False}
    if ma is None:
        return "BREAK", "no classification seam: the wire self-claim " \
                        "%r stands uncontradicted" % (lying,)
    ann, source = ma.classify_tool("evil::rm", {}, declared=lying)
    if source == "conservative" and ann["destructive_hint"] is True \
            and ann["read_only_hint"] is False:
        return "HELD", "wire self-claim ignored; un-attested tool " \
                       "classified conservative (destructive=True)"
    return "ERROR", "unexpected classification %r %r" % (ann, source)


def _p4_scope_gap():
    """R4: a required scope can be demanded and enforced at the seam."""
    ma = _capability()
    if ma is None:
        return "BREAK", "no scope seam: a boundary-allowed call passes " \
                        "WITHIN with no way to demand a caller scope"
    from gov import keyset as keyset_mod
    ks, att = _mint(ma, keyset_mod, "p4", "files::read",
                    ["mcp:files:read"])
    reg, refused = ma.build_tool_registry([att], ks.to_dict())
    if refused or set(reg) != {"files::read"}:
        return "ERROR", "registry build failed: %r" % (refused,)
    bad = ap.check(_action(), {}, _boundary(), mcp_tool_registry=reg,
                   token_claims=_claims(3600, "mcp:files:write"))
    good = ap.check(_action(), {}, _boundary(), mcp_tool_registry=reg,
                    token_claims=_claims(3600, "mcp:files:read"))
    if bad.verdict != ap.EXCEEDS:
        return "ERROR", "scope-less caller not refused: %r" % (bad.verdict,)
    if good.verdict != ap.WITHIN:
        return "ERROR", "in-scope caller not allowed: %r" % (good.verdict,)
    return "HELD", "scope-less claims -> exceeds_boundary; in-scope " \
                   "claims -> within"


def _p5_attested_honored():
    """R5: a valid operator attestation is honored by classification."""
    ma = _capability()
    if ma is None:
        return "BREAK", "no attestation API: nothing to honor"
    from gov import keyset as keyset_mod
    ks, att = _mint(ma, keyset_mod, "p5", "files::read", [])
    reg, refused = ma.build_tool_registry([att], ks.to_dict())
    if refused:
        return "ERROR", "registry build failed: %r" % (refused,)
    ann, source = ma.classify_tool("files::read", reg)
    if source == "attested" and ann == READ_ONLY:
        return "HELD", "operator-attested read-only annotation honored"
    return "ERROR", "unexpected classification %r %r" % (ann, source)


def _p6_revoked_refused():
    """R6: an attestation from a revoked keyset version refuses."""
    ma = _capability()
    if ma is None:
        return "BREAK", "no attestation API: revocation has no meaning"
    from gov import keyset as keyset_mod
    ks1, att = _mint(ma, keyset_mod, "p6", "files::read", [])
    ks2, _ = keyset_mod.rotate_keyset(ks1, _seed("p6-rot"),
                                      _seed("p6"))
    ks3 = keyset_mod.revoke_version(ks2, 1, "battery compromise",
                                    _seed("p6-rot"))
    reg, refused = ma.build_tool_registry([att], ks3.to_dict())
    if reg == {} and len(refused) == 1 and "revoked" in refused[0][1]:
        return "HELD", "revoked attestation refused from the registry"
    return "ERROR", "registry=%r refused=%r" % (reg, refused)


def _p7_expired_claims():
    """R7: expired identity-token claims fail the scope check."""
    ma = _capability()
    if ma is None:
        return "BREAK", "no claim-consumption seam at the MCP path"
    from gov import keyset as keyset_mod
    ks, att = _mint(ma, keyset_mod, "p7", "files::read",
                    ["mcp:files:read"])
    reg, refused = ma.build_tool_registry([att], ks.to_dict())
    if refused:
        return "ERROR", "registry build failed: %r" % (refused,)
    p = ap.check(_action(), {}, _boundary(), mcp_tool_registry=reg,
                 token_claims=_claims(-7200, "mcp:files:read"))
    if p.verdict == ap.EXCEEDS and "expired" in p.counterexample.reason:
        return "HELD", "expired claims -> exceeds_boundary"
    return "ERROR", "verdict=%r reason=%r" % (
        p.verdict, getattr(p.counterexample, "reason", None))


def _p8_conservative_default():
    """R8: un-attested tools classify to the conservative defaults."""
    ma = _capability()
    if ma is None:
        return "BREAK", "no classification seam: no conservative default"
    ann, source = ma.classify_tool("never::seen", {})
    if source == "conservative" and ann == ma.CONSERVATIVE_ANNOTATIONS \
            and ann["destructive_hint"] is True \
            and ann["read_only_hint"] is False:
        return "HELD", "un-attested tool -> conservative " \
                       "(destructive=True, read-only=False)"
    return "ERROR", "unexpected classification %r %r" % (ann, source)


_PROBES = [
    ("R1", _p1_capability),
    ("R2", _p2_seam),
    ("R3", _p3_trust_gap),
    ("R4", _p4_scope_gap),
    ("R5", _p5_attested_honored),
    ("R6", _p6_revoked_refused),
    ("R7", _p7_expired_claims),
    ("R8", _p8_conservative_default),
]


def _run_once():
    out = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # harness error, never a probe pass
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        out.append((name, verdict, detail))
    return out


def main():
    first = _run_once()
    second = _run_once()
    breaks = held = errors = 0
    print("%-4s %-6s %s" % ("ID", "VERDICT", "DETAIL"))
    for (name, v1, d1), (_n2, v2, _d2) in zip(first, second):
        if v1 != v2:
            v1, d1 = "ERROR", \
                "%s nondeterministic: %r then %r" % (name, v1, v2)
        print("%-4s %-6s %s" % (name, v1, d1))
        if v1 == "BREAK":
            breaks += 1
        elif v1 == "HELD":
            held += 1
        else:
            errors += 1
    print("breaks=%d held=%d errors=%d" % (breaks, held, errors))
    if breaks:
        print("BREAK: %s" % ", ".join(n for n, v, _ in first
                                       if v == "BREAK"))
    return 1 if errors else 0


def _green_check():
    """Depth-1 green check: the adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip; skips
    gracefully on trees where the wave-196 suite does not exist."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    if importlib.util.find_spec("tests.test_mcp_annotations") is None:
        print("GREEN CHECK: skipped (tests.test_mcp_annotations absent "
              "on this tree)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_mcp_annotations",
         "tests.test_authority_proof_mcp_graphql"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK unit suites: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
