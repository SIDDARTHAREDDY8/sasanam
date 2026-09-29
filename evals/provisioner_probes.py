#!/usr/bin/env python3
"""Break-first probes for wave-196 lane C: step-ca provisioner steal.

Steal: smallstep/certificates `authority/provisioner` (typed registry of
attestation methods for minting short-lived credentials) + `claims.go`
(per-provisioner credential-lifetime envelope: min/max duration,
disableRenewal, allowRenewalAfterExpiry). Steal ONLY the mechanism --
smallstep's TPM-attested enrollment / CRL-OCSP / HSM keys are
commercial-gated per their own README and this lane designs around
none of them; no smallstep dependency (stdlib only).

The gap: our keyset machinery (rotation, ThresholdSigner, TransitSigner,
wave-191/192 token claim-set with exp/jti) handles agent identity, but
`ToolExecutor.mint_identity` has NO provisioner abstraction and NO
per-issuer issuance policy -- expiry exists on the token, issuance
policy does not.

RED-PHASE (--red-phase): gap demonstration on the pristine tree.
  R1: a token with a 30-day lifetime mints a run identity -- no
      max-TTL issuance policy exists. Expect ACCEPTED; exit 0 = gap.
  R2: a token with scope "admin:everything,pii:export" mints -- no
      scope policy exists, nothing recorded. Expect ACCEPTED.
  R3: no provisioner concept at all -- `gov.provisioner` absent and
      `mint_identity` has no provisioner/justification/ttl params,
      so break-glass issuance is indistinguishable from normal
      issuance and requires no justification. Expect GAP.
GREEN-PHASE (default): closure battery against gov/provisioner.py +
  the mint_identity provisioner seam. TTL-over-max refused, token
  lifetime over max refused, scope outside grant refused, break-glass
  without justification refused, unknown/unnamed provisioner refused,
  role outside provisioner grant refused, refusals consume no budget,
  per-provisioner mint budget enforced, renewal policy recorded on
  the chained audit event, the authorizing envelope recorded on the
  event (auditor-reconstructible), and the oidc attestation method
  refusing a mint with no presented token.

Usage:
  python3 evals/provisioner_probes.py --red-phase   # gap demo
  python3 evals/provisioner_probes.py               # closure battery

Deterministic: expiries anchored far from now (days); the skew-adjacent
probes use fixed second offsets. main() runs the battery twice and
requires identical statuses.

Conventions: module-level GOV_DEPLOYMENT_MODE=staging; verify standalone
under `env -u GOV_DEPLOYMENT_MODE`; GOV_SKIP_GREEN honored; green check
is depth-1 (tests/test_provisioner only, child env GOV_SKIP_GREEN=1);
the battery never touches the shared tree -- TREE is the tree it lives
in.
"""

import inspect
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Synthetic HMAC key for the chained audit log (same convention as
# other executor-driving batteries): per-process, never leaves the run.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "provisioner-battery")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREE = REPO_ROOT  # this battery lives in the tree it tests
sys.path.insert(0, TREE)

ISSUER = "https://dex.sasanam.internal"
DAY = 86400

IDENTITY = {"agent_id": "agent:org1:run-7", "role": "operator",
            "principal": "org1", "run_id": "run-7"}

_ALLOW_ALL = """\
version: 2
roles:
  operator: [read_file]
  coder: [read_file]
policies:
  - id: allow-all
    effect: allow
    match:
      tool: [read_file]
    reason: provisioner fixture
"""


def _claims(exp_offset, iat_offset=-3600, **over):
    now = int(time.time())
    c = {"iss": ISSUER, "sub": IDENTITY["agent_id"],
         "aud": "sasanam-policy-engine", "iat": now + iat_offset,
         "exp": now + exp_offset, "jti": "token-jti-001",
         "principal": IDENTITY["principal"], "role": IDENTITY["role"],
         "agent_scope": "tools:read"}
    c.update(over)
    return c


def _short_token(**over):
    """A presented token whose lifetime fits the dex-prod 3600s cap.

    The default ``iat`` anchor (now-3600) makes even a 15-minute token
    live 75 minutes; green-phase probes that must PASS the lifetime
    check use iat=now instead. Red-phase probes keep the default.
    """
    return _claims(600, iat_offset=0, **over)


def _executor(provisioner_registry=None):
    from pathlib import Path
    from gov.executor import ToolExecutor
    from gov.policy import PolicyEngine
    from gov.log import ActionLog
    from gov.approvals import ApprovalQueue
    run_dir = Path(tempfile.mkdtemp(prefix="govprov-"))
    (run_dir / "policy.yaml").write_text(_ALLOW_ALL)
    policy = PolicyEngine(str(run_dir / "policy.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex_kwargs = dict(
        ledger_path=run_dir / "egress_ledger.jsonl",
        ungoverned_ack="provisioner test: synthetic executor")
    if provisioner_registry is not None:
        # Only passed when set: on the pristine tree the kwarg does not
        # exist yet, and the red phase must run against the legacy
        # constructor.
        ex_kwargs["provisioner_registry"] = provisioner_registry
    ex = ToolExecutor(run_dir, policy, log, approvals, **ex_kwargs)
    return ex, run_dir


def _events(run_dir, name):
    path = run_dir / "actions.jsonl"
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and e.get("event") == name:
                out.append(e)
    return out


def _registry():
    from gov.provisioner import (
        BreakGlassProvisioner, LifetimeClaims, Provisioner,
        ProvisionerRegistry, ProvisionerType)
    return ProvisionerRegistry([
        Provisioner("dex-prod", ProvisionerType.OIDC,
                    LifetimeClaims(
                        max_ttl_seconds=3600,
                        allowed_scopes=frozenset(
                            {"tools:read", "tools:write"}),
                        allowed_roles=frozenset(
                            {"operator", "coder"}))),
        Provisioner("workload-run", ProvisionerType.WORKLOAD,
                    LifetimeClaims(
                        max_ttl_seconds=600, min_ttl_seconds=60,
                        allowed_scopes=frozenset({"tools:read"}),
                        max_mints_per_run=2)),
        BreakGlassProvisioner("break-glass-1"),
    ])


def _mint(ex, **kw):
    return ex.mint_identity(IDENTITY["agent_id"], IDENTITY["role"],
                            IDENTITY["principal"], **kw)


# --------------------------------------------------------------------------
# RED PHASE: gap demonstration on the pristine tree
# --------------------------------------------------------------------------

def red_r1_thirty_day_token_mints():
    """No max-TTL issuance policy: a 30-day token mints fine."""
    ex, _ = _executor()
    ident = _mint(ex, token_claims=_claims(30 * DAY))
    assert ident.agent_id == IDENTITY["agent_id"]
    return "PASS", "30-day token minted: no issuance lifetime policy"


def red_r2_wildcard_scope_mints():
    """No scope policy: an all-powerful scope claim mints fine."""
    ex, _ = _executor()
    ident = _mint(ex, token_claims=_claims(
        900, agent_scope="admin:everything pii:export"))
    assert ident.agent_id == IDENTITY["agent_id"]
    return "PASS", "wildcard scope minted: no scope policy, nothing recorded"


def red_r3_no_provisioner_concept():
    """No provisioner abstraction: break-glass is indistinguishable."""
    try:
        import gov.provisioner  # noqa: F401
        return "FAIL", "gov.provisioner exists on pristine tree"
    except ImportError:
        pass
    from gov.executor import ToolExecutor
    params = set(inspect.signature(ToolExecutor.mint_identity).parameters)
    for p in ("provisioner", "ttl_seconds", "scopes", "justification"):
        if p in params:
            return "FAIL", "mint_identity already takes %r" % p
    return ("PASS",
            "no provisioner module; mint_identity has no issuance-policy "
            "params: break-glass needs no justification, nothing "
            "distinguishes it")


RED_PROBES = [
    ("R1_thirty_day_token_mints", red_r1_thirty_day_token_mints),
    ("R2_wildcard_scope_mints", red_r2_wildcard_scope_mints),
    ("R3_no_provisioner_concept", red_r3_no_provisioner_concept),
]


# --------------------------------------------------------------------------
# GREEN PHASE: closure battery
# --------------------------------------------------------------------------

def g1_valid_mint_within_policy():
    from gov.provisioner import ProvisionerRefusedError  # noqa: F401
    ex, run_dir = _executor(_registry())
    ident = _mint(ex, provisioner="dex-prod", ttl_seconds=600,
                  scopes=["tools:read"],
                  token_claims=_short_token())
    assert ident.agent_id == IDENTITY["agent_id"]
    minted = _events(run_dir, "identity_minted")
    assert minted, "identity_minted audit event missing"
    e = minted[-1]
    assert e.get("provisioner") == "dex-prod", e
    assert e.get("provisioner_type") == "oidc", e
    assert e.get("ttl_seconds") == 600, e
    assert e.get("expires_at"), e
    assert e.get("scopes") == ["tools:read"], e
    assert e.get("renewable") is True, e
    # The authorizing envelope is on the chain too: the policy
    # decision is reconstructible without the deployment config.
    policy = e.get("policy") or {}
    assert policy.get("max_ttl_seconds") == 3600, e
    assert policy.get("allowed_scopes") == ["tools:read", "tools:write"], e
    return "PASS", "mint within policy accepted; audit carries claims"


def g2_ttl_over_max_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    before = ex._mint_count
    try:
        _mint(ex, provisioner="dex-prod", ttl_seconds=7200,
              token_claims=_short_token())
    except ProvisionerRefusedError as err:
        assert "max_ttl" in str(err) or "7200" in str(err), err
        assert ex._mint_count == before, "refusal consumed mint budget"
        return "PASS", "TTL over max refused: %s" % err
    return "FAIL", "TTL 7200 > max 3600 minted"


def g3_token_lifetime_over_max_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="dex-prod",
              token_claims=_claims(30 * DAY))
    except ProvisionerRefusedError as err:
        return "PASS", "30-day token vs max 3600 refused: %s" % err
    return "FAIL", "30-day token minted under 3600s-max provisioner"


def g4_scope_outside_grant_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        # The token carries pii:export so the scope cross-check passes
        # and the provisioner's grant is what refuses.
        _mint(ex, provisioner="dex-prod", ttl_seconds=600,
              scopes=["pii:export"],
              token_claims=_short_token(agent_scope="pii:export"))
    except ProvisionerRefusedError as err:
        assert "pii:export" in str(err), err
        return "PASS", "out-of-grant scope refused: %s" % err
    return "FAIL", "pii:export minted under tools-only provisioner"


def g5_break_glass_without_justification_refused():
    from gov.provisioner import BreakGlassRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="break-glass-1", ttl_seconds=120)
    except BreakGlassRefusedError as err:
        assert "justification" in str(err), err
        return "PASS", "unjustified break-glass refused: %s" % err
    except Exception as err:  # noqa: BLE001
        return "FAIL", "wrong exception: %r" % err
    return "FAIL", "break-glass minted with no justification"


def g6_break_glass_with_justification_accepted():
    ex, run_dir = _executor(_registry())
    ident = _mint(ex, provisioner="break-glass-1", ttl_seconds=120,
                  justification="INC-2049: prod DB locked, on-call paged")
    assert ident.agent_id == IDENTITY["agent_id"]
    bg = _events(run_dir, "identity_break_glass_minted")
    assert bg, "break-glass audit event missing"
    assert "INC-2049" in bg[-1].get("justification", ""), bg[-1]
    minted = _events(run_dir, "identity_minted")
    assert minted and minted[-1].get("renewable") is False, minted
    assert minted[-1].get("ttl_seconds") == 120, minted[-1]
    return "PASS", "justified break-glass accepted, loud + audited"


def g7_break_glass_ttl_capped():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="break-glass-1", ttl_seconds=3600,
              justification="INC-2049")
    except ProvisionerRefusedError as err:
        return "PASS", "break-glass TTL capped at 300s: %s" % err
    return "FAIL", "break-glass minted with 3600s TTL"


def g8_unknown_provisioner_refused():
    from gov.provisioner import UnknownProvisionerError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="no-such-issuer", ttl_seconds=60)
    except UnknownProvisionerError as err:
        return "PASS", "unknown provisioner refused: %s" % err
    except Exception as err:  # noqa: BLE001
        return "FAIL", "wrong exception: %r" % err
    return "FAIL", "unknown provisioner minted"


def g9_unnamed_provisioner_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, ttl_seconds=60)
    except ProvisionerRefusedError as err:
        assert "provisioner" in str(err).lower(), err
        return "PASS", "registry configured + no provisioner named: %s" % err
    return "FAIL", "minted with registry configured but no provisioner"


def g10_role_outside_provisioner_grant_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        # The token agrees with the requested identity (so the token
        # check passes) and the provisioner's role grant refuses.
        ex.mint_identity(IDENTITY["agent_id"], "auditor",
                         IDENTITY["principal"], provisioner="dex-prod",
                         ttl_seconds=600,
                         token_claims=_short_token(role="auditor"))
    except ProvisionerRefusedError as err:
        return "PASS", "role outside provisioner grant refused: %s" % err
    return "FAIL", "auditor role minted under operator/coder grant"


def g11_per_provisioner_budget_enforced():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    _mint(ex, provisioner="workload-run", ttl_seconds=120,
          scopes=["tools:read"])
    _mint(ex, provisioner="workload-run", ttl_seconds=120,
          scopes=["tools:read"])
    try:
        _mint(ex, provisioner="workload-run", ttl_seconds=120,
              scopes=["tools:read"])
    except ProvisionerRefusedError as err:
        return "PASS", "per-provisioner budget (2) enforced: %s" % err
    return "FAIL", "third mint under max_mints_per_run=2 succeeded"


def g12_scope_token_disagreement_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="dex-prod", ttl_seconds=600,
              scopes=["tools:write"],
              token_claims=_claims(900, agent_scope="tools:read"))
    except ProvisionerRefusedError as err:
        return "PASS", "scope/token-scope disagreement refused: %s" % err
    return "FAIL", "minted scopes broader than the token carries"


def g13_token_scope_enforced_when_unrequested():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="dex-prod",
              token_claims=_claims(900, agent_scope="pii:export"))
    except ProvisionerRefusedError as err:
        return "PASS", "token scope outside grant refused: %s" % err
    return "FAIL", "token carrying pii:export minted under tools grant"


def g14_min_ttl_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="workload-run", ttl_seconds=30,
              scopes=["tools:read"])
    except ProvisionerRefusedError as err:
        return "PASS", "TTL under min refused: %s" % err
    return "FAIL", "TTL 30 < min 60 minted"


def g15_default_ttl_is_capped():
    ex, run_dir = _executor(_registry())
    _mint(ex, provisioner="dex-prod", scopes=["tools:read"],
          token_claims=_short_token())
    minted = _events(run_dir, "identity_minted")
    assert minted and minted[-1].get("ttl_seconds") == 3600, minted
    ex2, run_dir2 = _executor(_registry())
    _mint(ex2, provisioner="break-glass-1",
          justification="INC-2050: default TTL check")
    minted2 = _events(run_dir2, "identity_minted")
    assert minted2 and minted2[-1].get("ttl_seconds") == 300, minted2
    return "PASS", "default TTL = min(3600, max_ttl)"


def g16_no_registry_with_policy_args_refused():
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor()  # no provisioner registry
    try:
        _mint(ex, provisioner="dex-prod", ttl_seconds=60)
    except ProvisionerRefusedError as err:
        return "PASS", "policy args without registry fail closed: %s" % err
    return "FAIL", "provisioner named but no registry: silently honored"


def g17_legacy_mint_unchanged_without_registry():
    ex, _ = _executor()  # no provisioner registry: legacy path
    ident = _mint(ex, token_claims=_claims(900))
    assert ident.agent_id == IDENTITY["agent_id"]
    return "PASS", "legacy mint (no registry) byte-identical behavior"


def g18_oidc_provisioner_requires_presented_token():
    # The oidc attestation method attests via the dex-issued JWT: with
    # no presented token there is nothing attesting the identity, so
    # the mint is refused fail-closed -- this is what makes the oidc
    # type a real mapping onto the dex token seam rather than a label.
    from gov.provisioner import ProvisionerRefusedError
    ex, _ = _executor(_registry())
    try:
        _mint(ex, provisioner="dex-prod", ttl_seconds=600,
              scopes=["tools:read"])
    except ProvisionerRefusedError as err:
        assert "oidc" in str(err), err
        return "PASS", "oidc mint without token refused: %s" % err
    return "FAIL", "oidc provisioner minted with no presented token"


PROBES = [
    ("G1_valid_mint_within_policy", g1_valid_mint_within_policy),
    ("G2_ttl_over_max_refused", g2_ttl_over_max_refused),
    ("G3_token_lifetime_over_max_refused", g3_token_lifetime_over_max_refused),
    ("G4_scope_outside_grant_refused", g4_scope_outside_grant_refused),
    ("G5_break_glass_without_justification_refused",
     g5_break_glass_without_justification_refused),
    ("G6_break_glass_with_justification_accepted",
     g6_break_glass_with_justification_accepted),
    ("G7_break_glass_ttl_capped", g7_break_glass_ttl_capped),
    ("G8_unknown_provisioner_refused", g8_unknown_provisioner_refused),
    ("G9_unnamed_provisioner_refused", g9_unnamed_provisioner_refused),
    ("G10_role_outside_provisioner_grant_refused",
     g10_role_outside_provisioner_grant_refused),
    ("G11_per_provisioner_budget_enforced", g11_per_provisioner_budget_enforced),
    ("G12_scope_token_disagreement_refused",
     g12_scope_token_disagreement_refused),
    ("G13_token_scope_enforced_when_unrequested",
     g13_token_scope_enforced_when_unrequested),
    ("G14_min_ttl_refused", g14_min_ttl_refused),
    ("G15_default_ttl_is_capped", g15_default_ttl_is_capped),
    ("G16_no_registry_with_policy_args_refused",
     g16_no_registry_with_policy_args_refused),
    ("G17_legacy_mint_unchanged_without_registry",
     g17_legacy_mint_unchanged_without_registry),
    ("G18_oidc_provisioner_requires_presented_token",
     g18_oidc_provisioner_requires_presented_token),
]


def _run_once(probes):
    results = []
    for name, fn in probes:
        try:
            status, detail = fn()
        except AssertionError as e:
            status, detail = "FAIL", "assertion: %s" % (e,)
        except Exception as e:  # noqa: BLE001 - probes must not crash
            status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
        results.append((name, status, detail))
    return results


def _green_check():
    """Depth-1: adjacent unit module only, child env GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="prov-green-")
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_provisioner", "-v"],
            capture_output=True, text=True, timeout=600, cwd=TREE,
            env=env)
        tail = (p.stdout + p.stderr)[-1500:]
        print("green check (tests/test_provisioner):\n%s" % tail)
        return p.returncode == 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    red_phase = "--red-phase" in argv
    probes = RED_PROBES if red_phase else PROBES
    first = _run_once(probes)
    second = _run_once(probes)
    det_ok = ([(n, s) for n, s, _ in first]
              == [(n, s) for n, s, _ in second])
    width = max(len(n) for n, _, _ in first)
    print("== provisioner probes (%s) =="
          % ("RED-PHASE: gap demonstration" if red_phase else
             "GREEN-PHASE: closure battery"))
    for name, status, detail in first:
        print("%-*s %s  %s" % (width, name, status, detail))
    print("determinism x2: %s" % ("IDENTICAL" if det_ok else "DIVERGED"))
    if red_phase:
        # Gap demonstration: the pristine seam has no issuance policy.
        # Exit 0 = gap shown (all three probes PASS = gap demonstrated).
        if all(s == "PASS" for _, s, _ in first) and det_ok:
            print("GAP SHOWN: %d/%d gaps demonstrated, statuses identical x2"
                  % (len(first), len(first)))
            return 0
        print("RED-PHASE INCONCLUSIVE")
        return 1
    if not _green_check():
        print("GREEN CHECK FAILED")
        return 1
    bad = [(n, d) for n, s, d in first if s != "PASS"]
    if bad or not det_ok:
        print("%d probe(s) failing" % len(bad))
        for n, d in bad:
            print("  FAIL %s: %s" % (n, d))
        return 1
    print("ALL %d PROBES PASS" % len(first))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
