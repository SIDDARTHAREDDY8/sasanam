#!/usr/bin/env python3
"""Unit tests for wave-198 lane E: MCP token-claims wiring at the executor.

The wave-196 lane A built keyset-attested MCP ToolAnnotations and the
``authority_proof.check(..., mcp_tool_registry=..., token_claims=...)``
seam, but the executor never passed token claims -- enforcement was
live at the seam only. This lane threads the agent's verified token
claims (recorded at ``mint_identity`` time) into both
``authority_proof.check`` call sites (pre-decision seam and the
approved-sweep re-proof).

Public seams only:
  - ToolExecutor.set_mcp_tool_registry / _mcp_token_claims_for
  - ToolExecutor.call with a registry installed (scope miss -> denied)
  - ToolExecutor.execute_approved sweep re-proof (scope miss -> refused)

Stdlib only. $0 spend. Deterministic; no clock dependence except the
expiry re-validation probe, which uses a white-box expired stored
claim (no sleeping).
"""

import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import authority_proof as ap  # noqa: E402
from gov import mcp_annotations as ma  # noqa: E402
from gov.identity import IdentityTokenError  # noqa: E402
from gov.keyset import new_keyset  # noqa: E402
from harness import make_run  # noqa: E402

ISSUER = "https://dex.sasanam.internal"
READ_ONLY = {"read_only_hint": True, "destructive_hint": False,
             "idempotent_hint": True, "open_world_hint": False}
SCOPE = "mcp:files:read"


def _seed(tag):
    return hashlib.sha256(b"mcp-wiring-tests:" + tag.encode()).digest()


def _registry(pair="files::read", scopes=(SCOPE,)):
    ks, _ = new_keyset(_seed("wks"), purpose=ma.ATTESTATION_PURPOSE)
    stmt = ma.attest_tool_annotations(
        ks, pair, dict(READ_ONLY), _seed("wks"),
        required_scopes=list(scopes), at=1790000000)
    reg, refused = ma.build_tool_registry([stmt], ks.to_dict())
    assert refused == [], refused
    return reg


def _claims(agent_id, exp_offset, scope="mcp:files:read mcp:files:write",
            **over):
    now = int(time.time())
    c = {"iss": ISSUER, "sub": agent_id,
         "aud": "sasanam-policy-engine", "iat": now - 60,
         "exp": now + exp_offset, "jti": "wiring-jti-%s" % agent_id,
         "principal": "org1", "role": "coder", "agent_scope": scope}
    c.update(over)
    return c


def _boundary(**kw):
    d = {"boundary_id": "wiring", "version": "1",
         "mcp_servers": ["files"],
         "mcp_tools": ["files::read", "files::write"],
         "mcp_max_arg_bytes": 4096}
    d.update(kw)
    return ap.boundary_from_dict(d)


def _policy(allow_mcp=False):
    src = Path(os.path.dirname(_TESTS_DIR), "policies",
               "default.yaml").read_text()
    src = src.replace(
        "coder: [read_file, write_file, delete_file, api_call, "
        "install_package]",
        "coder: [read_file, write_file, delete_file, api_call, "
        "install_package, mcp_call]")
    if allow_mcp:
        # The sweep's step-4 fresh policy re-evaluation runs before
        # the authority re-proof; without an allow rule the default
        # deny stops the run before the seam under test. The rule can
        # only name mcp_call while the test patches
        # gov.policy.KNOWN_TOOLS (cleaned up afterwards).
        src += ("\n  - id: test-allow-mcp\n"
                "    description: Test-only allow for the sweep test.\n"
                "    effect: allow\n"
                "    match:\n"
                "      tool: [mcp_call]\n"
                "    reason: test-only\n")
    path = Path(tempfile.mkdtemp(prefix="mcp-wiring-pol-"),
                "policy.yaml")
    path.write_text(src)
    return str(path)


def _denied_authority(result):
    return (result.get("status") == "denied"
            and result.get("policy_id") == "authority-boundary")


class TestRegistrySeam(unittest.TestCase):
    def test_set_registry_accepts_mapping_and_none(self):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        self.assertIsNone(ex._mcp_tool_registry)
        reg = _registry()
        ex.set_mcp_tool_registry(reg)
        self.assertIs(ex._mcp_tool_registry, reg)
        ex.set_mcp_tool_registry(None)
        self.assertIsNone(ex._mcp_tool_registry)

    def test_set_registry_rejects_non_mapping(self):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        for bad in (["files::read"], "registry", 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ex.set_mcp_tool_registry(bad)
        # A rejected set leaves the previous value untouched.
        self.assertIsNone(ex._mcp_tool_registry)

    def test_mint_records_verified_claims(self):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        presented = _claims("a1", 3600)
        ex.mint_identity("a1", "coder", "org1", token_claims=presented)
        got = ex._mcp_token_claims_for("a1")
        self.assertEqual(got, presented)
        # Defensive copy: caller-side mutation cannot alter enforcement.
        presented["agent_scope"] = "mcp:admin"
        self.assertNotEqual(ex._mcp_token_claims_for("a1")["agent_scope"],
                            "mcp:admin")

    def test_mint_without_claims_records_nothing(self):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        ex.mint_identity("a2", "coder", "org1")
        self.assertIsNone(ex._mcp_token_claims_for("a2"))

    def test_remint_without_claims_drops_stale_claims(self):
        """Spec-review regression: re-minting an agent_id without a
        token must not inherit the previous mint's claims (stale
        scopes would silently survive the re-mint)."""
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        ex.mint_identity("a2b", "coder", "org1",
                         token_claims=_claims("a2b", 3600))
        self.assertIsNotNone(ex._mcp_token_claims_for("a2b"))
        ex.mint_identity("a2b", "coder", "org1")
        self.assertIsNone(ex._mcp_token_claims_for("a2b"))
        # And the enforcement consequence: scope-required tools now
        # fail closed for the re-minted tokenless identity.
        ex.set_authority_boundary(_boundary())
        ex.set_mcp_tool_registry(_registry())
        ident = ex.mint_identity("a2c", "coder", "org1",
                                 token_claims=_claims("a2c", 3600,
                                                      scope=SCOPE))
        ex.mint_identity("a2c", "coder", "org1")  # re-mint, no token
        r = ex.call(ident, "mcp_call", server="files", name="read",
                    arguments={})
        self.assertTrue(_denied_authority(r), r)

    def test_mint_invalid_claims_raises_and_records_nothing(self):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        bad = _claims("a3", 3600, agent_scope="")
        with self.assertRaises(IdentityTokenError):
            ex.mint_identity("a3", "coder", "org1", token_claims=bad)
        self.assertIsNone(ex._mcp_token_claims_for("a3"))

    def test_claims_for_unknown_agent_is_none(self):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        self.assertIsNone(ex._mcp_token_claims_for("nobody"))
        self.assertIsNone(ex._mcp_token_claims_for(None))


class TestExecutorScopeEnforcement(unittest.TestCase):
    def _wired(self, agent_id="w1", scope="mcp:other"):
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        ident = ex.mint_identity(agent_id, "coder", "org1",
                                 token_claims=_claims(agent_id, 3600,
                                                      scope=scope))
        ex.set_authority_boundary(_boundary())
        ex.set_mcp_tool_registry(_registry())
        return ctx, ex, ident

    def _authority_denials(self, ctx):
        return [e for e in ctx["read_log"]()
                if isinstance(e, dict)
                and e.get("flag") == "authority_boundary_refused"]

    def test_scope_miss_refused_at_predecision_seam(self):
        """The lane's core promise: scope-missing token -> denied."""
        ctx, ex, ident = self._wired(scope="mcp:other")
        r = ex.call(ident, "mcp_call", server="files", name="read",
                    arguments={})
        self.assertTrue(_denied_authority(r), r)
        denials = self._authority_denials(ctx)
        self.assertEqual(len(denials), 1)
        proof = denials[0]["authority_proof"]
        self.assertEqual(proof["verdict"], "exceeds_boundary")
        self.assertEqual(
            proof["counterexample"]["domain"], "mcp_tools")
        # The missing scope is named in the proof's counterexample
        # (the executor's one-line reason carries only the pair).
        self.assertIn(SCOPE,
                      proof["counterexample"]["reason"])

    def test_scope_hit_passes_authority_seam(self):
        ctx, ex, ident = self._wired(scope="mcp:files:read mcp:other")
        r = ex.call(ident, "mcp_call", server="files", name="read",
                    arguments={})
        self.assertFalse(_denied_authority(r), r)
        self.assertEqual(self._authority_denials(ctx), [])

    def test_no_registry_legacy_unchanged(self):
        """Registry absent: scope-missing token is NOT refused at the
        authority seam (legacy path byte-identical)."""
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        ident = ex.mint_identity("w2", "coder", "org1",
                                 token_claims=_claims("w2", 3600,
                                                      scope="mcp:other"))
        ex.set_authority_boundary(_boundary())
        # No registry installed: the legacy path.
        r = ex.call(ident, "mcp_call", server="files", name="read",
                    arguments={})
        self.assertFalse(_denied_authority(r), r)
        self.assertEqual(self._authority_denials(ctx), [])

    def test_no_token_claims_fails_closed(self):
        """Registry installed but the agent minted no token: scoped
        tools fail closed (fail-closed direction, never silent)."""
        ctx = make_run(policy_path=_policy())
        ex = ctx["executor"]
        ident = ex.mint_identity("w3", "coder", "org1")
        ex.set_authority_boundary(_boundary())
        ex.set_mcp_tool_registry(_registry())
        r = ex.call(ident, "mcp_call", server="files", name="read",
                    arguments={})
        self.assertTrue(_denied_authority(r), r)
        proof = self._authority_denials(ctx)[0]["authority_proof"]
        self.assertEqual(proof["verdict"], "exceeds_boundary")
        self.assertIn("no identity token claims",
                      proof["counterexample"]["reason"])

    def test_unattested_pair_requires_no_scopes(self):
        """Attestation can only tighten: a pair with no attested entry
        is not refused for scopes even with a registry installed."""
        ctx, ex, ident = self._wired(scope="mcp:other")
        r = ex.call(ident, "mcp_call", server="files", name="write",
                    arguments={})
        self.assertFalse(_denied_authority(r), r)

    def test_scope_matching_is_exact(self):
        """Substring/prefix scopes do not satisfy a required scope."""
        for tricky in ("mcp:files:readwrite", "xmcp:files:read",
                       "mcp:files:rea"):
            ctx, ex, ident = self._wired(agent_id="w4-" + tricky[:4],
                                         scope=tricky)
            r = ex.call(ident, "mcp_call", server="files", name="read",
                        arguments={})
            self.assertTrue(_denied_authority(r),
                            (tricky, r))

    def test_expired_token_fails_closed_at_check_time(self):
        """Expiry is re-validated at every check: a token that has
        since expired fails closed even though mint accepted it."""
        ctx, ex, ident = self._wired(scope=SCOPE)
        # White-box time travel: the stored claim set now reads expired
        # (well past the 60s clock skew tolerance).
        ex._mcp_token_claims[ident.agent_id]["exp"] = int(time.time()) - 600
        r = ex.call(ident, "mcp_call", server="files", name="read",
                    arguments={})
        self.assertTrue(_denied_authority(r), r)
        proof = self._authority_denials(ctx)[0]["authority_proof"]
        self.assertEqual(proof["verdict"], "exceeds_boundary")
        self.assertIn("expired", proof["counterexample"]["reason"])

    def test_sweep_reproof_enforces_scopes(self):
        """TOCTOU continuity: registry installed between approval and
        sweep -> the execution-time re-proof refuses the scoped call.

        The record is queued directly through the public
        ``ApprovalQueue.queue`` API (a policy file cannot name the
        ``mcp_call`` tool -- the policy validator only knows tools
        registered in the tool taxonomy -- so the queue path is driven
        at the queue seam, exactly as the executor's own require_approval
        path does).
        """
        from gov.policy import PolicyDecision
        import gov.policy as _policy_mod
        # The policy validator only accepts rules naming tools in
        # KNOWN_TOOLS; the sweep test's allow rule needs mcp_call
        # registered. Patched for this test only, discarded after.
        _policy_mod.KNOWN_TOOLS.add("mcp_call")
        self.addCleanup(_policy_mod.KNOWN_TOOLS.discard, "mcp_call")
        ctx = make_run(policy_path=_policy(allow_mcp=True))
        ex = ctx["executor"]
        ident = ex.mint_identity("w5", "coder", "org1",
                                 token_claims=_claims("w5", 3600,
                                                      scope="mcp:other"))
        ex.set_authority_boundary(_boundary())
        # The sweep's display≡execution check re-derives the
        # approver-facing preview with the executor's own renderer;
        # build the queued preview the same way so the run reaches
        # the authority re-proof (the seam under test).
        from gov.approvals import sanitize_preview_text
        _args = {"server": "files", "name": "read", "arguments": {}}
        _preview = sanitize_preview_text(ex._preview("mcp_call", _args))
        aid = ctx["approvals"].queue(
            {"tool": "mcp_call",
             "args": _args,
             "identity": ident.as_dict(),
             "agent_justification": None,
             "redactions": []},
            PolicyDecision("require_approval",
                           "test-only: queue for sweep re-proof",
                           policy_id="test-queue-mcp",
                           flag="test_queue"),
            "agent_direct",
            _preview,
            caller_identity=ident,
            # Match the executor's normal queue path: stamp the
            # record with the active policy hash so the sweep's
            # policy-staleness check passes and the run reaches the
            # authority re-proof (the seam under test).
            policy_hash=ex.policy.policy_hash)
        ctx["approvals"].decide(aid, True, reason="test approval",
                                decided_by="human-operator")
        # Operator installs the attested registry before the sweep.
        ex.set_mcp_tool_registry(_registry())
        ex.execute_approved()
        refused = [e for e in ctx["read_log"]()
                   if isinstance(e, dict)
                   and e.get("flag") == "authority_boundary_exceeded"]
        self.assertEqual(len(refused), 1)
        # The sweep's refusal reason carries the pair (the scope names
        # live in the proof counterexample, asserted at the
        # pre-decision seam above); the flag and policy id are the
        # sweep-time contract.
        self.assertIn("files::read", refused[0]["reason"])
        self.assertEqual(refused[0]["flag"], "authority_boundary_exceeded")
        self.assertEqual(refused[0]["policy_id"],
                         "authority-boundary-execution-refused")


if __name__ == "__main__":
    unittest.main()
