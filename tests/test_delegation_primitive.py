"""P10 governed authority-delegation primitive (wave-24).

Tests the 16 adversarial situations from
workstreams/architect/DELEGATION_PRIMITIVE_SPEC.md §5 against
gov/approvals.py::DelegationStore — the server-side, MAC-bound grant
store. Each situation asserts the exact refusal reason AND the audit
event (loudness discipline).

Boundary note (updated wave-26): these tests exercise the store's
contract directly (mint / verify_invocation / revoke_grant /
check_unscoped_framing). The executor wiring that consumes these
methods on the call path landed in wave-26 (gov/executor.py
``ToolExecutor.call()`` consults the store: unscoped framing is denied
under ``unscoped_delegation: deny``, presented grants are verified
before policy evaluation, store errors fail closed) and is pinned by
tests/test_delegation_executor_wiring.py. The P10 incident probe in
evals/ keeps asserting the flag-default executor behavior (red-team
area; not touched here).
"""

import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov.approvals import (DelegationError, DelegationStore,
                           _delegation_record_mac)
from gov.identity import AgentIdentity
from gov.policy import PolicyEngine

from tests import harness

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_TEXT = (REPO_ROOT / "policies" / "default.yaml").read_text()

_DELEGATION_BLOCK_RE = re.compile(
    r"\ndelegation:\n(?:  [^\n]*\n)+")


def _policy_with(delegation_block):
    """Write a temp policy: default policy with the top-level
    ``delegation:`` block replaced."""
    text, n = _DELEGATION_BLOCK_RE.subn("\n" + delegation_block, 
                                        DEFAULT_POLICY_TEXT, count=1)
    assert n == 1, "top-level delegation block not found"
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(text)
    f.close()
    return f.name


def _delegation_block(**kw):
    cfg = {"enabled": True, "default_ttl_minutes": 60,
           "max_ttl_minutes": 240, "max_depth": 1,
           "require_provisioned_for": [], "unscoped_delegation": "flag"}
    cfg.update(kw)

    def fmt(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, list):
            return "[]" if not v else "[%s]" % ", ".join(v)
        return str(v)
    lines = ["delegation:"]
    for k in ("enabled", "default_ttl_minutes", "max_ttl_minutes",
              "max_depth", "require_provisioned_for",
              "unscoped_delegation"):
        lines.append("  %s: %s" % (k, fmt(cfg[k])))
    return "\n".join(lines) + "\n"


def _make_store(ctx, policy=None, **kw):
    policy = policy or ctx["policy"]
    store = DelegationStore(
        ctx["run_dir"], ctx["log"],
        config=dict(policy.authority_delegation),
        known_agent_ids={"support-1", "coder-1", "researcher-1",
                         "worker-1", "worker-2", "attacker-1"},
        **kw)

    def effect_probe(role, tool):
        d = policy.evaluate(
            {"tool": tool, "role": role, "agent_id": "probe", "args": {}},
            {"role": role, "agent": "probe"})
        return d.effect

    store.set_policy_probes(policy.role_allows, effect_probe)
    # The executor's own minted-identity verifier (F26), installed the
    # way ToolExecutor.__init__ installs it on the approval queue.
    store.set_identity_verifier(ctx["executor"]._verify_approval_identity)
    return store


def _events(ctx, name):
    return [e for e in ctx["read_log"]() if e.get("event") == name]


def _assert_refused(test, ctx, fn, reason):
    with test.assertRaises(DelegationError) as cm:
        fn()
    test.assertEqual(cm.exception.reason, reason,
                     "expected reason %r, got %r (%s)"
                     % (reason, cm.exception.reason, cm.exception))
    return cm.exception


class DelegationPrimitiveTest(unittest.TestCase):
    # -- S1: unscoped claim on a privileged tool, deny -------------------
    def test_s1_unscoped_deny(self):
        policy = PolicyEngine(_policy_with(
            _delegation_block(unscoped_delegation="deny")))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        researcher = ctx["identities"]["researcher"]
        verdict = store.check_unscoped_framing(
            on_behalf_of="boss-agent", identity=researcher)
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["policy_id"], "delegation-unscoped")
        self.assertEqual(verdict["flag"], "unscoped_delegation_denied")
        denied = _events(ctx, "unscoped_delegation_denied")
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["on_behalf_of"], "boss-agent")

    # -- S2: P10 regression (default config): flag, label-only -----------
    def test_s2_unscoped_flag_default(self):
        ctx = harness.make_run()  # default policy: delegation disabled
        store = _make_store(ctx)
        researcher = ctx["identities"]["researcher"]
        verdict = store.check_unscoped_framing(
            on_behalf_of="boss-agent", delegated_by="supervisor-1",
            identity=researcher)
        self.assertTrue(verdict["allowed"])
        self.assertEqual(verdict["mode"], "label-only")
        # Enabled + flag: allowed but explicitly flagged mode.
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx2 = harness.make_run(policy_path=policy.yaml_path)
        store2 = _make_store(ctx2, policy)
        verdict2 = store2.check_unscoped_framing(
            on_behalf_of="boss-agent", identity=researcher)
        self.assertTrue(verdict2["allowed"])
        self.assertEqual(verdict2["mode"], "flag")
        # No grant id anywhere: a grant-bearing call is not "unscoped".
        verdict3 = store2.check_unscoped_framing(
            on_behalf_of="boss-agent",
            delegation_grant_id="some-grant", identity=researcher)
        self.assertFalse(verdict3["unscoped"])

    # -- happy path: mint -> invoke, dual attribution, approval flags ---
    def test_happy_path_dual_attribution(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        self.assertIn("grant_id", grant)
        self.assertEqual(grant["delegator"]["agent_id"], "coder-1")
        self.assertEqual(grant["delegatee"], "worker-1")
        self.assertFalse(grant["revoked"])
        granted = _events(ctx, "delegation_granted")
        self.assertEqual(len(granted), 1)
        ok = store.verify_invocation(
            grant["grant_id"], worker, "read_file", {"path": "a.txt"})
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["delegator"]["agent_id"], "coder-1")
        invoked = _events(ctx, "delegation_invoked")
        self.assertEqual(len(invoked), 1)
        self.assertEqual(invoked[0]["agent_id"], "worker-1")
        self.assertEqual(invoked[0]["delegator_agent_id"], "coder-1")
        self.assertEqual(invoked[0]["grant_id"], grant["grant_id"])

    def test_approval_flags_propagate(self):
        # The effect probe marks api_call require_approval for the
        # researcher role here; the flag must ride into the grant
        # scope so the executor queues the delegatee's invocation.
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = DelegationStore(
            ctx["run_dir"], ctx["log"],
            config=dict(policy.authority_delegation),
            known_agent_ids={"researcher-1", "worker-1"})
        store.set_identity_verifier(
            ctx["executor"]._verify_approval_identity)
        store.set_policy_probes(
            lambda role, tool: True,
            lambda role, tool: ("require_approval"
                                if tool == "api_call" else "allow"))
        researcher = ctx["identities"]["researcher"]
        worker = ctx["mint_identity"]("worker-1", "researcher",
                                      "research-org")
        grant = store.delegate_grant(
            researcher, "worker-1", {"tools": ["api_call"]})
        self.assertEqual(grant["scope"]["approval_gated"], ["api_call"])
        ok = store.verify_invocation(
            grant["grant_id"], worker, "api_call", {})
        self.assertEqual(ok["requires_approval"], ["api_call"])

    # -- S3: forged grant id -------------------------------------------
    def test_s3_forged_grant_id(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation("f" * 64, worker, "read_file"),
            "unknown_grant")
        self.assertEqual(_events(ctx, "delegation_invoked"), [])
        refused = _events(ctx, "delegation_invocation_refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["reason"], "unknown_grant")

    # -- S4: expired grant ----------------------------------------------
    def test_s4_expired_grant(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # Simulate the passage of time: move expires_at into the past
        # and re-MAC (the MAC stays valid — the control under test is
        # the expiry check, not the clock).
        grant["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        grant["grant_mac"] = _delegation_record_mac(grant)
        store._rewrite([grant])
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], worker, "read_file"),
            "grant_expired")

    # -- S5: revoked grant; revocation propagates down the chain ---------
    def test_s5_revoked_grant(self):
        policy = PolicyEngine(_policy_with(
            _delegation_block(max_depth=2)))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "coder", "dev-org")
        sub = ctx["mint_identity"]("attacker-1", "coder", "dev-org")
        root = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        child = store.delegate_grant(
            worker, "attacker-1", {"tools": ["read_file"]},
            parent_grant_id=root["grant_id"])
        store.revoke_grant(root["grant_id"], coder, reason="compromised")
        revoked = _events(ctx, "delegation_revoked")
        self.assertEqual(len(revoked), 1)
        self.assertEqual(revoked[0]["revoker_agent_id"], "coder-1")
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                root["grant_id"], worker, "read_file"),
            "grant_revoked")
        # The descendant dies too — via chain_broken, with no
        # per-descendant bookkeeping (revocation propagates for free).
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                child["grant_id"], sub, "read_file"),
            "chain_broken")

    def test_s5_revoke_not_authorized(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        _assert_refused(
            self, ctx,
            lambda: store.revoke_grant(grant["grant_id"], worker),
            "revoke_not_authorized")
        # The grant still verifies — the failed revoke changed nothing.
        ok = store.verify_invocation(
            grant["grant_id"], worker, "read_file")
        self.assertTrue(ok["ok"])

    # -- S6: scope amplification at mint ---------------------------------
    def test_s6_scope_amplification(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        support = ctx["identities"]["support"]
        # support's role allowlist lacks write_file entirely.
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                support, "worker-1", {"tools": ["write_file"]}),
            "scope_amplification")
        # send_email IS in support's role allowlist but the live
        # policy DENIES it (deny-egress-unallowlisted): the
        # effect==deny arm of the no-amplification check fires.
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                support, "worker-1", {"tools": ["send_email"]}),
            "scope_amplification")
        # Nothing was minted.
        self.assertEqual(store._read_all(), [])
        refused = _events(ctx, "delegation_refused")
        self.assertEqual(
            [e["reason"] for e in refused],
            ["scope_amplification", "scope_amplification"])

    def test_mint_requires_verified_identity(self):
        # Bare principal strings are never accepted as the minter
        # (spec §1.2.1): TypeError, nothing minted, nothing audited as
        # a grant.
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        with self.assertRaises(TypeError):
            store.delegate_grant(
                "coder-1", "worker-1", {"tools": ["read_file"]})
        # A forged AgentIdentity the executor never minted is refused
        # by the installed verifier (UnmintedIdentityError, not a
        # grant refusal — the caller never authenticated). Note the
        # agent_id must differ from every minted tuple: the verifier
        # keys on (agent_id, role, run_id, principal).
        forged = AgentIdentity(agent_id="coder-2", role="coder",
                               run_id=ctx["run_dir"].name,
                               principal="dev-org")
        from gov.identity import UnmintedIdentityError
        with self.assertRaises(UnmintedIdentityError):
            store.delegate_grant(
                forged, "worker-1", {"tools": ["read_file"]})
        self.assertEqual(store._read_all(), [])

    # -- S7: scope exceeded at invoke ------------------------------------
    def test_s7_scope_exceeded(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], worker, "write_file"),
            "scope_exceeded")

    def test_s7_arg_constraints(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1",
            {"tools": ["read_file"],
             "arg_constraints": {"path": ["/sandbox/notes.txt"]}})
        ok = store.verify_invocation(
            grant["grant_id"], worker, "read_file",
            {"path": "/sandbox/notes.txt"})
        self.assertTrue(ok["ok"])
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], worker, "read_file",
                {"path": "/etc/passwd"}),
            "arg_constraint_violated")

    # -- S8: delegatee mismatch (stolen grant id) -------------------------
    def test_s8_delegatee_mismatch(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        attacker = ctx["mint_identity"]("attacker-1", "coder", "dev-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # The attacker holds the grant id but not the delegatee
        # identity: the grant is not a bearer token.
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], attacker, "read_file"),
            "delegatee_mismatch")
        # The legitimate delegatee still verifies fine afterwards.
        ok = store.verify_invocation(
            grant["grant_id"], worker, "read_file")
        self.assertTrue(ok["ok"])

    # -- S9: sub-delegation widens scope ----------------------------------
    def test_s9_sub_delegation_widens_scope(self):
        policy = PolicyEngine(_policy_with(
            _delegation_block(max_depth=2)))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "coder", "dev-org")
        root = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # worker's own role allows write_file (no amplification), but
        # the PARENT grant lacks it: narrowing violation.
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                worker, "attacker-1",
                {"tools": ["read_file", "write_file"]},
                parent_grant_id=root["grant_id"]),
            "scope_widened")

    def test_s9_sub_delegation_extends_ttl(self):
        policy = PolicyEngine(_policy_with(
            _delegation_block(max_depth=2)))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "coder", "dev-org")
        root = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]}, ttl_minutes=10)
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                worker, "attacker-1", {"tools": ["read_file"]},
                ttl_minutes=60, parent_grant_id=root["grant_id"]),
            "ttl_extended")

    def test_s9_sub_delegator_must_be_parent_delegatee(self):
        policy = PolicyEngine(_policy_with(
            _delegation_block(max_depth=3)))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "coder", "dev-org")
        outsider = ctx["mint_identity"]("attacker-1", "coder", "dev-org")
        root = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # Hop-skipping: the outsider is not the parent's delegatee.
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                outsider, "worker-2", {"tools": ["read_file"]},
                parent_grant_id=root["grant_id"]),
            "not_parent_delegatee")

    # -- S10: depth exceeded ----------------------------------------------
    def test_s10_depth_exceeded(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))  # depth 1
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "coder", "dev-org")
        root = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                worker, "attacker-1", {"tools": ["read_file"]},
                parent_grant_id=root["grant_id"]),
            "depth_exceeded")

    def test_s10_depth_two_ok_depth_three_refused(self):
        policy = PolicyEngine(_policy_with(
            _delegation_block(max_depth=2)))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "coder", "dev-org")
        sub = ctx["mint_identity"]("attacker-1", "coder", "dev-org")
        root = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        child = store.delegate_grant(
            worker, "attacker-1", {"tools": ["read_file"]},
            parent_grant_id=root["grant_id"])
        self.assertEqual(len(child["chain"]), 1)
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                sub, "researcher-1", {"tools": ["read_file"]},
                parent_grant_id=child["grant_id"]),
            "depth_exceeded")

    # -- S11: tampered grant store -----------------------------------------
    def test_s11_tampered_store(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # Attacker with run-dir write access flips scope.tools in
        # delegations.jsonl WITHOUT re-MACing (no key).
        path = Path(ctx["run_dir"]) / "delegations.jsonl"
        rec = json.loads(path.read_text().strip())
        rec["scope"]["tools"] = ["read_file", "write_file", "delete_file"]
        path.write_text(json.dumps(rec) + "\n")
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], worker, "delete_file"),
            "grant_integrity_violation")
        # Even the originally-scoped tool now refuses: the MAC covers
        # the whole record, so ANY tamper breaks verification.
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], worker, "read_file"),
            "grant_integrity_violation")

    # -- S12: single-use replay ---------------------------------------------
    def test_s12_single_use_replay(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]}, single_use=True)
        ok = store.verify_invocation(
            grant["grant_id"], worker, "read_file")
        self.assertTrue(ok["single_use_consumed"])
        _assert_refused(
            self, ctx,
            lambda: store.verify_invocation(
                grant["grant_id"], worker, "read_file"),
            "grant_consumed")

    def test_s12_single_use_concurrent_consume_race(self):
        # F39 shape: N threads racing one single-use grant — exactly
        # one invocation may succeed. The consume path re-checks the
        # consumed flag under the store lock (see verify_invocation).
        import threading
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]}, single_use=True)
        wins, fails = [], []
        barrier = threading.Barrier(20)

        def attempt():
            barrier.wait()
            try:
                store.verify_invocation(
                    grant["grant_id"], worker, "read_file")
                wins.append(1)
            except DelegationError:
                fails.append(1)

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(fails), 19)

    # -- S13: cross-run smuggling --------------------------------------------
    def test_s13_cross_run_smuggling(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx_a = harness.make_run(policy_path=policy.yaml_path)
        store_a = _make_store(ctx_a, policy)
        coder = ctx_a["identities"]["coder"]
        worker_a = ctx_a["mint_identity"]("worker-1", "support",
                                          "customer-org")
        grant = store_a.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # Run B: a different run dir, an identity for the same agent
        # id but bound to run B. The grant store of run A is
        # consulted (as a shared/cross-run store would be).
        ctx_b = harness.make_run(policy_path=policy.yaml_path)
        worker_b = ctx_b["mint_identity"]("worker-1", "support",
                                          "customer-org")
        self.assertNotEqual(ctx_a["run_dir"].name, ctx_b["run_dir"].name)
        _assert_refused(
            self, ctx_a,
            lambda: store_a.verify_invocation(
                grant["grant_id"], worker_b, "read_file"),
            "cross_run_denied")
        # Explicit cross_run grants are the opt-in escape hatch.
        grant2 = store_a.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]}, cross_run=True)
        ok = store_a.verify_invocation(
            grant2["grant_id"], worker_b, "read_file")
        self.assertTrue(ok["ok"])
        # ...but the delegatee binding still holds cross-run.
        attacker_b = ctx_b["mint_identity"]("attacker-1", "coder",
                                             "dev-org")
        _assert_refused(
            self, ctx_a,
            lambda: store_a.verify_invocation(
                grant2["grant_id"], attacker_b, "read_file"),
            "delegatee_mismatch")

    # -- S14: human powers are non-delegable ----------------------------------
    def test_s14_human_powers_non_delegable(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        for power in ("decide", "cast_vote", "break_glass"):
            _assert_refused(
                self, ctx,
                lambda p=power: store.verify_invocation(
                    grant["grant_id"], worker, p),
                "non_delegable_power")
        # A grant can never even be MINTED with a human power in
        # scope: the no-amplification check fires first (no role
        # allowlists decide/cast_vote/break_glass as tools).
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                coder, "worker-1", {"tools": ["decide"]}),
            "scope_amplification")

    # -- S15: self-delegation --------------------------------------------------
    def test_s15_self_delegation(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                coder, "coder-1", {"tools": ["read_file"]}),
            "self_delegation")
        # The principal-alias arm: naming your own principal is the
        # same laundering shape (D1-core §3.3).
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                coder, "dev-org", {"tools": ["read_file"]},
                delegatee_is_principal=True),
            "self_delegation")
        self.assertEqual(store._read_all(), [])

    # -- S16: taint laundering via delegation -----------------------------------
    def test_s16_taint_inherited(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        worker = ctx["mint_identity"]("worker-1", "support", "customer-org")
        grant = store.delegate_grant(
            coder, "worker-1", {"tools": ["read_file"]})
        # The delegator's session is tainted; the delegatee's
        # invocation must CARRY the taint (delegation is not a
        # clean-room). The ok-dict flag is what the executor's A2
        # Rule-of-Two gate consumes at call time (executor wiring is
        # the follow-up lane; this test pins the carry contract).
        ok = store.verify_invocation(
            grant["grant_id"], worker, "read_file",
            tainted=True, taint_sources=["tool:api_call#3"])
        self.assertTrue(ok["taint_inherited"])
        invoked = _events(ctx, "delegation_invoked")
        self.assertEqual(len(invoked), 1)
        self.assertTrue(invoked[0]["taint_inherited"])
        self.assertEqual(invoked[0]["taint_sources"], ["tool:api_call#3"])
        # Untainted invocations record the negative explicitly.
        ok2 = store.verify_invocation(
            grant["grant_id"], worker, "read_file")
        self.assertFalse(ok2["taint_inherited"])

    # -- config: fail-closed normalization --------------------------------------
    def test_config_fail_closed(self):
        from gov.approvals import _normalize_authority_delegation_config as norm
        base = norm(None)
        self.assertFalse(base["enabled"])
        with self.assertRaises(ValueError):
            norm("not-a-dict")
        for bad in ({"enabled": "yes"},
                    {"max_depth": 9},
                    {"max_depth": 0},
                    {"default_ttl_minutes": 0},
                    {"default_ttl_minutes": 500, "max_ttl_minutes": 240},
                    {"unscoped_delegation": "maybe"},
                    {"require_provisioned_for": "break_glass_tools"}):
            with self.assertRaises(ValueError, msg="cfg=%r" % (bad,)):
                norm(dict(base, **bad))
        # The engine refuses to load a malformed section (fail closed
        # at load, not at first mint).
        with self.assertRaises(ValueError):
            PolicyEngine(_policy_with(_delegation_block(max_depth=9)))

    def test_mint_refused_when_disabled(self):
        ctx = harness.make_run()  # default: delegation.enabled false
        store = _make_store(ctx)
        coder = ctx["identities"]["coder"]
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                coder, "worker-1", {"tools": ["read_file"]}),
            "delegation_disabled")

    def test_mint_refused_without_policy_probes(self):
        # No-amplification cannot run blind: minting without the live
        # policy probes is refused fail-closed.
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = DelegationStore(
            ctx["run_dir"], ctx["log"],
            config=dict(policy.authority_delegation))
        store.set_identity_verifier(
            ctx["executor"]._verify_approval_identity)
        coder = ctx["identities"]["coder"]
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                coder, "worker-1", {"tools": ["read_file"]}),
            "no_amplification_oracle")

    def test_scope_schema_rejects_wildcards(self):
        policy = PolicyEngine(_policy_with(_delegation_block()))
        ctx = harness.make_run(policy_path=policy.yaml_path)
        store = _make_store(ctx, policy)
        coder = ctx["identities"]["coder"]
        _assert_refused(
            self, ctx,
            lambda: store.delegate_grant(
                coder, "worker-1", {"tools": ["*"]}),
            "bad_scope")


if __name__ == "__main__":
    unittest.main()
