"""P10 executor wiring (wave-26): DelegationStore on the call path.

These tests exercise gov/executor.py::ToolExecutor.call() — the wiring
the wave-24 store contract (tests/test_delegation_primitive.py) was
built for. Deterministic, synthetic, no network.

What the wiring must prove:
* unscoped on_behalf_of/delegated_by framing is DENIED on the call
  path when policy says ``unscoped_delegation: deny`` (fail-closed);
* the flag default (and the disabled default) keeps today's
  label-only behavior — the P10 incident probe shape is preserved;
* a valid, scoped grant authorizes exactly its scope on the call path
  (read_file vehicles: they exercise the call path without depending
  on egress-policy shape; F94 later fixed the effect probe to use the
  permissive call-shaped context, so arg-dependent denies like the
  domain allowlist no longer refuse the mint — see
  ToolExecutor._delegation_effect_probe)
  (executes, with dual attribution in the audit entry);
* grant refusals (unknown id, scope exceeded, delegatee mismatch)
  deny on the call path with the store's exact reason;
* store ERRORS (not refusals) deny fail-closed, loudly.
"""

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def _deny_policy():
    return PolicyEngine(_policy_with(
        _delegation_block(unscoped_delegation="deny")))


def _flag_policy():
    return PolicyEngine(_policy_with(_delegation_block()))


def _events(ctx, name):
    return [e for e in ctx["read_log"]() if e.get("event") == name]


def _tool_calls(ctx):
    return [e for e in ctx["read_log"]()
            if e.get("event") == "tool_call"]


def _mint_grant(ctx, delegator, delegatee_agent_id, scope, **kw):
    """Mint through the EXECUTOR's own store (the wiring installs the
    identity verifier + policy probes at construction)."""
    store = ctx["executor"]._delegation_store
    return store.delegate_grant(delegator, delegatee_agent_id, scope, **kw)


class DelegationExecutorWiringTest(unittest.TestCase):
    # -- unscoped framing: deny on the call path -----------------------
    def test_unscoped_framing_denied_on_call_path(self):
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        r = ex.call(researcher, "read_file", path="notes.txt",
                    on_behalf_of="boss-agent")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "delegation-unscoped")
        # The tool never executed.
        self.assertEqual(ex._executed.get("read_file", 0), 0)
        # The call-path denial entry carries the policy id + flag.
        denied = [e for e in _tool_calls(ctx)
                  if e.get("decision") == "denied"
                  and e.get("policy_id") == "delegation-unscoped"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["flag"], "unscoped_delegation_denied")
        # Loud: the store's unscoped_delegation_denied event exists.
        refused = _events(ctx, "unscoped_delegation_denied")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["on_behalf_of"], "boss-agent")
        # delegated_by framing is governed the same way.
        r2 = ex.call(researcher, "read_file", path="notes.txt",
                     delegated_by="supervisor-1")
        self.assertEqual(r2["status"], "denied")
        self.assertEqual(r2["policy_id"], "delegation-unscoped")

    # -- label-only behavior preserved where policy does not deny ------
    def test_unscoped_framing_flag_default_still_executes(self):
        # Default policy: delegation disabled -> label-only, as today.
        # This is the P10 incident probe's shape; it must not change.
        ctx = harness.make_run()
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        r = ex.call(researcher, "read_file", path="notes.txt",
                    on_behalf_of="boss-agent")
        self.assertEqual(r["status"], "executed")
        last = _tool_calls(ctx)[-1]
        self.assertTrue(last["delegation_attempted"])
        self.assertIsNone(last["delegation_grant_id"])

    def test_unscoped_framing_flag_enabled_still_executes(self):
        # Enabled + flag: allowed, explicitly the flag mode.
        policy = _flag_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        r = ex.call(researcher, "read_file", path="notes.txt",
                    on_behalf_of="boss-agent")
        self.assertEqual(r["status"], "executed")
        self.assertTrue(_tool_calls(ctx)[-1]["delegation_attempted"])

    def test_plain_call_unaffected_under_deny(self):
        # Deny governs FRAMING claims, not ordinary calls.
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        r = ex.call(researcher, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")

    # -- grant path: scoped authority executes, with dual attribution --
    def test_grant_bearing_call_executes_with_dual_attribution(self):
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        coder = ctx["identities"]["coder"]
        grant = _mint_grant(ctx, researcher, "coder-1",
                            {"tools": ["read_file"]})
        r = ex.call(coder, "read_file", path="notes.txt",
                    on_behalf_of="researcher-1",
                    delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "executed")
        # Dual attribution on the tool_call audit entry (spec §1.4).
        entry = _tool_calls(ctx)[-1]
        self.assertEqual(entry["delegation_grant_id"], grant["grant_id"])
        self.assertEqual(entry["delegator"]["agent_id"], "researcher-1")
        self.assertEqual(entry["delegator"]["principal"], "research-org")
        self.assertEqual(entry["delegation_scope"], ["read_file"])
        # Loud: the store audited the invocation.
        invoked = _events(ctx, "delegation_invoked")
        self.assertEqual(len(invoked), 1)
        self.assertEqual(invoked[0]["grant_id"], grant["grant_id"])

    def test_grant_with_framing_not_treated_as_unscoped(self):
        # Under deny, a VALID grant + framing kwargs must not trip the
        # unscoped path: the grant is the governed way to carry the
        # framing claim.
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        coder = ctx["identities"]["coder"]
        grant = _mint_grant(ctx, researcher, "coder-1",
                            {"tools": ["read_file"]})
        r = ex.call(coder, "read_file", path="notes.txt",
                    on_behalf_of="researcher-1",
                    delegated_by="researcher-1",
                    delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "executed")
        self.assertEqual(_events(ctx, "unscoped_delegation_denied"), [])

    # -- grant refusals deny on the call path --------------------------
    def test_grant_scope_exceeded_denied_on_call_path(self):
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        coder = ctx["identities"]["coder"]
        grant = _mint_grant(ctx, researcher, "coder-1",
                            {"tools": ["read_file"]})
        r = ex.call(coder, "write_file", path="notes.txt",
                    content="x", delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "delegation-grant-refused")
        self.assertEqual(ex._executed.get("write_file", 0), 0)
        refused = _events(ctx, "delegation_invocation_refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["reason"], "scope_exceeded")
        # The call-path entry surfaces the machine-readable reason.
        denied = [e for e in _tool_calls(ctx)
                  if e.get("decision") == "denied"]
        self.assertEqual(denied[-1]["delegation_refusal_reason"],
                         "scope_exceeded")

    def test_grant_unknown_id_denied_on_call_path(self):
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        r = ex.call(coder, "read_file", path="notes.txt",
                    delegation_grant_id="forged-grant-id")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "delegation-grant-refused")
        refused = _events(ctx, "delegation_invocation_refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["reason"], "unknown_grant")

    def test_grant_delegatee_mismatch_denied_on_call_path(self):
        # Stolen grant id: presenting it from a non-matching identity
        # is useless (grants are not bearer tokens).
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        coder = ctx["identities"]["coder"]
        attacker = ctx["mint_identity"]("attacker-1", "researcher",
                                        "research-org")
        grant = _mint_grant(ctx, researcher, "coder-1",
                            {"tools": ["read_file"]})
        r = ex.call(attacker, "read_file", path="notes.txt",
                    delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "delegation-grant-refused")
        refused = _events(ctx, "delegation_invocation_refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["reason"], "delegatee_mismatch")

    # -- fail-closed on store errors -----------------------------------
    def test_fail_closed_on_verify_store_error(self):
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]
        with mock.patch.object(ex._delegation_store, "verify_invocation",
                               side_effect=RuntimeError("disk gone")):
            r = ex.call(coder, "read_file", path="notes.txt",
                        delegation_grant_id="any-grant")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "delegation-store-error")
        self.assertEqual(ex._executed.get("read_file", 0), 0)
        errors = _events(ctx, "delegation_store_error")
        self.assertEqual(len(errors), 1)
        self.assertIn("disk gone", errors[0]["reason"])

    def test_fail_closed_on_framing_store_error(self):
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]
        with mock.patch.object(ex._delegation_store,
                               "check_unscoped_framing",
                               side_effect=OSError("store unreadable")):
            r = ex.call(researcher, "read_file", path="notes.txt",
                        on_behalf_of="boss-agent")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "delegation-store-error")
        self.assertEqual(ex._executed.get("read_file", 0), 0)
        errors = _events(ctx, "delegation_store_error")
        self.assertEqual(len(errors), 1)

    # -- F101: delegation must not launder requester-exclusion --------
    def test_f101_delegator_cannot_decide_delegated_approval(self):
        # F101 (MEDIUM): a grant-verified approval-gated call queues
        # under the ACTING (delegatee) identity. The grant id and the
        # delegating party ride on the approval record (MAC-bound), and
        # decide() excludes the delegator alongside the requester —
        # the delegator, who intended the action, cannot approve it
        # by proxy (D1-core requester-exclusion laundering).
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        approvals = ctx["approvals"]
        delegator = ctx["mint_identity"]("coder-1", "coder",
                                         "research-org")
        delegatee = ctx["mint_identity"]("worker-1", "coder",
                                         "contractor-corp")
        grant = _mint_grant(ctx, delegator, "worker-1",
                            {"tools": ["write_file"]})
        r = ex.call(delegatee, "write_file",
                    path="/tmp/f101-delegated.txt", content="x",
                    delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "queued")
        aid = r["approval_id"]
        # The grant id + delegator are stamped on the approval record.
        rec = approvals.get(aid)
        self.assertEqual(rec["delegation_grant_id"], grant["grant_id"])
        self.assertEqual(rec["delegation_delegator"]["agent_id"],
                         "coder-1")
        self.assertEqual(rec["delegation_delegator"]["principal"],
                         "research-org")
        # Baseline: the delegator's OWN direct call is already refused
        # self-decision (D1-core requester-exclusion).
        r0 = ex.call(delegator, "write_file",
                     path="/tmp/f101-direct.txt", content="x")
        self.assertEqual(r0["status"], "queued")
        with self.assertRaises(ValueError):
            approvals.decide(r0["approval_id"], True, reason="self",
                             decided_by="coder-1")
        # The delegatee (requester of record) still cannot decide.
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="self",
                             decided_by="worker-1")
        # F101: the DELEGATOR cannot decide the delegatee's record —
        # neither by agent_id nor by principal alias.
        with self.assertRaises(ValueError) as vctx:
            approvals.decide(aid, True, reason="looks fine",
                             decided_by="coder-1")
        self.assertIn("delegator", str(vctx.exception))
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="looks fine",
                             decided_by="research-org")
        self.assertEqual(approvals.get(aid)["status"], "pending")
        # The refusal is audited loudly.
        attempts = [e for e in ctx["read_log"]()
                    if e.get("event") == "approval_decision_attempt"
                    and e.get("decision") == "rejected_attempt"]
        self.assertTrue(any("delegation grant" in (e.get("reason") or "")
                            for e in attempts))
        # A non-involved party CAN still decide: the action executes.
        approvals.decide(aid, True, reason="ok",
                         decided_by="human-operator")
        ex.execute_approved()
        self.assertTrue(any(
            e.get("event") == "tool_call"
            and e.get("decision") == "approved_executed"
            and e.get("tool") == "write_file"
            for e in ctx["read_log"]()))

    def test_f101_delegator_cannot_vote_delegated_quorum_approval(self):
        # F101, quorum path: the delegator cannot vote the delegatee's
        # quorum-collecting approval through either (D1-core §10.3
        # requester-exclusion applies at cast_vote() too).
        policy = _deny_policy()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        approvals = ctx["approvals"]
        approvals.set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["research-org", "alice", "bob"]})
        delegator = ctx["mint_identity"]("coder-1", "coder",
                                         "research-org")
        delegatee = ctx["mint_identity"]("worker-1", "coder",
                                         "contractor-corp")
        grant = _mint_grant(ctx, delegator, "worker-1",
                            {"tools": ["write_file"]})
        r = ex.call(delegatee, "write_file", path="/tmp/f101-q.txt",
                    content="x",
                    delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "queued")
        aid = r["approval_id"]
        self.assertEqual(approvals.get(aid)["decision_mode"], "quorum")
        # The delegator is an eligible voter by principal — but the
        # delegation guard excludes them (both aliases).
        with self.assertRaises(ValueError) as vctx:
            approvals.cast_vote(aid, True, "fine", delegator)
        self.assertIn("requester_vote", str(vctx.exception))
        # An eligible non-involved voter can still vote.
        alice = ctx["mint_identity"]("v-alice", "voter", "alice")
        rec, _ = approvals.cast_vote(aid, True, "fine", alice)
        self.assertEqual(rec["status"], "pending")


if __name__ == "__main__":
    unittest.main()
