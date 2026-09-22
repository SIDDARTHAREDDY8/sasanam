"""F103 closure tests (wave-27): the F101 delegator exclusion must cover the
FULL delegator lineage when delegation depth >= 2.

Reproduction (F103, MEDIUM, OPEN pre-fix): with
``delegation: enabled, max_depth=2, unscoped_delegation: deny`` —
(1) ``coder-1`` (principal ``research-org``) mints grant G1 for
``worker-1``; (2) ``worker-1`` (principal ``contractor-corp``) mints
sub-grant G2 (``parent_grant_id=G1``) for ``worker-2``; (3)
``worker-2``'s grant-verified ``write_file`` queues under ``worker-2``
with the approval record stamping only the IMMEDIATE delegator
(``delegation_delegator=worker-1``). Pre-fix,
``approvals.decide(aid, True, decided_by="coder-1")`` — the ANCESTOR
(root) delegator — and ``decided_by="research-org"`` (its principal
alias) both ALLOWED, and the quorum ``cast_vote()`` path ALLOWED too;
the action executes. Post-fix the whole intending lineage is stamped
(``delegation_delegator_chain``, MAC-bound, F101 pattern) and
``decide()``/``cast_vote()`` exclude every ancestor by agent_id AND
principal alias.

Deterministic, synthetic, no network. Venv python only.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov.policy import PolicyEngine
from gov.approvals import _pending_record_content_ok

from tests import harness

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_TEXT = (REPO_ROOT / "policies" / "default.yaml").read_text()

_DELEGATION_BLOCK_RE = re.compile(
    r"\ndelegation:\n(?:  [^\n]*\n)+")


def _policy_with(delegation_block):
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
           "require_provisioned_for": [], "unscoped_delegation": "deny"}
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


def _deny_policy_depth2():
    return PolicyEngine(_policy_with(_delegation_block(max_depth=2)))


def _deny_policy_depth1():
    return PolicyEngine(_policy_with(_delegation_block(max_depth=1)))


def _mint_grant(ctx, delegator, delegatee_agent_id, scope, **kw):
    store = ctx["executor"]._delegation_store
    return store.delegate_grant(delegator, delegatee_agent_id, scope, **kw)


def _rewrite_approvals(ctx, fn):
    path = Path(ctx["run_dir"]) / "approvals.jsonl"
    recs = [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for r in recs:
        fn(r)
    path.write_text(
        "\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")


def _chain_identities(ctx):
    """Mint the three-link identity chain: coder-1 (root) -> worker-1 ->
    worker-2, plus a non-involved voter."""
    coder = ctx["mint_identity"]("coder-1", "coder", "research-org")
    worker1 = ctx["mint_identity"]("worker-1", "coder", "contractor-corp")
    worker2 = ctx["mint_identity"]("worker-2", "coder", "contractor-corp")
    return coder, worker1, worker2


def _mint_chain(ctx, coder, worker1):
    """G1 (coder-1 -> worker-1), then sub-grant G2 (worker-1 -> worker-2)."""
    g1 = _mint_grant(ctx, coder, "worker-1", {"tools": ["write_file"]})
    g2 = _mint_grant(ctx, worker1, "worker-2", {"tools": ["write_file"]},
                     parent_grant_id=g1["grant_id"])
    return g1, g2


def _queue_leaf_call(ctx, worker2, g2, path):
    ex = ctx["executor"]
    r = ex.call(worker2, "write_file", path=path, content="x",
                delegation_grant_id=g2["grant_id"])
    assert r["status"] == "queued", r
    return r["approval_id"]


class F103ChainDelegationExclusionTest(unittest.TestCase):
    # -- the full lineage is stamped on the approval record ------------
    def test_f103_delegator_chain_stamped_root_to_immediate(self):
        # The approval record must carry the FULL delegator lineage
        # (root -> immediate), each {agent_id, role, principal}, so
        # decide()/cast_vote() can exclude every intending party.
        policy = _deny_policy_depth2()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        coder, worker1, worker2 = _chain_identities(ctx)
        g1, g2 = _mint_chain(ctx, coder, worker1)
        aid = _queue_leaf_call(ctx, worker2, g2, "/tmp/f103-chain.txt")
        rec = ctx["approvals"].get(aid)
        self.assertEqual(rec["delegation_grant_id"], g2["grant_id"])
        # F101 field still stamps the immediate delegator.
        self.assertEqual(rec["delegation_delegator"]["agent_id"], "worker-1")
        self.assertEqual(rec["delegation_delegator"]["principal"],
                         "contractor-corp")
        # F103: the whole lineage, root first.
        chain = rec["delegation_delegator_chain"]
        self.assertEqual([h["agent_id"] for h in chain],
                         ["coder-1", "worker-1"])
        self.assertEqual([h["principal"] for h in chain],
                         ["research-org", "contractor-corp"])
        for hop in chain:
            self.assertEqual(set(hop),
                             {"agent_id", "role", "principal"})
        # The chain is MAC-bound: the pending record verifies now.
        self.assertTrue(_pending_record_content_ok(rec))

    # -- ancestor cannot decide the depth-2 approval -------------------
    def test_f103_ancestor_cannot_decide_depth2_approval(self):
        # The exact F103 repro: coder-1 (root delegator) decides the
        # leaf's approval. Pre-fix this ALLOWED and the action executed.
        policy = _deny_policy_depth2()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        coder, worker1, worker2 = _chain_identities(ctx)
        g1, g2 = _mint_chain(ctx, coder, worker1)
        aid = _queue_leaf_call(ctx, worker2, g2, "/tmp/f103-decide.txt")
        approvals = ctx["approvals"]
        # ANCESTOR (root) delegator: refused by agent_id...
        with self.assertRaises(ValueError) as vctx:
            approvals.decide(aid, True, reason="looks fine",
                             decided_by="coder-1")
        self.assertIn("delegator", str(vctx.exception).lower())
        # ...and by principal alias.
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="looks fine",
                             decided_by="research-org")
        # Immediate delegator still refused (F101 preserved), both aliases.
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="looks fine",
                             decided_by="worker-1")
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="looks fine",
                             decided_by="contractor-corp")
        # The requester of record (worker-2) still refused.
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="self",
                             decided_by="worker-2")
        self.assertEqual(approvals.get(aid)["status"], "pending")
        # Refusals are audited loudly.
        attempts = [e for e in ctx["read_log"]()
                    if e.get("event") == "approval_decision_attempt"
                    and e.get("decision") == "rejected_attempt"]
        self.assertTrue(any("delegation grant" in (e.get("reason") or "")
                            for e in attempts))
        # A non-involved party CAN still decide: the action executes.
        approvals.decide(aid, True, reason="ok",
                         decided_by="human-operator")
        ctx["executor"].execute_approved()
        self.assertTrue(any(
            e.get("event") == "tool_call"
            and e.get("decision") == "approved_executed"
            and e.get("tool") == "write_file"
            for e in ctx["read_log"]()))

    # -- ancestor cannot vote the depth-2 quorum approval --------------
    def test_f103_ancestor_cannot_vote_depth2_quorum_approval(self):
        # Quorum path (D1-core §10.3): the ancestor must be excluded
        # from voting too, by agent_id AND principal alias.
        policy = _deny_policy_depth2()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        approvals = ctx["approvals"]
        approvals.set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["research-org", "alice", "bob"]})
        coder, worker1, worker2 = _chain_identities(ctx)
        g1, g2 = _mint_chain(ctx, coder, worker1)
        aid = _queue_leaf_call(ctx, worker2, g2, "/tmp/f103-vote.txt")
        self.assertEqual(approvals.get(aid)["decision_mode"], "quorum")
        # The ancestor is an eligible voter by principal — but the
        # lineage guard excludes it (agent_id form of the identity).
        with self.assertRaises(ValueError) as vctx:
            approvals.cast_vote(aid, True, "fine", coder)
        self.assertIn("requester_vote", str(vctx.exception))
        # Principal-alias form: a different agent_id voting under the
        # ancestor's principal is excluded as well.
        alias_voter = ctx["mint_identity"]("v-eve", "voter", "research-org")
        with self.assertRaises(ValueError):
            approvals.cast_vote(aid, True, "fine", alias_voter)
        # The immediate delegator is still excluded (F101 preserved).
        with self.assertRaises(ValueError):
            approvals.cast_vote(aid, True, "fine", worker1)
        # An eligible non-involved voter can still vote.
        alice = ctx["mint_identity"]("v-alice", "voter", "alice")
        rec, _ = approvals.cast_vote(aid, True, "fine", alice)
        self.assertEqual(rec["status"], "pending")

    # -- the stamped lineage is integrity-bound (fail-closed) ----------
    def test_f103_chain_tamper_breaks_digest(self):
        # Rewriting or dropping the stamped lineage breaks the pending
        # record's MAC: decide() refuses, never re-MACs (F38 pattern).
        policy = _deny_policy_depth2()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        coder, worker1, worker2 = _chain_identities(ctx)
        g1, g2 = _mint_chain(ctx, coder, worker1)
        aid = _queue_leaf_call(ctx, worker2, g2, "/tmp/f103-tamper.txt")
        # Attacker strips the ancestor hop from the JSONL.
        _rewrite_approvals(
            ctx, lambda r: r.update({"delegation_delegator_chain":
                                     [r["delegation_delegator_chain"][-1]]})
            if r["id"] == aid else None)
        after = ctx["approvals"].get(aid)
        self.assertFalse(_pending_record_content_ok(after))
        with self.assertRaises(ValueError) as vctx:
            ctx["approvals"].decide(aid, True, reason="ok",
                                    decided_by="human-operator")
        self.assertIn("integrity", str(vctx.exception).lower())

    # -- depth-1 behavior unchanged ------------------------------------
    def test_f103_depth1_behavior_unchanged(self):
        # At max_depth=1 the lineage is just the immediate delegator —
        # the F101 contract holds exactly as before.
        policy = _deny_policy_depth1()
        ctx = harness.make_run(policy_path=policy.yaml_path)
        ex = ctx["executor"]
        approvals = ctx["approvals"]
        delegator = ctx["mint_identity"]("coder-1", "coder", "research-org")
        delegatee = ctx["mint_identity"]("worker-1", "coder",
                                         "contractor-corp")
        grant = _mint_grant(ctx, delegator, "worker-1",
                            {"tools": ["write_file"]})
        r = ex.call(delegatee, "write_file", path="/tmp/f103-d1.txt",
                    content="x", delegation_grant_id=grant["grant_id"])
        self.assertEqual(r["status"], "queued")
        aid = r["approval_id"]
        rec = approvals.get(aid)
        self.assertEqual([h["agent_id"] for h in
                          rec["delegation_delegator_chain"]], ["coder-1"])
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="x", decided_by="coder-1")
        with self.assertRaises(ValueError):
            approvals.decide(aid, True, reason="x",
                             decided_by="research-org")
        # Third party still decides and the action executes.
        approvals.decide(aid, True, reason="ok", decided_by="human-operator")
        ex.execute_approved()
        self.assertTrue(any(
            e.get("event") == "tool_call"
            and e.get("decision") == "approved_executed"
            for e in ctx["read_log"]()))


if __name__ == "__main__":
    unittest.main()
