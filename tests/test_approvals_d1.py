"""D1-core tests: human delegation + quorum-gated multi-party approval.

Phase 1 (core, gov/approvals.py): delegate(), cast_vote(), quorum
snapshots at queue time, bridge-expiry markers, sweep hardenings
(batch/auto-approve/break-glass), reconciliation preservation,
audit_status() visibility, CLI vote/delegate surfaces.

Adversarial coverage per the D1-core spec: requester delegation by
agent_id AND principal alias, loops, self-delegation, hop limits,
field tampering (delegated_to, vote rows, bridge marker), vote replay
and post-finalization replay, direct-decision bypass of quorum,
policy-edit quorum shrink, bridge expiry + late decisions, and
break-glass refusal on quorum records.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.approvals import (
    _normalize_delegation_config,
    _normalize_quorum_config,
    _pending_record_content_ok,
    approval_digest_ok,
)
from gov.identity import AgentIdentity, PrincipalRegistry


def _queue_send_email(run, agent_id="agent-1", principal="agent-1"):
    """Queue one send_email (require_approval under the default policy)."""
    ident = run["executor"].mint_identity(agent_id, "support", principal)
    res = run["executor"].call(
        ident, "send_email", to="victim@synthetic.local",
        subject="hello", body="hello")
    assert res["status"] == "queued", res
    return res["approval_id"]


def _events(run, name):
    path = Path(run["run_dir"]) / "actions.jsonl"
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            if e.get("event") == name:
                out.append(e)
    return out


def _rewrite_approvals(run, fn):
    path = Path(run["run_dir"]) / "approvals.jsonl"
    recs = [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for r in recs:
        fn(r)
    path.write_text(
        "\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")


def _voter(run, principal):
    return run["executor"].mint_identity("v-%s" % principal, "voter",
                                         principal)


QUORUM_2_OF_3 = {"min_approvals": 2,
                 "eligible_principals": ["alice", "bob", "carol"]}


class TestDelegationConfigNormalization(unittest.TestCase):
    """D1-core L1-L3: delegation config fails closed at load."""

    def test_absent_means_disabled(self):
        cfg = _normalize_delegation_config(None)
        self.assertEqual(cfg, {"enabled": False, "max_hops": 1})

    def test_enabled_shape(self):
        cfg = _normalize_delegation_config(
            {"enabled": True, "max_hops": 3})
        self.assertEqual(cfg, {"enabled": True, "max_hops": 3})

    def test_non_dict_refused_l1(self):
        with self.assertRaises(ValueError):
            _normalize_delegation_config(["enabled"])

    def test_non_bool_enabled_refused_l2(self):
        # "yes" must not silently enable delegation (opt-in is bool).
        with self.assertRaises(ValueError):
            _normalize_delegation_config({"enabled": "yes"})
        with self.assertRaises(ValueError):
            _normalize_delegation_config({"enabled": 1})

    def test_max_hops_bounds_l3(self):
        for bad in (0, -1, 6, 99, "2", 2.0, True):
            with self.assertRaises(ValueError, msg="max_hops=%r" % (bad,)):
                _normalize_delegation_config(
                    {"enabled": True, "max_hops": bad})
        # ceiling is 5: chains beyond that launder responsibility.
        self.assertEqual(
            _normalize_delegation_config(
                {"enabled": True, "max_hops": 5})["max_hops"], 5)


class TestQuorumConfigNormalization(unittest.TestCase):
    """D1-core L4-L9: quorum config fails closed at load."""

    def test_absent_means_no_quorum(self):
        self.assertIsNone(_normalize_quorum_config(None))

    def test_valid_shape(self):
        cfg = _normalize_quorum_config(QUORUM_2_OF_3)
        self.assertEqual(cfg["min_approvals"], 2)
        self.assertEqual(cfg["eligible_principals"],
                         ("alice", "bob", "carol"))
        # deny_veto defaults to True and is the only legal value.
        self.assertTrue(cfg["deny_veto"])
        self.assertIsNone(cfg["flags"])

    def test_non_dict_refused_l4(self):
        with self.assertRaises(ValueError):
            _normalize_quorum_config("2-of-3")

    def test_bad_min_approvals_l5(self):
        for bad in (0, -2, "2", 2.0, True, None):
            with self.assertRaises(ValueError,
                                   msg="min_approvals=%r" % (bad,)):
                _normalize_quorum_config(
                    {"min_approvals": bad,
                     "eligible_principals": ["alice", "bob"]})

    def test_bad_eligible_l6(self):
        for bad in ([], [" "], ["alice", ""], "alice", [1, 2], None):
            with self.assertRaises(ValueError,
                                   msg="eligible=%r" % (bad,)):
                _normalize_quorum_config(
                    {"min_approvals": 1, "eligible_principals": bad})
        # duplicates would let one human fill two vote slots.
        with self.assertRaises(ValueError):
            _normalize_quorum_config(
                {"min_approvals": 1,
                 "eligible_principals": ["alice", "alice"]})

    def test_unreachable_quorum_refused_l7(self):
        # min_approvals > len(eligible) is silent starvation — fail the
        # load, never queue records no vote pattern can decide.
        with self.assertRaises(ValueError):
            _normalize_quorum_config(
                {"min_approvals": 3,
                 "eligible_principals": ["alice", "bob"]})

    def test_deny_veto_non_negotiable_l8(self):
        # Explicit false (or any non-True) is a LOAD ERROR — never a
        # silent majority-overrides-dissent.
        for bad in (False, "yes", 0, None):
            with self.assertRaises(ValueError,
                                   msg="deny_veto=%r" % (bad,)):
                _normalize_quorum_config(
                    {"min_approvals": 1,
                     "eligible_principals": ["alice"],
                     "deny_veto": bad})
        cfg = _normalize_quorum_config(
            {"min_approvals": 1, "eligible_principals": ["alice"],
             "deny_veto": True})
        self.assertTrue(cfg["deny_veto"])

    def test_flags_shape_l9(self):
        cfg = _normalize_quorum_config(dict(
            QUORUM_2_OF_3, flags=["cross_run_campaign"]))
        self.assertEqual(cfg["flags"], ("cross_run_campaign",))
        with self.assertRaises(ValueError):
            _normalize_quorum_config(dict(
                QUORUM_2_OF_3, flags="cross_run_campaign"))
        with self.assertRaises(ValueError):
            _normalize_quorum_config(dict(QUORUM_2_OF_3, flags=[" "]))

    def test_setters_reject_invalid_live(self):
        # The queue's install path normalizes too — a bad policy can
        # never be installed, even via direct setter call.
        run = make_run()
        with self.assertRaises(ValueError):
            run["approvals"].set_quorum_config(
                {"min_approvals": 1, "eligible_principals": ["a"],
                 "deny_veto": False})
        with self.assertRaises(ValueError):
            run["approvals"].set_delegation_config({"enabled": "yes"})


class TestDelegation(unittest.TestCase):
    """D1-core T1-T4: delegation of single-decider records."""

    def _delegating_run(self, **cfg):
        run = make_run()
        run["approvals"].set_delegation_config(
            {"enabled": True, **cfg} if cfg else {"enabled": True})
        return run

    def test_happy_path_transfers_decision_power(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        record, entry = run["approvals"].delegate(
            aid, "alice", "alice is on call", "human-operator")
        self.assertEqual(record["delegated_to"], "alice")
        self.assertEqual(len(record["delegation_chain"]), 1)
        hop = record["delegation_chain"][0]
        self.assertEqual((hop["from"], hop["to"]),
                         ("human-operator", "alice"))
        self.assertTrue(_pending_record_content_ok(record),
                        "delegation must re-MAC the mutated record")
        self.assertEqual(entry["event"], "approval_delegated")
        # T3: the original operator can no longer decide it.
        with self.assertRaises(ValueError):
            run["approvals"].decide(aid, True, "i queued this",
                                    decided_by="human-operator")
        # T3: only the assignee may decide — exact principal match.
        with self.assertRaises(ValueError):
            run["approvals"].decide(aid, True, "wrong person",
                                    decided_by="bob")
        record, _ = run["approvals"].decide(
            aid, True, "on-call review", decided_by="alice")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["decided_by"], "alice")

    def test_disabled_delegation_refuses_without_mutation(self):
        run = make_run()  # delegation NOT enabled
        aid = _queue_send_email(run)
        before = run["approvals"].get(aid)
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "alice", "reason",
                                      "human-operator")
        self.assertIn("delegation_disabled", str(ctx.exception))
        after = run["approvals"].get(aid)
        self.assertIsNone(after["delegated_to"])
        self.assertEqual(after["delegation_chain"], [])
        # refusal is audited, and the record is untouched (no hop, no
        # re-MAC — digest still verifies against the original).
        refused = _events(run, "delegation_refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["refusal_code"], "delegation_disabled")
        self.assertTrue(_pending_record_content_ok(after))
        self.assertEqual(before["args_digest"], after["args_digest"])

    def test_requester_excluded_by_agent_id(self):
        run = self._delegating_run()
        aid = _queue_send_email(run, agent_id="agent-1",
                               principal="someone-else")
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "agent-1", "back to requester",
                                      "human-operator")
        self.assertIn("requester_target", str(ctx.exception))
        self.assertEqual(len(_events(run, "delegation_refused")), 1)

    def test_requester_excluded_by_principal_alias(self):
        # The alias shape: agent_id != principal, delegatee matches the
        # principal. Exact match on EITHER field must refuse.
        run = self._delegating_run()
        aid = _queue_send_email(run, agent_id="agent-1",
                               principal="tenant-acme")
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "tenant-acme", "alias route",
                                      "human-operator")
        self.assertIn("requester_target", str(ctx.exception))

    def test_self_delegation_refused(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "human-operator", "self-hop",
                                      "human-operator")
        self.assertIn("self_delegation", str(ctx.exception))

    def test_delegation_loop_refused(self):
        run = self._delegating_run(max_hops=5)
        aid = _queue_send_email(run)
        run["approvals"].delegate(aid, "alice", "hop 1", "human-operator")
        run["approvals"].delegate(aid, "bob", "hop 2", "alice")
        # bob -> alice would close a loop; bob -> human-operator too.
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "alice", "loop", "bob")
        self.assertIn("delegation_loop", str(ctx.exception))
        with self.assertRaises(ValueError):
            run["approvals"].delegate(aid, "human-operator", "loop 2",
                                      "bob")

    def test_max_hops_enforced(self):
        run = self._delegating_run(max_hops=1)
        aid = _queue_send_email(run)
        run["approvals"].delegate(aid, "alice", "hop 1", "human-operator")
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "bob", "hop 2", "alice")
        self.assertIn("max_hops_exceeded", str(ctx.exception))
        # the refused second hop left the chain at exactly one hop.
        record = run["approvals"].get(aid)
        self.assertEqual(len(record["delegation_chain"]), 1)
        self.assertEqual(record["delegated_to"], "alice")

    def test_wrong_delegator_refused(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        # Only the current assignee (human-operator: unassigned default)
        # may delegate — a bystander cannot.
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "alice", "hijack", "mallory")
        self.assertIn("wrong_delegator", str(ctx.exception))
        run["approvals"].delegate(aid, "alice", "legit", "human-operator")
        # After delegation, the OLD assignee lost delegation authority.
        with self.assertRaises(ValueError):
            run["approvals"].delegate(aid, "carol", "stale", "human-operator")
        # The new assignee may re-delegate (within max_hops).
        run2 = self._delegating_run(max_hops=2)
        aid2 = _queue_send_email(run2)
        run2["approvals"].delegate(aid2, "alice", "hop 1", "human-operator")
        rec, _ = run2["approvals"].delegate(aid2, "bob", "hop 2", "alice")
        self.assertEqual(rec["delegated_to"], "bob")

    def test_tampered_record_delegate_refused_no_remac(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        orig_digest = run["approvals"].get(aid)["args_digest"]
        # Attacker rewrites delegated_to directly in the JSONL.
        _rewrite_approvals(
            run, lambda r: r.update({"delegated_to": "mallory"})
            if r["id"] == aid else None)
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "alice", "after tamper",
                                      "human-operator")
        self.assertIn("tamper", str(ctx.exception))
        # The tamper was NOT laundered: digest unchanged (still the
        # pre-tamper MAC over different content → does not verify).
        after = run["approvals"].get(aid)
        self.assertEqual(after["args_digest"], orig_digest)
        self.assertFalse(_pending_record_content_ok(after))
        self.assertEqual(after["delegated_to"], "mallory")  # not re-MACed

    def test_delegate_non_pending_refused(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        run["approvals"].decide(aid, True, "done",
                               decided_by="human-operator")
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "alice", "too late",
                                      "human-operator")
        self.assertIn("not_pending", str(ctx.exception))

    def test_delegate_unknown_id_refused(self):
        run = self._delegating_run()
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate("nope", "alice", "r", "human-operator")
        self.assertIn("not_pending", str(ctx.exception))

    def test_empty_reason_and_target_refused(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        with self.assertRaises(ValueError):
            run["approvals"].delegate(aid, "alice", "   ", "human-operator")
        with self.assertRaises(ValueError):
            run["approvals"].delegate(aid, "", "reason", "human-operator")

    def test_unregistered_delegatee_refused_with_registry(self):
        run = make_run()
        run["approvals"].set_delegation_config({"enabled": True})
        registry = PrincipalRegistry({"alice", "bob", "human-operator"})
        run["approvals"].set_principal_registry(registry)
        aid = _queue_send_email(run)
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "mallory", "outsider",
                                      "human-operator")
        self.assertIn("unregistered_delegatee", str(ctx.exception))
        rec, _ = run["approvals"].delegate(aid, "alice", "insider",
                                           "human-operator")
        self.assertEqual(rec["delegated_to"], "alice")

    def test_no_registry_means_principal_strings_are_terminal(self):
        # Documented localhost-grade limit: without a configured
        # registry, principal strings are the trust root.
        run = self._delegating_run()
        aid = _queue_send_email(run)
        rec, _ = run["approvals"].delegate(aid, "anyone", "dev mode",
                                           "human-operator")
        self.assertEqual(rec["delegated_to"], "anyone")

    def test_audit_status_shows_delegated(self):
        run = self._delegating_run()
        aid = _queue_send_email(run)
        run["approvals"].delegate(aid, "alice", "on call", "human-operator")
        status = run["approvals"].audit_status()
        self.assertIn(aid, status["delegated_ids"])

    def test_decide_requester_sod_unchanged(self):
        # D1-core T4: decide()'s SoD guard is UNCHANGED by D1 — the
        # requester-exclusion invariant (both aliases) lives at
        # queue()/delegate()/cast_vote() time (§10.3), not here. The
        # classic agent_id self-approval refusal still holds.
        run = self._delegating_run()
        aid = _queue_send_email(run, agent_id="agent-1",
                               principal="tenant-acme")
        with self.assertRaises(ValueError):
            run["approvals"].decide(aid, True, "self approve",
                                    decided_by="agent-1")
        # The record is still pending for a real operator.
        record, _ = run["approvals"].decide(
            aid, True, "operator review", decided_by="human-operator")
        self.assertEqual(record["status"], "approved")


class TestQuorum(unittest.TestCase):
    """D1-core T5-T9, T13: quorum-gated multi-party approval."""

    def _quorum_run(self, quorum_cfg=None, agent_id="agent-1",
                    principal="agent-1"):
        run = make_run()
        run["approvals"].set_quorum_config(quorum_cfg or QUORUM_2_OF_3)
        aid = _queue_send_email(run, agent_id=agent_id, principal=principal)
        return run, aid

    def test_queue_opens_quorum_with_mac_snapshot(self):
        run, aid = self._quorum_run()
        record = run["approvals"].get(aid)
        self.assertEqual(record["decision_mode"], "quorum")
        snap = record["quorum"]
        self.assertEqual(snap["min_approvals"], 2)
        self.assertEqual(snap["eligible_principals"],
                         ["alice", "bob", "carol"])
        self.assertTrue(snap["deny_veto"])
        self.assertIn("opened_at", snap)
        self.assertEqual(record["votes"], [])
        self.assertTrue(_pending_record_content_ok(record),
                        "quorum snapshot must be MAC-bound at queue time")
        opened = _events(run, "quorum_opened")
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0]["approval_id"], aid)

    def test_requester_in_eligible_set_refused_at_queue(self):
        # By agent_id...
        run = make_run()
        run["approvals"].set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["agent-1", "bob", "carol"]})
        with self.assertRaises(ValueError) as ctx:
            _queue_send_email(run, agent_id="agent-1", principal="other")
        self.assertIn("eligible", str(ctx.exception))
        self.assertEqual(len(_events(run, "quorum_misconfigured")), 1)
        # ...and by principal alias.
        run = make_run()
        run["approvals"].set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["tenant-acme", "bob", "carol"]})
        with self.assertRaises(ValueError):
            _queue_send_email(run, agent_id="agent-9",
                              principal="tenant-acme")
        self.assertEqual(len(_events(run, "quorum_misconfigured")), 1)

    def test_quorum_flags_selectivity(self):
        run = make_run()
        run["approvals"].set_quorum_config(dict(
            QUORUM_2_OF_3, flags=["cross_run_campaign"]))
        # send_email queues with the default policy's flag, not
        # cross_run_campaign → stays single-decider.
        aid = _queue_send_email(run)
        record = run["approvals"].get(aid)
        self.assertEqual(record["decision_mode"], "single")
        self.assertIsNone(record["quorum"])

    def test_two_approvals_finalize(self):
        run, aid = self._quorum_run()
        rec, e1 = run["approvals"].cast_vote(
            aid, True, "looks fine", _voter(run, "alice"))
        self.assertEqual(rec["status"], "pending")  # 1 of 2: not final
        self.assertEqual(e1["event"], "quorum_vote")
        rec, entry = run["approvals"].cast_vote(
            aid, True, "agree", _voter(run, "bob"))
        self.assertEqual(rec["status"], "approved")
        self.assertEqual(rec["decided_by"], "quorum:2-of-3")
        self.assertIn("alice", rec["decision_reason"])
        self.assertIn("bob", rec["decision_reason"])
        self.assertTrue(approval_digest_ok(rec),
                        "quorum finalize must re-MAC with decided_by bound")
        finalized = _events(run, "quorum_finalized")
        self.assertEqual(len(finalized), 1)
        self.assertEqual(finalized[0]["finalize"], "m_approvals")
        decisions = _events(run, "approval_decision")
        self.assertTrue(any(e["approval_id"] == aid and
                            e["decision"] == "approved"
                            for e in decisions))
        self.assertTrue(approval_digest_ok(run["approvals"].get(aid)))

    def test_deny_veto_is_terminal(self):
        run, aid = self._quorum_run()
        run["approvals"].cast_vote(aid, True, "fine", _voter(run, "alice"))
        rec, entry = run["approvals"].cast_vote(
            aid, False, "too risky", _voter(run, "bob"))
        self.assertEqual(rec["status"], "rejected")
        self.assertEqual(rec["decided_by"], "quorum/veto:bob")
        self.assertTrue(approval_digest_ok(rec))
        finalized = _events(run, "quorum_finalized")
        self.assertEqual(finalized[0]["finalize"], "deny_veto")
        # Post-finalization: no more votes — the gate is closed.
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "late", _voter(run, "carol"))
        self.assertIn("already_finalized", str(ctx.exception))

    def test_duplicate_vote_refused(self):
        run, aid = self._quorum_run()
        run["approvals"].cast_vote(aid, True, "first", _voter(run, "alice"))
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "replay", _voter(run, "alice"))
        self.assertIn("duplicate_vote", str(ctx.exception))
        # The replay did not append a second vote row.
        record = run["approvals"].get(aid)
        self.assertEqual(len(record["votes"]), 1)

    def test_non_eligible_voter_refused(self):
        run, aid = self._quorum_run()
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "outsider",
                                       _voter(run, "mallory"))
        self.assertIn("not_eligible", str(ctx.exception))

    def test_requester_can_never_vote(self):
        # Defense in depth behind the queue-time check: a record whose
        # eligible set somehow contains the requester still refuses the
        # requester's vote (checked on both voter_principal and
        # agent_id against both record fields).
        run = make_run()
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run, agent_id="agent-1", principal="agent-1")
        # Hand-corrupt the snapshot to include the requester (simulates
        # a record queued before the T5 check existed), re-MAC via the
        # test-only path is impossible — instead verify the vote-time
        # check fires even when eligibility would pass: use a voter
        # whose principal IS in the eligible set but whose agent_id is
        # the requester's.
        evil = run["executor"].mint_identity("agent-1", "voter", "alice")
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "self-approve", evil)
        self.assertIn("requester_vote", str(ctx.exception))

    def test_bare_string_voter_rejected(self):
        run, aid = self._quorum_run()
        with self.assertRaises(TypeError):
            run["approvals"].cast_vote(aid, True, "reason", "alice")

    def test_vote_on_non_quorum_record_refused(self):
        run = make_run()  # no quorum config → single-decider
        aid = _queue_send_email(run)
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "r", _voter(run, "alice"))
        self.assertIn("not_quorum", str(ctx.exception))

    def test_decide_cannot_bypass_quorum(self):
        run, aid = self._quorum_run()
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].decide(aid, True, "bypass",
                                    decided_by="human-operator")
        self.assertIn("quorum_direct_decide", str(ctx.exception))
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "pending")
        refused = _events(run, "decision_refused")
        self.assertTrue(any("quorum_direct_decide" in e["reason"]
                            for e in refused))

    def test_tampered_vote_row_refuses_next_vote(self):
        run, aid = self._quorum_run()
        run["approvals"].cast_vote(aid, True, "fine", _voter(run, "alice"))
        # Attacker flips the recorded approve flag in the JSONL.
        _rewrite_approvals(
            run, lambda r: r["votes"][0].update({"approve": False})
            if r["id"] == aid else None)
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "second",
                                       _voter(run, "bob"))
        self.assertIn("tamper", str(ctx.exception))
        # And the forged deny can never reach finalize/execution: the
        # record no longer verifies at all.
        self.assertFalse(
            _pending_record_content_ok(run["approvals"].get(aid)))

    def test_policy_edit_cannot_shrink_live_quorum(self):
        # The snapshot is the authority, never the live policy: after
        # queueing 2-of-3, "tightening" the config to 1-of-1 for mallory
        # changes nothing for the live record.
        run, aid = self._quorum_run()
        run["approvals"].set_quorum_config(
            {"min_approvals": 1, "eligible_principals": ["mallory"]})
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "pwn", _voter(run, "mallory"))
        self.assertIn("not_eligible", str(ctx.exception))
        run["approvals"].cast_vote(aid, True, "one", _voter(run, "alice"))
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "pending")  # still needs 2
        run["approvals"].cast_vote(aid, True, "two", _voter(run, "bob"))
        self.assertEqual(run["approvals"].get(aid)["status"], "approved")

    def test_break_glass_refused_on_quorum_ticket_not_consumed(self):
        run = make_run(break_glass_tickets=[("BG-1", "human-operator",
                                             "reviewer-1")])
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        operator = run["executor"].mint_identity("cli", "operator",
                                                 "human-operator")
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].break_glass(aid, "emergency", operator,
                                         ticket_id="BG-1")
        self.assertIn("quorum", str(ctx.exception))
        refused = _events(run, "break_glass_refused")
        self.assertEqual(len(refused), 1)
        # The single-use ticket was NOT consumed by the refused attempt.
        ticket = run["approvals"]._resolve_break_glass_ticket("BG-1")
        self.assertIsNotNone(ticket)

    def test_batch_decide_excludes_quorum(self):
        run, aid = self._quorum_run()
        decided, excluded, _entry = run["approvals"].batch_decide(
            [aid], True, "batch it", decided_by="human-operator")
        self.assertEqual(decided, [])
        self.assertEqual(len(excluded), 1)
        self.assertIn("quorum", excluded[0]["batch_exclusion_reason"])
        self.assertEqual(run["approvals"].get(aid)["status"], "pending")

    def test_batch_decide_delegated_exact_match(self):
        run = make_run()
        run["approvals"].set_delegation_config({"enabled": True})
        aid = _queue_send_email(run)
        run["approvals"].delegate(aid, "alice", "on call", "human-operator")
        # Batch by a non-assignee excludes the delegated record…
        decided, excluded, _e = run["approvals"].batch_decide(
            [aid], True, "batch", decided_by="human-operator")
        self.assertEqual(decided, [])
        self.assertEqual(len(excluded), 1)
        self.assertIn("delegated", excluded[0]["batch_exclusion_reason"])
        # …but a batch BY the assignee (exact match) may decide it.
        decided, excluded, _e = run["approvals"].batch_decide(
            [aid], True, "batch", decided_by="alice")
        self.assertEqual([r["id"] for r in decided], [aid])
        self.assertEqual(excluded, [])

    def test_auto_approve_skips_quorum_and_delegated(self):
        run, aid = self._quorum_run()
        self.assertIsNone(run["approvals"].maybe_auto_approve(
            aid, {"enabled": True, "max_risk_score": 100}))
        run2 = make_run()
        run2["approvals"].set_delegation_config({"enabled": True})
        aid2 = _queue_send_email(run2)
        run2["approvals"].delegate(aid2, "alice", "on call",
                                   "human-operator")
        self.assertIsNone(run2["approvals"].maybe_auto_approve(
            aid2, {"enabled": True, "max_risk_score": 100}))
        for r, a in ((run, aid), (run2, aid2)):
            self.assertEqual(r["approvals"].get(a)["status"], "pending")

    def test_vote_slot_delegation(self):
        # T13: delegating on a quorum record transfers a VOTE SLOT —
        # the delegatee takes the delegator's place in the snapshot; M
        # is unchanged.
        run = make_run()
        run["approvals"].set_delegation_config({"enabled": True})
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        rec, entry = run["approvals"].delegate(
            aid, "dave", "alice is out", "alice")
        self.assertEqual(entry["transfer"], "vote_slot")
        snap = rec["quorum"]["eligible_principals"]
        self.assertNotIn("alice", snap)
        self.assertIn("dave", snap)
        self.assertEqual(rec["quorum"]["min_approvals"], 2)
        self.assertTrue(_pending_record_content_ok(rec))
        # The delegator lost the slot: their vote is now not_eligible.
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].cast_vote(aid, True, "late", _voter(run, "alice"))
        self.assertIn("not_eligible", str(ctx.exception))
        # The delegatee's vote counts toward the UNCHANGED M.
        run["approvals"].cast_vote(aid, True, "for alice", _voter(run, "dave"))
        rec, _ = run["approvals"].cast_vote(aid, True, "ok", _voter(run, "bob"))
        self.assertEqual(rec["status"], "approved")
        self.assertEqual(rec["decided_by"], "quorum:2-of-3")

    def test_vote_slot_delegation_guards(self):
        run = make_run()
        run["approvals"].set_delegation_config({"enabled": True})
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        # Non-slot-holder cannot delegate a slot.
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "dave", "r", "mallory")
        self.assertIn("wrong_delegator", str(ctx.exception))
        # A voter who already voted cannot delegate the slot away —
        # the vote stands.
        run["approvals"].cast_vote(aid, True, "voted", _voter(run, "alice"))
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "dave", "after vote", "alice")
        self.assertIn("vote_already_cast", str(ctx.exception))
        # Requester exclusion applies to vote slots too.
        with self.assertRaises(ValueError) as ctx:
            run["approvals"].delegate(aid, "agent-1", "back", "bob")
        self.assertIn("requester_target", str(ctx.exception))

    def test_audit_status_shows_quorum_tally(self):
        run, aid = self._quorum_run()
        run["approvals"].cast_vote(aid, True, "one", _voter(run, "alice"))
        status = run["approvals"].audit_status()
        self.assertEqual(len(status["quorum_collecting"]), 1)
        qc = status["quorum_collecting"][0]
        self.assertEqual(qc["id"], aid)
        self.assertEqual(qc["approvals_cast"], 1)
        self.assertEqual(qc["min_approvals"], 2)


class TestBridgeExpiry(unittest.TestCase):
    """D1-core T10-T12: bounded bridge waits and audit-only late
    decisions."""

    def test_mark_bridge_expired_sets_mac_marker(self):
        run = make_run()
        aid = _queue_send_email(run)
        record, entry = run["approvals"].mark_bridge_expired(
            aid, "bridge-7", "callback never arrived within 300s")
        self.assertTrue(record["bridge_expired"])
        self.assertIsNotNone(record["bridge_expired_at"])
        self.assertTrue(_pending_record_content_ok(record),
                        "bridge marker must be MAC-bound")
        self.assertEqual(entry["event"], "bridge_wait_expired")
        # The record is still pending — the marker is not a decision.
        self.assertEqual(record["status"], "pending")

    def test_late_decision_is_audit_only(self):
        run = make_run()
        aid = _queue_send_email(run)
        run["approvals"].mark_bridge_expired(aid, "bridge-7", "timed out")
        record, _entry = run["approvals"].decide(
            aid, True, "human still wants it", decided_by="human-operator")
        self.assertTrue(record["late_decision"])
        late = _events(run, "approval_late_decision")
        self.assertEqual(len(late), 1)
        self.assertEqual(late[0]["approval_id"], aid)
        # The late decision is recorded AND digested (forensics intact)…
        self.assertEqual(record["status"], "approved")
        self.assertTrue(approval_digest_ok(record))
        # …but the sweep must refuse it: bridge_expired keys the T12
        # refusal, not late_decision (flipping late_decision in the
        # JSONL changes nothing executable).
        self.assertTrue(record["bridge_expired"])
        status = run["approvals"].audit_status()
        self.assertIn(aid, status["late_decision_ids"])

    def test_bridge_marker_is_mac_bound(self):
        run = make_run()
        aid = _queue_send_email(run)
        run["approvals"].mark_bridge_expired(aid, "bridge-7", "timed out")
        # Attacker clears the marker directly in the JSONL to resurrect
        # the timed-out approval.
        _rewrite_approvals(
            run, lambda r: r.update({"bridge_expired": False,
                                     "bridge_expired_at": None})
            if r["id"] == aid else None)
        self.assertFalse(
            _pending_record_content_ok(run["approvals"].get(aid)),
            "clearing bridge_expired must break the digest — the marker "
            "is MAC-bound, so the forgery cannot verify")

    def test_mark_bridge_expired_refuses_tampered_record(self):
        run = make_run()
        aid = _queue_send_email(run)
        _rewrite_approvals(
            run, lambda r: r.update({"tool": "evil_tool"})
            if r["id"] == aid else None)
        with self.assertRaises(ValueError):
            run["approvals"].mark_bridge_expired(aid, "bridge-7", "x")
        refused = _events(run, "bridge_expired_refused")
        self.assertEqual(len(refused), 1)
        self.assertFalse(run["approvals"].get(aid)["bridge_expired"])

    def test_mark_bridge_expired_after_execution_is_anomaly(self):
        run = make_run()
        aid = _queue_send_email(run)
        run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
        run["executor"].execute_approved()
        self.assertTrue(run["approvals"].get(aid)["executed"])
        # The TOCTOU already resolved the other way: audit an anomaly,
        # change nothing.
        record = run["approvals"].mark_bridge_expired(
            aid, "bridge-7", "late expiry report")
        self.assertFalse(record["bridge_expired"])
        anomalies = _events(run, "bridge_expired_after_execution")
        self.assertEqual(len(anomalies), 1)

    def test_mark_bridge_expired_unknown_id(self):
        run = make_run()
        with self.assertRaises(ValueError):
            run["approvals"].mark_bridge_expired("nope", "b", "r")


class TestD1Reconciliation(unittest.TestCase):
    """Interrupted-execution reconciliation preserves D1 state: votes
    and the delegation chain stay intact (MACed), the current
    assignment resets with the decision, and bridge_expired survives
    (a world-fact, not decision state)."""

    def _interrupt(self, run, aid):
        # Simulate a crash between claim and completion: a valid,
        # chained tool_call entry with decision=execution_authorized
        # and no approved_executed. (The scan keys on event=tool_call.)
        run["log"].append({
            "event": "tool_call",
            "decision": "execution_authorized",
            "approval_id": aid,
            "run_id": run["approvals"].run_id,
        })
        return run["approvals"]._reconcile_interrupted_executions()

    def test_delegated_record_reconcile(self):
        run = make_run()
        run["approvals"].set_delegation_config({"enabled": True})
        aid = _queue_send_email(run)
        run["approvals"].delegate(aid, "alice", "on call", "human-operator")
        run["approvals"].decide(aid, True, "ok", decided_by="alice")
        reconciled = self._interrupt(run, aid)
        self.assertEqual(reconciled, [aid])
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "pending")
        self.assertFalse(record["executed"])
        # The current assignment resets with the voided decision…
        self.assertIsNone(record["delegated_to"])
        # …but the forensic chain stays intact and re-MACed.
        self.assertEqual(len(record["delegation_chain"]), 1)
        self.assertTrue(_pending_record_content_ok(record))

    def test_quorum_record_reconcile_keeps_votes(self):
        run, aid = self._quorum_approved_run()
        reconciled = self._interrupt(run, aid)
        self.assertEqual(reconciled, [aid])
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["decision_mode"], "quorum")
        # Residual votes and the snapshot stay intact (MACed) — the
        # quorum's already-cast decision is not erased by the crash.
        self.assertEqual(len(record["votes"]), 2)
        self.assertEqual(record["quorum"]["min_approvals"], 2)
        self.assertTrue(_pending_record_content_ok(record))

    def _quorum_approved_run(self):
        run = make_run()
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        run["approvals"].cast_vote(aid, True, "one", _voter(run, "alice"))
        run["approvals"].cast_vote(aid, True, "two", _voter(run, "bob"))
        self.assertEqual(run["approvals"].get(aid)["status"], "approved")
        return run, aid

    def test_bridge_expired_survives_reconcile(self):
        run = make_run()
        aid = _queue_send_email(run)
        run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
        run["approvals"].mark_bridge_expired(aid, "bridge-7", "timed out")
        reconciled = self._interrupt(run, aid)
        self.assertEqual(reconciled, [aid])
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "pending")
        # The expiry is a world-fact: it survives the reset, so any
        # re-decision is still late/audit-only and still unexecutable.
        self.assertTrue(record["bridge_expired"])
        self.assertFalse(record["late_decision"])  # voided with the decision
        self.assertTrue(_pending_record_content_ok(record))


class TestD1CLI(unittest.TestCase):
    """CLI surfaces for delegate/vote."""

    def _run_cli(self, run, *argv):
        from gov.approvals import main as cli_main
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["--rundir", str(run["run_dir"])] + list(argv))
        return code, buf.getvalue()

    def test_cli_vote_round_trip(self):
        run = make_run()
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        code, out = self._run_cli(run, "vote", aid, "approve",
                                  "--reason", "cli ok", "--by", "alice")
        self.assertEqual(code, 0)
        self.assertIn("vote recorded", out)
        code, out = self._run_cli(run, "vote", aid, "approve",
                                  "--reason", "cli ok 2", "--by", "bob")
        self.assertEqual(code, 0)
        self.assertIn("FINALIZED", out)
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "approved")
        self.assertEqual(record["decided_by"], "quorum:2-of-3")

    def test_cli_vote_denied_veto(self):
        run = make_run()
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        code, _out = self._run_cli(run, "vote", aid, "deny",
                                   "--reason", "too risky", "--by", "alice")
        self.assertEqual(code, 0)
        record = run["approvals"].get(aid)
        self.assertEqual(record["status"], "rejected")
        self.assertEqual(record["decided_by"], "quorum/veto:alice")

    def test_cli_vote_replay_refused(self):
        run = make_run()
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid = _queue_send_email(run)
        self._run_cli(run, "vote", aid, "approve",
                      "--reason", "one", "--by", "alice")
        code, _out = self._run_cli(run, "vote", aid, "approve",
                                   "--reason", "replay", "--by", "alice")
        self.assertEqual(code, 1)  # duplicate_vote → error, not a vote

    def test_cli_list_shows_substates(self):
        run = make_run()
        run["approvals"].set_delegation_config({"enabled": True})
        aid_d = _queue_send_email(run)
        run["approvals"].delegate(aid_d, "alice", "on call",
                                  "human-operator")
        # Quorum config installed AFTER the single-decider record was
        # queued — the snapshot only covers records queued under it.
        run["approvals"].set_quorum_config(QUORUM_2_OF_3)
        aid_q = _queue_send_email(run)
        run["approvals"].cast_vote(aid_q, True, "one", _voter(run, "alice"))
        code, out = self._run_cli(run, "list")
        self.assertEqual(code, 0)
        self.assertIn("DELEGATED to alice", out)
        self.assertIn("QUORUM COLLECTING: 1-of-2", out)


if __name__ == "__main__":
    unittest.main()
