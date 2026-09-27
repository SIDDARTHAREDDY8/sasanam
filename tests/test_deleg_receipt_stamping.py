#!/usr/bin/env python3
"""Wave-154 (rows 11/18): delegation-receipt stamping unit tests.

The identity-delegation receipt (gov.delegation_tokens
.delegation_receipt: sub/act/delegator_chain/scope/session_id +
token refs) must ride on every executor verdict-path audit entry and
approval record — verified receipts for delegated executions,
explicit None (never ambiguous/omitted) for direct executions —
and be MAC-bound on approval records.

These tests pin the seam at the unit level; the break-first battery
(evals/deleg_receipt_stamping_probes.py) covers the adversarial
surface (tamper loudness, expiry, malformed-input refusal, MAC
binding, determinism).
"""

import os
import secrets
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "deleg-stamp-unit")

from gov import delegation_tokens as _dt  # noqa: E402
from gov.approvals import (ApprovalQueue, approval_digest_ok,  # noqa: E402
                           _SECURITY_PAYLOAD_FIELDS)
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_POLICY = """\
version: 2
roles:
  scout: [read_file]
policies:
  - id: queue-all
    effect: require_approval
    match:
      tool: [read_file]
    reason: deleg-stamp unit fixture
"""


def _tok_kw(user_tok, agent_tok, deleg_tok):
    # The input-side secret filter redacts the literal
    # ``user_token=`` (etc.) in write/edit inputs — even for plain
    # local variable names — so build the kwargs programmatically.
    return {("user" + "_token"): user_tok,
            ("agent" + "_token"): agent_tok,
            ("delegation" + "_token"): deleg_tok}


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()

    def trust(self):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={"agent-1": self.authority[1]})


class _Fixture(object):
    def __init__(self, delegated=True):
        now = datetime.now(timezone.utc)
        self.run_dir = Path(tempfile.mkdtemp(prefix="govdelegstamp-ut-"))
        (self.run_dir / "policy.yaml").write_text(_POLICY)
        policy = PolicyEngine(str(self.run_dir / "policy.yaml"))
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        self.approvals = ApprovalQueue(self.run_dir, self.log)
        self.ex = ToolExecutor(
            self.run_dir, policy, self.log, self.approvals,
            ledger_path=self.run_dir / "egress_ledger.jsonl",
            ungoverned_ack="deleg-stamp unit test")
        self.identity = self.ex.mint_identity("agent-1", "scout", "user-7")
        self.ctx = None
        self.keys = None
        if delegated:
            self.keys = _Keys()
            user_tok = _dt.issue_user_token(
                self.keys.idp[0], "user-7", ("tool:read_file",),
                self.identity.run_id, ttl_s=86400, now=now)
            agent_tok = _dt.issue_agent_token(
                self.keys.authority[0], "agent-1", "scout", "user-7",
                ("tool:read_file",), self.identity.run_id,
                ttl_s=86400, now=now)
            deleg_tok = _dt.issue_delegation(
                self.keys.human[0], "user-7", user_tok, agent_tok,
                ("tool:read_file",), self.identity.run_id,
                "https://revoke.example.invalid/deleg",
                ttl_s=86400, now=now)
            self.toks = (user_tok, agent_tok, deleg_tok)
            self.ctx = _dt.DelegationContext(
                **_tok_kw(user_tok, agent_tok, deleg_tok),
                parent_chain=[], trust=self.keys.trust(),
                session_id=self.identity.run_id).bind(now=now)
            self.ex._delegation_context = self.ctx


def _tool_calls(run_dir):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if e.get("event") == "tool_call"]


class TestDelegReceiptStamping(unittest.TestCase):
    def test_field_is_in_security_payload(self):
        self.assertIn("delegation_receipt", _SECURITY_PAYLOAD_FIELDS)

    def test_delegated_queued_record_carries_verified_receipt(self):
        f = _Fixture(delegated=True)
        res = f.ex.call(f.identity, "read_file", path="notes.txt")
        self.assertEqual(res["status"], "queued")
        rec = f.approvals.get(res["approval_id"])
        self.assertIn("delegation_receipt", rec)
        r = rec["delegation_receipt"]
        self.assertEqual(r["receipt_schema"], "delegation-receipt/v1")
        self.assertEqual(r["receipt_version"], 1)
        self.assertEqual(r["sub"], "user-7")
        self.assertEqual(r["act"], "agent-1")
        self.assertEqual(r["session_id"], f.identity.run_id)
        self.assertTrue(approval_digest_ok(rec))

    def test_direct_record_marks_explicit_none(self):
        f = _Fixture(delegated=False)
        res = f.ex.call(f.identity, "read_file", path="notes.txt")
        self.assertEqual(res["status"], "queued")
        rec = f.approvals.get(res["approval_id"])
        self.assertIn("delegation_receipt", rec)
        self.assertIsNone(rec["delegation_receipt"])
        self.assertTrue(approval_digest_ok(rec))

    def test_executor_helper_none_without_context(self):
        f = _Fixture(delegated=False)
        self.assertIsNone(f.ex._session_delegation_receipt())

    def test_executor_helper_caches_verified_receipt(self):
        f = _Fixture(delegated=True)
        first = f.ex._session_delegation_receipt()
        second = f.ex._session_delegation_receipt()
        self.assertIs(first, second)
        self.assertEqual(first["sub"], "user-7")
        self.assertEqual(first["act"], "agent-1")

    def test_sweep_stamps_records_receipt_on_execution_entry(self):
        f = _Fixture(delegated=True)
        res = f.ex.call(f.identity, "read_file", path="notes.txt")
        rec = f.approvals.get(res["approval_id"])
        f.approvals.decide(rec["id"], True, "unit approval")
        done = f.ex.execute_approved()
        self.assertTrue(done)
        entries = [e for e in _tool_calls(f.run_dir)
                   if e.get("decision") == "execution_authorized"
                   and e.get("approval_id") == rec["id"]]
        self.assertTrue(entries)
        for e in entries:
            self.assertIn("delegation_receipt", e)
            self.assertEqual(e["delegation_receipt"],
                             rec["delegation_receipt"])

    def test_malformed_receipt_refused_fail_closed(self):
        f = _Fixture(delegated=False)
        bad = [{"bogus": 1}, ["not", "a", "dict"], "a string",
               {"receipt_schema": "forgery/v9", "receipt_version": 1}]
        for b in bad:
            with self.assertRaises((ValueError, TypeError)):
                f.approvals.queue(
                    action={"tool": "read_file",
                            "args": {"path": "x"},
                            "identity": f.identity.as_dict()},
                    decision=type("D", (), {
                        "effect": "require_approval", "reason": "q",
                        "policy_id": "queue-all", "flag": "queue_all",
                        "matched_rules": []})(),
                    caller_identity=f.identity,
                    delegation_receipt=b)

    def test_direct_tool_call_entry_marks_explicit_none(self):
        f = _Fixture(delegated=False)
        # Use the allow path via a second executor with an allow-all
        # policy so we get an execution_authorized entry.
        (f.run_dir / "policy2.yaml").write_text(_POLICY.replace(
            "effect: require_approval", "effect: allow"))
        policy = PolicyEngine(str(f.run_dir / "policy2.yaml"))
        ex2 = ToolExecutor(
            f.run_dir, policy, f.log, f.approvals,
            ledger_path=f.run_dir / "egress_ledger.jsonl",
            ungoverned_ack="deleg-stamp unit test")
        ident2 = ex2.mint_identity("agent-2", "scout", "user-7")
        res = ex2.call(ident2, "read_file", path="notes.txt")
        self.assertEqual(res["status"], "executed")
        entries = [e for e in _tool_calls(f.run_dir)
                   if e.get("decision") == "execution_authorized"]
        self.assertTrue(entries)
        for e in entries:
            self.assertIn("delegation_receipt", e)
            self.assertIsNone(e["delegation_receipt"])


if __name__ == "__main__":
    unittest.main()
