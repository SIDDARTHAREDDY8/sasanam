"""Unit tests: cross-app delegation receipts (Row 18 residual).

gov/delegation_tokens.delegation_receipt / verify_delegation_receipt /
DelegationContext.receipt, plus the "receipt" key on authorize_action's
verdict. Mirrors evals/delegation_receipt_probes.py at the public-seam
unit level. Hermetic: synthetic keys, fixed session, explicit now.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import delegation_tokens as _dt

_NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
_SID = "sess-receipt-ut"
_REVOKE_URI = "https://revoke.example.invalid/deleg"


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, extra_agent_keys=None):
        agent_keys = {"agent-1": self.parent[1]}
        if extra_agent_keys:
            agent_keys.update(extra_agent_keys)
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=agent_keys)


def _trio(keys, user_id="user-7", agent_id="agent-1", session=_SID,
          now=_NOW):
    user_tok = _dt.issue_user_token(
        keys.idp[0], user_id, ("tool:read_file", "tool:send_email"),
        session, now=now)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], agent_id, "scout", user_id,
        ("tool:read_file", "tool:send_email"), session, now=now)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], user_id, user_tok, agent_tok, ("tool:read_file",),
        session, _REVOKE_URI, now=now)
    return user_tok, agent_tok, deleg_tok


def _bound(keys, **kw):
    toks = _trio(keys, **kw)
    ctx = _dt.DelegationContext(
        user_token=toks[0], agent_token=toks[1], delegation_token=toks[2],
        parent_chain=[], trust=keys.trust(),
        session_id=kw.get("session", _SID)).bind(now=_NOW)
    return ctx, toks


def _vargs(keys, toks, **kw):
    args = dict(user_token=toks[0], agent_token=toks[1],
                delegation_token=toks[2], parent_chain=[],
                trust=keys.trust(), session_id=_SID, now=_NOW)
    args.update(kw)
    return args


class ReceiptMintTest(unittest.TestCase):
    def test_sub_act_distinct(self):
        keys = _Keys()
        ctx, _ = _bound(keys)
        r = _dt.delegation_receipt(ctx)
        self.assertEqual(r["receipt_version"], 1)
        self.assertEqual(r["receipt_schema"], "delegation-receipt/v1")
        self.assertEqual(r["sub"], "user-7")
        self.assertEqual(r["act"], "agent-1")
        self.assertNotEqual(r["sub"], r["act"])

    def test_context_receipt_method(self):
        keys = _Keys()
        ctx, _ = _bound(keys)
        self.assertEqual(ctx.receipt()["sub"], "user-7")

    def test_chain_names_human_then_parent(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        child = ctx.spawn("agent-2", ["tool:read_file"], keys.parent[0],
                          now=_NOW)
        r = _dt.delegation_receipt(child)
        self.assertEqual(r["sub"], "user-7")   # originating human, stable
        self.assertEqual(r["act"], "agent-2")  # leaf actor
        chain = r["delegator_chain"]
        self.assertEqual(
            [(h["depth"], h["delegator"], h["subject"]) for h in chain],
            [(0, "user-7", "agent-1"), (1, "agent-1", "agent-2")])

    def test_unbound_cannot_mint(self):
        keys = _Keys()
        toks = _trio(keys)
        unbound = _dt.DelegationContext(
            user_token=toks[0], agent_token=toks[1],
            delegation_token=toks[2], parent_chain=[],
            trust=keys.trust(), session_id=_SID)
        with self.assertRaises(_dt.DelegationRequiredError):
            _dt.delegation_receipt(unbound)

    def test_verdict_carries_receipt(self):
        keys = _Keys()
        ctx, _ = _bound(keys)
        verdict = _dt.authorize_action(ctx, "tool:read_file", now=_NOW)
        self.assertEqual(verdict["receipt"]["sub"], "user-7")
        self.assertEqual(verdict["receipt"]["act"], "agent-1")
        # Pre-existing keys untouched.
        self.assertTrue(all(verdict["allowed_by"].values()))
        self.assertEqual(verdict["session_id"], _SID)

    def test_receipt_json_serializable(self):
        import json
        keys = _Keys()
        ctx, _ = _bound(keys)
        json.dumps(_dt.delegation_receipt(ctx), sort_keys=True)


class ReceiptVerifyTest(unittest.TestCase):
    def test_valid_receipt_verifies(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        r = _dt.delegation_receipt(ctx)
        out = _dt.verify_delegation_receipt(r, **_vargs(keys, toks))
        self.assertEqual(out["sub"], "user-7")

    def test_forged_sub_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        forged = deepcopy(_dt.delegation_receipt(ctx))
        forged["sub"] = "cfo-admin"
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(forged, **_vargs(keys, toks))

    def test_forged_act_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        forged = deepcopy(_dt.delegation_receipt(ctx))
        forged["act"] = "agent-9"
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(forged, **_vargs(keys, toks))

    def test_widened_scope_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        forged = deepcopy(_dt.delegation_receipt(ctx))
        forged["scope"] = ["tool:*"]
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(forged, **_vargs(keys, toks))

    def test_dropped_hop_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        child = ctx.spawn("agent-2", ["tool:read_file"], keys.parent[0],
                          now=_NOW)
        trust = keys.trust(extra_agent_keys={"agent-2": keys.parent[1]})
        r = _dt.delegation_receipt(child)
        forged = deepcopy(r)
        forged["delegator_chain"] = forged["delegator_chain"][:1]
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(
                forged, user_token=toks[0], agent_token=toks[1],
                delegation_token=child.delegation_token,
                parent_chain=[toks[2]], trust=trust, session_id=_SID,
                now=_NOW)

    def test_foreign_session_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        r = _dt.delegation_receipt(ctx)
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(r, **_vargs(keys, toks,
                                                      session_id="other"))

    def test_wrong_roster_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        r = _dt.delegation_receipt(ctx)
        stranger = _Keys()
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(r, **_vargs(keys, toks,
                                                      trust=stranger.trust()))

    def test_bad_schema_refused(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        bad = deepcopy(_dt.delegation_receipt(ctx))
        bad["receipt_schema"] = "delegation-receipt/v9"
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt(bad, **_vargs(keys, toks))

    def test_non_dict_refused(self):
        keys = _Keys()
        _, toks = _bound(keys)
        with self.assertRaises(_dt.DelegationError):
            _dt.verify_delegation_receipt("not-a-receipt",
                                          **_vargs(keys, toks))

    def test_depth2_chain_verifies(self):
        keys = _Keys()
        ctx, toks = _bound(keys)
        child = ctx.spawn("agent-2", ["tool:read_file"], keys.parent[0],
                          now=_NOW)
        trust = keys.trust(extra_agent_keys={"agent-2": keys.parent[1]})
        r = _dt.delegation_receipt(child)
        out = _dt.verify_delegation_receipt(
            r, user_token=toks[0], agent_token=toks[1],
            delegation_token=child.delegation_token,
            parent_chain=[toks[2]], trust=trust, session_id=_SID,
            now=_NOW)
        self.assertEqual(out["act"], "agent-2")
        self.assertEqual(out["sub"], "user-7")


if __name__ == "__main__":
    unittest.main()
