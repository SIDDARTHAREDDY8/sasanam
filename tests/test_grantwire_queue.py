#!/usr/bin/env python3
"""Wave-320 (grant wiring): unit tests for the presented_grant queue seam.

Covers the approval-queue grant binding at the public seams:
  - queue() stamps presented_grant MAC-bound (explicit None default);
  - a tampered presented_grant breaks approval_digest_ok (F38);
  - the sweep re-verifies the queued grant (expiry, scope);
  - the queue-time check refuses presenter/audience mismatch;
  - absent grant leaves the record with explicit None.
"""

import hashlib
import json
import os
import sys
import unittest
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

from tests.keyfixture import provision_test_key  # noqa: E402

provision_test_key()

from harness import make_run  # noqa: E402
from gov import ed25519  # noqa: E402
from gov import grant_negotiation as gn  # noqa: E402
from gov.approvals import approval_digest_ok  # noqa: E402


def _kp(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    return seed, pub, hashlib.sha256(pub).hexdigest()[:16]


OWNER_SEED, OWNER_PUB, OWNER_KID = _kp("51" * 32)
AGENT_SEED, AGENT_PUB, AGENT_KID = _kp("52" * 32)
PUBKEYS = {OWNER_KID: OWNER_PUB, AGENT_KID: AGENT_PUB}

TOOL = "send_email"
RECIPIENT = "victim@synthetic.local"


def _registry():
    reg = gn.GrantRegistry()
    reg.register_tool(TOOL, owner_key_id=OWNER_KID)
    for kid, pub in PUBKEYS.items():
        reg.register_key(kid, pub)
    return reg


def _grant(audience="agent-7", recipient=RECIPIENT, ttl_seconds=1800):
    now = datetime.now(timezone.utc)
    return gn.issue(TOOL, ["send"], recipient, OWNER_KID, OWNER_SEED,
                    audience, ttl_seconds=ttl_seconds, issued_at=now)


def _run():
    run = make_run()
    run["executor"].set_grant_registry(_registry())
    return run


def _call(run, agent_id, grant, **kw):
    ident = run["executor"].mint_identity(agent_id, "support", agent_id)
    args = dict(to=RECIPIENT, subject="s", body="b")
    args.update(kw)
    if grant is not None:
        args["grant"] = grant
    return run["executor"].call(ident, TOOL, **args)


class GrantWireQueueTest(unittest.TestCase):
    def test_queue_stamps_presented_grant_mac_bound(self):
        run = _run()
        g = _grant()
        res = _call(run, "agent-7", g)
        self.assertEqual(res["status"], "queued")
        rec = run["approvals"].get(res["approval_id"])
        self.assertIsNotNone(rec.get("presented_grant"))
        self.assertEqual(rec["presented_grant"]["identifier"],
                         g["identifier"])
        self.assertEqual(rec["presented_grant"]["signature"],
                         g["signature"])
        # The field is MAC-covered: the digest verifies.
        self.assertTrue(approval_digest_ok(rec))

    def test_queue_defaults_presented_grant_to_none(self):
        run = _run()
        res = _call(run, "agent-7", None)
        self.assertEqual(res["status"], "queued")
        rec = run["approvals"].get(res["approval_id"])
        self.assertIn("presented_grant", rec)
        self.assertIsNone(rec["presented_grant"])
        self.assertTrue(approval_digest_ok(rec))

    def test_tampered_grant_breaks_digest(self):
        run = _run()
        g = _grant()
        res = _call(run, "agent-7", g)
        rec = run["approvals"].get(res["approval_id"])
        # Simulate an in-place tamper of the MAC-bound grant.
        rec["presented_grant"]["resource"] = "tampered@x.test"
        self.assertFalse(approval_digest_ok(rec))

    def test_queue_time_refuses_audience_mismatch(self):
        run = _run()
        g = _grant(audience="agent-7")
        res = _call(run, "agent-9", g)  # Mallory presents Alice's grant
        self.assertEqual(res["status"], "denied")
        self.assertIn("grantneg-audience-mismatch", res["reason"])
        self.assertEqual(res["policy_id"], "grant-advisory")

    def test_queue_time_refuses_expired_grant(self):
        from datetime import timedelta
        run = _run()
        past = datetime.now(timezone.utc) - timedelta(seconds=120)
        g = _grant()
        # Re-issue with a past issued_at so the TTL has lapsed.
        g = gn.issue(TOOL, ["send"], RECIPIENT, OWNER_KID, OWNER_SEED,
                     "agent-7", ttl_seconds=60, issued_at=past)
        res = _call(run, "agent-7", g)
        self.assertEqual(res["status"], "denied")
        self.assertIn("grantneg-expired", res["reason"])

    def test_sweep_refuses_lapsed_grant(self):
        import time
        run = _run()
        g = _grant(ttl_seconds=1)
        res = _call(run, "agent-7", g)
        aid = res["approval_id"]
        run["approvals"].decide(aid, True, "ok",
                                decided_by="human-operator")
        time.sleep(2.5)
        run["executor"].execute_approved()
        rec = run["approvals"].get(aid)
        self.assertFalse(rec["executed"])
        self.assertIn("grantneg-expired",
                      rec["execution_refused_reason"])

    def test_sweep_refuses_scope_broken_by_human_edit(self):
        run = _run()
        g = _grant(recipient=RECIPIENT)
        res = _call(run, "agent-7", g)
        aid = res["approval_id"]
        edited = {"to": "other@synthetic.local",
                  "subject": "s", "body": "b"}
        run["approvals"].decide(aid, True, "ok",
                                decided_by="human-operator",
                                edited_args=edited)
        run["executor"].execute_approved()
        rec = run["approvals"].get(aid)
        self.assertFalse(rec["executed"])
        self.assertIn("grantneg-scope-mismatch",
                      rec["execution_refused_reason"])

    def test_verified_grant_executes_after_approval(self):
        run = _run()
        g = _grant()
        res = _call(run, "agent-7", g)
        aid = res["approval_id"]
        run["approvals"].decide(aid, True, "ok",
                                decided_by="human-operator")
        run["executor"].execute_approved()
        rec = run["approvals"].get(aid)
        self.assertTrue(rec["executed"])

    def test_grant_chain_bound_and_verified(self):
        run = _run()
        root = _grant()
        # Delegate a narrowed child link to the same audience.
        child = gn.derive(root, actions=["send"], audience="agent-7",
                          issuer_key_id=AGENT_KID, issuer_seed=AGENT_SEED,
                          ttl_seconds=900)
        res = _call(run, "agent-7", [root, child])
        self.assertEqual(res["status"], "queued")
        rec = run["approvals"].get(res["approval_id"])
        self.assertIsNotNone(rec.get("presented_grant"))
        self.assertTrue(approval_digest_ok(rec))


if __name__ == "__main__":
    unittest.main(verbosity=2)
