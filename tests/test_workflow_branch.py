"""Tests for gov/workflow_branch.py: Seata-style branch registration,
XID propagation, coordinator-driven commit/rollback, and
lease-across-suspension.

Red-first: these tests were written before the module existed.
"""

import os
import unittest

from gov import ed25519
from gov import workflow_branch as wb


def _seed():
    return ed25519.generate_seed()


class XIDPropagationTests(unittest.TestCase):
    def test_begin_mints_xid(self):
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        self.assertEqual(len(xid), 64)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in xid))

    def test_step_records_matching_xid_ok(self):
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        c.register_branch(xid, "b1", "worker-1")
        c.record_step(xid, "b1", {"op": "write", "xid": xid})
        self.assertEqual(c.branch_state(xid, "b1")["steps"], 1)

    def test_step_without_expected_xid_refuses(self):
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        other = c.begin(_seed())
        c.register_branch(xid, "b1", "worker-1")
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.record_step(xid, "b1", {"op": "write", "xid": other})
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_step_missing_xid_refuses(self):
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        c.register_branch(xid, "b1", "worker-1")
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.record_step(xid, "b1", {"op": "write"})
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_unknown_xid_refuses(self):
        c = wb.BranchCoordinator()
        with self.assertRaises(wb.WorkflowBranchError):
            c.register_branch("f" * 64, "b1", "worker-1")


class BranchRegistrationTests(unittest.TestCase):
    def test_unregistered_branch_commit_refuses(self):
        c = wb.BranchCoordinator()
        seed = _seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "commit")
        pkg = c.decide(xid, "commit", seed)
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.apply_decision(xid, "ghost", pkg)
        self.assertEqual(ctx.exception.code, "workflow-branch-unregistered")

    def test_duplicate_branch_registration_refuses(self):
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        c.register_branch(xid, "b1", "worker-1")
        with self.assertRaises(wb.WorkflowBranchError):
            c.register_branch(xid, "b1", "worker-2")


class CoordinatorDecisionTests(unittest.TestCase):
    def test_commit_happy_path(self):
        c = wb.BranchCoordinator()
        seed = _seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.register_branch(xid, "b2", "worker-2")
        c.vote(xid, "b1", "commit")
        c.vote(xid, "b2", "commit")
        pkg = c.decide(xid, "commit", seed)
        self.assertTrue(c.apply_decision(xid, "b1", pkg))
        self.assertTrue(c.apply_decision(xid, "b2", pkg))
        self.assertEqual(c.transaction_state(xid), "committed")

    def test_rollback_path(self):
        c = wb.BranchCoordinator()
        seed = _seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "rollback")
        pkg = c.decide(xid, "rollback", seed)
        self.assertTrue(c.apply_decision(xid, "b1", pkg))
        self.assertEqual(c.transaction_state(xid), "rolled-back")

    def test_forged_decision_refuses(self):
        c = wb.BranchCoordinator()
        seed = _seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "commit")
        pkg = c.decide(xid, "commit", seed)
        # Attacker re-signs the decision with their own key.
        evil = dict(pkg)
        evil_seed = _seed()
        evil["signature"] = ed25519.sign(
            evil_seed, wb._canonical_decision_body(pkg)).hex()
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.apply_decision(xid, "b1", evil)
        self.assertEqual(ctx.exception.code,
                         "workflow-branch-decision-forgery")

    def test_decide_requires_all_branches_voted(self):
        c = wb.BranchCoordinator()
        seed = _seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.register_branch(xid, "b2", "worker-2")
        c.vote(xid, "b1", "commit")
        with self.assertRaises(wb.WorkflowBranchError):
            c.decide(xid, "commit", seed)

    def test_decision_xid_mismatch_refuses(self):
        c = wb.BranchCoordinator()
        seed = _seed()
        xid_a = c.begin(seed)
        xid_b = c.begin(seed)
        c.register_branch(xid_a, "b1", "worker-1")
        c.register_branch(xid_b, "b1", "worker-1")
        c.vote(xid_a, "b1", "commit")
        c.vote(xid_b, "b1", "commit")
        pkg = c.decide(xid_a, "commit", seed)
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.apply_decision(xid_b, "b1", pkg)
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")


class LeaseAcrossSuspensionTests(unittest.TestCase):
    def _lease(self, lm, seed, ttl=100, at=1000):
        return lm.acquire("scope-a", ttl, "holder-1",
                          authority_seed=seed, issued_at=at)

    def test_suspend_resume_live_lease_ok(self):
        from gov import coordination_lease as cl
        lm = cl.LeaseManager()
        seed = _seed()
        lease = self._lease(lm, seed)
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        susp = c.suspend_lease(xid, lm, "scope-a",
                              lease["fencing_token"], "holder-1",
                              suspended_at=1050)
        self.assertTrue(c.resume_lease(susp, lm, checked_at=1080))

    def test_resume_expired_while_suspended_refuses(self):
        from gov import coordination_lease as cl
        lm = cl.LeaseManager()
        seed = _seed()
        lease = self._lease(lm, seed, ttl=100, at=1000)  # expires 1100
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        susp = c.suspend_lease(xid, lm, "scope-a",
                              lease["fencing_token"], "holder-1",
                              suspended_at=1050)
        with self.assertRaises(Exception) as ctx:
            c.resume_lease(susp, lm, checked_at=1200)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "coord-lease-expired")

    def test_resume_does_not_silently_extend(self):
        from gov import coordination_lease as cl
        lm = cl.LeaseManager()
        seed = _seed()
        lease = self._lease(lm, seed, ttl=100, at=1000)  # expires 1100
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        susp = c.suspend_lease(xid, lm, "scope-a",
                              lease["fencing_token"], "holder-1",
                              suspended_at=1050)
        # Resume at 1090 (still live) must NOT move the expiry to 1190.
        self.assertTrue(c.resume_lease(susp, lm, checked_at=1090))
        with self.assertRaises(Exception) as ctx:
            lm.check_write("scope-a", lease["fencing_token"], "holder-1",
                           checked_at=1150)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "coord-lease-expired")

    def test_suspend_records_xid_binding(self):
        from gov import coordination_lease as cl
        lm = cl.LeaseManager()
        seed = _seed()
        lease = self._lease(lm, seed)
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        susp = c.suspend_lease(xid, lm, "scope-a",
                              lease["fencing_token"], "holder-1",
                              suspended_at=1050)
        self.assertEqual(susp["xid"], xid)


class CodeContractTests(unittest.TestCase):
    def test_new_codes_in_taxonomy(self):
        from gov import decision_codes
        for code in ("workflow-branch-xid-mismatch",
                     "workflow-branch-unregistered",
                     "workflow-branch-decision-forgery"):
            self.assertIn(code, decision_codes.TAXONOMY)

    def test_ed25519_verify_contract(self):
        seed = _seed()
        pub = ed25519.publickey(seed)
        sig = ed25519.sign(seed, b"msg")
        self.assertIs(ed25519.verify(pub, b"msg", sig), True)
        self.assertIs(ed25519.verify(pub, b"other", sig), False)


if __name__ == "__main__":
    unittest.main()
