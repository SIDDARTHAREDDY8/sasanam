"""Tests for the F385 closure: resume_lease binds the suspension's XID
to a live transaction of this coordinator.

F385 (LOW, filed 2026-10-03, wave-303 independent red-team):
``BranchCoordinator.resume_lease`` shape-checked the suspension's XID
but never resolved it against the coordinator's live transactions.
Closed in wave-304 lane A: resume resolves ``suspension["xid"]``
through ``self._txn`` (fail closed on unknown XIDs), requires the
transaction to still be open, and requires the presented record to
match field-for-field the suspension parked for that XID by
``suspend_lease`` (the coordinator remembers the park). Mismatch
refuses ``workflow-branch-xid-mismatch``.

Red-first: on the pristine wave-303 base, the tamper/never-begun
probes below BREAK (resume returned True); on the fixed tree they
refuse coded. The SPEC-axis review (2026-10-03) caught that a
pubkey-only binding does not stop an A->B swap when both transactions
share the coordinator's key (single seed): the exact parked-record
match closes that variant too.
"""

import unittest

from gov import ed25519
from gov import coordination_lease as cl
from gov import workflow_branch as wb


def _seed():
    return ed25519.generate_seed()


class F385ResumeXidBindingTests(unittest.TestCase):
    def _setup(self):
        lm = cl.LeaseManager()
        lease = lm.acquire("scope-x", 100, "holder-1",
                           authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid_a = c.begin(_seed())
        xid_b = c.begin(_seed())
        susp = c.suspend_lease(xid_a, lm, "scope-x",
                               lease["fencing_token"], "holder-1",
                               suspended_at=1050)
        return lm, c, xid_a, xid_b, susp

    def _code_of(self, fn):
        # check_write refusals arrive as coordination_lease's own
        # exception type; read .code off any exception.
        try:
            fn()
        except Exception as e:
            return getattr(e, "code", "unexpected:%s" % type(e).__name__)
        return None

    def test_cross_transaction_xid_refuses_xid_mismatch(self):
        lm, c, xid_a, xid_b, susp = self._setup()
        tampered = dict(susp)
        tampered["xid"] = xid_b  # live, but not the parking txn
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(tampered, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_same_seed_swap_refuses_xid_mismatch(self):
        # SPEC-review scenario: both transactions begun with the SAME
        # coordinator seed, so their coordinator_pubkey values are
        # identical. Swapping the record's xid from A to B must still
        # refuse -- the binding is to the parked record, not the key.
        seed = _seed()
        lm = cl.LeaseManager()
        lease = lm.acquire("scope-x", 100, "holder-1",
                           authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid_a = c.begin(seed)
        xid_b = c.begin(seed)
        susp = c.suspend_lease(xid_a, lm, "scope-x",
                               lease["fencing_token"], "holder-1",
                               suspended_at=1050)
        tampered = dict(susp)
        tampered["xid"] = xid_b
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(tampered, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_committed_transaction_refuses_malformed(self):
        # A suspension parked under a transaction that has since
        # committed is unlive: resume must fail closed.
        seed = _seed()
        lm = cl.LeaseManager()
        lease = lm.acquire("scope-x", 100, "holder-1",
                           authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(seed)
        susp = c.suspend_lease(xid, lm, "scope-x",
                               lease["fencing_token"], "holder-1",
                               suspended_at=1050)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "commit")
        pkg = c.decide(xid, "commit", seed)
        self.assertTrue(c.apply_decision(xid, "b1", pkg))
        self.assertEqual(c.transaction_state(xid), "committed")
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(susp, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "decision-code-malformed")

    def test_field_edit_refuses_xid_mismatch(self):
        # Any edit to the parked record (here the fencing token)
        # breaks the exact-match binding.
        lm, c, xid_a, xid_b, susp = self._setup()
        tampered = dict(susp)
        tampered["fencing_token"] = "ff" * 16
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(tampered, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_never_begun_xid_refuses_malformed(self):
        lm, c, xid_a, xid_b, susp = self._setup()
        tampered = dict(susp)
        tampered["xid"] = "ab" * 32  # well-formed, never begun
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(tampered, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "decision-code-malformed")

    def test_tampered_pubkey_refuses_xid_mismatch(self):
        # The XID is live but the record's pubkey does not match the
        # transaction's -- the record was not parked under this XID.
        lm, c, xid_a, xid_b, susp = self._setup()
        tampered = dict(susp)
        tampered["coordinator_pubkey"] = "00" * 32
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(tampered, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_missing_pubkey_refuses_malformed(self):
        lm, c, xid_a, xid_b, susp = self._setup()
        stripped = dict(susp)
        del stripped["coordinator_pubkey"]
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.resume_lease(stripped, lm, checked_at=1090)
        self.assertEqual(ctx.exception.code, "decision-code-malformed")

    def test_legit_resume_still_returns_true(self):
        lm, c, xid_a, xid_b, susp = self._setup()
        self.assertTrue(c.resume_lease(susp, lm, checked_at=1090))

    def test_expired_lease_still_fences_coded(self):
        # The liveness oracle is untouched by the binding fix. NB: the
        # expiry refusal arrives as coordination_lease's own exception
        # type (not WorkflowBranchError) -- catch broadly like the
        # pre-existing test_workflow_branch.py convention.
        lm2 = cl.LeaseManager()
        lease = lm2.acquire("scope-y", 100, "holder-2",
                            authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        susp = c.suspend_lease(xid, lm2, "scope-y",
                               lease["fencing_token"], "holder-2",
                               suspended_at=1050)
        with self.assertRaises(Exception) as ctx:
            c.resume_lease(susp, lm2, checked_at=1200)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "coord-lease-expired")


if __name__ == "__main__":
    unittest.main()
