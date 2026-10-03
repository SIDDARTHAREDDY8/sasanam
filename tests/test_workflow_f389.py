"""Tests for F389: suspend_lease must prove lease-holdership at suspend
time -- an unauthenticated re-park must not clobber the parked
suspension.

Red-first: the F389 probe (evals/w305_redteam_probes.py::
p_f389_suspend_lease_clobber) BREAKs on the pristine wave-305 base;
these tests pin the fixed contract.
"""

import unittest

from gov import ed25519
from gov import workflow_branch as wb


def _seed():
    return ed25519.generate_seed()


class F389SuspendHoldershipTests(unittest.TestCase):
    def _fx(self, ttl=100, issued_at=1000):
        from gov import coordination_lease as cl
        lm = cl.LeaseManager()
        lease = lm.acquire("scope-x", ttl, "holder-1",
                           authority_seed=_seed(), issued_at=issued_at)
        c = wb.BranchCoordinator()
        xid = c.begin(_seed())
        return lm, lease["fencing_token"], c, xid

    def test_attacker_repark_with_bogus_token_refuses(self):
        lm, tok, c, xid = self._fx()
        susp = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                              suspended_at=1050)
        # Attacker knows the xid but holds no lease: bogus token.
        with self.assertRaises(Exception) as ctx:
            c.suspend_lease(xid, lm, "scope-x", 999999, "mallory",
                            suspended_at=1060)
        self.assertEqual(ctx.exception.code, "coord-lease-fencing")
        # The legitimate park is intact: resume still works.
        self.assertTrue(c.resume_lease(susp, lm, checked_at=1080))

    def test_attacker_repark_with_wrong_holder_refuses(self):
        lm, tok, c, xid = self._fx()
        c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                       suspended_at=1050)
        # Right token shape is not enough: holder must match too.
        with self.assertRaises(Exception) as ctx:
            c.suspend_lease(xid, lm, "scope-x", tok, "mallory",
                            suspended_at=1060)
        self.assertEqual(ctx.exception.code, "coord-lease-invalid")

    def test_legitimate_repark_with_current_token_still_works(self):
        # The documented re-park semantics (latest park wins) are
        # preserved for the lease holder.
        lm, tok, c, xid = self._fx()
        susp1 = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                               suspended_at=1050)
        susp2 = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                               suspended_at=1060)
        self.assertNotEqual(susp1["suspended_at"], susp2["suspended_at"])
        self.assertTrue(c.resume_lease(susp2, lm, checked_at=1080))
        # The superseded park no longer matches: exact-record match.
        with self.assertRaises(Exception) as ctx:
            c.resume_lease(susp1, lm, checked_at=1080)
        self.assertEqual(ctx.exception.code,
                         "workflow-branch-xid-mismatch")

    def test_suspend_with_expired_lease_refuses(self):
        lm, tok, c, xid = self._fx(ttl=100, issued_at=1000)  # expires 1100
        with self.assertRaises(Exception) as ctx:
            c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                            suspended_at=1200)
        self.assertEqual(ctx.exception.code, "coord-lease-expired")

    def test_suspend_unknown_xid_still_refuses_first(self):
        lm, tok, c, xid = self._fx()
        with self.assertRaises(Exception) as ctx:
            c.suspend_lease("f" * 64, lm, "scope-x", tok, "holder-1",
                            suspended_at=1050)
        self.assertEqual(ctx.exception.code, "decision-code-malformed")

    def test_suspend_bad_lease_manager_shape_refuses(self):
        lm, tok, c, xid = self._fx()
        with self.assertRaises(Exception) as ctx:
            c.suspend_lease(xid, object(), "scope-x", tok, "holder-1",
                            suspended_at=1050)
        self.assertEqual(ctx.exception.code, "decision-code-malformed")


if __name__ == "__main__":
    unittest.main()
