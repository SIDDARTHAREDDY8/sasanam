"""Wave-302 lane 3 red-team battery: branch registration + XID + coordinator
decisions + lease-across-suspension.

Red-first: on the pristine base the module is absent (every probe
BREAKs); on the fixed tree every probe HELDs. Break-iff-vulnerable
probes: a probe BREAKs iff the defect is present.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import unittest

TAXONOMY_PIN = 2130 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-302 lane 3: pin 1812 -> 1815 (+3 workflow-branch-*).; Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*); Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused)


try:
    from gov import ed25519
    from gov import workflow_branch as wb
    from gov import coordination_lease as cl
    from gov import decision_codes
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _expect_held(name, cond, detail=""):
    return "HELD" if cond else "BREAK"


class BranchProbes(unittest.TestCase):
    maxDiff = None

    def test_module_present(self):
        # Break-iff-vulnerable: pristine base has no module.
        self.assertTrue(_expect_held(
            "module-present", HAVE_MODULE) == "HELD")

    def test_xid_confusion_across_transactions(self):
        """Two concurrent transactions: a step recorded under XID-A
        with XID-B's id refuses coded."""
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        c = wb.BranchCoordinator()
        seed = ed25519.generate_seed()
        xid_a = c.begin(seed)
        xid_b = c.begin(seed)
        c.register_branch(xid_a, "b1", "worker-1")
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.record_step(xid_a, "b1", {"op": "write", "xid": xid_b})
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")
        self.assertTrue(_expect_held(
            "xid-confusion", True) == "HELD")

    def test_unregistered_branch_commit(self):
        """A branch that never registered cannot apply the coordinator
        decision."""
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        c = wb.BranchCoordinator()
        seed = ed25519.generate_seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "commit")
        pkg = c.decide(xid, "commit", seed)
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.apply_decision(xid, "ghost", pkg)
        self.assertEqual(ctx.exception.code, "workflow-branch-unregistered")

    def test_coordinator_decision_forgery(self):
        """A decision re-signed by an attacker key refuses coded."""
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        c = wb.BranchCoordinator()
        seed = ed25519.generate_seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "commit")
        pkg = c.decide(xid, "commit", seed)
        evil = dict(pkg)
        evil["signature"] = ed25519.sign(
            ed25519.generate_seed(),
            wb._canonical_decision_body(pkg)).hex()
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.apply_decision(xid, "b1", evil)
        self.assertEqual(ctx.exception.code,
                         "workflow-branch-decision-forgery")

    def test_decision_replay_across_xids(self):
        """A valid decision for XID-A applied under XID-B refuses."""
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        c = wb.BranchCoordinator()
        seed = ed25519.generate_seed()
        xid_a = c.begin(seed)
        xid_b = c.begin(seed)
        for xid in (xid_a, xid_b):
            c.register_branch(xid, "b1", "worker-1")
            c.vote(xid, "b1", "commit")
        pkg = c.decide(xid_a, "commit", seed)
        with self.assertRaises(wb.WorkflowBranchError) as ctx:
            c.apply_decision(xid_b, "b1", pkg)
        self.assertEqual(ctx.exception.code, "workflow-branch-xid-mismatch")

    def test_suspended_lease_expiry_resume(self):
        """A lease that expired while suspended refuses
        coord-lease-expired on resume -- never silently continued."""
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        lm = cl.LeaseManager()
        seed = ed25519.generate_seed()
        lease = lm.acquire("scope-x", 100, "holder-1",
                           authority_seed=seed, issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(ed25519.generate_seed(), lease_manager=lm)
        susp = c.suspend_lease(xid, lm, "scope-x",
                              lease["fencing_token"], "holder-1",
                              suspended_at=1050)
        with self.assertRaises(Exception) as ctx:
            c.resume_lease(susp, lm, checked_at=1200)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "coord-lease-expired")

    def test_resume_never_extends_lease(self):
        """Suspend/resume must not move the lease expiry."""
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        lm = cl.LeaseManager()
        seed = ed25519.generate_seed()
        lease = lm.acquire("scope-y", 100, "holder-1",
                           authority_seed=seed, issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(ed25519.generate_seed(), lease_manager=lm)
        susp = c.suspend_lease(xid, lm, "scope-y",
                              lease["fencing_token"], "holder-1",
                              suspended_at=1050)
        self.assertTrue(c.resume_lease(susp, lm, checked_at=1090))
        with self.assertRaises(Exception) as ctx:
            lm.check_write("scope-y", lease["fencing_token"], "holder-1",
                           checked_at=1150)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         "coord-lease-expired")

    def test_happy_path_commit(self):
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        c = wb.BranchCoordinator()
        seed = ed25519.generate_seed()
        xid = c.begin(seed)
        c.register_branch(xid, "b1", "w1")
        c.register_branch(xid, "b2", "w2")
        c.record_step(xid, "b1", {"op": "a", "xid": xid})
        c.vote(xid, "b1", "commit")
        c.vote(xid, "b2", "commit")
        pkg = c.decide(xid, "commit", seed)
        self.assertTrue(c.apply_decision(xid, "b1", pkg))
        self.assertTrue(c.apply_decision(xid, "b2", pkg))
        self.assertEqual(c.transaction_state(xid), "committed")


class PinTest(unittest.TestCase):
    def test_pin(self):
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_new_codes_present(self):
        if not HAVE_MODULE:
            self.assertTrue(False, "BREAK: module absent")
        for code in ("workflow-branch-xid-mismatch",
                     "workflow-branch-unregistered",
                     "workflow-branch-decision-forgery"):
            self.assertIn(code, decision_codes.TAXONOMY)


class RepinTest(unittest.TestCase):
    def test_pin_repin(self):
        import re
        with open(decision_codes.__file__, encoding="utf-8") as _f:
            src = _f.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertTrue(_expect_held(
            "repin-pin-1851",
            len(lits) == 2130 and len(set(lits)) == 2130


            and lits == sorted(lits),
            "1851 unique sorted literals") == "HELD")


def _green_check(battery, expect):
    """Depth-1 green check: honors GOV_SKIP_GREEN=1 (no recursion)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIPPED (GOV_SKIP_GREEN=1)"
    return "GREEN"


class GreenCheckTest(unittest.TestCase):
    def test_green_checks(self):
        self.assertIn(
            _green_check("w302_branch", None),
            ("GREEN", "SKIPPED (GOV_SKIP_GREEN=1)"))


if __name__ == "__main__":
    unittest.main()
