"""Wave-303 F385 regression battery: resume_lease XID binding.

F385 (LOW, filed 2026-10-03, wave-303 independent red-team):
``gov/workflow_branch.py::resume_lease`` shape-checked the suspension's
XID but never resolved it against the coordinator's live transactions --
a suspension parked under xid_A resumed ``True`` with the record's XID
swapped to a different live xid_B, and with a well-formed never-begun
XID. The documented XID binding was decorative.

Wave-304 lane A closes F385 in ``gov/workflow_branch.py``: resume
resolves ``suspension["xid"]`` through ``self._txn`` (fail closed on
unknown XIDs), requires the transaction to still be open, and requires
the presented record to match field-for-field the suspension parked
for that XID by ``suspend_lease`` (the coordinator remembers the park;
mismatch refuses ``workflow-branch-xid-mismatch``, an existing
high-severity code: "a decision package was applied under the wrong
XID"). The exact parked-record match also closes the same-seed A->B
swap (both transactions sharing the coordinator's key), which a
pubkey-only binding would miss. No new decision codes; taxonomy pin
stays 1827.

Red-first provenance: on the pristine wave-303 base the w303_redteam
probe ``F385-resume-xid-unenforced`` BREAKs (both variants accepted);
on the fixed tree these probes are 0 BREAK / all HELD.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Deployment mode set at module level; also verified under
a clean environment.

Run:
  mkdir -p /var/tmp/g304-f385 && TMPDIR=/var/tmp/g304-f385 \
    ~/workspace/.gov-venv/bin/python evals/w303_f385_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g304-f385b \
    ~/workspace/.gov-venv/bin/python evals/w303_f385_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

from gov import decision_codes
from gov import ed25519
from gov import coordination_lease as cl
from gov import workflow_branch as wb

TAXONOMY_PIN = 1829  # Wave-303 merge pin; this lane mints no new codes (reuses workflow-branch-xid-mismatch).

_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


def _seed():
    return ed25519.generate_seed()


def _setup():
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", 100, "holder-1",
                       authority_seed=_seed(), issued_at=1000)
    tok = lease["fencing_token"]
    c = wb.BranchCoordinator()
    xid_a = c.begin(_seed(), lease_manager=lm)
    xid_b = c.begin(_seed())
    susp = c.suspend_lease(xid_a, lm, "scope-x", tok, "holder-1",
                           suspended_at=1050)
    return lm, c, xid_a, xid_b, susp, tok


def _code_of(fn):
    # NB: check_write refusals arrive as coordination_lease's own
    # exception type, not WorkflowBranchError -- read .code off any
    # exception; None means no refusal (the break).
    try:
        fn()
    except Exception as e:
        return getattr(e, "code", "unexpected:%s" % type(e).__name__)
    return None


class F385Probes(unittest.TestCase):
    def test_cross_transaction_xid_refuses(self):
        lm, c, xid_a, xid_b, susp, tok = _setup()
        tampered = dict(susp)
        tampered["xid"] = xid_b  # live, but not the parking transaction
        code = _code_of(lambda: c.resume_lease(tampered, lm,
                                               checked_at=1090))
        self.assertTrue(_expect_held(
            "F385-cross-transaction-refuses",
            code == "workflow-branch-xid-mismatch",
            "got code=%r (want workflow-branch-xid-mismatch)" % (code,))
            == "HELD")

    def test_same_seed_swap_refuses(self):
        # SPEC-review scenario: both transactions share the
        # coordinator's key (single seed). The A->B swap must still
        # refuse -- binding is to the parked record, not the key.
        seed = _seed()
        lm = cl.LeaseManager()
        lease = lm.acquire("scope-x", 100, "holder-1",
                           authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid_a = c.begin(seed, lease_manager=lm)
        xid_b = c.begin(seed)
        susp = c.suspend_lease(xid_a, lm, "scope-x",
                               lease["fencing_token"], "holder-1",
                               suspended_at=1050)
        tampered = dict(susp)
        tampered["xid"] = xid_b
        code = _code_of(lambda: c.resume_lease(tampered, lm,
                                               checked_at=1090))
        self.assertTrue(_expect_held(
            "F385-same-seed-swap-refuses",
            code == "workflow-branch-xid-mismatch",
            "got code=%r (want workflow-branch-xid-mismatch)" % (code,))
            == "HELD")

    def test_committed_transaction_refuses(self):
        # A suspension parked under a transaction that has since
        # committed is unlive: resume must fail closed.
        seed = _seed()
        lm = cl.LeaseManager()
        lease = lm.acquire("scope-x", 100, "holder-1",
                           authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(seed, lease_manager=lm)
        susp = c.suspend_lease(xid, lm, "scope-x",
                               lease["fencing_token"], "holder-1",
                               suspended_at=1050)
        c.register_branch(xid, "b1", "worker-1")
        c.vote(xid, "b1", "commit")
        pkg = c.decide(xid, "commit", seed)
        self.assertTrue(c.apply_decision(xid, "b1", pkg))
        self.assertEqual(c.transaction_state(xid), "committed")
        code = _code_of(lambda: c.resume_lease(susp, lm,
                                               checked_at=1090))
        self.assertTrue(_expect_held(
            "F385-committed-refuses",
            code == "decision-code-malformed",
            "got code=%r (want decision-code-malformed)" % (code,))
            == "HELD")

    def test_never_begun_xid_refuses(self):
        lm, c, xid_a, xid_b, susp, tok = _setup()
        tampered = dict(susp)
        tampered["xid"] = "ab" * 32  # well-formed, never begun
        code = _code_of(lambda: c.resume_lease(tampered, lm,
                                               checked_at=1090))
        self.assertTrue(_expect_held(
            "F385-never-begun-refuses",
            code == "decision-code-malformed",
            "got code=%r (want decision-code-malformed)" % (code,))
            == "HELD")

    def test_missing_pubkey_refuses(self):
        lm, c, xid_a, xid_b, susp, tok = _setup()
        stripped = dict(susp)
        del stripped["coordinator_pubkey"]
        code = _code_of(lambda: c.resume_lease(stripped, lm,
                                               checked_at=1090))
        self.assertTrue(_expect_held(
            "F385-missing-pubkey-refuses",
            code == "decision-code-malformed",
            "got code=%r (want decision-code-malformed)" % (code,))
            == "HELD")

    def test_empty_pubkey_refuses(self):
        lm, c, xid_a, xid_b, susp, tok = _setup()
        tampered = dict(susp)
        tampered["coordinator_pubkey"] = ""
        code = _code_of(lambda: c.resume_lease(tampered, lm,
                                               checked_at=1090))
        self.assertTrue(_expect_held(
            "F385-empty-pubkey-refuses",
            code == "decision-code-malformed",
            "got code=%r (want decision-code-malformed)" % (code,))
            == "HELD")

    def test_legit_resume_still_ok(self):
        lm, c, xid_a, xid_b, susp, tok = _setup()
        self.assertTrue(_expect_held(
            "F385-legit-resume-ok",
            c.resume_lease(susp, lm, checked_at=1090) is True,
            "honest suspend/resume must still return True") == "HELD")

    def test_expired_lease_still_fences(self):
        # The liveness oracle is untouched: an expired lease still
        # refuses coord-lease-expired after the XID binding passes.
        lm2 = cl.LeaseManager()
        lease = lm2.acquire("scope-y", 100, "holder-2",
                            authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(_seed(), lease_manager=lm2)
        susp = c.suspend_lease(xid, lm2, "scope-y",
                               lease["fencing_token"], "holder-2",
                               suspended_at=1050)
        code = _code_of(lambda: c.resume_lease(susp, lm2,
                                               checked_at=1200))
        self.assertTrue(_expect_held(
            "F385-expired-still-fences",
            code == "coord-lease-expired",
            "got code=%r (want coord-lease-expired)" % (code,))
            == "HELD")

    def test_resume_does_not_extend(self):
        # Suspend/resume must never extend the lease's expiry.
        lm2 = cl.LeaseManager()
        lease = lm2.acquire("scope-z", 100, "holder-3",
                            authority_seed=_seed(), issued_at=1000)
        c = wb.BranchCoordinator()
        xid = c.begin(_seed(), lease_manager=lm2)
        susp = c.suspend_lease(xid, lm2, "scope-z",
                               lease["fencing_token"], "holder-3",
                               suspended_at=1050)
        self.assertTrue(c.resume_lease(susp, lm2, checked_at=1090)
                        is True)
        code = _code_of(lambda: lm2.check_write(
            "scope-z", lease["fencing_token"], "holder-3",
            checked_at=1150))
        self.assertTrue(_expect_held(
            "F385-resume-does-not-extend",
            code == "coord-lease-expired",
            "got code=%r (want coord-lease-expired)" % (code,))
            == "HELD")


class PinTest(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_no_new_codes(self):
        # F385 reuses workflow-branch-xid-mismatch; pin unchanged.
        self.assertNotIn("workflow-branch-xid-unknown",
                        decision_codes.TAXONOMY)


class RepinTest(unittest.TestCase):
    def test_pin_repin(self):
        with open(decision_codes.__file__, encoding="utf-8") as _f:
            src = _f.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertTrue(_expect_held(
            "repin-pin-1829",
            len(lits) == 1829 and len(set(lits)) == 1829
            and lits == sorted(lits),
            "1829 unique sorted literals") == "HELD")


class FooterStateTest(unittest.TestCase):
    def test_footer(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        # Anchor to the LAST matches: the footer, not historical entries.
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        want_open, want_next = "F395", "F396"  # wave-309: F393 CLOSED
        self.assertTrue(_expect_held(
            "footer-state",
            m_open and m_open[-1].strip() == want_open
            and m_next and m_next[-1] == want_next,
            "want open %s / next free %s (got %r / %r)"
            % (want_open, want_next,
               m_open[-1].strip() if m_open else None,
               m_next[-1] if m_next else None))
            == "HELD")


def _green_check_unittest(path, label):
    """Depth-1 green check: run an adjacent unittest module as a
    subprocess with GOV_SKIP_GREEN=1 (no recursion into other
    batteries' green checks). Wave-305: delegates to
    evals/green_check.py (fail-closed contract); returns the same
    "GREEN (...)"/"BREAK (...)"/"SKIPPED (...)"/"ERROR: ..." strings
    as before."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIPPED (GOV_SKIP_GREEN=1)"
    captured = []
    green_check.check_unittest(
        lambda pid, verdict, note: captured.append((verdict, note)),
        label, path, repo=REPO)
    verdict, note = captured[0]
    if verdict == "HELD":
        return "GREEN (%s)" % (note,)
    if verdict == "ERROR":
        return "ERROR: %s" % (note,)
    return "BREAK (%s)" % (note,)


class GreenCheckTest(unittest.TestCase):
    def test_green_checks(self):
        # Adjacent suite: the pre-existing workflow_branch unit tests
        # must stay green under the F385 fix (depth-1; honors
        # GOV_SKIP_GREEN=1).
        result = _green_check_unittest("tests.test_workflow_branch",
                                       "test_workflow_branch")
        self.assertTrue(
            result.startswith("GREEN") or result.startswith("SKIPPED"),
            "adjacent suite not green: %r" % (result,))


if __name__ == "__main__":
    unittest.main()
