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
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import decision_codes
from gov import ed25519
from gov import coordination_lease as cl
from gov import workflow_branch as wb

TAXONOMY_PIN = 2044 # Wave-303 merge pin; this lane mints no new codes (reuses workflow-branch-xid-mismatch).; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



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
            "repin-pin-1851",
            len(lits) == 2044 and len(set(lits)) == 2044


            and lits == sorted(lits),
            "1851 unique sorted literals") == "HELD")


class FooterStateTest(unittest.TestCase):
    def test_footer(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        # Anchor to the LAST matches: the footer, not historical entries.
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        want_open, want_next = "none", "F409"  # wave-323 lane 1: F407 closed
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


_gc_returns = []


def _install_gc_capture():
    # Capture _green_check_unittest's return so the GreenCheckTest can
    # be recorded as SKIP (not just assert-pass) when GOV_SKIP_GREEN=1.
    global _green_check_unittest
    _orig = _green_check_unittest

    def _captured(path, label):
        r = _orig(path, label)
        _gc_returns.append(r)
        return r

    globals()["_green_check_unittest"] = _captured


def _run_test(test_cls, test):
    """Run one unittest test; return a (pid, verdict, note) triple.

    Wave-316 lane-3: the suite runs programmatically (no
    TextTestRunner -- its failure tracebacks would trip the shared
    green_check's fail-closed TRACEBACK_RE in parent batteries).
    Probe tests record one _expect_held entry each; its name is the
    pid. A failed assertion -> BREAK, an unexpected exception ->
    ERROR. GreenCheckTest maps the helper's SKIPPED/GREEN/else to
    SKIP/HELD/BREAK (D1).
    """
    method = test.id().split(".")[-1]
    mark = len(_results)
    res = unittest.TestResult()
    test.run(res)
    new = _results[mark:]
    if test_cls.__name__ == "GreenCheckTest":
        gc = _gc_returns[-1] if _gc_returns else ""
        if gc.startswith("SKIPPED"):
            return ("green-check", "SKIP", gc)
        if gc.startswith("GREEN"):
            return ("green-check", "HELD", gc)
        return ("green-check", "BREAK", gc or "green check failed")
    if len(new) == 1:
        name, status, detail = new[0]
        if res.errors:
            return (name, "ERROR", detail)
        if res.failures:
            return (name, "BREAK", detail)
        return (name, status, detail)
    pid = "%s.%s" % (test_cls.__name__, method)
    problems = res.errors + res.failures
    if problems:
        tb = problems[0][1].strip().splitlines()
        note = tb[-1] if tb else "failed"
        return (pid, "ERROR" if res.errors else "BREAK",
                probe_lines.first_line(note))
    return (pid, "HELD", "pass")


def main():
    _install_gc_capture()
    loader = unittest.TestLoader()
    results = []
    for test_cls in (F385Probes, PinTest, RepinTest, FooterStateTest,
                     GreenCheckTest):
        for test in loader.loadTestsFromTestCase(test_cls):
            results.append(_run_test(test_cls, test))
    probe_lines.emit(results)
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    hld = sum(1 for _, v, _ in results if v == "HELD")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, hld, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, hld, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
