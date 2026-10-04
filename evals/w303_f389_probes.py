"""Wave-306 F389 regression battery: suspend_lease lease-holdership proof.

F389 (LOW, filed 2026-10-03, wave-305 independent red-team):
``gov/workflow_branch.py::suspend_lease`` performed no authority check --
a caller who knew the xid could re-park a different suspension record
(bogus fencing token, foreign holder), clobbering the legitimate
holder's parked suspension. The legitimate holder's subsequent
``resume_lease`` then refused ``workflow-branch-xid-mismatch`` (the F385
exact-parked-record match made the clobbering stick). Availability-only:
the attacker could not complete the resume themselves (``check_write``'s
fencing token still gated), recoverable by re-suspending.

Wave-306 lane A closes F389 in ``gov/workflow_branch.py``:
``suspend_lease`` now proves lease-holdership at suspend time via
``lease_manager.check_write(scope, fencing_token, holder_id,
checked_at=suspended_at)`` BEFORE anything is parked -- a stale/foreign
token refuses ``coord-lease-fencing``, a dead lease refuses
``coord-lease-expired``. The fencing token is the lease capability: only
the current holder knows it. Legitimate re-suspending with the current
token (documented re-park semantics: latest park wins) still works.
No new decision codes; taxonomy pin stays 1827.

Red-first provenance: on the pristine wave-305 base the w305_redteam
probe ``F389-suspend-lease-clobber`` BREAKs; on the fixed tree it is
HELD (unauthenticated re-park refused).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Deployment mode set at module level; also verified under
a clean environment.

Run:
  mkdir -p /var/tmp/g306-f389 && TMPDIR=/var/tmp/g306-f389 \
    ~/workspace/.gov-venv/bin/python evals/w303_f389_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g306-f389b \
    ~/workspace/.gov-venv/bin/python evals/w303_f389_probes.py
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
from gov import workflow_branch as wb

TAXONOMY_PIN = 1976 # Wave-305 merge pin; this lane mints no new codes (reuses coord-lease-*).; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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


def _fx(ttl=100, issued_at=1000):
    from gov import coordination_lease as cl
    lm = cl.LeaseManager()
    lease = lm.acquire("scope-x", ttl, "holder-1",
                       authority_seed=_seed(), issued_at=issued_at)
    c = wb.BranchCoordinator()
    xid = c.begin(_seed(), lease_manager=lm)
    return lm, lease["fencing_token"], c, xid


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return None


class F389SuspendHoldershipTests(unittest.TestCase):
    def test_repark_with_bogus_token_refuses_fencing(self):
        lm, tok, c, xid = _fx()
        susp = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                              suspended_at=1050)
        code = _code_of(lambda: c.suspend_lease(
            xid, lm, "scope-x", 999999, "mallory", suspended_at=1060))
        self.assertTrue(_expect_held(
            "F389-repark-bogus-token-refuses",
            code == "coord-lease-fencing",
            "got code=%r (want coord-lease-fencing)" % (code,)) == "HELD")
        # The legitimate park is intact: resume still works.
        self.assertTrue(_expect_held(
            "F389-legitimate-park-intact",
            c.resume_lease(susp, lm, checked_at=1080) is True,
            "legitimate resume broken by refused re-park") == "HELD")

    def test_repark_with_wrong_holder_refuses(self):
        lm, tok, c, xid = _fx()
        c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                       suspended_at=1050)
        code = _code_of(lambda: c.suspend_lease(
            xid, lm, "scope-x", tok, "mallory", suspended_at=1060))
        self.assertTrue(_expect_held(
            "F389-repark-wrong-holder-refuses",
            code == "coord-lease-invalid",
            "got code=%r (want coord-lease-invalid)" % (code,)) == "HELD")

    def test_legitimate_repark_still_works(self):
        lm, tok, c, xid = _fx()
        c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                       suspended_at=1050)
        susp2 = c.suspend_lease(xid, lm, "scope-x", tok, "holder-1",
                               suspended_at=1060)
        self.assertTrue(_expect_held(
            "F389-legitimate-repark-works",
            c.resume_lease(susp2, lm, checked_at=1080) is True,
            "holder re-park with current token must keep working")
            == "HELD")

    def test_suspend_expired_lease_refuses(self):
        lm, tok, c, xid = _fx(ttl=100, issued_at=1000)  # expires 1100
        code = _code_of(lambda: c.suspend_lease(
            xid, lm, "scope-x", tok, "holder-1", suspended_at=1200))
        self.assertTrue(_expect_held(
            "F389-suspend-expired-refuses",
            code == "coord-lease-expired",
            "got code=%r (want coord-lease-expired)" % (code,)) == "HELD")


class PinTest(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_no_new_codes(self):
        # F389 reuses coord-lease-fencing / coord-lease-expired /
        # coord-lease-invalid; pin unchanged.
        for code in ("coord-lease-fencing", "coord-lease-expired",
                     "coord-lease-invalid"):
            self.assertIn(code, decision_codes.TAXONOMY)


class RepinTest(unittest.TestCase):
    def test_pin_repin(self):
        with open(decision_codes.__file__, encoding="utf-8") as _f:
            src = _f.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertTrue(_expect_held(
            "repin-pin-1851",
            len(lits) == 1976 and len(set(lits)) == 1976
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
        want_open, want_next = "none", "F407"  # wave-311 merge: F395 CLOSED, F396 OPEN
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
    batteries' green checks). Delegates to evals/green_check.py
    (fail-closed contract); returns the same "GREEN (...)"/"BREAK
    (...)"/"SKIPPED (...)"/"ERROR: ..." strings."""
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
        # Adjacent suite: the pre-existing branch unit tests must stay
        # green under the F389 fix (depth-1; honors GOV_SKIP_GREEN=1).
        result = _green_check_unittest("tests.test_workflow_branch",
                                       "test_workflow_branch")
        self.assertTrue(
            result.startswith("GREEN") or result.startswith("SKIPPED"),
            "adjacent suite not green: %r" % (result,))


_TEST_CLASSES = (F389SuspendHoldershipTests, PinTest, RepinTest,
                 FooterStateTest, GreenCheckTest)

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
    for test_cls in _TEST_CLASSES:
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
