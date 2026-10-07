"""Wave-303 F381 closure battery: idempotency caller binding + evict authority.

F381 (MEDIUM, filed 2026-10-03, wave-302 red-team): complete()/checkpoint()
were not caller-bound (cross-caller result poisoning) and evict_completed()
was unauthenticated.

Closure (wave-303 lane 2, gov/workflow_idempotency.py only): BeginOutcome
records the beginning caller; complete()/checkpoint() refuse coded
workflow-idempotency-caller-mismatch on mismatch; evict_completed()
requires and verifies an authority verifier (refusing/raising verifier
fails closed coded workflow-idempotency-authority-lapsed).

Red-first provenance: these probes were written from the red-team
reproduction and confirmed BREAK on the pre-fix tree (all three
exploits reproduced: poisoning, cross-caller checkpoint, unauthenticated
eviction); they flip HELD on the fixed tree. Written BEFORE the fix was
verified green, against the pristine base.

Pin 1821 at lane time (+1 workflow-idempotency-caller-mismatch).
Wave-303 merge: open F385,F386 / next free F387.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Depth-1 green checks honoring GOV_SKIP_GREEN=1.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import re
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

from gov import workflow_idempotency as idem

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_coded(name, fn, codes):
    """fn must raise a coded error whose .code is in codes. Anything
    else (no raise, uncoded raise, wrong code) is a BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code in codes:
            return _record(name, "HELD", "coded %s" % (code,))
        return _record(name, "BREAK",
                       "wrong escape: %s(code=%r), want one of %s"
                       % (type(e).__name__, code, sorted(codes)))
    return _record(name, "BREAK", "no refusal: fn returned")


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


def _verifier(**kw):
    return True


def _refusing(**kw):
    return False


def _raising(**kw):
    raise RuntimeError("verifier down")


_AT = 1700000000
_OPD = hashlib.sha256(b"op").hexdigest()


class BaseStateTest(unittest.TestCase):
    def test_footer_state(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        # Wave-316 merge footer: F398/F399/F400 CLOSED; F401/F402/F403 OPEN; next F404.
        ok = (m_open and m_open[-1].strip() == "F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559, F560, F561, F562, F563, F564, F565, F566, F567, F568, F569"  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
              and m_next and m_next[-1] == "F570")  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
        self.assertTrue(_expect_held(
            "footer-state", ok,
            "want open F521, F522, F523, F524, F525 / next free F526") == "HELD")  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)

    def test_pin(self):
        with open(os.path.join(REPO, "gov", "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        ok = (len(lits) == TAXONOMY_PIN and len(set(lits)) == TAXONOMY_PIN
              and lits == sorted(lits))
        self.assertTrue(_expect_held(
            "taxonomy-pin",
            ok and TAXONOMY_PIN == 2135,#Wave-333 merge: pin 2069 -> 2106 (+8 revocation-push-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


            "%d literals / %d unique / sorted=%s"
            % (len(lits), len(set(lits)), lits == sorted(lits))) == "HELD")

    def test_new_code_present_and_sorted(self):
        with open(os.path.join(REPO, "gov", "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertTrue(_expect_held(
            "new-code-present",
            "workflow-idempotency-caller-mismatch" in lits,
            "caller-mismatch code missing") == "HELD")
        self.assertTrue(_expect_held(
            "no-duplicate-code-literals",
            len(lits) == len(set(lits)),
            "duplicate code literals") == "HELD")


class CallerBindingTest(unittest.TestCase):
    """complete()/checkpoint() are bound to the beginning caller."""

    def _pair(self, key="k1"):
        backing = {}
        s1 = idem.IdempotencyStore(backing=backing)
        s2 = idem.IdempotencyStore(backing=backing)
        o1 = s1.begin("ns1", "pay", key, _OPD, "alice", _verifier, at=_AT)
        o2 = s2.begin("ns1", "pay", key, _OPD, "mallory", _verifier, at=_AT)
        return s1, o1, o2

    def test_cross_caller_complete_refuses_coded(self):
        _, _, o2 = self._pair()
        self.assertEqual(o2.status, "retry")
        self.assertTrue(_expect_coded(
            "cross-caller-complete",
            lambda: o2.complete("cd" * 32, "mallory-result-ref", at=_AT),
            {"workflow-idempotency-caller-mismatch"}) == "HELD")

    def test_cross_caller_checkpoint_refuses_coded(self):
        _, _, o2 = self._pair(key="k3")
        self.assertTrue(_expect_coded(
            "cross-caller-checkpoint",
            lambda: o2.checkpoint("mallory was here", at=_AT),
            {"workflow-idempotency-caller-mismatch"}) == "HELD")

    def test_no_poisoning_after_refusal(self):
        s1, _, o2 = self._pair()
        try:
            o2.complete("cd" * 32, "mallory-result-ref", at=_AT)
        except Exception:  # noqa: BLE001
            pass
        o1b = s1.begin("ns1", "pay", "k1", _OPD, "alice", _verifier, at=_AT)
        o1b.complete("ef" * 32, "alice-result-ref", at=_AT)
        o3 = s1.begin("ns1", "pay", "k1", _OPD, "alice", _verifier, at=_AT)
        self.assertTrue(_expect_held(
            "no-poisoning",
            o3.status == "replay" and o3.result_ref == "alice-result-ref",
            "replay poisoned or honest completion broken") == "HELD")

    def test_same_caller_complete_and_checkpoint(self):
        s = idem.IdempotencyStore()
        o = s.begin("ns1", "pay", "kc", _OPD, "alice", _verifier, at=_AT)
        o.checkpoint("halfway", at=_AT)
        self.assertTrue(_expect_held(
            "same-caller-checkpoint", "halfway" in o.notes,
            "honest checkpoint broke") == "HELD")
        self.assertTrue(_expect_held(
            "same-caller-complete",
            o.complete("ab" * 32, "ptr://r", at=_AT) is None,
            "honest complete broke") == "HELD")

    def test_crash_retry_same_caller(self):
        backing = {}
        s1 = idem.IdempotencyStore(backing=backing)
        s2 = idem.IdempotencyStore(backing=backing)
        s1.begin("ns1", "pay", "k9", _OPD, "agent-a", _verifier, at=_AT)
        o2 = s2.begin("ns1", "pay", "k9", _OPD, "agent-a", _verifier, at=_AT)
        self.assertEqual(o2.status, "retry")
        self.assertTrue(_expect_held(
            "crash-retry-same-caller",
            o2.complete("ab" * 32, "ptr://r9", at=_AT) is None,
            "acks_late same-caller retry broke") == "HELD")


class EvictAuthorityTest(unittest.TestCase):
    """evict_completed() requires a verified authority."""

    def _completed(self):
        s = idem.IdempotencyStore()
        o = s.begin("ns1", "pay", "k2", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ref", at=_AT)
        return s

    def test_evict_without_verifier_fails_closed(self):
        s = self._completed()
        try:
            s.evict_completed("ns1", "pay", "k2", operator="mallory", at=_AT)
            refused = False
        except Exception:  # noqa: BLE001
            refused = True
        self.assertTrue(_expect_held(
            "evict-no-verifier", refused,
            "eviction without a verifier succeeded") == "HELD")

    def test_evict_refusing_verifier_coded(self):
        s = self._completed()
        self.assertTrue(_expect_coded(
            "evict-refusing-verifier",
            lambda: s.evict_completed("ns1", "pay", "k2",
                                      operator="mallory",
                                      authority_verifier=_refusing, at=_AT),
            {"workflow-idempotency-authority-lapsed"}) == "HELD")

    def test_evict_raising_verifier_fails_closed_coded(self):
        s = self._completed()
        self.assertTrue(_expect_coded(
            "evict-raising-verifier",
            lambda: s.evict_completed("ns1", "pay", "k2",
                                      operator="mallory",
                                      authority_verifier=_raising, at=_AT),
            {"workflow-idempotency-authority-lapsed"}) == "HELD")

    def test_evict_authorized_loud(self):
        sink = []
        s = idem.IdempotencyStore(sink=sink.append)
        o = s.begin("ns1", "pay", "k2", _OPD, "alice", _verifier, at=_AT)
        o.complete("ab" * 32, "ref", at=_AT)
        rec = s.evict_completed("ns1", "pay", "k2", operator="ops",
                                authority_verifier=_verifier, at=_AT)
        self.assertTrue(_expect_held(
            "evict-authorized",
            rec["reason"] == "operator"
            and any(r.get("event") == "evict-operator" for r in sink),
            "authorized eviction broke or went silent") == "HELD")


# ---------------------------------------------------------------------------
# Depth-1 green checks (honor GOV_SKIP_GREEN).
# ---------------------------------------------------------------------------

def _green_check_unittest(path, label):
    # All three call sites are unittest-style (child prints "Ran N
    # tests" + OK, exit 0). Wave-305: delegates to evals/green_check.py
    # (fail-closed contract); the PYTHONPATH the old form set is
    # preserved via extra_env. Returns (status, detail) as before.
    return green_check.check_unittest_result(
        label, path, repo=REPO,
        extra_env={"PYTHONPATH": REPO + os.pathsep +
                   os.environ.get("PYTHONPATH", "")})


class GreenCheckTest(unittest.TestCase):
    def test_green_w301_idempotency(self):
        status, detail = _green_check_unittest(
            "evals/w301_idempotency_probes.py", "w301_idempotency")
        self.assertTrue(_expect_held(
            "green-w301-idempotency", status == "HELD", detail) == "HELD")

    def test_green_unit_idempotency(self):
        status, detail = _green_check_unittest(
            "tests/test_workflow_idempotency.py", "test_workflow_idempotency")
        self.assertTrue(_expect_held(
            "green-unit-idempotency", status == "HELD", detail) == "HELD")

    def test_green_unit_f381(self):
        status, detail = _green_check_unittest(
            "tests/test_workflow_f381.py", "test_workflow_f381")
        self.assertTrue(_expect_held(
            "green-unit-f381", status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, CallerBindingTest, EvictAuthorityTest,
                GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    n_break = sum(1 for _, s, _ in _results if s == "BREAK")
    n_held = sum(1 for _, s, _ in _results if s == "HELD")
    n_err = sum(1 for _, s, _ in _results if s == "ERROR")
    print("w303_f381: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    if not result.wasSuccessful() or n_break or n_err:
        probe_lines.emit((n, s, probe_lines.first_line(d) if d else "")
                         for n, s, d in _results if s != "HELD")
    return result


if __name__ == "__main__":
    main()
