"""Wave-305 F387 regression battery: recv_step/sleep_step drift refusal.

F387 (LOW, filed 2026-10-03, wave-304 independent red-team):
``gov/workflow.py::recv_step``/``sleep_step`` completed paths skipped
the inputs-drift refusal ``run_step`` enforces. Both record an
``inputs_digest`` (``{"event": event}`` / ``{"wake_at": wake_at}``) yet
the completed-path replay checked only ``rec["name"] != name``:
- a slot completed for event "settled" (payload ``{"amount": 100}``)
  replayed ``({"amount": 100}, True)`` for a "refunded" subscription;
- a slot completed with ``wake_at=T1`` returned ``(True, True)`` for
  ``wake_at=T2``.

Wave-305 lane A closes F387 in ``gov/workflow.py``: the recv_step and
sleep_step completed paths now apply the same name AND inputs-digest
drift checks as ``run_step``'s sequence-slot path, refusing coded
``workflow-step-unauthorized`` (F383 defect class). The module
docstring already promised drift refusal "for an already-completed
step slot". Authority re-proof (F380) stays first: a revoked ledger
refuses ``workflow-authority-revoked`` even when inputs also drift.
No new decision codes; taxonomy pin stays 1827.

Red-first provenance: on the pristine wave-304 base the w304_redteam
probes ``F387-recv-event-drift`` / ``F387-sleep-wakeat-drift`` BREAK;
on the fixed tree these probes are 0 BREAK / all HELD.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Deployment mode set at module level; also verified under
a clean environment.

Run:
  mkdir -p /var/tmp/g305-f387 && TMPDIR=/var/tmp/g305-f387 \
    ~/workspace/.gov-venv/bin/python evals/w303_f387_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g305-f387b \
    ~/workspace/.gov-venv/bin/python evals/w303_f387_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
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
from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import workflow as wf

TAXONOMY_PIN = 2128 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-304 merge pin; this lane mints no new codes (reuses workflow-step-unauthorized).; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


AT = 1_700_000_000

_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


def _fx():
    sa = hashlib.sha256(b"w305f387-batt-a").digest()
    sb = hashlib.sha256(b"w305f387-batt-b").digest()
    pa = ed25519.publickey(sa).hex()
    pb = ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    chain = [root]
    ledger = drv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": chain, "trust_roots": [pa],
            "revocation_ledger": ledger}
    return wf.WorkflowStore(), auth, ledger, root


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- probe harness
        return getattr(e, "code", "unexpected:%s" % type(e).__name__)
    return None


class F387Probes(unittest.TestCase):
    def test_recv_event_drift_refuses_coded(self):
        ws, auth, _, _ = _fx()
        ws.start_run("wf", run_id="r1", authority=auth, at=AT)
        ws.notify("r1", "settled", {"amount": 100},
                  authority=auth, at=AT)
        out, rep = ws.recv_step("r1", 1, "wait", "settled",
                                authority=auth, at=AT)
        self.assertEqual((out, rep), ({"amount": 100}, False))
        code = _code_of(lambda: ws.recv_step(
            "r1", 1, "wait", "refunded", authority=auth, at=AT + 5))
        self.assertTrue(_expect_held(
            "F387-recv-event-drift-refuses",
            code == "workflow-step-unauthorized",
            "got code=%r (want workflow-step-unauthorized)" % (code,))
            == "HELD")

    def test_sleep_wakeat_drift_refuses_coded(self):
        ws, auth, _, _ = _fx()
        ws.start_run("wf", run_id="r2", authority=auth, at=AT)
        a1, x1 = ws.sleep_step("r2", 1, "nap", AT + 100,
                               authority=auth, at=AT, now=AT + 200)
        self.assertEqual((a1, x1), (True, False))
        code = _code_of(lambda: ws.sleep_step(
            "r2", 1, "nap", AT + 999999, authority=auth,
            at=AT + 5, now=AT + 200))
        self.assertTrue(_expect_held(
            "F387-sleep-wakeat-drift-refuses",
            code == "workflow-step-unauthorized",
            "got code=%r (want workflow-step-unauthorized)" % (code,))
            == "HELD")

    def test_recv_matching_event_still_replays(self):
        ws, auth, _, _ = _fx()
        ws.start_run("wf", run_id="r3", authority=auth, at=AT)
        ws.notify("r3", "settled", {"amount": 100},
                  authority=auth, at=AT)
        ws.recv_step("r3", 1, "wait", "settled",
                     authority=auth, at=AT)
        out, rep = ws.recv_step("r3", 1, "wait", "settled",
                                authority=auth, at=AT + 5)
        self.assertTrue(_expect_held(
            "F387-recv-matching-event-replays",
            (out, rep) == ({"amount": 100}, True),
            "honest replay must still return the payload") == "HELD")

    def test_sleep_matching_wakeat_still_replays(self):
        ws, auth, _, _ = _fx()
        ws.start_run("wf", run_id="r4", authority=auth, at=AT)
        ws.sleep_step("r4", 1, "nap", AT + 100,
                      authority=auth, at=AT, now=AT + 200)
        a2, x2 = ws.sleep_step("r4", 1, "nap", AT + 100,
                               authority=auth, at=AT + 5,
                               now=AT + 200)
        self.assertTrue(_expect_held(
            "F387-sleep-matching-wakeat-replays",
            (a2, x2) == (True, True),
            "honest replay must still return (True, True)") == "HELD")

    def test_recv_timeout_drift_refuses(self):
        ws, auth, _, _ = _fx()
        ws.start_run("wf", run_id="r5", authority=auth, at=AT)
        out, rep = ws.recv_step("r5", 1, "wait", "never-arrives",
                                authority=auth, at=AT, now=AT + 50,
                                timeout_at=AT + 10)
        self.assertEqual((out, rep), ({"timeout": True}, False))
        code = _code_of(lambda: ws.recv_step(
            "r5", 1, "wait", "other-event", authority=auth,
            at=AT + 6))
        self.assertTrue(_expect_held(
            "F387-recv-timeout-drift-refuses",
            code == "workflow-step-unauthorized",
            "got code=%r (want workflow-step-unauthorized)" % (code,))
            == "HELD")

    def test_authority_reproof_stays_first(self):
        # F380 ordering: a revoked ledger refuses
        # workflow-authority-revoked even when inputs also drift.
        ws, auth, ledger, root = _fx()
        ws.start_run("wf", run_id="r6", authority=auth, at=AT)
        ws.notify("r6", "settled", {"amount": 100},
                  authority=auth, at=AT)
        ws.recv_step("r6", 1, "wait", "settled",
                     authority=auth, at=AT)
        ledger.revoke(root["receipt_id"], AT + 5)
        revoked = dict(auth)
        code = _code_of(lambda: ws.recv_step(
            "r6", 1, "wait", "refunded", authority=revoked,
            at=AT + 6))
        self.assertTrue(_expect_held(
            "F387-authority-first",
            code == "workflow-authority-revoked",
            "got code=%r (want workflow-authority-revoked)" % (code,))
            == "HELD")


class PinTest(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_no_new_codes(self):
        # F387 reuses workflow-step-unauthorized; pin unchanged.
        self.assertIn("workflow-step-unauthorized",
                      decision_codes.TAXONOMY)


class RepinTest(unittest.TestCase):
    def test_pin_repin(self):
        with open(decision_codes.__file__, encoding="utf-8") as _f:
            src = _f.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertTrue(_expect_held(
            "repin-pin-1851",
            len(lits) == 2128 and len(set(lits)) == 2128


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
        # Wave-309 lane A: F393 CLOSED; footer open none / next F396.
        want_open, want_next = "none", "F407"
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
    batteries' green checks). Wave-305 merge: delegates to
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
        # Adjacent suite: the pre-existing workflow unit tests must
        # stay green under the F387 fix (depth-1; honors
        # GOV_SKIP_GREEN=1).
        result = _green_check_unittest("tests.test_workflow",
                                       "test_workflow")
        self.assertTrue(
            result.startswith("GREEN") or result.startswith("SKIPPED"),
            "adjacent suite not green: %r" % (result,))


_TEST_CLASSES = (F387Probes, PinTest, RepinTest, FooterStateTest,
                 GreenCheckTest)

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
