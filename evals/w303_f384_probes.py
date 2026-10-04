"""Wave-303 F384 regression battery: operator recovery of escalated sagas.

F384 (LOW, filed 2026-10-03, wave-302 independent red-team): escalated
sagas refused run/resume with no operator recovery API -- escalation
was terminal despite "until an operator intervenes".

Wave-303 lane 4 closes F384 with the operator recovery path in
gov/workflow_saga.py: ``describe_escalation`` (inspect) +
``resolve_escalation`` / ``retry_compensation`` (resolve), bound to the
same authority-verifier model as step authorities and re-verified NOW
at every recovery call.

Red-first provenance: on the pristine wave-302 base these probes BREAK
(no recovery API on SagaManager -- see the lane's repro script and the
w302_redteam F384-escalation-terminal probe); on the fixed tree they
are 0 BREAK / all HELD.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Deployment mode set at module level; also verified under
a clean environment.

Run:
  mkdir -p /var/tmp/g303-f384 && TMPDIR=/var/tmp/g303-f384 \
    ~/workspace/.gov-venv/bin/python evals/w303_f384_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g303-f384b \
    ~/workspace/.gov-venv/bin/python evals/w303_f384_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import decision_codes
from gov import ed25519 as _ed25519
from gov import workflow_saga as saga

if os.path.join(REPO, "evals") not in sys.path:
    sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check

TAXONOMY_PIN = 2045 # Wave-302 merge pin 1820; this lane: +2 workflow-saga-* (operator-unauthorized, resolution-invalid).; Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


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


def _escalated(tag, comp_fn=None, maxc=1, op_ref="op", op_ok=True):
    """Build an escalated saga: s1 succeeds, s2 fails, s1's compensation
    fails `maxc` time(s). Returns (mgr, inst)."""
    saga.clear_ops()
    saga.register_op("f384-a-%s" % tag, lambda p: ({"ok": 1}, []))
    def _bad(p):
        raise RuntimeError("downstream still down")
    saga.register_op("f384-c-%s" % tag, comp_fn or _bad)
    saga.register_op("f384-f-%s" % tag, lambda p: 1 / 0)
    mgr = saga.SagaManager(
        authority_verifiers={"op": lambda: op_ok} if op_ref else {},
        max_compensation_attempts=maxc,
        operator_authority_ref=op_ref)
    d = mgr.define([
        saga.SagaStepDef("s1", "f384-a-%s" % tag, {},
                         "f384-c-%s" % tag, {}),
        saga.SagaStepDef("s2", "f384-f-%s" % tag, {},
                         "f384-c-%s" % tag, {}),
    ])
    inst = mgr.start(d, saga_id="f384-%s" % tag)
    try:
        mgr.run(inst)
    except saga.SagaError:
        pass
    return mgr, inst


class RecoveryApiExistsTest(unittest.TestCase):
    def test_recovery_api_present(self):
        # F384 core: the operator recovery path must exist.
        for meth in ("describe_escalation", "resolve_escalation",
                     "retry_compensation"):
            self.assertTrue(_expect_held(
                "F384-api-%s" % meth,
                callable(getattr(saga.SagaManager, meth, None)),
                "SagaManager.%s missing" % meth) == "HELD")


class DescribeEscalationTest(unittest.TestCase):
    def test_describe_returns_failed_steps(self):
        mgr, inst = _escalated("desc")
        desc = mgr.describe_escalation(inst)
        self.assertTrue(_expect_held(
            "F384-describe",
            desc["status"] == "escalated"
            and desc["escalation_code"]
            == "workflow-saga-compensation-failed"
            and [s["step_id"] for s in desc["outstanding_steps"]] == ["s1"]
            and desc["outstanding_steps"][0]["comp_attempts"] == 1,
            "desc=%r" % (desc,)) == "HELD")
        # JSON-serializable: an operator tool can consume it.
        json.dumps(desc)

    def test_describe_refuses_non_escalated(self):
        mgr, inst = _escalated("desc2")
        saga.register_op("f384-c-desc2", lambda p: None)
        mgr.retry_compensation(inst)  # recover -> compensated
        self.assertTrue(_expect_coded(
            "F384-describe-non-escalated",
            lambda: mgr.describe_escalation(inst),
            {"workflow-saga-resolution-invalid"}) == "HELD")


class RetryCompensationTest(unittest.TestCase):
    def test_retry_with_valid_operator_recovers_and_journals(self):
        # (a) recovery with valid operator authority works and is
        # journaled.
        mgr, inst = _escalated("retry")
        saga.register_op("f384-c-retry", lambda p: None)  # downstream fixed
        mgr.retry_compensation(inst)
        types = [e["type"] for e in inst.history]
        self.assertTrue(_expect_held(
            "F384-retry-recovers",
            inst.status == "compensated"
            and "escalation_recovery_started" in types
            and "escalation_resolved" in types,
            "status=%r" % (inst.status,)) == "HELD")
        # (c) recovered saga terminates deterministically: run/resume
        # are safe no-ops.
        mgr.run(inst)
        mgr.resume(inst)
        self.assertTrue(_expect_held(
            "F384-recovered-terminates",
            inst.status == "compensated",
            "status=%r" % (inst.status,)) == "HELD")

    def test_retry_forged_operator_refuses_coded(self):
        # (b) forged operator authority refuses coded; escalation kept.
        mgr, inst = _escalated("forged", op_ok=False)
        self.assertTrue(_expect_coded(
            "F384-retry-forged-operator",
            lambda: mgr.retry_compensation(inst),
            {"workflow-saga-operator-unauthorized"}) == "HELD")
        self.assertTrue(_expect_held(
            "F384-forged-keeps-escalation",
            inst.status == "escalated",
            "status=%r" % (inst.status,)) == "HELD")

    def test_retry_missing_operator_ref_refuses_coded(self):
        # (b) no operator ref configured: fail closed.
        mgr, inst = _escalated("noop", op_ref=None)
        self.assertTrue(_expect_coded(
            "F384-retry-missing-operator",
            lambda: mgr.retry_compensation(inst),
            {"workflow-saga-operator-unauthorized"}) == "HELD")

    def test_operator_reverified_now_not_cached(self):
        # The operator verifier is re-verified at recovery time, not
        # cached: refuse-then-accept across a verifier flip.
        flip = {"ok": False}
        saga.clear_ops()
        saga.register_op("f384-a-flip", lambda p: ({"ok": 1}, []))
        def _down(p):
            raise RuntimeError("down")
        saga.register_op("f384-c-flip", _down)
        saga.register_op("f384-f-flip", lambda p: 1 / 0)
        mgr = saga.SagaManager(
            authority_verifiers={"op": lambda: flip["ok"]},
            max_compensation_attempts=1, operator_authority_ref="op")
        d = mgr.define([
            saga.SagaStepDef("s1", "f384-a-flip", {}, "f384-c-flip", {}),
            saga.SagaStepDef("s2", "f384-f-flip", {}, "f384-c-flip", {}),
        ])
        inst = mgr.start(d, saga_id="f384-flip")
        try:
            mgr.run(inst)
        except saga.SagaError:
            pass
        self.assertTrue(_expect_coded(
            "F384-operator-flip-refuse",
            lambda: mgr.retry_compensation(inst),
            {"workflow-saga-operator-unauthorized"}) == "HELD")
        saga.register_op("f384-c-flip", lambda p: None)
        flip["ok"] = True
        mgr.retry_compensation(inst)
        self.assertTrue(_expect_held(
            "F384-operator-flip-accept",
            inst.status == "compensated",
            "status=%r" % (inst.status,)) == "HELD")

    def test_double_recovery_refuses_coded(self):
        # (d) double-recovery of the same escalation is safe: refused
        # coded, not re-run.
        mgr, inst = _escalated("dbl")
        saga.register_op("f384-c-dbl", lambda p: None)
        mgr.retry_compensation(inst)
        self.assertTrue(_expect_coded(
            "F384-double-recovery",
            lambda: mgr.retry_compensation(inst),
            {"workflow-saga-resolution-invalid"}) == "HELD")
        self.assertTrue(_expect_held(
            "F384-double-keeps-status",
            inst.status == "compensated",
            "status=%r" % (inst.status,)) == "HELD")

    def test_retry_still_broken_reescalates_loud(self):
        # Re-driving a still-broken downstream re-escalates loudly --
        # never silently.
        mgr, inst = _escalated("stillbad")
        self.assertTrue(_expect_coded(
            "F384-retry-still-broken",
            lambda: mgr.retry_compensation(inst),
            {"workflow-saga-compensation-failed"}) == "HELD")
        types = [e["type"] for e in inst.history]
        self.assertTrue(_expect_held(
            "F384-still-escalated",
            inst.status == "escalated"
            and inst.escalation_code
            == "workflow-saga-compensation-failed",
            "status=%r" % (inst.status,)) == "HELD")
        # The failed recovery attempt is closed in the journal: a
        # started recovery never dangles without a resolution record.
        self.assertTrue(_expect_held(
            "F384-recovery-failed-journaled",
            "escalation_recovery_started" in types
            and "escalation_recovery_failed" in types
            and "escalation_resolved" not in types,
            "types=%r" % (types,)) == "HELD")

    def test_resolve_non_escalated_refuses_coded(self):
        mgr, inst = _escalated("nonesc")
        saga.register_op("f384-c-nonesc", lambda p: None)
        mgr.retry_compensation(inst)
        self.assertTrue(_expect_coded(
            "F384-resolve-non-escalated",
            lambda: mgr.resolve_escalation(
                inst, {"action": "retry_compensation"}),
            {"workflow-saga-resolution-invalid"}) == "HELD")

    def test_unknown_action_refuses_coded(self):
        mgr, inst = _escalated("unkact")
        self.assertTrue(_expect_coded(
            "F384-unknown-action",
            lambda: mgr.resolve_escalation(inst, {"action": "nuke_it"}),
            {"workflow-saga-resolution-invalid"}) == "HELD")


class AbortAndCompensateTest(unittest.TestCase):
    def test_abort_continues_pass_with_remaining_budget(self):
        mgr, inst = _escalated("abort", maxc=2)
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        attempts_before = st["comp_attempts"]
        saga.register_op("f384-c-abort", lambda p: None)  # fixed
        mgr.resolve_escalation(inst, {"action": "abort_and_compensate_all"})
        self.assertTrue(_expect_held(
            "F384-abort-recovers",
            inst.status == "compensated"
            and st["comp_attempts"] == attempts_before,
            "status=%r attempts=%r" % (inst.status,
                                       st["comp_attempts"])) == "HELD")


class ManualRemediationTest(unittest.TestCase):
    def test_accept_manual_remediation_marks_compensated(self):
        mgr, inst = _escalated("man")
        mgr.resolve_escalation(inst, {
            "action": "accept_manual_remediation",
            "step_ids": ["s1"],
        })
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        types = [e["type"] for e in inst.history]
        self.assertTrue(_expect_held(
            "F384-manual",
            inst.status == "compensated"
            and st["state"] == "compensated"
            and st.get("manual_remediation") is True
            and "manual_remediation_accepted" in types,
            "status=%r state=%r" % (inst.status, st["state"])) == "HELD")
        # Dump/load round-trips the attestation flag.
        data = json.loads(json.dumps(mgr.dump(inst)))
        inst2 = mgr.load(data)
        st2 = [s for s in inst2.steps if s["step_id"] == "s1"][0]
        self.assertTrue(_expect_held(
            "F384-manual-roundtrip",
            inst2.status == "compensated"
            and st2.get("manual_remediation") is True,
            "round-trip lost the attestation") == "HELD")

    def test_incomplete_attestation_refuses_coded(self):
        mgr, inst = _escalated("manbad")
        self.assertTrue(_expect_coded(
            "F384-manual-incomplete",
            lambda: mgr.resolve_escalation(inst, {
                "action": "accept_manual_remediation",
                "step_ids": [],
            }),
            {"workflow-saga-resolution-invalid"}) == "HELD")
        self.assertTrue(_expect_held(
            "F384-manual-keeps-escalation",
            inst.status == "escalated",
            "status=%r" % (inst.status,)) == "HELD")


class PinTest(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_new_codes_present(self):
        for code in ("workflow-saga-operator-unauthorized",
                     "workflow-saga-resolution-invalid"):
            self.assertIn(code, decision_codes.TAXONOMY)


class RepinTest(unittest.TestCase):
    def test_pin_repin(self):
        with open(decision_codes.__file__, encoding="utf-8") as _f:
            src = _f.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertTrue(_expect_held(
            "repin-pin-1851",
            len(lits) == 2045 and len(set(lits)) == 2045


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
        want_open, want_next = "none", "F407"  # wave-313 lane A: F397 CLOSED
        self.assertTrue(_expect_held(
            "footer-state",
            m_open and m_open[-1].strip() == want_open
            and m_next and m_next[-1] == want_next,
            "want open %s / next free %s (got %r / %r)"
            % (want_open, want_next,
               m_open[-1].strip() if m_open else None,
               m_next[-1] if m_next else None))
            == "HELD")


class GreenCheckTest(unittest.TestCase):
    def test_green_checks(self):
        # Real depth-1 green check via the shared fail-closed helper.
        # Wave-307: the previous stub returned "GREEN" without spawning
        # anything -- a vacuous pass. The F384 probes exercise
        # gov/workflow_saga.py operator recovery, so the adjacent saga
        # unit suite is the dependency under check. GOV_SKIP_GREEN=1 is
        # honored inside the helper (records a skip note, not a pass).
        verdict, note = green_check.check_unittest_result(
            "green-test-workflow-saga", "tests.test_workflow_saga",
            repo=REPO)
        self.assertEqual(verdict, "HELD", note)


if __name__ == "__main__":
    unittest.main()
