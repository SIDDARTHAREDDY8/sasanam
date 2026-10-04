"""Wave-303 F380 closure battery: workflow authority re-verification.

F380 (MEDIUM, filed 2026-10-03 by the wave-302 independent red team):
``gov/workflow.py`` treated the revocation ledger as optional in
``_verify_authority`` (a revoked chain authorized when the caller
omitted the ledger), and the completed-step replay path in
``run_step`` returned recorded outputs BEFORE ``_verify_authority`` --
so ``replay()`` performed NO authority check at all, including the
actor binding.

Closed 2026-10-03 by wave-303 lane 1:
  1. The revocation ledger is REQUIRED on every authority
     verification -- an authority without one fails closed coded
     ``workflow-authority-revoked`` (the F378 precedent).
  2. ``run_step`` re-proves authority on EVERY entry, before the
     completed-step replay paths (seq-slot and step-level
     idempotency-key). ``replay()`` delegates to ``run_step``, so it
     inherits the re-verification.
  3. Same defect class closed in ``sleep_step`` and ``recv_step``:
     their completed paths also re-prove authority before trusting
     the checkpoint.

Red-first provenance: the three core attacks were reproduced on the
pristine wave-302-merge base (c18ed4c7) via the w302 red-team
battery's own probes (3 BREAK / 2 HELD); the sleep/recv variants were
reproduced with throwaway scripts before this battery was written.
This battery is 0 BREAK / all HELD on the fixed tree.

Base: wave-302 merge c18ed4c7b4025d1949b2042aa1ff202e856d6b6f.
Pin 1820 at lane time (this lane mints no decision codes). Next free
F385 at lane time (F380 CLOSED by this lane; F381-F384 still OPEN).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g303-f380 && TMPDIR=/var/tmp/g303-f380 \\
    ~/workspace/.gov-venv/bin/python evals/w303_f380_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g303-f380b \\
    ~/workspace/.gov-venv/bin/python evals/w303_f380_probes.py
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
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

from gov import delegation as dg
from gov import delegation_revocation as rev
from gov import ed25519 as _ed25519
from gov import workflow as wf

TAXONOMY_PIN = 2052 # Wave-302 merge pin 1820; this lane mints no codes.; Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



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


def _seed(tag):
    return hashlib.sha256(("w303-f380-%s" % tag).encode()).digest()


def _pub(seed):
    return _ed25519.publickey(seed).hex()


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


_AT = 1_700_000_000


def _chain(seed, delegator_id, delegatee_id, delegatee_pub):
    cons = {"expires_at": _AT + 3600, "max_depth": 4,
            "allowed_targets": [delegatee_id]}
    return dg.issue(seed, delegator_id, delegatee_id, delegatee_pub,
                    ["tool.invoke"], issued_at=_AT, constraints=cons)


def _auth(chain, actor="agent-b", ledger="default", seed_tag="f380-root"):
    d = {"actor_id": actor, "action": "tool.invoke", "chain": chain,
         "trust_roots": [_pub(_seed(seed_tag))]}
    if ledger == "default":
        d["revocation_ledger"] = rev.DelegationRevoker(
            _seed(seed_tag), "agent-a")
    elif ledger is not None:
        d["revocation_ledger"] = ledger
    return d


def _revoked():
    sa = _seed("f380-root")
    sb = _seed("f380-agent")
    chain = [_chain(sa, "agent-a", "agent-b", _pub(sb))]
    ledger = rev.DelegationRevoker(sa, "agent-a")
    ledger.revoke(chain[0]["receipt_id"], _AT + 5)
    return sa, chain, ledger


class BaseStateTest(unittest.TestCase):
    def test_footer_state(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        # Wave-303 F380 closure lane: F380 CLOSED; F381-F384 still OPEN.
        ok = (m_open and m_open[-1].strip()
              == "F411"
              and m_next and m_next[-1] == "F412")
        self.assertTrue(_expect_held(
            "footer-state", ok,
            "want open F406 / next free F407")
            == "HELD")

    def test_pin(self):
        lits = _literals()
        ok = (len(lits) == TAXONOMY_PIN and len(set(lits)) == TAXONOMY_PIN
              and lits == sorted(lits))
        self.assertTrue(_expect_held(
            "pin-taxonomy", ok,
            "%d/%d/0 sorted" % (len(lits), len(set(lits)))) == "HELD")


class LedgerRequiredTest(unittest.TestCase):
    """F380 (a): every authority verification fails closed when the
    revocation ledger is absent -- the F378 precedent."""

    def test_start_run_no_ledger_refuses(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        self.assertTrue(_expect_coded(
            "F380-ledger-start-run",
            lambda: store.start_run(
                "etl", run_id="r1", authority=_auth(chain, ledger=None),
                at=_AT),
            {"workflow-authority-revoked"}) == "HELD")

    def test_run_step_no_ledger_refuses(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r2", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-ledger-run-step",
            lambda: store.run_step(
                "r2", 0, "s0", lambda i: {"done": 1},
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_run_step_revoked_no_ledger_refuses_revoked(self):
        # The original F380 break: a REVOKED chain authorized when the
        # ledger was omitted. Now the refusal is coded
        # workflow-authority-revoked either way.
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r3", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-ledger-revoked-no-ledger",
            lambda: store.run_step(
                "r3", 0, "s0", lambda i: {"done": 1},
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_replay_no_ledger_refuses(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r4", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-ledger-replay",
            lambda: store.replay(
                "r4", [{"seq": 0, "name": "s0",
                        "fn": lambda i: {"v": 1}, "inputs": {}}],
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_notify_no_ledger_refuses(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r5", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-ledger-notify",
            lambda: store.notify(
                "r5", "ev", {"k": 1},
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_complete_run_no_ledger_refuses(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r6", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-ledger-complete-run",
            lambda: store.complete_run(
                "r6", authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_revoked_chain_with_ledger_refuses(self):
        # Control: the presented ledger names the revoked receipt.
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r7", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-ledger-revoked-with-ledger",
            lambda: store.run_step(
                "r7", 0, "s0", lambda i: {"done": 1},
                authority=_auth(chain, ledger=ledger), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")


class ReplayReverificationTest(unittest.TestCase):
    """F380 (b): the completed-step replay paths re-verify authority
    (incl. the actor binding) before returning recorded outputs."""

    def test_completed_replay_reverifies_revoked(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r8", authority=_auth(chain), at=_AT)
        store.run_step("r8", 0, "s0", lambda i: {"v": 1},
                       authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-replay-revoked-no-ledger",
            lambda: store.replay(
                "r8", [{"seq": 0, "name": "s0",
                        "fn": lambda i: {"evil": 1}, "inputs": {}}],
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_completed_replay_cross_actor_refuses(self):
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r9", authority=_auth(chain), at=_AT)
        store.run_step("r9", 0, "s0", lambda i: {"secret": "A"},
                       authority=_auth(chain), at=_AT)
        garbage = {"actor_id": "mallory", "action": "tool.invoke",
                   "chain": [], "trust_roots": [],
                   "revocation_ledger": rev.DelegationRevoker(
                       _seed("f380-root"), "agent-a")}
        self.assertTrue(_expect_coded(
            "F380-replay-cross-actor",
            lambda: store.replay(
                "r9", [{"seq": 0, "name": "s0",
                        "fn": lambda i: {"evil": 1}, "inputs": {}}],
                authority=garbage, at=_AT + 10),
            {"workflow-step-unauthorized"}) == "HELD")

    def test_idempotency_key_replay_reverifies(self):
        # The step-level idempotency-key completed path is a replay
        # path too: it must re-verify authority.
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r10", authority=_auth(chain), at=_AT)
        store.run_step("r10", 0, "s0", lambda i: {"v": 1},
                       idempotency_key="K", authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-idemkey-replay-reverifies",
            lambda: store.run_step(
                "r10", 5, "s0", lambda i: {"evil": 1}, idempotency_key="K",
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_sleep_completed_reverifies(self):
        # Same defect class in sleep_step's completed path.
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r11", authority=_auth(chain), at=_AT)
        store.sleep_step("r11", 0, "wait", wake_at=_AT,
                         authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-sleep-completed-reverifies",
            lambda: store.sleep_step(
                "r11", 0, "wait", wake_at=_AT,
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_recv_completed_reverifies(self):
        # Same defect class in recv_step's completed path.
        sa, chain, ledger = _revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r12", authority=_auth(chain), at=_AT)
        store.notify("r12", "ev", {"p": 1},
                     authority=_auth(chain), at=_AT)
        store.recv_step("r12", 0, "wait-ev", "ev",
                        authority=_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-recv-completed-reverifies",
            lambda: store.recv_step(
                "r12", 0, "wait-ev", "ev",
                authority=_auth(chain, ledger=None), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")


class HonestPathTest(unittest.TestCase):
    """The fix must not break honest deployments: a fresh chain with a
    presented ledger executes, replays, and resumes normally."""

    def test_fresh_chain_executes_and_replays(self):
        sa, chain, ledger = _revoked()
        fresh_ledger = rev.DelegationRevoker(_seed("f380-root"), "agent-a")
        auth = _auth(chain, ledger=fresh_ledger)
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r13", authority=auth, at=_AT)
        out, replayed = store.run_step(
            "r13", 0, "s0", lambda i: {"ok": 1}, authority=auth, at=_AT)
        ok = (out == {"ok": 1} and replayed is False)
        out2, replayed2 = store.run_step(
            "r13", 0, "s0", lambda i: {"evil": 2}, authority=auth,
            at=_AT + 10)
        ok = ok and out2 == {"ok": 1} and replayed2 is True
        res = store.replay(
            "r13", [{"seq": 0, "name": "s0", "fn": lambda i: {"e": 3},
                     "inputs": {}}], authority=auth, at=_AT + 20)
        ok = ok and res[0][4] == {"ok": 1} and res[0][3] is True
        self.assertTrue(_expect_held(
            "F380-honest-execute-replay", ok,
            "honest path with presented ledger broken") == "HELD")

    def test_sleep_recv_honest(self):
        fresh_ledger = rev.DelegationRevoker(_seed("f380-root"), "agent-a")
        sa = _seed("f380-root")
        sb = _seed("f380-agent")
        chain = [_chain(sa, "agent-a", "agent-b", _pub(sb))]
        auth = _auth(chain, ledger=fresh_ledger)
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="r14", authority=auth, at=_AT)
        awake, rp = store.sleep_step("r14", 0, "wait", wake_at=_AT,
                                     authority=auth, at=_AT)
        awake2, rp2 = store.sleep_step("r14", 0, "wait", wake_at=_AT,
                                       authority=auth, at=_AT + 10)
        store.notify("r14", "ev", {"p": 1}, authority=auth, at=_AT)
        p1, _ = store.recv_step("r14", 1, "w", "ev", authority=auth,
                                at=_AT)
        p2, rp3 = store.recv_step("r14", 1, "w", "ev", authority=auth,
                                  at=_AT + 10)
        ok = (awake and rp is False and awake2 and rp2 is True
              and p1 == {"p": 1} and p2 == {"p": 1} and rp3 is True)
        self.assertTrue(_expect_held(
            "F380-honest-sleep-recv", ok,
            "honest sleep/recv path broken") == "HELD")


def _green_check(battery, expect):
    # Exact-summary form, wave-305: delegates to evals/green_check.py
    # (fail-closed contract). Returns (status, detail) as before.
    return green_check.check_battery_result(
        "green-check", os.path.join("evals", battery), repo=REPO,
        expected_summary=expect)


def _green_check_unittest(path, label):
    # Unittest-suite form, wave-305: delegates to evals/green_check.py.
    # Returns (status, detail) as before.
    return green_check.check_unittest_result(label, path, repo=REPO)


class GreenCheckTest(unittest.TestCase):
    def test_green_w301_workflow(self):
        status, detail = _green_check(
            "w301_workflow_probes.py",
            "w301_workflow: 0 BREAK / 15 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w301-workflow", status == "HELD", detail) == "HELD")

    def test_green_w302_workflow_composed(self):
        status, detail = _green_check(
            "w302_workflow_composed_probes.py",
            "w302_workflow_composed: 0 BREAK / 16 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w302-workflow-composed", status == "HELD", detail)
            == "HELD")

    def test_green_w302_workflow_approval(self):
        status, detail = _green_check(
            "w302_workflow_approval_probes.py",
            "== 0 BREAK / 14 HELD / 0 ERROR ==")
        self.assertTrue(_expect_held(
            "green-w302-workflow-approval", status == "HELD", detail)
            == "HELD")

    def test_green_w302_branch(self):
        status, detail = _green_check_unittest(
            "evals.w302_branch_probes", "w302_branch")
        self.assertTrue(_expect_held(
            "green-w302-branch", status == "HELD", detail) == "HELD")

    def test_green_test_workflow(self):
        status, detail = _green_check_unittest(
            "tests.test_workflow", "test_workflow")
        self.assertTrue(_expect_held(
            "green-test-workflow", status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, LedgerRequiredTest,
                ReplayReverificationTest, HonestPathTest, GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    n_break = sum(1 for _, s, _ in _results if s == "BREAK")
    n_held = sum(1 for _, s, _ in _results if s == "HELD")
    n_err = sum(1 for _, s, _ in _results if s == "ERROR")
    print("w303_f380: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    return result


if __name__ == "__main__":
    main()
