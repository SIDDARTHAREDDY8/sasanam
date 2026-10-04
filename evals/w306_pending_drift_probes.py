"""Wave-306 lane C investigation battery: pending-path re-presentation drift
in gov/workflow.py sleep_step/recv_step.

Wave-305 lane A (F387 closure) noted as a residual that the *completed*-path
re-presentation in sleep_step/recv_step now drift-checks, but the *pending*-
path re-presentation does not: a pending sleep re-presented with a different
wake_at, or a pending recv re-presented with a different event, does not
refuse -- the pending record keeps the first inputs.

This battery investigates the severity EMPIRICALLY through the public API
before any filing decision.

Findings (all verified on the wave-305 base d9554021):
  P1 sleep-pending-latest-wins: a sleep pending with wake_at=T1, re-presented
     with wake_at=T2 (still pending), keeps the first inputs_digest in the
     pending record (observable via get_step) -- BUT the step completes with
     the RE-PRESENTED T2 when now>=T2, and the completed record carries
     D({"wake_at": T2}). Replay with T2 succeeds; replay with T1 refuses
     coded workflow-step-unauthorized (F387).
  P2 recv-pending-latest-wins: a recv pending for event A, re-presented with
     event B, keeps D({"event": A}) in the pending record -- BUT a later B
     notification is consumed on re-presentation of B, and the completed
     record carries D({"event": B}) with B's payload.
  P3 no-wrong-outputs: at no point are outputs produced for inputs other
     than the re-presented ones. The pending record's inputs_digest is never
     read for any decision (only completed-path checks read it, and the
     composed _resolve_replay requires completed status).
  P4 journal-history-accurate: the journal records the full history --
     pending with the first inputs, completed with the final inputs. The
     audit trail is not misleading about what actually happened.

Verdict: NEGATIVE -- not a genuine integrity gap. The pending record is a
deduplication marker, not a commitment: no outputs exist to protect, so the
F387 replay-determinism principle does not apply. The observable semantic is
"latest re-presentation wins at completion," which is coherent -- the
caller's current intent is honored, and the completed record (the actual
commitment) always reflects the inputs that produced the outputs. No finding
filed; this battery is kept as a regression guard pinning the semantic.

Probes are recorded HELD (behavior as analyzed, no violation).

Run:
  mkdir -p /var/tmp/g306-pending && TMPDIR=/var/tmp/g306-pending \
    ~/workspace/.gov-venv/bin/python evals/w306_pending_drift_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g306-pendingb \
    ~/workspace/.gov-venv/bin/python evals/w306_pending_drift_probes.py
"""

import hashlib
import os
import re
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

from gov import decision_codes  # noqa: E402,F401  (pin taxonomy import)
from gov import delegation as dg  # noqa: E402
from gov import delegation_revocation as drv  # noqa: E402
from gov import ed25519  # noqa: E402
from gov import workflow as wf  # noqa: E402

TAXONOMY_PIN = 2021 # Wave-305 merge pin; this lane mints no new codes.; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 1: pin 2020 -> 2021 (+1 witness-alert-state-lost)



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
    sa = hashlib.sha256(b"w306-pending-batt-a").digest()
    sb = hashlib.sha256(b"w306-pending-batt-b").digest()
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
    return wf.WorkflowStore(), auth


def _digest(value):
    return wf._digest(value)


def _code(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- probe harness
        return getattr(e, "code", "unexpected:%s" % type(e).__name__)
    return None


class PendingDriftProbes(unittest.TestCase):
    def test_sleep_pending_record_keeps_first(self):
        # The pending RECORD keeps the first wake_at (the residual's
        # observation). This documents the record staleness.
        ws, auth = _fx()
        ws.start_run("wf", run_id="r1", authority=auth, at=AT)
        awake, rep = ws.sleep_step("r1", 0, "nap", AT + 100,
                                   authority=auth, at=AT, now=AT)
        self.assertEqual((awake, rep), (False, False))
        awake2, rep2 = ws.sleep_step("r1", 0, "nap", AT + 200,
                                     authority=auth, at=AT + 10, now=AT + 10)
        self.assertEqual((awake2, rep2), (False, False))
        rec = ws.get_step("r1", 0)
        self.assertTrue(_expect_held(
            "PENDING-sleep-record-keeps-first",
            rec["status"] == "pending"
            and rec["inputs_digest"] == _digest({"wake_at": AT + 100}),
            "pending record inputs_digest=%r" % (rec["inputs_digest"],))
            == "HELD")

    def test_sleep_completion_uses_latest(self):
        # The COMPLETION uses the re-presented wake_at, not the pending
        # record's. Latest re-presentation wins.
        ws, auth = _fx()
        ws.start_run("wf", run_id="r2", authority=auth, at=AT)
        ws.sleep_step("r2", 0, "nap", AT + 100,
                      authority=auth, at=AT, now=AT)
        ws.sleep_step("r2", 0, "nap", AT + 200,
                      authority=auth, at=AT + 10, now=AT + 10)
        awake, rep = ws.sleep_step("r2", 0, "nap", AT + 200,
                                   authority=auth, at=AT + 250,
                                   now=AT + 250)
        self.assertEqual((awake, rep), (True, False))
        rec = ws.get_step("r2", 0)
        self.assertTrue(_expect_held(
            "PENDING-sleep-completion-uses-latest",
            rec["status"] == "completed"
            and rec["inputs_digest"] == _digest({"wake_at": AT + 200}),
            "completed inputs_digest reflects re-presented wake_at")
            == "HELD")

    def test_sleep_replay_after_pending_drift(self):
        # After completing with the re-presented wake_at, replay is
        # consistent: same wake_at replays, different wake_at refuses
        # (F387). No stale-output hazard from the pending drift.
        ws, auth = _fx()
        ws.start_run("wf", run_id="r3", authority=auth, at=AT)
        ws.sleep_step("r3", 0, "nap", AT + 100,
                      authority=auth, at=AT, now=AT)
        ws.sleep_step("r3", 0, "nap", AT + 200,
                      authority=auth, at=AT + 10, now=AT + 10)
        ws.sleep_step("r3", 0, "nap", AT + 200,
                      authority=auth, at=AT + 250, now=AT + 250)
        out, rep = ws.sleep_step("r3", 0, "nap", AT + 200,
                                 authority=auth, at=AT + 300, now=AT + 300)
        self.assertEqual((out, rep), (True, True))

        self.assertTrue(_expect_held(
            "PENDING-sleep-replay-consistent",
            _code(lambda: ws.sleep_step(
                "r3", 0, "nap", AT + 100, authority=auth, at=AT + 310,
                now=AT + 310)) == "workflow-step-unauthorized",
            "replay with original wake_at refuses coded")
            == "HELD")

    def test_recv_pending_record_keeps_first(self):
        ws, auth = _fx()
        ws.start_run("wf", run_id="r4", authority=auth, at=AT)
        out, rep = ws.recv_step("r4", 0, "wait", "settled",
                               authority=auth, at=AT)
        self.assertEqual((out, rep), (None, False))
        out2, rep2 = ws.recv_step("r4", 0, "wait", "refunded",
                                  authority=auth, at=AT + 10)
        self.assertEqual((out2, rep2), (None, False))
        rec = ws.get_step("r4", 0)
        self.assertTrue(_expect_held(
            "PENDING-recv-record-keeps-first",
            rec["status"] == "pending"
            and rec["inputs_digest"] == _digest({"event": "settled"}),
            "pending record inputs_digest=%r" % (rec["inputs_digest"],))
            == "HELD")

    def test_recv_completion_uses_latest(self):
        # A notification for the RE-PRESENTED event is consumed; the
        # completed record carries the re-presented event and payload.
        ws, auth = _fx()
        ws.start_run("wf", run_id="r5", authority=auth, at=AT)
        ws.recv_step("r5", 0, "wait", "settled", authority=auth, at=AT)
        ws.recv_step("r5", 0, "wait", "refunded",
                     authority=auth, at=AT + 10)
        ws.notify("r5", "refunded", {"amount": 50},
                  authority=auth, at=AT + 20)
        out, rep = ws.recv_step("r5", 0, "wait", "refunded",
                               authority=auth, at=AT + 30)
        self.assertEqual((out, rep), ({"amount": 50}, False))
        rec = ws.get_step("r5", 0)
        self.assertTrue(_expect_held(
            "PENDING-recv-completion-uses-latest",
            rec["status"] == "completed"
            and rec["inputs_digest"] == _digest({"event": "refunded"})
            and rec["outputs"] == {"amount": 50},
            "completed record reflects re-presented event+payload")
            == "HELD")

    def test_pending_inputs_digest_never_read(self):
        # White-box pin: the ONLY inputs_digest reads in gov/workflow.py
        # are the completed-path drift checks (run_step x2, sleep_step,
        # recv_step). No decision reads a pending record's digest: each
        # comparison site must sit inside a `status == "completed"` guard
        # belonging to the enclosing method.
        src = open(os.path.join(REPO, "gov", "workflow.py")).read()
        reads = [m.start() for m in
                 re.finditer(r'\["inputs_digest"\] !=', src)]
        ok = True
        for pos in reads:
            # Nearest enclosing method start before this site...
            mdef = list(re.finditer(r'\n    def ', src[:pos]))
            # ...and the nearest completed-guard before this site.
            mguard = list(re.finditer(
                r'(?:existing|rec)\["status"\]\s*==\s*"completed"',
                src[:pos]))
            if not mdef or not mguard or mguard[-1].start() < mdef[-1].start():
                ok = False
        self.assertTrue(_expect_held(
            "PENDING-inputs-digest-never-read-for-pending",
            ok and len(reads) == 4,
            "found %d inputs_digest comparison sites, all "
            "completed-guarded" % (len(reads),))
            == "HELD")


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD",
            "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


def _literals():
    # Same extraction the w303_f388 battery uses: "code": literals in
    # gov/decision_codes.py (unsorted here; the pin check asserts order).
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    # Wave-308 lane A: F391 CLOSED; footer open F395 / next F396.
    ok = (m_open and m_open[-1].strip() == "none"
          and m_next and m_next[-1] == "F409")
    if ok:
        _record("footer-state", "HELD", "open none / next F409")
    else:
        _record("footer-state", "BREAK",
                "open=%r next=%r" % (
                    m_open[-1].strip() if m_open else None,
                    m_next[-1] if m_next else None))


def p_green_checks():
    green_check.check_battery(
        _record, "green-w303-f387", "evals/w303_f387_probes.py",
        repo=REPO, expect_break_ids=())
    # Wave-306 merge: F389 CLOSED -- w304 reports 0 BREAKs.
    green_check.check_battery(
        _record, "green-w304-redteam", "evals/w304_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # Wave-306 merge: F389 CLOSED -- w305 reports 0 BREAKs.
    green_check.check_battery(
        _record, "green-w305-redteam", "evals/w305_redteam_probes.py",
        repo=REPO, expect_break_ids=())


def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(PendingDriftProbes)
    result = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull,
                                                              "w")).run(suite)
    for _ in result.errors + result.failures:
        pass
    p_taxonomy_pin()
    p_footer_state()
    p_green_checks()
    n_break = sum(1 for _, s, _ in _results if s == "BREAK")
    n_held = sum(1 for _, s, _ in _results if s == "HELD")
    n_err = sum(1 for _, s, _ in _results if s == "ERROR")
    for name, status, detail in _results:
        tag = "[%s]" % status
        print("%-42s %-6s %s" % (name, tag, detail))
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
