"""Wave-77 recovery: "get back to safe" as named, audited operations (2026-09-22).

Load-bearing claims under test (workstreams/architect/RECOVERY_DESIGN.md):
- checkpoint: MAC'd in its own domain, chained inside the journal
  (not a side file), RPO=0 on the clean path (measured latency)
- verify-before-resume: all 8 sub-checks run and are chained, even on
  fail; journal tamper between checkpoint and resume is caught
- resume: NEVER reuses the halted session's authority — the old
  session dies first; resume without fresh delegation is refused as
  resume_authority_not_reissued; sealed identities can never resume
- effect journal: recorded effects are never re-executed; ambiguous
  (started-but-unrecorded) effects go to the human decision, not an
  automatic retry
- halt: requires the halt-key MAC; agent credentials refused; wrong
  MAC domain refused; halt-key compromise is bounded (availability,
  not integrity)
- decommission: ordered revoke -> drain -> seal -> anchor; a fault at
  any step leaves status incomplete-<step>, never a silent partial
- trip -> recovery drain: no lost trips across a mid-write crash, no
  double-triggers across restarts (idempotent case ids)
- executor wiring: a halted identity is refused on the verdict path
  (sticky RecoveryHaltedError, loud audit)

Hermetic: temp dirs, synthetic deterministic, no network.
Deterministic except wall-clock ts (never asserted on).
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import recovery as _rec  # noqa: E402
from gov import detection as _det  # noqa: E402
from gov import log as _log  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

_BASE_POLICY = Path(_REPO_MAIN, "policies", "default.yaml").read_text()

IDENTITY = "u:u1/a:agent-9/d:deleg-1"


class _Ctx:
    """One hermetic recovery world: journal + controller + run dir."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir(parents=True)
        self.log = ActionLog(str(self.run_dir / "actions.jsonl"))
        self.ctl = _rec.RecoveryController(self.log, self.run_dir)

    def teardown(self):
        self.tmp.cleanup()


def _halt_body(ctl, identity=IDENTITY, reason="test", trips=()):
    return ctl.halt_authority.sign_halt(identity, reason, trips)


def _fresh(ctl, old="sess-old", new="sess-new", by="op:alice"):
    return ctl.issue_fresh_delegation(old_session_id=old,
                                      new_session_id=new,
                                      operator_principal=by)


class TestCheckpoint(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def test_checkpoint_pins_tail_rpo_zero(self):
        t0 = time.perf_counter()
        for i in range(3):
            self.c.log.append({"event": "note", "i": i})
        tail = self.c.log.tail_seq
        cp = self.c.ctl.checkpoint(IDENTITY)
        dt_ms = (time.perf_counter() - t0) * 1000
        # RPO = 0: the checkpoint pins the live tail exactly.
        self.assertEqual(cp["journal_seq"], tail)
        self.assertTrue(self.c.ctl._checkpoint_body_ok(cp))
        print("measured checkpoint latency: %.1f ms (objective < 1000)"
              % dt_ms)
        self.assertLess(dt_ms, 1000)

    def test_checkpoint_is_chained_not_a_side_file(self):
        cp = self.c.ctl.checkpoint(IDENTITY)
        entries = _log.read_entries(self.c.log.path)
        found = [e for e in entries
                 if e.get("event") == "recovery_checkpoint"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["mac"], cp["mac"])
        # It lives inside the HMAC chain: verify_chain covers it.
        ok, broken, _n = _log.verify_chain(self.c.log.path)
        self.assertTrue(ok, broken)

    def test_checkpoint_forged_mac_rejected(self):
        cp = self.c.ctl.checkpoint(IDENTITY)
        bad = dict(cp, journal_seq=cp["journal_seq"] + 99)
        self.assertFalse(self.c.ctl._checkpoint_body_ok(bad))
        bad2 = dict(cp, mac="0" * 64)
        self.assertFalse(self.c.ctl._checkpoint_body_ok(bad2))

    def test_superseded_checkpoint_refused(self):
        # F72's lesson at the recovery seam: the operator re-checkpoints
        # at halt time; replaying the older valid checkpoint is a
        # rollback and the gate refuses it.
        self.c.log.append({"event": "note"})
        old_cp = self.c.ctl.checkpoint(IDENTITY)
        self.c.log.append({"event": "note"})
        new_cp = self.c.ctl.checkpoint(IDENTITY)
        fresh = _fresh(self.c.ctl)
        v = self.c.ctl.verify_before_resume(
            old_cp, old_session_id="sess-old", fresh_delegation=fresh)
        self.assertEqual(v["checks"]["checkpoint_freshness"],
                         "fail-checkpoint-superseded")
        with self.assertRaisesRegex(_rec.RecoveryRefused,
                                    "checkpoint_freshness"):
            self.c.ctl.resume(old_cp, old_session_id="sess-old",
                              fresh_delegation=fresh,
                              operator_principal="op:alice")
        # The newest checkpoint still resumes.
        fresh2 = _fresh(self.c.ctl, new="sess-new2")
        stored = self.c.ctl.resume(new_cp, old_session_id="sess-old",
                                   fresh_delegation=fresh2,
                                   operator_principal="op:alice",
                                   policy_digest="sha256:abc")
        self.assertEqual(stored["event"], "agent_resumed")

    def test_checkpoint_mac_domain_separation(self):
        # A MAC minted under the journal domain (or any other domain)
        # is not a valid checkpoint MAC.
        cp = self.c.ctl.checkpoint(IDENTITY)
        forged = dict(cp)
        forged["mac"] = _rec._mac(self.c.ctl._recovery_key, "other-domain",
                                  _rec._canonical(
                                      {k: v for k, v in cp.items()
                                       if k not in ("mac",
                                                    "checkpoint_seq")}))
        self.assertFalse(self.c.ctl._checkpoint_body_ok(forged))


class TestVerifyGate(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def _resume_inputs(self):
        self.c.log.append({"event": "note"})
        cp = self.c.ctl.checkpoint(IDENTITY, voided_approvals=["ap-1"])
        return cp, _fresh(self.c.ctl)

    def test_verify_all_eight_checks_chained(self):
        t0 = time.perf_counter()
        cp, fresh = self._resume_inputs()
        v = self.c.ctl.verify_before_resume(
            cp, old_session_id="sess-old", fresh_delegation=fresh,
            policy_digest="sha256:abc")
        dt_ms = (time.perf_counter() - t0) * 1000
        self.assertEqual(v["verdict"], "pass")
        self.assertEqual(len(v["checks"]), 8)
        failed = [n for n, verdict in v["checks"].items()
                  if str(verdict).startswith("fail")]
        self.assertEqual(failed, [])
        # The unknown-policy-digest shape is graded honestly: with no
        # digest the sub-check is "unknown", not a silent pass.
        v2 = self.c.ctl.verify_before_resume(
            cp, old_session_id="sess-old", fresh_delegation=fresh)
        self.assertEqual(v2["checks"]["policy_pinned"],
                         "unknown-no-policy-digest")
        self.assertEqual(v2["verdict"], "pass")
        # The verification record itself is chained.
        entries = _log.read_entries(self.c.log.path)
        self.assertTrue(any(e.get("event") == "resume_verification"
                            for e in entries))
        print("measured verify-gate latency: %.1f ms (objective < 2000)"
              % dt_ms)
        self.assertLess(dt_ms, 2000)

    def test_journal_tamper_between_checkpoint_and_resume_caught(self):
        cp, fresh = self._resume_inputs()
        # F52-style run-dir writer rewrites a pre-checkpoint entry,
        # keeping the file length identical.
        path = Path(self.c.log.path)
        lines = path.read_text(encoding="utf-8").splitlines()
        victim = json.loads(lines[0])
        victim["event"] = "note-tampered!!"
        lines[0] = json.dumps(victim)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        v = self.c.ctl.verify_before_resume(
            cp, old_session_id="sess-old", fresh_delegation=fresh,
            policy_digest="sha256:abc")
        self.assertEqual(v["verdict"], "fail")
        self.assertEqual(v["checks"]["chain_to_checkpoint"], "fail")
        with self.assertRaises(_rec.RecoveryRefused):
            self.c.ctl.resume(cp, old_session_id="sess-old",
                              fresh_delegation=fresh,
                              operator_principal="op:alice",
                              policy_digest="sha256:abc")


class TestResumeAuthority(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def _cp(self):
        self.c.log.append({"event": "note"})
        return self.c.ctl.checkpoint(IDENTITY)

    def test_resume_replays_compromise_refused(self):
        # Halt an agent mid-compromise; resume under the SAME session
        # authority must be refused — restarting a compromised agent
        # without invalidating its authority replays the compromise.
        cp = self._cp()
        stale_attest = {"old_session_id": "sess-old",
                        "new_session_id": "sess-old",  # reuse!
                        "issued_by": "op:alice",
                        "issued_at": "2026-09-22T00:00:00Z"}
        with self.assertRaisesRegex(_rec.RecoveryRefused,
                                    "resume_authority_not_reissued"):
            self.c.ctl.resume(cp, old_session_id="sess-old",
                              fresh_delegation=stale_attest,
                              operator_principal="op:alice")
        # The refusal is loud: a chained resume_refused record.
        entries = _log.read_entries(self.c.log.path)
        refused = [e for e in entries
                   if e.get("event") == "resume_refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["reason"],
                         "resume_authority_not_reissued")

    def test_resume_with_fresh_authority_passes_and_kills_old(self):
        cp = self._cp()
        fresh = _fresh(self.c.ctl)
        stored = self.c.ctl.resume(cp, old_session_id="sess-old",
                                   fresh_delegation=fresh,
                                   operator_principal="op:alice",
                                   policy_digest="sha256:abc")
        self.assertEqual(stored["event"], "agent_resumed")
        self.assertEqual(stored["new_session_id"], "sess-new")
        # The old session's authority is dead: in the revocation
        # ledger BEFORE the resume record.
        self.assertTrue(
            self.c.ctl._revocations.is_revoked("session:sess-old"))
        entries = _log.read_entries(self.c.log.path)
        kinds = [e.get("event") for e in entries]
        self.assertLess(kinds.index("session_revoked"),
                        kinds.index("agent_resumed"))

    def test_resume_voids_in_flight_approvals(self):
        self.c.log.append({"event": "note"})
        cp = self.c.ctl.checkpoint(IDENTITY,
                                   voided_approvals=["ap-1", "ap-2"])
        fresh = _fresh(self.c.ctl)
        self.c.ctl.resume(cp, old_session_id="sess-old",
                          fresh_delegation=fresh,
                          operator_principal="op:alice",
                          policy_digest="sha256:abc")
        entries = _log.read_entries(self.c.log.path)
        voided = [e for e in entries
                  if e.get("event") == "approvals_voided"]
        self.assertEqual(len(voided), 1)
        self.assertEqual(voided[0]["voided_approval_ids"],
                         ["ap-1", "ap-2"])

    def test_sealed_identity_cannot_resume(self):
        self.c.log.append({"event": "note"})
        cp = self._cp()
        self.c.ctl.decommission(IDENTITY, operator_principal="op:alice",
                                halt_mac_body=_halt_body(self.c.ctl),
                                token_refs=["tok:1"],
                                approval_ids=["ap-1"])
        self.assertEqual(self.c.ctl.decommission_status(IDENTITY),
                         "complete")
        fresh = _fresh(self.c.ctl)
        with self.assertRaisesRegex(_rec.RecoveryRefused, "sealed"):
            self.c.ctl.resume(cp, old_session_id="sess-old",
                              fresh_delegation=fresh,
                              operator_principal="op:alice")

    def test_fresh_delegation_same_session_refused_at_issue(self):
        with self.assertRaises(_rec.RecoveryRefused):
            self.c.ctl.issue_fresh_delegation(old_session_id="s",
                                              new_session_id="s",
                                              operator_principal="op:a")


class TestEffectJournal(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def test_recorded_effects_never_reexecuted(self):
        ctl = self.c.ctl
        ctl.record_effect_started("fx-1", identity_key=IDENTITY,
                                  tool="send_email")
        ctl.record_effect_recorded("fx-1", identity_key=IDENTITY,
                                   tool="send_email", outcome="sent")
        cp = ctl.checkpoint(IDENTITY, effect_watermark=1)
        plan = ctl.replay_plan(cp)
        self.assertEqual(plan["skip_effect_ids"], ["fx-1"])
        self.assertEqual(plan["ambiguous_effect_ids"], [])

    def test_ambiguous_effect_goes_to_human_not_retry(self):
        # Tool call executed but outcome unrecorded at halt: the
        # resume plan must NOT re-execute it — it is ambiguous and
        # goes to the resume_or_halt decision as evidence.
        ctl = self.c.ctl
        ctl.record_effect_started("fx-9", identity_key=IDENTITY,
                                  tool="api_call")
        # No record_effect_recorded: the halt landed mid-effect.
        cp = ctl.checkpoint(IDENTITY)
        plan = ctl.replay_plan(cp)
        self.assertNotIn("fx-9", plan["skip_effect_ids"])
        self.assertEqual(plan["ambiguous_effect_ids"], ["fx-9"])
        fresh = _fresh(ctl)
        v = ctl.verify_before_resume(cp, old_session_id="sess-old",
                                     fresh_delegation=fresh,
                                     policy_digest="sha256:abc")
        self.assertIn("fx-9", v["ambiguous_effect_ids"])


class TestHalt(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def test_halt_without_credential_refused_loud(self):
        with self.assertRaisesRegex(_rec.RecoveryRefused, "halt_refused"):
            self.c.ctl.halt(IDENTITY, reason="x", trip_ids=[],
                             halt_mac_body=None)
        entries = _log.read_entries(self.c.log.path)
        self.assertTrue(any(e.get("event") == "halt_refused"
                            for e in entries))

    def test_halt_with_agent_credentials_refused(self):
        # The agent's own journal-domain MAC is not a halt credential.
        fake = {"identity_key": IDENTITY, "reason": "x", "trip_ids": [],
                "at": "2026-09-22T00:00:00Z"}
        fake["mac"] = _rec._mac(self.c.ctl._recovery_key, "agent-domain",
                                _rec._canonical(
                                    {k: v for k, v in fake.items()
                                     if k != "mac"}))
        with self.assertRaises(_rec.RecoveryRefused):
            self.c.ctl.halt(IDENTITY, reason="x", trip_ids=[],
                             halt_mac_body=fake)

    def test_halt_key_compromise_is_bounded(self):
        # The stolen halt key halts (availability) but cannot forge
        # journal entries, resume, or alter approvals: wrong domains.
        ctl = self.c.ctl
        body = _halt_body(ctl, reason="compromised-key-drill",
                          trips=["t1"])
        ctl.halt(IDENTITY, reason="compromised-key-drill",
                 trip_ids=["t1"], halt_mac_body=body)
        self.assertTrue(ctl.is_halted(IDENTITY))
        # ...but the halt MAC verifies in NO other domain:
        self.assertFalse(_rec._mac(b"wrong", _rec.HALT_DOMAIN, b"x")
                         == body["mac"])
        forged_cp = {"rcp_version": 1, "identity_key": IDENTITY,
                     "journal_seq": 1, "mac": body["mac"]}
        self.assertFalse(ctl._checkpoint_body_ok(forged_cp))
        # ...and the halt key cannot mint a resume attestation:
        attest = {"old_session_id": "a", "new_session_id": "b",
                  "issued_by": "attacker", "issued_at": "t",
                  "mac": body["mac"]}
        self.assertFalse(ctl._delegation_attest_ok(attest, "a"))

    def test_halt_is_idempotent(self):
        self.c.ctl.halt(IDENTITY, reason="r", trip_ids=[],
                         halt_mac_body=_halt_body(self.c.ctl))
        self.c.ctl.halt(IDENTITY, reason="r", trip_ids=[],
                         halt_mac_body=_halt_body(self.c.ctl))
        self.assertTrue(self.c.ctl.is_halted(IDENTITY))

    def test_halt_latch_stops_executor(self):
        # The kill-switch path through a real ToolExecutor.call():
        # halted identity is refused on the verdict path, sticky.
        run_dir = Path(self.c.tmp.name) / "exec"
        run_dir.mkdir()
        log = ActionLog(str(run_dir / "actions.jsonl"))
        policy = PolicyEngine.from_text(_BASE_POLICY)
        queue = ApprovalQueue(str(run_dir), log)
        ctl = _rec.RecoveryController(log, run_dir)
        ex = ToolExecutor(str(run_dir), policy, log, queue, recovery=ctl)
        ident = ex.mint_identity("agent-9", "scout", "u1")
        ctl.halt("agent-9", reason="drill", trip_ids=[],
                 halt_mac_body=ctl.halt_authority.sign_halt(
                     "agent-9", "drill", []))
        with self.assertRaises(_rec.RecoveryHaltedError):
            ex.call(ident, "read_file", path="/tmp/x")
        # Sticky: catching and calling again still raises.
        with self.assertRaises(_rec.RecoveryHaltedError):
            ex.call(ident, "read_file", path="/tmp/x")
        entries = _log.read_entries(log.path)
        denied = [e for e in entries
                  if e.get("flag") == "recovery_halted"]
        self.assertEqual(len(denied), 2)


class TestDecommission(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def _decom(self, **kw):
        kw.setdefault("operator_principal", "op:alice")
        kw.setdefault("halt_mac_body", _halt_body(self.c.ctl))
        kw.setdefault("token_refs", ["tok:1", "tok:2"])
        kw.setdefault("approval_ids", ["ap-1"])
        return self.c.ctl.decommission(IDENTITY, **kw)

    def test_decommission_refused_without_halt_key(self):
        with self.assertRaisesRegex(_rec.RecoveryRefused,
                                    "decommission_refused"):
            self.c.ctl.decommission(IDENTITY,
                                    operator_principal="op:alice",
                                    halt_mac_body={"mac": "nope"})
        self.assertEqual(self.c.ctl.decommission_status(IDENTITY),
                         "not-started")

    def test_agent_cannot_decommission_itself(self):
        # An agent-identity call presents no halt-key MAC: refused at
        # the trust-domain check before any step runs.
        ctl = self.c.ctl
        agent_mac = {"identity_key": IDENTITY, "reason": "self",
                     "trip_ids": [], "at": "t", "mac": "agent-forged"}
        with self.assertRaises(_rec.RecoveryRefused):
            ctl.decommission(IDENTITY, operator_principal="agent-9",
                             halt_mac_body=agent_mac)
        self.assertFalse(ctl.is_sealed(IDENTITY))

    def test_decommission_order_and_records(self):
        status = self._decom()
        self.assertEqual(status["status"], "complete")
        self.assertTrue(self.c.ctl.is_sealed(IDENTITY))
        self.assertTrue(self.c.ctl._revocations.is_revoked("tok:1"))
        self.assertTrue(self.c.ctl._revocations.is_revoked("tok:2"))
        entries = _log.read_entries(self.c.log.path)
        kinds = [e.get("event") for e in entries]
        for want in ("decommission_revoked", "decommission_drained",
                     "log_sealed", "final_anchor"):
            self.assertIn(want, kinds)
        self.assertLess(kinds.index("decommission_revoked"),
                        kinds.index("decommission_drained"))
        self.assertLess(kinds.index("decommission_drained"),
                        kinds.index("log_sealed"))
        self.assertLess(kinds.index("log_sealed"),
                        kinds.index("final_anchor"))
        drained = [e for e in entries
                   if e.get("event") == "decommission_drained"][0]
        self.assertEqual(drained["terminal_state"],
                         "cancelled-decommission-drain")

    def test_decommission_fault_is_incomplete_not_silent(self):
        for step in ("revoke", "drain", "seal", "anchor"):
            c = _Ctx()
            try:
                c.ctl._fault_step = step
                with self.assertRaises(RuntimeError):
                    c.ctl.decommission(
                        IDENTITY, operator_principal="op:alice",
                        halt_mac_body=c.ctl.halt_authority.sign_halt(
                            IDENTITY, "x", []),
                        token_refs=["tok:1"], approval_ids=["ap-1"])
                self.assertEqual(
                    c.ctl.decommission_status(IDENTITY),
                    "incomplete-%s" % step, step)
                entries = _log.read_entries(c.log.path)
                self.assertTrue(any(
                    e.get("event") == "decommission_incomplete"
                    and e.get("failed_at") == step for e in entries),
                    step)
            finally:
                c.teardown()

    def test_production_requires_explicit_keys(self):
        with self.assertRaisesRegex(_rec.RecoveryError,
                                    "explicit recovery_key"):
            _rec.RecoveryController(self.c.log, self.c.run_dir,
                                    deployment_mode="production")

    def test_keys_must_differ(self):
        k = b"k" * 32
        with self.assertRaisesRegex(_rec.RecoveryError, "must differ"):
            _rec.RecoveryController(self.c.log, self.c.run_dir,
                                    recovery_key=k, halt_key=k)


class TestTripDrain(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def test_drain_maps_trips_to_cases_no_double_trigger(self):
        mon = _det.BehavioralMonitor(run_dir=str(self.c.run_dir))
        for i in range(3):
            mon._trips_emitted.append({
                "detector_id": "d1", "identity_key": IDENTITY,
                "signal": "tool_call_rate", "trip_kind": "spike",
                "seq": i})
        trig = _rec.RecoveryTrigger(self.c.log, self.c.run_dir)
        first = trig.drain(mon)
        self.assertEqual(len(first), 3)
        # Second drain: nothing pending -> no new cases.
        self.assertEqual(trig.drain(mon), [])
        # Same trips re-queued (replay): seen set suppresses them.
        mon.requeue_trips([{"detector_id": "d1",
                            "identity_key": IDENTITY,
                            "signal": "tool_call_rate",
                            "trip_kind": "spike", "seq": 0}])
        self.assertEqual(trig.drain(mon), [])
        # And across a process restart: the seen set is on disk.
        trig2 = _rec.RecoveryTrigger(self.c.log, self.c.run_dir)
        mon.requeue_trips([{"detector_id": "d1",
                            "identity_key": IDENTITY,
                            "signal": "tool_call_rate",
                            "trip_kind": "spike", "seq": 1}])
        self.assertEqual(trig2.drain(mon), [])

    def test_drain_crash_loses_no_trips(self):
        mon = _det.BehavioralMonitor(run_dir=str(self.c.run_dir))
        trips = [{"detector_id": "d1", "identity_key": IDENTITY,
                  "signal": "tool_call_rate", "trip_kind": "spike",
                  "seq": i} for i in range(3)]
        mon._trips_emitted.extend(trips)
        trig = _rec.RecoveryTrigger(self.c.log, self.c.run_dir)
        # Sabotage the log write after the first trigger record.
        real_append = self.c.log.append
        calls = {"n": 0}

        def _flaky(event):
            if event.get("event") == "recovery_triggered":
                calls["n"] += 1
                if calls["n"] > 1:
                    raise OSError("injected mid-batch crash")
            return real_append(event)
        self.c.log.append = _flaky
        with self.assertRaises(OSError):
            trig.drain(mon)
        self.c.log.append = real_append
        # The unprocessed trips were re-queued: a fresh trigger
        # recovers all of them; the already-seen one is not doubled.
        trig2 = _rec.RecoveryTrigger(self.c.log, self.c.run_dir)
        recovered = trig2.drain(mon)
        self.assertEqual(len(recovered), 2)
        entries = _log.read_entries(self.c.log.path)
        triggered = [e for e in entries
                     if e.get("event") == "recovery_triggered"]
        case_ids = [e["case_id"] for e in triggered]
        self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_action_mapping(self):
        self.assertEqual(
            _rec.RecoveryTrigger.action_for_trip(
                {"trip_kind": "anchor_downgrade"}), "halt")
        self.assertEqual(
            _rec.RecoveryTrigger.action_for_trip(
                {"signal": "priv_escalation_attempts"}), "halt")
        self.assertEqual(
            _rec.RecoveryTrigger.action_for_trip(
                {"signal": "tool_call_rate", "trip_kind": "spike"}),
            "decision")


class TestResumeOrHaltDecision(unittest.TestCase):
    def setUp(self):
        self.c = _Ctx()

    def tearDown(self):
        self.c.teardown()

    def test_decision_record_chained_with_evidence(self):
        stored = self.c.ctl.decide(
            IDENTITY, decision="keep_halted",
            operator_principal="op:alice",
            evidence={"trip_ids": ["t1"],
                      "verification": "fail:chain_to_checkpoint"})
        self.assertEqual(stored["event"], "resume_or_halt_decision")
        self.assertEqual(stored["decision"], "keep_halted")
        with self.assertRaises(_rec.RecoveryRefused):
            self.c.ctl.decide(IDENTITY, decision="maybe",
                              operator_principal="op:alice", evidence={})


if __name__ == "__main__":
    unittest.main()
