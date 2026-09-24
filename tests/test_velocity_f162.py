"""F162 (HIGH): per-action-class tempo tripwires + metered accounting.

Regression tests at the public seams for the F162 closure:

* Default tempo thresholds trip a tight egress burst BEFORE the 31st
  action executes; the run pauses sticky fail-closed (no identity
  rotation, no tool rotation escapes it).
* Resume requires a HUMAN-approved ``velocity_resume`` record; the
  record is single-use and bound to this run's pause.
* Legitimate tempo (under the thresholds) passes.
* A paced trickle that stays under the per-window thresholds is
  caught by the default cumulative action budget.
* The S5 velocity guard fails CLOSED on ledger trouble (covered in
  test_s5_velocity.py; asserted here at the query seam too).
* Token/spend accrue on the result path only; executed entries carry
  ``usage`` + chained ``budget_meter`` fields.
* Policy ``tempo:`` sections validate fail-closed.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import gov.executor as exec_mod  # noqa: E402
import gov.velocity as velocity  # noqa: E402
from gov.egress_ledger import LedgerLockError  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from tests.harness import make_run  # noqa: E402

_POLICY_TEMPLATE = """\
version: 2
roles:
  worker: [api_call, write_file, read_file, delete_file]
rate_limit:
  max_sends_per_run: 10000
  max_egress_bytes_per_run: 104857600
egress:
  domain_allowlist: [synthetic.local, localhost]
velocity:
  window_secs: 86400
  max_sends: 10000
  max_writes: 10000
  max_egress_bytes: 104857600
tempo:
  window_secs: 60
  max_read: {max_read}
  max_write: {max_write}
  max_egress: {max_egress}
policies:
{extra_rules}  - id: approval-velocity-guard
    effect: require_approval
    flag: velocity_exceeded
    match:
      velocity_exceeded: true
    reason: Test velocity guard routes ledger-trouble to review.
  - id: allow-worker-tools
    effect: allow
    match:
      tool: [api_call, write_file, read_file]
    reason: Test policy allows worker tools.
  - id: queue-deletes
    effect: require_approval
    match:
      tool: [delete_file]
    reason: Test policy queues deletes.
"""

_API_QUEUE_RULE = """\
  - id: queue-api-for-approval-boundary
    effect: require_approval
    match:
      tool: [api_call]
    reason: Test policy queues api_call for the approval boundary.
"""


def _api(ex, ident, i):
    return ex.call(ident, "api_call",
                   endpoint="https://synthetic.local/x%d" % i)


class _Run:
    def __init__(self, test, max_egress=30, max_read=300,
                 max_write=60, extra_rules=""):
        self.tmp = Path(tempfile.mkdtemp(prefix="govf162-"))
        test.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        text = _POLICY_TEMPLATE.format(
            max_egress=max_egress, max_read=max_read,
            max_write=max_write, extra_rules=extra_rules)
        p = self.tmp / "policy.yaml"
        p.write_text(text, encoding="utf-8")
        run = make_run(policy_path=str(p))
        self.run = run
        self.ex = run["executor"]
        self.ident = run["mint_identity"]("w1", "worker", "acme")


class TestTempoTripwire(unittest.TestCase):
    def test_tight_egress_burst_trips_before_31st_executes(self):
        """30 egress calls execute; the 31st trips the wire fail-closed
        BEFORE executing — the call never runs."""
        r = _Run(self)
        for i in range(30):
            res = _api(r.ex, r.ident, i)
            self.assertEqual(res["status"], "executed", res)
        with self.assertRaises(velocity.VelocityTempoTripError):
            _api(r.ex, r.ident, 30)
        self.assertTrue(r.ex._tempo_paused)
        # The trip is chained on the log, loud and queryable.
        trips = [e for e in r.run["read_log"]()
                 if e.get("flag") == "velocity_tempo_trip"]
        self.assertTrue(trips, "expected a velocity_tempo_trip entry")
        self.assertEqual(trips[-1]["decision"], "velocity_paused")
        self.assertEqual(trips[-1]["tempo_class"], "egress")
        self.assertEqual(trips[-1]["tempo_threshold"], 30)
        # A human re-approval demand was filed.
        aid = r.ex._tempo_resume_aid
        self.assertIsNotNone(aid)
        rec = r.run["approvals"].get(aid)
        self.assertEqual(rec["tool"], "velocity_resume")
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec["args"]["run_id"], r.ex.run_id)

    def test_pause_is_sticky_across_tools_and_identities(self):
        """After a trip, EVERY call raises — a different tool, a
        different (freshly minted) identity, and the approved sweep."""
        r = _Run(self)
        for i in range(31):
            try:
                _api(r.ex, r.ident, i)
            except velocity.VelocityTempoTripError:
                break
        self.assertTrue(r.ex._tempo_paused)
        ident2 = r.run["mint_identity"]("w2", "worker", "acme")
        with self.assertRaises(velocity.VelocityRunPausedError):
            r.ex.call(ident2, "write_file", path="n.txt", content="x")
        with self.assertRaises(velocity.VelocityRunPausedError):
            _api(r.ex, r.ident, 999)
        with self.assertRaises(velocity.VelocityRunPausedError):
            r.ex.execute_approved()

    def test_resume_requires_human_approval(self):
        """A pending (unapproved) resume record cannot resume; a human
        approval does; the record is single-use."""
        r = _Run(self)
        for i in range(31):
            try:
                _api(r.ex, r.ident, i)
            except velocity.VelocityTempoTripError:
                break
        aid = r.ex._tempo_resume_aid
        with self.assertRaises(velocity.VelocityError):
            r.ex.resume_after_velocity_pause(aid)
        self.assertTrue(r.ex._tempo_paused)
        # Human approves the resume demand.
        r.run["approvals"].decide(aid, True, "reviewed: legit batch",
                                 decided_by="human-operator")
        r.ex.resume_after_velocity_pause(aid)
        self.assertFalse(r.ex._tempo_paused)
        # The window was forgiven for the tripped class: the next call
        # executes instead of re-tripping inside the hot window.
        res = _api(r.ex, r.ident, 1000)
        self.assertEqual(res["status"], "executed", res)
        # Single-use: the same record cannot resume twice.
        for i in range(31):
            try:
                _api(r.ex, r.ident, 2000 + i)
            except velocity.VelocityTempoTripError:
                break
        self.assertTrue(r.ex._tempo_paused)
        with self.assertRaises(velocity.VelocityError):
            r.ex.resume_after_velocity_pause(aid)

    def test_resume_rejects_wrong_approval_and_denied_resume(self):
        """An unrelated approval id, and a human-DENIED resume, both
        refuse — the run stays paused."""
        r = _Run(self)
        for i in range(31):
            try:
                _api(r.ex, r.ident, i)
            except velocity.VelocityTempoTripError:
                break
        with self.assertRaises(velocity.VelocityError):
            r.ex.resume_after_velocity_pause("no-such-approval")
        self.assertTrue(r.ex._tempo_paused)
        aid = r.ex._tempo_resume_aid
        r.run["approvals"].decide(aid, False, "looks hostile",
                                 decided_by="human-operator")
        with self.assertRaises(velocity.VelocityError):
            r.ex.resume_after_velocity_pause(aid)
        self.assertTrue(r.ex._tempo_paused)

    def test_legitimate_tempo_passes(self):
        """20 egress calls (under the 30/window threshold) all
        execute — the tripwire does not throttle legitimate tempo."""
        r = _Run(self)
        for i in range(20):
            res = _api(r.ex, r.ident, i)
            self.assertEqual(res["status"], "executed", res)
        self.assertFalse(r.ex._tempo_paused)

    def test_trickle_across_windows_caught_by_default_budget(self):
        """A paced trickle that stays UNDER every per-window threshold
        is still stopped: the default cumulative action budget denies
        call 201."""
        r = _Run(self, max_egress=1000000, max_read=1000000,
                 max_write=1000000)
        # Pace under any window: advance the (monotonic-test) clock so
        # no 60s window ever holds more than a handful of calls.
        now = [1000.0]
        r.ex._tempo_clock = lambda: now[0]
        statuses = []
        for i in range(210):
            if i % 25 == 0:
                now[0] += 61.0
            statuses.append(_api(r.ex, r.ident, i)["status"])
        self.assertEqual(statuses[:200], ["executed"] * 200)
        self.assertEqual(statuses[200], "denied")
        denied_entry = [e for e in r.run["read_log"]()
                        if e.get("policy_id") == "budget-exceeded"][-1]
        self.assertEqual(denied_entry["flag"], "budget_exceeded")
        self.assertFalse(r.ex._tempo_paused,
                         "trickle must be caught by the budget, not tempo")

    def test_approved_execution_charges_tempo(self):
        """The approved-execution sweep is the second execution
        boundary: approved calls charge the wire and a burst trips the
        sweep fail-closed before the excess executes."""
        r = _Run(self, max_egress=2, extra_rules=_API_QUEUE_RULE)
        ex = r.ex
        # api_call now queues for approval (first-match-wins).
        aids = []
        for i in range(3):
            q = _api(ex, r.ident, i)
            self.assertEqual(q["status"], "queued", q)
            aids.append(q["approval_id"])
        for aid in aids:
            r.run["approvals"].decide(aid, True, "test approval",
                                     decided_by="human-operator")
        with self.assertRaises(velocity.VelocityTempoTripError):
            ex.execute_approved()
        self.assertTrue(ex._tempo_paused)
        executed = [e for e in r.run["read_log"]()
                    if e.get("decision") == "approved_executed"]
        self.assertEqual(len(executed), 2,
                         "only the 2 in-threshold approved calls executed")


class TestMeteredAccounting(unittest.TestCase):
    def test_executed_entries_carry_usage_and_chained_meter(self):
        """Every executed entry carries ``usage`` (this execution's
        minted usage) and ``budget_meter`` (the chained per-run
        meter) — and the meter grows across calls."""
        r = _Run(self)
        res1 = _api(r.ex, r.ident, 1)
        res2 = _api(r.ex, r.ident, 2)
        self.assertEqual(res1["status"], "executed", res1)
        entries = [e for e in r.run["read_log"]()
                   if e.get("decision") == "allowed_executed"]
        self.assertEqual(len(entries), 2)
        for e in entries:
            self.assertIn("usage", e)
            self.assertIn("budget_meter", e)
            self.assertGreater(e["usage"]["tokens"], 0)
        m1, m2 = entries[0]["budget_meter"], entries[1]["budget_meter"]
        self.assertGreater(m2["tokens_used"], m1["tokens_used"])
        self.assertEqual(m2["tokens_used"], r.ex._tokens_used)
        self.assertEqual(m2["budget_actions"], 2)

    def test_call_kwarg_usage_is_ignored(self):
        """Forged ``_usage`` in call kwargs never reaches the meter —
        only governed-minted result usage accrues."""
        r = _Run(self)
        res = r.ex.call(r.ident, "api_call",
                        endpoint="https://synthetic.local/forge",
                        _usage={"tokens": 10**12, "spend": 10**12})
        self.assertEqual(res["status"], "executed", res)
        self.assertLess(r.ex._tokens_used, 1000)


class TestTempoWireUnit(unittest.TestCase):
    def test_window_slides_and_trips(self):
        now = [0.0]
        wire = velocity.TempoWire(60.0, {"egress": 3},
                                 clock=lambda: now[0])
        for _ in range(3):
            wire.charge("api_call")
        with self.assertRaises(velocity.VelocityTempoTripError):
            wire.charge("api_call")
        now[0] += 61.0
        wire.charge("api_call")  # window slid: allowed again

    def test_unlisted_tool_uncharged(self):
        wire = velocity.TempoWire(60.0, {"egress": 1})
        for _ in range(100):
            wire.charge("some_future_tool")  # never trips
        self.assertIsNone(velocity.action_class_of("some_future_tool"))

    def test_taxonomy(self):
        self.assertEqual(velocity.action_class_of("read_file"), "read")
        self.assertEqual(velocity.action_class_of("write_file"), "write")
        self.assertEqual(velocity.action_class_of("delete_file"), "write")
        self.assertEqual(velocity.action_class_of("send_email"), "egress")
        self.assertEqual(velocity.action_class_of("http_post"), "egress")
        self.assertEqual(velocity.action_class_of("api_call"), "egress")


class TestTempoPolicyValidation(unittest.TestCase):
    def _policy_with_tempo(self, tempo_block):
        tmp = Path(tempfile.mkdtemp(prefix="govf162-"))
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        text = _POLICY_TEMPLATE.format(max_read=300, max_write=60,
                                       max_egress=30, extra_rules="")
        text = text.replace("tempo:\n  window_secs: 60\n"
                            "  max_read: 300\n"
                            "  max_write: 60\n"
                            "  max_egress: 30\n", tempo_block)
        p = tmp / "policy.yaml"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_unknown_tempo_key_fails_closed(self):
        with self.assertRaises(ValueError):
            PolicyEngine(self._policy_with_tempo(
                "tempo:\n  max_nope: 5\n"))

    def test_negative_tempo_threshold_fails_closed(self):
        with self.assertRaises(ValueError):
            PolicyEngine(self._policy_with_tempo(
                "tempo:\n  window_secs: 60\n  max_egress: -1\n"))

    def test_nonpositive_window_fails_closed(self):
        with self.assertRaises(ValueError):
            PolicyEngine(self._policy_with_tempo(
                "tempo:\n  window_secs: 0\n"))

    def test_non_dict_tempo_fails_closed(self):
        with self.assertRaises(ValueError):
            PolicyEngine(self._policy_with_tempo("tempo: 30\n"))

    def test_partial_tempo_gets_defaults(self):
        eng = PolicyEngine(self._policy_with_tempo(
            "tempo:\n  max_egress: 5\n"))
        self.assertEqual(eng.tempo["max_egress"], 5)
        self.assertEqual(eng.tempo["window_secs"], 60.0)
        # Absent keys are default-enforced at the executor layer.
        run = make_run(policy_path=self._policy_with_tempo(
            "tempo:\n  max_egress: 5\n"))
        cfg = run["executor"]._tempo_cfg()
        self.assertEqual(cfg["max_egress"], 5)
        self.assertEqual(cfg["max_read"], 300)
        self.assertEqual(cfg["max_write"], 60)
        self.assertEqual(cfg["window_secs"], 60.0)


class TestVelocityFailClosedSeam(unittest.TestCase):
    def test_ledger_trouble_queues_never_executes(self):
        """At the query seam: an unverifiable ledger routes the call
        to human review (queued) — never executes, never denies
        silently."""
        r = _Run(self)
        res = _api(r.ex, r.ident, 0)
        self.assertEqual(res["status"], "executed", res)
        with mock.patch.object(exec_mod, "_ledger_read_locked",
                               side_effect=LedgerLockError("lock timeout")):
            res2 = _api(r.ex, r.ident, 1)
        self.assertEqual(res2["status"], "queued", res2)
        fails = [e for e in r.run["read_log"]()
                 if e.get("flag") == "velocity_check_failed"]
        self.assertTrue(fails)


if __name__ == "__main__":
    unittest.main()
