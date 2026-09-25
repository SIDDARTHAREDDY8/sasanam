"""F167 (MEDIUM): the F162 tempo pause must survive executor rotation.

The F162 tempo tripwire pauses the run sticky across identities — but
pre-fix the pause (``_tempo_paused``) lived only in executor memory, so
a fresh executor constructed over the same run_dir (the documented F60
deployment pattern: fresh executor per sweep) started unpaused and
executed freely.

These tests drive the public seams — ``ToolExecutor(...)``
construction over a shared run_dir and ``call()`` raising
``VelocityRunPausedError`` — and assert the user-visible containment
behavior, not private helpers.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov.executor import ToolExecutor  # noqa: E402
import gov.velocity as velocity  # noqa: E402
from tests.harness import make_run  # noqa: E402

_POLICY = """\
version: 2
roles:
  worker: [api_call, read_file, write_file]
rate_limit:
  max_sends_per_run: 10000
  max_egress_bytes_per_run: 104857600
tempo:
  window_secs: 60
  max_read: 300
  max_write: 60
  max_egress: 30
policies:
  - id: test-allow-api
    effect: allow
    match:
      tool: [api_call]
    reason: Test policy allows api_call.
"""


def _run(test):
    tmp = Path(tempfile.mkdtemp(prefix="govf167-"))
    test.addCleanup(__import__("shutil").rmtree, tmp, True)
    p = tmp / "policy.yaml"
    p.write_text(_POLICY, encoding="utf-8")
    return make_run(policy_path=str(p))


def _trip(ex, ident):
    """Drive a tight egress burst until the tempo wire trips."""
    for i in range(60):
        try:
            ex.call(ident, "api_call",
                    endpoint="https://synthetic.local/t%d" % i)
        except velocity.VelocityTempoTripError:
            return
    raise AssertionError("tempo wire did not trip")


def _rotated(run):
    """Fresh executor over the SAME run (F60 pattern): same run_dir,
    policy, log, approvals, and the run's own ledger."""
    return ToolExecutor(
        run["run_dir"], run["policy"], run["log"], run["approvals"],
        ledger_path=run["run_dir"] / "egress_ledger.jsonl",
        ungoverned_ack=("f167 test: re-construction over the same run "
                        "dir; raw pipeline by design"))


class TestPauseSurvivesRotation(unittest.TestCase):
    def test_rotation_preserves_pause(self):
        """Trip on ex1; a rotated ex2 over the same run_dir must refuse
        every call with VelocityRunPausedError (containment holds)."""
        run = _run(self)
        ex1 = run["executor"]
        ident = run["mint_identity"]("w1", "worker", "acme")
        _trip(ex1, ident)
        self.assertTrue(ex1._tempo_paused)

        ex2 = _rotated(run)
        ident2 = ex2.mint_identity("w2", "worker", "acme")
        with self.assertRaises(velocity.VelocityRunPausedError):
            ex2.call(ident2, "api_call",
                     endpoint="https://synthetic.local/after")

    def test_resume_on_rotated_executor_clears_pause_exactly_once(self):
        """The human-approved velocity_resume flow works on the rotated
        executor (via the auto-filed record's operator branch) and the
        record stays single-use."""
        run = _run(self)
        ex1 = run["executor"]
        ident = run["mint_identity"]("w1", "worker", "acme")
        _trip(ex1, ident)
        aid = ex1._tempo_resume_aid
        self.assertIsNotNone(aid)

        ex2 = _rotated(run)
        # Still paused before the human approves.
        with self.assertRaises(velocity.VelocityRunPausedError):
            ex2.call(ex2.mint_identity("w2", "worker", "acme"),
                     "api_call", endpoint="https://synthetic.local/x")
        # Human approves the auto-filed resume demand; the rotated
        # executor resumes through the operator-filed branch.
        run["approvals"].decide(aid, True, "reviewed: legit batch",
                                decided_by="human-operator")
        out = ex2.resume_after_velocity_pause(aid)
        self.assertEqual(out["status"], "resumed")
        # The run executes again after resume...
        res = ex2.call(ex2.mint_identity("w3", "worker", "acme"),
                       "api_call", endpoint="https://synthetic.local/ok")
        self.assertEqual(res["status"], "executed", res)
        # ...and a rotated executor built after the resume sees the
        # cleared pause too (no stale pause resurrected from the log).
        ex3 = _rotated(run)
        res = ex3.call(ex3.mint_identity("w4", "worker", "acme"),
                       "api_call", endpoint="https://synthetic.local/ok2")
        self.assertEqual(res["status"], "executed", res)
        # Single-use: the consumed record cannot resume a later pause.
        _trip(ex2, ex2.mint_identity("w5", "worker", "acme"))
        with self.assertRaises(velocity.VelocityError):
            ex2.resume_after_velocity_pause(aid)

    def test_fresh_run_dir_starts_unpaused(self):
        """A fresh run_dir never inherits a stale pause."""
        run = _run(self)
        ex1 = run["executor"]
        ident = run["mint_identity"]("w1", "worker", "acme")
        _trip(ex1, ident)
        self.assertTrue(ex1._tempo_paused)

        run2 = _run(self)
        res = run2["executor"].call(
            run2["mint_identity"]("w1", "worker", "acme"),
            "api_call", endpoint="https://synthetic.local/fresh")
        self.assertEqual(res["status"], "executed", res)

    def test_planted_resume_line_does_not_unpause(self):
        """A forged velocity_resumed line without the log's chain
        bookkeeping (seq/hash) is never trusted by the rehydration
        scan — only real chained entries count."""
        run = _run(self)
        ex1 = run["executor"]
        ident = run["mint_identity"]("w1", "worker", "acme")
        _trip(ex1, ident)

        log_path = run["run_dir"] / "actions.jsonl"
        with log_path.open("a", encoding="utf-8") as f:
            f.write('{"event": "tool_call", "run_id": %r, "tool": '
                    '"velocity_resume", "decision": "velocity_resumed"}\n'
                    % ex1.run_id)
        ex2 = _rotated(run)
        with self.assertRaises(velocity.VelocityRunPausedError):
            ex2.call(ex2.mint_identity("w2", "worker", "acme"),
                     "api_call", endpoint="https://synthetic.local/x")

    def test_trip_record_is_chained_when_pause_reports(self):
        """Whenever the pause is set, the velocity_paused record exists
        in the chained log — the audit trail is the pause's source of
        truth (append-before-flag ordering)."""
        run = _run(self)
        ex1 = run["executor"]
        ident = run["mint_identity"]("w1", "worker", "acme")
        _trip(ex1, ident)
        paused_entries = [e for e in run["read_log"]()
                          if e.get("decision") in ("velocity_paused",
                                                   "velocity_resumed")]
        self.assertTrue(paused_entries,
                        "expected a chained pause/resume entry")
        self.assertEqual(paused_entries[-1]["decision"], "velocity_paused")
        # And the rotated executor agrees with the log.
        ex2 = _rotated(run)
        with self.assertRaises(velocity.VelocityRunPausedError):
            ex2.call(ex2.mint_identity("w2", "worker", "acme"),
                     "api_call", endpoint="https://synthetic.local/x")


if __name__ == "__main__":
    unittest.main()
