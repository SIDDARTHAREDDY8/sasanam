"""S5 (K-052): cross-run per-principal velocity guard.

Verifies the executor rebase onto the landed F74 egress-ledger lock:
the velocity query reuses ``_ledger_read_locked`` and the velocity
record goes through ``EgressLedger.append`` (which holds
``_ledger_write_locked`` internally) — S5 adds NO competing lock.
The guard is heuristic: it queues (never denies), fails open with a
loud ``velocity_check_skipped`` audit entry on ledger trouble, and is
unenforced when the ``velocity:`` policy section is absent.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import gov.executor as exec_mod  # noqa: E402
import gov.egress_ledger as ledger_mod  # noqa: E402
from gov.egress_ledger import LedgerLockError  # noqa: E402
from tests.harness import make_run  # noqa: E402

_VELOCITY_POLICY = """\
version: 2
roles:
  sender: [read_file, send_email, write_file, api_call]
rate_limit:
  max_sends_per_run: 10
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
velocity:
  window_secs: 3600
  max_sends: {max_sends}
  max_writes: 100
  max_egress_bytes: 1000000
policies:
  - id: test-allow-sends
    effect: allow
    match:
      tool: [send_email]
      domain_allowlisted: true
    reason: Test policy allows sends.
  - id: test-allow-writes
    effect: allow
    match:
      tool: [write_file]
      path_outside_sandbox: false
    reason: Test policy allows sandbox writes.
  - id: test-queue-writes-for-approval-boundary
    effect: require_approval
    match:
      tool: [write_file]
      path_outside_sandbox: true
    reason: Test policy queues outside-sandbox writes.
  - id: approval-velocity-guard
    effect: require_approval
    flag: velocity_exceeded
    match:
      velocity_exceeded: true
    reason: Test velocity guard.
"""


def _write_policy(tmp, max_sends=2):
    p = tmp / "velocity_policy.yaml"
    p.write_text(_VELOCITY_POLICY.format(max_sends=max_sends),
                 encoding="utf-8")
    return str(p)


def _velocity_entries(ledger_path):
    out = []
    ledger_path = Path(ledger_path)
    if not ledger_path.exists():
        return out
    text = ledger_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("kind") == "velocity":
            out.append(entry)
    return out


def _send(executor, ident, body="hello"):
    return executor.call(ident, "send_email", to="ops@synthetic.local",
                         subject="t", body=body)


class TestS5Velocity(unittest.TestCase):
    def test_velocity_threshold_queues_across_runs(self):
        """Two sends in run 1 execute and are ledgered; a fresh run for
        the same principal against the shared ledger sees
        2 sends >= max_sends and the third send queues via
        approval-velocity-guard (never denies)."""
        tmp = Path(tempfile.mkdtemp(prefix="govs5-"))
        ledger = tmp / "shared_ledger.jsonl"
        policy_path = _write_policy(tmp, max_sends=2)

        run1 = make_run(policy_path=policy_path, ledger_path=ledger)
        ident1 = run1["mint_identity"]("a1", "sender", "acme")
        r1 = _send(run1["executor"], ident1, body="one")
        r2 = _send(run1["executor"], ident1, body="two")
        self.assertEqual(r1["status"], "executed", r1)
        self.assertEqual(r2["status"], "executed", r2)

        entries = _velocity_entries(ledger)
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(e["principal"] == "acme" for e in entries))
        self.assertTrue(all(e["tool"] == "send_email" for e in entries))
        self.assertEqual([e["sends"] for e in entries], [1, 1])
        self.assertTrue(all(e["egress_bytes"] > 0 for e in entries))

        # Fresh run, same principal, shared ledger: velocity trips.
        run2 = make_run(policy_path=policy_path, ledger_path=ledger)
        ident2 = run2["mint_identity"]("a2", "sender", "acme")
        r3 = _send(run2["executor"], ident2, body="three")
        self.assertEqual(r3["status"], "queued", r3)
        self.assertEqual(r3["policy_id"], "approval-velocity-guard", r3)

        # The queued audit entry carries the velocity signal.
        queued = [e for e in run2["read_log"]()
                  if e.get("decision") == "queued_pending"]
        self.assertTrue(queued, "expected a queued_pending audit entry")
        self.assertEqual(queued[-1]["flag"], "velocity_exceeded")
        self.assertEqual(queued[-1]["policy_id"],
                         "approval-velocity-guard")

    def test_velocity_query_failure_fails_open_with_loud_audit(self):
        """A ledger-lock timeout during the velocity query must NOT
        deny the call (fail-open) — but it must be audit-visible via
        velocity_check_skipped."""
        tmp = Path(tempfile.mkdtemp(prefix="govs5-"))
        ledger = tmp / "shared_ledger.jsonl"
        policy_path = _write_policy(tmp, max_sends=2)

        run = make_run(policy_path=policy_path, ledger_path=ledger)
        ident = run["mint_identity"]("a1", "sender", "acme")
        # First send executes normally so the ledger file exists (the
        # query short-circuits on a missing ledger without touching
        # the lock — the failure path needs a ledger to query).
        r1 = _send(run["executor"], ident, body="one")
        self.assertEqual(r1["status"], "executed", r1)

        with mock.patch.object(exec_mod, "_ledger_read_locked",
                               side_effect=LedgerLockError("lock timeout")):
            r2 = _send(run["executor"], ident, body="two")
        # Fail-open: the call still executes; it is NOT denied.
        self.assertEqual(r2["status"], "executed", r2)

        skips = [e for e in run["read_log"]()
                 if e.get("flag") == "velocity_check_skipped"]
        self.assertTrue(skips,
                        "expected a loud velocity_check_skipped audit entry")
        self.assertIn("fail-open", skips[0]["reason"])
        self.assertEqual(skips[0]["decision"], "velocity_check_skipped")

    def test_velocity_records_at_both_execution_boundaries(self):
        """The allow path and the approved-execution path each record
        one velocity entry (executions, not attempts)."""
        tmp = Path(tempfile.mkdtemp(prefix="govs5-"))
        ledger = tmp / "shared_ledger.jsonl"
        # Threshold high: nothing queues for velocity here.
        policy_path = _write_policy(tmp, max_sends=100)

        run = make_run(policy_path=policy_path, ledger_path=ledger)
        ident = run["mint_identity"]("a1", "sender", "acme")

        # Allow path: send executes directly.
        r1 = _send(run["executor"], ident, body="one")
        self.assertEqual(r1["status"], "executed", r1)

        # Approved path: outside-sandbox write queues, human approves,
        # execute_approved runs it (quarantined by the simulator).
        q = run["executor"].call(ident, "write_file", path="/tmp/evil.txt",
                                 content="x" * 16)
        self.assertEqual(q["status"], "queued", q)
        run["approvals"].decide(q["approval_id"], True, "test approval",
                                decided_by="human-operator")
        done = run["executor"].execute_approved()
        self.assertEqual(len(done), 1, done)

        entries = _velocity_entries(ledger)
        self.assertEqual(len(entries), 2, entries)
        by_tool = {e["tool"]: e for e in entries}
        self.assertEqual(by_tool["send_email"]["sends"], 1)
        self.assertEqual(by_tool["send_email"]["writes"], 0)
        self.assertEqual(by_tool["write_file"]["writes"], 1)
        self.assertEqual(by_tool["write_file"]["sends"], 0)
        # Approved-execution snapshot carries the velocity signal key.
        approved = [e for e in run["read_log"]()
                    if e.get("decision") == "approved_executed"]
        self.assertTrue(approved, "expected an approved_executed entry")
        self.assertIn("velocity_exceeded",
                      approved[0]["policy_context"])

    def test_velocity_unconfigured_is_unenforced(self):
        """Without a velocity: section there is no query, no record, no
        skip audit — the guard is unenforced, never zero."""
        tmp = Path(tempfile.mkdtemp(prefix="govs5-"))
        ledger = tmp / "shared_ledger.jsonl"
        run = make_run(ledger_path=ledger)  # default policy: no velocity:
        self.assertEqual(run["policy"].velocity, {})
        ident = run["mint_identity"]("coder-1", "coder", "acme")
        r = run["executor"].call(ident, "write_file", path="notes.txt",
                                 content="hello")
        self.assertEqual(r["status"], "executed", r)
        self.assertEqual(_velocity_entries(ledger), [])
        skips = [e for e in run["read_log"]()
                 if e.get("flag") == "velocity_check_skipped"]
        self.assertEqual(skips, [])

    def test_s5_reuses_ledger_lock_no_competing_lock(self):
        """The S5 query enters the ledger's own _ledger_read_locked and
        the S5 record enters _ledger_write_locked (inside
        EgressLedger.append); the executor holds no lock of its own
        for S5."""
        tmp = Path(tempfile.mkdtemp(prefix="govs5-"))
        ledger = tmp / "shared_ledger.jsonl"
        policy_path = _write_policy(tmp, max_sends=1)

        entered = []
        real_read = exec_mod._ledger_read_locked
        real_write = ledger_mod._ledger_write_locked

        @contextlib.contextmanager
        def spy_read(path):
            entered.append(("read", str(path)))
            with real_read(path):
                yield

        @contextlib.contextmanager
        def spy_write(path):
            entered.append(("write", str(path)))
            with real_write(path):
                yield

        run1 = make_run(policy_path=policy_path, ledger_path=ledger)
        ident1 = run1["mint_identity"]("a1", "sender", "acme")
        with mock.patch.object(exec_mod, "_ledger_read_locked",
                               spy_read), \
             mock.patch.object(ledger_mod, "_ledger_write_locked",
                               spy_write):
            r1 = _send(run1["executor"], ident1, body="one")
        self.assertEqual(r1["status"], "executed", r1)
        # Record path went through the ledger's write lock...
        self.assertIn(("write", str(ledger)), entered, entered)
        # ...and the executor itself holds no S5 lock: the only lock
        # acquisitions on the S5 paths are the ledger's own primitives,
        # and the executor instance owns no lock objects at all (the
        # pre-existing _lock_refusal_* attributes are audit-rate-limit
        # timestamps, not locks).
        kinds = {k for k, _ in entered}
        self.assertEqual(kinds, {"write"}, entered)
        import threading as _threading
        _lock_type = type(_threading.Lock())
        self.assertFalse(
            [v for v in vars(run1["executor"]).values()
             if isinstance(v, _lock_type)])

        # Second run: the query path enters the ledger's read lock,
        # then the guard queues (1 send >= max_sends=1).
        entered.clear()
        run2 = make_run(policy_path=policy_path, ledger_path=ledger)
        ident2 = run2["mint_identity"]("a2", "sender", "acme")
        with mock.patch.object(exec_mod, "_ledger_read_locked",
                               spy_read), \
             mock.patch.object(ledger_mod, "_ledger_write_locked",
                               spy_write):
            r2 = _send(run2["executor"], ident2, body="two")
        self.assertEqual(r2["status"], "queued", r2)
        self.assertEqual(r2["policy_id"], "approval-velocity-guard", r2)
        self.assertIn(("read", str(ledger)), entered, entered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
