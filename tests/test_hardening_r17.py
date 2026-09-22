"""Hardening round-17 regression tests: F70 + F71.

F70 (HIGH, OPEN): the R16 incremental chain-tip verifier is blind to
    length-preserving edits of already-verified (pre-tip) bytes -- a
    fundamental property of any O(new) verifier. R17 originally
    bounded (not closed) that silent window with a MAC-authenticated
    ``full_in`` countdown forcing a full verification every 8 refused
    sweeps; the countdown was REVERTED (red-team wave-19 final R17
    verdict) because it is replayable by the F52 run-dir writer (F72:
    a saved valid tip restores the countdown, so the "at most N
    sweeps" bound does not bind against the in-model attacker). F70
    therefore stays OPEN; the retired countdown tests below were
    removed with the mechanism. The F70 fix direction (log-anchored
    generation counter or MAC'd interrupted-marker manifest at
    authorization time) remains for a future round.

F71 (HIGH): a forged execution_authorized marker forced a full
    O(n) _verify on EVERY sweep (the F52/F60 CPU amplifier moved to
    reconciliation). R17 caches only authenticated INVALID marker
    verdicts, keyed by marker content+position, checkpoint state, key
    epoch, and exact log end. Unchanged repeats reuse the fail-closed
    verdict without re-verification or duplicate audit; any
    append/change invalidates the verdict so a genuine repair is
    honored. A forged cache can never authorize or reconcile -- it is
    consulted only to deny.
"""

import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")

_F71_N = 20000
# Historical cost of the forged-marker full verify at 20k (R16):
# 386-580ms per sweep. Cached sweeps must stay far below that.
# (2026-09-22: absolute wall-clock bounds removed from the F71 perf test
# in favor of a self-normalizing within-run comparison; see the test.)


def _make_run_dir(refused=True):
    run_dir = Path(tempfile.mkdtemp(prefix="gov-r17-test-"))
    if refused:
        (run_dir / "approvals.lock").mkdir()
    return run_dir


def _fresh_executor(run_dir, policy):
    log = ActionLog(run_dir / "actions.jsonl")
    queue = ApprovalQueue(run_dir, log)
    return ToolExecutor(run_dir, policy, log, queue,
                        ledger_path=run_dir / "egress_ledger.jsonl")


def _successful_sweep(run_dir, policy):
    # No approvals.lock directory: the queue lock is acquirable, so
    # the sweep body (including reconciliation) runs.
    ex = _fresh_executor(run_dir, policy)
    t0 = time.perf_counter()
    ret = ex.execute_approved()
    return ret, time.perf_counter() - t0


def _plant_forged_marker(log_path, aid):
    """Append a forged execution_authorized marker (no key, no MAC).

    The seq is chosen far out-of-band (no legitimate entry will ever
    carry it) so the marker is unambiguous in the candidate scan and
    the markers_key fingerprint.
    """
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "event": "tool_call", "decision": "execution_authorized",
            "approval_id": aid, "seq": 999999999, "run_id": "forged-run",
        }) + "\n")


def _marker_invalid_audit_count(run_dir):
    n = 0
    for e in read_entries(run_dir / "actions.jsonl"):
        if isinstance(e, dict) and e.get(
                "event") == "reconciliation_marker_invalid":
            n += 1
    return n


def _chain_unverifiable_audit_count(run_dir):
    n = 0
    for e in read_entries(run_dir / "actions.jsonl"):
        if isinstance(e, dict) and e.get(
                "event") == "reconciliation_chain_unverifiable":
            n += 1
    return n


# NOTE (R17 final verdict, wave-19): the F70 ``full_in`` countdown was
# REVERTED -- it is replayable by the F52 run-dir writer (F72), so the
# "pre-tip tamper goes loud within at most N refused sweeps" bound did
# not bind against the in-model attacker. The countdown tests
# (TestF70PreTipTamperBounded, TestF70WarmSweepBounded) were retired
# with the mechanism; F70 stays OPEN. Steady-state refused-sweep cost
# remains covered by R16's TestF69WarmTipBounded.


class TestF71ForgedMarkerCache(unittest.TestCase):
    def test_forged_marker_cached_twenty_sweeps_at_20k(self):
        """F71: 20 forged-marker sweeps at 20k -- first expensive, rest cheap.

        The first sweep pays one full verification and one loud audit;
        unchanged repeats reuse the authenticated invalid verdict:
        exactly one reconciliation_marker_invalid audit, and cached
        sweeps far below the historical 386-580ms full-verify cost.
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir(refused=False)
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(_F71_N):
                log.append({"event": "r17_setup", "i": i})
            _plant_forged_marker(run_dir / "actions.jsonl", "aid-forged")
            times = []
            for k in range(20):
                ret, dt = _successful_sweep(run_dir, policy)
                self.assertEqual(ret, [],
                                 "sweep with forged marker must not "
                                 "execute anything")
                times.append(dt)
            self.assertEqual(
                _marker_invalid_audit_count(run_dir), 1,
                "exactly one invalid-marker audit across 20 sweeps")
            # Load-robust perf claim (2026-09-22): the old absolute 150ms
            # bound bit three full-suite runs under concurrent VM load
            # (150-240ms cached sweeps). The invariant that matters is
            # self-normalizing: within THIS run, cached sweeps must cost
            # far less than the first (uncached, full-verify + loud audit)
            # sweep. No absolute wall-clock, so it cannot flake under load
            # and cannot mask a real cache regression (a broken cache
            # would make cached sweeps cost ~times[0]).
            cached = times[1:]
            median = sorted(cached)[len(cached) // 2]
            self.assertLess(
                median, times[0] / 2,
                "median cached sweep %.1fms not far below uncached "
                "%.1fms (cache not saving work)" % (
                    median * 1000, times[0] * 1000))
            slowest = max(cached)
            self.assertLess(
                slowest, times[0],
                "a 'cached' sweep took %.1fms >= uncached %.1fms "
                "(cache bypassed)" % (slowest * 1000, times[0] * 1000))
            self.assertTrue(
                (run_dir / "reconcile_marker_verdict.json").exists(),
                "invalid verdict must be cached")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_genuine_repair_invalidates_cache_and_is_honored(self):
        """A genuine repair (forged marker removed) invalidates the cache.

        The log end changes, so the cached invalid verdict cannot be
        reused: the sweep re-verifies, finds a valid chain with no
        markers, and reconciles nothing -- no invalid-marker audit.
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir(refused=False)
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(500):
                log.append({"event": "r17_setup", "i": i})
            log_path = run_dir / "actions.jsonl"
            _plant_forged_marker(log_path, "aid-forged")
            ret, _dt = _successful_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            self.assertEqual(_marker_invalid_audit_count(run_dir), 1)
            self.assertTrue(
                (run_dir / "reconcile_marker_verdict.json").exists())
            # Genuine repair: remove the forged marker line. The remaining
            # chain is valid (it verified before the plant); the marker
            # removal changes markers_key, so the cached invalid
            # verdict cannot be reused.
            lines = log_path.read_text(encoding="utf-8").splitlines(
                keepends=True)
            kept = [ln for ln in lines if "aid-forged" not in ln]
            self.assertLess(len(kept), len(lines),
                            "forged marker line must be removed")
            log_path.write_text("".join(kept), encoding="utf-8")
            ret, _dt = _successful_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            self.assertEqual(
                _marker_invalid_audit_count(run_dir), 1,
                "repair must not re-audit: the invalid verdict is "
                "invalidated by the log-end change and the valid chain "
                "with no markers reconciles nothing")
            self.assertEqual(
                _chain_unverifiable_audit_count(run_dir), 0,
                "a genuinely repaired chain must verify")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_no_marker_broken_chain_audits_loud(self):
        """F70: no candidates but a broken chain audits loudly.

        The reconciliation verification gate runs even with no
        interrupted markers; a broken chain with no markers produces a
        loud reconciliation_chain_unverifiable audit and reconciles
        nothing.
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir(refused=False)
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(200):
                log.append({"event": "r17_setup", "i": i})
            # Break the chain with a MAC-invalid (valid JSON) line and
            # no markers at all.
            with open(run_dir / "actions.jsonl", "a",
                      encoding="utf-8") as f:
                f.write(json.dumps({
                    "event": "r17_broken", "seq": 201,
                    "hash": "not-a-real-mac"}) + "\n")
            ret, _dt = _successful_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            self.assertEqual(
                _chain_unverifiable_audit_count(run_dir), 1,
                "broken chain with no markers must audit loudly")
            self.assertEqual(_marker_invalid_audit_count(run_dir), 0)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
