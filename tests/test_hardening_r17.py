"""Hardening round-17 regression tests: F70 + F71.

F70 (HIGH): the R16 incremental chain-tip verifier is blind to
    length-preserving edits of already-verified (pre-tip) bytes -- a
    fundamental property of any O(new) verifier. R17 bounds (not
    closes) that silent window: the MAC-authenticated tip carries a
    ``full_in`` countdown (refused sweeps remaining before a forced
    full verification), decremented once per refused sweep on both the
    tip-path branch (verify_chain_tip) and the healthy-state branch
    (executor._r17_forced_full_verify), and consumed by the
    reconciliation verification gate on successful-lock sweeps. Every
    N=8 refused sweeps the chain is fully re-verified; a pre-tip
    tamper goes loud at most 8 sweeps after planting. The countdown
    is MAC-covered, so the F52 run-dir writer cannot extend it.

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
from gov.log import (  # noqa: E402
    ActionLog,
    TIP_FORCED_FULL_VERIFY_EVERY_N_SWEEPS,
    _read_tip_cache,
    read_entries,
)
from gov.policy import PolicyEngine  # noqa: E402

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")

N = TIP_FORCED_FULL_VERIFY_EVERY_N_SWEEPS
assert N == 8, "R17 tests pin the F70 interval at 8"

_F71_N = 20000
# Historical cost of the forged-marker full verify at 20k (R16):
# 386-580ms per sweep. Cached sweeps must stay far below that.
_F71_CACHED_SWEEP_BOUND_SECS = 0.150


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


def _refused_sweep(run_dir, policy):
    ex = _fresh_executor(run_dir, policy)
    t0 = time.perf_counter()
    ret = ex.execute_approved()
    return ret, time.perf_counter() - t0


def _successful_sweep(run_dir, policy):
    # No approvals.lock directory: the queue lock is acquirable, so
    # the sweep body (including reconciliation) runs.
    ex = _fresh_executor(run_dir, policy)
    t0 = time.perf_counter()
    ret = ex.execute_approved()
    return ret, time.perf_counter() - t0


def _tamper_audit_count(run_dir):
    n = 0
    for line in (run_dir / "actions.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if (isinstance(e, dict)
                and e.get("event") == "approval_sweep_refused"
                and "pre-tip tamper suspected" in str(
                    e.get("reason", ""))):
            n += 1
    return n


def _plant_length_preserving_edit(log_path, target_seq):
    """Rewrite one valid entry's content keeping the exact byte length.

    The entry's MAC then fails: the incremental tip walk (which starts
    after the tip) cannot see it, but the forced full verification
    must catch it loudly.
    """
    lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
    idx = target_seq - 1  # seqs are 1-based, lines 0-based here
    entry = json.loads(lines[idx])
    # Flip a content character inside the JSON without changing the
    # byte length: the "event" value is rewritten to the same length.
    old_event = entry["event"]
    assert len(old_event) >= 2
    entry["event"] = "X" + old_event[1:]
    new_line = json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n"
    assert len(new_line.encode("utf-8")) == len(
        lines[idx].encode("utf-8")), "edit must be length-preserving"
    lines[idx] = new_line
    log_path.write_text("".join(lines), encoding="utf-8")


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


class TestF70PreTipTamperBounded(unittest.TestCase):
    def test_pre_tip_edit_goes_loud_within_n_sweeps(self):
        """F70: a length-preserving pre-tip edit is loud within <=8 sweeps.

        Healthy coalesce state, refused sweeps: the countdown ticks in
        _r17_forced_full_verify. Sweeps before the countdown exhausts
        stay quiet (incremental walk cannot see the edit); the sweep
        that exhausts it forces a full verification and audits LOUD
        with tamper attribution.
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir(refused=True)
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(1000):
                log.append({"event": "r17_setup", "i": i})
            # Sweep 1 seeds the tip (full verify, full_in=N).
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            tip = _read_tip_cache(run_dir / "actions.jsonl")
            self.assertIsNotNone(tip)
            self.assertEqual(tip["full_in"], N)
            # Plant a length-preserving edit well before the tip.
            _plant_length_preserving_edit(run_dir / "actions.jsonl", 500)
            loud_at = None
            for k in range(1, N + 1):
                ret, _dt = _refused_sweep(run_dir, policy)
                self.assertEqual(ret, [],
                                 "refused sweep must fail closed")
                if _tamper_audit_count(run_dir) > 0:
                    loud_at = k
                    break
            self.assertIsNotNone(
                loud_at,
                "pre-tip tamper must go loud within %d sweeps" % N)
            self.assertLessEqual(loud_at, N)
            # The countdown was consumed: after the loud sweep the tip
            # is reseeded only on success; a broken chain never
            # reseeds, so every later sweep stays loud (fail-loud,
            # never folded).
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(_tamper_audit_count(run_dir), 2)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_countdown_ticks_once_per_refused_sweep(self):
        """The tip countdown decrements exactly once per refused sweep."""
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir(refused=True)
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(200):
                log.append({"event": "r17_setup", "i": i})
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            seen = []
            for _ in range(N - 1):
                tip = _read_tip_cache(run_dir / "actions.jsonl")
                seen.append(tip["full_in"])
                ret, _dt = _refused_sweep(run_dir, policy)
                self.assertEqual(ret, [])
            # 8,7,6,5,4,3,2: each refused sweep ticks once. The 7th
            # sweep leaves full_in=1 (due); the 8th forces a full
            # verification and reseeds to N.
            self.assertEqual(seen, [8, 7, 6, 5, 4, 3, 2])
            tip = _read_tip_cache(run_dir / "actions.jsonl")
            self.assertEqual(tip["full_in"], 1)
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            tip = _read_tip_cache(run_dir / "actions.jsonl")
            self.assertEqual(tip["full_in"], N)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class TestF70WarmSweepBounded(unittest.TestCase):
    def test_warm_sweeps_bounded_periodic_full_verify(self):
        """Steady refused sweeps stay O(new); only the Nth pays O(n)."""
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir(refused=True)
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(_F71_N):
                log.append({"event": "r17_setup", "i": i})
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            warm_times = []
            for k in range(N - 1):
                ret, dt = _refused_sweep(run_dir, policy)
                self.assertEqual(ret, [])
                warm_times.append(dt)
                self.assertLess(
                    dt, _F71_CACHED_SWEEP_BOUND_SECS,
                    "warm sweep %d took %.1fms at %d entries" % (
                        k, dt * 1000, _F71_N))
            # The Nth sweep forces a full verification: slower than
            # warm, but it must complete and stay fail-closed.
            ret, dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [],
                             "forced full-verify sweep must fail closed")
            self.assertGreater(
                dt, max(warm_times),
                "forced full verify should cost more than a warm sweep")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


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
            for k, dt in enumerate(times[1:], start=2):
                self.assertLess(
                    dt, _F71_CACHED_SWEEP_BOUND_SECS,
                    "cached sweep %d took %.1fms (historical full "
                    "verify: 386-580ms)" % (k, dt * 1000))
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
        interrupted markers (it consumes the F70 countdown); a broken
        chain with no markers produces a loud
        reconciliation_chain_unverifiable audit and reconciles nothing.
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
