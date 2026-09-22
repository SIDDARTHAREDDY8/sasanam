"""Hardening round-16 regression tests: F69 + demo direct-invocation fix.

F69 (HIGH): each refused sweep paid a full chain verification + full log
    read -- O(log size) per sweep, an unbounded CPU amplifier while the
    coalesce state file is held corrupt. Fixed by MAC-authenticated
    incremental chain-tip verification (gov/log.py verify_chain_tip):
    the F60 fallback verifies only entries appended since the cached
    tip (byte-offset seeks, O(new bytes)); the tip advances after each
    verified sweep. A missing/corrupt/foreign tip, a shrunk log, or any
    segment failure falls back to full verification (fail-loud) -- never
    silent trust, and the suppression decision still requires a verified
    chain.
DEMO: demo/attack_scenario.py's ``__main__`` guard sat above main()'s
    def, so ``python3 demo/attack_scenario.py`` died with NameError.
    The guard now sits below main(); both direct invocation and the
    gov-attack-demo entry point (demo.attack_scenario:main) work.
"""

import json
import os
import shutil
import subprocess
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
    _read_tip_cache,
    _tip_cache_path,
    verify_chain,
    verify_chain_tip,
)
from gov.policy import PolicyEngine  # noqa: E402

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")

# Measured 2026-09-22 (this VM): worst warm refused sweep at 20k entries
# was 73ms across 3 trials (typical 30-50ms). The bound carries ~2x
# headroom; it pins the F69 fix (old code: ~580-690ms at 20k), not the
# hardware.
_WARM_SWEEP_BOUND_SECS = 0.150
_F69_N = 20000


def _make_run_dir():
    run_dir = Path(tempfile.mkdtemp(prefix="gov-r16-test-"))
    (run_dir / "approvals.lock").mkdir()
    return run_dir


def _fresh_executor(run_dir, policy):
    log = ActionLog(run_dir / "actions.jsonl")
    queue = ApprovalQueue(run_dir, log)
    return ToolExecutor(run_dir, policy, log, queue,
                        ledger_path=run_dir / "egress_ledger.jsonl")


def _corrupt_coalesce_state(run_dir):
    (run_dir / "lock_refusal_coalesce.json").write_text(
        '{"broken": true', encoding="utf-8")


def _refused_sweep(run_dir, policy):
    _corrupt_coalesce_state(run_dir)
    ex = _fresh_executor(run_dir, policy)
    t0 = time.perf_counter()
    ret = ex.execute_approved()
    return ret, time.perf_counter() - t0


def _refusal_count(run_dir):
    # Genuine audit entries carry decision="refused"; a planted
    # MAC-invalid line (the F60 shape) does not.
    n = 0
    for line in (run_dir / "actions.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("event") == "approval_sweep_refused" \
                and e.get("decision") == "refused":
            n += 1
    return n


def _entry_count(run_dir):
    n = 0
    for line in (run_dir / "actions.jsonl").read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            n += 1
    return n


class TestF69WarmTipBounded(unittest.TestCase):
    def test_warm_tip_refused_sweep_bounded_at_20k(self):
        """F69: refused sweeps with a warm tip stay bounded at 20k.

        The attack shape is a corrupt coalesce state file on every
        sweep (the F60 fallback path). The first sweep pays one full
        verification and seeds the tip; every later sweep verifies
        only the new segment. Each warm sweep must refuse fail-closed
        ([]) and finish under the bound, and the refusal must be
        audited exactly once (suppression works off the verified tip).
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir()
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(_F69_N):
                log.append({"event": "r16_setup", "i": i})

            ret, _cold_dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            self.assertIsNotNone(
                _read_tip_cache(run_dir / "actions.jsonl"),
                "cold sweep must seed the chain-tip cache")

            for k in range(5):
                ret, dt = _refused_sweep(run_dir, policy)
                self.assertEqual(ret, [],
                                 "refused sweep must fail closed")
                self.assertLess(
                    dt, _WARM_SWEEP_BOUND_SECS,
                    "warm sweep %d took %.1fms at %d entries "
                    "(bound %.0fms)" % (k, dt * 1000, _F69_N,
                                        _WARM_SWEEP_BOUND_SECS * 1000))
            self.assertEqual(_refusal_count(run_dir), 1,
                             "one audit, then suppression off the tip")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_repeated_tip_verify_without_new_entries(self):
        """Back-to-back incremental verifies (no new entries or sidecar
        lines between) must both succeed: the stored checkpoint anchor
        carries its key_epoch, so the re-check's MAC binds the epoch
        even when the newest anchor comes from the cache, not from
        fresh sidecar lines."""
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir()
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(100):
                log.append({"event": "r16_setup", "i": i})
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            log_path = run_dir / "actions.jsonl"
            for _ in range(3):
                verdict = verify_chain_tip(
                    log_path, flags=("queue_lock_invalid",))
                self.assertIsNotNone(
                    verdict, "incremental verify must not degrade to "
                    "full verify with no new entries")
                self.assertTrue(verdict["ok"])
            self.assertEqual(verdict["entries"],
                             _entry_count(run_dir))
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_tip_advances_and_reverifies(self):
        """The tip advances to the tail; a later incremental verify is ok.

        The cold sweep seeds the tip over the entries verified so far
        (the refusal audit it then appends lands after seeding); the
        next warm sweep verifies that audit entry and advances the tip
        to the true tail.
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir()
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(500):
                log.append({"event": "r16_setup", "i": i})
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            ret, _dt = _refused_sweep(run_dir, policy)
            self.assertEqual(ret, [])
            tip = _read_tip_cache(run_dir / "actions.jsonl")
            self.assertIsNotNone(tip)
            self.assertEqual(tip["seq"], _entry_count(run_dir))
            verdict = verify_chain_tip(run_dir / "actions.jsonl",
                                       flags=("queue_lock_invalid",))
            self.assertIsNotNone(verdict)
            self.assertTrue(verdict["ok"])
            self.assertEqual(verdict["entries"], _entry_count(run_dir))
            self.assertIsInstance(
                verdict["refusals"].get("queue_lock_invalid"), str)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class TestF69TipFallbacks(unittest.TestCase):
    def _seeded(self, policy, n=3000):
        run_dir = _make_run_dir()
        log = ActionLog(run_dir / "actions.jsonl")
        for i in range(n):
            log.append({"event": "r16_setup", "i": i})
        ret, _dt = _refused_sweep(run_dir, policy)
        self.assertEqual(ret, [])
        self.assertIsNotNone(_read_tip_cache(
            run_dir / "actions.jsonl"))
        return run_dir

    def test_deleted_and_corrupt_tip_fall_back(self):
        """A missing/corrupt tip degrades to full verification.

        The sweep still refuses fail-closed, audits exactly once, and
        reseeds the tip -- slower, never unverified trust.
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        for mode in ("deleted", "corrupt"):
            run_dir = self._seeded(policy)
            try:
                tip_path = _tip_cache_path(run_dir / "actions.jsonl")
                if mode == "deleted":
                    tip_path.unlink()
                else:
                    tip_path.write_text("garbage{{{", encoding="utf-8")
                self.assertIsNone(_read_tip_cache(
                    run_dir / "actions.jsonl"))
                ret, _dt = _refused_sweep(run_dir, policy)
                self.assertEqual(ret, [],
                                 "must refuse fail-closed (%s tip)" % mode)
                self.assertEqual(_refusal_count(run_dir), 1,
                                 "exactly one audit (%s tip)" % mode)
                self.assertIsNotNone(_read_tip_cache(
                    run_dir / "actions.jsonl"),
                    "tip reseeded after full verify (%s)" % mode)
            finally:
                shutil.rmtree(run_dir, ignore_errors=True)

    def test_flipped_byte_in_segment_triggers_loud_reverify(self):
        """A flipped byte after the tip forces full re-verification.

        The incremental walk must reject the segment (MAC failure),
        the fallback full verification must report the tamper, and the
        refusal must be audited LOUD (no silent suppression).
        """
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = self._seeded(policy)
        try:
            log_path = run_dir / "actions.jsonl"
            # One genuine entry after the tip, then flip a byte in it.
            ActionLog(log_path).append(
                {"event": "r16_post_tip", "v": "aaaaaaaaaaaaaaaa"})
            lines = log_path.read_text(encoding="utf-8").splitlines()
            victim = lines[-1]
            idx = victim.index("aaaaaaaaaaaaaaaa")
            lines[-1] = (victim[:idx] + "X" + victim[idx + 1:])
            log_path.write_text("\n".join(lines) + "\n",
                                encoding="utf-8")

            self.assertIsNone(
                verify_chain_tip(log_path),
                "incremental verify must reject the tampered segment")
            ok, broken, _n = verify_chain(log_path)
            self.assertFalse(ok, "full verify must detect the tamper")
            self.assertIsNotNone(broken)

            _corrupt_coalesce_state(run_dir)
            ex = _fresh_executor(run_dir, policy)
            self.assertFalse(
                ex._log_shows_recent_lock_refusal("queue_lock_invalid"),
                "tampered chain must not suppress")
            self.assertTrue(
                ex._audit_lock_refusal("queue_lock_invalid", "r16-test"),
                "tamper must be LOUD")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_tail_truncation_is_loud(self):
        """Deleting tail entries past the checkpoint anchor goes loud."""
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = self._seeded(policy)
        try:
            log_path = run_dir / "actions.jsonl"
            lines = log_path.read_text(encoding="utf-8").splitlines()
            log_path.write_text("\n".join(lines[:1500]) + "\n",
                                encoding="utf-8")
            self.assertIsNone(verify_chain_tip(log_path),
                              "truncation must defeat the tip")
            _corrupt_coalesce_state(run_dir)
            ex = _fresh_executor(run_dir, policy)
            self.assertTrue(
                ex._audit_lock_refusal("queue_lock_invalid", "r16-test"),
                "truncation must be LOUD")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class TestF60PlantedLineStillLoud(unittest.TestCase):
    def test_planted_mac_invalid_line_does_not_suppress(self):
        """F60 follow-up (r15 sit99 shape): a planted MAC-invalid line as
        the whole log must not suppress -- the refusal audits loud on
        every sweep, with and without the tip cache in play."""
        policy = PolicyEngine(DEFAULT_POLICY)
        run_dir = _make_run_dir()
        try:
            planted = {"event": "approval_sweep_refused",
                       "flag": "queue_lock_invalid",
                       "ts": "2026-09-22T00:00:00+00:00",
                       "seq": 1, "hash": "0" * 64,
                       "prev_hash": "0" * 64}
            (run_dir / "actions.jsonl").write_text(
                json.dumps(planted) + "\n", encoding="utf-8")
            for _ in range(2):
                ret, _dt = _refused_sweep(run_dir, policy)
                self.assertEqual(ret, [])
            # No tip could ever be seeded (chain never verified), so no
            # suppression: both sweeps audited loud.
            self.assertIsNone(_read_tip_cache(
                run_dir / "actions.jsonl"))
            ex = _fresh_executor(run_dir, policy)
            self.assertFalse(
                ex._log_shows_recent_lock_refusal("queue_lock_invalid"))
            self.assertEqual(_refusal_count(run_dir), 2)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class TestDemoDirectInvocation(unittest.TestCase):
    def test_direct_invocation_exits_zero_with_result(self):
        """demo/attack_scenario.py runs directly: exit 0 + RESULT line."""
        work = Path(tempfile.mkdtemp(prefix="gov-r16-demo-"))
        try:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "demo"
                                    / "attack_scenario.py")],
                cwd=str(work), capture_output=True, text=True,
                timeout=120)
            self.assertEqual(proc.returncode, 0,
                             "stderr: %s" % proc.stderr[-2000:])
            self.assertRegex(proc.stdout, r"(?m)^RESULT: ",
                             "an honest RESULT line is required")
            self.assertNotIn("NameError", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_entry_point_import_path_still_works(self):
        """The gov-attack-demo console script target still works."""
        work = Path(tempfile.mkdtemp(prefix="gov-r16-demo-ep-"))
        try:
            proc = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); "
                 "from demo.attack_scenario import main; "
                 "raise SystemExit(main())" % str(REPO_ROOT)],
                cwd=str(work), capture_output=True, text=True,
                timeout=120)
            self.assertEqual(proc.returncode, 0,
                             "stderr: %s" % proc.stderr[-2000:])
            self.assertRegex(proc.stdout, r"(?m)^RESULT: ")
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
