"""Wave-110 ledger-robustness regression tests (F165, F166, F170).

Red-first: written against the audit repros in
~/workspace/audits/wave109/vrfy_ledger_{window_failopen,wallclock,growth}.py
and FAIL against the unfixed gov/exchange_ledger.py (verified on a scratch
copy of the pre-fix module). They pass only with the fail-closed fixes.

Seams under test (pre-agreed): check_exchange_read (public guard),
_read_window (window accounting), _append_record (ledger write path).
Time is controlled with mock.patch on time.time / time.monotonic -- no
sleeps, no wall-clock dependence.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from gov import exchange_ledger as xl
from gov.exchange_ledger import ExchangeAccessDenied


def _xp(i):
    return "/x/runs/victim-%d/exchanges.jsonl" % i


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="w110-"))
        self.ledger = self.tmp / "exchange_access.jsonl"
        self._saved = {}
        for k, v in {
                "GOV_EXCHANGE_LEDGER_PATH": str(self.ledger),
                "GOV_EXCHANGE_MAX_RUNS": "5",
                "GOV_EXCHANGE_WINDOW_SEC": "900",
                "GOV_EXCHANGE_MAX_SINGLE_READ": "100000",
                "GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL": "0",
                "GOV_EXCHANGE_READ_ALLOW": "",
                "GOV_EXCHANGE_LEDGER_TAIL_BYTES": "",
                "GOV_EXCHANGE_LEDGER_COMPACT_BYTES": "",
        }.items():
            self._saved[k] = os.environ.get(k)
            if v == "":
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _reads(self, n, start=0):
        denied = 0
        for i in range(start, start + n):
            try:
                xl.check_exchange_read(_xp(i), n_entries=10)
            except ExchangeAccessDenied:
                denied += 1
        return denied

    def _denied_records(self):
        if not self.ledger.exists():
            return []
        return [json.loads(l) for l in
                self.ledger.read_text(encoding="utf-8").splitlines()
                if l.strip() and json.loads(l).get("event")
                == "exchange_read_denied"]


# -- F165: window config fail-closed --------------------------------

class F165WindowConfigTest(_Base):
    def test_zero_window_denies_cross_run_read_fail_closed(self):
        os.environ["GOV_EXCHANGE_WINDOW_SEC"] = "0"
        with self.assertRaises(ExchangeAccessDenied) as cm:
            xl.check_exchange_read(_xp(1), n_entries=10)
        self.assertIn("GOV_EXCHANGE_WINDOW_SEC", str(cm.exception))
        denied = self._denied_records()
        self.assertEqual(len(denied), 1)
        self.assertIn("0", denied[0]["reason"])

    def test_negative_window_denies_cross_run_read(self):
        os.environ["GOV_EXCHANGE_WINDOW_SEC"] = "-30"
        with self.assertRaises(ExchangeAccessDenied):
            xl.check_exchange_read(_xp(1), n_entries=10)

    def test_zero_window_never_silently_allows_bulk_harvest(self):
        # The audit repro shape: 60 distinct runs, limit 5 -> every read
        # must be denied (fail-closed), never allowed=60/denied=0.
        os.environ["GOV_EXCHANGE_WINDOW_SEC"] = "0"
        denied = self._reads(60)
        self.assertEqual(denied, 60)

    def test_zero_window_does_not_brick_own_run_reads(self):
        os.environ["GOV_EXCHANGE_WINDOW_SEC"] = "0"
        with xl.bind_reader("agent", "my-run"):
            # Own working memory stays frictionless even on misconfig.
            self.assertIsNone(xl.check_exchange_read(
                "/x/runs/my-run/exchanges.jsonl", n_entries=10))

    def test_zero_window_does_not_block_allowlisted_reads(self):
        os.environ["GOV_EXCHANGE_WINDOW_SEC"] = "0"
        os.environ["GOV_EXCHANGE_READ_ALLOW"] = "unknown:victim-1"
        # The allowlist path never consults the window; an explicit trust
        # decision keeps its meaning under window misconfiguration.
        self.assertIsNone(xl.check_exchange_read(_xp(1), n_entries=10))

    def test_malformed_window_falls_back_to_documented_default(self):
        # Non-numeric was already safe (audit-confirmed): the documented
        # default 900 applies, so the tripwire still works.
        os.environ["GOV_EXCHANGE_WINDOW_SEC"] = "not-a-number"
        denied = self._reads(6)  # limit is 5
        self.assertEqual(denied, 1)


# -- F166: monotonic window, boot-epoch aware ------------------------

class F166MonotonicWindowTest(_Base):
    def test_forward_wall_jump_does_not_empty_window(self):
        t0 = 1_700_000_000.0
        with mock.patch("time.time", return_value=t0):
            self._reads(3)
            n = len(xl._read_window(self.ledger, "unknown", 900))
        self.assertEqual(n, 3)
        with mock.patch("time.time", return_value=t0 + 3600):
            n2 = len(xl._read_window(self.ledger, "unknown", 900))
        # Pre-fix this is 0 (fail-open); post-fix the monotonic window
        # holds across the wall-clock jump.
        self.assertEqual(n2, 3)

    def test_forward_jump_grants_no_fresh_harvest_budget(self):
        t0 = 1_700_000_000.0
        os.environ["GOV_EXCHANGE_MAX_RUNS"] = "5"
        with mock.patch("time.time", return_value=t0):
            self._reads(4)
        with mock.patch("time.time", return_value=t0 + 3600):
            # 5th distinct run: allowed (4+1 <= 5); 6th: must trip.
            xl.check_exchange_read(_xp(4), n_entries=10)
            with self.assertRaises(ExchangeAccessDenied):
                xl.check_exchange_read(_xp(5), n_entries=10)

    def test_records_carry_monotonic_stamp_and_boot_epoch(self):
        xl.check_exchange_read(_xp(1), n_entries=10)
        rec = json.loads(self.ledger.read_text(
            encoding="utf-8").splitlines()[0])
        self.assertIn("mono", rec)
        self.assertIn("boot", rec)
        self.assertIsInstance(rec["mono"], float)
        self.assertTrue(rec["boot"])
        # Wall-clock ts stays for audit readability.
        self.assertIn("ts", rec)

    def test_restart_does_not_launder_tempo_budget(self):
        # Guards the cross-boot design decision: a naive monotonic port
        # (records keyed on monotonic with no boot epoch) would treat
        # pre-restart records as expired and hand out a fresh budget.
        # This passes on the pre-fix module too (wall-clock never
        # laundered on restart) -- it pins the new behavior against the
        # naive alternative.
        os.environ["GOV_EXCHANGE_MAX_RUNS"] = "5"
        t0 = 1_700_000_000.0
        with mock.patch("time.time", return_value=t0), \
                mock.patch.object(xl, "_BOOT_EPOCH", "epoch-a"):
            self._reads(4)
        # Simulated restart: new boot epoch, wall clock barely moved.
        with mock.patch("time.time", return_value=t0 + 100), \
                mock.patch.object(xl, "_BOOT_EPOCH", "epoch-b"):
            xl.check_exchange_read(_xp(4), n_entries=10)
            with self.assertRaises(ExchangeAccessDenied):
                xl.check_exchange_read(_xp(5), n_entries=10)

    def test_backward_wall_jump_stays_fail_closed(self):
        t0 = 1_700_000_000.0
        with mock.patch("time.time", return_value=t0):
            self._reads(3)
        with mock.patch("time.time", return_value=t0 - 3600):
            n = len(xl._read_window(self.ledger, "unknown", 900))
        self.assertEqual(n, 3)

    def test_legacy_records_without_mono_use_wall_clock(self):
        # Pre-fix ledgers have no mono/boot fields; they take the
        # wall-clock arm (status-quo behavior, no worse than before).
        t0 = 1_700_000_000.0
        xl._append_record(self.ledger, {"event": "exchange_read",
                                       "ts": t0,
                                       "reader_key": "unknown",
                                       "target_run_id": "victim-0"})
        with mock.patch("time.time", return_value=t0 + 100):
            n = len(xl._read_window(self.ledger, "unknown", 900))
        self.assertEqual(n, 1)
        with mock.patch("time.time", return_value=t0 + 3600):
            n = len(xl._read_window(self.ledger, "unknown", 900))
        self.assertEqual(n, 0)


# -- F170: bounded scan + compaction ---------------------------------

class F170BoundedLedgerTest(_Base):
    def _old_record(self, ts, i):
        return {"event": "exchange_read", "ts": ts,
                "reader_key": "unknown", "target_run_id": "old-%d" % i}

    def test_compaction_drops_window_irrelevant_records(self):
        now = 1_700_000_000.0
        # Seed past the (lowered) cap without compacting: the cap is
        # read per append, so seed big then shrink it for the trigger.
        os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "10000000"
        with mock.patch("time.time", return_value=now):
            for i in range(300):
                xl._append_record(self.ledger,
                                  self._old_record(now - 100000, i))
            size_before = self.ledger.stat().st_size
            self.assertGreater(size_before, 20000)
            # One fresh append past the cap triggers compaction.
            os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "20000"
            xl._append_record(self.ledger,
                              self._old_record(now, 9999))
            size_after = self.ledger.stat().st_size
        # Pre-fix the file only grows; post-fix the 300 stale records
        # are dropped and the file shrinks.
        self.assertLess(size_after, size_before)
        recs = [json.loads(l) for l in
                self.ledger.read_text(encoding="utf-8").splitlines()
                if l.strip()]
        self.assertTrue(all(r["target_run_id"] == "old-9999"
                            for r in recs))

    def test_compaction_keeps_window_relevant_records(self):
        os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "20000"
        now = 1_700_000_000.0
        with mock.patch("time.time", return_value=now):
            for i in range(300):
                xl._append_record(self.ledger,
                                  self._old_record(now - 100000, i))
            for i in range(5):
                xl.check_exchange_read(_xp(i), n_entries=10)
            size_after = self.ledger.stat().st_size
        # The 5 fresh reads must survive compaction.
        recs = [json.loads(l) for l in
                self.ledger.read_text(encoding="utf-8").splitlines()
                if l.strip()]
        targets = {r["target_run_id"] for r in recs
                   if r.get("event") == "exchange_read"}
        for i in range(5):
            self.assertIn("victim-%d" % i, targets)
        self.assertLess(size_after, 20000 + 5000)

    def test_truncated_tail_scan_denies_fail_closed(self):
        # Tail budget smaller than the fresh records present: the guard
        # cannot prove the allow case -> deny, never warn-and-continue.
        # Seed via _append_record: seeding through check_exchange_read
        # would itself (correctly) hit the truncation deny.
        os.environ["GOV_EXCHANGE_LEDGER_TAIL_BYTES"] = "300"
        os.environ["GOV_EXCHANGE_MAX_RUNS"] = "5000"
        for i in range(10):
            xl._append_record(self.ledger, {
                "event": "exchange_read", "ts": time.time(),
                "mono": time.monotonic(), "boot": xl._boot_epoch(),
                "reader_key": "unknown",
                "target_run_id": "victim-%d" % i})
        with self.assertRaises(ExchangeAccessDenied) as cm:
            xl.check_exchange_read(_xp(10), n_entries=10)
        self.assertIn("truncat", str(cm.exception).lower())

    def test_compaction_failure_denies_rather_than_grows_unbounded(self):
        os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "10"
        now = 1_700_000_000.0
        with mock.patch("time.time", return_value=now):
            xl._append_record(self.ledger, self._old_record(now, 1))
            # Break the atomic replace: compaction cannot run safely.
            with mock.patch("os.replace",
                             side_effect=OSError("disk read-only")):
                with self.assertRaises(ExchangeAccessDenied):
                    xl._append_record(self.ledger,
                                      self._old_record(now, 2))

    def test_stale_records_do_not_inflate_read_cost(self):
        # 3000 stale records compacted away: the window scan stays
        # bounded by the tail budget, not by total history.
        os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "20000"
        now = 1_700_000_000.0
        with mock.patch("time.time", return_value=now):
            for i in range(3000):
                xl._append_record(self.ledger,
                                  self._old_record(now - 100000, i))
            # Trigger compaction with one fresh record.
            xl._append_record(self.ledger, self._old_record(now, 9999))
            recs, truncated = xl._read_window_full(
                self.ledger, "unknown", 900)
        self.assertFalse(truncated)
        self.assertEqual(len(recs), 1)

    def test_concurrent_compacting_appends_lose_no_records(self):
        # Compaction is read-modify-replace: concurrent appender threads
        # must not lose records through the temp-file / replace window.
        # Tiny threshold forces every append to take the compact path.
        os.environ["GOV_EXCHANGE_LEDGER_COMPACT_BYTES"] = "10"
        errors = []
        import threading as _th

        def worker(w):
            try:
                for i in range(25):
                    xl._append_record(
                        self.ledger,
                        {"event": "exchange_read", "ts": time.time(),
                         "mono": time.monotonic(),
                         "boot": xl._boot_epoch(),
                         "reader_key": "unknown",
                         "target_run_id": "w%d-%d" % (w, i)})
            except Exception as e:  # noqa: BLE001 - collect, don't hide
                errors.append(e)

        threads = [_th.Thread(target=worker, args=(w,))
                   for w in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        targets = {json.loads(l)["target_run_id"]
                   for l in self.ledger.read_text(
                       encoding="utf-8").splitlines() if l.strip()}
        # Every thread's records were window-relevant (fresh), so all
        # 200 must survive every compaction.
        self.assertEqual(len(targets), 200)


if __name__ == "__main__":
    unittest.main()
