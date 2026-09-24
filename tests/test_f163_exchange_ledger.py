"""F163 regression tests: exchange-access ledger (bulk harvest control).

Red-first: these tests were written against the break battery
(evals/f163_harvest_break.py) and fail without gov/exchange_ledger.py
hooked into the log seam.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from gov import exchange_ledger as xl
from gov.exchange_ledger import (ExchangeAccessDenied, bind_reader,
                                 exchange_target_for_path)
from gov.log import ActionLog, read_entries, read_entries_with_stats


def _write_run(runs_dir, run_id, n):
    d = runs_dir / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "actions.jsonl").write_text(
        "\n".join(json.dumps({"event": "tool_call", "seq": j})
                  for j in range(n)) + "\n", encoding="utf-8")
    return d / "actions.jsonl"


class F163ExchangeLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="f163t-"))
        self.runs = self.tmp / "runs"
        self.ledger = self.tmp / "exchange_access.jsonl"
        self._saved = {}
        for k, v in {
                "GOV_EXCHANGE_LEDGER_PATH": str(self.ledger),
                "GOV_EXCHANGE_MAX_RUNS": "5",
                "GOV_EXCHANGE_WINDOW_SEC": "900",
                "GOV_EXCHANGE_MAX_SINGLE_READ": "100000",
                "GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL": "0",
                "GOV_EXCHANGE_READ_ALLOW": "",
        }.items():
            self._saved[k] = os.environ.get(k)
            os.environ[k] = v

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _records(self):
        if not self.ledger.exists():
            return []
        return [json.loads(l) for l in
                self.ledger.read_text(encoding="utf-8").splitlines()
                if l.strip()]

    # -- path classification --------------------------------------

    def test_target_run_id_under_runs_dir(self):
        p = self.tmp / "runs" / "demo-20260924-1" / "actions.jsonl"
        self.assertEqual(exchange_target_for_path(p), "demo-20260924-1")

    def test_transcript_jsonl_classified(self):
        p = self.tmp / "atk_x" / "run1" / "transcript.jsonl"
        self.assertEqual(exchange_target_for_path(p), "run1")

    def test_other_paths_skipped(self):
        self.assertIsNone(exchange_target_for_path(
            self.tmp / "notes.jsonl"))
        self.assertIsNone(exchange_target_for_path(
            self.tmp / "data" / "actions.json"))
        self.assertIsNone(exchange_target_for_path(
            self.tmp / "other" / "actions.jsonl"))

    # -- C4: own-run reads stay frictionless -----------------------

    def test_own_run_read_is_silent(self):
        path = _write_run(self.runs, "run-00", 10)
        with bind_reader("agent-7", "run-00"):
            for _ in range(3):
                self.assertEqual(len(read_entries(path)), 10)
                self.assertEqual(len(read_entries_with_stats(path)[0]),
                                 10)
        self.assertEqual(self._records(), [])

    # -- C1: cross-run reads are recorded ---------------------------

    def test_cross_run_read_recorded(self):
        path = _write_run(self.runs, "run-01", 10)
        with bind_reader("agent-7", "run-00"):
            self.assertEqual(len(read_entries(path)), 10)
        recs = self._records()
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["event"], "exchange_read")
        self.assertEqual(rec["reader_principal"], "agent-7")
        self.assertEqual(rec["reader_run_id"], "run-00")
        self.assertEqual(rec["target_run_id"], "run-01")
        self.assertEqual(rec["n_entries"], 10)
        self.assertEqual(rec["decision"], "allow")
        self.assertNotIn(str(self.tmp), rec["path_tail"])

    def test_unknown_reader_recorded_as_unknown(self):
        path = _write_run(self.runs, "run-01", 5)
        self.assertEqual(len(read_entries(path)), 5)
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["reader_principal"], "unknown")
        self.assertIsNone(recs[0]["reader_run_id"])

    # -- C2: harvest tempo trips fail-closed ------------------------

    def test_bulk_tempo_denies_fail_closed(self):
        for i in range(5):
            _write_run(self.runs, "run-%02d" % i, 10)
        with bind_reader("harvester", "run-99"):
            for i in range(5):
                read_entries(self.runs / ("run-%02d" % i)
                             / "actions.jsonl")
            with self.assertRaises(ExchangeAccessDenied):
                read_entries(self.runs / "run-05" / "actions.jsonl")
        recs = self._records()
        denied = [r for r in recs if r["event"] == "exchange_read_denied"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["target_run_id"], "run-05")
        self.assertEqual(denied[0]["decision"], "deny")
        self.assertIn("tempo", denied[0]["reason"])

    def test_denied_caller_receives_no_entries(self):
        _write_run(self.runs, "run-01", 10)
        with bind_reader("harvester", "run-99"):
            got = []
            for i in range(2, 12):
                _write_run(self.runs, "run-%02d" % i, 10)
                try:
                    got.append(read_entries(
                        self.runs / ("run-%02d" % i) / "actions.jsonl"))
                except ExchangeAccessDenied:
                    got.append(None)
        self.assertIsNone(got[-1])  # fail-closed: no entries leak

    # -- C3: single full-trace read trips ---------------------------

    def test_single_huge_read_denies(self):
        path = _write_run(self.runs, "run-big", 3000)
        os.environ["GOV_EXCHANGE_MAX_SINGLE_READ"] = "1000"
        with self.assertRaises(ExchangeAccessDenied):
            read_entries(path)
        denied = [r for r in self._records()
                  if r["event"] == "exchange_read_denied"]
        self.assertEqual(len(denied), 1)
        self.assertIn("scale", denied[0]["reason"])

    # -- C5: strict posture ------------------------------------------

    def test_strict_mode_denies_without_allowlist(self):
        os.environ["GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL"] = "1"
        path = _write_run(self.runs, "run-02", 10)
        with bind_reader("agent-7", "run-00"):
            with self.assertRaises(ExchangeAccessDenied):
                read_entries(path)
        denied = [r for r in self._records()
                  if r["event"] == "exchange_read_denied"]
        self.assertEqual(len(denied), 1)

    def test_allowlist_restores_access_in_strict_mode(self):
        os.environ["GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL"] = "1"
        os.environ["GOV_EXCHANGE_READ_ALLOW"] = "agent-7:run-02"
        path = _write_run(self.runs, "run-02", 10)
        with bind_reader("agent-7", "run-00"):
            self.assertEqual(len(read_entries(path)), 10)
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["event"], "exchange_read")
        self.assertEqual(recs[0]["reason"], "allowlisted")

    def test_strict_mode_denies_unknown_reader(self):
        os.environ["GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL"] = "1"
        path = _write_run(self.runs, "run-03", 10)
        with self.assertRaises(ExchangeAccessDenied):
            read_entries(path)

    # -- chained-log mirror ------------------------------------------

    def test_mirror_to_chained_log(self):
        from tests.keyfixture import provision_test_key
        provision_test_key()
        log_path = self.tmp / "reader" / "actions.jsonl"
        log = ActionLog(log_path)
        path = _write_run(self.runs, "run-04", 7)
        with bind_reader("agent-7", "run-00", action_log=log):
            read_entries(path)
        mirrored = [e for e in read_entries(log_path)
                    if e.get("event") == "exchange_read"]
        self.assertEqual(len(mirrored), 1)
        self.assertEqual(mirrored[0]["target_run_id"], "run-04")
        self.assertEqual(mirrored[0]["reader_principal"], "agent-7")

    # -- ledger failure is fail-closed --------------------------------

    def test_unwritable_ledger_denies_cross_run_read(self):
        os.environ["GOV_EXCHANGE_LEDGER_PATH"] = str(self.tmp)
        path = _write_run(self.runs, "run-05", 10)
        with bind_reader("agent-7", "run-00"):
            with self.assertRaises(ExchangeAccessDenied):
                read_entries(path)

    def test_unwritable_ledger_leaves_own_run_alone(self):
        os.environ["GOV_EXCHANGE_LEDGER_PATH"] = str(self.tmp)
        path = _write_run(self.runs, "run-00", 10)
        with bind_reader("agent-7", "run-00"):
            self.assertEqual(len(read_entries(path)), 10)


if __name__ == "__main__":
    unittest.main()
