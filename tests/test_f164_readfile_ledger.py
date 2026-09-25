"""F164 regression tests: the agent read_file tool path goes through the
F163 exchange-access ledger.

Red-first: written against the UNFIXED tree (gov/executor.py never calls
check_exchange_read). On the unfixed tree the cross-run cases FAIL:
read_file of another run's exchanges returns real bytes with zero
ledger records and no tripwire. Post-fix all cases are green.

Public seams only: tool-call status, returned content, ledger record
counts/events, chained-log mirror entries.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import re
import unittest
from pathlib import Path

from tests.harness import make_run
from gov.exchange_ledger import ExchangeAccessDenied


def _plant_victim(ctx, run_id, n=20):
    """Plant a victim run transcript inside the agent's file-readable
    sandbox scope."""
    sb = Path(str(ctx["executor"]._sandbox_resolved))
    d = sb / "runs" / run_id
    d.mkdir(parents=True, exist_ok=True)
    entries = [{"seq": i, "event": "tool_call",
                "thought": "VICTIM-TRACE-%s-%d: secret plan" % (run_id, i)}
               for i in range(n)]
    (d / "exchanges.jsonl").write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n",
        encoding="utf-8")
    return "runs/%s/exchanges.jsonl" % run_id


class F164ReadFileLedgerTest(unittest.TestCase):
    def setUp(self):
        self._saved = {}
        for k, v in {
                "GOV_EXCHANGE_LEDGER_PATH": "",
                "GOV_EXCHANGE_MAX_RUNS": "5",
                "GOV_EXCHANGE_WINDOW_SEC": "900",
                "GOV_EXCHANGE_MAX_SINGLE_READ": "100000",
                "GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL": "0",
                "GOV_EXCHANGE_READ_ALLOW": "",
        }.items():
            self._saved[k] = os.environ.get(k)
            if v == "":
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.ctx = make_run()
        self.ex = self.ctx["executor"]
        self.ident = self.ctx["identities"]["researcher"]
        # Per-test ledger: one file per test so record assertions are
        # isolated. Placed under the run dir (outside the sandbox) so
        # the agent cannot read or tamper with it via read_file.
        self.ledger = Path(str(self.ctx["run_dir"])) / "exchange_access.jsonl"
        os.environ["GOV_EXCHANGE_LEDGER_PATH"] = str(self.ledger)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _records(self):
        if not self.ledger.exists():
            return []
        return [json.loads(l) for l in
                self.ledger.read_text(encoding="utf-8").splitlines()
                if l.strip()]

    # -- C1: single cross-run read_file harvest is recorded ----------

    def test_cross_run_readfile_harvest_recorded(self):
        rel = _plant_victim(self.ctx, "victim-run-9", n=20)
        res = self.ex.call(self.ident, "read_file", path=rel)
        self.assertEqual(res.get("status"), "executed")
        content = str(((res.get("result") or {}).get("content")) or "")
        self.assertIn("VICTIM-TRACE-victim-run-9-0", content)
        recs = self._records()
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["event"], "exchange_read")
        self.assertEqual(rec["target_run_id"], "victim-run-9")
        self.assertEqual(rec["reader_principal"], "research-org")
        self.assertEqual(rec["decision"], "allow")
        self.assertEqual(rec["n_entries"], 20)

    def test_harvest_record_mirrored_to_chained_log(self):
        rel = _plant_victim(self.ctx, "victim-run-9", n=20)
        self.ex.call(self.ident, "read_file", path=rel)
        events = [e for e in self.ctx["read_log"]()
                  if e.get("event") == "exchange_read"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["target_run_id"], "victim-run-9")

    # -- C2: bulk harvest via read_file trips the tempo denial -------

    def test_bulk_readfile_harvest_trips_tempo_denial(self):
        # GOV_EXCHANGE_MAX_RUNS=5: five distinct victim runs read fine,
        # the sixth distinct run is denied fail-closed.
        for i in range(5):
            rel = _plant_victim(self.ctx, "victim-%d" % i, n=10)
            res = self.ex.call(self.ident, "read_file", path=rel)
            self.assertEqual(res.get("status"), "executed")
        rel = _plant_victim(self.ctx, "victim-5", n=10)
        with self.assertRaises(ExchangeAccessDenied):
            self.ex.call(self.ident, "read_file", path=rel)
        recs = self._records()
        denied = [r for r in recs if r["event"] == "exchange_read_denied"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["target_run_id"], "victim-5")
        self.assertEqual(denied[0]["decision"], "deny")
        # The denial is mirrored onto the reader's chained log (hash-
        # chain integrity for the refusal, same as the seam).
        mirrored = [e for e in self.ctx["read_log"]()
                    if e.get("event") == "exchange_read_denied"]
        self.assertEqual(len(mirrored), 1)
        self.assertEqual(mirrored[0]["target_run_id"], "victim-5")
        # The 6th read's bytes never reached the agent: the denial
        # raised out of call(), so no result dict with content exists.
        allowed = [r for r in recs if r["event"] == "exchange_read"]
        self.assertEqual(len(allowed), 5)

    def test_single_full_trace_pull_trips_size_denial(self):
        os.environ["GOV_EXCHANGE_MAX_SINGLE_READ"] = "50"
        rel = _plant_victim(self.ctx, "victim-big", n=200)
        with self.assertRaises(ExchangeAccessDenied):
            self.ex.call(self.ident, "read_file", path=rel)
        denied = [r for r in self._records()
                  if r["event"] == "exchange_read_denied"]
        self.assertEqual(len(denied), 1)
        self.assertIn("scale", denied[0]["reason"])

    # -- C3: own-run reads stay frictionless --------------------------

    def test_own_run_readfile_frictionless(self):
        own = self.ex.run_id
        rel = _plant_victim(self.ctx, own, n=15)
        res = self.ex.call(self.ident, "read_file", path=rel)
        self.assertEqual(res.get("status"), "executed")
        content = str(((res.get("result") or {}).get("content")) or "")
        self.assertIn("VICTIM-TRACE-%s-0" % own, content)
        self.assertEqual(self._records(), [])

    # -- C4: allowlist + strict posture preserved on the tool path ----

    def test_allowlisted_cross_run_read_allowed_and_recorded(self):
        os.environ["GOV_EXCHANGE_READ_ALLOW"] = "research-org:victim-allow"
        rel = _plant_victim(self.ctx, "victim-allow", n=12)
        res = self.ex.call(self.ident, "read_file", path=rel)
        self.assertEqual(res.get("status"), "executed")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["event"], "exchange_read")
        self.assertEqual(recs[0]["reason"], "allowlisted")

    def test_strict_posture_denies_unallowlisted_tool_read(self):
        os.environ["GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL"] = "1"
        rel = _plant_victim(self.ctx, "victim-strict", n=12)
        with self.assertRaises(ExchangeAccessDenied):
            self.ex.call(self.ident, "read_file", path=rel)
        denied = [r for r in self._records()
                  if r["event"] == "exchange_read_denied"]
        self.assertEqual(len(denied), 1)
        self.assertIn("strict", denied[0]["reason"])

    # -- C5: non-exchange reads are untouched -------------------------

    def test_plain_file_read_untouched(self):
        sb = Path(str(self.ex._sandbox_resolved))
        (sb / "notes.txt").write_text("just some notes\n" * 10,
                                      encoding="utf-8")
        res = self.ex.call(self.ident, "read_file", path="notes.txt")
        self.assertEqual(res.get("status"), "executed")
        self.assertIn("just some notes",
                      str(((res.get("result") or {}).get("content")) or ""))
        self.assertEqual(self._records(), [])

    # -- C6: nested bindings attribute to the innermost reader ------

    def test_nested_binding_innermost_reader_wins(self):
        # Spec user story 7: an outer ambient binding (e.g. a parent
        # agent's context on another thread of control) must not leak
        # into the executor's attribution. The executor binds the
        # calling identity for the execution; the outer binding is
        # restored afterwards.
        from gov import exchange_ledger as xl
        rel = _plant_victim(self.ctx, "victim-nest", n=10)
        with xl.bind_reader("outer-parent", "outer-run"):
            res = self.ex.call(self.ident, "read_file", path=rel)
            self.assertEqual(res.get("status"), "executed")
            # Outer binding still in force inside its own scope: the
            # executor's inner binding was unwound on exit.
            self.assertEqual(xl._current_reader()[0], "outer-parent")
            self.assertEqual(xl._current_reader()[1], "outer-run")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["reader_principal"], "research-org")
        self.assertEqual(recs[0]["reader_run_id"], self.ex.run_id)
        self.assertEqual(recs[0]["target_run_id"], "victim-nest")

    # -- no-import-cycle regression pin --------------------------------

    def test_exchange_ledger_has_no_gov_imports(self):
        src = Path(__file__).resolve().parent.parent / "gov" \
            / "exchange_ledger.py"
        text = src.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*(?:from|import)\s+([a-zA-Z0-9_.]+)",
                             text, re.M):
            mod = m.group(1)
            self.assertFalse(mod == "gov" or mod.startswith("gov."),
                             "exchange_ledger imports gov module: %s" % mod)


if __name__ == "__main__":
    unittest.main()
