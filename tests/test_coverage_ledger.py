"""Unit tests for gov/coverage_ledger.py (wave-275 lane D).

Clean-room DeTTECT patterns (GPL-3.0, no code reuse): dated score logbook,
visibility-vs-detection split, data-quality contract, denominator +
proof-method discipline, monitor-never-implies-prevention.
"""

import copy
import os
import re
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w275-coverage-unit")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.coverage_ledger as cl  # noqa: E402
from gov import decision_codes as dc  # noqa: E402

TAXONOMY_PIN = 1541  # Wave-275 lane D: pin 1485 -> 1485 (+5 coverage-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*)

T0 = "2026-10-01T12:00:00+00:00"
T1 = "2026-10-01T13:00:00+00:00"
T2 = "2026-10-01T14:00:00+00:00"

GOOD = {"completeness": 5, "freshness": 5, "depth": 5,
        "brittleness": 5, "integrity": 5}


def _ledger_with_scored():
    led = cl.CoverageLedger()
    led.record_technique("t1", visibility="FULL", sources={"s1": dict(GOOD)})
    led.score("t1", 3, proof_method="simulated-events", scored_at=T1)
    return led


class ScaleTest(unittest.TestCase):
    def test_scale_constants(self):
        self.assertEqual((cl.SCORE_MIN, cl.SCORE_MAX), (-1, 5))
        self.assertEqual(cl.SCORE_VISIBLE_ONLY, 0)
        self.assertEqual(set(cl.VISIBILITIES), {"NONE", "PARTIAL", "FULL"})
        self.assertEqual(set(cl.QUALITY_DIMS),
                         {"completeness", "freshness", "depth",
                          "brittleness", "integrity"})

    def test_score_out_of_range_rejected(self):
        led = cl.CoverageLedger()
        led.record_technique("t", visibility="FULL")
        for bad in (-2, 6, 1.5, True, "3"):
            with self.assertRaises(ValueError, msg="score=%r" % (bad,)):
                led.score("t", bad, proof_method="x", scored_at=T0)

    def test_bad_visibility_rejected(self):
        led = cl.CoverageLedger()
        with self.assertRaises(ValueError):
            led.record_technique("t", visibility="MOSTLY")

    def test_bad_quality_dims_rejected(self):
        led = cl.CoverageLedger()
        bad = dict(GOOD, freshness=6)
        with self.assertRaises(ValueError):
            led.record_technique("t", visibility="FULL", sources={"s": bad})
        with self.assertRaises(ValueError):
            led.set_source_quality("nope", dict(GOOD))


class LogbookTest(unittest.TestCase):
    def test_append_is_chained_and_monotonic(self):
        led = _ledger_with_scored()
        e2 = led.score("t1", 4, proof_method="simulated-events", scored_at=T2)
        book = led.logbook("t1")
        self.assertEqual([e["seq"] for e in book], [0, 1])
        self.assertEqual(book[1]["prev_digest"], book[0]["digest"])
        self.assertEqual(book[0]["prev_digest"], cl.GENESIS)
        self.assertEqual(e2["seq"], 1)
        led.verify_chain(book)  # genuine chain verifies

    def test_backdated_entry_refused(self):
        led = _ledger_with_scored()
        with self.assertRaises(cl.CoverageLedgerError) as ctx:
            led.score("t1", 4, proof_method="x", scored_at=T0)
        self.assertEqual(ctx.exception.code,
                         "coverage-refused-backdated-entry")

    def test_equal_timestamp_allowed(self):
        led = _ledger_with_scored()
        e = led.score("t1", 4, proof_method="x", scored_at=T1)  # not earlier
        self.assertEqual(e["seq"], 1)

    def test_rewritten_history_detected(self):
        led = _ledger_with_scored()
        book = led.logbook("t1")
        forged = dict(book[0])
        forged["score"] = 5
        book[0] = forged
        with self.assertRaises(cl.CoverageLedgerError) as ctx:
            led.verify_chain(book)
        self.assertEqual(ctx.exception.code, "coverage-logbook-chain-broken")

    def test_dropped_entry_detected(self):
        led = _ledger_with_scored()
        led.score("t1", 4, proof_method="x", scored_at=T2)
        book = led.logbook("t1")
        with self.assertRaises(cl.CoverageLedgerError) as ctx:
            led.verify_chain(book[1:])  # first entry dropped
        self.assertEqual(ctx.exception.code, "coverage-logbook-chain-broken")

    def test_logbook_returns_copies(self):
        led = _ledger_with_scored()
        book = led.logbook("t1")
        book[0]["score"] = 5
        # internal state untouched: genuine chain still verifies
        led.verify_chain(led.logbook("t1"))

    def test_keyed_chain_marked(self):
        led = _ledger_with_scored()
        entry = led.logbook("t1")[0]
        self.assertTrue(entry["chain_keyed"])
        self.assertIsInstance(entry["key_epoch"], str)
        self.assertTrue(entry["key_epoch"])  # epoch recorded, never empty

    def test_score_requires_proof_method(self):
        led = cl.CoverageLedger()
        led.record_technique("t", visibility="FULL")
        for bad in ("", "   ", None):
            with self.assertRaises(cl.CoverageLedgerError) as ctx:
                led.score("t", 2, proof_method=bad, scored_at=T0)
            self.assertEqual(ctx.exception.code,
                             "coverage-refused-no-proof-method")

    def test_unknown_technique_rejected(self):
        led = cl.CoverageLedger()
        with self.assertRaises(ValueError):
            led.score("ghost", 2, proof_method="x", scored_at=T0)

    def test_malformed_timestamp_is_value_error_not_backdated(self):
        led = cl.CoverageLedger()
        led.record_technique("t", visibility="FULL")
        for bad in ("not-a-date", "2026-10-01T12:00:00", 42):
            with self.assertRaises(ValueError):
                led.score("t", 2, proof_method="x", scored_at=bad)

    def test_non_keyprovider_failure_propagates_not_downgraded(self):
        # Regression: _chain_record catches only NoKeyConfiguredError; a
        # real keyprovider bug must propagate, never silently downgrade
        # to an unkeyed chain.
        from unittest import mock
        led = cl.CoverageLedger()
        led.record_technique("t", visibility="FULL")
        with mock.patch.object(cl._cs, "resolve_chain_key",
                               side_effect=RuntimeError("keyprovider bug")):
            with self.assertRaises(RuntimeError):
                led.score("t", 2, proof_method="x", scored_at=T0)
        self.assertEqual(len(led.logbook("t")), 0)  # nothing half-chained


class EmissionTest(unittest.TestCase):
    def test_no_denominator_refused(self):
        led = _ledger_with_scored()
        for bad in (None, []):
            with self.assertRaises(cl.CoverageLedgerError) as ctx:
                led.emit_coverage(denominator=bad, proof_method="x")
            self.assertEqual(ctx.exception.code,
                             "coverage-refused-no-denominator")

    def test_string_denominator_is_malformed(self):
        led = _ledger_with_scored()
        with self.assertRaises(cl.CoverageLedgerError) as ctx:
            led.emit_coverage(denominator="t1t2", proof_method="x")
        self.assertEqual(ctx.exception.code,
                         "coverage-refused-no-denominator")

    def test_no_proof_method_refused(self):
        led = _ledger_with_scored()
        for bad in (None, "", "  "):
            with self.assertRaises(cl.CoverageLedgerError) as ctx:
                led.emit_coverage(denominator=["t1"], proof_method=bad)
            self.assertEqual(ctx.exception.code,
                             "coverage-refused-no-proof-method")

    def test_score_zero_never_counts(self):
        led = cl.CoverageLedger()
        led.record_technique("vis", visibility="FULL",
                             sources={"s": dict(GOOD)})
        led.score("vis", 0, proof_method="monitor-counts", scored_at=T1)
        rep = led.emit_coverage(denominator=["vis"],
                                proof_method="monitor-counts")
        self.assertEqual(rep["covered"], 0)
        self.assertEqual(rep["visible_not_detected"], ["vis"])
        self.assertFalse(rep["prevents"])

    def test_no_sources_excluded_not_counted(self):
        led = cl.CoverageLedger()
        led.record_technique("lonely", visibility="FULL")
        led.score("lonely", 3, proof_method="red-probes", scored_at=T1)
        rep = led.emit_coverage(denominator=["lonely"],
                                proof_method="red-probes")
        self.assertEqual(rep["covered"], 0)
        self.assertIsNone(
            rep["techniques"]["lonely"]["sources_contract_ok"])
        self.assertEqual(rep["qualified_exclusions"][0]["reason"],
                         "no-sources")

    def test_source_quality_collapse_qualified_not_silent(self):
        led = _ledger_with_scored()
        led.set_source_quality("s1", dict(GOOD, freshness=1))
        rep = led.emit_coverage(denominator=["t1"], proof_method="x")
        self.assertEqual(rep["covered"], 0)
        self.assertEqual(len(rep["qualified_exclusions"]), 1)
        self.assertEqual(rep["qualified_exclusions"][0]["technique"], "t1")
        self.assertEqual(rep["qualified_exclusions"][0]["reason"],
                         "source-quality")

    def test_positive_control(self):
        led = _ledger_with_scored()
        rep = led.emit_coverage(denominator=["t1", "t2"], proof_method="x")
        self.assertEqual(rep["covered"], 1)
        self.assertEqual(rep["denominator"], 2)
        self.assertAlmostEqual(rep["percentage"], 50.0)
        self.assertEqual(rep["proof_method"], "x")
        self.assertFalse(rep["prevents"])
        self.assertEqual(rep["mode"], "monitor")
        self.assertIn("t1", rep["techniques"])
        self.assertEqual(rep["techniques"]["t1"]["score"], 3)

    def test_duplicate_denominator_deduplicated_f297(self):
        # F297: a repeated technique id must not inflate the percentage.
        led = _ledger_with_scored()
        rep = led.emit_coverage(denominator=["t1", "t1", "t1", "t2"],
                                proof_method="x")
        self.assertEqual(rep["denominator"], 2)
        self.assertEqual(rep["duplicates_removed"], 2)
        self.assertEqual(rep["covered"], 1)
        self.assertAlmostEqual(rep["percentage"], 50.0)
        self.assertEqual(list(rep["techniques"].keys()), ["t1", "t2"])

    def test_declare_prevention_always_refused(self):
        led = _ledger_with_scored()
        with self.assertRaises(cl.CoverageLedgerError) as ctx:
            led.declare_prevention()
        self.assertEqual(ctx.exception.code,
                         "coverage-refused-monitor-implies-prevention")


class MonitorWiringTest(unittest.TestCase):
    def _monitor_report(self):
        return {"mode": "monitor",
                "monitor_would_deny": {"gatehard-policy-denied": 7,
                                       "unmapped-code": 2},
                "monitor_would_allow": 3,
                "monitor_evaluations": 12}

    def test_ingest_creates_visibility_entries(self):
        led = cl.CoverageLedger()
        led.register_code_mapping("gatehard-policy-denied", "tech-e")
        out = led.ingest_monitor_report(self._monitor_report())
        self.assertEqual(out["techniques_ingested"], 2)
        book = led.logbook("tech-e")
        self.assertEqual(book[0]["score"], 0)  # monitor: visible, not detected
        self.assertEqual(book[0]["proof_method"], "monitor-counts")

    def test_ingest_refuses_non_monitor(self):
        led = cl.CoverageLedger()
        with self.assertRaises(ValueError):
            led.ingest_monitor_report({"mode": "protect"})

    def test_scan_summary_shape_ingested(self):
        led = cl.CoverageLedger()
        led.register_code_mapping("gatehard-cap-deny", "tech-h")
        out = led.ingest_monitor_report(
            {"would_allow": 40, "would_deny": {"gatehard-cap-deny": 12}})
        self.assertEqual(out["techniques_ingested"], 1)
        book = led.logbook("tech-h")
        self.assertEqual(book[0]["score"], 0)
        self.assertEqual(book[0]["proof_method"], "scan-summary")
        # A counter proves observation of matching requests, not full
        # technique visibility.
        self.assertEqual(led._techniques["tech-h"]["visibility"], "PARTIAL")

    def test_reingest_same_observation_appends_no_duplicate(self):
        led = cl.CoverageLedger()
        led.register_code_mapping("gatehard-cap-deny", "tech-j")
        report = {"mode": "monitor",
                  "monitor_would_deny": {"gatehard-cap-deny": 7},
                  "monitor_would_allow": 3, "monitor_evaluations": 10}
        led.ingest_monitor_report(report)
        led.ingest_monitor_report(report)
        self.assertEqual(len(led.logbook("tech-j")), 1)
        # A changed counter is new information: appended.
        report["monitor_would_deny"] = {"gatehard-cap-deny": 9}
        led.ingest_monitor_report(report)
        self.assertEqual(len(led.logbook("tech-j")), 2)
        self.assertTrue(led.verify_chain(led.logbook("tech-j")) >= 2)

    def test_monitor_entries_never_count(self):
        led = cl.CoverageLedger()
        led.register_code_mapping("gatehard-policy-denied", "tech-e")
        led.ingest_monitor_report(self._monitor_report())
        rep = led.emit_coverage(denominator=["tech-e"],
                                proof_method="monitor-counts")
        self.assertEqual(rep["covered"], 0)
        self.assertEqual(rep["visible_not_detected"], ["tech-e"])

    def test_unmapped_code_gets_explicit_technique(self):
        led = cl.CoverageLedger()
        led.ingest_monitor_report(self._monitor_report())
        rep = led.emit_coverage(
            denominator=["unmapped:unmapped-code"],
            proof_method="monitor-counts")
        self.assertEqual(rep["visible_not_detected"],
                         ["unmapped:unmapped-code"])


class TaxonomyTest(unittest.TestCase):
    def test_pin_from_raw_literals(self):
        src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
        literals = re.findall(
            r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        self.assertEqual(len(literals), TAXONOMY_PIN)
        self.assertEqual(len(set(literals)), TAXONOMY_PIN)

    def test_len_taxonomy(self):
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)

    def test_new_codes_registered(self):
        for code in ("coverage-logbook-chain-broken",
                     "coverage-refused-backdated-entry",
                     "coverage-refused-monitor-implies-prevention",
                     "coverage-refused-no-denominator",
                     "coverage-refused-no-proof-method"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "coverage")


if __name__ == "__main__":
    unittest.main()
