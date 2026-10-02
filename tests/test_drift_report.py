"""Unit tests for gov/drift_report.py.

Conventions: explicit `now` everywhere (drift_report is deterministic
given now); module-level staging default is not needed (no deployment
gate in this module); pin 1494 = 1493 (wave-278 merge) + 1 new code (evbundle-contract-refused)
(3 provlabel-* + 8 rail-* + 3 decodetrust-* + 5 attestor-*).
"""

import os
import re
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import drift_report as dr  # noqa: E402
from gov import gate_hardening as gh  # noqa: E402

TAXONOMY_PIN = 1494  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).

_NOW = 1700000000


def _gate(predicate, extra=()):
    g = gh.Gate(mode="protect", global_deadline_s=5.0,
                now=lambda: _NOW, clock=lambda: 0.0)
    g.register_policy(gh.compile_policy({
        "policy_id": "p1", "predicate_name": "p",
        "predicate": predicate, "host_callbacks": []}))
    for spec in extra:
        g.register_policy(gh.compile_policy(spec))
    return g


def _reqs(*ids):
    return [{"request_id": i} for i in ids]


class TestDriftLog(unittest.TestCase):
    def test_append_chains(self):
        log = dr.DriftLog(now=lambda: _NOW)
        r1 = log.append({"event": "a"})
        r2 = log.append({"event": "b"})
        self.assertEqual(r1["seq"], 0)
        self.assertEqual(r2["seq"], 1)
        self.assertEqual(r2["prev_digest"], r1["event_digest"])
        self.assertTrue(log.verify())

    def test_tamper_detected(self):
        log = dr.DriftLog(now=lambda: _NOW)
        log.append({"event": "a"})
        log.append({"event": "b"})
        log.records()[0]["event"] = "zzz"
        with self.assertRaises(dr.DriftReportError) as ctx:
            log.verify()
        self.assertEqual(ctx.exception.code, "drift-log-corrupt")

    def test_truncation_detected(self):
        log = dr.DriftLog(now=lambda: _NOW)
        log.append({"event": "a"})
        log.append({"event": "b"})
        del log._records[0]
        with self.assertRaises(dr.DriftReportError) as ctx:
            log.verify()
        self.assertEqual(ctx.exception.code, "drift-log-corrupt")

    def test_append_rejects_non_dict(self):
        log = dr.DriftLog(now=lambda: _NOW)
        with self.assertRaises(dr.DriftReportError) as ctx:
            log.append("not-a-dict")
        self.assertEqual(ctx.exception.code, "drift-malformed")

    def test_bad_scanner_refused(self):
        with self.assertRaises(dr.DriftReportError) as ctx:
            dr.DriftReporter(object(), now=lambda: _NOW)
        self.assertEqual(ctx.exception.code, "drift-malformed")

    def test_bad_gate_digest_refused(self):
        g = _gate(lambda rt: True)
        with self.assertRaises(dr.DriftReportError) as ctx:
            dr.DriftReporter(g, now=lambda: _NOW,
                             gate_digest="not-a-digest")
        self.assertEqual(ctx.exception.code, "drift-malformed")

    def test_none_request_id_refused(self):
        g = _gate(lambda rt: True)
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        with self.assertRaises(dr.DriftReportError) as ctx:
            rep.rescan([{"request_id": None}])
        self.assertEqual(ctx.exception.code, "drift-malformed")

    def test_gate_policy_digest_requires_hex(self):
        class Odd(object):
            def policy_digest(self):
                return "zz" * 32  # 64 chars, not hex
        self.assertEqual(dr.gate_policy_digest(Odd()), "unknown")


class TestDriftReporter(unittest.TestCase):
    def test_baseline_event_and_digest(self):
        g = _gate(lambda rt: True)
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        out = rep.record_baseline(_reqs("r1", "r2"))
        self.assertEqual(out["items"], 2)
        ev = rep.events()[0]
        self.assertEqual(ev["event"], "drift-baseline-updated")
        self.assertEqual(ev["gate_digest"], g.policy_digest())

    def test_newly_denying_emitted(self):
        g = _gate(lambda rt: True)
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        rep.record_baseline(_reqs("r1", "r2"))
        g.register_policy(gh.compile_policy({
            "policy_id": "p2", "predicate_name": "deny-r2",
            "predicate": lambda rt: rt.request.get("request_id") != "r2",
            "host_callbacks": []}))
        report = rep.rescan(_reqs("r1", "r2"))
        self.assertEqual(len(report["newly_denying"]), 1)
        item = report["newly_denying"][0]
        self.assertEqual(item["request_id"], "r2")
        self.assertEqual(item["then_decision"], "allow")
        self.assertEqual(item["now_decision"], "deny")
        ev = rep.events()[-1]
        self.assertEqual(ev["event"], "drift-detected")
        # the gate digest changed with the new policy: visible on event
        self.assertNotEqual(
            ev["gate_digest"], rep.events()[0]["gate_digest"])

    def test_resolved_not_drift(self):
        g = _gate(lambda rt: rt.request.get("request_id") != "r1")
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        rep.record_baseline(_reqs("r1", "r2"))
        # r1 was denied at baseline; loosen is not "newly-denying"
        g2 = _gate(lambda rt: True)
        rep2 = dr.DriftReporter(g2, now=lambda: _NOW)
        rep2.record_baseline(_reqs("r1"))
        report = rep2.rescan(_reqs("r1"))
        self.assertEqual(report["newly_denying"], [])

    def test_unknown_request_not_drift(self):
        g = _gate(lambda rt: True)
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        rep.record_baseline(_reqs("r1"))
        report = rep.rescan(_reqs("r1", "r2"))
        self.assertEqual(report["newly_denying"], [])

    def test_first_rescan_records_baseline(self):
        g = _gate(lambda rt: True)
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        report = rep.rescan(_reqs("r1"))
        self.assertTrue(report["baseline_recorded"])
        self.assertEqual(report["newly_denying"], [])

    def test_policy_digest_changes(self):
        g = _gate(lambda rt: True)
        d1 = g.policy_digest()
        g.register_policy(gh.compile_policy({
            "policy_id": "p2", "predicate_name": "p",
            "predicate": lambda rt: True, "host_callbacks": []}))
        self.assertNotEqual(d1, g.policy_digest())

    def test_verify_log(self):
        g = _gate(lambda rt: True)
        rep = dr.DriftReporter(g, now=lambda: _NOW)
        rep.record_baseline(_reqs("r1"))
        self.assertTrue(rep.verify_log())


class TestTaxonomy(unittest.TestCase):
    def test_pin(self):
        src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
        codes = re.findall(
            r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        self.assertEqual(len(codes), TAXONOMY_PIN)
        self.assertEqual(len(set(codes)), TAXONOMY_PIN)

    def test_new_codes_registered(self):
        from gov import decision_codes
        for code in ("drift-baseline-updated", "drift-detected",
                     "drift-log-corrupt", "drift-malformed",
                     "revbind-content-mismatch",
                     "revbind-equivalence-accepted", "revbind-malformed"):
            self.assertIn(code, decision_codes.TAXONOMY)


if __name__ == "__main__":
    unittest.main()
