"""Unit tests for gov/drift_report.py.

Conventions: explicit `now` everywhere (drift_report is deterministic
given now); module-level staging default is not needed (no deployment
gate in this module); pin 1569 = 1541 (wave-280 merge) + 22 new codes (wave-281 lanes)
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

TAXONOMY_PIN = 1945 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 3: pin 1933 -> 1945 (+12 quorum-*)

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
