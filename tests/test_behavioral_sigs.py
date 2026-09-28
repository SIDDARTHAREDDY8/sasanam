"""Unit tests for gov/behavioral_sigs.py — public seams only.

Seams under test: normalize_entries (fail-closed), SIGNATURES registry
shape/versioning, scan() findings contract, to_discovery_signals()
adapter. Expected values are independent literals, never recomputed
from the implementation.
"""

import unittest

from gov.behavioral_sigs import (
    REGISTRY_VERSION,
    SIGNATURES,
    Finding,
    normalize_entries,
    scan,
    to_discovery_signals,
)

T0 = 1_788_000_000


def ev(t, tool="api_call", event="api_call", principal="p",
       dest=None, target=None, session=None):
    e = {"ts": t, "principal": principal, "tool": tool, "event": event}
    if dest is not None:
        e["dest"] = dest
    if target is not None:
        e["target"] = target
    if session is not None:
        e["session_id"] = session
    return e


class TestNormalize(unittest.TestCase):
    def test_valid_entries_sorted(self):
        valid, skipped = normalize_entries(
            [ev(T0 + 5), ev(T0), {"ts": "garbage", "principal": "p"},
             {"principal": "p"}, {"ts": T0}])
        self.assertEqual(skipped, 3)  # bad ts, missing ts, missing principal
        self.assertEqual([e["_t"] for e in valid], [T0, T0 + 5])

    def test_iso_ts_accepted(self):
        valid, skipped = normalize_entries(
            [{"ts": "2026-09-28T00:00:00Z", "principal": "p"}])
        self.assertEqual(skipped, 0)
        self.assertEqual(len(valid), 1)

    def test_empty_and_none(self):
        self.assertEqual(normalize_entries([]), ([], 0))
        self.assertEqual(normalize_entries(None), ([], 0))


class TestRegistry(unittest.TestCase):
    def test_version_pinned(self):
        self.assertEqual(REGISTRY_VERSION, "1")
        self.assertEqual(len(SIGNATURES), 6)

    def test_every_signature_versioned_and_documented(self):
        for sig_id, sig in SIGNATURES.items():
            self.assertEqual(sig.signature_id, sig_id)
            self.assertTrue(sig.version, sig_id)
            self.assertTrue(sig.name.strip(), sig_id)
            self.assertTrue(sig.desc.strip(), sig_id)
            self.assertTrue(sig.params, sig_id)
            self.assertTrue(sig.fp_control.strip(), sig_id)
            self.assertTrue(sig.evasion_note.strip(), sig_id)
            self.assertTrue(callable(sig.match_fn), sig_id)

    def test_signature_to_dict_round_trip(self):
        d = SIGNATURES["fanned_egress"].to_dict()
        self.assertEqual(d["signature_id"], "fanned_egress")
        self.assertEqual(d["version"], "v1")
        self.assertEqual(d["params"]["min_distinct_dests"], 8)


class TestScanContract(unittest.TestCase):
    def test_one_finding_per_signature_sorted(self):
        findings = scan([ev(T0)])
        self.assertEqual([f.signature_id for f in findings],
                         sorted(SIGNATURES))
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.signature_version,
                             SIGNATURES[f.signature_id].version)
            self.assertIsInstance(f.matched, bool)
            self.assertGreaterEqual(f.strength, 0.0)
            self.assertLessEqual(f.strength, 1.0)
            d = f.to_dict()
            self.assertEqual(d["signature_id"], f.signature_id)

    def test_fanned_egress_boundary(self):
        # exactly 8 distinct dests in window -> matched (boundary)
        entries = [ev(T0 + i, dest="10.0.0.%d" % i) for i in range(8)]
        m = [f for f in scan(entries)
             if f.signature_id == "fanned_egress" and f.matched]
        self.assertEqual(len(m), 1)
        # 7 -> not matched
        entries = [ev(T0 + i, dest="10.0.0.%d" % i) for i in range(7)]
        m = [f for f in scan(entries)
             if f.signature_id == "fanned_egress" and f.matched]
        self.assertEqual(m, [])

    def test_credential_hints_never_invented(self):
        entries = [ev(T0, tool="secrets_read", target="x/ssh-key"),
                   ev(T0 + 10, tool="db_dump", event="export")]
        m = [f for f in scan(entries)
             if f.signature_id == "credential_then_export" and f.matched]
        self.assertEqual(m, [])  # no hints -> absent

    def test_bad_hint_regex_fail_closed(self):
        entries = [ev(T0, tool="secrets_read", target="x/ssh-key")]
        findings = scan(entries, credential_hints=["([unclosed"])
        f = [x for x in findings
             if x.signature_id == "credential_then_export"][0]
        self.assertFalse(f.matched)
        self.assertIn("bad credential hint", f.detail)

    def test_malformed_entries_do_not_break_scan(self):
        entries = [{"ts": "nope", "principal": "p"}, ev(T0)]
        findings = scan(entries)
        self.assertEqual(len(findings), len(SIGNATURES))

    def test_broken_matcher_fail_closed(self):
        import dataclasses
        from unittest import mock

        from gov import behavioral_sigs as bs

        def boom(events, hints):
            raise RuntimeError("simulated matcher bug")

        broken = dataclasses.replace(SIGNATURES["burst_cadence"],
                                     match_fn=boom)
        with mock.patch.dict(bs.SIGNATURES,
                             {"burst_cadence": broken}):
            findings = bs.scan([ev(T0 + i * 2.0) for i in range(12)])
        f = [x for x in findings
             if x.signature_id == "burst_cadence"][0]
        self.assertFalse(f.matched)  # a broken matcher never claims
        self.assertIn("fail-closed", f.detail)


class TestDiscoveryAdapter(unittest.TestCase):
    def test_only_matched_become_signals(self):
        entries = [ev(T0 + i * 2.0, dest="10.0.0.%d" % i)
                   for i in range(12)]
        signals = to_discovery_signals(scan(entries))
        kinds = {s["signal_kind"] for s in signals}
        self.assertIn("fanned_egress", kinds)
        for s in signals:
            self.assertIn("signal_kind", s)
            self.assertIn("weight", s)
            self.assertIn("detail", s)
            self.assertGreaterEqual(s["weight"], 1)
            self.assertLessEqual(s["weight"], 4)

    def test_no_match_no_signals(self):
        self.assertEqual(to_discovery_signals(scan([ev(T0)])), [])


if __name__ == "__main__":
    unittest.main()
