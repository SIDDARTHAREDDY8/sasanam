"""Wave-146 row 13: unit tests for cumulative canary-fragment detection.

Covers the registry fragment seam at the unit level (the battery
evals/canary_fragment_probes.py covers the end-to-end trip). Deterministic:
CanaryMint is seeded by run_id.
"""

import unittest

from gov.canary import (CanaryMint, CanaryRegistry, CanaryTripHalt,
                        FRAGMENT_LEN, _derive_fragments,
                        _fragment_floor, _has_half_span,
                        _is_low_entropy_fragment)


def _reg(run_id="run-frag-unit"):
    mint = CanaryMint(run_id)
    reg = CanaryRegistry()
    reg.register(mint)
    return reg


def _value(reg, label):
    for v, meta in reg._by_value.items():
        if meta["label"] == label:
            return v
    raise AssertionError(label)


class TestDeriveFragments(unittest.TestCase):
    def test_token_canaries_have_fragments(self):
        reg = _reg()
        for label in ("github-token", "aws-secret-0", "stripe-secret",
                      "internal-api-token"):
            v = _value(reg, label)
            frags = reg._fragments[v]
            self.assertGreater(len(frags), 0, label)
            for f in frags:
                self.assertEqual(len(f), FRAGMENT_LEN)
                self.assertIn(f, v)

    def test_predictable_structure_not_fragmented(self):
        # The database-url's structural runs yield no fragments; only
        # the unpredictable password part does.
        reg = _reg()
        v = _value(reg, "database-url")
        frags = reg._fragments[v]
        self.assertGreater(len(frags), 0)
        for f in frags:
            self.assertNotIn("internal", f.lower())
            self.assertNotIn("postgres", f.lower())

    def test_hostname_canaries_have_no_fragments(self):
        # Hostnames are entirely predictable structure; the whole-value
        # path (match_host) still protects them.
        reg = _reg()
        for label in ("internal-host-0", "internal-host-1",
                      "internal-host-2"):
            v = _value(reg, label)
            self.assertEqual(reg._fragments[v], [], label)

    def test_short_value_yields_nothing(self):
        self.assertEqual(_derive_fragments("short"), [])

    def test_half_span(self):
        self.assertTrue(_has_half_span("xx" + "A" * 10 + "yy", "A" * 20))
        self.assertFalse(_has_half_span("xx" + "A" * 9 + "yy", "A" * 20))
        self.assertFalse(_has_half_span("short", "A" * 20))

    def test_half_span_ignores_predictable_infrastructure(self):
        # Regression: a shared predictable suffix (".staging.internal")
        # across rotated hostnames must not trip the half-span rule.
        # canary.p1.rotation_previous_run_no_trip.
        host = "backup-gateway-23.staging.internal"
        self.assertFalse(
            _has_half_span("https://other-host.staging.internal/x", host))
        # The unpredictable remainder alone is too short to hold a
        # half-span, so no trip either.
        self.assertFalse(_has_half_span("backup-gateway-23", host))


class TestMatchFragments(unittest.TestCase):
    def test_two_distinct_fragments_trip(self):
        reg = _reg()
        v = _value(reg, "github-token")
        frags = reg._fragments[v]
        self.assertIsNone(reg.match_fragments("a " + frags[0] + " b"))
        hit = reg.match_fragments("c " + frags[5] + " d")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["label"], "github-token")
        self.assertEqual(hit["trigger"], "two_distinct_fragments")
        self.assertGreaterEqual(hit["fragments_seen"], 2)

    def test_same_fragment_twice_no_trip(self):
        reg = _reg()
        v = _value(reg, "github-token")
        frag = reg._fragments[v][0]
        self.assertIsNone(reg.match_fragments("a " + frag + " b"))
        self.assertIsNone(reg.match_fragments("c " + frag + " d"))

    def test_no_cross_canary_accumulation(self):
        reg = _reg()
        va = _value(reg, "github-token")
        vb = _value(reg, "aws-secret-0")
        self.assertIsNone(
            reg.match_fragments("a " + reg._fragments[va][0] + " b"))
        self.assertIsNone(
            reg.match_fragments("c " + reg._fragments[vb][0] + " d"))

    def test_half_canary_single_fragment_trips(self):
        reg = _reg()
        v = _value(reg, "github-token")  # 40 chars
        self.assertIsNotNone(reg.match_fragments("xx " + v[:20] + " yy"))

    def test_short_string_ignored(self):
        reg = _reg()
        v = _value(reg, "github-token")
        self.assertIsNone(reg.match_fragments(v[:8]))

    def test_per_run_reset(self):
        # register() for a new run clears fragment observations.
        reg = _reg("run-a")
        v = _value(reg, "github-token")
        frag = reg._fragments[v][0]
        reg.match_fragments("a " + frag + " b")
        self.assertEqual(len(reg._fragment_seen[v]), 1)
        reg.register(CanaryMint("run-b"))
        self.assertEqual(reg._fragment_seen, {})


def _low_entropy_reg():
    # Registry holding a single hand-built low-entropy canary
    # ("ab" * 16, every 16-char window has entropy 1.0). Stands in
    # for short structured canaries with repetitive segments; the
    # matching path is the real one.
    reg = CanaryRegistry()
    v = "ab" * 16
    reg._by_value[v] = {"kind": "bearer_token", "label": "synth-lowent",
                        "value": v, "channel": "decoy_config"}
    reg._fragments[v] = _derive_fragments(v)
    return reg, v


class TestFragmentFloorAndEntropy(unittest.TestCase):
    """Wave-148 row 13: per-format fragment floors + entropy gate."""

    def test_floor_table_matches_measurements(self):
        # Measured 2026-09-27: shortest fragment length with zero
        # benign-corpus hits per format (see
        # evals/canary_fragment_floor_probes.py).
        self.assertEqual(_fragment_floor("aws_access_key"), 8)
        self.assertEqual(_fragment_floor("aws_secret_key"), 8)
        self.assertEqual(_fragment_floor("bearer_token"), 8)
        self.assertEqual(_fragment_floor("hostname"), 8)
        self.assertEqual(_fragment_floor("env_entry"), 10)
        # Unknown kinds stay conservative: never below 16.
        self.assertEqual(_fragment_floor("something-new"), FRAGMENT_LEN)

    def test_derive_clamps_below_floor(self):
        v = "sk_live_" + "R" * 24
        frags = _derive_fragments(v, kind="env_entry", frag_len=8)
        self.assertTrue(frags)
        for f in frags:
            self.assertEqual(len(f), 10)

    def test_derive_at_floor_token(self):
        reg = _reg()
        v = _value(reg, "aws-key-0")
        frags = _derive_fragments(v, kind="aws_access_key", frag_len=8)
        self.assertTrue(frags)
        for f in frags:
            self.assertEqual(len(f), 8)
            self.assertIn(f, v)

    def test_default_derive_unchanged(self):
        # No kind/frag_len: the operational 16-char derivation.
        reg = _reg()
        v = _value(reg, "aws-key-0")
        self.assertEqual(_derive_fragments(v), reg._fragments[v])

    def test_entropy_gate_boundaries(self):
        self.assertTrue(_is_low_entropy_fragment("abababababababab"))
        self.assertTrue(_is_low_entropy_fragment("a" * 16))
        # A genuine access-key fragment is far above the gate.
        self.assertFalse(_is_low_entropy_fragment(
            _value(_reg(), "aws-key-0")[4:20]))

    def test_single_low_entropy_fragment_no_trip(self):
        reg, _ = _low_entropy_reg()
        self.assertIsNone(
            reg.match_fragments("xx abababababababab yy"))

    def test_two_low_entropy_fragments_trip(self):
        reg, _ = _low_entropy_reg()
        self.assertIsNone(
            reg.match_fragments("xx abababababababab yy"))
        hit = reg.match_fragments("zz babababababababa ww")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["trigger"], "two_distinct_fragments")

    def test_high_entropy_half_span_still_trips(self):
        # The gate must not silence genuine high-entropy spans. (A
        # 20-char span holds several 16-char windows, so the pair rule
        # may fire first -- either trigger is a trip, not silence.)
        reg = _reg()
        v = _value(reg, "github-token")  # 40 chars
        hit = reg.match_fragments("xx " + v[:20] + " yy")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["label"], "github-token")


if __name__ == "__main__":
    unittest.main()
