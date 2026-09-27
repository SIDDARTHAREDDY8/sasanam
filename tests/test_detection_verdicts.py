"""Unit tests for gov/detection_verdicts.py (row-13 tiered verdicts).

Pure-function tests over compose()/footprint_of(): no I/O, no
ledgers, deterministic. The end-to-end detector behavior is pinned
by evals/detection_verdict_tier_probes.py.
"""

import json
import re
import unittest

from gov.detection_verdicts import (
    FOOTPRINT_SIGNAL_FLOOR,
    FOOTPRINT_THRESHOLDS,
    STRUCTURED_LINES_FLOOR,
    SUSPICIOUS_BYTES_FLOOR,
    compose,
    footprint_of,
)

TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


def t1(verdict="allow", score=0.0, structured=0.0, dump=0.0, entropy=0.0):
    return {"verdict": verdict, "score": score,
            "signals": {"structured": structured, "dump": dump,
                        "entropy": entropy}}


def t2(verdict="allow", overlap=0, novel=False, docs=0, threshold=3,
       source_ids=(), destination=None):
    return {"verdict": verdict, "overlap": overlap,
            "destination_novel": novel, "docs_read": docs,
            "threshold": threshold, "source_ids": list(source_ids),
            "destination": destination}


class FootprintTest(unittest.TestCase):
    def test_material_structure_is_footprint(self):
        is_fp, name, val = footprint_of(t1(structured=1.0))
        self.assertTrue(is_fp)
        self.assertEqual(name, "structured")
        self.assertEqual(val, 1.0)

    def test_below_floor_not_footprint(self):
        is_fp, _, _ = footprint_of(
            t1(structured=FOOTPRINT_SIGNAL_FLOOR - 0.01))
        self.assertFalse(is_fp)

    def test_at_floor_is_footprint(self):
        is_fp, _, _ = footprint_of(t1(entropy=FOOTPRINT_SIGNAL_FLOOR))
        self.assertTrue(is_fp)

    def test_empty_signals_not_footprint(self):
        self.assertFalse(footprint_of({})[0])
        self.assertFalse(footprint_of(None)[0])

    def test_strongest_signal_named(self):
        is_fp, name, _ = footprint_of(t1(structured=0.5, dump=1.0))
        self.assertTrue(is_fp)
        self.assertEqual(name, "dump")


def _t1_detail(structured_lines=0, suspicious_bytes=0,
               structured=0.0, dump=0.0, entropy=0.0):
    rec = t1(structured=structured, dump=dump, entropy=entropy)
    rec["detail"] = {
        "structured": {"structured_lines": structured_lines,
                       "total_lines": 11},
        "entropy": {"suspicious_bytes": suspicious_bytes,
                    "total_bytes": 644},
    }
    return rec


class AbsoluteLegsTest(unittest.TestCase):
    """Padding-robust presence legs (evals/detection_verdict_evasion_probes).

    Density ratios dilute under benign padding; the detectors' own
    presence conditions do not: the lines/bytes are either in the
    egress or they are not.
    """

    def test_structured_lines_leg_fires(self):
        is_fp, name, val = footprint_of(_t1_detail(structured_lines=2))
        self.assertTrue(is_fp)
        self.assertEqual(name, "structured_lines")
        self.assertEqual(val, 2.0)

    def test_single_line_not_footprint(self):
        # The <2-line gate is structured_density's own fire condition;
        # a lone "key: value" line must not move the needle.
        self.assertFalse(
            footprint_of(_t1_detail(structured_lines=1))[0])

    def test_suspicious_bytes_leg_fires(self):
        is_fp, name, val = footprint_of(_t1_detail(suspicious_bytes=40))
        self.assertTrue(is_fp)
        self.assertEqual(name, "suspicious_bytes")
        self.assertEqual(val, 40.0)

    def test_below_byte_floor_not_footprint(self):
        self.assertFalse(
            footprint_of(_t1_detail(suspicious_bytes=39))[0])

    def test_missing_detail_unchanged(self):
        # Records without a detail section (e.g. synthetic) keep the
        # density-only behavior.
        self.assertFalse(footprint_of(t1())[0])
        is_fp, name, _ = footprint_of(t1(structured=1.0))
        self.assertTrue(is_fp)
        self.assertEqual(name, "structured")

    def test_density_leg_takes_precedence(self):
        is_fp, name, _ = footprint_of(
            _t1_detail(structured_lines=7, structured=0.9))
        self.assertTrue(is_fp)
        self.assertEqual(name, "structured")

    def test_thresholds_cover_every_signal(self):
        for sig in ("structured", "dump", "entropy",
                    "structured_lines", "suspicious_bytes"):
            self.assertIn(sig, FOOTPRINT_THRESHOLDS)
        self.assertEqual(FOOTPRINT_THRESHOLDS["structured_lines"],
                         STRUCTURED_LINES_FLOOR)
        self.assertEqual(FOOTPRINT_THRESHOLDS["suspicious_bytes"],
                         SUSPICIOUS_BYTES_FLOOR)

    def test_compose_t3_via_absolute_leg(self):
        t1r = _t1_detail(structured_lines=2)
        t2r = t2("behavioral_flag", novel=True, docs=1,
                 source_ids=["doc1"],
                 destination="https://evil.example/x")
        out = compose(t1r, t2r)
        self.assertEqual(out["verdict"], "require_approval")
        self.assertEqual(out["tier"], "T3")
        self.assertTrue(out["composed"])
        t1prov = [p for p in out["provenance"] if p["tier"] == "T1"][0]
        self.assertEqual(t1prov["signal"], "structured_lines")
        self.assertEqual(t1prov["threshold"], STRUCTURED_LINES_FLOOR)


class T3CompositionTest(unittest.TestCase):
    def _t3_inputs(self):
        return (t1(structured=1.0),
                t2("behavioral_flag", novel=True, docs=1,
                   source_ids=["doc1"],
                   destination="https://evil.example/x"))

    def test_footprint_plus_behavior_escalates(self):
        out = compose(*self._t3_inputs())
        self.assertEqual(out["verdict"], "require_approval")
        self.assertEqual(out["tier"], "T3")
        self.assertTrue(out["composed"])
        tiers = {p["tier"] for p in out["provenance"]}
        self.assertEqual(tiers, {"T1", "T2"})

    def test_no_footprint_no_t3(self):
        out = compose(t1(),
                      t2("behavioral_flag", novel=True, docs=1))
        self.assertFalse(out["composed"])
        self.assertEqual(out["verdict"], "behavioral_flag")
        self.assertEqual(out["tier"], "T2")

    def test_no_behavior_no_t3(self):
        out = compose(t1(structured=1.0), t2())
        self.assertFalse(out["composed"])
        self.assertEqual(out["verdict"], "allow")

    def test_overlap_owned_by_content_ladder(self):
        # overlap >= 1 never routes through T3: the content tier owns
        # token overlap (here the tracker's overlap flag leg).
        out = compose(t1(structured=1.0),
                      t2("flag", overlap=2, novel=True, docs=1))
        self.assertFalse(out["composed"])
        self.assertEqual(out["verdict"], "flag")
        self.assertEqual(out["tier"], "T1")

    def test_t1_hold_never_relabeled_t3(self):
        out = compose(t1("require_approval", score=0.9, dump=1.0),
                      t2("behavioral_flag", novel=True, docs=1))
        self.assertEqual(out["verdict"], "require_approval")
        self.assertEqual(out["tier"], "T1")
        self.assertFalse(out["composed"])

    def test_tracker_overlap_hold_reports_t1(self):
        out = compose(t1(), t2("require_approval", overlap=5, novel=True))
        self.assertEqual(out["verdict"], "require_approval")
        self.assertEqual(out["tier"], "T1")
        self.assertFalse(out["composed"])

    def test_t1_flag_plus_behavior_is_t3_shape(self):
        # T1 graduated "flag" is not a hold, so the T3 rule still
        # applies: footprint + behavioral + zero overlap escalates.
        out = compose(t1("flag", score=0.5, structured=0.9),
                      t2("behavioral_flag", novel=True, docs=1))
        self.assertEqual(out["verdict"], "require_approval")
        self.assertEqual(out["tier"], "T3")
        self.assertTrue(out["composed"])

    def test_quiet_inputs_allow(self):
        out = compose(t1(), t2())
        self.assertEqual(out["verdict"], "allow")
        self.assertEqual(out["tier"], "T1")
        self.assertFalse(out["composed"])
        self.assertEqual(out["provenance"], [])

    def test_unknown_verdict_raises(self):
        with self.assertRaises(ValueError):
            compose(t1(verdict="explode"), t2())


class ProvenancePrivacyTest(unittest.TestCase):
    def test_no_secret_strings_in_t3_verdict(self):
        secret = "sk-live-9f8e7d6c5b4a"
        out = compose(t1(structured=1.0),
                      t2("behavioral_flag", novel=True, docs=1,
                         source_ids=["doc1"],
                         destination="https://evil.example/x"))
        blob = json.dumps(out, sort_keys=True).lower()
        for tok in TOKEN_RE.findall(secret.lower()):
            if len(tok) >= 4:
                self.assertNotIn(tok, blob)

    def test_provenance_record_shape(self):
        out = compose(*T3CompositionTest()._t3_inputs())
        for p in out["provenance"]:
            for k in ("tier", "detector", "signal", "measured",
                      "threshold", "contribution"):
                self.assertIn(k, p)
            self.assertIn(p["tier"], ("T1", "T2", "T3"))


class MonotonicityTest(unittest.TestCase):
    def test_never_weaker_than_strongest_input(self):
        order = {"allow": 0, "flag": 1, "behavioral_flag": 1,
                 "require_approval": 2}
        for t1v in ("allow", "flag", "require_approval"):
            for t2v in ("allow", "flag", "behavioral_flag",
                        "require_approval"):
                for ov in (0, 2):
                    if t2v == "behavioral_flag" and ov != 0:
                        continue  # impossible by construction
                    out = compose(
                        t1(verdict=t1v, structured=0.9),
                        t2(verdict=t2v, overlap=ov, novel=True, docs=1))
                    self.assertGreaterEqual(
                        order[out["verdict"]],
                        max(order[t1v], order[t2v]),
                        "downgrade: %s + %s -> %s"
                        % (t1v, t2v, out["verdict"]))


if __name__ == "__main__":
    unittest.main()
