"""Unit tests for gov/control_profiles.py (wave-257 lane 2).

inspec/inspec ADAPT (pattern only): declarative controls-as-code
profiles whose typed result records compose with
gov/compliance_emitter.py.

Seams under test: validate_profile / run_profile / profile_digest /
severity_for_impact / emit_profile_results (+ quality_gate). Every
test pins the module contract at its public interface.
"""

import copy
import unittest

from gov import control_profiles as cp
from gov import decision_codes


def _ok(snapshot):
    return True


def _no(snapshot):
    return False


def _control(cid, check=_ok, impact=0.9, **kw):
    c = {"id": cid, "impact": impact, "title": "Control %s" % cid,
         "desc": "desc for %s" % cid, "check": check}
    c.update(kw)
    return c


def _profile(controls, **kw):
    p = {"id": "PROF-001", "title": "Demo profile",
         "controls": controls}
    p.update(kw)
    return p


class TestTaxonomyPin(unittest.TestCase):
    def test_pin(self):
        n = len(decision_codes.TAXONOMY)
        self.assertEqual(n, 1064)  # Wave-258 merge: pin -> 1064.

    def test_codes_resolve(self):
        for code in ("control-profile-malformed",
                     "control-profile-duplicate-control-id",
                     "control-profile-empty",
                     "control-profile-evidence-malformed",
                     "control-profile-gate-failed",
                     "control-profile-invalid-impact",
                     "control-profile-non-callable-check",
                     "control-profile-unknown-key",
                     "control-profile-check-passed"):
            self.assertIsNotNone(decision_codes.code_for(code), code)


class TestValidateProfile(unittest.TestCase):
    def test_happy_path(self):
        out = cp.validate_profile(_profile([_control("C1")]))
        self.assertEqual(out["id"], "PROF-001")
        self.assertEqual(len(out["controls"]), 1)

    def test_non_dict_refused(self):
        for bad in (None, [], "nope"):
            with self.assertRaises(cp.ControlProfileError) as ctx:
                cp.validate_profile(bad)
            self.assertEqual(ctx.exception.code,
                             "control-profile-malformed")

    def test_missing_controls_refused(self):
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.validate_profile({"id": "P", "title": "T"})
        self.assertEqual(ctx.exception.code,
                         "control-profile-malformed")

    def test_duplicate_ids_refused(self):
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.validate_profile(
                _profile([_control("C1"), _control("C1")]))
        self.assertEqual(ctx.exception.code,
                         "control-profile-duplicate-control-id")

    def test_check_objects_kept_by_reference(self):
        prof = _profile([_control("C1", check=_ok)])
        out = cp.validate_profile(prof)
        self.assertIs(out["controls"][0]["check"], _ok)

    def test_error_carries_code_attribute(self):
        err = cp.ControlProfileError("x", "control-profile-malformed")
        self.assertEqual(err.code, "control-profile-malformed")


class TestSeverity(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(cp.severity_for_impact(1.0), "high")
        self.assertEqual(cp.severity_for_impact(0.7), "high")
        self.assertEqual(cp.severity_for_impact(0.69), "medium")
        self.assertEqual(cp.severity_for_impact(0.4), "medium")
        self.assertEqual(cp.severity_for_impact(0.39), "low")
        self.assertEqual(cp.severity_for_impact(0.0), "low")


class TestRunProfile(unittest.TestCase):
    def test_pass_and_fail(self):
        res = cp.run_profile(
            _profile([_control("C1", _ok), _control("C2", _no)]), {})
        self.assertFalse(res["success"])
        by_id = {r["control_id"]: r for r in res["results"]}
        self.assertEqual(by_id["C1"]["status"], "pass")
        self.assertEqual(by_id["C2"]["status"], "fail")
        self.assertTrue(by_id["C2"]["reason"])
        self.assertIsNone(by_id["C2"]["exception_info"])
        self.assertEqual(len(res["profile_digest"]), 64)
        for r in res["results"]:
            self.assertEqual(len(r["digest"]), 64)

    def test_tuple_reason_check(self):
        def check(snapshot):
            return False, "journal lacks chain link"

        res = cp.run_profile(_profile([_control("C1", check)]), {})
        self.assertEqual(res["results"][0]["status"], "fail")
        self.assertEqual(res["results"][0]["reason"],
                         "journal lacks chain link")

    def test_malformed_tuple_reason_becomes_error(self):
        # (False, non-string) must never silently record a pass.
        def check(snapshot):
            return False, 123

        res = cp.run_profile(_profile([_control("C1", check)]), {})
        self.assertFalse(res["success"])
        self.assertEqual(res["results"][0]["status"], "error")
        self.assertIn("ControlProfileError",
                      res["results"][0]["exception_info"]["raised"])

    def test_non_deepcopyable_snapshot_refused(self):
        import threading
        res_profile = _profile([_control("C1", _ok)])
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.run_profile(res_profile,
                           {"lock": threading.Lock()})
        self.assertEqual(ctx.exception.code,
                         "control-profile-evidence-malformed")

    def test_does_not_mutate_snapshot(self):
        snap = {"a": [1, 2]}
        before = copy.deepcopy(snap)
        cp.run_profile(_profile([_control("C1", _ok)]), snap)
        self.assertEqual(snap, before)

    def test_statistics(self):
        res = cp.run_profile(
            _profile([_control("C1", _ok), _control("C2", _no)]), {})
        stats = res["statistics"]
        self.assertEqual(stats["evaluated_controls"], 2)
        self.assertEqual(stats["passed_controls"], 1)
        self.assertEqual(stats["failed_controls"], 1)
        self.assertEqual(stats["errored_controls"], 0)


class TestEmitProfileResults(unittest.TestCase):
    def test_all_pass_emits_without_findings(self):
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        out = cp.emit_profile_results(res, fmt="json")
        self.assertIn("control-profile-check-passed", out)
        self.assertNotIn('"kind": "finding"', out)

    def test_fail_emits_finding_with_severity(self):
        res = cp.run_profile(
            _profile([_control("C1", _no, impact=0.85)]), {})
        out = cp.emit_profile_results(res, fmt="json")
        self.assertIn('"kind": "finding"', out)
        self.assertIn("high", out)
        self.assertIn("C1", out)

    def test_markdown_format(self):
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        out = cp.emit_profile_results(res, fmt="markdown")
        self.assertIn("# Compliance control", out)

    def test_oscal_format(self):
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        out = cp.emit_profile_results(res, fmt="oscal")
        self.assertIn("component-definition", out)

    def test_quality_gate_passes_on_clean(self):
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        out = cp.emit_profile_results(
            res, fmt="json", quality_gate=True,
            quality_expectations=[
                {"expectation_type": "expect_evidence_monotonic",
                 "kwargs": {}}],
            quality_evidence=[{"seq": 1}, {"seq": 2}])
        self.assertIn("control-profile-check-passed", out)

    def test_quality_gate_requires_inputs(self):
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.emit_profile_results(res, quality_gate=True)
        self.assertEqual(ctx.exception.code,
                         "control-profile-malformed")

    def test_deployment_findings_index_merges(self):
        res = cp.run_profile(
            _profile([_control("C1", _no, impact=0.2)]), {})
        out = cp.emit_profile_results(res, fmt="json", findings={})
        self.assertIn("low", out)


if __name__ == "__main__":
    unittest.main()
