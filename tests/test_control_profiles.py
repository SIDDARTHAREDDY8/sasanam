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
        self.assertEqual(n, 1730)  # Wave-279 lane 2: pin 1493 -> 1494 (+1 evbundle-contract-refused); prior Wave-271 merge: pin 1372 -> 1411 (+39 codes).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 lane 2: pin 1730 -> 1730 (+3 toolcall-*: sequence-violated, secret-in-args, rule-compile-invalid)

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

    def test_per_control_snapshot_isolation(self):
        # F225: each control's check evaluates against a pristine
        # per-control deep copy; a check that mutates its view
        # cannot poison later controls' views.
        seen = {}

        def mutator(snapshot):
            snapshot["poisoned"] = True
            snapshot["nested"]["items"].append("forged")
            return True

        def reader(snapshot):
            seen["poisoned"] = snapshot.get("poisoned", False)
            seen["items"] = list(snapshot["nested"]["items"])
            return not snapshot.get("poisoned", False)

        res = cp.run_profile(
            _profile([_control("C1", mutator),
                      _control("C2", reader)]),
            {"evidence": 1, "nested": {"items": ["genuine"]}})
        by_id = {r["control_id"]: r for r in res["results"]}
        self.assertFalse(seen["poisoned"])
        self.assertEqual(seen["items"], ["genuine"])
        self.assertEqual(by_id["C2"]["status"], "pass")
        self.assertTrue(res["success"])

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

    def test_quality_gate_empty_evidence_wrapped(self):
        # F226: empty quality evidence raises EvidenceQualityError
        # (evidence-quality-empty-evidence) inside evaluate(); the
        # seam must wrap it as ControlProfileError naming the
        # wrapped code -- never a raw escape.
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.emit_profile_results(
                res, fmt="json", quality_gate=True,
                quality_expectations=[
                    {"expectation_type": "expect_evidence_monotonic",
                     "kwargs": {}}],
                quality_evidence=[])
        self.assertEqual(ctx.exception.code,
                         "control-profile-gate-failed")
        self.assertIn("evidence-quality-empty-evidence",
                      str(ctx.exception))

    def test_quality_gate_malformed_expectation_wrapped(self):
        # F226 defense in depth: an unknown expectation type raises
        # EvidenceQualityError(evidence-quality-unknown-expectation)
        # inside evaluate(); wrapped identically.
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.emit_profile_results(
                res, fmt="json", quality_gate=True,
                quality_expectations=[
                    {"expectation_type": "nope_unknown",
                     "kwargs": {}}],
                quality_evidence=[{"seq": 1}])
        self.assertEqual(ctx.exception.code,
                         "control-profile-gate-failed")
        self.assertIn("evidence-quality-unknown-expectation",
                      str(ctx.exception))

    def test_deployment_findings_index_merges(self):
        res = cp.run_profile(
            _profile([_control("C1", _no, impact=0.2)]), {})
        out = cp.emit_profile_results(res, fmt="json", findings={})
        self.assertIn("low", out)

    def test_emit_refuses_result_missing_each_key(self):
        # F227: per-result keys are re-validated fail-closed before
        # any is indexed. A caller-built record missing any of them
        # must be refused with control-profile-malformed -- never a
        # raw KeyError escaping the seam.
        for key in ("control_id", "status", "reason", "impact",
                    "severity", "digest"):
            with self.subTest(key=key):
                res = cp.run_profile(
                    _profile([_control("C1", _no)]), {})
                del res["results"][0][key]
                with self.assertRaises(cp.ControlProfileError) as ctx:
                    cp.emit_profile_results(res, fmt="json")
                self.assertEqual(ctx.exception.code,
                                 "control-profile-malformed")
                self.assertIn(key, str(ctx.exception))

    def test_emit_refuses_non_dict_result_record(self):
        # F227 defense in depth: a non-dict record cannot have keys
        # checked -- refused with the machine code, not a raw
        # TypeError from r["status"].
        res = cp.run_profile(_profile([_control("C1", _no)]), {})
        res["results"][0] = "not-a-record"
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.emit_profile_results(res, fmt="json")
        self.assertEqual(ctx.exception.code,
                         "control-profile-malformed")

    def test_emit_refuses_non_list_results(self):
        # F227 defense in depth: results must be a list of records;
        # a dict would iterate its keys and escape a raw TypeError.
        res = cp.run_profile(_profile([_control("C1", _no)]), {})
        res["results"] = {"C1": "fail"}
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.emit_profile_results(res, fmt="json")
        self.assertEqual(ctx.exception.code,
                         "control-profile-malformed")

    def test_emit_refuses_pass_record_missing_key(self):
        # F227: validation runs before the pass/fail split, so it is
        # status-agnostic -- a pass record missing a key is refused
        # too.
        res = cp.run_profile(_profile([_control("C1", _ok)]), {})
        del res["results"][0]["digest"]
        with self.assertRaises(cp.ControlProfileError) as ctx:
            cp.emit_profile_results(res, fmt="json")
        self.assertEqual(ctx.exception.code,
                         "control-profile-malformed")


if __name__ == "__main__":
    unittest.main()
