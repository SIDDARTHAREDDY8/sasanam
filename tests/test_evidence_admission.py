"""Unit tests for gov/evidence_admission.py.

Verifier-side evidence-admission trust policy (notaryproject/notation
trust-policy ladder, clean-room). Red-before-green: these were written
against the module's contract, then run.
"""

import os
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import evidence_admission as ap  # noqa: E402
from gov import governed_exceptions as ge  # noqa: E402


def _doc(**kw):
    d = {
        "format": "admission-policy/1",
        "policy_id": "adm-u",
        "scopes": [
            {"scope": "provenance", "level": "strict"},
            {"scope": "checkpoint", "level": "permissive"},
        ],
    }
    d.update(kw)
    return d


def _full(fails=()):
    return dict((c, c not in fails) for c in (
        "signature-valid", "digest-binds", "provenance-present",
        "builder-allowlisted", "endorsement-independent",
        "witness-quorum", "freshness"))


def _ev(kind):
    return {"kind": kind, "artifact_digest": "d" * 64, "envelope": None}


class TestLadder(unittest.TestCase):
    def test_order(self):
        self.assertTrue(ap.STRICT > ap.PERMISSIVE > ap.AUDIT > ap.SKIP)

    def test_floor_members(self):
        self.assertEqual(ap.INTEGRITY_FLOOR,
                         frozenset({"signature-valid", "digest-binds"}))


class TestCompile(unittest.TestCase):
    def test_compile_ok(self):
        pol = ap.compile_policy(_doc())
        self.assertEqual(pol.policy_id, "adm-u")
        self.assertEqual(len(pol.digest), 64)

    def test_bad_format(self):
        d = _doc()
        d["format"] = "nope"
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.compile_policy(d)
        self.assertEqual(cm.exception.code, "admission-policy-invalid")

    def test_vacuous_scopes(self):
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.compile_policy(_doc(scopes=[]))
        self.assertEqual(cm.exception.code, "admission-policy-invalid")

    def test_floor_lowering_refused(self):
        d = _doc()
        d["scopes"].append({"scope": "x", "level": "permissive",
                           "checks": {"signature-valid": "audit"}})
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.compile_policy(d)
        self.assertEqual(cm.exception.code, "admission-policy-invalid")

    def test_unknown_check_refused(self):
        d = _doc()
        d["scopes"].append({"scope": "x", "level": "permissive",
                           "checks": {"nope": "strict"}})
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.compile_policy(d)
        self.assertEqual(cm.exception.code, "admission-policy-invalid")

    def test_bad_level_refused(self):
        d = _doc()
        d["scopes"].append({"scope": "x", "level": "paranoid"})
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.compile_policy(d)
        self.assertEqual(cm.exception.code, "admission-policy-invalid")


class TestAdmit(unittest.TestCase):
    def test_strict_admit_all_pass(self):
        pol = ap.compile_policy(_doc())
        d = ap.admit(_ev("provenance"), pol, _full())
        self.assertEqual(d["verdict"], "ADMIT")
        self.assertEqual(d["policy_id"], "adm-u")
        self.assertEqual(len(d["decision_digest"]), 64)

    def test_strict_refuse_nonfloor(self):
        pol = ap.compile_policy(_doc())
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit(_ev("provenance"), pol,
                     _full(fails=("freshness",)))
        self.assertEqual(cm.exception.code, "admission-refused")

    def test_floor_refusal_code(self):
        pol = ap.compile_policy(_doc())
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit(_ev("provenance"), pol,
                     _full(fails=("digest-binds",)))
        self.assertEqual(cm.exception.code,
                         "admission-integrity-floor-violated")

    def test_no_applicable_policy(self):
        pol = ap.compile_policy(_doc())
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit(_ev("inclusion-receipt"), pol, _full())
        self.assertEqual(cm.exception.code,
                         "admission-no-applicable-policy")

    def test_longest_scope_wins(self):
        d = _doc()
        d["scopes"].append({"scope": "provenance/special",
                            "level": "audit"})
        pol = ap.compile_policy(d)
        dec = ap.admit(_ev("provenance/special"), pol,
                       _full(fails=("freshness",)))
        self.assertEqual(dec["verdict"], "ADMIT-AUDIT")

    def test_malformed_evidence(self):
        pol = ap.compile_policy(_doc())
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit({"kind": ""}, pol, _full())
        self.assertEqual(cm.exception.code, "admission-check-failed")


class TestAtRisk(unittest.TestCase):
    def _store(self):
        reg = ge.CheckRegistry()
        reg.register(ap.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                     "admission", "medium", "accept at operator risk",
                     ["admission-policy"])
        store = ge.ExceptionStore(reg)
        store.set_approvers(["ops"])
        return store

    def test_at_risk_needs_refuse_decision(self):
        pol = ap.compile_policy(_doc())
        dec = {"verdict": "ADMIT", "policy_id": "adm-u",
               "floor_failed": [], "decision_digest": "x" * 64}
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(dec, self._store(), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")

    def test_at_risk_needs_live_exception(self):
        dec = {"verdict": "REFUSE", "policy_id": "adm-u",
               "floor_failed": [], "decision_digest": "x" * 64}
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(dec, self._store(), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")


class TestPins(unittest.TestCase):
    def test_pin_roundtrip(self):
        d = tempfile.mkdtemp(prefix="w288-adm-u-")
        pinpath = os.path.join(d, "pins.json")
        pol = ap.compile_policy(_doc())
        ap.pin_admission_policy("adm-u", pol.digest, pinpath)
        pins = ap.load_admission_pins(pinpath)
        dec = ap.admit(_ev("provenance"), pol, _full(), pins=pins)
        self.assertEqual(dec["verdict"], "ADMIT")

    def test_pin_drift_refuses(self):
        d = tempfile.mkdtemp(prefix="w288-adm-u-")
        pinpath = os.path.join(d, "pins.json")
        pol = ap.compile_policy(_doc())
        ap.pin_admission_policy("adm-u", pol.digest, pinpath)
        pins = ap.load_admission_pins(pinpath)
        pol.doc["scopes"].append({"scope": "z", "level": "skip"})
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit(_ev("provenance"), pol, _full(), pins=pins)
        self.assertEqual(cm.exception.code, "admission-policy-invalid")


class TestTaxonomy(unittest.TestCase):
    def test_pin(self):
        # Wave-288 lane 7: pin 1684 -> 1691 (+7 admission-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*)
        import gov.decision_codes as dc
        self.assertEqual(len(dc.TAXONOMY), 1700)


if __name__ == "__main__":
    unittest.main()
