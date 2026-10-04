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
    def _store(self, grant=False, policy_id="adm-u"):
        reg = ge.CheckRegistry()
        reg.register(ap.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                     "admission", "medium", "accept at operator risk",
                     ["admission-policy"])
        store = ge.ExceptionStore(reg)
        store.set_approvers(["ops"])
        if grant:
            now = time.time()
            store.grant(ap.ACCEPT_RISK_CHECK_ID, ("policy", policy_id),
                        "accepting at risk for this test run",
                        "ops", now + 3600, now)
        return store

    def _refuse_err(self, fails):
        pol = ap.compile_policy(_doc())
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit(_ev("provenance"), pol, _full(fails=fails))
        return cm.exception

    def test_at_risk_rejects_synthesized_dict(self):
        # F349: a caller-synthesized refuse dict can never reach the
        # floor gate.
        dec = {"verdict": "REFUSE", "policy_id": "adm-u",
               "floor_failed": [], "decision_digest": "x" * 64}
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(dec, self._store(grant=True), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")

    def test_at_risk_rejects_error_without_decision(self):
        err = ap.AdmissionError("refused", code="admission-refused")
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(err, self._store(grant=True), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")

    def test_at_risk_needs_live_exception(self):
        err = self._refuse_err(fails=("provenance-present",))
        self.assertEqual(err.code, "admission-refused")
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(err, self._store(), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")

    def test_at_risk_accepts_with_live_exception(self):
        err = self._refuse_err(fails=("provenance-present",))
        rec = ap.admit_at_risk(err, self._store(grant=True),
                               now=time.time())
        self.assertEqual(rec["verdict"], "ADMIT-AT-RISK")
        self.assertIn("exception_digest", rec)
        self.assertEqual(rec["floor_failed"], [])

    def test_at_risk_floor_never_exceptioned(self):
        # F349: the floor-failed state is mechanism-bound -- the gate
        # reads the registered record admit() produced.
        err = self._refuse_err(fails=("signature-valid",))
        self.assertEqual(err.code, "admission-integrity-floor-violated")
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(err, self._store(grant=True), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")

    def test_at_risk_tampered_decision_still_refuses(self):
        # Post-hoc mutation of the error-carried record must not move
        # the floor gate: the registry copy is authoritative.
        err = self._refuse_err(fails=("signature-valid",))
        err.decision["floor_failed"] = []
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit_at_risk(err, self._store(grant=True), now=time.time())
        self.assertEqual(cm.exception.code, "admission-exception-refused")


class TestRegistryImmutability(unittest.TestCase):
    def test_checks_entries_immutable(self):
        # F348: the registry is frozen at import; in-process mutation
        # must raise instead of silently removing the floor.
        with self.assertRaises(TypeError):
            ap.CHECKS["signature-valid"] = "tampered"
        with self.assertRaises(TypeError):
            del ap.CHECKS["signature-valid"]

    def test_floor_still_enforced(self):
        pol = ap.compile_policy(_doc())
        with self.assertRaises(ap.AdmissionError) as cm:
            ap.admit(_ev("provenance"), pol,
                     _full(fails=("digest-binds",)))
        self.assertEqual(cm.exception.code,
                         "admission-integrity-floor-violated")

    def test_rebound_registry_fails_closed(self):
        # F348: even rebinding the module attribute must fail closed,
        # never skip the floor.
        saved = ap.CHECKS
        try:
            ap.CHECKS = {}
            pol = ap.compile_policy(_doc())
            with self.assertRaises(ap.AdmissionError) as cm:
                ap.admit(_ev("provenance"), pol, {})
            self.assertEqual(cm.exception.code, "admission-check-failed")
        finally:
            ap.CHECKS = saved


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
        self.assertEqual(len(dc.TAXONOMY), 1964)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)


if __name__ == "__main__":
    unittest.main()
