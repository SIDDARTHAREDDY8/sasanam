#!/usr/bin/env python3
"""Unit tests for gov/reconcile_agreement.py.

Wave-231 lane A: five-valued decision/effect agreement table for
the reconcile stage. Tests exercise the PUBLIC seams
(agreement_table, not_exercised_verdict, verify_table_verdict,
seal_table_verdict, table_digest_of, deny_authority_use) with
independent spec-vector literals — expected verdicts come from
the lane spec table, never from the implementation's internals.
"""

import copy
import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import action_capsule as ac  # noqa: E402
from gov import reconcile_agreement as ra  # noqa: E402

HEX64 = "ab" * 32
HEX64_B = "cd" * 32


def _code_of(fn, *args):
    try:
        fn(*args)
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None)
    return None


class TableCellsTest(unittest.TestCase):
    # The spec table, as literals: the tests pin the table, not
    # the other way round.
    CELLS = {
        ("permitted", "occurred"): "agree",
        ("permitted", "absent"): "disagree",
        ("permitted", "unobservable"): "indeterminate",
        ("denied", "occurred"): "disagree",
        ("denied", "absent"): "agree",
        ("denied", "unobservable"): "one-sided",
        ("none", "occurred"): "one-sided",
        ("none", "absent"): "one-sided",
        ("none", "unobservable"): "one-sided",
    }

    def test_all_nine_cells(self):
        for (reported, observed), expected in self.CELLS.items():
            out = ra.agreement_table(reported, observed)
            self.assertEqual(out["verdict"], expected,
                             (reported, observed))
            self.assertEqual(out["decision_reported"], reported)
            self.assertEqual(out["effect_observed"], observed)
            self.assertEqual(out["v"], ra.RECONCILE_VERSION)

    def test_permitted_absent_is_disagree_not_agree(self):
        out = ra.agreement_table("permitted", "absent")
        self.assertEqual(out["verdict"], "disagree")
        self.assertNotEqual(out["verdict"], "agree")

    def test_denied_occurred_is_disagree(self):
        out = ra.agreement_table("denied", "occurred")
        self.assertEqual(out["verdict"], "disagree")

    def test_denied_absent_is_agree(self):
        out = ra.agreement_table("denied", "absent")
        self.assertEqual(out["verdict"], "agree")

    def test_table_is_deterministic(self):
        first = ra.agreement_table("none", "occurred")
        second = ra.agreement_table("none", "occurred")
        self.assertEqual(first, second)


class InputGateTest(unittest.TestCase):
    def test_unknown_axis_strings_refused(self):
        for args in (("allowed", "occurred"), ("permitted", "happened"),
                     ("", "occurred"), ("permitted", ""),
                     ("Permitted", "occurred")):
            self.assertEqual(
                _code_of(ra.agreement_table, *args),
                "agreement-input-unmapped", args)

    def test_non_string_axes_refused(self):
        for args in ((None, "occurred"), ("permitted", None),
                     (True, "occurred"), ("permitted", 1),
                     (["permitted"], "occurred")):
            self.assertEqual(
                _code_of(ra.agreement_table, *args),
                "agreement-input-unmapped", args)

    def test_verdict_vocab_is_closed(self):
        # Through public seams only: the table's nine cells plus the
        # not-exercised path must land exactly on the five closed
        # verdicts, no more, no fewer.
        cells = {ra.agreement_table(r, o)["verdict"]
                 for r in ("permitted", "denied", "none")
                 for o in ("occurred", "absent", "unobservable")}
        ne = ra.not_exercised_verdict(HEX64, HEX64_B,
                                      "superseded")["verdict"]
        self.assertEqual(cells | {ne},
                         {"agree", "disagree", "not-exercised",
                          "indeterminate", "one-sided"})


class NotExercisedTest(unittest.TestCase):
    def test_bare_claim_refused(self):
        self.assertEqual(
            _code_of(ra.not_exercised_verdict, "x", HEX64, "superseded"),
            "agreement-input-unmapped")
        self.assertEqual(
            _code_of(ra.not_exercised_verdict, HEX64, "y", "superseded"),
            "agreement-input-unmapped")

    def test_evidence_bound_verdict(self):
        out = ra.not_exercised_verdict(HEX64, HEX64_B, "superseded")
        self.assertEqual(out["verdict"], "not-exercised")
        self.assertEqual(out["superseding_digest"], HEX64_B)
        self.assertNotEqual(out["verdict"], "disagree")

    def test_verdict_recomputes(self):
        out = ra.not_exercised_verdict(HEX64, HEX64_B, "superseded")
        recomputed = ra.verify_table_verdict(out)
        self.assertEqual(recomputed, out["table_digest"])

    def test_tampered_digest_fails_recompute(self):
        out = ra.not_exercised_verdict(HEX64, HEX64_B, "superseded")
        tampered = dict(out)
        tampered["superseding_digest"] = HEX64
        self.assertEqual(
            _code_of(ra.verify_table_verdict, tampered),
            "agreement-input-unmapped")


class DigestDisciplineTest(unittest.TestCase):
    def test_verdict_digest_recomputes_from_fields(self):
        out = ra.agreement_table("permitted", "occurred")
        body = {
            "domain": "reconcile-agreement/v1",
            "verdict": "agree",
            "decision_reported": "permitted",
            "effect_observed": "occurred",
        }
        expected = hashlib.sha256(
            ac.canonical_json_bytes(body)).hexdigest()
        self.assertEqual(out["table_digest"], expected)
        self.assertEqual(ra.verify_table_verdict(out), expected)

    def test_surgical_edit_fails_recompute(self):
        out = ra.agreement_table("denied", "absent")
        tampered = copy.deepcopy(out)
        tampered["verdict"] = "disagree"
        self.assertEqual(
            _code_of(ra.verify_table_verdict, tampered),
            "agreement-input-unmapped")

    def test_forged_cell_verdict_refused(self):
        # A record claiming the wrong verdict for its axes is a
        # forgery, even if its digest recomputes under the claim.
        # The expected digest is built from spec-vector literals
        # with stdlib sha256, never from the implementation.
        out = ra.agreement_table("permitted", "absent")
        body = {
            "domain": "reconcile-agreement/v1",
            "verdict": "agree",
            "decision_reported": "permitted",
            "effect_observed": "absent",
        }
        forged = dict(out)
        forged["verdict"] = "agree"
        forged["table_digest"] = hashlib.sha256(
            ac.canonical_json_bytes(body)).hexdigest()
        self.assertEqual(
            _code_of(ra.verify_table_verdict, forged),
            "agreement-input-unmapped")

    def test_non_verdict_inputs_refused(self):
        for bad in (None, {}, {"verdict": "agree"}):
            self.assertEqual(
                _code_of(ra.verify_table_verdict, bad),
                "agreement-input-unmapped")


class SealTest(unittest.TestCase):
    def test_seal_and_recompute(self):
        cap = ra.seal_table_verdict("permitted", "occurred")
        body = ac.verify_capsule(cap)
        self.assertEqual(body["effect"]["status"], "admitted")
        digest = ra.table_digest_of(cap)
        self.assertEqual(digest, body["attempt"]["table_digest"])
        self.assertEqual(body["attempt"]["verdict"], "agree")

    def test_sealed_evidence_tamper_refused(self):
        # Surgical tamper that PASSES capsule replay (re-sealed with
        # edited evidence) must still fail at the module's digest
        # gate: the evidence no longer commits to the attempt bytes.
        cap = ra.seal_table_verdict("denied", "absent")
        body = ac.verify_capsule(cap)
        rebuilt = ac.seal_capsule({
            "attempt": body["attempt"],
            "effect": {"status": "admitted",
                       "evidence": hashlib.sha256(b"evil").hexdigest()},
        })
        self.assertEqual(
            _code_of(ra.table_digest_of, rebuilt),
            "agreement-input-unmapped")

    def test_seal_refuses_unmapped_input(self):
        self.assertEqual(
            _code_of(ra.seal_table_verdict, "maybe", "occurred"),
            "agreement-input-unmapped")


class AuthorityBoundaryTest(unittest.TestCase):
    def test_verdict_as_authority_refused(self):
        verdict = ra.agreement_table("denied", "absent")
        self.assertEqual(
            _code_of(ra.deny_authority_use, verdict),
            "agreement-not-authorization")

    def test_not_exercised_as_authority_refused(self):
        ne = ra.not_exercised_verdict(HEX64, HEX64_B, "superseded")
        self.assertEqual(
            _code_of(ra.deny_authority_use, ne),
            "agreement-not-authorization")

    def test_sealed_capsule_as_authority_refused(self):
        cap = ra.seal_table_verdict("denied", "absent")
        self.assertEqual(
            _code_of(ra.deny_authority_use, cap),
            "agreement-not-authorization")

    def test_malformed_refused_as_input_first(self):
        for bad in (None, {}, {"verdict": "agree"}):
            self.assertEqual(
                _code_of(ra.deny_authority_use, bad),
                "agreement-input-unmapped")


if __name__ == "__main__":
    unittest.main()
