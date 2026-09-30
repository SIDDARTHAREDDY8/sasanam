"""Unit tests for gov/refusal_oracle_guard.py (wave-239 lane C).

Jackson WIMSE -03 refusal-oracle rules, prose re-derived: one valid path
suffices; a broken path never neutralizes a valid one; refusal text is
oracle-clean; audit distinguishes evaluated-and-refused from
could-not-evaluate; a misconfigured verifier fails closed loudly.
"""

import unittest

from gov import refusal_oracle_guard as rog


def _path(path_id, result):
    def check():
        return result
    return rog.AuthPath(path_id=path_id, check=check)


def _unavailable(path_id):
    def check():
        raise rog.PathUnavailable("dependency down")
    return rog.AuthPath(path_id=path_id, check=check)


def _crash(path_id):
    def check():
        raise RuntimeError("path-local crash")
    return rog.AuthPath(path_id=path_id, check=check)


class ConstantsTests(unittest.TestCase):
    def test_code_strings(self):
        self.assertEqual(rog.ORACLE_EVALUATED_AND_REFUSED,
                         "oracle-evaluated-and-refused")
        self.assertEqual(rog.ORACLE_COULD_NOT_EVALUATE,
                         "oracle-could-not-evaluate")
        self.assertEqual(rog.ORACLE_VERIFIER_MISCONFIGURED,
                         "oracle-verifier-misconfigured")

    def test_codes_are_distinct(self):
        codes = {rog.ORACLE_EVALUATED_AND_REFUSED,
                 rog.ORACLE_COULD_NOT_EVALUATE,
                 rog.ORACLE_VERIFIER_MISCONFIGURED}
        self.assertEqual(len(codes), 3)

    def test_codes_registered_in_taxonomy(self):
        # Add-only: the merge coordinator reconciles the pin; these must
        # exist exactly once. Wave-239 merge pin: 695 + 3 = 698.
        from gov import decision_codes as dc
        for code in ("oracle-evaluated-and-refused",
                     "oracle-could-not-evaluate",
                     "oracle-verifier-misconfigured"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "oracle")


class AuthorizeHappyPathTests(unittest.TestCase):
    def test_single_valid_path_authorizes(self):
        res = rog.authorize([_path("p1", True)])
        self.assertTrue(res["authorized"])
        self.assertIsNone(res["refusal"])
        self.assertEqual(res["audit"]["via"], "p1")

    def test_broken_path_does_not_neutralize(self):
        res = rog.authorize([_path("bad", False), _path("good", True)])
        self.assertTrue(res["authorized"])
        self.assertEqual(res["audit"]["via"], "good")

    def test_unavailable_path_does_not_neutralize(self):
        res = rog.authorize([_unavailable("flaky"), _path("good", True)])
        self.assertTrue(res["authorized"])
        self.assertEqual(res["audit"]["via"], "good")

    def test_crash_does_not_neutralize(self):
        res = rog.authorize([_crash("crashy"), _path("good", True)])
        self.assertTrue(res["authorized"])

    def test_first_granted_wins_audit_via(self):
        res = rog.authorize([_path("a", True), _path("b", True)])
        self.assertEqual(res["audit"]["via"], "a")


class EvaluatedAndRefusedTests(unittest.TestCase):
    def test_all_refused_code(self):
        res = rog.authorize([_path("p1", False), _path("p2", False)])
        self.assertFalse(res["authorized"])
        self.assertEqual(res["refusal"], rog.ORACLE_EVALUATED_AND_REFUSED)
        self.assertEqual(res["audit"]["refusal_code"],
                         rog.ORACLE_EVALUATED_AND_REFUSED)

    def test_refusal_detail_is_fixed_template(self):
        res = rog.authorize([_path("p1", False)])
        self.assertEqual(res["detail"], "no authorization path granted")

    def test_truthy_non_true_does_not_grant(self):
        # Strict: only exactly True grants. Fail-closed per path.
        res = rog.authorize([_path("p1", 1)])
        self.assertFalse(res["authorized"])
        self.assertEqual(res["refusal"], rog.ORACLE_EVALUATED_AND_REFUSED)

    def test_none_return_does_not_grant(self):
        res = rog.authorize([_path("p1", None)])
        self.assertFalse(res["authorized"])


class CouldNotEvaluateTests(unittest.TestCase):
    def test_unavailable_gives_distinct_code(self):
        res = rog.authorize([_unavailable("p1")])
        self.assertFalse(res["authorized"])
        self.assertEqual(res["refusal"], rog.ORACLE_COULD_NOT_EVALUATE)
        self.assertNotEqual(res["refusal"], rog.ORACLE_EVALUATED_AND_REFUSED)

    def test_crash_counts_as_could_not_evaluate(self):
        res = rog.authorize([_crash("p1")])
        self.assertEqual(res["refusal"], rog.ORACLE_COULD_NOT_EVALUATE)

    def test_mixed_refused_and_unavailable_prefers_cne(self):
        res = rog.authorize([_path("p1", False), _unavailable("p2")])
        self.assertEqual(res["refusal"], rog.ORACLE_COULD_NOT_EVALUATE)

    def test_audit_per_path_outcomes(self):
        res = rog.authorize([_path("p1", False), _unavailable("p2")])
        slim = {p["path_id"]: p["outcome"] for p in res["audit"]["paths"]}
        self.assertEqual(slim, {"p1": "refused", "p2": "could-not-evaluate"})

    def test_audit_note_names_exception_class_only(self):
        res = rog.authorize([_crash("p1")])
        note = res["audit"]["paths"][0]["note"]
        self.assertEqual(note, "RuntimeError")
        self.assertNotIn("path-local crash", note)


class MisconfiguredTests(unittest.TestCase):
    def _assert_loud_closed(self, cfg):
        res = rog.authorize(cfg)
        self.assertFalse(res["authorized"], "authorized a misconfigured verifier")
        self.assertEqual(res["refusal"], rog.ORACLE_VERIFIER_MISCONFIGURED)
        self.assertEqual(res["detail"],
                         "verifier misconfigured; refusing closed")

    def test_empty_path_set(self):
        self._assert_loud_closed([])

    def test_duplicate_path_ids(self):
        self._assert_loud_closed([_path("dup", True), _path("dup", False)])

    def test_non_callable_check(self):
        self._assert_loud_closed(
            [rog.AuthPath(path_id="nc", check=None)])

    def test_non_list_input(self):
        self._assert_loud_closed("not-a-list")
        self._assert_loud_closed(None)

    def test_bad_path_id(self):
        self._assert_loud_closed([rog.AuthPath(path_id="", check=lambda: True)])
        self._assert_loud_closed(
            [rog.AuthPath(path_id=123, check=lambda: True)])

    def test_non_authpath_entry(self):
        self._assert_loud_closed([{"path_id": "x"}])

    def test_check_configuration_public(self):
        self.assertIsNone(rog.check_configuration([_path("p", True)]))
        self.assertIsNotNone(rog.check_configuration([]))


class OracleCleanTests(unittest.TestCase):
    def test_refusal_details_never_carry_path_labels(self):
        secret_ids = ["grant-ALPHA-%d" % i for i in range(3)]
        refused = rog.authorize([rog.AuthPath(pid, lambda: False)
                                 for pid in secret_ids[:2]])
        cne = rog.authorize([_unavailable(secret_ids[2])])
        miscfg = rog.authorize([])
        for res in (refused, cne, miscfg):
            for pid in secret_ids:
                self.assertNotIn(pid, res["detail"])
                self.assertNotIn(pid, res["refusal"])


class AuthorizeOrRaiseTests(unittest.TestCase):
    def test_raise_carries_code_and_clean_detail(self):
        with self.assertRaises(rog.RefusalOracleError) as ctx:
            rog.authorize_or_raise([_path("secret-p", False)])
        self.assertEqual(ctx.exception.code,
                         rog.ORACLE_EVALUATED_AND_REFUSED)
        self.assertEqual(ctx.exception.detail,
                         "no authorization path granted")

    def test_raise_passes_authorized_through(self):
        res = rog.authorize_or_raise([_path("p", True)])
        self.assertTrue(res["authorized"])


if __name__ == "__main__":
    unittest.main()
