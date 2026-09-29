"""Unit tests for gov.artifact_rules (wave-212 lane B).

Stdlib unittest. Covers the full six-rule grammar, the fail-closed
load discipline (no terminal DISALLOW -> refused at load), name/digest
hygiene, consumptive accounting, and the audit report shape. The
break-first adversarial shapes live in evals/artifact_rules_probes.py.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import artifact_rules as ar

D1 = "aa" * 32
D2 = "bb" * 32
D3 = "cc" * 32


def _rules(*specs):
    return list(specs)


class TestParseRule(unittest.TestCase):
    def test_valid_forms(self):
        self.assertEqual(ar.parse_rule(("CREATE", "out/*")),
                         ("CREATE", "out/*"))
        self.assertEqual(ar.parse_rule(("MODIFY", "src/*.c")),
                         ("MODIFY", "src/*.c"))
        self.assertEqual(ar.parse_rule(("DELETE", "tmp/*")),
                         ("DELETE", "tmp/*"))
        self.assertEqual(ar.parse_rule(("REQUIRE", "release.tar.gz")),
                         ("REQUIRE", "release.tar.gz"))
        self.assertEqual(ar.parse_rule(("MATCH", "x", D1)),
                         ("MATCH", "x", D1))
        self.assertEqual(ar.parse_rule(("DISALLOW",)), ("DISALLOW",))

    def test_unknown_kind_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("ALLOW", "*"))

    def test_wrong_arity_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("CREATE", "a", "b"))
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("DISALLOW", "extra"))
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("MATCH", "x"))
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(())

    def test_non_tuple_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule("CREATE out/*")

    def test_empty_pattern_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("CREATE", ""))

    def test_bad_digest_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("MATCH", "x", "nothex"))
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("MATCH", "x", "aa" * 31))  # short
        with self.assertRaises(ar.ArtifactRuleError):
            ar.parse_rule(("MATCH", "x", "AA" * 32))  # not lowercase

    def test_error_is_value_error(self):
        self.assertTrue(issubclass(ar.ArtifactRuleError, ValueError))


class TestLoadRules(unittest.TestCase):
    def test_valid_set_returns_normalized_tuple(self):
        rules = ar.load_rules(_rules(("REQUIRE", "a"), ("DISALLOW",)))
        self.assertIsInstance(rules, tuple)
        self.assertEqual(rules[-1], ("DISALLOW",))

    def test_empty_set_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.load_rules([])

    def test_no_disallow_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.load_rules(_rules(("REQUIRE", "a")))

    def test_mid_disallow_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.load_rules(_rules(("DISALLOW",), ("REQUIRE", "a"),
                                 ("DISALLOW",)))

    def test_double_terminal_disallow_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.load_rules(_rules(("REQUIRE", "a"), ("DISALLOW",),
                                 ("DISALLOW",)))


class TestVerifyArtifacts(unittest.TestCase):
    def test_empty_queues_verify(self):
        report = ar.verify_artifacts({}, {},
                                     _rules(("DISALLOW",)))
        self.assertTrue(report["ok"])
        self.assertEqual(report["consumed_count"], 0)

    def test_rule_order_matters(self):
        # DISALLOW first would refuse everything; rules are ordered.
        materials = {"a": D1}
        products = {}
        with self.assertRaises(ar.ArtifactRuleError):
            ar.verify_artifacts(materials, products,
                                _rules(("DISALLOW",), ("REQUIRE", "a")))
        # (load_rules refuses mid DISALLOW; this path double-covers)
        self.assertTrue(True)

    def test_create_consumes_product(self):
        report = ar.verify_artifacts({"s": D1}, {"out/bin": D2},
                                     _rules(("CREATE", "out/*"),
                                            ("REQUIRE", "s"),
                                            ("DISALLOW",)))
        self.assertEqual(report["per_rule"][0]["consumed"],
                         ["product:out/bin"])

    def test_modify_consumes_both_records(self):
        report = ar.verify_artifacts({"f": D1}, {"f": D2},
                                     _rules(("MODIFY", "f"),
                                            ("DISALLOW",)))
        self.assertEqual(sorted(report["per_rule"][0]["consumed"]),
                         ["material:f", "product:f"])

    def test_delete_consumes_material(self):
        report = ar.verify_artifacts({"tmp/x": D1}, {},
                                     _rules(("DELETE", "tmp/*"),
                                            ("DISALLOW",)))
        self.assertEqual(report["per_rule"][0]["consumed"],
                         ["material:tmp/x"])

    def test_match_pins_digest(self):
        ar.verify_artifacts({"rel": D1}, {},
                            _rules(("MATCH", "rel", D1),
                                   ("DISALLOW",)))
        with self.assertRaises(ar.ArtifactRuleError):
            ar.verify_artifacts({"rel": D1}, {},
                                _rules(("MATCH", "rel", D2),
                                       ("DISALLOW",)))

    def test_match_checks_every_record_with_name(self):
        # product record disagrees with the pin -> refuse
        with self.assertRaises(ar.ArtifactRuleError):
            ar.verify_artifacts({"rel": D1}, {"rel": D2},
                                _rules(("MATCH", "rel", D1),
                                       ("DISALLOW",)))

    def test_require_consumes_both_records(self):
        report = ar.verify_artifacts({"a": D1}, {"a": D1},
                                     _rules(("REQUIRE", "a"),
                                            ("DISALLOW",)))
        self.assertEqual(sorted(report["per_rule"][0]["consumed"]),
                         ["material:a", "product:a"])

    def test_noop_pattern_rules_allowed(self):
        # CREATE/MODIFY/DELETE patterns matching nothing are no-ops;
        # the terminal DISALLOW still accounts for everything.
        ar.verify_artifacts({"a": D1}, {},
                            _rules(("CREATE", "out/*"),
                                   ("REQUIRE", "a"),
                                   ("DISALLOW",)))

    def test_context_echoed(self):
        report = ar.verify_artifacts({}, {}, _rules(("DISALLOW",)),
                                     context="promote:build-42")
        self.assertEqual(report["context"], "promote:build-42")
        with self.assertRaises(ar.ArtifactRuleError) as cm:
            ar.verify_artifacts({"a": D1}, {},
                                _rules(("REQUIRE", "b"),
                                       ("DISALLOW",)),
                                context="promote:build-42")
        self.assertIn("promote:build-42", str(cm.exception))

    def test_rule_set_digest_stable(self):
        r1 = ar.verify_artifacts({"a": D1}, {},
                                 _rules(("REQUIRE", "a"),
                                        ("DISALLOW",)))
        r2 = ar.verify_artifacts({"a": D1}, {},
                                 _rules(("REQUIRE", "a"),
                                        ("DISALLOW",)))
        self.assertEqual(r1["rule_set_digest"], r2["rule_set_digest"])
        self.assertEqual(len(r1["rule_set_digest"]), 64)
        r3 = ar.verify_artifacts({"a": D1}, {},
                                 _rules(("MATCH", "a", D1),
                                        ("DISALLOW",)))
        self.assertNotEqual(r1["rule_set_digest"], r3["rule_set_digest"])

    def test_name_hygiene(self):
        for bad in ("/abs/path", "a/../b", "a\\b", "a\x00b", ""):
            with self.assertRaises(ar.ArtifactRuleError, msg=bad):
                ar.verify_artifacts({bad: D1}, {},
                                    _rules(("DISALLOW",)))

    def test_non_dict_inputs_refused(self):
        with self.assertRaises(ar.ArtifactRuleError):
            ar.verify_artifacts([("a", D1)], {},
                                _rules(("DISALLOW",)))

    def test_preloaded_rules_accepted(self):
        preloaded = ar.load_rules(_rules(("REQUIRE", "a"),
                                         ("DISALLOW",)))
        report = ar.verify_artifacts({"a": D1}, {}, preloaded)
        self.assertTrue(report["ok"])


if __name__ == "__main__":
    unittest.main()
