#!/usr/bin/env python3
"""Unit tests for gov.provenance_verifier (wave-204 lane C).

Covers the in-toto-pattern rule engine (REQUIRE / MATCH / terminal
DISALLOW), the Nix-ADAPT reproducibility checks (double build,
input-closure identity, signed binary substitution), and the
fail-closed strictness of the public seams.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from gov import build_provenance as bp  # noqa: E402
from gov import provenance_verifier as pv  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402


def _signers():
    s1 = Ed25519Signer(bytes([1]) * 32)
    s2 = Ed25519Signer(bytes([2]) * 32)
    return (s1, Ed25519Verifier(s1.public_key, s1.key_id),
            s2, Ed25519Verifier(s2.public_key, s2.key_id))


def _seal(signer, artifact_hex, inputs):
    stmt = bp.ProvenanceStatement(
        builder="ci-builder-1",
        recipe="repo@sha256:" + "ab" * 32,
        inputs=inputs,
        artifact_hex=artifact_hex,
        built_at=1700000000,
    )
    return stmt.seal(signer)


def _inp(name, char, deterministic=True):
    return bp.ProvenanceInput(name=name, digest_hex=char * 64,
                              deterministic=deterministic)


class TestRuleParsing(unittest.TestCase):
    def test_require_ok(self):
        self.assertEqual(pv.parse_rule(("REQUIRE", "a")),
                         ("REQUIRE", "a"))

    def test_match_ok(self):
        self.assertEqual(pv.parse_rule(["MATCH", "a", "b" * 64]),
                         ("MATCH", "a", "b" * 64))

    def test_disallow_ok(self):
        self.assertEqual(pv.parse_rule(("DISALLOW",)), ("DISALLOW",))

    def test_unknown_kind_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.parse_rule(("ALLOW", "a"))

    def test_wrong_arity_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.parse_rule(("REQUIRE", "a", "b"))
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.parse_rule(("MATCH", "a"))
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.parse_rule(("DISALLOW", "a"))

    def test_bad_digest_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.parse_rule(("MATCH", "a", "not-a-digest"))

    def test_empty_rule_set_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.check_rule_set([])

    def test_missing_terminal_disallow_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.check_rule_set([("REQUIRE", "a")])

    def test_nonterminal_disallow_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.check_rule_set([("DISALLOW",), ("REQUIRE", "a"),
                               ("DISALLOW",)])

    def test_valid_set_normalized(self):
        rules = pv.check_rule_set([["REQUIRE", "a"],
                                   ("MATCH", "b", "c" * 64),
                                   ("DISALLOW",)])
        self.assertEqual(rules, [("REQUIRE", "a"),
                                 ("MATCH", "b", "c" * 64),
                                 ("DISALLOW",)])


class TestChain(unittest.TestCase):
    def setUp(self):
        self.s1, self.v1, _, _ = _signers()
        self.sealed_a = _seal(self.s1, "aa" * 32,
                              [_inp("src", "1")])
        self.sealed_b = _seal(self.s1, "bb" * 32,
                              [_inp("src", "2")])
        self.named = {"a": self.sealed_a, "b": self.sealed_b}
        self.artifacts = {"a": "aa" * 32, "b": "bb" * 32}
        self.verifiers = {self.v1.key_id: self.v1}

    def test_positive_chain(self):
        res = pv.verify_provenance_chain(
            dict(self.named), dict(self.artifacts),
            [("REQUIRE", "a"), ("MATCH", "b", "bb" * 32), ("DISALLOW",)],
            self.verifiers)
        self.assertEqual(sorted(res["consumed"]), ["a", "b"])
        self.assertEqual(res["rules_applied"], 3)

    def test_match_wrong_expected_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_provenance_chain(
                dict(self.named), dict(self.artifacts),
                [("MATCH", "a", "cc" * 32), ("DISALLOW",)], self.verifiers)

    def test_require_twice_refused(self):
        # Second REQUIRE hits an already-consumed artifact.
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_provenance_chain(
                dict(self.named), dict(self.artifacts),
                [("REQUIRE", "a"), ("REQUIRE", "a"), ("DISALLOW",)],
                self.verifiers)

    def test_untrusted_key_refused(self):
        _, _, s2, v2 = _signers()
        bad = _seal(s2, "aa" * 32, [_inp("src", "1")])
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_provenance_chain(
                {"a": bad}, {"a": "aa" * 32},
                [("REQUIRE", "a"), ("DISALLOW",)], self.verifiers)

    def test_tampered_statement_refused(self):
        tampered = dict(self.sealed_a)
        stmt = dict(tampered["statement"])
        stmt["builder"] = "evil-builder"
        tampered["statement"] = stmt
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_provenance_chain(
                {"a": tampered}, {"a": "aa" * 32},
                [("REQUIRE", "a"), ("DISALLOW",)], self.verifiers)

    def test_empty_named_statements_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_provenance_chain(
                {}, dict(self.artifacts),
                [("REQUIRE", "a"), ("DISALLOW",)], self.verifiers)

    def test_non_verifier_value_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_provenance_chain(
                dict(self.named), dict(self.artifacts),
                [("REQUIRE", "a"), ("DISALLOW",)],
                {self.v1.key_id: object()})

    def test_error_type_is_verifier_error(self):
        # The documented contract: public seams raise
        # ProvenanceVerifierError, never a raw ProvenanceError.
        try:
            pv.verify_provenance_chain(
                dict(self.named), {"a": "ff" * 32},
                [("REQUIRE", "a"), ("DISALLOW",)], self.verifiers)
        except pv.ProvenanceVerifierError:
            pass
        else:
            self.fail("expected ProvenanceVerifierError")

    def test_malformed_sealed_in_mapping_raises_verifier_error(self):
        # A malformed sealed statement in named_statements must raise
        # ProvenanceVerifierError, not a raw ProvenanceError.
        for junk in ("junk", 12345, {"statement": {}}):
            try:
                pv.verify_provenance_chain(
                    {"a": junk}, {"a": "aa" * 32},
                    [("REQUIRE", "a"), ("DISALLOW",)], self.verifiers)
            except pv.ProvenanceVerifierError:
                pass
            else:
                self.fail("expected ProvenanceVerifierError for %r"
                          % (junk,))


class TestDoubleBuild(unittest.TestCase):
    def setUp(self):
        self.s1, self.v1, _, _ = _signers()
        self.sealed = _seal(self.s1, "aa" * 32,
                            [_inp("src", "1"),
                             _inp("seed", "2", deterministic=False)])

    def test_honest(self):
        res = pv.verify_double_build(
            self.sealed, lambda n: {"src": "1" * 64}[n],
            self.v1, "aa" * 32)
        self.assertEqual(res, {"checked": ["src"], "unchecked": ["seed"]})

    def test_flaky_rebuild_refused(self):
        calls = []

        def flaky(name):
            calls.append(name)
            return "1" * 64 if len(calls) == 1 else "9" * 64

        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_double_build(self.sealed, flaky, self.v1, "aa" * 32)

    def test_wrong_digest_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_double_build(
                self.sealed, lambda n: "9" * 64, self.v1, "aa" * 32)

    def test_wrong_artifact_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_double_build(
                self.sealed, lambda n: "1" * 64, self.v1, "ff" * 32)

    def test_non_callable_rebuilder_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_double_build(self.sealed, "not-callable",
                                   self.v1, "aa" * 32)


class TestClosure(unittest.TestCase):
    def setUp(self):
        self.s1, self.v1, _, _ = _signers()
        self.sealed = _seal(self.s1, "aa" * 32,
                            [_inp("b-src", "2"), _inp("a-src", "1")])

    def test_closure_is_order_independent(self):
        # inputs declared b,a -- closure digest must not depend on
        # declaration order.
        d1 = pv.input_closure_digest(self.sealed)
        stmt, _, _ = bp.parse_statement(self.sealed)
        rev = bp.ProvenanceStatement(
            builder=stmt.builder, recipe=stmt.recipe,
            inputs=list(reversed(stmt.inputs)),
            artifact_hex=stmt.artifact_hex, built_at=stmt.built_at)
        self.assertEqual(pv.input_closure_digest(rev), d1)
        self.assertEqual(len(d1), 64)

    def test_honest_closure(self):
        res = pv.verify_input_closure(
            self.sealed, [("a-src", "1" * 64), ("b-src", "2" * 64)],
            self.v1, "aa" * 32)
        self.assertEqual(res["closure"],
                         pv.input_closure_digest(self.sealed))

    def test_drift_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_input_closure(
                self.sealed, [("a-src", "1" * 64), ("b-src", "9" * 64)],
                self.v1, "aa" * 32)

    def test_omission_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_input_closure(
                self.sealed, [("a-src", "1" * 64)], self.v1, "aa" * 32)

    def test_addition_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_input_closure(
                self.sealed,
                [("a-src", "1" * 64), ("b-src", "2" * 64),
                 ("extra", "3" * 64)],
                self.v1, "aa" * 32)

    def test_duplicate_observed_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_input_closure(
                self.sealed,
                [("a-src", "1" * 64), ("a-src", "1" * 64)],
                self.v1, "aa" * 32)

    def test_closure_digest_garbage_raises_verifier_error(self):
        # input_closure_digest on non-statement input must raise
        # ProvenanceVerifierError, not a raw ProvenanceError.
        for junk in ("garbage", 12345, {"statement": {}}):
            try:
                pv.input_closure_digest(junk)
            except pv.ProvenanceVerifierError:
                pass
            else:
                self.fail("expected ProvenanceVerifierError for %r"
                          % (junk,))


class TestPrebuilt(unittest.TestCase):
    def setUp(self):
        self.s1, self.v1, _, _ = _signers()
        self.sealed = _seal(self.s1, "aa" * 32, [_inp("src", "1")])

    def test_signed_prebuilt_ok(self):
        stmt = pv.verify_prebuilt("lib.o", "aa" * 32, self.sealed,
                                  self.v1)
        self.assertEqual(stmt.artifact_hex, "aa" * 32)

    def test_unsigned_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_prebuilt("lib.o", "aa" * 32, None, self.v1)

    def test_wrong_digest_refused(self):
        with self.assertRaises(pv.ProvenanceVerifierError):
            pv.verify_prebuilt("lib.o", "ff" * 32, self.sealed, self.v1)

    def test_error_type_contract(self):
        for args in (("lib.o", "aa" * 32, None, self.v1),
                     ("lib.o", "ff" * 32, self.sealed, self.v1)):
            try:
                pv.verify_prebuilt(*args)
            except pv.ProvenanceVerifierError:
                pass
            else:
                self.fail("expected ProvenanceVerifierError for %r"
                          % (args,))


if __name__ == "__main__":
    unittest.main()
