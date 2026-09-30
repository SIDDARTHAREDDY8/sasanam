#!/usr/bin/env python3
"""Unit tests for gov/grant_attenuation.py (wave-235 lane C).

Delegated grants refine scope, never extend: delegation transfers the
attenuated envelope, never copies rights. Deterministic; no network;
stdlib only.
"""

import copy
import hashlib
import json
import unittest

from gov import grant_attenuation as ga


_SCOPE = {
    "actions": ["read", "write", "delete"],
    "regions": ["us", "eu"],
    "tier": "standard",
    "budget": {"min": 0, "max": 1000},
}


def _fresh_scope():
    # deepcopy: plain dict(_SCOPE) would share the inner lists across
    # tests, letting one test pollute another.
    return copy.deepcopy(_SCOPE)


def _code_of(fn):
    try:
        fn()
    except ga.GrantAttenuationError as exc:
        return exc.code
    return None


class MintTest(unittest.TestCase):
    def test_root_has_empty_chain(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(root["attenuation_chain"], [])
        self.assertIsNone(root["parent_grant_id"])
        self.assertEqual(root["root_grant_id"], "r1")
        self.assertEqual(len(root["grant_digest"]), 64)

    def test_empty_scope_refused(self):
        self.assertEqual(
            _code_of(lambda: ga.mint_root_grant("r1", {})),
            "grant-malformed")

    def test_bad_grant_id_refused(self):
        self.assertEqual(
            _code_of(lambda: ga.mint_root_grant("", _fresh_scope())),
            "grant-malformed")

    def test_deterministic_digest(self):
        a = ga.mint_root_grant("r1", _fresh_scope())
        b = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(a["grant_digest"], b["grant_digest"])

    def test_caller_objects_decoupled(self):
        scope = _fresh_scope()
        root = ga.mint_root_grant("r1", scope)
        scope["actions"].append("admin")
        self.assertNotIn("admin", root["scope"]["actions"])


class NarrowingTest(unittest.TestCase):
    def test_set_subset_narrows(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        child = ga.delegate(root, {"actions": ["read"]}, "d1")
        self.assertEqual(child["scope"]["actions"], ["read"])

    def test_range_containment_narrows(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        child = ga.delegate(root, {"budget": {"min": 10, "max": 500}},
                            "d1")
        self.assertEqual(child["scope"]["budget"],
                         {"min": 10, "max": 500})

    def test_range_widening_refused(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(
            _code_of(lambda: ga.delegate(
                root, {"budget": {"min": 0, "max": 2000}}, "d1")),
            "grant-widened")

    def test_scalar_equal_confirms(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        child = ga.delegate(
            root, {"tier": "standard", "actions": ["read"]}, "d1")
        self.assertEqual(child["scope"]["tier"], "standard")

    def test_scalar_change_is_widening(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(
            _code_of(lambda: ga.delegate(root, {"tier": "gold"}, "d1")),
            "grant-widened")

    def test_unknown_dimension_is_widening(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(
            _code_of(lambda: ga.delegate(root, {"zones": ["a"]}, "d1")),
            "grant-widened")

    def test_type_change_is_malformed(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(
            _code_of(lambda: ga.delegate(root, {"actions": "read"}, "d1")),
            "grant-malformed")

    def test_exact_copy_refused_as_gap(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(
            _code_of(lambda: ga.delegate(root, _fresh_scope(), "d1")),
            "grant-attenuation-gap")

    def test_empty_attenuation_refused_as_gap(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        self.assertEqual(
            _code_of(lambda: ga.delegate(root, {}, "d1")),
            "grant-attenuation-gap")

    def test_parent_not_mutated(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        ga.delegate(root, {"actions": ["read"]}, "d1")
        self.assertEqual(sorted(root["scope"]["actions"]),
                         ["delete", "read", "write"])
        self.assertEqual(root["attenuation_chain"], [])

    def test_tampered_parent_refused(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        bad = copy.deepcopy(root)
        bad["scope"]["actions"].append("admin")
        self.assertEqual(
            _code_of(lambda: ga.delegate(bad, {"actions": ["read"]}, "d1")),
            "grant-malformed")


class ChainVerifyTest(unittest.TestCase):
    def _chain3(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        c1 = ga.delegate(root, {"actions": ["read", "write"]}, "d1")
        c2 = ga.delegate(c1, {"regions": ["us"]}, "d2")
        c3 = ga.delegate(c2, {"actions": ["read"]}, "d3")
        return root, c3

    def test_three_hop_chain_verifies(self):
        _, c3 = self._chain3()
        audit = ga.verify_delegation_chain(c3)
        self.assertEqual(audit["chain_length"], 3)
        self.assertEqual(audit["root_grant_id"], "r1")
        self.assertEqual([h["index"] for h in audit["hops"]], [0, 1, 2])

    def test_root_refused_chain_required(self):
        root, _ = self._chain3()
        self.assertEqual(
            _code_of(lambda: ga.verify_delegation_chain(root)),
            "grant-chain-required")

    def test_revocation_callable_supported(self):
        _, c3 = self._chain3()
        # A callable that revokes nothing: the chain verifies.
        audit = ga.verify_delegation_chain(
            c3, revocation_registry=lambda d: False)
        self.assertEqual(audit["chain_length"], 3)
        # A callable that revokes everything: grant-revoked.
        self.assertEqual(
            _code_of(lambda: ga.verify_delegation_chain(
                c3, revocation_registry=lambda d: True)),
            "grant-revoked")

    def test_revoked_refusal_names_hop(self):
        _, c3 = self._chain3()
        digest = c3["attenuation_chain"][2]["hop_digest"]
        try:
            ga.verify_delegation_chain(
                c3, revocation_registry={digest: True})
            self.fail("expected grant-revoked")
        except ga.GrantAttenuationError as exc:
            self.assertEqual(exc.code, "grant-revoked")
            self.assertIn("hop 2", str(exc))
            self.assertIn("d3", str(exc))

    def test_revocation_endpoint_carried(self):
        root = ga.mint_root_grant("r1", _fresh_scope())
        child = ga.delegate(root, {"actions": ["read"]}, "d1",
                            revocation_endpoint="https://rev.example/hops")
        hop = child["attenuation_chain"][0]
        self.assertEqual(hop["revocation_endpoint"],
                         "https://rev.example/hops")
        audit = ga.verify_delegation_chain(child)
        self.assertEqual(audit["chain_length"], 1)

    def test_broken_continuity_refused(self):
        _, c3 = self._chain3()
        bad = copy.deepcopy(c3)
        hop = bad["attenuation_chain"][1]
        hop["parent_grant_id"] = "someone-else"
        hop_body = {k: v for k, v in hop.items() if k != "hop_digest"}
        hop["hop_digest"] = hashlib.sha256(
            json.dumps(hop_body, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest()
        grant_body = {k: v for k, v in bad.items()
                      if k != "grant_digest"}
        bad["grant_digest"] = hashlib.sha256(
            json.dumps(grant_body, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest()
        # Digests are consistent; only the lineage continuity breaks.
        self.assertEqual(
            _code_of(lambda: ga.verify_delegation_chain(bad)),
            "grant-attenuation-gap")

    def test_base_error_carries_no_code(self):
        # w228 scanner sees only real product codes.
        self.assertIsNone(ga.GrantAttenuationError.code)


if __name__ == "__main__":
    unittest.main()
