"""Unit tests for gov.c2pa_provenance (wave-210 lane B).

Complements evals/c2pa_provenance_probes.py (the red-first battery):
the probes attack the public seams break-first; these tests pin
edge-case behavior and error taxonomy at the same seams.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import c2pa_provenance as c2pa
from gov import decision_bom as bom
from gov.signing import Ed25519Signer, Ed25519Verifier

_SEED_A = bytes.fromhex("71" * 32)
_SEED_B = bytes.fromhex("73" * 32)


def _d(data):
    return hashlib.sha256(data).hexdigest()


def _manifest(**kw):
    base = dict(content_digest=_d(b"artifact bytes"),
                content_len=14,
                action="c2pa.ai_generated",
                software_agent="sasanam-agent v0.9")
    base.update(kw)
    return c2pa.build_manifest(**base)


class TestBuildValidation(unittest.TestCase):
    def test_bad_content_digest_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(content_digest="not-hex")

    def test_negative_content_len_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(content_len=-1)

    def test_bool_content_len_refused(self):
        # True == 1 in Python; a bare int check would accept it.
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(content_len=True)

    def test_unknown_action_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(action="c2pa.teleported")

    def test_empty_software_agent_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(software_agent="")

    def test_unknown_ingredient_role_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(ingredients=[{
                "ingredient_digest": _d(b"p"),
                "manifest_digest": None,
                "relationship": "parentOf",
                "role": "mystery"}])

    def test_unknown_ingredient_field_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(ingredients=[{
                "ingredient_digest": _d(b"p"),
                "manifest_digest": None,
                "relationship": "parentOf",
                "role": "prompt",
                "extra": "nope"}])

    def test_bad_relationship_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(ingredients=[{
                "ingredient_digest": _d(b"p"),
                "manifest_digest": None,
                "relationship": "childOf",
                "role": "prompt"}])

    def test_duplicate_parent_manifest_refused(self):
        parent = _manifest()
        pd = c2pa.manifest_digest(parent)
        ing = {"ingredient_digest": _d(b"p"), "manifest_digest": pd,
               "relationship": "parentOf", "role": "prior-decision"}
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(ingredients=[ing, dict(ing)])

    def test_none_manifest_digest_allowed_for_external_inputs(self):
        m = _manifest(ingredients=[{
            "ingredient_digest": _d(b"prompt-bytes"),
            "manifest_digest": None,
            "relationship": "parentOf", "role": "prompt"}])
        self.assertIsNone(
            m["assertions"]["c2pa.ingredient"]["ingredients"][0]
            ["manifest_digest"])

    def test_empty_description_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(description="")

    def test_conformance_label_is_honest(self):
        m = _manifest()
        self.assertEqual(m["conformance"], "c2pa-shaped-not-conformant")
        self.assertEqual(m["manifest_format"], "c2pa-shaped-manifest/v1")


class TestLint(unittest.TestCase):
    def test_each_judgment_token_refused(self):
        for token in ("good", "bad", "safe", "unsafe", "trustworthy",
                      "correct", "wise"):
            with self.assertRaises(c2pa.C2PAManifestError,
                                   msg="token %r" % token):
                _manifest(description="a %s summary" % token)

    def test_word_boundary_no_false_positive(self):
        # "safety" and "incorrectly" must not trip the lint: the match
        # is on word boundaries, and judgment is about worth, not prose
        # that merely contains a banned substring.
        m = _manifest(description="safety review notes, drafted")
        self.assertIn("description", m)

    def test_incorrect_is_itself_banned(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            _manifest(description="an incorrect rendering")

    def test_lint_runs_at_verify_too(self):
        m = _manifest()
        m["description"] = "a safe output"
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.verify_manifest_shape(m)

    def test_lint_names_field_and_token(self):
        m = _manifest()
        m["description"] = "trustworthy results"
        try:
            c2pa.verify_manifest_shape(m)
        except c2pa.C2PAManifestError as exc:
            self.assertIn("description", str(exc))
            self.assertIn("trustworthy", str(exc))
        else:
            self.fail("expected C2PAManifestError")


class TestDigestAndSeal(unittest.TestCase):
    def test_manifest_digest_deterministic(self):
        m1 = _manifest()
        m2 = _manifest()
        self.assertEqual(c2pa.manifest_digest(m1),
                         c2pa.manifest_digest(m2))

    def test_canonical_bytes_stable(self):
        m = _manifest()
        self.assertEqual(c2pa.canonical_manifest(m),
                         c2pa.canonical_manifest(m))

    def test_seal_requires_signer(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.seal_manifest(_manifest(), [])

    def test_threshold_two(self):
        m = _manifest()
        digest = m["assertions"]["c2pa.hash.data"]["digest"]
        sa, sb = Ed25519Signer(_SEED_A), Ed25519Signer(_SEED_B)
        env = c2pa.seal_manifest(m, [sa, sb])
        verifiers = [Ed25519Verifier(sa.public_key),
                     Ed25519Verifier(sb.public_key)]
        opened = c2pa.open_manifest(env, digest, verifiers, threshold=2)
        self.assertEqual(c2pa.manifest_digest(opened),
                         c2pa.manifest_digest(m))
        # Threshold 2 with only one known key must fail.
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.open_manifest(env, digest, verifiers[:1], threshold=2)

    def test_wrong_payload_type_refused(self):
        from gov import dsse_envelope as de
        m = _manifest()
        env = de.seal(c2pa.canonical_manifest(m), "application/json",
                      [Ed25519Signer(_SEED_A)])
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.open_manifest(env,
                               m["assertions"]["c2pa.hash.data"]["digest"],
                               [Ed25519Verifier(
                                   Ed25519Signer(_SEED_A).public_key)])

    def test_open_without_chain_store_skips_walk(self):
        m = _manifest()
        digest = m["assertions"]["c2pa.hash.data"]["digest"]
        s = Ed25519Signer(_SEED_A)
        env = c2pa.seal_manifest(m, [s])
        opened = c2pa.open_manifest(env, digest,
                                    [Ed25519Verifier(s.public_key)])
        self.assertEqual(c2pa.manifest_digest(opened),
                         c2pa.manifest_digest(m))

    def test_non_json_payload_refused(self):
        from gov import dsse_envelope as de
        s = Ed25519Signer(_SEED_A)
        env = de.seal(b"not json at all", c2pa.PAYLOAD_TYPE, [s])
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.open_manifest(env, _d(b"x"),
                               [Ed25519Verifier(s.public_key)])


class TestChain(unittest.TestCase):
    def _chain(self):
        g0 = _manifest(action="c2pa.created",
                       software_agent="sasanam-model v1.2.3")
        g0d = c2pa.manifest_digest(g0)
        g0c = g0["assertions"]["c2pa.hash.data"]["digest"]
        g1 = _manifest(ingredients=[{
            "ingredient_digest": g0c, "manifest_digest": g0d,
            "relationship": "parentOf", "role": "model"}])
        g1d = c2pa.manifest_digest(g1)
        g1c = g1["assertions"]["c2pa.hash.data"]["digest"]
        g2 = _manifest(ingredients=[{
            "ingredient_digest": g1c, "manifest_digest": g1d,
            "relationship": "parentOf", "role": "prior-decision"}])
        store = {g0d: g0, g1d: g1, c2pa.manifest_digest(g2): g2}
        return g0, g1, g2, store

    def test_walk_order_child_first(self):
        g0, g1, g2, store = self._chain()
        walked = c2pa.verify_chain(g2, store)
        self.assertEqual(walked, [c2pa.manifest_digest(g2),
                                  c2pa.manifest_digest(g1),
                                  c2pa.manifest_digest(g0)])

    def test_relabeled_parent_refused(self):
        g0, g1, g2, store = self._chain()
        evil = dict(g2)
        import copy
        evil = copy.deepcopy(g2)
        evil["assertions"]["c2pa.ingredient"]["ingredients"][0][
            "ingredient_digest"] = _d(b"something else")
        # The store is fine; the CHILD's recorded digest is wrong.
        with self.assertRaises(c2pa.C2PAManifestError) as ctx:
            c2pa.verify_chain(evil, store)
        self.assertIn("relabeled parent", str(ctx.exception))

    def test_store_entry_not_a_manifest(self):
        g0, g1, g2, store = self._chain()
        store[c2pa.manifest_digest(g0)] = "not a manifest"
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.verify_chain(g2, store)

    def test_cycle_branch_defense_in_depth(self):
        # The _path cycle branch is unreachable through key-consistent
        # stores; pin it via the internal parameter directly.
        g0, g1, g2, store = self._chain()
        g2d = c2pa.manifest_digest(g2)
        with self.assertRaises(c2pa.C2PAManifestError) as ctx:
            c2pa.verify_chain(g2, store, _path=(g2d,))
        self.assertIn("cycle", str(ctx.exception))

    def test_max_depth_boundary(self):
        store = {}
        child = _manifest(action="c2pa.created",
                          software_agent="sasanam-model v1.2.3")
        store[c2pa.manifest_digest(child)] = child
        for i in range(c2pa.MAX_CHAIN_DEPTH - 1):
            pd = c2pa.manifest_digest(child)
            pc = child["assertions"]["c2pa.hash.data"]["digest"]
            child = _manifest(ingredients=[{
                "ingredient_digest": pc, "manifest_digest": pd,
                "relationship": "parentOf", "role": "prior-decision"}])
            store[c2pa.manifest_digest(child)] = child
        # Exactly MAX_CHAIN_DEPTH generations: walks fine.
        walked = c2pa.verify_chain(child, store)
        self.assertEqual(len(walked), c2pa.MAX_CHAIN_DEPTH)


class TestBomSection(unittest.TestCase):
    def test_section_shape(self):
        s = c2pa.bom_c2pa_section(_d(b"m"), 3, [_d(b"r1"), _d(b"r2")])
        self.assertEqual(s, {"manifest_digest": _d(b"m"),
                             "chain_length": 3,
                             "root_ingredient_digests": [_d(b"r1"),
                                                         _d(b"r2")]})

    def test_bad_manifest_digest_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.bom_c2pa_section("zz", 1, [])

    def test_zero_chain_length_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.bom_c2pa_section(_d(b"m"), 0, [])

    def test_bool_chain_length_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.bom_c2pa_section(_d(b"m"), True, [])

    def test_bad_root_digest_refused(self):
        with self.assertRaises(c2pa.C2PAManifestError):
            c2pa.bom_c2pa_section(_d(b"m"), 1, ["nope"])

    def test_empty_roots_allowed_for_genesis(self):
        s = c2pa.bom_c2pa_section(_d(b"m"), 1, [])
        self.assertEqual(s["root_ingredient_digests"], [])


class TestDecisionBomWiring(unittest.TestCase):
    def _base(self):
        return dict(policy_id="p7", policy_version="v1",
                    policy_digest=_d(b"policy-bytes"),
                    evidence_head_digest=_d(b"head"),
                    principal={"agent_id": "a1", "role": "r",
                               "principal": "p", "run_id": "run1"})

    def test_omission_byte_identical(self):
        b0 = bom.build_bom(**self._base())
        b1 = bom.build_bom(c2pa_provenance=None, **self._base())
        self.assertEqual(bom.bom_digest(b0), bom.bom_digest(b1))

    def test_partial_section_refused(self):
        with self.assertRaises(bom.BomError):
            bom.build_bom(c2pa_provenance={"manifest_digest": _d(b"m")},
                          **self._base())

    def test_unknown_keys_refused(self):
        with self.assertRaises(bom.BomError):
            bom.build_bom(c2pa_provenance={
                "manifest_digest": _d(b"m"), "chain_length": 1,
                "root_ingredient_digests": [], "extra": 1},
                **self._base())

    def test_non_dict_refused(self):
        with self.assertRaises(bom.BomError):
            bom.build_bom(c2pa_provenance="nope", **self._base())

    def test_shape_check_catches_bad_section(self):
        b = bom.build_bom(**self._base())
        b["inputs"]["c2pa_provenance"] = {"manifest_digest": "zz"}
        ok, reason = bom.check_bom_shape(b)
        self.assertFalse(ok)
        self.assertIn("manifest_digest", reason)

    def test_verify_leg_rejects_swapped_body(self):
        m = _manifest()
        section = c2pa.bom_c2pa_section(c2pa.manifest_digest(m), 1, [])
        b = bom.build_bom(c2pa_provenance=section, **self._base())
        # Deterministic builder: _manifest() would be byte-identical,
        # so vary the software agent to get a genuinely different body.
        other = _manifest(software_agent="sasanam-agent v0.10")
        self.assertNotEqual(c2pa.manifest_digest(other),
                            c2pa.manifest_digest(m))
        ok, reason = bom.verify_bom(
            b, policy_bundle_bytes=b"policy-bytes",
            c2pa_manifest_body=other)
        self.assertFalse(ok)
        self.assertIn("does not re-derive", reason)

    def test_verify_leg_rejects_malformed_body(self):
        m = _manifest()
        section = c2pa.bom_c2pa_section(c2pa.manifest_digest(m), 1, [])
        b = bom.build_bom(c2pa_provenance=section, **self._base())
        bad = dict(m)
        del bad["assertions"]
        ok, reason = bom.verify_bom(
            b, policy_bundle_bytes=b"policy-bytes",
            c2pa_manifest_body=bad)
        self.assertFalse(ok)
        self.assertIn("shape check", reason)

    def test_verify_leg_checked_path(self):
        m = _manifest()
        section = c2pa.bom_c2pa_section(c2pa.manifest_digest(m), 1, [])
        b = bom.build_bom(c2pa_provenance=section, **self._base())
        ok, reason = bom.verify_bom(
            b, policy_bundle_bytes=b"policy-bytes",
            c2pa_manifest_body=m)
        self.assertTrue(ok, reason)
        self.assertIn("c2pa-provenance", reason)


class TestDefaultBounds(unittest.TestCase):
    def test_defaults_validate_and_disjoint(self):
        from gov import claim_bounds as cb
        bounds = c2pa.default_manifest_bounds()
        validated = cb.validate_bounds(bounds)
        self.assertEqual(validated, bounds)
        self.assertFalse(set(bounds["proves"])
                         & set(bounds["does_not_prove"]))
        self.assertIn("content-truth", bounds["does_not_prove"])
        self.assertIn("content-safety", bounds["does_not_prove"])
        self.assertIn("content-wisdom", bounds["does_not_prove"])

    def test_supplied_bounds_used_verbatim(self):
        custom = {"proves": ["manifest-integrity"],
                  "does_not_prove": ["content-truth"],
                  "verifier_assumptions": ["a"],
                  "scope_limits": ["s"]}
        m = _manifest(claim_bounds=custom)
        self.assertEqual(m["claim_bounds"]["proves"],
                         ["manifest-integrity"])


if __name__ == "__main__":
    unittest.main()
