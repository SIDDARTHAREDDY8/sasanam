"""Regression tests for the wave-292 lane-6 uncoded-exception sweep.

F357: seal_provenance refuses a non-dict claim["builder"] coded
      (provenance-envelope-malformed), not a bare AttributeError.
F358: check_rebuild_recipe refuses a non-sequence material_uris coded
      (provenance-rebuild-invalid), not a bare TypeError.
F359: digest_of refuses a non-serializable body coded
      (delegation-malformed), not a bare TypeError.
"""

import unittest

from gov import delegation_chain as dc
from gov import evidence_provenance as ep


def _code_of(exc):
    return getattr(exc, "code", None)


class SweepRegressionTest(unittest.TestCase):
    # F357
    def test_seal_builder_none_coded(self):
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.seal_provenance({"builder": None}, bytes(32))
        self.assertEqual(_code_of(ctx.exception),
                         "provenance-envelope-malformed")

    def test_seal_builder_str_coded(self):
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.seal_provenance({"builder": "x"}, bytes(32))
        self.assertEqual(_code_of(ctx.exception),
                         "provenance-envelope-malformed")

    def test_seal_builder_list_coded(self):
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.seal_provenance({"builder": []}, bytes(32))
        self.assertEqual(_code_of(ctx.exception),
                         "provenance-envelope-malformed")

    def test_seal_builder_dict_still_works(self):
        env = ep.seal_provenance(
            {"builder": {"id": "b1", "keyid": "k1"}}, bytes(32))
        self.assertEqual(env["keyid"], "k1")
        self.assertEqual(len(env["signature"]), 128)

    # F358
    def test_recipe_uris_int_coded(self):
        recipe = {"recipe_format": "sasanam-rebuild/1",
                  "inputs": ["u1"], "steps": [{"op": "sha256"}]}
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, 5)
        self.assertEqual(_code_of(ctx.exception),
                         "provenance-rebuild-invalid")

    def test_recipe_uris_unhashable_coded(self):
        recipe = {"recipe_format": "sasanam-rebuild/1",
                  "inputs": ["u1"], "steps": [{"op": "sha256"}]}
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, [{"u": "1"}])
        self.assertEqual(_code_of(ctx.exception),
                         "provenance-rebuild-invalid")

    def test_recipe_uris_none_still_allowed(self):
        recipe = {"recipe_format": "sasanam-rebuild/1",
                  "inputs": ["u1"], "steps": [{"op": "sha256"}]}
        # None material_uris: every input is undeclared -> invalid, coded.
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, None)
        self.assertEqual(_code_of(ctx.exception),
                         "provenance-rebuild-invalid")

    def test_recipe_valid_still_passes(self):
        recipe = {"recipe_format": "sasanam-rebuild/1",
                  "inputs": ["u1"], "steps": [{"op": "sha256"}]}
        self.assertTrue(ep.check_rebuild_recipe(recipe, ["u1"]))

    # F359
    def test_digest_of_nonserializable_coded(self):
        with self.assertRaises(dc.DelegationMalformed) as ctx:
            dc.digest_of({"a": object()})
        self.assertEqual(_code_of(ctx.exception), "delegation-malformed")

    def test_digest_of_serializable_still_works(self):
        d = dc.digest_of({"a": 1})
        self.assertEqual(len(d), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in d))


if __name__ == "__main__":
    unittest.main()
