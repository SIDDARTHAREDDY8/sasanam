"""Unit tests for re-derivation receipts (wave-290 lane 6).

gov/evidence_provenance.py: optional ``rebuild_recipe`` in provenance
claims, ``verify_rebuild`` / ``rebuild_receipt``, strict-policy
re-derivation demand in ``verify_provenance`` and
``anchor_bundle_gated``. Stdlib only, synthetic keys, no network.
"""

import hashlib
import unittest

from gov import ed25519
from gov import evidence_provenance as ep


_MATS = {
    "material/a": b"A" * 32,
    "material/b": b"B" * 48,
}
_BID = "build.example.com/ci"
_KEYID = "key-1"


def _policy(rebuild_required=()):
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    return seed, ep.BuilderPolicy("auditor-pin-1", {_BID: pub},
                                  rebuild_required=rebuild_required)


def _materials():
    return [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
             "completeness": "verified"} for u, b in _MATS.items()]


def _recipe(order=("material/a", "material/b")):
    return {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["material/a", "material/b"],
        "steps": [{"op": "concat", "order": list(order)},
                  {"op": "sha256"}],
    }


def _sealed(seed, recipe=_recipe(), tamper=None):
    order = recipe["steps"][0]["order"]
    artifact = hashlib.sha256(b"".join(_MATS[u] for u in order)).hexdigest()
    claim = ep.make_provenance_claim(_BID, _KEYID, artifact, _materials(),
                                     issued_at=1700000000,
                                     rebuild_recipe=recipe)
    env = ep.seal_provenance(claim, seed)
    if tamper is not None:
        tamper(env)
    return env, artifact


class TestRecipeValidation(unittest.TestCase):
    def test_valid_recipe_accepted(self):
        self.assertIs(ep.check_rebuild_recipe(_recipe(),
                                              list(_MATS)), True)

    def test_non_dict_recipe_invalid(self):
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe("nope", list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_wrong_recipe_format_invalid(self):
        recipe = _recipe()
        recipe["recipe_format"] = "sasanam-rebuild/2"
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_undeclared_input_invalid(self):
        recipe = _recipe()
        recipe["inputs"] = ["material/a", "material/ghost"]
        recipe["steps"][0]["order"] = ["material/a", "material/ghost"]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_duplicate_inputs_invalid(self):
        recipe = _recipe()
        recipe["inputs"] = ["material/a", "material/a"]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_unknown_transform_coded(self):
        recipe = _recipe()
        recipe["steps"] = [{"op": "eval"}, {"op": "sha256"}]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-transform-unknown")

    def test_missing_terminal_hash_invalid(self):
        recipe = _recipe()
        recipe["steps"] = [{"op": "concat", "order": ["material/a"]},
                           {"op": "hex"}]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_extra_step_keys_invalid(self):
        recipe = _recipe()
        recipe["steps"][0]["extra"] = "junk"
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_oversized_header_invalid(self):
        recipe = _recipe()
        recipe["steps"] = [
            {"op": "concat", "order": ["material/a"]},
            {"op": "prefix",
             "bytes": "ff" * (ep.MAX_REBUILD_HEADER_BYTES + 1)},
            {"op": "sha256"}]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_too_many_steps_invalid(self):
        recipe = _recipe()
        recipe["steps"] = [{"op": "hex"}] * (ep.MAX_REBUILD_STEPS + 1) + \
            [{"op": "sha256"}]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_slice_bounds_invalid(self):
        recipe = _recipe()
        recipe["steps"] = [
            {"op": "concat", "order": ["material/a"]},
            {"op": "slice", "offset": -1, "length": 4},
            {"op": "sha256"}]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.check_rebuild_recipe(recipe, list(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_make_claim_registers_recipe(self):
        seed, policy = _policy()
        env, artifact = _sealed(seed)
        self.assertIn("rebuild_recipe", env["provenance"])
        self.assertIs(ep.verify_provenance(env, policy,
                                           require_rebuild=True,
                                           material_bytes=dict(_MATS)),
                      True)

    def test_make_claim_refuses_bad_recipe(self):
        seed, _pol = _policy()
        evil = _recipe()
        evil["steps"][0]["order"] = ["material/ghost"]
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.make_provenance_claim(_BID, _KEYID, "ab" * 32, _materials(),
                                     rebuild_recipe=evil)
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_recipe_inside_signed_bytes(self):
        seed, policy = _policy()
        env, _artifact = _sealed(
            seed,
            tamper=lambda e: e["provenance"].__setitem__(
                "rebuild_recipe", _recipe(order=("material/b",
                                                 "material/a"))))
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_rebuild(env, policy, dict(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-signature-invalid")


class TestRebuildExecution(unittest.TestCase):
    def test_happy_path(self):
        seed, policy = _policy()
        env, artifact = _sealed(seed)
        self.assertEqual(ep.verify_rebuild(env, policy, dict(_MATS)),
                         artifact)

    def test_order_matters(self):
        seed, policy = _policy()
        env, _artifact = _sealed(seed, recipe=_recipe(
            order=("material/b", "material/a")))
        want = hashlib.sha256(_MATS["material/b"] +
                              _MATS["material/a"]).hexdigest()
        self.assertEqual(env["provenance"]["artifact"]["digest"], want)
        self.assertEqual(ep.verify_rebuild(env, policy, dict(_MATS)), want)

    def test_digest_mismatch_critical(self):
        seed, policy = _policy()
        env, _artifact = _sealed(seed)
        tampered = dict(_MATS)
        tampered["material/a"] = b"X" * 32
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_rebuild(env, policy, tampered)
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-mismatch")
        from gov import decision_codes as dc
        self.assertEqual(dc.TAXONOMY["provenance-rebuild-mismatch"]
                         ["severity"], "critical")

    def test_missing_material_bytes_invalid(self):
        seed, policy = _policy()
        env, _artifact = _sealed(seed)
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_rebuild(env, policy, {"material/a": _MATS["material/a"]})
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_no_recipe_missing_code(self):
        seed, policy = _policy()
        claim = ep.make_provenance_claim(_BID, _KEYID, "ab" * 32,
                                         _materials(), issued_at=1700000000)
        env = ep.seal_provenance(claim, seed)
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_rebuild(env, policy, dict(_MATS))
        self.assertEqual(ctx.exception.code, "provenance-rebuild-missing")

    def test_slice_execution_bounds(self):
        seed, policy = _policy()
        recipe = {
            "recipe_format": "sasanam-rebuild/1",
            "inputs": ["material/a"],
            "steps": [{"op": "concat", "order": ["material/a"]},
                      {"op": "slice", "offset": 0, "length": 8},
                      {"op": "sha256"}],
        }
        artifact = hashlib.sha256(_MATS["material/a"][:8]).hexdigest()
        claim = ep.make_provenance_claim(_BID, _KEYID, artifact,
                                         _materials(), issued_at=1700000000,
                                         rebuild_recipe=recipe)
        env = ep.seal_provenance(claim, seed)
        self.assertEqual(ep.verify_rebuild(env, policy, dict(_MATS)),
                         artifact)

    def test_slice_past_buffer_invalid(self):
        seed, policy = _policy()
        recipe = {
            "recipe_format": "sasanam-rebuild/1",
            "inputs": ["material/a"],
            "steps": [{"op": "concat", "order": ["material/a"]},
                      {"op": "slice", "offset": 1000, "length": 8},
                      {"op": "sha256"}],
        }
        env, _artifact = _sealed(seed, recipe=recipe)
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_rebuild(env, policy, dict(_MATS))
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")

    def test_input_budget_enforced(self):
        seed, policy = _policy()
        env, _artifact = _sealed(seed)
        old = ep.MAX_REBUILD_INPUT_BYTES
        ep.MAX_REBUILD_INPUT_BYTES = 16
        try:
            with self.assertRaises(ep.ProvenanceError) as ctx:
                ep.verify_rebuild(env, policy, dict(_MATS))
        finally:
            ep.MAX_REBUILD_INPUT_BYTES = old
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-invalid")


class TestStrictPolicy(unittest.TestCase):
    def test_require_rebuild_kwarg_missing(self):
        seed, policy = _policy()
        claim = ep.make_provenance_claim(_BID, _KEYID, "ab" * 32,
                                         _materials(), issued_at=1700000000)
        env = ep.seal_provenance(claim, seed)
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy, require_rebuild=True,
                                 material_bytes=dict(_MATS))
        self.assertEqual(ctx.exception.code, "provenance-rebuild-missing")

    def test_policy_rebuild_required_missing(self):
        seed, policy = _policy(rebuild_required=[_BID])
        claim = ep.make_provenance_claim(_BID, _KEYID, "ab" * 32,
                                         _materials(), issued_at=1700000000)
        env = ep.seal_provenance(claim, seed)
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code, "provenance-rebuild-missing")

    def test_policy_rebuild_required_satisfied(self):
        seed, policy = _policy(rebuild_required=[_BID])
        env, _artifact = _sealed(seed)
        self.assertIs(ep.verify_provenance(env, policy,
                                           material_bytes=dict(_MATS)),
                      True)

    def test_policy_rebuild_required_unknown_builder(self):
        seed, pub = None, None
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(seed).hex()
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.BuilderPolicy("p-1", {_BID: pub},
                             rebuild_required=["ghost.example.com/x"])
        self.assertEqual(ctx.exception.code,
                         "provenance-envelope-malformed")

    def test_rebuild_optional_by_default(self):
        seed, policy = _policy()
        claim = ep.make_provenance_claim(_BID, _KEYID, "ab" * 32,
                                         _materials(), issued_at=1700000000)
        env = ep.seal_provenance(claim, seed)
        self.assertIs(ep.verify_provenance(env, policy), True)


class TestRebuildReceipt(unittest.TestCase):
    def test_receipt_shape(self):
        seed, policy = _policy()
        env, artifact = _sealed(seed)
        receipt = ep.rebuild_receipt(env, policy, dict(_MATS))
        self.assertEqual(receipt["scheme_id"], "provenance-rebuild/v1")
        self.assertEqual(receipt["claim_digest"],
                         ep.claim_digest(env["provenance"]))
        end = receipt["endorsement"]
        self.assertEqual(end["builder_id"], _BID)
        self.assertEqual(end["builder_policy"], "auditor-pin-1")
        self.assertEqual(end["artifact_digest"], artifact)
        self.assertEqual(end["derived_digest"], artifact)
        self.assertRegex(end["recipe_digest"], r"^[0-9a-f]{64}$")

    def test_receipt_mismatch_refuses(self):
        seed, policy = _policy()
        env, _artifact = _sealed(seed)
        tampered = dict(_MATS)
        tampered["material/b"] = b"Y" * 48
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.rebuild_receipt(env, policy, tampered)
        self.assertEqual(ctx.exception.code,
                         "provenance-rebuild-mismatch")


class TestTaxonomy(unittest.TestCase):
    def test_codes_mapped(self):
        from gov import decision_codes as dc
        for code in ("provenance-rebuild-invalid",
                     "provenance-rebuild-mismatch",
                     "provenance-rebuild-missing",
                     "provenance-rebuild-transform-unknown"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "evidence-provenance")

    def test_pin(self):
        from gov import decision_codes as dc
        self.assertEqual(len(dc.TAXONOMY), 1934)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(len(set(dc.TAXONOMY)), 1934)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(sorted(dc.TAXONOMY), list(dc.TAXONOMY))


if __name__ == "__main__":
    unittest.main()
