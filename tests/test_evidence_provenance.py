"""Unit tests for gov/evidence_provenance.py.

Covers: builder allowlist enforcement, completeness marking,
unsigned-envelope refusal at the anchor gate, input-digest binding,
artifact-mismatch binding, and graph recording.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import ed25519
from gov import evidence_anchor as ea
from gov import evidence_provenance as ep
from gov import guac_graph as gg


def _builder(bid="build.example.com/ci"):
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    return seed, ep.BuilderPolicy("test-policy", {bid: pub})


def _sealed(seed, bid="build.example.com/ci", keyid="key-1",
            artifact="ab" * 32, materials=None, issued_at=1700000000):
    if materials is None:
        materials = [{"uri": "https://git.example.com/repo",
                      "digest": "cd" * 32, "completeness": "verified"}]
    claim = ep.make_provenance_claim(bid, keyid, artifact, materials,
                                     issued_at=issued_at)
    return ep.seal_provenance(claim, seed)


class TestAllowlist(unittest.TestCase):
    def test_valid_claim_verifies(self):
        seed, policy = _builder()
        env = _sealed(seed)
        self.assertIs(ep.verify_provenance(env, policy), True)

    def test_foreign_builder_refused(self):
        _seed, policy = _builder()
        evil = ed25519.generate_seed()
        env = _sealed(evil, bid="evil.example.com/x", keyid="key-9")
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-builder-untrusted")

    def test_vacuous_policy_refused_at_construction(self):
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.BuilderPolicy("empty", {})
        self.assertEqual(ctx.exception.code,
                         "provenance-builder-untrusted")

    def test_wrong_key_for_pinned_builder_refused(self):
        seed, policy = _builder()
        other = ed25519.generate_seed()  # not the pinned key
        env = _sealed(other)
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-signature-invalid")


class TestCompletenessMarking(unittest.TestCase):
    def test_unmarked_material_refused(self):
        seed, policy = _builder()
        env = _sealed(seed, materials=[{"uri": "u", "digest": "cd" * 32}])
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-material-unmarked")

    def test_unverified_material_refused_by_default(self):
        seed, policy = _builder()
        env = _sealed(seed, materials=[{"uri": "u", "digest": "cd" * 32,
                                        "completeness": "unverified"}])
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-material-unverified")

    def test_unverified_material_honored_on_opt_in(self):
        seed, policy = _builder()
        env = _sealed(seed, materials=[{"uri": "u", "digest": "cd" * 32,
                                        "completeness": "unverified"}])
        self.assertIs(ep.verify_provenance(
            env, policy, allow_unverified_materials=True), True)


class TestSignatureBinding(unittest.TestCase):
    def test_tampered_material_digest_refused(self):
        seed, policy = _builder()
        env = _sealed(seed)
        env["provenance"]["materials"][0]["digest"] = "ee" * 32
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-signature-invalid")

    def test_tampered_artifact_digest_refused(self):
        seed, policy = _builder()
        env = _sealed(seed)
        env["provenance"]["artifact"]["digest"] = "ff" * 32
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-signature-invalid")

    def test_malformed_envelope_refused(self):
        _seed, policy = _builder()
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance({"provenance": {}}, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-envelope-malformed")


class TestAnchorGate(unittest.TestCase):
    def _log(self, tmp):
        root = tempfile.mkdtemp(prefix="w287-unit-")
        seed = ed25519.generate_seed()
        log = ea.TransparencyLog(root, origin="unit-log.example",
                                 signer_keyid="op-1", signer_seed=seed)
        return log, ed25519.publickey(seed)

    def test_missing_provenance_refuses(self):
        seed, policy = _builder()
        log, _pub = self._log(tempfile.mkdtemp())
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.anchor_bundle_gated(log, "ab" * 32, None, policy)
        self.assertEqual(ctx.exception.code, "provenance-missing")

    def test_unsigned_provenance_refuses_at_gate(self):
        seed, policy = _builder()
        env = _sealed(seed)
        env["signature"] = "00" * 64
        log, _pub = self._log(tempfile.mkdtemp())
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.anchor_bundle_gated(log, "ab" * 32, env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-signature-invalid")

    def test_artifact_mismatch_refuses_at_gate(self):
        seed, policy = _builder()
        env = _sealed(seed, artifact="ab" * 32)
        log, _pub = self._log(tempfile.mkdtemp())
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.anchor_bundle_gated(log, "ff" * 32, env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-artifact-mismatch")

    def test_gated_anchor_issues_verifying_receipt(self):
        seed, policy = _builder()
        digest = "ab" * 32
        env = _sealed(seed, artifact=digest)
        log, pub = self._log(tempfile.mkdtemp())
        receipt = ep.anchor_bundle_gated(log, digest, env, policy)
        self.assertEqual(receipt["bundle_digest"], digest)
        self.assertIs(ea.verify_receipt(receipt, pub), True)

    def test_ungated_anchor_unchanged(self):
        log, _pub = self._log(tempfile.mkdtemp())
        receipt = ea.anchor(log, "ab" * 32)
        self.assertEqual(receipt["bundle_digest"], "ab" * 32)

    def test_raising_sink_does_not_break_verification(self):
        # F345: a broken audit sink must never break provenance
        # verification (the timestamp_authority precedent): the sink
        # failure is isolated, never the sink's raw exception type at
        # a public seam.
        seed, policy = _builder()
        env = _sealed(seed)

        def bad_sink(evt):
            raise RuntimeError("sink is down")

        ep.set_emit(bad_sink)
        try:
            self.assertIs(ep.verify_provenance(env, policy), True)
        finally:
            ep.set_emit(None)
        # The raising sink must not leak into subsequent verifications.
        self.assertIs(ep.verify_provenance(env, policy), True)


class TestGraph(unittest.TestCase):
    def test_records_structural_hasslsa(self):
        seed, policy = _builder()
        env = _sealed(seed)
        graph = gg.GuacGraph()
        nodes = ep.record_provenance_in_graph(graph, env, policy)
        want_ev = "evidence:" + ep.claim_digest(env["provenance"])
        self.assertEqual(nodes["evidence_node"], want_ev)
        hits = graph.edges_with(gg.EdgeSpec(kind="HasSLSA"))
        self.assertTrue(any(h[0] == nodes["software_node"]
                            and h[2] == want_ev for h in hits))

    def test_unsigned_never_enters_graph(self):
        seed, policy = _builder()
        env = _sealed(seed)
        env["signature"] = "00" * 64
        graph = gg.GuacGraph()
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.record_provenance_in_graph(graph, env, policy)
        self.assertEqual(ctx.exception.code,
                         "provenance-signature-invalid")
        self.assertEqual(graph.node_ids(), [])


if __name__ == "__main__":
    unittest.main()
