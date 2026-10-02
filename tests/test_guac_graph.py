"""Unit tests for gov/guac_graph.py (wave-284 lane 5, GUAC STEAL)."""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import guac_graph as gg
from gov.signing import Ed25519Signer, Ed25519Verifier


def _keypair(seed_byte):
    s = Ed25519Signer(bytes([seed_byte]) * 32)
    return s, Ed25519Verifier(s.public_key)


class TestOntology(unittest.TestCase):
    def test_node_types_closed(self):
        self.assertEqual(gg.NODE_TYPES,
                         ("evidence", "actor", "software", "artifact"))

    def test_add_node_id_grammars(self):
        g = gg.GuacGraph()
        self.assertEqual(g.add_node("software", "skill-x@1.0"),
                         "software:skill-x@1.0")
        self.assertEqual(g.add_node("evidence", "a" * 64),
                         "evidence:" + "a" * 64)
        self.assertEqual(g.add_node("actor", "b" * 16), "actor:" + "b" * 16)
        with self.assertRaises(gg.GuacGraphError) as ctx:
            g.add_node("software", "no-version-here")
        self.assertEqual(ctx.exception.code, "guac-graph-malformed")
        with self.assertRaises(gg.GuacGraphError):
            g.add_node("package", "x@1.0")

    def test_idempotent_add(self):
        g = gg.GuacGraph()
        a = g.add_node("actor", "c" * 16)
        self.assertEqual(g.add_node("actor", "c" * 16), a)
        self.assertEqual(len(g.node_ids()), 1)


class TestEdges(unittest.TestCase):
    def test_edge_vocabulary_present(self):
        for kind in ("HasSBOM", "HasSLSA", "CertifyVuln", "CertifyBad",
                     "CertifyGood", "IsDependency", "IsOccurrence",
                     "HashEqual", "PkgEqual", "HasSourceAt", "HasMetadata"):
            self.assertIn(kind, gg.EDGE_KINDS)

    def test_shape_check(self):
        g = gg.GuacGraph()
        a = g.add_node("actor", "d" * 16)
        s = g.add_node("software", "skill-x@1.0")
        with self.assertRaises(gg.GuacGraphError) as ctx:
            g.add_edge(a, "IsDependency", s)
        self.assertEqual(ctx.exception.code, "guac-graph-malformed")

    def test_unlinked_refused(self):
        g = gg.GuacGraph()
        s1 = g.add_node("software", "a@1.0")
        with self.assertRaises(gg.GuacGraphError) as ctx:
            g.add_edge(s1, "IsDependency", "software:b@1.0")
        self.assertEqual(ctx.exception.code, "guac-graph-unlinked")

    def test_claim_edges_not_direct(self):
        g = gg.GuacGraph()
        a = g.add_node("actor", "e" * 16)
        s = g.add_node("software", "a@1.0")
        with self.assertRaises(gg.GuacGraphError):
            g.add_edge(a, "CertifyBad", s)


class TestClaims(unittest.TestCase):
    def test_quorum_pending_then_verified(self):
        (s1, v1), (s2, v2) = _keypair(0x61), _keypair(0x62)
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        r1 = g.ingest_envelope(
            gg.seal_claim(s1, "CertifyBad", "evil", subject=sw), [v1, v2])
        self.assertEqual(r1["status"], "pending")
        r2 = g.ingest_envelope(
            gg.seal_claim(s2, "CertifyBad", "evil", subject=sw), [v1, v2])
        self.assertEqual(r2["status"], "verified")
        self.assertEqual(len(r2["actors"]), 2)

    def test_envelope_type_binding(self):
        (s1, v1) = _keypair(0x61)
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        env = gg.seal_claim(s1, "CertifyBad", "evil", subject=sw)
        env["payloadType"] = "application/x-evil"
        with self.assertRaises(gg.GuacGraphError) as ctx:
            g.ingest_envelope(env, [v1])
        self.assertEqual(ctx.exception.code, "guac-graph-envelope-refused")

    def test_threshold_enforced(self):
        (s1, v1), (s2, v2) = _keypair(0x61), _keypair(0x62)
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        env = gg.seal_claim(s1, "CertifyBad", "evil", subject=sw)
        with self.assertRaises(gg.GuacGraphError):
            g.ingest_envelope(env, [v1, v2], threshold=2)

    def test_is_occurrence_args(self):
        (s1, v1), (s2, v2) = _keypair(0x61), _keypair(0x62)
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        art = g.add_node("artifact", "f" * 64)
        for s in (s1, s2):
            rec = g.ingest_envelope(
                gg.seal_claim(s, "IsOccurrence", "seen",
                              software=sw, artifact=art), [v1, v2])
        self.assertEqual(rec["status"], "verified")
        hits = g.edges_with(gg.IsOccurrenceSpec(software=sw))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][:3], (sw, "IsOccurrence", art))

    def test_contested(self):
        (s1, v1), (s2, v2), (s3, v3), (s4, v4) = (
            _keypair(0x61), _keypair(0x62), _keypair(0x63), _keypair(0x64))
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        for s in (s1, s2):
            g.ingest_envelope(
                gg.seal_claim(s, "CertifyBad", "evil", subject=sw),
                [v1, v2, v3, v4])
        for s in (s3, s4):
            g.ingest_envelope(
                gg.seal_claim(s, "CertifyGood", "fine", subject=sw),
                [v1, v2, v3, v4])
        self.assertIn(sw, g.contested())
        with self.assertRaises(gg.GuacGraphError) as ctx:
            g.blast_radius(sw)
        self.assertEqual(ctx.exception.code, "guac-graph-claim-conflict")


class TestBlastRadius(unittest.TestCase):
    def _bad_tree(self):
        (s1, v1), (s2, v2) = _keypair(0x61), _keypair(0x62)
        g = gg.GuacGraph()
        bad = g.add_node("software", "lib-evil@9.9")
        mid = g.add_node("software", "skill-mid@2.0")
        top = g.add_node("software", "agent-top@1.0")
        art = g.add_node("artifact", "c" * 64)
        g.add_edge(mid, "IsDependency", bad)
        g.add_edge(top, "IsDependency", mid)
        for s in (s1, s2):
            g.ingest_envelope(
                gg.seal_claim(s, "CertifyBad", "evil", subject=bad),
                [v1, v2])
            g.ingest_envelope(
                gg.seal_claim(s, "IsOccurrence", "seen",
                              software=bad, artifact=art), [v1, v2])
        return g, bad, mid, top, art

    def test_transitive(self):
        g, bad, mid, top, art = self._bad_tree()
        radius = g.blast_radius(bad)
        self.assertEqual(radius, sorted(radius))
        for node in (bad, mid, top, art):
            self.assertIn(node, radius)

    def test_pending_no_propagation(self):
        (s1, v1) = _keypair(0x61)
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        dep = g.add_node("software", "skill-y@1.0")
        g.add_edge(dep, "IsDependency", sw)
        g.ingest_envelope(
            gg.seal_claim(s1, "CertifyBad", "evil", subject=sw), [v1])
        self.assertEqual(g.blast_radius(sw), [sw])

    def test_unlinked(self):
        g = gg.GuacGraph()
        with self.assertRaises(gg.GuacGraphError) as ctx:
            g.blast_radius("software:nope@0.0")
        self.assertEqual(ctx.exception.code, "guac-graph-unlinked")

    def test_deterministic_digest(self):
        g1, _, _, _, _ = self._bad_tree()
        g2, _, _, _, _ = self._bad_tree()
        self.assertEqual(g1.digest(), g2.digest())
        self.assertEqual(g1.serialize(), g2.serialize())


class TestCodes(unittest.TestCase):
    def test_codes_registered(self):
        for code in ("guac-graph-ambiguous-link", "guac-graph-bad-spec",
                     "guac-graph-claim-conflict",
                     "guac-graph-envelope-refused", "guac-graph-malformed",
                     "guac-graph-overflow", "guac-graph-unlinked"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "guac-graph")


if __name__ == "__main__":
    unittest.main()
