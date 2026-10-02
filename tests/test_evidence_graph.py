"""Unit tests for gov/evidence_graph.py (wave-250 lane 4).

The evidence graph projects already-verified artifacts (skill
admissions, offline bundles, decision packets, policy revisions) into
one traversable auditor view. GUAC-adapted: identifier linking fails
closed on ambiguity instead of guessing.
"""

import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes as dc
from gov import ed25519
from gov import evidence_graph as eg
from gov import skill_admission


def _keys():
    auth_seed = b"\x11" * 32
    step_seed = b"\x22" * 32
    return (auth_seed, step_seed,
            ed25519.publickey(auth_seed).hex(),
            ed25519.publickey(step_seed).hex())


def _admit():
    auth_seed, step_seed, auth_pub, step_pub = _keys()
    rules = [("REQUIRE", "skill-src.zip"),
             ("MATCH", "skill.tar.gz", "ab" * 32),
             ("DISALLOW",)]
    layout = skill_admission.make_layout(
        "layout-unit-1",
        [{"name": "build", "command": ["make", "bundle"],
          "signer_pub": step_pub, "rules": rules}],
        auth_seed)
    link = skill_admission.make_link(
        "layout-unit-1", "build", ["make", "bundle"],
        {"skill-src.zip": "ab" * 32}, {"skill.tar.gz": "ab" * 32},
        step_seed)
    verdict = skill_admission.admit(layout, [link], auth_pub)
    assert verdict["admitted"] is True, verdict
    return verdict, auth_pub


class TaxonomyPinTest(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-250 lane 4: re-pointed to 983 (979 + 4 evidence-graph
        # codes), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1493)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        for code in ("evidence-graph-ambiguous-link",
                     "evidence-graph-malformed",
                     "evidence-graph-overflow",
                     "evidence-graph-unlinked"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["code"], code)
            self.assertEqual(dc.TAXONOMY[code]["domain"],
                             "evidence-graph")


class GraphBasicsTest(unittest.TestCase):
    def test_add_node_round_trip(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill", {"layout_id": "s1"})
        self.assertEqual(g.node_count(), 1)
        self.assertIn("skill:s1", g.traverse("skill:s1"))

    def test_add_node_idempotent(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill", {"a": 1})
        g.add_node("skill:s1", "skill", {"b": 2})
        self.assertEqual(g.node_count(), 1)

    def test_add_node_rejects_unknown_type(self):
        g = eg.EvidenceGraph()
        with self.assertRaises(eg.GraphMalformed) as ctx:
            g.add_node("widget:w1", "widget")
        self.assertEqual(ctx.exception.code,
                         "evidence-graph-malformed")

    def test_add_node_rejects_type_mismatch(self):
        g = eg.EvidenceGraph()
        with self.assertRaises(eg.GraphMalformed):
            g.add_node("skill:s1", "bundle")

    def test_add_node_rejects_bad_id(self):
        g = eg.EvidenceGraph()
        for bad in ("no-colon", "skill:", 42, None):
            with self.assertRaises(eg.GraphMalformed):
                g.add_node(bad, "skill")

    def test_add_node_rejects_non_dict_attrs(self):
        g = eg.EvidenceGraph()
        with self.assertRaises(eg.GraphMalformed):
            g.add_node("skill:s1", "skill", attrs=[("a", 1)])

    def test_add_identity_convenience(self):
        g = eg.EvidenceGraph()
        g.add_identity("identity:agent-1")
        self.assertIn("identity:agent-1", g.traverse("identity:agent-1"))

    def test_add_edge_and_idempotence(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        g.add_identity("identity:auth")
        g.add_edge("skill:s1", "identity:auth", "admitted_by")
        g.add_edge("skill:s1", "identity:auth", "admitted_by")
        self.assertEqual(g.edge_count(), 1)

    def test_add_edge_rejects_missing_endpoint(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        with self.assertRaises(eg.GraphMalformed):
            g.add_edge("skill:s1", "identity:ghost", "admitted_by")

    def test_add_edge_rejects_unknown_kind(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        g.add_node("skill:s2", "skill")
        with self.assertRaises(eg.GraphMalformed) as ctx:
            g.add_edge("skill:s1", "skill:s2", "maybe_related")
        self.assertEqual(ctx.exception.code,
                         "evidence-graph-malformed")

    def test_overflow_nodes(self):
        g = eg.EvidenceGraph(max_nodes=2, max_edges=100)
        g.add_node("skill:s1", "skill")
        g.add_node("skill:s2", "skill")
        with self.assertRaises(eg.GraphOverflow) as ctx:
            g.add_node("skill:s3", "skill")
        self.assertEqual(ctx.exception.code, "evidence-graph-overflow")

    def test_overflow_edges(self):
        g = eg.EvidenceGraph(max_nodes=100, max_edges=1)
        g.add_node("skill:s1", "skill")
        g.add_node("skill:s2", "skill")
        g.add_identity("identity:a")
        g.add_edge("skill:s1", "identity:a", "admitted_by")
        with self.assertRaises(eg.GraphOverflow) as ctx:
            g.add_edge("skill:s2", "identity:a", "admitted_by")
        self.assertEqual(ctx.exception.code, "evidence-graph-overflow")

    def test_bad_bounds_rejected(self):
        with self.assertRaises(eg.GraphMalformed):
            eg.EvidenceGraph(max_nodes=0)


class LinkFailClosedTest(unittest.TestCase):
    def test_link_exact(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        g.add_identity("identity:agent-1")
        g.link("skill:s1", "identity:agent-1", "produced_by")
        self.assertIn("identity:agent-1", g.traverse("skill:s1"))

    def test_link_ambiguous_refused(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        g.add_identity("identity:agent-alpha")
        g.add_identity("identity:agent-alpine")
        with self.assertRaises(eg.AmbiguousLink) as ctx:
            g.link("skill:s1", "identity:agent-al", "produced_by")
        self.assertEqual(ctx.exception.code,
                         "evidence-graph-ambiguous-link")
        # no edge was smuggled in
        self.assertEqual(g.edge_count(), 0)

    def test_link_unlinked_refused(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        with self.assertRaises(eg.Unlinked) as ctx:
            g.link("skill:s1", "identity:ghost", "produced_by")
        self.assertEqual(ctx.exception.code, "evidence-graph-unlinked")

    def test_link_malformed_selector(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        with self.assertRaises(eg.GraphMalformed):
            g.link("skill:s1", "", "produced_by")


class QueryTest(unittest.TestCase):
    def _web(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill")
        g.add_identity("identity:auth")
        g.add_edge("skill:s1", "identity:auth", "admitted_by")
        g.add_node("decision:d1", "decision")
        g.add_edge("decision:d1", "identity:auth", "decided_by")
        g.add_edge("decision:d1", "skill:s1", "produced_by")
        g.add_node("bundle:b1", "bundle")
        g.add_edge("decision:d1", "bundle:b1", "sealed_in")
        return g

    def test_traverse_connected_set(self):
        g = self._web()
        reached = g.traverse("skill:s1")
        self.assertEqual(sorted(reached),
                         ["bundle:b1", "decision:d1", "identity:auth",
                          "skill:s1"])

    def test_traverse_edge_kind_filter(self):
        g = self._web()
        reached = g.traverse("skill:s1", edge_kinds=("admitted_by",))
        self.assertEqual(reached, ["identity:auth", "skill:s1"])

    def test_traverse_rejects_bad_kind(self):
        g = self._web()
        with self.assertRaises(eg.GraphMalformed):
            g.traverse("skill:s1", edge_kinds=("vibes",))

    def test_traverse_unknown_node(self):
        g = self._web()
        with self.assertRaises(eg.GraphMalformed):
            g.traverse("skill:ghost")

    def test_provenance_reaches_admission(self):
        g = self._web()
        paths = g.provenance("decision:d1")
        flat = [n for p in paths for n in p]
        self.assertIn("identity:auth", flat)
        self.assertIn("skill:s1", flat)
        self.assertIn("bundle:b1", flat)
        for path in paths:
            self.assertEqual(path[0], "decision:d1")
        self.assertEqual(paths, sorted(paths))

    def test_blast_radius_forward_dependents(self):
        g = self._web()
        radius = g.blast_radius("skill:s1")
        self.assertIn("decision:d1", radius)
        self.assertIn("bundle:b1", radius)
        self.assertIn("skill:s1", radius)
        # the admission authority is upstream, not a dependent
        self.assertNotIn("identity:auth", radius)

    def test_module_level_query_functions(self):
        g = self._web()
        self.assertEqual(eg.traverse(g, "skill:s1"), g.traverse("skill:s1"))
        self.assertEqual(eg.provenance(g, "decision:d1"),
                         g.provenance("decision:d1"))
        self.assertEqual(eg.blast_radius(g, "skill:s1"),
                         g.blast_radius("skill:s1"))


class DeterminismTest(unittest.TestCase):
    def test_digest_stable_and_order_independent(self):
        def build(order):
            g = eg.EvidenceGraph()
            nodes = [("skill:s1", "skill"), ("skill:s2", "skill"),
                     ("identity:a", "identity")]
            edges = [("skill:s1", "identity:a", "admitted_by"),
                     ("skill:s2", "identity:a", "admitted_by")]
            if order:
                nodes.reverse()
                edges.reverse()
            for nid, ntype in nodes:
                g.add_node(nid, ntype)
            for src, dst, kind in edges:
                g.add_edge(src, dst, kind)
            return g.digest()
        d1, d2 = build(False), build(True)
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)
        int(d1, 16)  # lowercase hex

    def test_serialize_canonical(self):
        g = eg.EvidenceGraph()
        g.add_node("skill:s1", "skill", {"b": 2, "a": 1})
        raw = g.serialize()
        parsed = json.loads(raw.decode("utf-8"))
        self.assertEqual(parsed["nodes"]["skill:s1"]["attrs"],
                         {"a": 1, "b": 2})
        self.assertEqual(raw, json.dumps(
            parsed, sort_keys=True,
            separators=(",", ":")).encode("utf-8"))


class ProjectionTest(unittest.TestCase):
    def test_project_admission(self):
        verdict, auth_pub = _admit()
        g = eg.EvidenceGraph()
        skill = eg.project_admission(g, verdict, authority_id=auth_pub)
        self.assertEqual(skill, "skill:layout-unit-1")
        reached = g.traverse(skill)
        self.assertIn("identity:" + auth_pub, reached)

    def test_project_admission_refuses_refused_verdict(self):
        g = eg.EvidenceGraph()
        with self.assertRaises(eg.GraphMalformed):
            eg.project_admission(g, {"admitted": False}, authority_id="x")

    def test_project_bundle_manifest(self):
        g = eg.EvidenceGraph()
        manifest = {"bundle_id": "b-1", "ledger_digest": "ab" * 32,
                    "entries": [{"seq": 1, "digest": "01" * 32},
                                {"seq": 2, "digest": "02" * 32}]}
        bundle = eg.project_bundle_manifest(g, manifest)
        self.assertEqual(bundle, "bundle:b-1")
        reached = g.traverse(bundle)
        self.assertIn("record:" + "01" * 32, reached)
        self.assertIn("record:" + "02" * 32, reached)

    def test_project_decision_packet(self):
        g = eg.EvidenceGraph()
        packet = {"decision": "allow", "policy_id": "pol-1", "seq": 3}
        node = eg.project_decision_packet(
            g, packet, identity_id="agent-9", skill_id="layout-unit-1")
        self.assertTrue(node.startswith("decision:"))
        reached = g.traverse(node)
        self.assertIn("identity:agent-9", reached)
        self.assertIn("skill:layout-unit-1", reached)
        # decision digest excludes the signature envelope
        sig = dict(packet)
        sig["signature"] = "00" * 64
        node2 = eg.EvidenceGraph()
        n2 = eg.project_decision_packet(
            node2, sig, identity_id="agent-9", skill_id="layout-unit-1")
        self.assertEqual(node, n2)

    def test_project_policy_revision_supersedes(self):
        g = eg.EvidenceGraph()
        new = eg.project_policy_revision(g, "r2", supersedes="r1")
        self.assertEqual(new, "policy_revision:r2")
        paths = g.provenance("policy_revision:r2")
        flat = [n for p in paths for n in p]
        self.assertIn("policy_revision:r1", flat)

    def test_project_revocation(self):
        g = eg.EvidenceGraph()
        eg.project_revocation(g, "root", "identity:agent-9")
        radius = g.blast_radius("identity:agent-9")
        self.assertIn("identity:root", radius)

    def test_end_to_end_auditor_story(self):
        verdict, auth_pub = _admit()
        g = eg.EvidenceGraph()
        eg.project_admission(g, verdict, authority_id=auth_pub)
        decision = eg.project_decision_packet(
            g, {"decision": "allow", "skill_id": "layout-unit-1"},
            identity_id="agent-9", skill_id="layout-unit-1")
        eg.project_bundle_manifest(
            g, {"bundle_id": "b-9", "entries": []},
            record_nodes=[decision])
        # one walk from the skill answers the auditor's question
        reached = g.traverse("skill:layout-unit-1")
        self.assertIn(decision, reached)
        self.assertIn("bundle:b-9", reached)
        self.assertIn("identity:" + auth_pub, reached)


if __name__ == "__main__":
    unittest.main()
