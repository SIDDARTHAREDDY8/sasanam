"""Unit tests for gov/attack_paths.py (wave-282 lane 7, BloodHound ADAPT).

Behavioral contracts only: graph construction, closed vocabularies,
edge composition, BFS shortest paths, cycle safety, waypoint
enforcement, findings determinism, and the audit-log writer chain.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import attack_paths as ap


def _demo_graph():
    g = ap.GrantGraph()
    g.add_node("a1", "agent")
    g.add_node("a2", "agent")
    g.add_node("t1", "tool", labels={"exfil-capable"})
    g.add_node("t2", "tool")
    g.add_edge("a2", "t1", "granted_to")  # no provenance checkpoint
    g.add_edge("a1", "a2", "delegated_by")
    g.add_edge("a1", "t2", "granted_to", provenance_checkpoint=True)
    g.mark_high_value("t1")
    return g


class ConstructionTest(unittest.TestCase):
    def test_nodes_and_edges_register(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent", labels={"low-trust"})
        g.add_node("t", "tool")
        g.add_edge("a", "t", "granted_to", provenance_checkpoint=True)
        self.assertEqual(g.nodes(), ["a", "t"])
        self.assertEqual(g.node("a"), {"kind": "agent",
                                       "labels": ["low-trust"]})
        self.assertEqual(g.edge("a", "t", "granted_to"),
                         {"provenance_checkpoint": True,
                          "approved": False})
        self.assertIsNone(g.node("ghost"))
        self.assertIsNone(g.edge("a", "t", "delegated_by"))

    def test_closed_edge_vocabulary_refused(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent")
        g.add_node("t", "tool")
        with self.assertRaises(ap.AttackPathError) as cm:
            g.add_edge("a", "t", "owns")
        self.assertEqual(cm.exception.code, "attackpath-unknown-edge-type")

    def test_unknown_node_refused(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent")
        with self.assertRaises(ap.AttackPathError) as cm:
            g.add_edge("a", "ghost", "granted_to")
        self.assertEqual(cm.exception.code, "attackpath-unknown-node")
        with self.assertRaises(ap.AttackPathError) as cm2:
            g.mark_high_value("ghost")
        self.assertEqual(cm2.exception.code, "attackpath-unknown-node")

    def test_duplicate_node_refused(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent")
        with self.assertRaises(ap.AttackPathError) as cm:
            g.add_node("a", "user")
        self.assertEqual(cm.exception.code, "attackpath-duplicate-node")

    def test_unknown_node_kind_refused(self):
        g = ap.GrantGraph()
        with self.assertRaises(ap.AttackPathError):
            g.add_node("x", "daemon")
        with self.assertRaises(ap.AttackPathError):
            g.add_node("", "agent")

    def test_refusal_codes_in_expected_set(self):
        self.assertTrue(ap.EXPECTED_CODES.issuperset(
            {"attackpath-unknown-node", "attackpath-unknown-edge-type",
             "attackpath-duplicate-node"}))

    def test_mark_high_value(self):
        g = ap.GrantGraph()
        g.add_node("t", "tool")
        g.mark_high_value("t")
        self.assertEqual(g.high_value_nodes(), ["t"])


class CompositionTest(unittest.TestCase):
    def test_direct_grant(self):
        g = _demo_graph()
        self.assertTrue(ap.can_call(g, "a2", "t1"))

    def test_delegated_chain_composes(self):
        g = _demo_graph()
        self.assertTrue(ap.can_call(g, "a1", "t1"))

    def test_absent_nodes_total(self):
        g = _demo_graph()
        self.assertFalse(ap.can_call(g, "ghost", "t1"))
        self.assertFalse(ap.can_call(g, "a1", "ghost"))
        self.assertFalse(ap.can_call(g, "t1", "a1"))  # reverse: no path

    def test_no_path_false(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent")
        g.add_node("t", "tool")
        self.assertFalse(ap.can_call(g, "a", "t"))


class ShortestPathsTest(unittest.TestCase):
    def test_minimal_path(self):
        g = _demo_graph()
        paths = ap.shortest_paths(g, "a1", "t1")
        self.assertEqual(len(paths), 1)
        self.assertEqual([(s, e, d) for (s, e, d, _a) in paths[0]],
                         [("a1", "delegated_by", "a2"),
                          ("a2", "granted_to", "t1")])

    def test_longer_detour_ignored(self):
        g = _demo_graph()
        g.add_node("a3", "agent")
        g.add_edge("a1", "a3", "delegated_by")
        g.add_edge("a3", "a2", "delegated_by")
        paths = ap.shortest_paths(g, "a1", "t1")
        self.assertTrue(paths)
        self.assertTrue(all(len(p) == 2 for p in paths))

    def test_all_minimal_paths_returned(self):
        g = ap.GrantGraph()
        for nid, kind in (("a", "agent"), ("x", "agent"), ("y", "agent"),
                          ("t", "tool")):
            g.add_node(nid, kind)
        g.add_edge("a", "x", "delegated_by")
        g.add_edge("a", "y", "delegated_by")
        g.add_edge("x", "t", "granted_to")
        g.add_edge("y", "t", "granted_to")
        paths = ap.shortest_paths(g, "a", "t")
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(len(p) == 2 for p in paths))

    def test_cycles_terminate(self):
        g = ap.GrantGraph()
        for nid, kind in (("a1", "agent"), ("a2", "agent"), ("t", "tool")):
            g.add_node(nid, kind)
        g.add_edge("a1", "a2", "delegated_by")
        g.add_edge("a2", "a1", "delegated_by")
        g.add_edge("a2", "t", "granted_to")
        paths = ap.shortest_paths(g, "a1", "t")
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(paths[0]), 2)
        self.assertTrue(ap.can_call(g, "a1", "t"))

    def test_no_path_empty(self):
        g = _demo_graph()
        self.assertEqual(ap.shortest_paths(g, "a1", "ghost"), [])
        g.add_node("iso", "agent")
        self.assertEqual(ap.shortest_paths(g, "iso", "t1"), [])

    def test_self_path(self):
        g = _demo_graph()
        paths = ap.shortest_paths(g, "a1", "a1")
        self.assertEqual(paths, [[]])


class FindingsTest(unittest.TestCase):
    def test_unprovenanced_path_flagged(self):
        g = _demo_graph()
        kinds = [f["finding_kind"] for f in ap.enumerate_findings(g)]
        self.assertIn("unprovenanced-path-to-high-value", kinds)

    def test_checkpointed_path_clean(self):
        g = _demo_graph()
        g.mark_high_value("t2")
        wp = [f for f in ap.enumerate_findings(g)
              if f["finding_kind"] == "unprovenanced-path-to-high-value"
              and f["target"] == "t2"]
        self.assertEqual(wp, [])

    def test_checked_edge_gates_tool(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent")
        g.add_node("t", "tool", labels={"exfil-capable"})
        g.add_node("cp", "checkpoint")
        g.add_edge("a", "t", "granted_to")
        g.add_edge("cp", "t", "checked")
        g.mark_high_value("t")
        wp = [f for f in ap.enumerate_findings(g)
              if f["finding_kind"] == "unprovenanced-path-to-high-value"
              and f["target"] == "t"]
        self.assertEqual(wp, [])

    def test_delegation_cycle_enumerated(self):
        g = ap.GrantGraph()
        for nid, kind in (("a1", "agent"), ("a2", "agent"), ("t", "tool")):
            g.add_node(nid, kind)
        g.add_edge("a1", "a2", "delegated_by")
        g.add_edge("a2", "a1", "delegated_by")
        kinds = [f["finding_kind"] for f in ap.enumerate_findings(g)]
        self.assertIn("delegation-cycle", kinds)

    def test_unapproved_high_value_grant(self):
        g = ap.GrantGraph()
        g.add_node("a", "agent")
        g.add_node("t", "tool", labels={"credential-bearing"})
        g.add_node("appr", "approval")
        g.add_edge("a", "t", "granted_to", provenance_checkpoint=True)
        g.mark_high_value("t")
        kinds = [f["finding_kind"] for f in ap.enumerate_findings(g)]
        self.assertIn("unapproved-high-value-grant", kinds)
        g.add_edge("appr", "t", "approved")
        kinds2 = [f["finding_kind"] for f in ap.enumerate_findings(g)]
        self.assertNotIn("unapproved-high-value-grant", kinds2)

    def test_findings_deterministic(self):
        g = _demo_graph()
        d1 = sorted(f["finding_digest"] for f in ap.enumerate_findings(g))
        d2 = sorted(f["finding_digest"] for f in ap.enumerate_findings(g))
        self.assertEqual(d1, d2)

    def test_finding_shape(self):
        g = _demo_graph()
        findings = ap.enumerate_findings(g)
        self.assertTrue(findings)
        for f in findings:
            for key in ("finding_kind", "source", "target", "path",
                        "missing_waypoints", "finding_digest"):
                self.assertIn(key, f)
            self.assertIn(f["finding_kind"], ap.FINDING_KINDS)
            self.assertEqual(len(f["finding_digest"]), 64)


class WriterChainTest(unittest.TestCase):
    def _log(self, tmp):
        from gov.log import ActionLog
        from tests.keyfixture import provision_test_key
        provision_test_key()
        return ActionLog(os.path.join(tmp, "audit.jsonl"))

    def test_findings_chain_and_verify(self):
        from gov.log import ActionLog  # noqa: F401
        tmp = tempfile.mkdtemp(prefix="g282-ap-ut-")
        log = self._log(tmp)
        w = ap.AttackPathWriter(log)
        findings = ap.enumerate_findings(_demo_graph())
        entries = w.write_findings(findings)
        self.assertEqual(len(entries), len(findings))
        records = ap.attack_path_records(log)
        self.assertEqual(len(records), len(findings))
        self.assertTrue(ap.verify_attack_path_records(records))

    def test_tamper_detected(self):
        tmp = tempfile.mkdtemp(prefix="g282-ap-ut-")
        log = self._log(tmp)
        w = ap.AttackPathWriter(log)
        w.write_findings(ap.enumerate_findings(_demo_graph()))
        records = ap.attack_path_records(log)
        records[0]["finding_kind"] = "forged-kind"
        self.assertFalse(ap.verify_attack_path_records(records))

    def test_reorder_detected(self):
        tmp = tempfile.mkdtemp(prefix="g282-ap-ut-")
        log = self._log(tmp)
        w = ap.AttackPathWriter(log)
        w.write_findings(ap.enumerate_findings(_demo_graph()))
        records = ap.attack_path_records(log)
        self.assertFalse(ap.verify_attack_path_records(list(reversed(records))))

    def test_malformed_finding_refused(self):
        tmp = tempfile.mkdtemp(prefix="g282-ap-ut-")
        log = self._log(tmp)
        w = ap.AttackPathWriter(log)
        with self.assertRaises(ap.AttackPathError):
            w.write_findings([{"finding_kind": "nope"}])

    def test_verify_never_raises(self):
        self.assertFalse(ap.verify_attack_path_records([None]))
        self.assertTrue(ap.verify_attack_path_records([]))


if __name__ == "__main__":
    unittest.main()
