"""Unit tests for gov/bom_queries.py (wave-214 lane B).

The blast-radius query layer: DecisionGraph builder, the pinned
edge-allowlist (usingOnly discipline), the three headline revocation
queries, the generic reachable() traversal, and the evidence report
binding. The allowlist digest below is a regression PIN: any
accidental change to the allowlist (a new edge kind, a rename, a
version bump) changes the digest and breaks this pin loudly -- an
allowlist widening must be a deliberate, reviewed, versioned act, not
a silent diff.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import bom_queries as bq
from gov import decision_bom

#: Regression pin for ALLOWLIST_VERSION=1, computed from the pinned
#: edge set (see gov/bom_queries.py). Deliberately a literal, not
#: recomputed: the pin must be able to disagree with the code.
PINNED_ALLOWLIST_DIGEST = (
    "208f5a02fa34080efdd173279664282a1461002d4bb19fc8823772e6ef5316f1")

PINNED_EDGE_LIST = [
    "artifact/attested-by",
    "artifact/derived-from",
    "decision/attested-by",
    "decision/consumed-verdict",
    "decision/emitted",
    "decision/used-builder",
    "promotion/admitted-verdict",
    "promotion/promoted-decision",
]


def _graph():
    g = bq.DecisionGraph()
    g.add_node("decision", "dec:001", {"label": "deploy approval"})
    g.add_node("decision", "dec:002", {"label": "config change"})
    g.add_node("builder", "builder:revoked-x", {"revoked": True})
    g.add_node("builder", "builder:live-y", {"revoked": False})
    g.add_node("key", "key:k1", {})
    g.add_node("artifact", "art:a1", {})
    g.add_node("artifact", "art:a2", {})
    g.add_node("scan_verdict", "verdict:v1", {})
    g.add_node("promotion", "promo:p1", {})
    g.add_node("promotion", "promo:p2", {})
    g.add_edge("dec:001", "builder:revoked-x", "decision/used-builder")
    g.add_edge("dec:002", "builder:live-y", "decision/used-builder")
    g.add_edge("dec:001", "key:k1", "decision/attested-by")
    g.add_edge("dec:001", "art:a1", "decision/emitted")
    g.add_edge("art:a1", "key:k1", "artifact/attested-by")
    g.add_edge("dec:002", "art:a2", "decision/emitted")
    g.add_edge("dec:001", "verdict:v1", "decision/consumed-verdict")
    g.add_edge("promo:p1", "dec:001", "promotion/promoted-decision")
    g.add_edge("promo:p2", "dec:002", "promotion/promoted-decision")
    g.add_edge("promo:p1", "verdict:v1", "promotion/admitted-verdict")
    return g


class AllowlistPinTests(unittest.TestCase):
    def test_digest_pin(self):
        self.assertEqual(bq.allowlist_digest(), PINNED_ALLOWLIST_DIGEST)

    def test_edge_list_pin(self):
        self.assertEqual(bq.list_edge_kinds(), PINNED_EDGE_LIST)

    def test_allowlist_is_frozen(self):
        self.assertIsInstance(bq.ALLOWLIST, frozenset)
        with self.assertRaises(AttributeError):
            bq.ALLOWLIST.add("smuggle/edge")  # frozenset has no add

    def test_pin_allowlist_accepts_current(self):
        self.assertTrue(bq.pin_allowlist(PINNED_ALLOWLIST_DIGEST))

    def test_pin_allowlist_rejects_wrong(self):
        with self.assertRaises(bq.GraphError):
            bq.pin_allowlist("0" * 64)
        with self.assertRaises(bq.GraphError):
            bq.pin_allowlist("not-hex")

    def test_defaults_are_allowlist_subsets(self):
        for name, using in bq.DEFAULT_USING_EDGES.items():
            for edge in using:
                self.assertIn(edge, bq.ALLOWLIST,
                              "%s default edge %r not allowlisted"
                              % (name, edge))
        self.assertEqual(set(bq.DEFAULT_USING_EDGES),
                         {"decisions_using_builder",
                          "artifacts_emitted_under_key",
                          "promotions_depending_on_verdict"})


class BuilderDisciplineTests(unittest.TestCase):
    def test_add_node_unknown_kind(self):
        g = bq.DecisionGraph()
        with self.assertRaises(bq.GraphError):
            g.add_node("smuggle", "x:1", {})

    def test_add_node_bad_id(self):
        g = bq.DecisionGraph()
        with self.assertRaises(bq.GraphError):
            g.add_node("decision", "", {})
        with self.assertRaises(bq.GraphError):
            g.add_node("decision", 5, {})

    def test_add_node_duplicate_id(self):
        g = bq.DecisionGraph()
        g.add_node("decision", "d:1", {})
        with self.assertRaises(bq.GraphError):
            g.add_node("artifact", "d:1", {})

    def test_add_edge_non_allowlisted_kind_refused(self):
        g = _graph()
        with self.assertRaises(bq.GraphError):
            g.add_edge("dec:001", "art:a2", "smuggle/edge")

    def test_add_edge_dangling_refused(self):
        g = _graph()
        with self.assertRaises(bq.GraphError):
            g.add_edge("dec:001", "ghost:x", "decision/emitted")
        with self.assertRaises(bq.GraphError):
            g.add_edge("ghost:x", "art:a1", "decision/emitted")

    def test_node_views(self):
        g = _graph()
        self.assertEqual(g.node_kind("dec:001"), "decision")
        self.assertIsNone(g.node_kind("ghost:x"))
        self.assertEqual(g.node_attrs("builder:revoked-x"),
                         {"revoked": True})
        self.assertIsNone(g.node_attrs("ghost:x"))
        self.assertEqual(g.node_ids("decision"), ["dec:001", "dec:002"])
        with self.assertRaises(bq.GraphError):
            g.node_ids("smuggle")


class TraversalDisciplineTests(unittest.TestCase):
    def test_reachable_escape_refused(self):
        g = _graph()
        with self.assertRaises(bq.QueryError):
            bq.reachable(g, "dec:001",
                         using_edges=("decision/emitted", "smuggle/x"))
        # No using_edges at all is also refused (explicit declaration
        # is mandatory, never a default walk).
        with self.assertRaises(bq.QueryError):
            bq.reachable(g, "dec:001", using_edges=None)

    def test_reachable_basic(self):
        g = _graph()
        got = bq.reachable(g, "dec:001",
                           using_edges=("decision/emitted",
                                        "decision/attested-by"))
        self.assertEqual(got, ["art:a1", "key:k1"])

    def test_reachable_excludes_start(self):
        g = _graph()
        got = bq.reachable(g, "dec:001",
                           using_edges=("decision/emitted",))
        self.assertNotIn("dec:001", got)

    def test_reachable_cycle_terminates(self):
        g = bq.DecisionGraph()
        g.add_node("decision", "d1", {})
        g.add_node("artifact", "a1", {})
        g.add_node("decision", "d2", {})
        g.add_edge("d1", "a1", "decision/emitted")
        g.add_edge("a1", "d2", "artifact/derived-from")
        g.add_edge("d2", "a1", "decision/emitted")
        got = bq.reachable(g, "d1",
                           using_edges=("decision/emitted",
                                        "artifact/derived-from"))
        self.assertEqual(got, ["a1", "d2"])
        # The undeclared edge kind is never walked, even mid-cycle.
        got2 = bq.reachable(g, "d1", using_edges=("decision/emitted",))
        self.assertEqual(got2, ["a1"])

    def test_reachable_missing_node_empty(self):
        g = _graph()
        self.assertEqual(bq.reachable(g, "ghost:x",
                                     using_edges=("decision/emitted",)),
                         [])

    def test_reachable_deterministic(self):
        g = _graph()
        edges = ("decision/emitted", "artifact/attested-by",
                 "decision/used-builder")
        self.assertEqual(bq.reachable(g, "dec:001", using_edges=edges),
                         bq.reachable(g, "dec:001", using_edges=edges))

    def test_neighbors_honors_using_edges(self):
        g = _graph()
        nb = g.neighbors("dec:001",
                         using_edges=("decision/emitted",))
        self.assertEqual(nb, [("decision/emitted", "art:a1")])
        self.assertEqual(g.neighbors("ghost:x",
                                     using_edges=("decision/emitted",)),
                         [])
        with self.assertRaises(bq.QueryError):
            g.neighbors("dec:001", using_edges=("smuggle/x",))


class HeadlineQueryTests(unittest.TestCase):
    def test_decisions_using_revoked_builder(self):
        g = _graph()
        self.assertEqual(
            bq.decisions_using_builder(g, "builder:revoked-x"),
            ["dec:001"])

    def test_live_builder_yields_empty_under_revoked_query(self):
        g = _graph()
        self.assertEqual(
            bq.decisions_using_builder(g, "builder:live-y"), [])

    def test_live_builder_listed_when_opted_in(self):
        g = _graph()
        self.assertEqual(
            bq.decisions_using_builder(g, "builder:live-y",
                                       require_revoked=False),
            ["dec:002"])

    def test_unknown_builder_empty(self):
        g = _graph()
        self.assertEqual(
            bq.decisions_using_builder(g, "builder:ghost"), [])
        # Wrong-kind node id is not a builder -> empty, not an error.
        self.assertEqual(
            bq.decisions_using_builder(g, "dec:001"), [])

    def test_revoked_attr_must_be_true(self):
        g = bq.DecisionGraph()
        g.add_node("decision", "d:1", {})
        g.add_node("builder", "b:1", {"revoked": "yes"})  # not True
        g.add_edge("d:1", "b:1", "decision/used-builder")
        self.assertEqual(bq.decisions_using_builder(g, "b:1"), [])
        self.assertEqual(
            bq.decisions_using_builder(g, "b:1",
                                       require_revoked=False), ["d:1"])

    def test_artifacts_emitted_under_key(self):
        g = _graph()
        self.assertEqual(
            bq.artifacts_emitted_under_key(g, "key:k1"), ["art:a1"])

    def test_artifacts_under_unknown_key_empty(self):
        g = _graph()
        self.assertEqual(
            bq.artifacts_emitted_under_key(g, "key:ghost"), [])

    def test_artifact_direct_attestation_path(self):
        g = bq.DecisionGraph()
        g.add_node("decision", "d:1", {})
        g.add_node("key", "k:9", {})
        g.add_node("artifact", "a:9", {})
        g.add_edge("a:9", "k:9", "artifact/attested-by")
        self.assertEqual(
            bq.artifacts_emitted_under_key(g, "k:9"), ["a:9"])

    def test_attestation_requires_attested_by_kind(self):
        # Regression: a non-attestation edge pointed at the key must
        # never count as attestation, however the caller declares
        # using_edges. The attestation edge KIND is pinned.
        g = bq.DecisionGraph()
        g.add_node("decision", "d:1", {})
        g.add_node("key", "k:1", {})
        g.add_node("artifact", "a:1", {})
        g.add_edge("d:1", "a:1", "decision/emitted")
        g.add_edge("d:1", "k:1", "decision/consumed-verdict")
        got = bq.artifacts_emitted_under_key(
            g, "k:1",
            using_edges=("decision/emitted", "decision/consumed-verdict"))
        self.assertEqual(got, [])

    def test_promotions_depending_on_verdict(self):
        g = _graph()
        # promo:p1 both directly admitted verdict:v1 and promoted the
        # decision that consumed it; reported once.
        self.assertEqual(
            bq.promotions_depending_on_verdict(g, "verdict:v1"),
            ["promo:p1"])

    def test_two_hop_only(self):
        g = bq.DecisionGraph()
        g.add_node("scan_verdict", "v:1", {})
        g.add_node("decision", "d:1", {})
        g.add_node("promotion", "p:1", {})
        g.add_edge("d:1", "v:1", "decision/consumed-verdict")
        g.add_edge("p:1", "d:1", "promotion/promoted-decision")
        self.assertEqual(
            bq.promotions_depending_on_verdict(g, "v:1"), ["p:1"])

    def test_unknown_verdict_empty(self):
        g = _graph()
        self.assertEqual(
            bq.promotions_depending_on_verdict(g, "verdict:ghost"), [])

    def test_query_escape_refused_at_headlines(self):
        g = _graph()
        with self.assertRaises(bq.QueryError):
            bq.decisions_using_builder(g, "builder:revoked-x",
                                       using_edges=("smuggle/x",))
        with self.assertRaises(bq.QueryError):
            bq.artifacts_emitted_under_key(g, "key:k1",
                                            using_edges=("smuggle/x",))
        with self.assertRaises(bq.QueryError):
            bq.promotions_depending_on_verdict(g, "verdict:v1",
                                               using_edges=("smuggle/x",))


class ReportTests(unittest.TestCase):
    def test_report_shape_and_pin(self):
        g = _graph()
        rep = bq.query_report(g, "decisions_using_builder",
                              {"builder_id": "builder:revoked-x"})
        self.assertEqual(rep["query"], "decisions_using_builder")
        self.assertEqual(rep["results"], ["dec:001"])
        self.assertEqual(rep["allowlist_digest"], PINNED_ALLOWLIST_DIGEST)
        self.assertEqual(rep["allowlist_version"], 1)
        self.assertEqual(rep["using_edges"],
                         list(bq.DEFAULT_USING_EDGES
                              ["decisions_using_builder"]))

    def test_report_deterministic(self):
        g = _graph()
        r1 = bq.query_report(g, "promotions_depending_on_verdict",
                             {"verdict_id": "verdict:v1"})
        r2 = bq.query_report(g, "promotions_depending_on_verdict",
                             {"verdict_id": "verdict:v1"})
        self.assertEqual(r1, r2)
        self.assertEqual(bq.report_digest(r1), bq.report_digest(r2))

    def test_report_digest_binds_results(self):
        g = _graph()
        r1 = bq.query_report(g, "decisions_using_builder",
                             {"builder_id": "builder:revoked-x"})
        r2 = bq.query_report(g, "decisions_using_builder",
                             {"builder_id": "builder:live-y"})
        self.assertNotEqual(bq.report_digest(r1), bq.report_digest(r2))

    def test_unknown_query_refused(self):
        g = _graph()
        with self.assertRaises(bq.QueryError):
            bq.query_report(g, "smuggle_query", {})

    def test_missing_required_param_refused(self):
        # A digest-bound report must never silently exonerate on a
        # misspelled param key: missing keys raise, unknown ids still
        # yield [] (the missing-node honest boundary).
        g = _graph()
        with self.assertRaises(bq.QueryError):
            bq.query_report(g, "decisions_using_builder",
                            {"builder_idx": "builder:revoked-x"})
        with self.assertRaises(bq.QueryError):
            bq.query_report(g, "artifacts_emitted_under_key", {})
        with self.assertRaises(bq.QueryError):
            bq.query_report(g, "promotions_depending_on_verdict", {})


class BomBridgeTests(unittest.TestCase):
    def _bom(self):
        return decision_bom.build_bom(
            policy_id="pol", policy_version="1",
            policy_digest="a" * 64,
            evidence_head_digest="head-1",
            principal={"agent_id": "a", "role": "r",
                       "principal": "p", "run_id": "run"})

    def test_add_decision_bom(self):
        g = bq.DecisionGraph()
        g.add_node("builder", "builder:b1", {"revoked": True})
        g.add_node("key", "key:k2", {})
        g.add_node("scan_verdict", "verdict:v2", {})
        bom = self._bom()
        decision_id = bq.add_decision_bom(
            g, bom, builder_id="builder:b1",
            signing_key_ids=["key:k2"],
            scan_verdict_ids=["verdict:v2"])
        self.assertEqual(decision_id,
                         "decision:" + decision_bom.bom_digest(bom))
        self.assertEqual(
            bq.decisions_using_builder(g, "builder:b1"), [decision_id])
        self.assertEqual(
            bq.artifacts_emitted_under_key(g, "key:k2"), [])
        self.assertEqual(
            bq.promotions_depending_on_verdict(g, "verdict:v2"), [])

    def test_add_decision_bom_dangling_refused(self):
        g = bq.DecisionGraph()
        with self.assertRaises(bq.GraphError):
            bq.add_decision_bom(g, self._bom(),
                                builder_id="builder:ghost")

    def test_add_decision_bom_malformed_refused(self):
        g = bq.DecisionGraph()
        with self.assertRaises(bq.GraphError):
            bq.add_decision_bom(g, {"not": "a bom"})

    def test_add_decision_bom_emitted_artifacts(self):
        # The bridge can answer question (2): artifacts the BOM's
        # decision emitted, bound to the signing key.
        g = bq.DecisionGraph()
        g.add_node("key", "key:k3", {})
        g.add_node("artifact", "art:out", {})
        decision_id = bq.add_decision_bom(
            g, self._bom(), signing_key_ids=["key:k3"],
            emitted_artifact_ids=["art:out"])
        self.assertEqual(
            bq.artifacts_emitted_under_key(g, "key:k3"), ["art:out"])
        self.assertEqual(g.node_kind(decision_id), "decision")


class AllowlistSignatureTests(unittest.TestCase):
    SEED = b"\x01" * 32
    OTHER_SEED = b"\x02" * 32

    def _signer(self, seed=SEED):
        from gov.signing import Ed25519Signer
        return Ed25519Signer(seed)

    def _verifier(self, seed=SEED):
        from gov.signing import Ed25519Verifier
        return Ed25519Verifier(self._signer(seed).public_key)

    def test_record_shape(self):
        rec = bq.allowlist_record()
        self.assertEqual(rec["version"], bq.ALLOWLIST_VERSION)
        self.assertEqual(rec["edges"], bq.list_edge_kinds())
        self.assertEqual(rec["digest"], PINNED_ALLOWLIST_DIGEST)

    def test_sign_verify_roundtrip(self):
        signed = bq.sign_allowlist(self._signer())
        self.assertEqual(signed["key_id"], self._signer().key_id)
        self.assertEqual(len(signed["signature"]), 128)
        rec = bq.verify_allowlist_signature(self._verifier(), signed)
        self.assertEqual(rec, bq.allowlist_record())

    def test_signature_deterministic(self):
        # Ed25519 signatures are deterministic: the signed allowlist
        # is stable across runs (reproducibility evidence).
        self.assertEqual(bq.sign_allowlist(self._signer()),
                         bq.sign_allowlist(self._signer()))

    def test_tampered_record_refused(self):
        signed = bq.sign_allowlist(self._signer())
        tampered = {"record": dict(signed["record"]),
                    "key_id": signed["key_id"],
                    "signature": signed["signature"]}
        tampered["record"]["edges"] = (signed["record"]["edges"]
                                       + ["smuggle/x"])
        with self.assertRaises(bq.GraphError):
            bq.verify_allowlist_signature(self._verifier(), tampered)

    def test_key_swap_refused(self):
        signed = bq.sign_allowlist(self._signer())
        with self.assertRaises(bq.GraphError):
            bq.verify_allowlist_signature(
                self._verifier(self.OTHER_SEED), signed)

    def test_forged_signature_refused(self):
        signed = bq.sign_allowlist(self._signer())
        forged = dict(signed)
        forged["signature"] = "ab" * 64
        with self.assertRaises(bq.GraphError):
            bq.verify_allowlist_signature(self._verifier(), forged)

    def test_malformed_envelope_refused(self):
        with self.assertRaises(bq.GraphError):
            bq.verify_allowlist_signature(self._verifier(),
                                          {"not": "an envelope"})


if __name__ == "__main__":
    unittest.main()
