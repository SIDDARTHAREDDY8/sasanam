"""Wave-317: unit tests for the provenance-segment producer wiring.

Tests the producer helper (_build_provenance_segments) and the
queue() stamping contract: origin grading, content-derived segment
ids, explicit-None-when-no-context, seal verifiability, and the
MAC-bound record field.
"""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tests.keyfixture as kf
from tests.harness import make_run
from gov import provenance_labels as PL
from gov.log import read_entries


class ProducerWiringTest(unittest.TestCase):
    def setUp(self):
        self._restore = kf.scrub_key_env()
        kf.provision_test_key()
        self.addCleanup(self._restore)
        self.ctx = make_run()
        self.ex = self.ctx["executor"]
        self.ident = self.ex.mint_identity("a1", "support", "org")

    def test_user_turn_grades_at_user(self):
        self.ex.set_intent_context(["do the thing"])
        segs = self.ex._build_provenance_segments(None, self.ident)
        self.assertEqual(len(segs), 1)
        seg = PL.Segment.from_dict(segs[0])
        self.assertEqual(seg.label.origin, "user")
        self.assertEqual(seg.label.trust_level, 100)
        self.assertTrue(PL.verify_label(seg.label, seg.content))

    def test_justification_grades_at_tool(self):
        self.ex.set_intent_context(None)
        segs = self.ex._build_provenance_segments(
            "doing the thing", self.ident)
        self.assertEqual(len(segs), 1)
        seg = PL.Segment.from_dict(segs[0])
        self.assertEqual(seg.label.origin, "tool")
        self.assertEqual(seg.label.trust_level, 50)
        self.assertEqual(seg.label.principal, "a1")
        self.assertTrue(PL.verify_label(seg.label, seg.content))

    def test_no_context_returns_none(self):
        self.ex.set_intent_context(None)
        self.assertIsNone(
            self.ex._build_provenance_segments(None, self.ident))
        self.assertIsNone(
            self.ex._build_provenance_segments("   ", self.ident))

    def test_segment_ids_deterministic(self):
        self.ex.set_intent_context(["do the thing"])
        a = self.ex._build_provenance_segments("why", self.ident)
        b = self.ex._build_provenance_segments("why", self.ident)
        self.assertEqual([s["segment_id"] for s in a],
                         [s["segment_id"] for s in b])
        self.assertTrue(all(i.startswith("pv-") for i in
                            [s["segment_id"] for s in a]))

    def test_segment_ids_differ_by_content(self):
        self.ex.set_intent_context(["do the thing"])
        a = self.ex._build_provenance_segments("why", self.ident)
        self.ex.set_intent_context(["do the other thing"])
        b = self.ex._build_provenance_segments("why", self.ident)
        ids_a = sorted(s["segment_id"] for s in a)
        ids_b = sorted(s["segment_id"] for s in b)
        self.assertNotEqual(ids_a, ids_b)

    def test_queue_stamps_segments_mac_bound(self):
        import gov.approvals as ap
        self.assertIn("provenance_segments", ap._SECURITY_PAYLOAD_FIELDS)
        segs = self.ex._build_provenance_segments("why", self.ident)
        q = self.ctx["approvals"]
        aid = q.queue(
            {"tool": "read_file", "args": {}, "identity": {}},
            _decision("allow"), "agent_direct", "preview",
            caller_identity=self.ident,
            provenance_segments=segs)
        rec = q.get(aid)
        self.assertEqual(rec["provenance_segments"], segs)
        self.assertTrue(ap.approval_digest_ok(rec))

    def test_queue_defaults_to_explicit_none(self):
        q = self.ctx["approvals"]
        aid = q.queue(
            {"tool": "read_file", "args": {}, "identity": {}},
            _decision("allow"), "agent_direct", "preview",
            caller_identity=self.ident)
        rec = q.get(aid)
        self.assertIn("provenance_segments", rec)
        self.assertIsNone(rec["provenance_segments"])

    def test_producer_never_raises(self):
        # A broken labeler degrades to None, never to an exception
        # that would break queueing.
        self.ex.set_intent_context(["do the thing"])
        orig = PL.issue_label
        try:
            PL.issue_label = None
            self.assertIsNone(
                self.ex._build_provenance_segments("why", self.ident))
        finally:
            PL.issue_label = orig

    def test_producer_degradation_is_audit_visible(self):
        # A producer failure must not silently return the sink to
        # dormancy: the degradation emits a structured audit event.
        self.ex.set_intent_context(["do the thing"])
        orig = PL.issue_label
        try:
            PL.issue_label = None
            self.assertIsNone(
                self.ex._build_provenance_segments("why", self.ident))
        finally:
            PL.issue_label = orig
        events = [e for e in read_entries(self.ex.log.path)
                  if isinstance(e, dict)
                  and e.get("event") == "provenance_producer_degraded"]
        self.assertTrue(events,
                        "no provenance_producer_degraded audit event")


def _decision(effect):
    from gov.policy import PolicyDecision
    return PolicyDecision(effect, "test", policy_id="test",
                          flag="t")


if __name__ == "__main__":
    unittest.main()
