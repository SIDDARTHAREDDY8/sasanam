"""Unit tests for gov/blast_radius.py (row-7 e1, wave-132).

These tests use synthetic events appended through the REAL ActionLog
(real HMAC chain), so chain-verification behavior is exercised, not
mocked. The end-to-end product path (policy, approvals, spawn) is
covered by evals/blast_radius_probes.py.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov.blast_radius import (  # noqa: E402
    AnchorNotFound,
    BlastRadiusUnverifiable,
    analyze_blast_radius,
)
from gov.log import ActionLog  # noqa: E402


class _LogBuilder(object):
    def __init__(self, test):
        self._td = tempfile.TemporaryDirectory(prefix="govblast-ut-")
        test.addCleanup(self._td.cleanup)
        self.path = str(Path(self._td.name) / "actions.jsonl")
        self.log = ActionLog(self.path)

    def append(self, **fields):
        event = {"run_id": "run-1"}
        event.update(fields)
        return self.log.append(event)["seq"]


def _approval(log, approval_id="A-1", agent="worker-1"):
    return log.append(event="approval_decision", approval_id=approval_id,
                      decision="approved", related_agent=agent,
                      agent_id="human-operator", tool="http_post",
                      run_id="run-1")


def _call(log, tool, agent, seq_after=None, **fields):  # noqa: ARG001
    event = {"event": "tool_call", "tool": tool, "agent_id": agent,
             "decision": "approved_executed", "run_id": "run-1", "args": {}}
    event.update(fields)
    return log.append(**event)


class TestAnchorResolution(unittest.TestCase):
    def test_unknown_approval_raises(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        with self.assertRaises(AnchorNotFound):
            analyze_blast_radius("A-nope", log.path)

    def test_unknown_seq_raises(self):
        log = _LogBuilder(self)
        _approval(log)
        with self.assertRaises(AnchorNotFound):
            analyze_blast_radius(9999, log.path)

    def test_invalid_anchor_types_rejected(self):
        log = _LogBuilder(self)
        _approval(log)
        # The anchor is one positional: an approval id (str) or an event
        # seq (int). Anything else is a caller bug -> ValueError.
        for bad in (None, True, False, 1.5, ["A-1"], {"id": "A-1"}):
            with self.assertRaises(ValueError, msg="anchor=%r" % (bad,)):
                analyze_blast_radius(bad, log.path)

    def test_str_anchor_routes_to_approval_and_int_to_seq(self):
        log = _LogBuilder(self)
        aseq = _approval(log, approval_id="A-1", agent="worker-1")
        by_approval = analyze_blast_radius("A-1", log.path)
        by_seq = analyze_blast_radius(aseq, log.path)
        self.assertEqual(by_approval["anchor"]["kind"], "approval")
        self.assertEqual(by_seq["anchor"]["kind"], "event")
        self.assertEqual(by_seq["anchor"]["seq"], aseq)

    def test_action_log_object_accepted_as_audit_log(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1", agent="worker-1")
        report = analyze_blast_radius("A-1", log.log)
        self.assertTrue(report["chain"]["verified"])
        self.assertEqual(report["anchor"]["approval_id"], "A-1")

    def test_denied_decision_is_not_an_anchor(self):
        log = _LogBuilder(self)
        log.append(event="approval_decision", approval_id="A-2",
                   decision="denied", related_agent="worker-1",
                   agent_id="human-operator", run_id="run-1")
        with self.assertRaises(AnchorNotFound):
            analyze_blast_radius("A-2", log.path)

    def test_anchor_block_names_agent_and_seq(self):
        log = _LogBuilder(self)
        aseq = _approval(log, approval_id="A-1", agent="worker-1")
        report = analyze_blast_radius("A-1", log.path)
        self.assertEqual(report["anchor"]["kind"], "approval")
        self.assertEqual(report["anchor"]["seq"], aseq)
        self.assertEqual(report["anchor"]["agent_id"], "worker-1")
        self.assertEqual(report["anchor"]["approval_id"], "A-1")
        self.assertTrue(report["chain"]["verified"])


class TestFailClosed(unittest.TestCase):
    def test_deleted_middle_entry_raises(self):
        log = _LogBuilder(self)
        aseq = _approval(log)
        _call(log, "http_post", "worker-1", approval_id="A-1",
              args={"url": "https://example.invalid/x"})
        _call(log, "write_file", "worker-1", args={"path": "a.txt"})
        lines = Path(log.path).read_text(encoding="utf-8").splitlines()
        tampered = Path(log.path).with_name("tampered.jsonl")
        tampered.write_text("\n".join(lines[:aseq] + lines[aseq + 1:]) + "\n",
                            encoding="utf-8")
        with self.assertRaises(BlastRadiusUnverifiable):
            analyze_blast_radius("A-1", str(tampered))

    def test_truncated_tail_raises(self):
        log = _LogBuilder(self)
        _approval(log)
        _call(log, "http_post", "worker-1", approval_id="A-1",
              args={"url": "https://example.invalid/x"})
        lines = Path(log.path).read_text(encoding="utf-8").splitlines()
        tampered = Path(log.path).with_name("truncated.jsonl")
        tampered.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        with self.assertRaises(BlastRadiusUnverifiable):
            analyze_blast_radius("A-1", str(tampered))


class TestEdges(unittest.TestCase):
    def test_approval_consumption_is_strong(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        cseq = _call(log, "http_post", "worker-1", approval_id="A-1",
                     args={"url": "https://example.invalid/x"})
        report = analyze_blast_radius("A-1", log.path)
        node = {n["seq"]: n for n in report["nodes"]}[cseq]
        self.assertEqual(node["edge_kind"], "approval_consumption")
        self.assertEqual(node["strength"], "strong")

    def test_authorized_execution_edge(self):
        log = _LogBuilder(self)
        aseq = _approval(log, approval_id="A-1")
        cseq = _call(log, "http_post", "worker-1",
                     authorization_seq=aseq,
                     args={"url": "https://example.invalid/x"})
        report = analyze_blast_radius("A-1", log.path)
        node = {n["seq"]: n for n in report["nodes"]}[cseq]
        self.assertEqual(node["edge_kind"], "authorized_execution")
        self.assertEqual(node["strength"], "strong")

    def test_data_flow_path_upgrades_lineage(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        _call(log, "write_file", "worker-1", approval_id="A-1",
              args={"path": "staged.txt"})
        rseq = _call(log, "read_file", "worker-1",
                     args={"path": "staged.txt"})
        report = analyze_blast_radius("A-1", log.path)
        node = {n["seq"]: n for n in report["nodes"]}[rseq]
        self.assertEqual(node["edge_kind"], "data_flow_path")
        self.assertEqual(node["strength"], "strong")

    def test_spawn_and_child_action(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        sseq = log.append(event="agent_spawn", agent_id="worker-1",
                          sub_agent_id="child-1", run_id="run-1")
        cseq = _call(log, "http_post", "child-1",
                     args={"url": "https://example.invalid/c"})
        report = analyze_blast_radius("A-1", log.path)
        by_seq = {n["seq"]: n for n in report["nodes"]}
        self.assertEqual(by_seq[sseq]["edge_kind"], "spawn")
        self.assertEqual(by_seq[cseq]["edge_kind"], "child_action")
        self.assertEqual(by_seq[cseq]["strength"], "strong")
        self.assertIn("child-1", report["agents_involved"])
        # The DAG links the child action to the spawn event.
        kinds = {(e["from"], e["to"]): e["kind"] for e in report["edges"]}
        self.assertEqual(kinds[(sseq, cseq)], "child_action")

    def test_unrelated_agent_excluded(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        _call(log, "http_post", "worker-1", approval_id="A-1",
              args={"url": "https://example.invalid/x"})
        other = _call(log, "http_post", "other-1",
                      args={"url": "https://example.invalid/o"})
        report = analyze_blast_radius("A-1", log.path)
        seqs = {n["seq"] for n in report["nodes"]}
        self.assertNotIn(other, seqs)
        self.assertNotIn("other-1", report["agents_involved"])

    def test_agent_lineage_medium_and_opt_out(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        wseq = _call(log, "write_file", "worker-1",
                     args={"path": "notes.txt"})
        report = analyze_blast_radius("A-1", log.path)
        node = {n["seq"]: n for n in report["nodes"]}[wseq]
        self.assertEqual(node["edge_kind"], "agent_lineage")
        self.assertEqual(node["strength"], "medium")
        slim = analyze_blast_radius("A-1", log.path,
                                    include_medium=False)
        self.assertNotIn(wseq, {n["seq"] for n in slim["nodes"]})

    def test_content_carry_medium(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        rseq = _call(log, "read_file", "worker-1",
                     args={"path": "secret.txt"})
        pseq = log.append(
            event="tool_call", tool="http_post", agent_id="worker-1",
            decision="approved_executed", run_id="run-1",
            args={"url": "https://example.invalid/x"},
            policy_context={"carries_read_content": True})
        report = analyze_blast_radius("A-1", log.path)
        by_seq = {n["seq"]: n for n in report["nodes"]}
        self.assertEqual(by_seq[pseq]["edge_kind"], "content_carry")
        self.assertEqual(by_seq[pseq]["strength"], "medium")
        kinds = {(e["from"], e["to"]): e["kind"] for e in report["edges"]}
        self.assertEqual(kinds[(rseq, pseq)], "content_carry")

    def test_upstream_actions_excluded(self):
        log = _LogBuilder(self)
        before = _call(log, "write_file", "worker-1",
                       args={"path": "early.txt"})
        _approval(log, approval_id="A-1")
        report = analyze_blast_radius("A-1", log.path)
        self.assertNotIn(before, {n["seq"] for n in report["nodes"]})


class TestViews(unittest.TestCase):
    def _scenario(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        _call(log, "http_post", "worker-1", approval_id="A-1",
              args={"url": "https://example.invalid/x"})
        _call(log, "write_file", "worker-1", args={"path": "staged.txt"})
        log.append(event="agent_spawn", agent_id="worker-1",
                   sub_agent_id="child-1", run_id="run-1")
        _call(log, "send_email", "child-1",
              args={"to": "ops@example.invalid"})
        return log

    def test_external_effects(self):
        report = analyze_blast_radius("A-1", self._scenario().path)
        dests = {fx["destination"] for fx in report["external_effects"]}
        self.assertIn("https://example.invalid/x", dests)
        self.assertIn("ops@example.invalid", dests)

    def test_data_touched(self):
        report = analyze_blast_radius("A-1", self._scenario().path)
        touched = {(d["path"], d["operation"]) for d in report["data_touched"]}
        self.assertIn(("staged.txt", "write"), touched)

    def test_containment_checklist(self):
        report = analyze_blast_radius("A-1", self._scenario().path)
        blob = "\n".join(report["containment_checklist"])
        self.assertIn("A-1", blob)
        self.assertIn("child-1", blob)
        self.assertIn("https://example.invalid/x", blob)
        self.assertIn("staged.txt", blob)
        self.assertTrue(report["honest_ceiling"])

    def test_counts(self):
        report = analyze_blast_radius("A-1", self._scenario().path)
        counts = report["counts"]
        self.assertEqual(counts["total"],
                         counts["strong"] + counts["medium"])
        self.assertGreater(counts["strong"], 0)

    def test_empty_downstream(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-9")
        report = analyze_blast_radius("A-9", log.path)
        self.assertEqual(report["nodes"], [])
        self.assertEqual(report["counts"]["total"], 0)
        # The checklist still covers the anchor itself.
        blob = "\n".join(report["containment_checklist"])
        self.assertIn("A-9", blob)
        self.assertIn("worker-1", blob)

    def test_run_id_scoping(self):
        log2 = _LogBuilder(self)
        _approval(log2, approval_id="A-1")
        log2.append(event="tool_call", tool="http_post", agent_id="worker-1",
                    decision="approved_executed", run_id="run-2",
                    approval_id="A-1",
                    args={"url": "https://example.invalid/x"})
        scoped = analyze_blast_radius("A-1", log2.path,
                                      run_id="run-1")
        self.assertEqual(scoped["nodes"], [])
        unscoped = analyze_blast_radius("A-1", log2.path)
        self.assertEqual(len(unscoped["nodes"]), 1)


class TestRootsAndNaming(unittest.TestCase):
    def test_queued_attempt_is_dag_root(self):
        # One approval's three audit stages: the queued attempt predates
        # the decision but is still the approval's subject and must be
        # reported as the DAG root.
        log = _LogBuilder(self)
        qseq = log.append(event="tool_call", tool="http_post",
                          agent_id="worker-1", decision="queued_pending",
                          approval_id="A-1", run_id="run-1",
                          args={"url": "https://example.invalid/x"})
        aseq = _approval(log, approval_id="A-1", agent="worker-1")
        xseq = _call(log, "http_post", "worker-1", approval_id="A-1",
                     args={"url": "https://example.invalid/x"})
        report = analyze_blast_radius("A-1", log.path)
        by_seq = {n["seq"]: n for n in report["affected_actions"]}
        self.assertIn(qseq, by_seq)
        self.assertEqual(by_seq[qseq]["edge_kind"], "approval_consumption")
        self.assertEqual(by_seq[qseq]["strength"], "strong")
        kinds = {(e["from"], e["to"]): e["kind"] for e in report["edges"]}
        self.assertEqual(kinds[(aseq, qseq)], "approval_consumption")
        self.assertIn(xseq, by_seq)
        # The queued attempt never executed: not data touched.
        self.assertNotIn(qseq, {d["seq"] for d in report["data_touched"]})

    def test_event_anchor_is_dag_root(self):
        log = _LogBuilder(self)
        wseq = _call(log, "write_file", "worker-1",
                     args={"path": "staged.txt"})
        rseq = _call(log, "read_file", "worker-1",
                     args={"path": "staged.txt"})
        report = analyze_blast_radius(wseq, log.path)
        by_seq = {n["seq"]: n for n in report["affected_actions"]}
        self.assertEqual(by_seq[wseq]["edge_kind"], "anchor")
        self.assertEqual(by_seq[wseq]["strength"], "strong")
        # The anchor's own write is data touched...
        touched = {(d["seq"], d["path"], d["operation"])
                   for d in report["data_touched"]}
        self.assertIn((wseq, "staged.txt", "write"), touched)
        # ...and the later read links back to the anchor via data flow.
        self.assertEqual(by_seq[rseq]["edge_kind"], "data_flow_path")
        kinds = {(e["from"], e["to"]): e["kind"] for e in report["edges"]}
        self.assertEqual(kinds[(wseq, rseq)], "data_flow_path")

    def test_affected_actions_is_public_name(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        _call(log, "http_post", "worker-1", approval_id="A-1",
              args={"url": "https://example.invalid/x"})
        report = analyze_blast_radius("A-1", log.path)
        self.assertIs(report["affected_actions"], report["nodes"])
        self.assertEqual(len(report["affected_actions"]), 1)

    def test_grandchild_spawn_lineage(self):
        # Nested spawns attribute each generation to its own spawn event.
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        s1 = log.append(event="agent_spawn", agent_id="worker-1",
                        sub_agent_id="child-1", run_id="run-1")
        s2 = log.append(event="agent_spawn", agent_id="child-1",
                        sub_agent_id="grandchild-1", run_id="run-1")
        gseq = _call(log, "http_post", "grandchild-1",
                     args={"url": "https://example.invalid/g"})
        report = analyze_blast_radius("A-1", log.path)
        by_seq = {n["seq"]: n for n in report["affected_actions"]}
        self.assertEqual(by_seq[gseq]["edge_kind"], "child_action")
        kinds = {(e["from"], e["to"]): e["kind"] for e in report["edges"]}
        self.assertEqual(kinds[(s2, gseq)], "child_action")
        self.assertIn("grandchild-1", report["agents_involved"])

    def test_containment_covers_delegation_revocation(self):
        log = _LogBuilder(self)
        _approval(log, approval_id="A-1")
        report = analyze_blast_radius("A-1", log.path)
        blob = "\n".join(report["containment_checklist"])
        self.assertIn("Revok", blob)
        self.assertIn("delegation", blob)
        self.assertIn("worker-1", blob)


if __name__ == "__main__":
    unittest.main()
