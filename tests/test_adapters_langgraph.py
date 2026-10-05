"""Adapter tests: LangGraph interrupt() -> ApprovalQueue recipe.

No model API is ever called and ``langgraph`` is never imported by the
recipe (it is an optional dependency): these tests drive the recipe with
a duck-typed ``interrupt`` stand-in whose contract matches
``langgraph.types.interrupt`` (langgraph 1.2.12 source):

  * first invocation raises (GraphInterrupt) carrying the payload value;
  * a client resumes with ``Command(resume=...)``;
  * the node RE-EXECUTES from the start, and ``interrupt()`` returns the
    resume value instead of raising;
  * a checkpointer is required (not our concern here).

RED-FIRST baseline (passes on the unshimmed base tree): an
interrupt-style human-in-the-loop node whose tool call never touches the
ApprovalQueue executes with zero governance.

The recipe (``gov.adapters.langgraph_hitl.governed_tool_call``) mediates
one tool call inside a LangGraph node:

  * executor "executed"  -> ("executed", result); interrupt NOT called.
  * executor "denied"    -> ToolDeniedError (default); interrupt NOT called.
  * executor "queued"    -> interrupt({"approval_id", ...}) pauses the
    graph; the human decides via the ApprovalQueue; the client resumes
    with Command(resume=...); the node re-enters with
    prior_approval_id=... (no duplicate queue entry) and the recipe
    returns ("approved"|"rejected", record). The deployment then runs
    executor.execute_approved() to execute approved actions.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.adapters.core import (
    GovernedBinding,
    ToolDeniedError,
    UnregisteredToolError,
)


# ---------------------------------------------------------------------------
# Duck-typed stand-in for langgraph.types.interrupt (contract verified
# against langgraph 1.2.12 source, langgraph/types.py).
# ---------------------------------------------------------------------------

class GraphInterrupt(Exception):
    """Stands in for langgraph.graph.GraphInterrupt."""

    def __init__(self, value):
        self.value = value
        super().__init__("graph interrupted: %r" % (value,))


class FakeInterrupt:
    """Mimics interrupt(): first call raises GraphInterrupt(value);
    when armed with a resume value, returns it instead (node re-entry)."""

    def __init__(self):
        self.calls = []
        self._resume = None
        self._armed = False

    def arm_resume(self, resume_value):
        self._resume = resume_value
        self._armed = True

    def __call__(self, value):
        self.calls.append(value)
        if self._armed:
            return self._resume
        raise GraphInterrupt(value)


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _import_recipe():
    from gov.adapters import langgraph_hitl as recipe
    return recipe


# ---------------------------------------------------------------------------
# RED-FIRST baseline: the unshimmed base tree mediates nothing.
# ---------------------------------------------------------------------------

class TestUnshimmedBaseline(unittest.TestCase):
    def test_recipe_module_now_exists(self):
        # RED-phase baseline (base tree) asserted ImportError here: no
        # recipe existed, so interrupt-style HITL nodes ran unmediated.
        # The recipe now exists; the unmediated demonstration below is
        # kept as the documented hole the recipe closes.
        import gov.adapters.langgraph_hitl  # noqa: F401

    def test_unmediated_interrupt_node_executes_without_queue(self):
        # Simulates a LangGraph node that pauses for a human via
        # interrupt() but runs its tool with no governance: the tool
        # executes, and the ApprovalQueue never sees the call.
        ctx = make_run()
        interrupt = FakeInterrupt()
        side_effects = []

        def tool_node(state):
            # Human-in-the-loop pause, then UNMEDIATED tool execution.
            answer = interrupt({"question": "approve write?"})
            if answer.get("approved"):
                side_effects.append(state["path"])
            return {"done": True}

        with self.assertRaises(GraphInterrupt):
            tool_node({"path": "/tmp/unshimmed-lg.txt"})
        interrupt.arm_resume({"approved": True})
        tool_node({"path": "/tmp/unshimmed-lg.txt"})
        self.assertEqual(side_effects, ["/tmp/unshimmed-lg.txt"])
        self.assertEqual(ctx["approvals"].all(), [],
                         "no approval record for the unmediated call")
        self.assertEqual(
            [e for e in ctx["read_log"]()
             if "unshimmed" in e.get("event", "")], [])


# ---------------------------------------------------------------------------
# The recipe (RED until gov.adapters.langgraph_hitl exists).
# ---------------------------------------------------------------------------

class TestGovernedToolCall(unittest.TestCase):
    def test_executed_call_never_interrupts(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        outcome, payload = recipe.governed_tool_call(
            binding, "write_file",
            {"path": "notes.txt", "content": "hello"},
            interrupt=interrupt, queue=ctx["approvals"])
        self.assertEqual(outcome, "executed")
        self.assertEqual(payload["status"], "executed")
        self.assertEqual(interrupt.calls, [],
                         "allowed calls must not pause the graph")
        self.assertTrue(
            (ctx["run_dir"] / "sandbox" / "notes.txt").is_file())

    def test_denied_call_raises_without_interrupting(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)  # coder may not send_email
        interrupt = FakeInterrupt()
        with self.assertRaises(ToolDeniedError):
            recipe.governed_tool_call(
                binding, "send_email",
                {"to": "x@synthetic.local", "subject": "s", "body": "b"},
                interrupt=interrupt, queue=ctx["approvals"])
        self.assertEqual(interrupt.calls, [],
                         "denied calls must not pause the graph")

    def test_denied_call_return_mode(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        outcome, payload = recipe.governed_tool_call(
            binding, "send_email",
            {"to": "x@synthetic.local", "subject": "s", "body": "b"},
            interrupt=interrupt, queue=ctx["approvals"],
            on_denied="return")
        self.assertEqual(outcome, "denied")
        self.assertEqual(payload["status"], "denied")
        self.assertEqual(interrupt.calls, [])

    def test_unregistered_tool_fails_closed(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        with self.assertRaises(UnregisteredToolError):
            recipe.governed_tool_call(
                binding, "drop_database", {"name": "prod"},
                interrupt=interrupt, queue=ctx["approvals"])
        self.assertEqual(interrupt.calls, [])

    def test_non_dict_arguments_fail_closed(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        with self.assertRaises(TypeError):
            recipe.governed_tool_call(
                binding, "write_file", ["not", "a", "dict"],
                interrupt=interrupt, queue=ctx["approvals"])
        self.assertEqual(interrupt.calls, [])

    def test_queued_call_pauses_graph_with_approval_payload(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        with self.assertRaises(GraphInterrupt) as cm:
            recipe.governed_tool_call(
                binding, "write_file",
                {"path": "/tmp/lg-should-not-write.txt", "content": "x"},
                interrupt=interrupt, queue=ctx["approvals"])
        # Exactly one pause, carrying the approval reference.
        self.assertEqual(len(interrupt.calls), 1)
        payload = cm.exception.value
        self.assertTrue(payload.get("sasanam_approval"))
        approval_id = payload.get("approval_id")
        self.assertIsNotNone(approval_id)
        self.assertEqual(payload["framework_tool"], "write_file")
        # The approval is really in OUR queue, pending, unexecuted.
        rec = ctx["approvals"].get(approval_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "pending")
        self.assertFalse(os.path.exists("/tmp/lg-should-not-write.txt"))
        # The interrupt payload is client-channel hygiene: no raw tool
        # arguments are surfaced to the graph client (the human decides
        # in the queue UI, which shows the redacted form).
        self.assertNotIn("content", json_payload_text(payload))

    def test_resume_after_approval_returns_approved(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        args = {"path": "/tmp/lg-approved.txt", "content": "x"}
        with self.assertRaises(GraphInterrupt) as cm:
            recipe.governed_tool_call(
                binding, "write_file", args,
                interrupt=interrupt, queue=ctx["approvals"])
        approval_id = cm.exception.value["approval_id"]
        # Human decides via the ApprovalQueue (the durable record).
        ctx["approvals"].decide(approval_id, True, reason="looks fine",
                               decided_by="human-operator")
        # Client resumes; the node RE-EXECUTES from the start.
        interrupt.arm_resume({"approval_id": approval_id})
        outcome, record = recipe.governed_tool_call(
            binding, "write_file", args,
            interrupt=interrupt, queue=ctx["approvals"],
            prior_approval_id=approval_id)
        self.assertEqual(outcome, "approved")
        self.assertEqual(record["id"], approval_id)
        # No duplicate queue entry was created on re-entry.
        pending = [r for r in ctx["approvals"].all()
                   if r["status"] == "pending"]
        self.assertEqual(pending, [])
        # The deployment executes approved actions via the sweep, which
        # re-validates before executing.
        done = ctx["executor"].execute_approved()
        self.assertTrue(done, "approved action must execute via the sweep")

    def test_resume_after_rejection_returns_rejected(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        args = {"path": "/tmp/lg-rejected.txt", "content": "x"}
        with self.assertRaises(GraphInterrupt) as cm:
            recipe.governed_tool_call(
                binding, "write_file", args,
                interrupt=interrupt, queue=ctx["approvals"])
        approval_id = cm.exception.value["approval_id"]
        ctx["approvals"].decide(approval_id, False, reason="no",
                               decided_by="human-operator")
        interrupt.arm_resume({"approval_id": approval_id})
        outcome, record = recipe.governed_tool_call(
            binding, "write_file", args,
            interrupt=interrupt, queue=ctx["approvals"],
            prior_approval_id=approval_id)
        self.assertEqual(outcome, "rejected")
        self.assertEqual(record["status"], "rejected")
        done = ctx["executor"].execute_approved()
        self.assertEqual(done, [],
                         "rejected actions must never execute")
        self.assertFalse(os.path.exists("/tmp/lg-rejected.txt"))

    def test_resume_with_mismatched_approval_id_fails_closed(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        args = {"path": "/tmp/lg-mismatch.txt", "content": "x"}
        with self.assertRaises(GraphInterrupt) as cm:
            recipe.governed_tool_call(
                binding, "write_file", args,
                interrupt=interrupt, queue=ctx["approvals"])
        approval_id = cm.exception.value["approval_id"]
        ctx["approvals"].decide(approval_id, True, reason="ok",
                               decided_by="human-operator")
        # A resume value naming a DIFFERENT approval must not be honored.
        interrupt.arm_resume({"approval_id": "not-" + approval_id})
        with self.assertRaises(recipe.ApprovalResumeMismatchError):
            recipe.governed_tool_call(
                binding, "write_file", args,
                interrupt=interrupt, queue=ctx["approvals"],
                prior_approval_id=approval_id)

    def test_resume_with_missing_record_fails_closed(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        interrupt.arm_resume({"approval_id": "no-such-approval"})
        with self.assertRaises(recipe.ApprovalRecordMissingError):
            recipe.governed_tool_call(
                binding, "write_file",
                {"path": "/tmp/lg-missing.txt", "content": "x"},
                interrupt=interrupt, queue=ctx["approvals"],
                prior_approval_id="no-such-approval")

    def test_premature_resume_fails_closed(self):
        # The client resumed before any human decided via the queue:
        # the queue is the decision authority, so fail closed rather
        # than guessing from the resume value.
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        args = {"path": "/tmp/lg-premature.txt", "content": "x"}
        with self.assertRaises(GraphInterrupt) as cm:
            recipe.governed_tool_call(
                binding, "write_file", args,
                interrupt=interrupt, queue=ctx["approvals"])
        approval_id = cm.exception.value["approval_id"]
        interrupt.arm_resume({"approved": True})  # tries to smuggle approval
        with self.assertRaises(recipe.ApprovalNotDecidedError):
            recipe.governed_tool_call(
                binding, "write_file", args,
                interrupt=interrupt, queue=ctx["approvals"],
                prior_approval_id=approval_id)
        self.assertFalse(os.path.exists("/tmp/lg-premature.txt"))

    def test_queue_defaults_to_binding_executor_queue(self):
        recipe = _import_recipe()
        ctx = make_run()
        binding = _coder_binding(ctx)
        interrupt = FakeInterrupt()
        with self.assertRaises(GraphInterrupt) as cm:
            recipe.governed_tool_call(
                binding, "write_file",
                {"path": "/tmp/lg-defaultq.txt", "content": "x"},
                interrupt=interrupt)  # no queue= passed
        rec = ctx["approvals"].get(cm.exception.value["approval_id"])
        self.assertIsNotNone(rec)


def json_payload_text(payload):
    import json as _json
    return _json.dumps(payload, sort_keys=True, default=str)


if __name__ == "__main__":
    unittest.main()
