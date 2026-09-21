"""Adapter tests: OpenAI-style function-call message loop.

No model API is ever called: `respond` is a scripted stub. Covers the
happy path, strict tool_call validation (malformed JSON, non-object
args, missing/duplicate ids, non-function types), fail-closed dispatch
of unknown tools, denial handling in raise vs return modes, and the
max-iterations runaway guard.
"""

import json
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.adapters.core import (
    AdapterError,
    GovernedBinding,
    MalformedToolCallError,
    ToolDeniedError,
    UnregisteredToolError,
)
from gov.adapters.openai_loop import (
    ParsedToolCall,
    parse_tool_calls,
    run_tool_loop,
)


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _assistant_tool_call(call_id, name, arguments):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": arguments},
        }],
    }


class TestParseToolCalls(unittest.TestCase):
    def test_valid_call_parsed(self):
        msg = _assistant_tool_call(
            "call_1", "write_file",
            json.dumps({"path": "a.txt", "content": "x"}))
        parsed = parse_tool_calls(msg)
        self.assertEqual(parsed, [ParsedToolCall(
            "call_1", "write_file", {"path": "a.txt", "content": "x"})])

    def test_no_tool_calls_returns_empty(self):
        self.assertEqual(parse_tool_calls({"role": "assistant",
                                           "content": "done"}), [])

    def test_malformed_json_fails_closed(self):
        msg = _assistant_tool_call("call_1", "write_file", "{not json")
        with self.assertRaises(MalformedToolCallError):
            parse_tool_calls(msg)

    def test_non_object_arguments_rejected(self):
        for bad in ('["a", "b"]', '"just a string"', "42"):
            msg = _assistant_tool_call("call_1", "write_file", bad)
            with self.assertRaises(MalformedToolCallError, msg="args=%r" % bad):
                parse_tool_calls(msg)

    def test_missing_id_rejected(self):
        msg = {"role": "assistant", "tool_calls": [{
            "type": "function",
            "function": {"name": "write_file", "arguments": "{}"}}]}
        with self.assertRaises(MalformedToolCallError):
            parse_tool_calls(msg)

    def test_duplicate_ids_rejected(self):
        msg = {"role": "assistant", "tool_calls": [
            _assistant_tool_call("dup", "write_file", "{}")["tool_calls"][0],
            _assistant_tool_call("dup", "read_file", "{}")["tool_calls"][0],
        ]}
        with self.assertRaises(MalformedToolCallError):
            parse_tool_calls(msg)

    def test_non_function_type_rejected(self):
        msg = _assistant_tool_call("call_1", "write_file", "{}")
        msg["tool_calls"][0]["type"] = "computer_use"
        with self.assertRaises(MalformedToolCallError):
            parse_tool_calls(msg)

    def test_missing_name_rejected(self):
        msg = _assistant_tool_call("call_1", "", "{}")
        with self.assertRaises(MalformedToolCallError):
            parse_tool_calls(msg)

    def test_non_dict_message_rejected(self):
        with self.assertRaises(MalformedToolCallError):
            parse_tool_calls("not a message")

    def test_dict_arguments_accepted(self):
        msg = _assistant_tool_call("call_1", "write_file",
                                   {"path": "a.txt", "content": "x"})
        parsed = parse_tool_calls(msg)
        self.assertEqual(parsed[0].arguments, {"path": "a.txt",
                                               "content": "x"})


class TestRunToolLoop(unittest.TestCase):
    def test_happy_path_single_turn(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        def respond(transcript):
            if len(transcript) == 1:
                return _assistant_tool_call(
                    "call_1", "write_file",
                    json.dumps({"path": "loop.txt", "content": "hi"}))
            return {"role": "assistant", "content": "done"}

        transcript = run_tool_loop(
            binding, [{"role": "user", "content": "write it"}], respond)
        roles = [m["role"] for m in transcript]
        self.assertEqual(roles, ["user", "assistant", "tool", "assistant"])
        tool_msg = transcript[2]
        self.assertEqual(tool_msg["tool_call_id"], "call_1")
        self.assertEqual(json.loads(tool_msg["content"])["status"], "executed")
        self.assertTrue((ctx["run_dir"] / "sandbox" / "loop.txt").is_file())

    def test_input_messages_not_mutated(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        start = [{"role": "user", "content": "hi"}]

        def respond(transcript):
            return {"role": "assistant", "content": "done"}

        run_tool_loop(binding, start, respond)
        self.assertEqual(start, [{"role": "user", "content": "hi"}])

    def test_malformed_call_dispatches_nothing(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        def respond(transcript):
            return _assistant_tool_call("call_1", "write_file", "{broken")

        with self.assertRaises(MalformedToolCallError):
            run_tool_loop(binding, [{"role": "user", "content": "x"}], respond)
        self.assertNotIn("write_file", ctx["executor"].counters,
                         "malformed call must never be dispatched")

    def test_unknown_tool_fails_closed(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        def respond(transcript):
            return _assistant_tool_call("call_1", "drop_database", "{}")

        with self.assertRaises(UnregisteredToolError):
            run_tool_loop(binding, [{"role": "user", "content": "x"}], respond)

    def test_denied_stops_loop_by_default(self):
        ctx = make_run()
        binding = _coder_binding(ctx)  # coder cannot send_email

        def respond(transcript):
            return _assistant_tool_call(
                "call_1", "send_email",
                json.dumps({"to": "x@synthetic.local", "subject": "s",
                            "body": "b"}))

        with self.assertRaises(ToolDeniedError):
            run_tool_loop(binding, [{"role": "user", "content": "x"}], respond)

    def test_denied_return_mode_feeds_denial_back(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        seen = []

        def respond(transcript):
            if any(m.get("role") == "tool" for m in transcript):
                seen.append(transcript[-1])
                return {"role": "assistant", "content": "understood"}
            return _assistant_tool_call(
                "call_1", "send_email",
                json.dumps({"to": "x@synthetic.local", "subject": "s",
                            "body": "b"}))

        transcript = run_tool_loop(
            binding, [{"role": "user", "content": "x"}], respond,
            on_denied="return")
        tool_msgs = [m for m in transcript if m["role"] == "tool"]
        self.assertEqual(len(tool_msgs), 1)
        self.assertEqual(json.loads(tool_msgs[0]["content"])["status"],
                         "denied")
        self.assertEqual(len(seen), 1, "model saw the denial and continued")

    def test_max_iterations_guard(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        def respond(transcript):
            # A model stuck in a tool loop forever.
            return _assistant_tool_call(
                "call_%d" % len(transcript), "read_file",
                json.dumps({"path": "notes.txt"}))

        with self.assertRaises(AdapterError):
            run_tool_loop(binding, [{"role": "user", "content": "x"}],
                          respond, max_iterations=3)

    def test_respond_must_return_dict(self):
        ctx = make_run()
        binding = _coder_binding(ctx)
        with self.assertRaises(MalformedToolCallError):
            run_tool_loop(binding, [], lambda t: "nope")

    def test_multiple_tool_calls_one_turn(self):
        ctx = make_run()
        binding = _coder_binding(ctx)

        def respond(transcript):
            if len(transcript) == 1:
                return {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "c1", "type": "function",
                     "function": {"name": "write_file", "arguments":
                                  json.dumps({"path": "m1.txt",
                                              "content": "1"})}},
                    {"id": "c2", "type": "function",
                     "function": {"name": "write_file", "arguments":
                                  json.dumps({"path": "m2.txt",
                                              "content": "2"})}},
                ]}
            return {"role": "assistant", "content": "done"}

        transcript = run_tool_loop(
            binding, [{"role": "user", "content": "x"}], respond)
        tool_msgs = [m for m in transcript if m["role"] == "tool"]
        self.assertEqual([m["tool_call_id"] for m in tool_msgs], ["c1", "c2"])
        self.assertTrue((ctx["run_dir"] / "sandbox" / "m1.txt").is_file())
        self.assertTrue((ctx["run_dir"] / "sandbox" / "m2.txt").is_file())


if __name__ == "__main__":
    unittest.main()
