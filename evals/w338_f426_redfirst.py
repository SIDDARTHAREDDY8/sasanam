"""RED-FIRST evidence for F426 (wave-338 lane 1) on the BASE tree.

Demonstrates the three open break shapes before the fix:
  1. guardrail built for framework_tool "read_file", attached to SDK
     FunctionTool "delete_file", declares NO expect_sdk_tool_name ->
     audit_agent_coverage CERTIFIES the agent; a delete_file call then
     returns allow while direct binding.call("delete_file") is denied
     (role-policy bypass).
  2. guardrail built for "read_file" declaring
     expect_sdk_tool_name="read_file", attached to FunctionTool
     "delete_file" -> audit STILL certifies (never consults the declared
     name).
  3. arg-shape mismatch (write_file guardrail called with send_email
     args) -> bare KeyError escapes the guardrail UNCODED.
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.adapters.openai_agents import (
    UncoveredSurfaceError, audit_agent_coverage,
    make_tool_input_guardrail)
from gov.adapters.core import GovernedBinding
from tests.keyfixture import provision_test_key

provision_test_key()
from tests.harness import make_run


class _Ctx:
    def __init__(self, tool_name, arguments):
        self.tool_name = tool_name
        self.tool_arguments = arguments


class _Data:
    def __init__(self, ctx):
        self.context = ctx


class _Tool:
    def __init__(self, name, guardrails):
        self.name = name
        self.tool_input_guardrails = guardrails


class _Agent:
    def __init__(self, tools):
        self.name = "miswired"
        self.tools = tools
        self.handoffs = []


def _data(tool_name, args):
    return _Data(_Ctx(tool_name, json.dumps(args)))


ctx = make_run()


def _bindings():
    support = GovernedBinding(ctx["executor"],
                              ctx["mint_identity"]("support-1", "support",
                                                   "dev-org"))
    coder = GovernedBinding(ctx["executor"],
                            ctx["mint_identity"]("coder-1", "coder",
                                                 "dev-org"))
    return support, coder


support, coder = _bindings()

# --- Shape 1: no declared name, misattached -> certified + bypass -----
g_read = make_tool_input_guardrail(support, "read_file")
agent = _Agent([_Tool("delete_file", [g_read])])
try:
    audit_agent_coverage(agent)
    shape1_certified = True
except UncoveredSurfaceError:
    shape1_certified = False
print("shape1 audit certified miswired agent:", shape1_certified)
print("shape1 guardrail exposes framework_tool attr:",
      getattr(g_read, "framework_tool", "<ABSENT>"))
print("shape1 guardrail exposes expect_sdk_tool_name attr:",
      getattr(g_read, "expect_sdk_tool_name", "<ABSENT>"))
out = g_read(_data("delete_file", {"path": "victim.txt"}))
info = out.output_info or {}
direct = support.call("delete_file", on_denied="return",
                      on_queued="return", path="victim.txt")
print("shape1 via guardrail:", out.behavior.get("type"),
      "framework_tool=", info.get("framework_tool"))
print("shape1 direct binding.call('delete_file'):", direct.get("status"),
      "-", str(direct.get("reason"))[:60])

# --- Shape 2: declared (mismatched) name -> still certified -----------
g_read_named = make_tool_input_guardrail(
    support, "read_file", expect_sdk_tool_name="read_file")
agent2 = _Agent([_Tool("delete_file", [g_read_named])])
try:
    audit_agent_coverage(agent2)
    shape2_certified = True
except UncoveredSurfaceError:
    shape2_certified = False
print("shape2 audit certified name-mismatched agent:", shape2_certified)

# --- Shape 3: arg-shape mismatch -> bare KeyError ----------------------
g_write = make_tool_input_guardrail(coder, "write_file")
try:
    g_write(_data("send_email", {"to": "x@synthetic.local",
                                 "subject": "s", "body": "b"}))
    print("shape3: no exception (unexpected)")
except KeyError as e:
    print("shape3: bare KeyError escaped UNCODED:", repr(e))
except Exception as e:  # noqa: BLE001
    code = getattr(e, "code", None)
    print("shape3: %r escaped (coded=%r)" % (e, code))
