#!/usr/bin/env python3
"""Wave-337 lane 4: independent red team vs the wave-336 tree.

Base: `2f270987` (wave-336 merge). Pin 2106. Footer open F424, F425, F426 /
next F427 (F426 filed by this lane).

New attack surface: the four production framework adapters --
`gov/adapters/crewai_tools.py` (CrewAI BaseTool shim),
`gov/adapters/ag2_hooks.py` (AG2 1.x middleware),
`gov/adapters/openai_agents.py` (OpenAI Agents SDK tool_input_guardrails
shim), `gov/adapters/langgraph_hitl.py` (LangGraph interrupt() ->
ApprovalQueue recipe). Frameworks are NOT installed in the canonical
venv, so crewai/ag2 are exercised through minimal injected stand-ins
for their import-time modules (real pydantic v2 for the F62 logic;
the funnel/run() behavior itself stays pinned by the lane's
real-framework tests), the OAI shim is duck-typed (it is designed to
work without the `agents` package), and langgraph takes `interrupt`
by injection (no langgraph import in the module).

Break-first probes at the public seams:

P1 (crewai F62/funnel logic): strict schema refused at construction;
  extra="allow" accepted and undeclared kwargs reach _mediate;
  args_schema reassignment to a strict schema refused; object.__setattr__
  bypass caught at mediation (F68); positional _run args refused;
  schema-level stripping validator passes the config check but drops a
  canary (WATCH residual -- the check is config-based, documented).
P2 (ag2 middleware): malformed JSON / non-dict args -> ToolErrorEvent,
  impl never runs; denied -> ToolErrorEvent w/ ToolDeniedError;
  unregistered name -> ToolErrorEvent; executed -> call_next exactly once;
  queued -> ToolErrorEvent w/ ApprovalRequiredError + approval_id;
  TealTiger-style outer limiter denying first -> tool never runs, and our
  audit sees nothing (composition-ordering note, not a finding).
P3 (oai guardrail shim): P3a F426 (CLOSED wave-338 lane 1) -- a guardrail
  built for one framework tool attached to a DIFFERENT SDK FunctionTool
  is now refused by audit_agent_coverage (undeclared/mismatched declared
  name); misattached arg shapes refuse coded
  guardrail_argument_shape_mismatch (no uncoded KeyError). Correctly
  attached guardrails (declared name matches) pass audit; as_tool()/
  hosted/handoff surfaces refused; malformed JSON trips the wire;
  expect_sdk_tool_name mismatch trips the wire.
P4 (langgraph recipe): queued pauses via interrupt with the approval_id;
  resume mismatch / premature / vanished-record all fail closed;
  client update_state arg-tampering cannot smuggle a different action
  past the queue (execute_approved runs the QUEUED args); non-raising
  interrupt on first entry refused; non-dict arguments refused.
P5 (F424/F425 live on this tree): NaN lock timeout escapes refresh()
  uncoded; -1 blocks forever under contention; raising clock escapes
  _check_tool_rate uncoded (no coded denial, no chained record).
P6 (honesty + regressions): pin 2135/2135/0 sorted-unique on raw
  literals; footer open none / next F430 (F426 closed wave-338 lane 1);
  F423 NUL now refused coded (closed); F417 non-numeric port refused
  coded; F421 double-refresh exactly-one.

Verdicts: HELD = behavior matches the pin; BREAK = genuine open
finding (F424/F425 shapes); ERROR = probe/harness problem.
No findings manufactured -- a 0-break battery is honest.

$0 spend; synthetic/local; no model calls.

Run:
  mkdir -p /var/tmp/g337-rt
  TMPDIR=/var/tmp/g337-rt ~/workspace/.gov-venv/bin/python evals/w337_redteam_probes.py
Clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g337-rtb ~/workspace/.gov-venv/bin/python evals/w337_redteam_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w337_redteam_probes.py P3a
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
# ---------------------------------------------------------------------------
# Import-time stand-ins: crewai / ag2 are not installed in the canonical
# venv. Inject minimal fake modules so the PURE-PYTHON shim logic (the
# F62 config check, mediation, middleware dispatch) is exercised with
# real pydantic v2. The framework funnel behavior (CrewAI run()->_run,
# AG2 middleware pipeline ordering) stays pinned by the lane's
# real-framework tests, not by these stand-ins.
# ---------------------------------------------------------------------------

from pydantic import BaseModel, ConfigDict, Field, model_validator  # noqa: E402


def _install_fake_crewai():
    if "crewai.tools" in sys.modules:
        return

    class _FakeBaseTool(BaseModel):
        """Minimal stand-in for crewai.tools.BaseTool: a pydantic model
        carrying name/description/args_schema. Enough for the shim's
        F62 logic (construction check, __setattr__ guard, _mediate
        re-check, _run/_arun positional refusal)."""

        model_config = ConfigDict(arbitrary_types_allowed=True)
        name: str = ""
        description: str = ""
        args_schema: object = None

    crewai_pkg = types.ModuleType("crewai")
    crewai_tools = types.ModuleType("crewai.tools")
    crewai_tools.BaseTool = _FakeBaseTool
    crewai_pkg.tools = crewai_tools
    sys.modules["crewai"] = crewai_pkg
    sys.modules["crewai.tools"] = crewai_tools


def _install_fake_ag2():
    if "ag2.events" in sys.modules:
        return

    class _FakeToolCallEvent:
        def __init__(self, name, raw_arguments):
            self.name = name
            self._raw = raw_arguments

        @property
        def serialized_arguments(self):
            # Real AG2: parsed from the model's JSON tool-call args.
            return json.loads(self._raw)

    class _FakeToolErrorEvent:
        def __init__(self, event, error):
            self.event = event
            self.error = error

        @classmethod
        def from_call(cls, event, error):
            return cls(event, error)

    class _FakeBaseMiddleware:
        def __init__(self, event, context):
            self.event = event
            self.context = context

    ag2_pkg = types.ModuleType("ag2")
    ag2_events = types.ModuleType("ag2.events")
    ag2_events.ToolCallEvent = _FakeToolCallEvent
    ag2_events.ToolErrorEvent = _FakeToolErrorEvent
    ag2_mw = types.ModuleType("ag2.middleware")
    ag2_mw.BaseMiddleware = _FakeBaseMiddleware
    ag2_pkg.events = ag2_events
    ag2_pkg.middleware = ag2_mw
    sys.modules["ag2"] = ag2_pkg
    sys.modules["ag2.events"] = ag2_events
    sys.modules["ag2.middleware"] = ag2_mw


_install_fake_crewai()
_install_fake_ag2()

from gov.adapters import crewai_tools as CREWAI_SHIM  # noqa: E402
from gov.adapters import ag2_hooks as AG2_SHIM  # noqa: E402
from gov.adapters import openai_agents as OAI_SHIM  # noqa: E402
from gov.adapters import langgraph_hitl as LG_SHIM  # noqa: E402
from gov.adapters.core import (  # noqa: E402
    AdapterError,
    ApprovalRequiredError,
    GovernedBinding,
    ToolDeniedError,
    UnregisteredToolError,
)
from gov import tool_rate_limit as TRL  # noqa: E402
from gov import agent_identity as AI  # noqa: E402
from gov import mcp_prm as PRM  # noqa: E402
from gov import mcp_oauth_binding as MOB  # noqa: E402
from gov import decision_codes as DC  # noqa: E402

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:170]))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    """An uncaught probe exception becomes ERROR, never a dead battery."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", "UNEXPECTED:%r" % (e,))
    return None


def _key():
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _make_run():
    try:
        from tests.harness import make_run
    except ImportError:
        from harness import make_run
    return make_run()


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _support_binding(ctx):
    ident = ctx["mint_identity"]("support-1", "support", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


# ---------------------------------------------------------------------------
# P1: crewai shim F62/funnel logic (fake crewai.tools + real pydantic).
# ---------------------------------------------------------------------------

class _StrictSchema(BaseModel):
    path: str = Field(default="")


class _AllowSchema(BaseModel):
    model_config = ConfigDict(extra="allow")
    path: str = Field(default="")


class _StrippingSchema(BaseModel):
    """extra='allow' on paper, but a schema-level validator strips
    undeclared keys -- the config check passes while behavior drops."""

    model_config = ConfigDict(extra="allow")
    path: str = Field(default="")

    @model_validator(mode="before")
    @classmethod
    def _strip_unknown(cls, data):
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k in cls.model_fields}
        return data


def _crewai_tool(binding, schema, **kw):
    kw.setdefault("framework_tool", "write_file")
    return CREWAI_SHIM.make_governed_crewai_tool(
        binding, name="t", description="t", args_schema=schema, **kw)


def P1a():
    """F62: strict schema (extra='ignore') refused at construction."""
    pid = "P1a-crewai-strict-schema-refused"
    ctx = _make_run()
    try:
        _crewai_tool(_coder_binding(ctx), _StrictSchema)
    except ValueError as e:
        if "extra='allow'" in str(e) or "extra=\"allow\"" in str(e) or "F62" in str(e):
            _held(pid, "strict args_schema refused at construction: %s"
                  % (str(e)[:80],))
            return
        _break(pid, "refused but wrong message: %r" % (e,))
        return
    _break(pid, "strict schema ACCEPTED at construction (F62 hole open)")


def P1b():
    """extra='allow' accepted; undeclared kwarg reaches _mediate (visible
    in the executor's audit record)."""
    pid = "P1b-crewai-allow-passes-smuggled-kwarg"
    ctx = _make_run()
    tool = _crewai_tool(_coder_binding(ctx), _AllowSchema)
    out = tool._run(path="notes.txt", bcc="evil@synthetic.local")
    if json.loads(out).get("status") != "executed":
        _break(pid, "allow-schema call did not execute: %r" % (out[:80],))
        return
    seen = False
    for e in ctx["read_log"]():
        args = (e.get("args") or {}) if e.get("event") == "tool_call" else {}
        # The bcc VALUE is DLP-redacted in the log (correct); the F62
        # property is that the undeclared KEY reaches mediation at all.
        if isinstance(args, dict) and "bcc" in args:
            seen = True
    if not seen:
        _break(pid, "smuggled kwarg missing from the audit record")
        return
    _held(pid, "extra='allow' accepted; undeclared kwarg reached mediation "
               "and the audit record")


def P1c():
    """args_schema reassignment to a strict schema refused via __setattr__."""
    pid = "P1c-crewai-schema-reassignment-refused"
    ctx = _make_run()
    tool = _crewai_tool(_coder_binding(ctx), _AllowSchema)
    try:
        tool.args_schema = _StrictSchema
    except ValueError:
        _held(pid, "post-construction strict reassignment refused")
        return
    _break(pid, "strict schema reassignment ACCEPTED (F62 re-opened)")


def P1d():
    """object.__setattr__ bypass of the reassignment guard is caught at
    mediation time (F68 class)."""
    pid = "P1d-crewai-setattr-bypass-caught-at-mediation"
    ctx = _make_run()
    tool = _crewai_tool(_coder_binding(ctx), _AllowSchema)
    object.__setattr__(tool, "args_schema", _StrictSchema)
    code = _code_of(lambda: tool._run(path="x"))
    if code is None:
        _break(pid, "mediation ran with bypassed strict schema")
        return
    _held(pid, "bypassed schema caught at mediation: %s" % (str(code)[:80],))


def P1e():
    """Positional args to _run/_arun refused (run() skips validation)."""
    pid = "P1e-crewai-positional-refused"
    ctx = _make_run()
    tool = _crewai_tool(_coder_binding(ctx), _AllowSchema)
    for fn in (lambda: tool._run("pos"),
               lambda: asyncio.run(tool._arun("pos"))):
        try:
            fn()
        except RuntimeError:
            continue
        _break(pid, "positional args accepted")
        return
    _held(pid, "_run/_arun positional args refused")


def P1f():
    """WATCH (not a finding): the F62 check is config-based. A schema with
    extra='allow' PLUS a stripping validator passes the check while
    behaviorally dropping undeclared kwargs -- the documented residual."""
    pid = "P1f-crewai-config-vs-behavior-watch"
    ok_config = CREWAI_SHIM._args_schema_allows_undeclared(_StrippingSchema)
    dumped = _StrippingSchema.model_validate(
        {"path": "a", "bcc": "evil@synthetic.local"}).model_dump()
    if ok_config and "bcc" not in dumped:
        _held(pid, "WATCH: config check passes but a stripping validator "
                   "drops undeclared kwargs -- check is config-based, not "
                   "behavioral (deployer-written validators only)")
        return
    if not ok_config:
        _held(pid, "stripping schema refused (stronger than documented)")
        return
    _break(pid, "unexpected: canary survived a stripping validator?")


# ---------------------------------------------------------------------------
# P2: ag2 middleware (fake ag2.events / ag2.middleware).
# ---------------------------------------------------------------------------

def _ag2_event(name, args):
    from ag2.events import ToolCallEvent
    return ToolCallEvent(name, json.dumps(args))


def P2a():
    """Malformed JSON args -> ToolErrorEvent; implementation never runs."""
    pid = "P2a-ag2-malformed-args-event"
    from ag2.events import ToolCallEvent, ToolErrorEvent
    ctx = _make_run()
    mw = AG2_SHIM.governed_tool_middleware(_coder_binding(ctx))
    ran = []

    async def call_next(event, context):
        ran.append(1)
        return "ran"

    bad = ToolCallEvent("write_file", "{not json")
    out = asyncio.run(mw(call_next, bad, None))
    if not isinstance(out, ToolErrorEvent):
        _break(pid, "want ToolErrorEvent, got %r" % type(out).__name__)
        return
    if "MalformedToolCallError" not in type(out.error).__name__:
        _break(pid, "want MalformedToolCallError, got %r" % (out.error,))
        return
    if ran:
        _break(pid, "implementation ran on malformed args")
        return
    _held(pid, "malformed args -> ToolErrorEvent(MalformedToolCallError)")


def P2b():
    """Denied call -> ToolErrorEvent(ToolDeniedError); impl never runs."""
    pid = "P2b-ag2-denied-event"
    from ag2.events import ToolErrorEvent
    ctx = _make_run()
    mw = AG2_SHIM.governed_tool_middleware(_coder_binding(ctx))
    ran = []

    async def call_next(event, context):
        ran.append(1)
        return "ran"

    out = asyncio.run(mw(call_next,
                         _ag2_event("send_email",
                                    {"to": "x@synthetic.local",
                                     "subject": "s", "body": "b"}), None))
    if not isinstance(out, ToolErrorEvent):
        _break(pid, "want ToolErrorEvent, got %r" % type(out).__name__)
        return
    if not isinstance(out.error, ToolDeniedError):
        _break(pid, "want ToolDeniedError, got %r" % (out.error,))
        return
    if ran:
        _break(pid, "implementation ran on denied call")
        return
    _held(pid, "denied -> ToolErrorEvent(ToolDeniedError), impl not run")


def P2c():
    """Unregistered tool name -> ToolErrorEvent(UnregisteredToolError)."""
    pid = "P2c-ag2-unregistered-event"
    from ag2.events import ToolErrorEvent
    ctx = _make_run()
    mw = AG2_SHIM.governed_tool_middleware(_coder_binding(ctx))
    ran = []

    async def call_next(event, context):
        ran.append(1)
        return "ran"

    out = asyncio.run(mw(call_next, _ag2_event("nope_tool", {}), None))
    if not isinstance(out, ToolErrorEvent):
        _break(pid, "want ToolErrorEvent, got %r" % type(out).__name__)
        return
    if not isinstance(out.error, UnregisteredToolError):
        _break(pid, "want UnregisteredToolError, got %r" % (out.error,))
        return
    if ran:
        _break(pid, "implementation ran on unregistered tool")
        return
    _held(pid, "unregistered -> ToolErrorEvent(UnregisteredToolError)")


def P2d():
    """Allowed call reaches the implementation exactly once."""
    pid = "P2d-ag2-executed-once"
    ctx = _make_run()
    mw = AG2_SHIM.governed_tool_middleware(_coder_binding(ctx))
    ran = []

    async def call_next(event, context):
        ran.append(1)
        return "ran-ok"

    out = asyncio.run(mw(call_next,
                         _ag2_event("write_file",
                                    {"path": "notes.txt",
                                     "content": "x"}), None))
    if out != "ran-ok" or len(ran) != 1:
        _break(pid, "allowed call not delivered exactly once: %r %r"
               % (out, ran))
        return
    _held(pid, "allowed call -> implementation exactly once")


def P2e():
    """Queued call -> ToolErrorEvent(ApprovalRequiredError) with
    approval_id; implementation never runs."""
    pid = "P2e-ag2-queued-event"
    from ag2.events import ToolErrorEvent
    ctx = _make_run()
    mw = AG2_SHIM.governed_tool_middleware(_coder_binding(ctx))
    ran = []

    async def call_next(event, context):
        ran.append(1)
        return "ran"

    out = asyncio.run(mw(call_next,
                         _ag2_event("write_file",
                                    {"path": "/tmp/ag2-queued.txt",
                                     "content": "x"}), None))
    if not isinstance(out, ToolErrorEvent):
        _break(pid, "want ToolErrorEvent, got %r" % type(out).__name__)
        return
    if not isinstance(out.error, ApprovalRequiredError):
        _break(pid, "want ApprovalRequiredError, got %r" % (out.error,))
        return
    if not out.error.approval_id:
        _break(pid, "queued but no approval_id")
        return
    if ran:
        _break(pid, "implementation ran on queued call")
        return
    _held(pid, "queued -> ToolErrorEvent(ApprovalRequiredError, approval_id)")


def P2f():
    """Composition note (not a finding): a TealTiger-style native limiter
    OUTSIDE our middleware that denies first means our middleware never
    runs -- the tool never executes (fail-closed), but our audit log has
    no record of the attempt. Ordering matters; Sasanam-outermost gives
    full attempt audit."""
    pid = "P2f-ag2-composition-ordering-note"
    from ag2.events import ToolErrorEvent
    ctx = _make_run()
    binding = _coder_binding(ctx)
    mw = AG2_SHIM.governed_tool_middleware(binding)
    ran = []

    async def tool_impl(event, context):
        ran.append(1)
        return "ran"

    async def native_limiter_outer(call_next, event, context):
        # Stand-in for a native rate-limit middleware denying first.
        return ToolErrorEvent.from_call(
            event, RuntimeError("native rate limit exceeded"))

    out = asyncio.run(native_limiter_outer(
        lambda e, c: mw(tool_impl, e, c),
        _ag2_event("write_file", {"path": "notes.txt", "content": "x"}),
        None))
    if ran:
        _break(pid, "tool ran despite outer denial")
        return
    attempts = [e for e in ctx["read_log"]()
                if e.get("tool") == "write_file"]
    if attempts:
        _held(pid, "outer denial: tool not run; attempt unexpectedly audited")
        return
    _held(pid, "NOTE: outer-native denial -> tool not run (fail-closed), "
               "but no Sasanam audit record of the attempt -- deploy "
               "Sasanam-outermost for full attempt audit (w336 R11)")


# ---------------------------------------------------------------------------
# P3: openai_agents shim (duck-typed; no `agents` package needed).
# ---------------------------------------------------------------------------

class _OAIContext:
    def __init__(self, tool_name, tool_arguments, tool_call_id="call_1"):
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments
        self.tool_call_id = tool_call_id


class _OAIData:
    def __init__(self, context):
        self.context = context


class _OAIFunctionTool:
    def __init__(self, name, guardrails=(), is_agent_tool=False):
        self.name = name
        self.tool_input_guardrails = list(guardrails)
        if is_agent_tool:
            self._is_agent_tool = True


class _OAIHostedTool:
    def __init__(self, name):
        self.name = name


class _OAIAgent:
    def __init__(self, name, tools, handoffs=()):
        self.name = name
        self.tools = list(tools)
        self.handoffs = list(handoffs)


def _oai_data(tool_name, arguments):
    return _OAIData(_OAIContext(tool_name, json.dumps(arguments)))


def P3a():
    """F426 (this lane): a guardrail built for one framework tool,
    attached to a DIFFERENT SDK FunctionTool, passes
    audit_agent_coverage -- calls are then mediated under the WRONG
    tool's policy while the agent is certified as covered. Primary
    shape: support-role delete_file (DENIED by role policy) mediated as
    read_file (allowed) -> ALLOW: a certified policy bypass. Second
    shape: misattached arg shapes crash the guardrail uncoded
    (KeyError escapes -- F417-class on the guardrail seam)."""
    pid = "P3a-oai-guardrail-misattachment-certified"
    ctx = _make_run()
    # support: read_file allowed, delete_file denied by role policy.
    binding = _support_binding(ctx)
    guard_r = OAI_SHIM.make_tool_input_guardrail(binding, "read_file")
    agent = _OAIAgent("miswired", [_OAIFunctionTool("delete_file",
                                                   [guard_r])])
    try:
        OAI_SHIM.audit_agent_coverage(agent)
    except OAI_SHIM.UncoveredSurfaceError:
        _held(pid, "audit refused the miswired agent")
        return
    # Certified -- now the bypass: delete_file mediated as read_file.
    out = guard_r(_oai_data("delete_file", {"path": "victim.txt"}))
    info = out.output_info or {}
    direct = binding.call("delete_file", on_denied="return",
                          on_queued="return", path="victim.txt")
    if (out.behavior.get("type") == "allow"
            and info.get("framework_tool") == "read_file"
            and direct.get("status") == "denied"):
        _break(pid, "F426: audit certified a miswired agent; support-role "
                    "delete_file mediated as read_file -> ALLOW (direct "
                    "delete_file: denied) -- role policy bypassed via "
                    "certified miswiring")
        return
    # Second shape: arg-shape mismatch crashes the guardrail uncoded.
    guard_w = OAI_SHIM.make_tool_input_guardrail(_coder_binding(ctx),
                                                 "write_file")
    try:
        guard_w(_oai_data("send_email",
                          {"to": "x@synthetic.local",
                           "subject": "s", "body": "b"}))
        crashed = None
    except Exception as e:  # noqa: BLE001
        crashed = e
    if crashed is not None and getattr(crashed, "code", None) is None:
        _break(pid, "F426: misattached guardrail crashed UNCODED %r "
                    "(F417-class on the guardrail seam)" % (crashed,))
        return
    _break(pid, "F426: audit certified a miswired agent (wrong-policy "
                "mediation)")


def P3b():
    """Correctly attached guardrails pass audit: the guardrail declares
    the SDK tool's name (expect_sdk_tool_name), so the audit can verify
    the correspondence (F426 strict close-when)."""
    pid = "P3b-oai-correct-attachment-passes"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(
        binding, "write_file", expect_sdk_tool_name="write_file")
    agent = _OAIAgent("ok", [_OAIFunctionTool("write_file", [g])])
    try:
        # F427: certification requires the deployment-declared
        # SDK-tool->framework-tool mapping; the declaration alone is
        # never trusted.
        rep = OAI_SHIM.audit_agent_coverage(
            agent, sdk_tool_map={"write_file": "write_file"})
    except OAI_SHIM.UncoveredSurfaceError as e:
        _break(pid, "correct agent refused: %s" % (str(e)[:100],))
        return
    if rep["tools"] != ["write_file"]:
        _break(pid, "wrong coverage report: %r" % (rep,))
        return
    _held(pid, "correctly wired agent certified")


def P3c():
    """as_tool() nested runs refused by audit (SDK marker)."""
    pid = "P3c-oai-as-tool-refused"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(binding, "write_file")
    agent = _OAIAgent("nested",
                      [_OAIFunctionTool("summarizer", [g], is_agent_tool=True)])
    try:
        OAI_SHIM.audit_agent_coverage(agent)
    except OAI_SHIM.UncoveredSurfaceError:
        _held(pid, "as_tool() nested run refused certification")
        return
    _break(pid, "as_tool() nested run CERTIFIED (residual violated)")


def P3d():
    """Hosted/built-in tools refused by audit."""
    pid = "P3d-oai-hosted-refused"
    ctx = _make_run()
    agent = _OAIAgent("hosted", [_OAIHostedTool("WebSearchTool")])
    try:
        OAI_SHIM.audit_agent_coverage(agent)
    except OAI_SHIM.UncoveredSurfaceError:
        _held(pid, "hosted tool refused certification")
        return
    _break(pid, "hosted tool CERTIFIED (residual violated)")


def P3e():
    """Handoffs refused by audit."""
    pid = "P3e-oai-handoff-refused"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(binding, "write_file")
    agent = _OAIAgent("hand", [_OAIFunctionTool("write_file", [g])],
                      handoffs=["other-agent"])
    try:
        OAI_SHIM.audit_agent_coverage(agent)
    except OAI_SHIM.UncoveredSurfaceError:
        _held(pid, "handoff refused certification")
        return
    _break(pid, "handoff CERTIFIED (residual violated)")


def P3f():
    """Malformed JSON arguments trip the wire fail-closed."""
    pid = "P3f-oai-malformed-args-tripwire"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(binding, "write_file")
    out = g(_OAIData(_OAIContext("write_file", "{not json")))
    if out.behavior.get("type") != "raise_exception":
        _break(pid, "want raise_exception, got %r" % (out.behavior,))
        return
    if out.output_info.get("error") != "malformed_tool_arguments":
        _break(pid, "wrong error: %r" % (out.output_info,))
        return
    _held(pid, "malformed args -> raise_exception(malformed_tool_arguments)")


def P3g():
    """expect_sdk_tool_name mismatch trips the wire (runtime backstop)."""
    pid = "P3g-oai-expect-name-mismatch"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(
        binding, "write_file", expect_sdk_tool_name="write_file")
    out = g(_oai_data("delete_file", {"path": "x"}))
    if out.behavior.get("type") != "raise_exception":
        _break(pid, "want raise_exception, got %r" % (out.behavior,))
        return
    if out.output_info.get("error") != "misconfigured_guardrail_attachment":
        _break(pid, "wrong error: %r" % (out.output_info,))
        return
    _held(pid, "expect_sdk_tool_name mismatch -> raise_exception")


# ---------------------------------------------------------------------------
# P4: langgraph recipe (interrupt injected; no langgraph import).
# ---------------------------------------------------------------------------

class _GraphInterrupt(Exception):
    pass


class _StandInterrupt:
    def __init__(self):
        self.payloads = []
        self.resume_value = None
        self._first = True

    def __call__(self, payload):
        self.payloads.append(payload)
        if self._first:
            self._first = False
            raise _GraphInterrupt(payload)
        return self.resume_value


def _queued_call(ctx, binding, tool="write_file", args=None):
    intr = _StandInterrupt()
    try:
        LG_SHIM.governed_tool_call(
            binding, tool, args or {"path": "/tmp/lg-q.txt",
                                   "content": "x"},
            interrupt=intr)
    except _GraphInterrupt:
        pass
    return intr


def P4a():
    """Queued call pauses via interrupt carrying the approval_id."""
    pid = "P4a-lg-queued-pauses"
    ctx = _make_run()
    intr = _queued_call(ctx, _coder_binding(ctx))
    if len(intr.payloads) != 1:
        _break(pid, "want exactly one interrupt, got %d" % len(intr.payloads))
        return
    aid = intr.payloads[0].get("approval_id")
    if not aid or "path" in json.dumps(intr.payloads[0]):
        # raw args must NOT be in the client-visible payload
        _break(pid, "payload missing approval_id or leaks raw args")
        return
    _held(pid, "queued -> interrupt(approval_id=%s...)" % (aid[:8],))


def P4b():
    """Resume naming a different approval id fails closed."""
    pid = "P4b-lg-resume-mismatch"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    intr = _queued_call(ctx, binding)
    aid = intr.payloads[0]["approval_id"]
    intr.resume_value = {"approval_id": "approval-other"}
    try:
        LG_SHIM.governed_tool_call(
            binding, "write_file", {"path": "/tmp/lg-q.txt", "content": "x"},
            interrupt=intr, prior_approval_id=aid)
    except LG_SHIM.ApprovalResumeMismatchError:
        _held(pid, "resume mismatch -> ApprovalResumeMismatchError")
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
        return
    _break(pid, "mismatched resume ACCEPTED")


def P4c():
    """Resume before any human decided fails closed."""
    pid = "P4c-lg-premature-resume"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    intr = _queued_call(ctx, binding)
    aid = intr.payloads[0]["approval_id"]
    intr.resume_value = {"approval_id": aid}
    try:
        LG_SHIM.governed_tool_call(
            binding, "write_file", {"path": "/tmp/lg-q.txt", "content": "x"},
            interrupt=intr, prior_approval_id=aid)
    except LG_SHIM.ApprovalNotDecidedError:
        _held(pid, "premature resume -> ApprovalNotDecidedError")
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
        return
    _break(pid, "premature resume ACCEPTED")


def P4d():
    """Vanished queue record fails closed."""
    pid = "P4d-lg-missing-record"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    intr = _StandInterrupt()
    intr._first = False  # simulate re-entry directly
    intr.resume_value = {"approval_id": "approval-nope"}
    try:
        LG_SHIM.governed_tool_call(
            binding, "write_file", {"path": "x", "content": "y"},
            interrupt=intr, prior_approval_id="approval-nope")
    except LG_SHIM.ApprovalRecordMissingError:
        _held(pid, "missing record -> ApprovalRecordMissingError")
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
        return
    _break(pid, "missing record ACCEPTED")


def P4e():
    """Client update_state arg-tampering cannot smuggle a different action
    past the queue: execute_approved runs the QUEUED (approved) args."""
    pid = "P4e-lg-arg-tamper-no-smuggle"
    ctx = _make_run()
    binding = _coder_binding(ctx)
    intr = _queued_call(ctx, binding,
                        args={"path": "/tmp/lg-approved.txt",
                              "content": "ok"})
    aid = intr.payloads[0]["approval_id"]
    ctx["executor"].approvals.decide(aid, True, reason="human ok",
                                     decided_by="human-operator")
    intr.resume_value = {"approval_id": aid}
    # Attacker-controlled client changed the node's arguments between
    # pause and resume (via update_state on another state key).
    outcome, record = LG_SHIM.governed_tool_call(
        binding, "write_file",
        {"path": "/tmp/lg-tampered.txt", "content": "evil"},
        interrupt=intr, prior_approval_id=aid)
    if outcome != "approved":
        _break(pid, "want approved, got %r" % (outcome,))
        return
    done = binding.executor.execute_approved()
    if not done:
        _break(pid, "nothing executed after approval")
        return
    seen_paths = set()
    for e in ctx["read_log"]():
        if e.get("event") == "tool_call" and e.get("tool") == "write_file":
            args = e.get("args") or {}
            if isinstance(args, dict) and "path" in args:
                seen_paths.add(args["path"])
    if "/tmp/lg-approved.txt" not in seen_paths:
        _break(pid, "approved action did not execute: %r" % (seen_paths,))
        return
    if "/tmp/lg-tampered.txt" in seen_paths:
        _break(pid, "TAMPERED args executed past the queue!")
        return
    _held(pid, "tampered node args cannot smuggle: sweep executed the "
               "QUEUED (approved) args")


def P4f():
    """Non-raising interrupt on first entry refused."""
    pid = "P4f-lg-nonraising-interrupt"
    ctx = _make_run()
    binding = _coder_binding(ctx)

    def _no_raise(payload):
        return "whatever"

    try:
        LG_SHIM.governed_tool_call(
            binding, "write_file", {"path": "/tmp/lg-q.txt", "content": "x"},
            interrupt=_no_raise)
    except LG_SHIM.ApprovalResumeError:
        _held(pid, "non-raising interrupt -> ApprovalResumeError")
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "wrong exception: %r" % (e,))
        return
    _break(pid, "non-raising interrupt ACCEPTED")


def P4g():
    """Non-dict arguments refused."""
    pid = "P4g-lg-nondict-args"
    ctx = _make_run()
    code = _code_of(lambda: LG_SHIM.governed_tool_call(
        _coder_binding(ctx), "write_file", ["not", "a", "dict"],
        interrupt=_StandInterrupt()))
    if code is None:
        _break(pid, "non-dict arguments accepted")
        return
    _held(pid, "non-dict arguments refused: %s" % (str(code)[:60],))


# ---------------------------------------------------------------------------
# P5: F424 / F425 live on this tree (expected BREAKs).
# ---------------------------------------------------------------------------

def _mint(store, sub="agent-9", now=2000):
    raw = {"sub": sub}
    ident = AI.normalize_claims(raw, "oidc")
    return store.mint_refresh(ident, "oidc", raw, now=now)


_RATE_POLICY_TEMPLATE = """\
version: 2
roles:
  worker: [http_post, api_call, read_file, send_email]
rate_limit:
  max_sends_per_run: 10000
  max_egress_bytes_per_run: 104857600
egress:
  domain_allowlist: [synthetic.local, localhost]
tool_rate_limits:
  http_post:
    window_secs: 60
    max_calls: 10
policies:
  - id: allow-worker-tools
    effect: allow
    match:
      tool: [http_post, api_call, read_file, send_email]
    reason: Battery allows worker tools.
"""


def _mkrun_rate():
    d = tempfile.mkdtemp(prefix="w337-redteam-",
                         dir=os.environ.get("TMPDIR") or "/var/tmp")
    p = os.path.join(d, "policy.yaml")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(_RATE_POLICY_TEMPLATE)
    try:
        from tests.harness import make_run
    except ImportError:
        from harness import make_run
    run = make_run(policy_path=p)
    ident = run["mint_identity"]("w1", "worker", "acme")
    return run, run["executor"], ident


def P5a():
    """F424 shape 1 (CLOSED): NaN lock_timeout_seconds refuses at
    construction with ValueError (fail-fast, wave-337 lane 1)."""
    pid = "P5a-f424-nan-uncoded"
    try:
        store = AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                     lock_timeout_seconds=float("nan"))
    except ValueError:
        _held(pid, "NaN refused at construction (F424 closed)")
        return
    issuer = AI.IdentityTokenIssuer(b"7" * 32)
    rid, secret = _mint(store)
    code = _code_of(lambda: store.refresh(issuer, rid, secret, "aud",
                                         now=2001))
    if code is None:
        _break(pid, "NaN timeout: refresh succeeded?!")
        return
    if code == "identity-refresh-lock-unavailable":
        _held(pid, "NaN refused coded (F424 closed)")
        return
    if str(code).startswith("UNEXPECTED"):
        _break(pid, "F424 OPEN: NaN -> uncoded %s" % (code,))
        return
    _break(pid, "F424 OPEN: NaN -> %r" % (code,))


def P5b():
    """F424 shape 2 (CLOSED): -1 lock_timeout_seconds refuses at
    construction with ValueError (fail-fast, wave-337 lane 1)."""
    pid = "P5b-f424-negative-hang"
    try:
        store = AI.RefreshTokenStore(time_fn=lambda: 2000.0,
                                     lock_timeout_seconds=-1)
    except ValueError:
        _held(pid, "negative timeout refused at construction (F424 closed)")
        return
    issuer = AI.IdentityTokenIssuer(b"7" * 32)
    rid, secret = _mint(store)
    lock = store._lock_for(rid)
    lock.acquire()
    done = []

    def worker():
        try:
            store.refresh(issuer, rid, secret, "aud", now=2001)
            done.append("finished")
        except Exception as e:  # noqa: BLE001
            done.append("raised:%r" % (e,))

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(4)
    lock.release()
    if done:
        if any("identity-refresh-lock-unavailable" in d for d in done):
            _held(pid, "negative timeout refused coded (F424 closed)")
        else:
            _break(pid, "negative timeout: contended acquire returned %r"
                   % (done,))
        return
    _break(pid, "F424 OPEN: -1 blocks forever under contention")


def P5c():
    """F425 (OPEN): raising clock escapes _check_tool_rate uncoded -- no
    coded tool-rate-limiter-unavailable, no chained refusal record."""
    pid = "P5c-f425-limiter-failure-uncoded"
    run, ex, ident = _mkrun_rate()

    def _boom():
        raise RuntimeError("synthetic clock failure")

    ex._tool_rate_wire._clock = _boom
    try:
        ex.call(ident, "http_post",
                url="https://synthetic.local/x0", body="b0")
    except TRL.ToolRateLimiterUnavailable as e:
        if e.code != "tool-rate-limiter-unavailable":
            _break(pid, "wrong code: %s" % (e.code,))
            return
    except Exception as e:  # noqa: BLE001
        _break(pid, "F425 OPEN: raw %r escaped uncoded" % (e,))
        return
    else:
        _break(pid, "call executed with a broken limiter (unlimited!)")
        return
    recs = [e for e in run["read_log"]()
            if e.get("decision") == "tool_call_refused"
            and e.get("flag") == "tool-rate-limiter-unavailable"]
    if not recs:
        _break(pid, "F425 OPEN: coded denial but no chained refusal record")
        return
    _held(pid, "broken limiter denies coded w/ chained record (F425 closed)")


# ---------------------------------------------------------------------------
# P6: honesty + regressions.
# ---------------------------------------------------------------------------

def P6a():
    """Pin 2106: taxonomy 2135/2135/0 sorted-unique on raw source
    literals (wave-260 lesson); 6 wave-335 codes registered."""
    pid = "P6a-pin-2131-taxonomy"
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    n = len(DC.TAXONOMY)
    if n != TAXONOMY_PIN or len(lits) != TAXONOMY_PIN:
        _break(pid, "taxonomy %d literals %d want %d"
               % (n, len(lits), TAXONOMY_PIN))
        return
    if lits != sorted(lits) or len(set(lits)) != len(lits):
        _break(pid, "taxonomy not sorted/unique on raw literals")
        return
    for c in ("identity-refresh-lock-unavailable",
              "evidence-pq-not-enabled", "evidence-pq-unknown-alg",
              "tool-rate-limit-exceeded", "tool-rate-limiter-unavailable",
              "tool-rate-limit-config-invalid"):
        if c not in DC.TAXONOMY:
            _break(pid, "code %r not centrally registered" % (c,))
            return
    _held(pid, "2135/2135/0 sorted-unique; 6 wave-335 codes registered")


def P6b():
    """Footer honesty: last line carries open none / next F430
    (raw-literal assertion, wave-331 lesson); F426 and F427 now CLOSED."""
    pid = "P6b-footer-open-f433-f434-f435-next-f436"
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              "rb") as f:
        lines = f.read().decode("utf-8").splitlines()
    last = lines[-1] if lines else ""
    if "Open findings: F469, F470, F471, F472." not in last:
        _break(pid, "last line lacks 'Open findings: F443.': %r"
               % (last[:160],))
        return
    if "Next free finding: **F473**" not in last:
        _break(pid, "last line lacks next-F436: %r" % (last[:160],))
        return
    for fnum in ("F424", "F425", "F426", "F427"):
        if not any(l.startswith("## " + fnum + " ") for l in lines):
            _break(pid, "%s section missing from FINDINGS.md" % (fnum,))
            return
    _held(pid, "footer honest: open none / next F430")


def P6c():
    """F423 (CLOSED wave-336): NUL in a PRM URL now refuses coded."""
    pid = "P6c-f423-nul-refused"
    code = _code_of(lambda: PRM.check_prm_url(
        "https://mcp.example/\x00x", "https://mcp.example.com/tools"))
    if code != "mcp-oauth-prm-malformed":
        _break(pid, "F423 regression: want mcp-oauth-prm-malformed, got %r"
               % (code,))
        return
    _held(pid, "F423 holds: NUL refused coded mcp-oauth-prm-malformed")


def P6d():
    """F417 regression: non-numeric URL port refuses coded."""
    pid = "P6d-f417-port-coded"
    code = _code_of(lambda: MOB._normalize_url(
        "https://as.example.com:abc/token", "as_issuer"))
    if code != "mcp-oauth-metadata-malformed":
        _break(pid, "F417 regression: want mcp-oauth-metadata-malformed, "
                    "got %r" % (code,))
        return
    _held(pid, "F417 holds: non-numeric port refused coded")


def P6e():
    """F421 regression: concurrent double-refresh -> exactly one wins."""
    pid = "P6e-f421-double-refresh"
    store = AI.RefreshTokenStore(time_fn=lambda: 2000.0)
    issuer = AI.IdentityTokenIssuer(b"9" * 32)
    rid, secret = _mint(store)
    results = []
    bar = threading.Barrier(2)

    def worker():
        bar.wait()
        try:
            store.refresh(issuer, rid, secret, "aud", now=2001)
            results.append("ok")
        except AI.IdentityTokenRejection as e:
            results.append(e.code)
        except Exception as e:  # noqa: BLE001
            results.append("UNEXPECTED:%r" % (e,))

    ts = [threading.Thread(target=worker) for _ in range(2)]
    [t.start() for t in ts]
    [t.join(10) for t in ts]
    if sorted(results) != ["identity-refresh-reuse-detected", "ok"]:
        _break(pid, "F421 regression: want exactly-one-win, got %r"
               % (results,))
        return
    _held(pid, "F421 holds: exactly one refresh wins")


_PROBES = [
    ("P1a-crewai-strict-schema-refused", P1a),
    ("P1b-crewai-allow-passes-smuggled-kwarg", P1b),
    ("P1c-crewai-schema-reassignment-refused", P1c),
    ("P1d-crewai-setattr-bypass-caught-at-mediation", P1d),
    ("P1e-crewai-positional-refused", P1e),
    ("P1f-crewai-config-vs-behavior-watch", P1f),
    ("P2a-ag2-malformed-args-event", P2a),
    ("P2b-ag2-denied-event", P2b),
    ("P2c-ag2-unregistered-event", P2c),
    ("P2d-ag2-executed-once", P2d),
    ("P2e-ag2-queued-event", P2e),
    ("P2f-ag2-composition-ordering-note", P2f),
    ("P3a-oai-guardrail-misattachment-certified", P3a),
    ("P3b-oai-correct-attachment-passes", P3b),
    ("P3c-oai-as-tool-refused", P3c),
    ("P3d-oai-hosted-refused", P3d),
    ("P3e-oai-handoff-refused", P3e),
    ("P3f-oai-malformed-args-tripwire", P3f),
    ("P3g-oai-expect-name-mismatch", P3g),
    ("P4a-lg-queued-pauses", P4a),
    ("P4b-lg-resume-mismatch", P4b),
    ("P4c-lg-premature-resume", P4c),
    ("P4d-lg-missing-record", P4d),
    ("P4e-lg-arg-tamper-no-smuggle", P4e),
    ("P4f-lg-nonraising-interrupt", P4f),
    ("P4g-lg-nondict-args", P4g),
    ("P5a-f424-nan-uncoded", P5a),
    ("P5b-f424-negative-hang", P5b),
    ("P5c-f425-limiter-failure-uncoded", P5c),
    ("P6a-pin-2131-taxonomy", P6a),
    ("P6b-footer-open-f433-f434-f435-next-f436", P6b),
    ("P6c-f423-nul-refused", P6c),
    ("P6d-f417-port-coded", P6d),
    ("P6e-f421-double-refresh", P6e),
]

# F426 filed by this battery (P3a). F424 (P5a/P5b) and F425 (P5c) remain
# open on this tree. Expected tally: 4 BREAK / 30 HELD / 0 ERROR.
_EXPECTED_BREAKS = set()  # never {} (wave-331 lesson); breaks documented above


def _run_root():
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    root = os.path.join(base, "w337-redteam")
    os.makedirs(root, exist_ok=True)
    return root


_CHILD_BATTERIES = [
    # w336_attack_probes.py excluded: model driver (no API spend here).
    # Tallies verified empirically on the wave-337 merged tree with
    # GOV_SKIP_GREEN=1 (the GREEN-SKIPPED record counts as one HELD).
    # F424/F425 closed: w336_redteam 0/28/0, w336_f423 0/7/0.
    ("w336_f423_probes.py", 0, "0/7/0"),
    ("w336_redteam_probes.py", 0, "0/28/0"),
]


def _run_child_output(name):
    """Run an adjacent battery's main with green checks skipped
    (depth-1 green checks) and return its stdout tail."""
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    root = _run_root()
    sub = os.path.join(root, "child-%s" % name)
    os.makedirs(sub, exist_ok=True)
    env["TMPDIR"] = sub
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", name)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=900)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-4:])
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", tail)
    if m is None:
        m = re.search(r"(\d+)/(\d+)/(\d+) \(break/held/error\)", tail)
    return m, tail


def _green_check():
    """Depth-1 green checks over the wave-336 child batteries."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("GREEN-SKIPPED", "HELD",
                "green check skipped (child mode)")
        return
    for name, want_breaks, want_tuple in _CHILD_BATTERIES:
        pid = "GREEN-" + name.replace(".py", "")
        m, tail = _run_child_output(name)
        if m is None:
            _record(pid, "ERROR", "no B/H/E tuple in child output:\n%s"
                    % tail)
            continue
        b, h, e = int(m.group(1)), int(m.group(2)), int(m.group(3))
        got = "%d/%d/%d" % (b, h, e)
        if got != want_tuple or b != want_breaks:
            _record(pid, "BREAK",
                    "child drift: got %s, want %s:\n%s" % (got, want_tuple,
                                                           tail))
        else:
            _record(pid, "HELD", "child %s as expected" % got)


def _summary():
    b = sum(1 for _, v, _ in _results if v == "BREAK")
    h = sum(1 for _, v, _ in _results if v == "HELD")
    e = sum(1 for _, v, _ in _results if v == "ERROR")
    return b, h, e


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    only = [a for a in argv if not a.startswith("-")]
    todo = _PROBES
    if only:
        matched = []
        for want in only:
            hits = [(pid, fn) for pid, fn in _PROBES
                    if pid == want or pid.startswith(want + "-")]
            if not hits:
                print("unknown probe id: %r" % (want,))
                return 1
            matched.extend(hits)
        todo = matched
    _key()
    _run_root()
    for pid, fn in todo:
        _safe(pid, fn)
    _green_check()
    b, h, e = _summary()
    print("\nw337_redteam: %d/%d/%d (break/held/error)" % (b, h, e))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
