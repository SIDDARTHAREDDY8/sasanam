"""Real-adapter shims for the adversary harness (TEAM ADVERSARY).

Reconciliation layer: wraps the REAL gov.adapters (GovernedBinding
contract) in the same interface the provisional shims expose, so every
matrix cell runs against BOTH harnesses:

    provisional -> evals/provisional_adapters.py (fallback column)
    real        -> this file (gov.adapters.core/generic/langchain_tools/
                   mcp_adapter/openai_loop)

Interface parity with provisional_adapters.py (what run_evals.py uses):

    RealAdapter.name                          # "decorator" | "langchain" |
                                              # "mcp" | "openai-loop"
    RealAdapter(executor, identity, registry=None)
    .call(tool, **kwargs) -> dict             # executor result dict
    decorator:  .wrap(tool)(**kwargs)
    langchain:  .tool(name).invoke({"args": kwargs})
    mcp:        .call_tool(server, name, arguments)
    openai-loop: .run_tool_calls([{"name":..., "arguments": {...}}])[0]

Adapter exceptions are converted to result dicts so the checkers see the
same vocabulary in both columns:

    UnregisteredToolError -> {"status": "denied",
                              "policy_id": "adapter-registry-miss", ...}
    MalformedToolCallError -> {"status": "denied",
                               "policy_id": "adapter-payload-shape", ...}
    ToolDeniedError / ApprovalRequiredError -> the executor's own dict
        (status denied / queued, with approval_id where present).

Design notes (reconciliation findings, see ADAPTER_INTERFACE.md):

* The real MCP client only runs the underlying session on "executed" and
  returns the SERVER's result verbatim. This shim reports
  {"status": "executed", "server_result": ...} so checkers keep working;
  the DeterministicFakeSession records whether the session was touched.
* The real openai-loop speaks OpenAI wire format (tool_calls with
  id/type/function). This shim translates the provisional
  [{"name","arguments"}] shape into wire format and parses the appended
  "tool"-role messages back into result dicts.
* langchain-core DROPS all arguments when args_schema declares no fields
  (its "no args" fast path). This shim declares every native-tool kwarg
  explicitly and strips None-valued kwargs before mediation, because the
  executor crashes on path=None (TypeError in _is_outside_sandbox).
"""

import asyncio
import json

from pydantic import BaseModel

from gov.adapters.core import (
    AdapterError,
    ApprovalRequiredError,
    GovernedBinding,
    MalformedToolCallError,
    ToolDeniedError,
    UnregisteredToolError,
    normalize_result,
)
from gov.adapters.generic import governed
from gov.adapters.langchain_tools import make_governed_tool
from gov.adapters.mcp_adapter import (
    DeterministicFakeSession,
    GovernedMCPClient,
)
from gov.adapters.openai_loop import run_tool_loop


def _exc_to_dict(exc):
    """Convert a real-adapter exception to a provisional-shaped dict."""
    if isinstance(exc, (ToolDeniedError, ApprovalRequiredError)):
        return dict(exc.result)
    if isinstance(exc, UnregisteredToolError):
        return {"status": "denied", "reason": str(exc),
                "policy_id": "adapter-registry-miss"}
    if isinstance(exc, MalformedToolCallError):
        return {"status": "denied", "reason": str(exc),
                "policy_id": "adapter-payload-shape"}
    if isinstance(exc, AdapterError):
        return {"status": "denied", "reason": str(exc),
                "policy_id": "adapter-error"}
    raise exc


class RealAdapterBase:
    """Base: one GovernedBinding per (executor, identity, registry)."""

    name = "base"

    def __init__(self, executor, identity, registry=None):
        # Flatten the provisional (server, advertised) registry into the
        # binding's flat framework-name -> native-name tool_map.
        tool_map = {}
        for (server, adv_name), native in dict(registry or {}).items():
            tool_map["%s:%s" % (server, adv_name)] = native
        self.executor = executor
        self.identity = identity
        self.registry = dict(registry or {})
        self.binding = GovernedBinding(executor, identity,
                                       tool_map=tool_map or None)

    def call(self, tool, **kwargs):
        try:
            return self.binding.call(tool, on_denied="return",
                                     on_queued="return", **kwargs)
        except AdapterError as exc:
            return _exc_to_dict(exc)


class RealDecoratorAdapter(RealAdapterBase):
    """@governed decorator path (gov.adapters.generic)."""

    name = "decorator"

    def wrap(self, tool):
        # run_body=False (default): the body never runs; the executor's
        # result dict is the whole outcome.
        return governed(self.binding, tool=tool,
                        on_denied="return",
                        on_queued="return")(lambda **kw: None)


class _GovArgsSchema(BaseModel):
    """Every native-tool kwarg, declared.

    langchain-core treats a field-less schema as "no args" and silently
    drops all input, so every kwarg the matrix playbooks use must be a
    declared field here. Unset fields validate as None and are stripped
    before mediation (the executor crashes on path=None).
    """
    path: str | None = None
    content: str | None = None
    endpoint: str | None = None
    params: dict | None = None
    url: str | None = None
    payload: dict | None = None
    to: str | None = None
    subject: str | None = None
    body: str | None = None
    justification: str | None = None
    on_behalf_of: str | None = None
    delegated_by: str | None = None


class _RealLangChainTool:
    """Provisional-shaped invoke() over a real GovernedStructuredTool."""

    def __init__(self, tool):
        self._tool = tool
        # Strip None-valued kwargs: langchain-core's _parse_input injects
        # explicit defaults (None) for undeclared-at-call-time fields, and
        # the executor cannot take path=None. orig_run is the BOUND
        # method; the closure is stored as a plain instance attribute so
        # no extra self is injected.
        orig_run = tool._run

        def _run_stripped(*args, **kwargs):
            clean = {k: v for k, v in kwargs.items() if v is not None}
            return orig_run(*args, **clean)

        tool._run = _run_stripped

    def invoke(self, payload):
        if isinstance(payload, dict) and "args" in payload:
            if not isinstance(payload["args"], dict):
                return {"status": "denied",
                        "reason": "real langchain shim: payload must be "
                                  "{'args': {...}}; refused before mediation",
                        "policy_id": "adapter-payload-shape"}
            args = payload["args"]
        elif isinstance(payload, dict):
            args = payload
        else:
            return {"status": "denied",
                    "reason": "real langchain shim: payload must be "
                              "{'args': {...}}; refused before mediation",
                    "policy_id": "adapter-payload-shape"}
        try:
            raw = self._tool.invoke(args)
            return json.loads(raw)  # normalize_result JSON of the dict
        except AdapterError as exc:
            return _exc_to_dict(exc)


class RealLangChainAdapter(RealAdapterBase):
    """LangChain StructuredTool path (gov.adapters.langchain_tools)."""

    name = "langchain"

    def tool(self, name):
        try:
            tool = make_governed_tool(
                self.binding, name,
                description="governed tool %s" % name,
                args_schema=_GovArgsSchema)
        except AdapterError as exc:
            # Unregistered at construction (fail closed, like the real
            # adapter): return an invoker that always denies.
            denied = _exc_to_dict(exc)

            class _Denied:
                def invoke(self, payload):
                    return dict(denied)

            return _Denied()
        return _RealLangChainTool(tool)

    def call(self, tool, **kwargs):
        return self.tool(tool).invoke({"args": kwargs})


class RealMCPAdapter(RealAdapterBase):
    """MCP client path (gov.adapters.mcp_adapter). Async under the hood."""

    name = "mcp"

    def __init__(self, executor, identity, registry=None):
        super().__init__(executor, identity, registry)
        self.session = DeterministicFakeSession()
        self.client = GovernedMCPClient(self.binding, self.session)

    def call_tool(self, server, name, arguments):
        if not isinstance(arguments, dict):
            return {"status": "denied",
                    "reason": "real mcp shim: arguments must be an object",
                    "policy_id": "adapter-payload-shape"}
        flat = "%s:%s" % (server, name)
        try:
            server_result = asyncio.run(
                self.client.call_tool(flat, dict(arguments)))
        except AdapterError as exc:
            return _exc_to_dict(exc)
        # The real adapter returns the SERVER's result verbatim on
        # "executed"; the session was touched iff mediation allowed it.
        return {"status": "executed", "server_result": server_result,
                "policy_id": None}

    def call(self, tool, **kwargs):
        # Direct canonical path (used for non-MCP tools in mixed playbooks).
        return super().call(tool, **kwargs)


class RealOpenAILoopAdapter(RealAdapterBase):
    """OpenAI-style function-call loop (gov.adapters.openai_loop)."""

    name = "openai-loop"

    def run_tool_calls(self, calls):
        wire = []
        for i, c in enumerate(calls):
            if not isinstance(c, dict) or "name" not in c:
                return [{"status": "denied",
                         "reason": "real openai-loop shim: malformed tool "
                                   "call",
                         "policy_id": "adapter-payload-shape"}]
            try:
                arguments = json.dumps(c.get("arguments") or {})
            except (TypeError, ValueError) as exc:
                return [{"status": "denied",
                         "reason": "real openai-loop shim: arguments not "
                                   "JSON-serializable: %s" % exc,
                         "policy_id": "adapter-payload-shape"}]
            wire.append({"id": "call-%d" % i, "type": "function",
                         "function": {"name": c["name"],
                                      "arguments": arguments}})
        state = {"served": False}

        def respond(transcript):
            if state["served"]:
                return {"role": "assistant", "content": "done"}
            state["served"] = True
            return {"role": "assistant", "content": "",
                    "tool_calls": wire}

        try:
            out = run_tool_loop(self.binding,
                                [{"role": "user", "content": "proceed"}],
                                respond, on_denied="return",
                                on_queued="return")
        except AdapterError as exc:
            return [_exc_to_dict(exc)]
        results = []
        for m in out:
            if m.get("role") == "tool":
                try:
                    results.append(json.loads(m.get("content") or "{}"))
                except (TypeError, ValueError):
                    results.append({"status": "denied",
                                    "reason": "real openai-loop shim: "
                                              "unparseable tool message",
                                    "policy_id": "adapter-payload-shape"})
        # Fail-fast parity with the provisional shim: the playbooks only
        # ever send one call per run_tool_calls, but keep the contract.
        return results or [{"status": "denied",
                            "reason": "real openai-loop shim: no tool "
                                      "messages produced",
                            "policy_id": "adapter-payload-shape"}]

    def call(self, tool, **kwargs):
        return self.run_tool_calls(
            [{"name": tool, "arguments": kwargs}])[0]


REAL_ADAPTER_CLASSES = {
    "decorator": RealDecoratorAdapter,
    "langchain": RealLangChainAdapter,
    "mcp": RealMCPAdapter,
    "openai-loop": RealOpenAILoopAdapter,
}
