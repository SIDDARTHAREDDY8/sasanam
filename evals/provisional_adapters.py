"""Provisional interception-adapter shims (TEAM ADVERSARY).

PROVISIONAL: gov/adapters/README.md does not exist yet. These shims define
the minimal interface the adversary harness needs; the coordinator must
reconcile them with the real Mediation API. See ADAPTER_INTERFACE.md.

Every shim is deliberately thin: framework convention -> executor.call().
The evals prove that no framework path can reach a side effect without
passing through the governance pipeline.
"""

from gov.executor import ToolExecutor  # noqa: F401  (documents the contract)


class ProvisionalAdapter:
    """Base: canonical mediated entry shared by all four shims."""

    name = "base"

    def __init__(self, executor, identity, registry=None):
        self.executor = executor
        self.identity = identity
        # Pinned tool registry for name-resolving adapters (MCP).
        # Maps (server, advertised_name) -> governed tool name.
        self.registry = dict(registry or {})

    def call(self, tool, **kwargs):
        """Canonical entry: straight to the governance pipeline."""
        return self.executor.call(self.identity, tool, **kwargs)


class DecoratorAdapter(ProvisionalAdapter):
    """Wraps an agent's tool functions like a @governed decorator would."""

    name = "decorator"

    def wrap(self, tool):
        def _governed_tool(**kwargs):
            return self.call(tool, **kwargs)

        _governed_tool.__name__ = "governed_%s" % tool
        return _governed_tool


class LangChainShim:
    """Mimics a LangChain Tool bound to governance."""

    adapter_name = "langchain"

    def __init__(self, name, adapter):
        self.tool_name = name
        self.adapter = adapter

    def invoke(self, payload):
        # Payload-shape validation BEFORE mediation: arg smuggling via a
        # non-dict payload must not reach the executor as opaque kwargs.
        if not isinstance(payload, dict) or not isinstance(
                payload.get("args"), dict):
            return {"status": "denied",
                    "reason": "langchain shim: payload must be "
                              "{'args': {...}}; refused before mediation",
                    "policy_id": "adapter-payload-shape"}
        # Call the BASE canonical entry directly: adapter.call() routes back
        # through the shim (payload-shape validation), which would recurse.
        return ProvisionalAdapter.call(self.adapter, self.tool_name,
                                       **payload["args"])


class LangChainAdapter(ProvisionalAdapter):
    name = "langchain"

    def tool(self, name):
        return LangChainShim(name, self)

    def call(self, tool, **kwargs):
        # Canonical path goes through the shim, like a real agent would.
        return self.tool(tool).invoke({"args": kwargs})


class MCPAdapter(ProvisionalAdapter):
    """Mimics an MCP client wrapper with a pinned tool registry."""

    name = "mcp"

    def call_tool(self, server, name, arguments):
        # ASI04: the server advertises names; the OPERATOR pins the mapping.
        # An unregistered name never reaches the executor.
        key = (server, name)
        if key not in self.registry:
            return {"status": "denied",
                    "reason": "mcp adapter: tool %r from server %r is not in "
                              "the pinned registry" % (name, server),
                    "policy_id": "adapter-registry-miss"}
        if not isinstance(arguments, dict):
            return {"status": "denied",
                    "reason": "mcp adapter: arguments must be an object",
                    "policy_id": "adapter-payload-shape"}
        return self.call(self.registry[key], **arguments)

    def call(self, tool, **kwargs):
        # Direct canonical path (used for non-MCP tools in mixed playbooks).
        return super().call(tool, **kwargs)


class OpenAILoopAdapter(ProvisionalAdapter):
    """Mimics an OpenAI-style function-calling loop."""

    name = "openai-loop"

    def run_tool_calls(self, calls):
        results = []
        for c in calls:
            if not isinstance(c, dict) or "name" not in c:
                results.append({"status": "denied",
                                "reason": "openai-loop: malformed tool call",
                                "policy_id": "adapter-payload-shape"})
                break
            r = ProvisionalAdapter.call(self, c["name"],
                                        **(c.get("arguments") or {}))
            results.append(r)
            if r.get("status") == "denied":
                break  # fail-fast: never continue blind past a denial
        return results

    def call(self, tool, **kwargs):
        return self.run_tool_calls(
            [{"name": tool, "arguments": kwargs}])[0]


ADAPTER_CLASSES = {
    "decorator": DecoratorAdapter,
    "langchain": LangChainAdapter,
    "mcp": MCPAdapter,
    "openai-loop": OpenAILoopAdapter,
}

# Default pinned MCP registry used by the evals. In production this is
# operator configuration, never server-advertised.
DEFAULT_MCP_REGISTRY = {
    ("rogue-search", "web_lookup"): "api_call",
    ("files", "read"): "read_file",
}
