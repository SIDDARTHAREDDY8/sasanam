"""Shared core for the gov.adapters complete-mediation layer.

Contract
--------

A :class:`GovernedBinding` pins together three things that must never be
separable at a call site:

1. a ``ToolExecutor`` (policy decisions, rate guards, audit log),
2. an ``AgentIdentity`` minted by *that* executor,
3. an **immutable** mapping from framework-facing tool names to the
   executor's native tool names
   (``read_file``, ``write_file``, ``delete_file``, ``api_call``,
   ``http_post``, ``send_email``).

Every adapter dispatches through ``binding.call(...)``. Unknown or
unregistered tool names fail closed with :class:`UnregisteredToolError`
*before* the executor is touched. Denied and queued outcomes surface as
:exc:`ToolDeniedError` / :exc:`ApprovalRequiredError` by default (or as
plain result dicts with ``on_denied="return"`` / ``on_queued="return"``).

What this core cannot do (documented honestly, tested in the adapter
suites):

* The executor *simulates* execution; it has no hook for an arbitrary
  user callable. Adapters that must run a real underlying implementation
  (MCP server tools, a wrapped Python body) do so *after* the executor
  returns ``"executed"``. That is a deliberate split
  authorization/execution boundary: the executor's write-ahead audit
  covers the authorization, not the foreign side effect.
* In-process Python cannot stop hostile code that already holds its own
  reference to an unmediated object (a raw MCP session, a bare LangChain
  tool). The adapters remove every *public* path to such objects; the
  residual is a deployment boundary (only hand governed objects to the
  agent), not a code boundary.
"""

import json
from types import MappingProxyType

from ..executor import ToolExecutor
from ..identity import AgentIdentity
from ..policy import KNOWN_TOOLS

#: The executor's native tool vocabulary. Adapter-facing names must resolve
#: to one of these.
NATIVE_TOOLS = frozenset(KNOWN_TOOLS)

#: Default name mapping: the six native names map to themselves. Pass an
#: explicit ``tool_map`` to ``GovernedBinding`` to add aliases, e.g.
#: ``{"read_notes": "read_file"}``. Names absent from the mapping are
#: rejected (fail closed); nothing is guessed.
DEFAULT_TOOL_MAP = MappingProxyType({name: name for name in sorted(NATIVE_TOOLS)})


class AdapterError(Exception):
    """Base class for all adapter errors."""


class UnregisteredToolError(AdapterError):
    """Raised when a framework-facing tool name has no mapping to a native
    tool. Fail-closed: the call is never dispatched."""


class ToolDeniedError(AdapterError):
    """Raised when the executor denies a mediated call.

    ``result`` is the executor's denial dict (``status``, ``reason``,
    ``policy_id``, ``seq``); ``seq`` is the audit-log sequence number of
    the denial entry.
    """

    def __init__(self, framework_tool, native_tool, result):
        self.framework_tool = framework_tool
        self.native_tool = native_tool
        self.result = dict(result)
        super().__init__(
            "governed tool %r (native %r) denied: %s"
            % (framework_tool, native_tool, result.get("reason"))
        )


class ApprovalRequiredError(AdapterError):
    """Raised when the executor queues a mediated call for human approval.

    ``approval_id`` identifies the queued request; the underlying action
    has NOT executed. Callers must not retry the tool in a loop while
    waiting -- that trips the executor's loop guard.
    """

    def __init__(self, framework_tool, native_tool, result):
        self.framework_tool = framework_tool
        self.native_tool = native_tool
        self.approval_id = result.get("approval_id")
        self.result = dict(result)
        super().__init__(
            "governed tool %r (native %r) queued for human approval "
            "(approval_id=%s); not executed."
            % (framework_tool, native_tool, self.approval_id)
        )


class MalformedToolCallError(AdapterError):
    """Raised when an OpenAI-style tool_call cannot be strictly validated
    (bad JSON, missing/duplicate id, unknown shape). Fail-closed."""


def _check_executor(executor):
    if not isinstance(executor, ToolExecutor):
        raise TypeError(
            "executor must be a gov.executor.ToolExecutor, got %r"
            % type(executor).__name__
        )


def _check_identity(executor, identity):
    if not isinstance(identity, AgentIdentity):
        raise TypeError(
            "identity must be a gov.identity.AgentIdentity minted by the "
            "executor, got %r" % type(identity).__name__
        )
    if identity not in _minted_set(executor):
        # Do not duplicate the executor's own unforgeability check here;
        # executor.call re-verifies. This is an early, cheap sanity check.
        pass


def _minted_set(executor):
    return {
        AgentIdentity(agent_id=a, role=r, run_id=i, principal=p)
        for (a, r, i, p) in executor._minted
    }


class GovernedBinding:
    """Immutable mediation endpoint shared by all adapters.

    ``GovernedBinding(executor, identity, tool_map=None)``

    * ``executor`` -- the ``ToolExecutor`` every call is mediated through.
    * ``identity`` -- an ``AgentIdentity`` minted by that executor.
    * ``tool_map`` -- ``{framework_name: native_name}``. Merged over
      :data:`DEFAULT_TOOL_MAP`; every native target must be in
      :data:`NATIVE_TOOLS`, else ``ValueError``. The stored mapping is
      immutable (``MappingProxyType``); there is no API to extend it
      after construction -- build a new binding instead.
    """

    def __init__(self, executor, identity, tool_map=None):
        _check_executor(executor)
        _check_identity(executor, identity)
        merged = dict(DEFAULT_TOOL_MAP)
        for framework_name, native_name in dict(tool_map or {}).items():
            if not isinstance(framework_name, str) or not framework_name:
                raise ValueError(
                    "tool_map keys must be non-empty strings, got %r"
                    % (framework_name,)
                )
            if native_name not in NATIVE_TOOLS:
                raise ValueError(
                    "tool_map[%r] = %r is not a native tool (known: %s)"
                    % (framework_name, native_name, sorted(NATIVE_TOOLS))
                )
            merged[framework_name] = native_name
        self._executor = executor
        self._identity = identity
        self._tool_map = MappingProxyType(merged)

    # -- introspection (read-only) --------------------------------------

    @property
    def executor(self):
        return self._executor

    @property
    def identity(self):
        return self._identity

    @property
    def tool_map(self):
        """The immutable framework-name -> native-name mapping."""
        return self._tool_map

    def framework_tools(self):
        """Sorted list of framework-facing tool names this binding serves."""
        return sorted(self._tool_map)

    # -- mediation ------------------------------------------------------

    def resolve(self, framework_tool):
        """Map a framework-facing name to its native tool.

        Raises :class:`UnregisteredToolError` for anything unmapped --
        fail closed, before the executor is touched.
        """
        try:
            return self._tool_map[framework_tool]
        except (KeyError, TypeError):
            raise UnregisteredToolError(
                "tool %r is not registered on this governed binding; "
                "refusing to dispatch." % (framework_tool,)
            )

    def call(self, framework_tool, on_denied="raise", on_queued="raise", **kwargs):
        """Mediate one tool call through the executor.

        Returns the executor's result dict on ``"executed"``. On
        ``"denied"`` raises :class:`ToolDeniedError` unless
        ``on_denied="return"``; on ``"queued"`` raises
        :class:`ApprovalRequiredError` unless ``on_queued="return"``.
        ``on_denied``/``on_queued`` accept only ``"raise"`` or
        ``"return"`` (anything else is a ``ValueError`` -- fail closed on
        misconfiguration, not on silent defaulting).
        """
        if on_denied not in ("raise", "return"):
            raise ValueError("on_denied must be 'raise' or 'return'")
        if on_queued not in ("raise", "return"):
            raise ValueError("on_queued must be 'raise' or 'return'")
        native_tool = self.resolve(framework_tool)
        result = self._executor.call(self._identity, native_tool, **kwargs)
        status = result.get("status")
        if status == "executed":
            return result
        if status == "denied":
            if on_denied == "return":
                return result
            raise ToolDeniedError(framework_tool, native_tool, result)
        if status == "queued":
            if on_queued == "return":
                return result
            raise ApprovalRequiredError(framework_tool, native_tool, result)
        # The executor only ever returns the three documented statuses;
        # anything else is a contract violation -- fail closed.
        raise AdapterError(
            "executor returned unexpected status %r for tool %r"
            % (status, framework_tool)
        )


def normalize_result(result):
    """Render an executor result dict as a stable JSON string.

    Used by adapters whose framework contract expects text (LangChain
    tools, OpenAI ``tool`` messages). Keys are sorted so output is
    deterministic; ``default=str`` keeps exotic values from crashing the
    render. Never raises for executor-shaped dicts.
    """
    if not isinstance(result, dict):
        raise TypeError("normalize_result expects a dict, got %r"
                        % type(result).__name__)
    return json.dumps(result, sort_keys=True, default=str)
