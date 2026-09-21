"""MCP adapter: a governed wrapper around an MCP client session.

``GovernedMCPClient`` wraps an ``mcp.ClientSession`` (or any object with
the same ``call_tool`` / ``list_tools`` coroutine interface). The only
tool-invocation path it exposes is its own ``call_tool`` coroutine:

1. the requested ``name`` is resolved through the binding's tool map
   (unregistered names -> :class:`UnregisteredToolError`, fail closed);
2. the executor mediates the call (identity, role, DLP, rate guards,
   policy, audit log);
3. only on ``"executed"`` is the underlying session's ``call_tool``
   invoked; denials and queued approvals raise *without ever touching*
   the session.

The raw session is stored name-mangled (``_GovernedMCPClient__session``)
and **no public accessor, property, or method exposes it**. ``dir()``
on the client shows no ``session`` attribute.

Execution model
---------------
The executor authorizes and logs, then the real MCP server executes --
a deliberate **split authorization/execution** boundary (the executor
cannot host arbitrary server implementations). The executor's
simulated result is *not* returned; the server's ``CallToolResult`` is.
What the executor *does* guarantee: nothing reaches the server unless
the full governance pipeline allowed it, and every attempt -- allowed,
denied, or queued -- is in the tamper-evident log.

Residual limitation: code that already holds its own reference to the
raw session can call ``session.call_tool`` directly. In-process Python
cannot prevent that; the deployment rule is to never hand the raw
session to agent code -- only the governed client.
"""

from .core import GovernedBinding


class GovernedMCPClient:
    """Mediated façade over an MCP client session.

    ``GovernedMCPClient(binding, session)``

    * ``binding`` -- the :class:`GovernedBinding` used for mediation.
    * ``session`` -- the underlying MCP ``ClientSession`` (or test
      double). Stored privately; never exposed.
    """

    def __init__(self, binding, session):
        if not isinstance(binding, GovernedBinding):
            raise TypeError("binding must be a GovernedBinding, got %r"
                            % type(binding).__name__)
        if session is None:
            raise TypeError("session must not be None")
        call_tool = getattr(session, "call_tool", None)
        if not callable(call_tool):
            raise TypeError(
                "session must expose a callable 'call_tool', got %r"
                % type(session).__name__)
        self._binding = binding
        self.__session = session  # name-mangled: no public path to it

    @property
    def binding(self):
        return self._binding

    @property
    def framework_tools(self):
        """Tool names this client will mediate (from the binding)."""
        return self._binding.framework_tools()

    async def call_tool(self, name, arguments=None, **session_kwargs):
        """Mediate one MCP tool call.

        ``name`` is resolved through the binding's tool map, then the
        executor mediates ``(native_tool, **arguments)``. On
        ``"executed"`` the underlying session's ``call_tool`` runs with
        the *framework-facing* ``name`` and the original ``arguments``,
        and its result is returned verbatim. Denials raise
        :class:`ToolDeniedError`; queued approvals raise
        :class:`ApprovalRequiredError`; unregistered names raise
        :class:`UnregisteredToolError` -- all before the session is
        touched.

        ``session_kwargs`` are forwarded to the underlying
        ``session.call_tool`` only (never to the executor): things like
        ``read_timeout_seconds``. They are validated to be
        keyword-only; governance-relevant routing stays with the
        binding.
        """
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise TypeError("arguments must be a dict, got %r"
                            % type(arguments).__name__)
        # Mediate FIRST. Any exception below means the session is never
        # touched: no side effect, no network, nothing.
        mediated = self._binding.call(name, **dict(arguments))
        if mediated.get("status") != "executed":
            # binding.call with defaults raises on denied/queued, so this
            # is unreachable -- kept as a fail-closed belt-and-braces.
            raise RuntimeError(
                "binding returned non-executed status without raising; "
                "refusing to call the MCP session.")
        return await self.__session.call_tool(
            name, arguments, **session_kwargs)

    async def list_tools(self):
        """Pass through the session's tool listing (read-only metadata).

        Listing is *not* policy-mediated: it performs no action and takes
        no arguments. Invoke tools only via :meth:`call_tool`.
        """
        list_tools = getattr(self.__session, "list_tools", None)
        if not callable(list_tools):
            raise TypeError("underlying session has no callable 'list_tools'")
        return await list_tools()


class DeterministicFakeSession:
    """In-process MCP session double for tests and demos.

    Implements the ``call_tool`` / ``list_tools`` coroutine interface
    with canned, deterministic results -- no network, no subprocesses.
    ``calls`` records every ``(name, arguments)`` pair the double
    received, so tests can assert the session was (or was not) touched.
    """

    def __init__(self, results=None):
        # results: {tool_name: result}. Missing names get a canned echo.
        self._results = dict(results or {})
        self.calls = []

    async def call_tool(self, name, arguments=None, **kwargs):
        self.calls.append((name, dict(arguments or {})))
        if name in self._results:
            return self._results[name]
        return {"echo": name, "arguments": dict(arguments or {})}

    async def list_tools(self):
        return [{"name": name} for name in self._results]
