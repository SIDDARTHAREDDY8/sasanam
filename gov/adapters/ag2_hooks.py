"""AG2 adapter: governance middleware for tool execution.

API note (verified against ag2 1.1.2, 2026-10-05): AG2 1.x replaced the
0.9 ``ConversableAgent`` ``hook_lists`` API (``process_all_messages_...``,
``execute_function``) with a middleware pipeline. The functional
successor of the hook system is ``BaseMiddleware.on_tool_execution``,
which wraps every tool call before the tool's own implementation runs.
This module targets the 1.x middleware API -- the API a current
``pip install ag2`` provides. The 0.9 hook API is superseded and is not
shimmed.

Two registration points, same enforcement:

* **Per-tool** -- :func:`governed_tool_middleware` returns a
  ``ToolMiddleware`` for ``FunctionTool.with_middleware(...)``: only the
  named tool's executions are mediated.
* **Agent-wide** -- :class:`GovernedAgentMiddleware` (a
  ``BaseMiddleware``) mediates every tool execution of the agent.
  Register with AG2's factory::

      from ag2.middleware import Middleware
      agent = Agent(..., middleware=[Middleware(GovernedAgentMiddleware,
                                                binding=binding)])

In both cases the call is mediated through a
:class:`~gov.adapters.core.GovernedBinding` *before* the tool's
implementation runs. Denied, queued-for-approval, and unregistered
calls never reach the implementation: the middleware returns a
``ToolErrorEvent`` carrying the adapter error (``ToolDeniedError`` /
``ApprovalRequiredError`` / ``UnregisteredToolError``), which is how
AG2 surfaces tool failures to the model. The executor's audit log
records every attempt, including the refusals.

Fail-closed properties:

* The binding is validated at middleware construction; a non-
  ``GovernedBinding`` raises ``TypeError`` immediately, not at first
  tool call.
* Malformed tool arguments (unparseable JSON, non-dict shapes,
  non-string keys) become a coded ``MalformedToolCallError`` carried in
  a ``ToolErrorEvent`` -- the tool never runs on inputs the binding
  could not see exactly.
* ``ag2`` missing at import time raises ``ImportError`` naming the
  ``'ag2'`` extra, same convention as the other framework adapters.

* Invocation plugins (ag2 1.1.2: plugins passed per-turn via
  ``additional_plugins``) contribute tools for ONE turn only. AG2's
  ``_drive_scope`` chains those tools into the same tool set and
  registers them through the same ``ToolExecutor`` + agent-middleware
  chain, so :class:`GovernedAgentMiddleware.on_tool_execution`
  mediates them by name exactly like declared tools -- the operator
  never sees them at agent construction time, but mediation is
  identical. :func:`audit_turn_plugins` audits a turn's plugin set
  BEFORE the turn starts: every contributed name must resolve through
  the binding, and no name may collide (AG2's ``resolve_tools`` keeps
  exactly one tool per name, later-in-code wins with a warning).

Residual limitations (see ``gov/adapters/README.md``): in-process
Python cannot stop code holding its own unmediated reference (a bare
``FunctionTool`` not registered with the middleware, a direct call to
the wrapped Python function). Only hand governed tools / middleware-
registered agents to agent code. A plugin-contributed ``FunctionTool``
may also carry its OWN tool-level middleware; tool-level middleware
wraps INSIDE the agent middleware chain (closest to the tool), so it
observes/mutates arguments AFTER our ``on_tool_execution``
mediation -- same split-authorization/execution residual class as the
executor below: mediation authorizes the arguments as AG2 presented
them, and in-process code downstream of the mediation point cannot be
re-authorized. The executor simulates tools; on
``"executed"`` the real tool implementation still runs after the
audited authorization (split authorization/execution).
"""

try:
    from ag2.events import ToolCallEvent, ToolErrorEvent
    from ag2.middleware import BaseMiddleware
except ImportError as _exc:
    raise ImportError(
        "gov.adapters.ag2_hooks requires the 'ag2' extra "
        "(ag2, verified against 1.1.x). Install it with "
        "`pip install agent-governance[ag2]`."
    ) from _exc

from .core import (
    AdapterError,
    ApprovalRequiredError,
    GovernedBinding,
    GovernedToolFacade,
    MalformedToolCallError,
    ToolDeniedError,
    UnregisteredToolError,
)


def _extract_arguments(event):
    """Return the tool arguments as a plain dict, fail closed.

    ``ToolCallEvent.arguments`` is a JSON string; ``serialized_arguments``
    parses it. Anything unparseable, non-dict, or carrying non-string
    keys refuses coded -- the binding must see exactly the inputs the
    tool would receive.
    """
    if not isinstance(event, ToolCallEvent):
        raise MalformedToolCallError(
            "AG2 middleware expected a ToolCallEvent, got %r"
            % type(event).__name__)
    name = event.name
    if not isinstance(name, str) or not name:
        raise MalformedToolCallError(
            "AG2 tool call has no usable name: %r" % (name,))
    try:
        arguments = event.serialized_arguments
    except Exception as exc:
        raise MalformedToolCallError(
            "AG2 tool call %r carries unparseable arguments: %s"
            % (name, exc))
    if not isinstance(arguments, dict):
        raise MalformedToolCallError(
            "AG2 tool call %r arguments are not a JSON object: %r"
            % (name, type(arguments).__name__))
    for key in arguments:
        if not isinstance(key, str):
            raise MalformedToolCallError(
                "AG2 tool call %r has a non-string argument key: %r"
                % (name, key))
    return name, dict(arguments)


def _refusal_event(event, error):
    """Surface an adapter refusal the way AG2 surfaces tool failures."""
    return ToolErrorEvent.from_call(event, error)


class GovernedToolMiddleware:
    """Per-tool AG2 middleware enforcing governance before execution.

    A ``ToolMiddleware``-compatible callable: ``await mw(call_next,
    event, context)``. Register on one tool via
    ``FunctionTool.with_middleware(governed_tool_middleware(binding))``.

    The tool's own implementation (``call_next``) runs only after the
    binding returns ``"executed"``. Denied / queued / unregistered /
    malformed calls return a ``ToolErrorEvent`` instead -- the
    implementation is never invoked.
    """

    def __init__(self, binding):
        if not isinstance(binding, GovernedBinding):
            raise TypeError("binding must be a GovernedBinding, got %r"
                            % type(binding).__name__)
        # F31: hold the restricted facade, not the full binding.
        self._facade = binding.facade()

    @property
    def facade(self):
        """The restricted mediation facade (read-only)."""
        return self._facade

    async def __call__(self, call_next, event, context):
        try:
            name, arguments = _extract_arguments(event)
        except MalformedToolCallError as exc:
            return _refusal_event(event, exc)
        try:
            # on_denied/on_queued="raise": refusals surface as
            # exceptions here so they can be converted to the AG2-native
            # ToolErrorEvent below. The tool implementation never runs.
            self._facade.call(name, **arguments)
        except (ToolDeniedError, ApprovalRequiredError,
                UnregisteredToolError) as exc:
            return _refusal_event(event, exc)
        return await call_next(event, context)


def governed_tool_middleware(binding):
    """Build a per-tool AG2 middleware for ``binding``.

    Use: ``tool.with_middleware(governed_tool_middleware(binding))``.
    Fail-closed at construction: a non-``GovernedBinding`` raises
    ``TypeError`` immediately.
    """
    return GovernedToolMiddleware(binding)


class GovernedAgentMiddleware(BaseMiddleware):
    """Agent-wide AG2 middleware: mediates every tool execution.

    Register via AG2's factory::

        from ag2.middleware import Middleware
        Agent(..., middleware=[Middleware(GovernedAgentMiddleware,
                                          binding=binding)])

    ``on_tool_execution`` delegates to the same per-tool enforcement as
    :class:`GovernedToolMiddleware`; the only difference is scope (every
    tool of the agent vs one tool).
    """

    def __init__(self, event, context, binding):
        super().__init__(event, context)
        if not isinstance(binding, GovernedBinding):
            raise TypeError("binding must be a GovernedBinding, got %r"
                            % type(binding).__name__)
        self._tool_middleware = GovernedToolMiddleware(binding)

    async def on_tool_execution(self, call_next, event, context):
        return await self._tool_middleware(call_next, event, context)


class PluginToolCollisionError(AdapterError):
    """Raised by :func:`audit_turn_plugins` when two AG2 tools answer
    one name in a single turn's tool set.

    AG2's ``resolve_tools`` keeps exactly one tool per name
    (later-in-code wins with a warning; a remote peer's tool never
    overrides one declared in code). A collision means the governed
    tool the operator audited may silently not be the one answering
    the call. Fail closed: refuse the turn's plugin set instead of
    guessing which implementation AG2 kept."""


def _plugin_tool_names(plugin):
    """Duck-typed tool-name extraction for an AG2 ``Plugin``.

    The real ``ag2.Plugin`` collects contributed tools in ``._tools``
    (``FunctionTool`` instances with ``.name``); tests and minimal
    integrations may pass stand-ins with the same shape.
    """
    tools = getattr(plugin, "_tools", None)
    if tools is None:
        raise MalformedToolCallError(
            "audit_turn_plugins expected a Plugin carrying _tools, got "
            "%r" % type(plugin).__name__)
    names = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not isinstance(name, str) or not name:
            raise MalformedToolCallError(
                "a plugin-contributed tool has no usable name: %r"
                % (tool,))
        names.append(name)
    return names


def audit_turn_plugins(binding, plugins, declared_tools=()):
    """Pre-turn audit of AG2 invocation plugins (verified against
    ag2 1.1.2).

    Invocation plugins (``additional_plugins`` on a turn) contribute
    tools/middleware/prompts/observers/policies/variables for ONE
    turn only. AG2's ``_drive_scope`` chains the contributed tools
    into the turn's tool set and registers them through the same
    ``ToolExecutor`` + agent-middleware chain as the agent's own
    tools, so :class:`GovernedAgentMiddleware` mediates them by name
    exactly like declared tools -- but the operator never sees them
    at agent construction time. This audit closes the pre-turn gap:

    * every plugin tool name must resolve through ``binding``
      (:exc:`UnregisteredToolError` -- the same fail-closed refusal
      the middleware returns at call time, surfaced before the turn
      starts instead of at first invocation);
    * no name may appear twice across the plugin set, and no plugin
      tool may collide with a declared agent tool
      (:exc:`PluginToolCollisionError` -- AG2's ``resolve_tools``
      keeps one tool per name, later-in-code wins with a warning; the
      audit refuses rather than silently letting the governed
      implementation lose).

    ``declared_tools`` are the agent's own tools (duck-typed, ``.name``
    or plain names). Returns ``{"plugins": n, "mediated":
    sorted(names)}`` on success.
    """
    if not isinstance(binding, GovernedBinding):
        raise TypeError("binding must be a GovernedBinding, got %r"
                        % type(binding).__name__)
    plugins = list(plugins or [])
    declared_names = []
    for tool in declared_tools or ():
        declared_names.append(getattr(tool, "name", tool))

    seen = {}
    mediated = []
    unregistered = []
    for index, plugin in enumerate(plugins):
        for name in _plugin_tool_names(plugin):
            if name in seen or name in declared_names:
                raise PluginToolCollisionError(
                    "invocation plugin %d contributes tool %r which "
                    "collides with %r; AG2 keeps one tool per name, "
                    "so the governed implementation may silently not "
                    "be the one answering the call -- refusing the "
                    "turn's plugin set." % (index, name,
                                            seen.get(name,
                                                     "a declared tool")))
            seen[name] = "plugin %d" % index
            try:
                binding.resolve(name)
            except UnregisteredToolError:
                unregistered.append(name)
                continue
            mediated.append(name)
    if unregistered:
        raise UnregisteredToolError(
            "invocation plugin(s) contribute tool(s) with no binding "
            "mapping: %s; they would refuse at first call -- refusing "
            "the turn's plugin set before the turn starts."
            % ", ".join(sorted(set(unregistered))))
    return {"plugins": len(plugins),
            "mediated": sorted(mediated)}


__all__ = [
    "GovernedAgentMiddleware",
    "GovernedToolMiddleware",
    "PluginToolCollisionError",
    "audit_turn_plugins",
    "governed_tool_middleware",
]
