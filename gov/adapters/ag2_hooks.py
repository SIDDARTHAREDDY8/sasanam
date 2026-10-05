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

Residual limitations (see ``gov/adapters/README.md``): in-process
Python cannot stop code holding its own unmediated reference (a bare
``FunctionTool`` not registered with the middleware, a direct call to
the wrapped Python function). Only hand governed tools / middleware-
registered agents to agent code. The executor simulates tools; on
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


__all__ = [
    "GovernedAgentMiddleware",
    "GovernedToolMiddleware",
    "governed_tool_middleware",
]
