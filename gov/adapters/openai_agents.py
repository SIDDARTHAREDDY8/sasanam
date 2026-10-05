"""OpenAI Agents SDK adapter: native ``tool_input_guardrails`` shim.

Maps a :class:`~gov.adapters.core.GovernedBinding` onto the OpenAI Agents
SDK's native tool-guardrail pipeline (verified against openai-agents
0.23.1 source, MIT license -- patterns described, nothing copied):

* ``make_tool_input_guardrail(binding, framework_tool, ...)`` returns a
  guardrail *function* ``(data) -> ToolGuardrailFunctionOutput``. Pass it
  to the SDK as ``ToolInputGuardrail(guardrail_function=...)`` or via the
  SDK's ``@tool_input_guardrail`` decorator, then attach it to a
  ``@function_tool``'s ``tool_input_guardrails=[...]``. The SDK runs it
  before the function tool is invoked
  (``_execute_tool_input_guardrails`` in
  ``run_internal/tool_execution.py``) and honors the returned behavior:

  - executor ``"executed"`` -> ``allow`` (``output_info`` carries the
    coded decision: policy_id, seq, governance marker);
  - executor ``"denied"``   -> ``raise_exception`` by default: the SDK
    raises ``ToolGuardrailTripwireTriggered`` and halts the run
    (fail closed). With ``on_denied="return"`` -> ``reject_content``
    carrying the coded denial message so the model can react;
  - executor ``"queued"``   -> ``raise_exception`` by default, with
    ``output_info["approval_id"]``: the human decides via OUR
    ``ApprovalQueue`` (the durable, chained, auditable record) and the
    run is re-invoked afterwards. With ``on_queued="return"`` ->
    ``reject_content`` carrying the approval notice.
  - malformed tool arguments (not JSON, or JSON that is not an object)
    -> ``raise_exception`` fail-closed. The SDK hands guardrails the RAW
    arguments string (``ToolContext.tool_arguments`` is set from
    ``tool_call.arguments`` *before* schema preparation), so there is no
    pre-guardrail filtering to audit around (no F62-class hole here);
    the shim parses strictly itself and every parsed kwarg reaches
    ``binding.call`` unmodified.

* ``audit_agent_coverage(agent, ...)`` fails closed
  (:exc:`UncoveredSurfaceError`) unless every execution surface of an SDK
  ``Agent`` is mediated: no handoffs, no non-``FunctionTool`` tools, no
  ``Agent.as_tool()`` nested tools, and every ``FunctionTool`` carries
  one of this module's issued guardrails.

The ``agents`` package is an OPTIONAL dependency: the shim works with
the real ``ToolGuardrailFunctionOutput`` when the SDK is installed and
with a behavior-compatible stand-in otherwise (``sdk_available()``).

RESIDUAL (honest boundary -- tested, not just documented): the SDK's
tool-guardrail pipeline runs ONLY for function tools. The following
never invoke this shim, and ``audit_agent_coverage`` refuses to certify
an agent that exposes them:

* hosted tools (``WebSearchTool``, ``FileSearchTool``,
  ``HostedMCPTool``, ``CodeInterpreterTool``, ``ImageGenerationTool``),
* built-in execution tools (``ComputerTool``, ``ShellTool``,
  ``ApplyPatchTool``, ``LocalShellTool``),
* handoffs (the receiving agent takes over the conversation outside any
  guardrail),
* ``Agent.as_tool()`` nested runs: the guardrail sees only the outer
  input string, never the nested tool calls (detected via the SDK's own
  ``_is_agent_tool`` marker, set by ``Agent.as_tool()``, or via
  deployment-declared names).

Those surfaces need separate enforcement points and must never be
described as covered by this shim.
"""

import json
import weakref

from .core import (
    AdapterError,
    GovernedBinding,
    UnregisteredToolError,
)

#: Tested honest-boundary contract: surfaces the SDK's tool-guardrail
#: pipeline NEVER covers. ``audit_agent_coverage`` refuses to certify an
#: agent exposing any of these; the strings are asserted by the test
#: suite so the documentation cannot silently stop naming them.
RESIDUAL_SURFACES = (
    "hosted tools (WebSearchTool, FileSearchTool, HostedMCPTool, "
    "CodeInterpreterTool, ImageGenerationTool): the SDK runs no "
    "tool_input_guardrails for them",
    "built-in execution tools (ComputerTool, ShellTool, ApplyPatchTool, "
    "LocalShellTool): outside the function-tool guardrail pipeline",
    "handoffs: the receiving agent takes over the conversation; no "
    "tool guardrail runs",
    "Agent.as_tool() nested runs: the guardrail sees only the outer "
    "input string, never the nested tool calls",
)

try:
    # Optional dependency: use the real output shape when installed.
    from agents.tool_guardrails import (  # noqa: F401
        ToolGuardrailFunctionOutput as _SDKOutput,
    )

    _HAVE_SDK = True
except ImportError:  # pragma: no cover - exercised via the stand-in path
    _HAVE_SDK = False


def sdk_available():
    """True when the ``agents`` (openai-agents) package is importable."""
    return _HAVE_SDK


class _StandInGuardrailOutput:
    """Behavior-compatible stand-in for the SDK's
    ``ToolGuardrailFunctionOutput`` (used when the ``agents`` package is
    not installed).

    The SDK's ``_execute_tool_input_guardrails`` only reads
    ``output.behavior["type"]`` (and ``behavior["message"]`` for
    rejections), so this shape works if it is ever handed to a real SDK.
    """

    def __init__(self, output_info, behavior):
        self.output_info = output_info
        self.behavior = dict(behavior)

    @classmethod
    def allow(cls, output_info=None):
        return cls(output_info, {"type": "allow"})

    @classmethod
    def reject_content(cls, message, output_info=None):
        return cls(output_info,
                   {"type": "reject_content", "message": message})

    @classmethod
    def raise_exception(cls, output_info=None):
        return cls(output_info, {"type": "raise_exception"})


def _output_factory():
    return _SDKOutput if _HAVE_SDK else _StandInGuardrailOutput


#: Registry of guardrail functions issued by this module (weak: guardrails
#: die with their deployments). ``audit_agent_coverage`` consults it.
_ISSUED_GUARDRAILS = weakref.WeakSet()


class UncoveredSurfaceError(AdapterError):
    """Raised by :func:`audit_agent_coverage` when an SDK agent exposes an
    execution surface this shim cannot mediate (hosted/built-in tools,
    handoffs, ``as_tool()`` nested runs, or a function tool without one
    of our guardrails). Fail closed: never certify partial coverage."""


def _extract_tool_context(data):
    """Return the tool context from SDK guardrail data, duck-typed.

    The SDK passes ``ToolInputGuardrailData`` (``.context`` is a
    ``ToolContext`` with ``.tool_name`` / ``.tool_arguments`` /
    ``.tool_call_id``). Tests and minimal integrations may pass the
    context object directly.
    """
    context = getattr(data, "context", data)
    tool_name = getattr(context, "tool_name", None)
    raw_arguments = getattr(context, "tool_arguments", None)
    if not isinstance(tool_name, str) or not tool_name:
        raise UncoveredSurfaceError(
            "guardrail received data without a tool name (%r); refusing "
            "to mediate an unidentified tool call." % (type(data).__name__,))
    if not isinstance(raw_arguments, str):
        raise UncoveredSurfaceError(
            "guardrail received non-string tool arguments for tool %r; "
            "refusing to guess their meaning." % (tool_name,))
    return tool_name, raw_arguments


def _parse_tool_arguments(raw_arguments):
    """Strict-parse the SDK's raw arguments string.

    Returns the argument dict, or None when the input is malformed
    (not JSON, or JSON that is not an object). Fail-closed: malformed
    input never reaches the executor and never executes.
    """
    try:
        parsed = json.loads(raw_arguments)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def make_tool_input_guardrail(binding, framework_tool, *,
                              on_denied="raise", on_queued="raise",
                              name=None, expect_sdk_tool_name=None):
    """Build an SDK ``tool_input_guardrails`` entry mediated by ``binding``.

    Parameters
    ----------
    binding : GovernedBinding
        Mediation endpoint. ``framework_tool`` must resolve through its
        tool map -- unregistered names raise :class:`UnregisteredToolError`
        here, at construction time (fail closed).
    framework_tool : str
        Binding-level tool name mediated by this guardrail.
    on_denied, on_queued : {"raise", "return"}
        ``"raise"`` (default): denied/queued calls produce the
        ``raise_exception`` behavior -- the SDK raises
        ``ToolGuardrailTripwireTriggered`` and halts the run (fail
        closed). ``"return"``: denied/queued calls produce
        ``reject_content`` with the coded notice, letting the model
        react and continue.
    name : str, optional
        Tracing name for the guardrail function (``__name__``).
    expect_sdk_tool_name : str, optional
        When given, the guardrail fails closed unless
        ``data.context.tool_name`` equals it -- catches the
        misconfiguration of attaching this guardrail to the wrong
        ``FunctionTool``.

    Returns a plain (sync -- the SDK accepts ``MaybeAwaitable``)
    function ``(data) -> ToolGuardrailFunctionOutput`` ready for
    ``ToolInputGuardrail(guardrail_function=...)`` or the SDK's
    ``@tool_input_guardrail`` decorator.

    The guardrail is registered in this module's issued-guardrail set so
    :func:`audit_agent_coverage` can verify its presence on an agent's
    function tools.
    """
    if not isinstance(binding, GovernedBinding):
        raise TypeError("binding must be a GovernedBinding, got %r"
                        % type(binding).__name__)
    binding.resolve(framework_tool)  # fail closed at construction time
    if on_denied not in ("raise", "return"):
        raise ValueError('on_denied must be "raise" or "return"')
    if on_queued not in ("raise", "return"):
        raise ValueError('on_queued must be "raise" or "return"')
    output_cls = _output_factory()

    def sasanam_tool_input_guardrail(data):
        tool_name, raw_arguments = _extract_tool_context(data)
        if (expect_sdk_tool_name is not None
                and tool_name != expect_sdk_tool_name):
            return output_cls.raise_exception({
                "governance": "sasanam",
                "error": "misconfigured_guardrail_attachment",
                "detail": ("guardrail built for SDK tool %r is attached "
                           "to SDK tool %r; refusing to mediate."
                           % (expect_sdk_tool_name, tool_name)),
            })
        arguments = _parse_tool_arguments(raw_arguments)
        if arguments is None:
            return output_cls.raise_exception({
                "governance": "sasanam",
                "error": "malformed_tool_arguments",
                "detail": ("tool %r supplied arguments that are not a "
                           "JSON object; failing closed." % (tool_name,)),
            })
        try:
            result = binding.call(framework_tool,
                                  on_denied="return", on_queued="return",
                                  **arguments)
        except AdapterError as exc:
            # Contract violation inside mediation (e.g. the executor
            # returned an undocumented status): fail closed via the
            # tripwire, never let the tool invoke. Non-AdapterError
            # exceptions (bugs) propagate loudly -- also fail-closed,
            # via a crashed run rather than a silent allow.
            return output_cls.raise_exception({
                "governance": "sasanam",
                "error": "mediation_error",
                "detail": str(exc),
            })
        status = result.get("status")
        if status == "executed":
            return output_cls.allow({
                "governance": "sasanam",
                "decision": "executed",
                "framework_tool": framework_tool,
                "policy_id": result.get("policy_id"),
                "seq": result.get("seq"),
            })
        if status == "denied":
            info = {
                "governance": "sasanam",
                "decision": "denied",
                "framework_tool": framework_tool,
                "policy_id": result.get("policy_id"),
                "reason": result.get("reason"),
                "seq": result.get("seq"),
            }
            if on_denied == "return":
                return output_cls.reject_content(
                    "Sasanam governance denied tool %r: %s"
                    % (framework_tool, result.get("reason")),
                    output_info=info)
            return output_cls.raise_exception(info)
        if status == "queued":
            info = {
                "governance": "sasanam",
                "decision": "queued",
                "framework_tool": framework_tool,
                "approval_id": result.get("approval_id"),
                "reason": result.get("reason"),
                "seq": result.get("seq"),
            }
            if on_queued == "return":
                return output_cls.reject_content(
                    "Sasanam governance queued tool %r for human approval "
                    "(approval_id=%s); it has NOT executed."
                    % (framework_tool, result.get("approval_id")),
                    output_info=info)
            return output_cls.raise_exception(info)
        # binding.call already fails closed on undocumented statuses, so
        # reaching here is unreachable; belt-and-braces.
        return output_cls.raise_exception({
            "governance": "sasanam",
            "error": "unexpected_mediation_status",
            "detail": "status=%r" % (status,),
        })

    if name:
        sasanam_tool_input_guardrail.__name__ = name
    _ISSUED_GUARDRAILS.add(sasanam_tool_input_guardrail)
    return sasanam_tool_input_guardrail


def _is_function_tool(tool):
    """Duck-typed FunctionTool check.

    Verified against openai-agents 0.23.1: ``FunctionTool`` is the only
    tool class in ``agents/tool.py`` defining ``tool_input_guardrails``;
    hosted tools (WebSearchTool, FileSearchTool, HostedMCPTool,
    CodeInterpreterTool, ImageGenerationTool) and built-in execution
    tools (ComputerTool, ShellTool, ApplyPatchTool, LocalShellTool) do
    not -- the SDK's guardrail pipeline never runs for them.
    """
    return hasattr(tool, "tool_input_guardrails")


def _is_issued_guardrail(entry):
    fn = getattr(entry, "guardrail_function", entry)
    return fn in _ISSUED_GUARDRAILS


def audit_agent_coverage(agent, *, nested_agent_tools=()):
    """Fail closed unless every execution surface of an SDK ``Agent`` is
    mediated by this shim.

    Inspects (duck-typed, so the ``agents`` package need not be
    installed):

    * ``agent.handoffs`` -- any handoff target is an uncovered surface
      (the SDK runs no tool guardrail for handoffs);
    * ``agent.tools`` -- every tool must be a ``FunctionTool``
      (duck-typed by the ``tool_input_guardrails`` attribute); hosted or
      built-in execution tools are uncovered surfaces;
    * ``Agent.as_tool()`` nested tools -- detected via the SDK's own
      ``_is_agent_tool`` marker (set by ``Agent.as_tool()`` in
      ``agents/agent.py``) or via ``nested_agent_tools`` declared names:
      the guardrail sees only the outer input string, never the nested
      tool calls, so these are uncovered surfaces;
    * every ``FunctionTool`` must carry at least one guardrail issued by
      :func:`make_tool_input_guardrail` (raw function or wrapped in the
      SDK's ``ToolInputGuardrail``).

    Returns a coverage report dict on success. Raises
    :exc:`UncoveredSurfaceError` naming every uncovered surface found
    (all surfaces are collected before raising, so one audit names them
    all).
    """
    nested = set(nested_agent_tools or ())
    uncovered = []

    if agent is None:
        raise UncoveredSurfaceError(
            "audit_agent_coverage received agent=None; refusing to "
            "certify a nonexistent agent.")
    handoffs = list(getattr(agent, "handoffs", None) or [])
    if handoffs:
        uncovered.append(
            "handoffs (%d target(s)): the SDK runs no tool guardrail "
            "for handoffs" % len(handoffs))

    tools = list(getattr(agent, "tools", None) or [])
    covered = []
    for tool in tools:
        tool_name = getattr(tool, "name", repr(tool))
        if not _is_function_tool(tool):
            uncovered.append(
                "tool %r (%s): not a FunctionTool -- hosted/built-in "
                "tools never enter the tool_input_guardrails pipeline"
                % (tool_name, type(tool).__name__))
            continue
        if getattr(tool, "_is_agent_tool", False) or tool_name in nested:
            uncovered.append(
                "tool %r: Agent.as_tool() nested run -- the guardrail "
                "sees only the outer input string, never the nested "
                "tool calls" % (tool_name,))
            continue
        guardrails = list(getattr(tool, "tool_input_guardrails", None) or [])
        if not any(_is_issued_guardrail(g) for g in guardrails):
            uncovered.append(
                "tool %r: FunctionTool without a Sasanam-issued "
                "tool_input_guardrail" % (tool_name,))
            continue
        covered.append(tool_name)

    if uncovered:
        raise UncoveredSurfaceError(
            "agent %r has uncovered execution surfaces outside this "
            "shim's visibility; refusing to certify coverage:\n  - %s"
            % (getattr(agent, "name", repr(agent)), "\n  - ".join(uncovered)))
    return {
        "agent": getattr(agent, "name", None),
        "tools": sorted(covered),
        "handoffs": [],
        "sdk": "openai-agents",
        "residual": list(RESIDUAL_SURFACES),
    }
