"""LangChain adapter: a governed ``StructuredTool``.

``make_governed_tool`` builds a ``langchain_core`` tool whose ``_run`` /
``_arun`` implementations route through a
:class:`~gov.adapters.core.GovernedBinding` instead of a raw Python
callable. Because ``BaseTool.invoke`` -> ``run`` -> ``_run`` (and the
async ``ainvoke`` -> ``arun`` -> ``_arun``) all funnel into the two
overridden methods (verified against langchain-core 1.6.3), every
normal LangChain execution path is mediated.

There is deliberately **no raw callable** on the tool: ``func`` and
``coroutine`` are left ``None``. Reading ``tool.func`` gives ``None``,
not a bypass. The mediation lives in ``_run``/``_arun`` themselves, so
even calling those dunders directly is still governed.

Residual limitation: a caller that builds its *own* plain
``StructuredTool``/``Tool`` around the same underlying Python function
bypasses governance entirely -- in-process Python cannot prevent that.
The deployment rule is: agent code is only ever handed governed tools.
(See ``gov/adapters/README.md``.)
"""

from typing import Any, Optional

from pydantic import PrivateAttr

from .core import GovernedBinding, GovernedToolFacade, normalize_result


def _structured_tool_base():
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:
        raise ImportError(
            "gov.adapters.langchain_tools requires the 'langchain-core' "
            "package (verified against 1.6.3). Install it with "
            "`pip install langchain-core`."
        ) from exc
    return StructuredTool


class GovernedStructuredTool(_structured_tool_base()):
    """A ``StructuredTool`` whose execution is mediated by a binding.

    Do not instantiate directly -- use :func:`make_governed_tool`, which
    validates the tool name against the binding up front.

    F31: the tool holds a restricted :class:`GovernedToolFacade`, NOT
    the full ``GovernedBinding``. A tool object is handed to agent code,
    so it must not expose the raw ``ToolExecutor`` (from which
    ``ApprovalQueue.set_identity_verifier`` was reachable via
    ``.approvals`` — the wave-8 traversal
    ``tool._binding.executor.approvals.set_identity_verifier(...)`` no
    longer resolves: the facade has no ``executor`` attribute).
    """

    _facade: Optional[GovernedToolFacade] = PrivateAttr(default=None)
    _framework_tool: str = PrivateAttr(default="")
    _on_denied: str = PrivateAttr(default="raise")
    _on_queued: str = PrivateAttr(default="raise")

    def _mediate(self, kwargs):
        if self._facade is None:
            # Defensive: a GovernedStructuredTool must always be built via
            # make_governed_tool. Fail closed rather than run unmediated.
            raise RuntimeError(
                "GovernedStructuredTool has no mediation facade; refusing "
                "to run.")
        result = self._facade.call(
            self._framework_tool,
            on_denied=self._on_denied,
            on_queued=self._on_queued,
            **kwargs)
        return normalize_result(result)

    def _run(self, *args: Any, config=None, run_manager=None, **kwargs: Any) -> Any:
        # *args is empty here: BaseTool.run() already converted validated
        # input into kwargs via _to_args_and_kwargs before reaching _run.
        # Positional leftovers would indicate a framework internals change;
        # fail closed instead of guessing their meaning.
        if args:
            raise RuntimeError(
                "GovernedStructuredTool._run received unexpected positional "
                "args; refusing to guess their meaning.")
        return self._mediate(kwargs)

    async def _arun(self, *args: Any, config=None, run_manager=None, **kwargs: Any) -> Any:
        # Mediation itself is synchronous (the executor is in-memory and
        # deterministic); there is nothing to await. Keeping _arun direct
        # avoids thread-hopping the audit path.
        if args:
            raise RuntimeError(
                "GovernedStructuredTool._arun received unexpected positional "
                "args; refusing to guess their meaning.")
        return self._mediate(kwargs)


def make_governed_tool(binding, name, description, args_schema,
                       framework_tool=None, on_denied="raise",
                       on_queued="raise", **tool_kwargs):
    """Build a governed LangChain tool.

    Parameters
    ----------
    binding : GovernedBinding
        Mediation endpoint. ``framework_tool`` (default: ``name``) must
        resolve through its tool map -- unregistered names raise
        :class:`UnregisteredToolError` here, at construction time.
    name : str
        The LangChain tool name the agent sees.
    description : str
        The LangChain tool description the agent sees.
    args_schema : pydantic.BaseModel
        Input schema (required by ``StructuredTool``). Invalid inputs
        are rejected by LangChain's own validation *before* mediation.
    framework_tool : str, optional
        Binding-level tool name; defaults to ``name``.
    on_denied, on_queued : {"raise", "return"}
        Passed through to ``binding.call``.
    **tool_kwargs
        Forwarded to the ``StructuredTool`` constructor (e.g.
        ``return_direct=True``).

    Returns a ``GovernedStructuredTool`` with ``func=None`` /
    ``coroutine=None`` (no raw callable to steal). Successful execution
    returns a JSON string of the executor's result dict; denials raise
    :class:`ToolDeniedError`; queued approvals raise
    :class:`ApprovalRequiredError`.
    """
    if not isinstance(binding, GovernedBinding):
        raise TypeError("binding must be a GovernedBinding, got %r"
                        % type(binding).__name__)
    framework_tool = framework_tool if framework_tool is not None else name
    binding.resolve(framework_tool)  # fail closed at construction time
    if on_denied not in ("raise", "return"):
        raise ValueError("on_denied must be 'raise' or 'return'")
    if on_queued not in ("raise", "return"):
        raise ValueError("on_queued must be 'raise' or 'return'")

    tool = GovernedStructuredTool(
        name=name,
        description=description,
        args_schema=args_schema,
        func=None,
        coroutine=None,
        **tool_kwargs)
    # F31: stash the restricted facade, not the full binding — the tool
    # object is agent-reachable and must not expose the raw executor.
    tool._facade = binding.facade()
    tool._framework_tool = framework_tool
    tool._on_denied = on_denied
    tool._on_queued = on_queued
    return tool
