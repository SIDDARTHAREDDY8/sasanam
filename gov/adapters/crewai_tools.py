"""CrewAI adapter: a governed ``BaseTool``.

``make_governed_crewai_tool`` builds a ``crewai.tools.BaseTool`` subclass
whose ``_run`` / ``_arun`` implementations route through a
:class:`~gov.adapters.core.GovernedBinding` instead of a raw Python
callable. CrewAI's ``BaseTool.run`` -> ``_run`` (and ``arun`` ->
``_arun``) funnel is verified against crewai 1.15.23 and pinned by
``test_funnel_assumption_pinned`` in the adapter test suite, so every
normal CrewAI execution path is mediated.

There is deliberately **no raw callable** on the tool: unlike CrewAI's
``Tool`` (which wraps a ``func``), the abstract ``BaseTool`` has no
``func`` field at all, so there is nothing to steal. The mediation
lives in ``_run``/``_arun`` themselves, so even calling those dunders
directly is still governed. (``to_structured_tool()`` exposes
``func=self._run`` on the converted tool -- still the mediated method.)

Residual limitation: a caller that builds its *own* plain ``Tool``
around the same underlying Python function bypasses governance
entirely -- in-process Python cannot prevent that. The deployment rule
is: agent code is only ever handed governed tools. (See
``gov/adapters/README.md``.)

F62 class (same hole as langchain-core, same fix): CrewAI's
``BaseTool.run`` calls ``_validate_kwargs`` *before* ``_run`` is
reached; that validates against ``args_schema`` with
``model_validate(kwargs).model_dump()``. With pydantic's default
``extra="ignore"`` any undeclared kwarg (e.g. a smuggled ``bcc``) is
silently dropped there -- it never reaches mediation, the DLP scan, or
the approval record. ``GovernedCrewTool`` therefore refuses any
``args_schema`` whose config does not set ``extra="allow"``: checked
at construction, on reassignment, and again immediately before
mediation (F68 class: ``object.__setattr__`` bypass or a
``model_rebuild`` that flips the config back would otherwise re-open
the hole). Positional args are refused outright -- ``run()`` skips
schema validation entirely when ``args`` is non-empty, so guessing
their meaning would be unmediated.

CrewAI invokes tools synchronously (``run()``); ``arun()`` awaits
``_arun``. Mediation itself is synchronous (the executor is in-memory),
so ``_arun`` calls the same sync mediation -- no thread-hopping of the
audit path.
"""

from typing import Any, Optional

try:
    from crewai.tools import BaseTool
    from pydantic import PrivateAttr, model_validator
except ImportError as _exc:
    raise ImportError(
        "gov.adapters.crewai_tools requires the 'crewai' extra "
        "(crewai, verified against 1.15.x). Install it with "
        "`pip install agent-governance[crewai]`."
    ) from _exc

from .core import (
    GovernedBinding,
    GovernedToolFacade,
    normalize_result,
)


def _args_schema_allows_undeclared(schema):
    """True iff CrewAI will pass undeclared kwargs through to ``_run``
    instead of silently dropping them.

    F62 class: ``BaseTool._validate_kwargs`` validates with
    ``args_schema.model_validate(kwargs)`` and keeps ``model_dump()``.
    With pydantic's default ``extra="ignore"`` the dump contains only
    declared fields -- undeclared kwargs vanish before mediation. Only
    ``extra="allow"`` preserves them. (CrewAI auto-generates an
    ``args_schema`` from the ``_run`` signature when none is given, via
    ``create_model`` with the same ``extra="ignore"`` default, so the
    auto-generated schema is rejected too -- callers must pass an
    explicit schema.)
    """
    if schema is None:
        return False
    config = getattr(schema, "model_config", None) or {}
    if str(config.get("extra") or "").lower() == "allow":
        return True
    # pydantic v1 models expose the setting as __config__.extra.
    v1_config = getattr(schema, "__config__", None)
    if v1_config is not None and str(
            getattr(v1_config, "extra", "") or "").lower() == "allow":
        return True
    return False


def _f62_schema_error(schema):
    return (
        "F62: GovernedCrewTool requires args_schema with "
        "extra='allow' (got %r). CrewAI validates tool input against "
        "args_schema BEFORE _run is reached; with pydantic's default "
        "extra='ignore', undeclared kwargs (e.g. a smuggled 'bcc') are "
        "silently dropped and never reach mediation, the DLP scan, or "
        "the approval record. Declare "
        "model_config = ConfigDict(extra='allow') on your schema so "
        "every input reaches mediation." % (type(schema).__name__,))


class GovernedCrewTool(BaseTool):
    """A ``crewai.tools.BaseTool`` whose execution is mediated by a
    binding.

    Do not instantiate directly -- use :func:`make_governed_crewai_tool`,
    which validates the tool name against the binding up front.

    F31: the tool holds a restricted :class:`GovernedToolFacade`, NOT
    the full ``GovernedBinding``. A tool object is handed to agent code,
    so it must not expose the raw ``ToolExecutor``.
    """

    _facade: Optional[GovernedToolFacade] = PrivateAttr(default=None)
    _framework_tool: str = PrivateAttr(default="")
    _on_denied: str = PrivateAttr(default="raise")
    _on_queued: str = PrivateAttr(default="raise")

    @model_validator(mode="after")
    def _f62_require_extra_allow(self):
        # F62 class: fail closed at construction. The check lives on the
        # class itself (not only in make_governed_crewai_tool) so direct
        # GovernedCrewTool(...) construction cannot bypass it.
        if not _args_schema_allows_undeclared(self.args_schema):
            raise ValueError(_f62_schema_error(self.args_schema))
        return self

    def __setattr__(self, name, value):
        # F62 class: a post-construction `tool.args_schema = <strict
        # schema>` would re-open the silent-drop hole, so reassignments
        # are held to the same rule as construction.
        if name == "args_schema" and not _args_schema_allows_undeclared(
                value):
            raise ValueError(_f62_schema_error(value))
        super().__setattr__(name, value)

    def _mediate(self, kwargs):
        # F68 class: re-check the EFFECTIVE args_schema's extra behavior
        # IMMEDIATELY before mediation. Construction and __setattr__
        # reassignment are already guarded, but a post-construction
        # mutation that bypasses __setattr__ --
        # object.__setattr__(tool, "args_schema", StrictSchema), or
        # model_config["extra"]="ignore" followed by
        # model_rebuild(force=True) -- would otherwise silently drop
        # undeclared kwargs before mediation. Fail closed unless
        # undeclared extras are allowed.
        if not _args_schema_allows_undeclared(self.args_schema):
            raise ValueError(_f62_schema_error(self.args_schema))
        if self._facade is None:
            # Defensive: a GovernedCrewTool must always be built via
            # make_governed_crewai_tool. Fail closed rather than run
            # unmediated.
            raise RuntimeError(
                "GovernedCrewTool has no mediation facade; refusing "
                "to run.")
        result = self._facade.call(
            self._framework_tool,
            on_denied=self._on_denied,
            on_queued=self._on_queued,
            **kwargs)
        return normalize_result(result)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        # *args is empty here: CrewAI's run() passes validated kwargs.
        # When args is non-empty, run() SKIPS schema validation entirely,
        # so positional leftovers would be unmediated input -- fail
        # closed instead of guessing their meaning.
        if args:
            raise RuntimeError(
                "GovernedCrewTool._run received unexpected positional "
                "args; refusing to guess their meaning.")
        return self._mediate(kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        # Mediation itself is synchronous (the executor is in-memory and
        # deterministic); there is nothing to await. Keeping _arun direct
        # avoids thread-hopping the audit path.
        if args:
            raise RuntimeError(
                "GovernedCrewTool._arun received unexpected positional "
                "args; refusing to guess their meaning.")
        return self._mediate(kwargs)


def make_governed_crewai_tool(binding, name, description, args_schema,
                              framework_tool=None, on_denied="raise",
                              on_queued="raise", **tool_kwargs):
    """Build a governed CrewAI tool.

    Parameters
    ----------
    binding : GovernedBinding
        Mediation endpoint. ``framework_tool`` (default: ``name``) must
        resolve through its tool map -- unregistered names raise
        :class:`UnregisteredToolError` here, at construction time.
    name : str
        The CrewAI tool name the agent sees.
    description : str
        The CrewAI tool description the agent sees.
    args_schema : pydantic.BaseModel
        Input schema. F62 class: the schema MUST declare
        ``model_config = ConfigDict(extra='allow')`` -- any other config
        raises here, at construction. CrewAI validates tool input against
        this schema *before* ``_run`` is reached; with pydantic's default
        ``extra='ignore'`` undeclared kwargs would be silently dropped
        there, never reaching mediation, the DLP scan, or the approval
        record.
    framework_tool : str, optional
        Binding-level tool name; defaults to ``name``.
    on_denied, on_queued : {"raise", "return"}
        Passed through to ``binding.call``.
    **tool_kwargs
        Forwarded to the ``BaseTool`` constructor (e.g.
        ``result_as_answer=True``, ``max_usage_count=5``).

    Returns a ``GovernedCrewTool`` with no raw callable. Successful
    execution returns a JSON string of the executor's result dict;
    denials raise :class:`ToolDeniedError`; queued approvals raise
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

    tool = GovernedCrewTool(
        name=name,
        description=description,
        args_schema=args_schema,
        **tool_kwargs)
    # F31: stash the restricted facade, not the full binding -- the tool
    # object is agent-reachable and must not expose the raw executor.
    tool._facade = binding.facade()
    tool._framework_tool = framework_tool
    tool._on_denied = on_denied
    tool._on_queued = on_queued
    return tool
