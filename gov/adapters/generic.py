"""Generic Python adapter: decorator and context-manager registry.

``governed`` decorates an ordinary Python function so every call is
mediated by a :class:`~gov.adapters.core.GovernedBinding`::

    binding = GovernedBinding(executor, identity)

    @governed(binding, tool="read_file")
    def read_notes(path):
        '''Read a notes file. (Body is documentation/spec only.)'''

    read_notes(path="notes.txt")   # -> executor result dict

``governed_registry`` is a context manager holding a named set of
governed callables; exiting the block seals the registry against new
registrations::

    with governed_registry(binding) as reg:
        reg.register("read_notes", read_notes)

        @reg.tool("write_notes")          # decorator form, tool="write_file"
        def _write(path, content): ...

        reg.call("read_notes", path="notes.txt")

Execution model (read this before choosing ``run_body``)
--------------------------------------------------------
The executor *simulates* tools; it accepts no arbitrary callable. So by
default the decorated function's **body never runs**: the executor's
``"executed"`` result is the whole outcome, which keeps exactly one
side effect inside the executor's write-ahead audit boundary.

``run_body=True`` changes that: after the executor returns
``"executed"``, the original body runs with the same kwargs and its
return value replaces the simulated payload. This is a deliberate
**split authorization/execution** boundary -- the executor authorized
and logged the call, but the side effect happens outside its
simulation. Use it only when you accept that residual, and prefer the
default whenever the executor's simulation is sufficient.
"""

import functools

from .core import AdapterError, GovernedBinding


def governed(binding, tool=None, *, on_denied="raise", on_queued="raise",
             run_body=False, name=None):
    """Decorate ``fn`` so each call is mediated through ``binding``.

    Parameters
    ----------
    binding : GovernedBinding
        The mediation endpoint (executor + minted identity + tool map).
    tool : str, optional
        Framework-facing tool name. Defaults to the wrapped function's
        ``__name__``; it must resolve through the binding's tool map
        (unregistered names raise :class:`UnregisteredToolError` at call
        time -- fail closed).
    on_denied, on_queued : {"raise", "return"}
        ``"raise"`` (default) turns executor denials into
        :class:`ToolDeniedError` and queued approvals into
        :class:`ApprovalRequiredError`; ``"return"`` returns the raw
        executor dict instead.
    run_body : bool
        ``False`` (default): the wrapped body never runs; the executor's
        simulated result is returned. ``True``: after an ``"executed"``
        decision the original body runs with the same kwargs -- see the
        module docstring for the split authorization/execution caveat.
    name : str, optional
        Override for the wrapper's ``__name__`` (defaults to the wrapped
        function's name).

    The wrapper preserves the wrapped function's ``__name__``,
    ``__doc__``, and signature metadata via ``functools.wraps``.
    """
    if not isinstance(binding, GovernedBinding):
        raise TypeError("binding must be a GovernedBinding, got %r"
                        % type(binding).__name__)
    # Fail fast on misconfiguration: validate modes at decoration time,
    # not on the first mediated call.
    if on_denied not in ("raise", "return"):
        raise ValueError("on_denied must be 'raise' or 'return'")
    if on_queued not in ("raise", "return"):
        raise ValueError("on_queued must be 'raise' or 'return'")

    def decorator(fn):
        framework_tool = tool if tool is not None else fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if args:
                # Positional args cannot be mapped to named tool arguments
                # deterministically; fail closed instead of guessing.
                raise AdapterError(
                    "governed tool %r does not accept positional arguments; "
                    "call with keyword arguments only." % (framework_tool,)
                )
            result = binding.call(
                framework_tool, on_denied=on_denied, on_queued=on_queued,
                **kwargs)
            if result.get("status") == "executed" and run_body:
                body_result = fn(**kwargs)
                result = dict(result)
                result["body_result"] = body_result
                result["execution_note"] = (
                    "split authorization/execution: executor authorized the "
                    "call; the wrapped body ran outside the executor's "
                    "write-ahead boundary.")
            return result

        wrapper.__governed_binding__ = binding
        wrapper.__governed_tool__ = framework_tool
        if name is not None:
            wrapper.__name__ = name
        # functools.wraps sets __wrapped__ -> the raw function, which would
        # be a documented public bypass around mediation. Remove it: the
        # only supported invocation path is the wrapper itself.
        # (Determined introspection via gc/closure cells is out of scope --
        # see README "residual limitations".)
        try:
            del wrapper.__wrapped__
        except AttributeError:
            pass
        return wrapper

    return decorator


class GovernedRegistry:
    """Named set of governed callables, sealed on context exit.

    ``with governed_registry(binding) as reg:``

    * ``reg.register(framework_tool, fn)`` -- wrap ``fn`` with
      :func:`governed` under ``framework_tool`` and store it.
    * ``reg.register(fn)`` -- use ``fn.__name__`` as the tool name.
    * ``@reg.tool(framework_tool, **kwargs)`` -- decorator form of
      ``register`` (``kwargs`` are passed to :func:`governed`).
    * ``reg.call(framework_tool, **kwargs)`` -- dispatch through the
      binding (identical to calling the registered wrapper).
    * ``reg.tools()`` -- sorted registered names.
    * ``reg.resolve(framework_tool)`` -- the registered wrapper.

    After ``__exit__`` the registry is **sealed**: ``register``/``tool``
    raise :class:`AdapterError`. Dispatch (``call``) keeps working --
    sealing freezes the tool *set*, not the mediation.
    """

    def __init__(self, binding, *, on_denied="raise", on_queued="raise",
                 run_body=False):
        if not isinstance(binding, GovernedBinding):
            raise TypeError("binding must be a GovernedBinding, got %r"
                            % type(binding).__name__)
        self._binding = binding
        self._defaults = {"on_denied": on_denied, "on_queued": on_queued,
                          "run_body": run_body}
        self._tools = {}
        self._sealed = False

    # -- context manager -------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._sealed = True
        return False  # never swallow exceptions

    @property
    def sealed(self):
        return self._sealed

    @property
    def binding(self):
        return self._binding

    # -- registration ----------------------------------------------------

    def _check_open(self):
        if self._sealed:
            raise AdapterError(
                "governed registry is sealed; no new tools may be registered.")

    def register(self, framework_tool=None, fn=None, **governed_kwargs):
        """Register ``fn`` under ``framework_tool`` (defaults to
        ``fn.__name__``). Also usable as ``register(fn)``."""
        self._check_open()
        if fn is None:
            # Called as register(fn).
            fn = framework_tool
            framework_tool = None
        if not callable(fn):
            raise TypeError("register() requires a callable, got %r"
                            % type(fn).__name__)
        name = framework_tool if framework_tool is not None else fn.__name__
        if not isinstance(name, str) or not name:
            raise ValueError("tool name must be a non-empty string")
        if name in self._tools:
            raise AdapterError(
                "tool %r is already registered; refusing to shadow it."
                % (name,))
        # Fail closed at registration time for names the binding cannot
        # resolve -- a typo'd tool name must not become a runtime surprise.
        self._binding.resolve(name)
        kwargs = dict(self._defaults)
        kwargs.update(governed_kwargs)
        wrapped = governed(self._binding, tool=name, **kwargs)(fn)
        self._tools[name] = wrapped
        return wrapped

    def tool(self, framework_tool=None, **governed_kwargs):
        """Decorator form of :meth:`register`::

            @reg.tool("write_notes", run_body=False)
            def _write(path, content): ...
        """
        def decorator(fn):
            return self.register(framework_tool, fn, **governed_kwargs)
        return decorator

    # -- dispatch --------------------------------------------------------

    def resolve(self, framework_tool):
        """Return the registered wrapper for ``framework_tool``.

        Raises :class:`UnregisteredToolError` for unknown names (via the
        binding) -- dispatch never falls through to an unmediated path.
        """
        self._binding.resolve(framework_tool)  # fail-closed validation
        try:
            return self._tools[framework_tool]
        except KeyError:
            raise AdapterError(
                "tool %r resolves in the binding but is not registered in "
                "this registry." % (framework_tool,))

    def call(self, framework_tool, **kwargs):
        """Dispatch ``framework_tool`` through the binding."""
        return self.resolve(framework_tool)(**kwargs)

    def tools(self):
        return sorted(self._tools)


def governed_registry(binding, **kwargs):
    """Create a :class:`GovernedRegistry` for use as a context manager::

        with governed_registry(binding) as reg:
            ...
    """
    return GovernedRegistry(binding, **kwargs)
