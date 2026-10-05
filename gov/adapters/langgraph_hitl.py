"""LangGraph adapter: ``interrupt()`` -> ``ApprovalQueue`` recipe.

Wires LangGraph's native human-in-the-loop ``interrupt()`` into Sasanam's
durable :class:`~gov.approvals.ApprovalQueue` so a LangGraph agent's tool
calls pause for human approval through the existing queue -- the chained,
auditable enforcement record -- instead of LangGraph's UI-mediated,
advisory interrupt.

Contract (verified against langgraph 1.2.12 source,
``langgraph/types.py``)::

    from langgraph.types import interrupt, Command

    from langgraph.types import interrupt, Command

    def tool_node(state):
        # First entry: returns ("executed"|"denied", ...) or RAISES
        # GraphInterrupt (queued). Re-entry after resume (with
        # prior_approval_id set): returns ("approved"|"rejected", ...).
        outcome, payload = governed_tool_call(
            binding, "write_file", {"path": ..., "content": ...},
            interrupt=interrupt,                # langgraph.types.interrupt
            prior_approval_id=state.get("approval_id"),
        )
        if outcome == "approved":
            binding.executor.execute_approved()  # sweep executes it
            return {"approval_id": None}
        return {"outcome": outcome}

    # Client side (proven required: the node raises GraphInterrupt before
    # it can write state, so the client persists the approval id itself):
    #
    #   chunks = graph.stream(input, thread_id=...)
    #   aid = <approval_id from the __interrupt__ payload>
    #   queue.decide(aid, True, reason=..., decided_by="human-operator")
    #   graph.update_state({"configurable": {"thread_id": ...}},
    #                      {"approval_id": aid})
    #   graph.invoke(Command(resume={"approval_id": aid}), thread_id=...)

Behavior:

* executor ``"executed"`` -> ``("executed", result)``; ``interrupt`` is
  never called (allowed calls do not pause the graph).
* executor ``"denied"``  -> raises :exc:`~gov.adapters.core.ToolDeniedError`
  by default (or ``("denied", result)`` with ``on_denied="return"``);
  ``interrupt`` is never called.
* executor ``"queued"``   -> ``interrupt(payload)`` pauses the graph. The
  payload carries the ``approval_id`` (plus tool names and a note -- never
  the raw tool arguments: the interrupt value is surfaced to the graph
  client, so client-channel hygiene keeps arguments in the queue UI,
  which shows the redacted form). The human decides via
  ``ApprovalQueue.decide``; the client resumes with
  ``Command(resume=...)``; the node RE-EXECUTES from the start (per the
  LangGraph contract) and calls this helper again with
  ``prior_approval_id`` set -- the helper then skips ``binding.call``
  (no duplicate queue entry), lets ``interrupt()`` return the resume
  value, re-reads the queue record, and returns ``("approved", record)``
  or ``("rejected", record)``.

The queue is the decision authority on resume: a resume value that names
a different approval id, a vanished record, or a resume that arrives
before any human decided all fail closed -- the resume value can never
smuggle an approval past the queue.

``langgraph`` is an OPTIONAL dependency: the recipe takes ``interrupt``
as a parameter (dependency injection), so it works with
``langgraph.types.interrupt`` in production and with a stand-in in
tests. No ``langgraph`` import appears in this module.

F62-class input audit: ``arguments`` must be a dict and is passed to
``binding.call`` unmodified -- nothing is filtered or dropped before the
executor's DLP scan sees it.
"""

from .core import AdapterError


class ApprovalResumeError(AdapterError):
    """Base class for fail-closed resume-path errors."""


class ApprovalRecordMissingError(ApprovalResumeError):
    """The prior approval id names no queue record (it vanished or never
    existed). Fail closed: never execute on a missing record."""


class ApprovalNotDecidedError(ApprovalResumeError):
    """The client resumed before any human decided via the ApprovalQueue.
    The queue is the decision authority -- a resume value claiming
    approval is not honored. Fail closed."""


class ApprovalResumeMismatchError(ApprovalResumeError):
    """The resume value names a different approval id than the one this
    node paused for. Fail closed: never apply another approval's
    decision."""


def _payload(framework_tool, native_tool, approval_id):
    return {
        "sasanam_approval": True,
        "approval_id": approval_id,
        "framework_tool": framework_tool,
        "native_tool": native_tool,
        "note": ("Human approval required via the Sasanam ApprovalQueue. "
                 "Decide with ApprovalQueue.decide(%r, ...) then resume "
                 "the graph with Command(resume=...)." % (approval_id,)),
    }


def _apply_resume(queue, approval_id, resume):
    """Map the post-resume queue record to an outcome (fail closed)."""
    if isinstance(resume, dict) and "approval_id" in resume:
        if resume["approval_id"] != approval_id:
            raise ApprovalResumeMismatchError(
                "resume names approval %r but this node paused for %r; "
                "refusing to apply another approval's decision."
                % (resume["approval_id"], approval_id))
    record = queue.get(approval_id)
    if record is None:
        raise ApprovalRecordMissingError(
            "approval %r has no queue record; refusing to execute."
            % (approval_id,))
    status = record.get("status")
    if status == "approved":
        return ("approved", record)
    if status == "rejected":
        return ("rejected", record)
    if status == "pending":
        raise ApprovalNotDecidedError(
            "approval %r is still pending: no human has decided via the "
            "ApprovalQueue. The queue is the decision authority; a resume "
            "value cannot substitute for a decision." % (approval_id,))
    # expired / revoked / anything else: fail closed.
    raise ApprovalResumeError(
        "approval %r is in terminal state %r; refusing to execute."
        % (approval_id, status))


def governed_tool_call(binding, framework_tool, arguments, *,
                       interrupt, queue=None, prior_approval_id=None,
                       on_denied="raise"):
    """Mediate one tool call inside a LangGraph node, pausing the graph
    for human approval through the ApprovalQueue when required.

    Parameters
    ----------
    binding : GovernedBinding
        Mediation endpoint.
    framework_tool : str
        Binding-level tool name (must resolve; unregistered names raise
        :class:`~gov.adapters.core.UnregisteredToolError`).
    arguments : dict
        Tool arguments (must be a dict; passed to ``binding.call``
        unmodified).
    interrupt : callable
        ``langgraph.types.interrupt`` in production (or a stand-in in
        tests): ``interrupt(value)`` raises on first call and returns the
        resume value when the node re-executes after
        ``Command(resume=...)``.
    queue : ApprovalQueue, optional
        Defaults to ``binding.executor.approvals``.
    prior_approval_id : str, optional
        The approval id this node paused for, read back from graph state
        on re-entry after resume. When set, ``binding.call`` is NOT
        re-run (no duplicate queue entry); the helper goes straight to
        the interrupt site so ``interrupt()`` returns the resume value.
    on_denied : {"raise", "return"}
        ``"raise"`` (default) raises
        :class:`~gov.adapters.core.ToolDeniedError` on denial;
        ``"return"`` returns ``("denied", result)``.

    Returns ``(outcome, payload)`` with outcome in ``"executed"``,
    ``"denied"``, ``"queued"``, ``"approved"``, ``"rejected"``:

    * ``"executed"`` -- allowed and executed; payload is the executor's
      result dict.
    * ``"denied"``   -- denied (``on_denied="return"`` only); payload is
      the executor's result dict.
    * ``"queued"``   -- never returned: a queued call pauses the graph
      via ``interrupt()`` (which raises) instead of returning. Listed
      for documentation completeness.
    * ``"approved"`` / ``"rejected"`` -- post-resume outcomes; payload is
      the queue record. On ``"approved"`` the deployment runs
      ``executor.execute_approved()`` to execute (the sweep re-validates
      before executing).
    """
    from .core import GovernedBinding as _GB
    if not isinstance(binding, _GB):
        raise TypeError("binding must be a GovernedBinding, got %r"
                        % type(binding).__name__)
    if not isinstance(arguments, dict):
        raise TypeError(
            "arguments must be a dict, got %r; refusing to guess their "
            "meaning." % type(arguments).__name__)
    if not callable(interrupt):
        raise TypeError("interrupt must be callable, got %r"
                        % type(interrupt).__name__)
    if on_denied not in ("raise", "return"):
        raise ValueError('on_denied must be "raise" or "return"')
    if queue is None:
        queue = binding.executor.approvals

    if prior_approval_id is not None:
        # Re-entry after Command(resume=...): the node re-executes from
        # the start per the LangGraph contract. Do NOT re-run
        # binding.call -- that would queue a duplicate approval. Go
        # straight to the interrupt site so interrupt() returns the
        # resume value instead of raising.
        resume = interrupt(_payload(framework_tool,
                                    binding.resolve(framework_tool),
                                    prior_approval_id))
        return _apply_resume(queue, prior_approval_id, resume)

    result = binding.call(framework_tool, on_denied=on_denied,
                          on_queued="return", **arguments)
    status = result.get("status")
    if status == "executed":
        return ("executed", result)
    if status == "denied":
        # on_denied="raise" already raised inside binding.call.
        return ("denied", result)
    # "queued": pause the graph. interrupt() raises GraphInterrupt on
    # first entry, carrying the approval payload to the client.
    approval_id = result.get("approval_id")
    interrupt(_payload(framework_tool, binding.resolve(framework_tool),
                       approval_id))
    # Unreachable with a real interrupt() (it always raises on first
    # entry); reachable only with a non-raising stand-in. Fail closed
    # rather than pretending the call was approved.
    raise ApprovalResumeError(
        "interrupt() returned without raising on first entry for approval "
        "%r; refusing to continue without a real graph pause." % (
            approval_id,))
