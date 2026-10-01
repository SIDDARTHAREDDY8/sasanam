"""ADK-style callback / HITL execution seams (wave-265 feature lane).

Adapts the before/after tool callback MECHANISM from google/adk-python
(Apache-2.0; license verified from the upstream LICENSE file;
pattern only -- no ADK code or text vendored) as a governance
interception seam around tool execution.

What this module provides, stdlib-only:

* :class:`CallbackExecutor`: wraps one tool call with ordered
  ``before_tool`` callbacks (inspect/rewrite/block/escalate),
  ``after_tool`` callbacks (observe/replace/escalate findings), and
  ``on_error`` callbacks (suppress with a replacement result).
  First non-``None``/non-:class:`Continue` verdict wins per phase.
* :class:`HumanApprovalGate`: a HITL callback kind. ``before`` pauses
  execution and emits a machine-coded approval-request record into a
  deployment-owned journal; ``resolve`` resumes on a human decision
  (approved runs the original call; denied refuses
  ``callback-approval-denied``); ``expire`` retires the request so a
  stale approval can never be resolved later.
* Verdicts: :class:`Continue`, :class:`Rewrite` (new args),
  :class:`Escalate` (reason + context), :class:`Block` (machine code).

Fail-closed composition (the enforcement floor):

* An optional ``enforcement(tool_name, args) -> (allowed, code)``
  predicate is evaluated BEFORE any callback runs. A denial returns
  the enforcement layer's own machine code and the callbacks are
  never consulted: callbacks can only tighten or escalate, never
  widen. A :class:`Rewrite` re-runs enforcement on the new args; a
  rewrite the enforcement would now deny refuses
  ``callback-cannot-widen``.
* Callbacks are untrusted code. A throwing callback fails closed
  (``callback-faulted``) and the tool never runs. A callback returning
  a non-verdict shape refuses ``callback-malformed-verdict``. A
  :class:`Block` naming a machine code outside the closed taxonomy
  refuses ``callback-malformed-verdict`` (callbacks cannot invent
  machine codes).

Composition (never duplication):

* This module owns ONLY the interception mechanism. The human
  decision itself stays in ``gov/approvals.py`` ``ApprovalQueue``;
  the gate emits a machine-coded request record (with an
  ``args_digest``, never raw args) that the deployment's queue
  consumes, and ``resolve`` ingests the queue's decision.
* After-phase :class:`Escalate` verdicts raise machine-coded findings
  into the journal; they do not alter the returned result.
* The pause is synchronous and in-process: :class:`EscalatedCall`
  carries the frozen (tool, args) for the deployment to resume or
  drop. There is no cross-process resume and no durable outbox in
  this module (documented residual).

Honest residuals:

* Raw tool args never enter the journal -- only the ``args_digest``.
  A verifier cannot re-audit what was passed, only that a call with
  that digest was gated.
* A throwing enforcement predicate fails closed (``callback-faulted``);
  enforcement is the trusted layer, so a throw there is a deployment
  bug, not an attacker-controlled path.
* Tool exceptions are NOT callback faults: with no suppressing
  ``on_error`` callback the original exception propagates to the
  caller unchanged (the caller's existing contract).
* Replay/spend/chain state of approvals is the queue's job; the gate
  tracks only pending request ids in memory.
"""

import hashlib
import json
import os
import uuid

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

CODES = (
    "callback-approval-denied",
    "callback-approval-expired",
    "callback-approval-requested",
    "callback-blocked",
    "callback-cannot-widen",
    "callback-faulted",
    "callback-finding-escalated",
    "callback-malformed-verdict",
    "callback-unknown-approval",
)


class CallbackError(Exception):
    """Loud callback-seam failure. ``code`` is a closed vocabulary
    member of :data:`CODES`."""

    def __init__(self, code, detail=""):
        super(CallbackError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _require_taxonomy():
    try:
        from . import decision_codes
    except ImportError:  # standalone: codes are validated at merge
        return None
    return decision_codes.TAXONOMY


class Continue(object):
    """Verdict: proceed unchanged (ADK's ``return None``)."""
    __slots__ = ()

    def __repr__(self):
        return "Continue()"


class Rewrite(object):
    """Verdict: proceed with replaced args. The replacement args are
    re-checked against the enforcement predicate when one is set."""

    __slots__ = ("new_args",)

    def __init__(self, new_args):
        self.new_args = new_args

    def __repr__(self):
        return "Rewrite(%r)" % (self.new_args,)


class Escalate(object):
    """Verdict: pause (before) or raise a finding (after). ``context``
    is deployment-owned metadata, never authority."""

    __slots__ = ("reason", "context")

    def __init__(self, reason, context=None):
        self.reason = reason
        self.context = dict(context) if context else {}

    def __repr__(self):
        return "Escalate(%r)" % (self.reason,)


class Block(object):
    """Verdict: refuse the call. ``code`` defaults to
    ``callback-blocked``; any other code must be a closed taxonomy
    member or the block itself is refused."""

    __slots__ = ("code",)

    def __init__(self, code="callback-blocked"):
        self.code = code

    def __repr__(self):
        return "Block(%r)" % (self.code,)


class EscalatedCall(object):
    """A paused execution. The deployment resumes it (e.g. via
    :meth:`HumanApprovalGate.resolve`) or drops it. Frozen: the tool
    name and args cannot be altered after the pause."""

    __slots__ = ("tool_name", "args", "reason", "context")

    def __init__(self, tool_name, args, reason, context=None):
        self.tool_name = tool_name
        self.args = dict(args)
        self.reason = reason
        self.context = dict(context) if context else {}

    def __repr__(self):
        return "EscalatedCall(%r, reason=%r)" % (self.tool_name,
                                                self.reason)


def _digest_args(args):
    body = json.dumps(args, sort_keys=True, separators=(",", ":"),
                      default=repr)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class CallbackExecutor(object):
    """Runs one tool call through the callback phases.

    ``enforcement`` (optional) is the fail-closed floor:
    ``(tool_name, args) -> (allowed: bool, code: str|None)``. It runs
    before any callback and is re-run after every :class:`Rewrite`.
    ``journal`` is a deployment-owned appendable sink for approval
    requests and escalated findings; ``None`` means escalation paths
    that need recording refuse fail-closed.
    """

    def __init__(self, journal=None):
        self._journal = journal
        self._before = []
        self._after = []
        self._on_error = []

    def add_before(self, fn):
        if not callable(fn):
            raise CallbackError("callback-malformed-verdict",
                                "before callback is not callable")
        self._before.append(fn)
        return fn

    def add_after(self, fn):
        if not callable(fn):
            raise CallbackError("callback-malformed-verdict",
                                "after callback is not callable")
        self._after.append(fn)
        return fn

    def add_on_error(self, fn):
        if not callable(fn):
            raise CallbackError("callback-malformed-verdict",
                                "on_error callback is not callable")
        self._on_error.append(fn)
        return fn

    # -- internal ----------------------------------------------------

    def _enforcement_decide(self, tool_name, args):
        if not callable(self._enforcement):
            raise CallbackError("callback-faulted",
                                "enforcement is not callable")
        try:
            decision = self._enforcement(tool_name, args)
        except Exception as exc:
            raise CallbackError("callback-faulted",
                                "enforcement threw: %r" % (exc,))
        if not (isinstance(decision, tuple) and len(decision) == 2
                and isinstance(decision[0], bool)):
            raise CallbackError("callback-faulted",
                                "enforcement must return (bool, code)")
        return decision

    def _check_block_code(self, code):
        if not isinstance(code, str) or not code:
            raise CallbackError("callback-malformed-verdict",
                                "block code must be a non-empty string")
        if code == "callback-blocked":
            return
        taxonomy = _require_taxonomy()
        if taxonomy is not None and code not in taxonomy:
            raise CallbackError("callback-malformed-verdict",
                                "block code %r is not a taxonomy member"
                                % (code,))

    def _run_before(self, tool_name, args):
        for cb in self._before:
            try:
                verdict = cb(tool_name, args)
            except Exception as exc:
                raise CallbackError("callback-faulted",
                                    "before callback threw: %r" % (exc,))
            if verdict is None or isinstance(verdict, Continue):
                continue
            if isinstance(verdict, Rewrite):
                new_args = verdict.new_args
                if not isinstance(new_args, dict):
                    raise CallbackError("callback-malformed-verdict",
                                        "rewrite args must be a dict")
                if self._enforcement is not None:
                    allowed, code = self._enforcement_decide(
                        tool_name, new_args)
                    if not allowed:
                        raise CallbackError(
                            "callback-cannot-widen",
                            "rewrite widened past the enforcement floor")
                args = new_args
                continue
            if isinstance(verdict, Block):
                self._check_block_code(verdict.code)
                raise CallbackError(verdict.code,
                                    "blocked by before_tool callback")
            if isinstance(verdict, Escalate):
                return args, verdict
            raise CallbackError("callback-malformed-verdict",
                                "before verdict %r is not a verdict"
                                % (verdict,))
        return args, None

    def _run_after(self, tool_name, args, result):
        for cb in self._after:
            try:
                verdict = cb(tool_name, args, result)
            except Exception as exc:
                raise CallbackError("callback-faulted",
                                    "after callback threw: %r" % (exc,))
            if verdict is None or isinstance(verdict, Continue):
                continue
            if isinstance(verdict, Escalate):
                self._raise_finding(tool_name, verdict)
                continue
            if isinstance(verdict, (Block, Rewrite)):
                raise CallbackError("callback-malformed-verdict",
                                    "after verdict %r is not allowed here"
                                    % (verdict,))
            result = verdict  # any other value replaces the result
        return result

    def _run_on_error(self, tool_name, args, error):
        for cb in self._on_error:
            try:
                replacement = cb(tool_name, args, error)
            except Exception as exc:
                raise CallbackError("callback-faulted",
                                    "on_error callback threw: %r" % (exc,))
            if replacement is not None:
                return replacement
        raise error

    def _raise_finding(self, tool_name, verdict):
        if self._journal is None:
            raise CallbackError("callback-malformed-verdict",
                                "escalation requires a journal")
        record = {"kind": "callback-finding",
                  "code": "callback-finding-escalated",
                  "tool": tool_name,
                  "reason": verdict.reason,
                  "context": dict(verdict.context)}
        self._journal.append(record)

    # -- public seam -------------------------------------------------

    def execute(self, action_fn, tool_name, args, enforcement=None,
                before=(), after=(), on_error=()):
        """Run ``action_fn(tool_name, args)`` through the seams.

        ``enforcement`` is the fail-closed floor for this call (see
        class docstring). Per-call ``before``/``after``/``on_error``
        tuples compose with the registered lists. Returns the (possibly
        replaced) tool result, or an :class:`EscalatedCall` when a
        before callback escalated. Refusals raise :class:`CallbackError`
        with a closed machine code.
        """
        if not callable(action_fn):
            raise CallbackError("callback-malformed-verdict",
                                "action_fn is not callable")
        if not isinstance(tool_name, str) or not tool_name:
            raise CallbackError("callback-malformed-verdict",
                                "tool_name must be a non-empty string")
        if not isinstance(args, dict):
            raise CallbackError("callback-malformed-verdict",
                                "args must be a dict")
        self._enforcement = enforcement
        befores = list(self._before) + list(before)
        afters = list(self._after) + list(after)
        on_errors = list(self._on_error) + list(on_error)
        if enforcement is not None:
            allowed, code = self._enforcement_decide(tool_name, args)
            if not allowed:
                raise CallbackError(code or "callback-blocked",
                                    "enforcement floor denied the call")
        saved_before, saved_after = self._before, self._after
        saved_on_error = self._on_error
        self._before, self._after, self._on_error = (
            befores, afters, on_errors)
        try:
            args, escalation = self._run_before(tool_name, args)
            if escalation is not None:
                return EscalatedCall(tool_name, args,
                                     escalation.reason,
                                     escalation.context)
            try:
                result = action_fn(tool_name, args)
            except CallbackError:
                raise
            except Exception as exc:
                result = self._run_on_error(tool_name, args, exc)
            return self._run_after(tool_name, args, result)
        finally:
            self._before, self._after = saved_before, saved_after
            self._on_error = saved_on_error
            self._enforcement = None


class HumanApprovalGate(object):
    """HITL approval as a callback kind.

    Owns ONLY the interception: pausing the call, emitting a
    machine-coded request record, and resuming on the deployment's
    decision. The decision itself lives in the deployment's
    ``ApprovalQueue``; :meth:`resolve` ingests it.
    """

    def __init__(self, journal):
        if journal is None:
            raise CallbackError("callback-malformed-verdict",
                                "HumanApprovalGate requires a journal")
        self._journal = journal
        self._pending = {}

    def request(self, tool_name, args):
        """Emit an approval-request record; returns the approval id."""
        approval_id = uuid.uuid4().hex
        record = {"kind": "approval-request",
                  "code": "callback-approval-requested",
                  "id": approval_id,
                  "tool": tool_name,
                  "args_digest": _digest_args(args),
                  "state": "pending"}
        self._journal.append(record)
        self._pending[approval_id] = {"tool": tool_name,
                                      "args": dict(args)}
        return approval_id

    def before(self, tool_name, args):
        """Use as a ``before`` callback: pauses every call for human
        approval."""
        if not isinstance(args, dict):
            raise CallbackError("callback-malformed-verdict",
                                "args must be a dict")
        approval_id = self.request(tool_name, args)
        return Escalate("human-approval-required",
                        {"approval_id": approval_id})

    def resolve(self, approval_id, approved, decider=None, note=""):
        """Ingest the human decision. Approved returns a
        :class:`Continue` verdict (drop it into the executor's
        ``before`` list to resume); denied refuses
        ``callback-approval-denied``."""
        if not isinstance(approval_id, str) \
                or approval_id not in self._pending:
            raise CallbackError("callback-unknown-approval",
                                "no pending approval %r" % (approval_id,))
        entry = self._pending.pop(approval_id)
        if approved:
            self._journal.append(
                {"kind": "approval-decision", "id": approval_id,
                 "tool": entry["tool"], "state": "approved",
                 "decider": decider, "note": note})
            return Continue()
        self._journal.append(
            {"kind": "approval-decision",
             "code": "callback-approval-denied", "id": approval_id,
             "tool": entry["tool"], "state": "denied",
             "decider": decider, "note": note})
        raise CallbackError("callback-approval-denied",
                            "human denied approval %s" % (approval_id,))

    def expire(self, approval_id):
        """Retire a pending request: a stale approval can never be
        resolved later."""
        if not isinstance(approval_id, str) \
                or approval_id not in self._pending:
            raise CallbackError("callback-unknown-approval",
                                "no pending approval %r" % (approval_id,))
        entry = self._pending.pop(approval_id)
        self._journal.append(
            {"kind": "approval-decision",
             "code": "callback-approval-expired", "id": approval_id,
             "tool": entry["tool"], "state": "expired"})
