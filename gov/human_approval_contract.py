"""Function-layer human approval contract (HumanLayer ADAPT).

HumanLayer -- the YC F24 "Human-in-the-Loop API" (legacy repo
``humanlayer/humanlayer``, Apache-2.0, now DEPRECATED; the
humanlayer.com rebuild is a separate proprietary product) -- established
the approval-request CONTRACT as a set of mechanisms this module
adapts:

* approval needs are DECLARED ON THE FUNCTION (a decorator on the tool),
  so the gate is deterministic and -- at the call sites that use it --
  prompt-injection-proof: never a system-prompt plea the agent can
  talk its way around. (Residual: executor-dispatch wiring is an
  explicit non-goal below; the gate is only as strong as its call
  sites.)
* the approval is agent-initiated: request -> wait -> human decision ->
  resume (the outer loop);
* the human outcomes are approve / deny / EDIT / timeout (edit is the
  novel outcome: the human approves MODIFIED args, and the modification
  is recorded as audit evidence with its own chain entry);
* a 4-tier function-stakes taxonomy decides which functions get the
  gate;
* every human decision lands in a durable audit trail (who, what, when,
  decision) -- here: the same HMAC-chained audit log the engine's
  decisions use, so the chain covers human-in-the-loop governance end
  to end.

ADAPT means contract shapes only: no HumanLayer code, text, SDK, or
service is reused, vendored, or contacted here. Everything is
re-implemented against gov.approvals.

What this module provides:

* ``ApprovalNeed`` -- the declarative per-function approval need
  (tool, stakes tier, contact channel, wait horizon). Declared in CODE,
  never in prompt text: agent framing ("no approval needed") cannot
  suppress a declared need.
* A process-local registry -- ``declare`` / ``need_for`` /
  ``requires_approval`` -- the deployment's single authority for
  "which tools need a human". ``request_human_decision`` refuses
  undeclared tools fail-closed (contract violation), so a missing
  declaration is never silently treated as "no approval needed".
* Stakes tiers (low / medium / high / critical) + per-tier default wait
  horizons.
* ``request_human_decision`` -- the agent-initiated outer loop: queue
  the request (persisted in the approval store BEFORE dispatch), block
  on the human, resume with a ``HumanDecision``
  (APPROVED / DENIED / EDITED / TIMED_OUT). Timeouts stamp the record
  ``request_expired`` and audit loudly -- a timed-out request can never
  be resurrected by a late human decision (fail-closed, mirroring the
  T11/T12 bridge-wait semantics).
* ``mark_request_expired`` is exposed on ApprovalQueue itself; this
  module drives it.

Explicit non-goals (honest residuals, follow-on work):

* Contact-channel DELIVERY (Slack/email/SMS/dashboard). The channel
  rides the record as contract data; the instrument that reaches the
  human is a deployment concern, not this lane.
* Wiring the registry into ``ToolExecutor.call``'s dispatch path. The
  executor must consult ``requires_approval(tool)`` before executing
  contract-covered tools without a human decision; until it does, the
  contract is enforced at the ``request_human_decision`` call sites.
* ``allow_edit`` per need: the human operator is the trust principal
  for edits, so ``decide()`` accepts ``edited_args`` from any human
  (audit-chained, MAC-bound to the decider). A deployment that wants
  to forbid edits enforces it in its decision instrument, not here.
"""

import copy
import json
import time

# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------

#: The agent's action runs as requested.
APPROVED = "approved"
#: The human refused; the agent must not run the action.
DENIED = "denied"
#: The human approved MODIFIED args; the agent runs the edited args.
EDITED = "edited"
#: The human wait lapsed; fail-closed (the agent must not run).
TIMED_OUT = "timed_out"

OUTCOMES = (APPROVED, DENIED, EDITED, TIMED_OUT)


class HumanDecision(object):
    """What the outer loop returns when the human (or the clock) answers.

    ``outcome`` is one of OUTCOMES. ``approval_id`` is the queued
    record. ``edited_args`` is the human-modified args dict on EDITED,
    else None. ``record`` is a detached copy of the decided record.
    """

    def __init__(self, outcome, approval_id, edited_args=None, record=None):
        if outcome not in OUTCOMES:
            raise ValueError(
                "HumanDecision refused: unknown outcome %r" % (outcome,))
        self.outcome = outcome
        self.approval_id = approval_id
        self.edited_args = (copy.deepcopy(edited_args)
                            if edited_args is not None else None)
        self.record = (copy.deepcopy(record)
                       if record is not None else None)

    def __repr__(self):  # pragma: no cover - debugging aid
        return "HumanDecision(%r, %r)" % (self.outcome, self.approval_id)


# ---------------------------------------------------------------------------
# Stakes taxonomy (HumanLayer 4-tier, adapted)
# ---------------------------------------------------------------------------

#: Read-only public data; the agent author is notified.
STAKES_LOW = "low"
#: Read private data; communicate under strict templates.
STAKES_MEDIUM = "medium"
#: Communicate on behalf of the human/company; write access to private
#: data.
STAKES_HIGH = "high"
#: Irreversible effects: data destruction, identity/key material,
#: financial moves, safety systems.
STAKES_CRITICAL = "critical"

STAKES_TIERS = (STAKES_LOW, STAKES_MEDIUM, STAKES_HIGH, STAKES_CRITICAL)

#: Mapping of the declared stakes tier onto the approval engine's
#: existing risk continuum (see ``gov.approvals._score_factors``).
#: Monotone, escalation-only: a higher declared tier adds risk points
#: to the record's packet risk score, which feeds the EXISTING
#: approval-level machinery -- harder to auto-approve, sooner
#: cooling-off (>=80), capture-tier approver shield (>=70). Never
#: negative, and the scorer caps at 100. Records queued without a
#: declared tier score exactly as before.
STAKES_RISK_BUMP = {
    STAKES_LOW: 0,
    STAKES_MEDIUM: 10,
    STAKES_HIGH: 20,
    STAKES_CRITICAL: 30,
}

#: Default human-wait horizons per tier (seconds). Higher stakes get a
#: longer review window -- the human needs more time, not less. These
#: are contract defaults; an explicit timeout_s overrides them.
_DEFAULT_WAIT_HORIZONS = {
    STAKES_LOW: 300.0,
    STAKES_MEDIUM: 900.0,
    STAKES_HIGH: 1800.0,
    STAKES_CRITICAL: 3600.0,
}

_MAX_WAIT_HORIZON_SECS = 24 * 3600.0  # fail-safe ceiling: one day


def validate_stakes(tier):
    """Return the canonical tier, or raise ValueError (fail-closed)."""
    if tier not in STAKES_TIERS:
        raise ValueError(
            "unknown stakes tier %r: must be one of %s"
            % (tier, ", ".join(STAKES_TIERS)))
    return tier


def default_wait_horizon(tier):
    """Default human-wait horizon in seconds for a stakes tier."""
    return _DEFAULT_WAIT_HORIZONS[validate_stakes(tier)]


# ---------------------------------------------------------------------------
# ApprovalNeed: the declarative per-function contract
# ---------------------------------------------------------------------------

class ApprovalNeed(object):
    """The approval contract for one function/tool.

    ``tool`` is the tool name (exact match). ``stakes`` is a STAKES_*
    tier. ``channel`` names where the human is reached
    ("console" / "slack" / "email" / "sms" / ...): contract DATA for
    the decision instrument -- this lane ships no delivery
    integration. ``wait_timeout_s`` overrides the tier default.
    """

    def __init__(self, tool, stakes, channel="console", wait_timeout_s=None):
        if not tool or not isinstance(tool, str):
            raise ValueError(
                "ApprovalNeed refused: tool must be a non-empty string")
        self.tool = tool
        self.stakes = validate_stakes(stakes)
        if (not channel or not isinstance(channel, str)
                or not channel.strip() or len(channel) > 64):
            raise ValueError(
                "ApprovalNeed refused: channel must be a non-empty "
                "string (<= 64 chars)")
        self.channel = channel.strip()
        if wait_timeout_s is None:
            wait_timeout_s = default_wait_horizon(self.stakes)
        if (isinstance(wait_timeout_s, bool)
                or not isinstance(wait_timeout_s, (int, float))):
            raise ValueError(
                "ApprovalNeed refused: wait_timeout_s must be a number, "
                "got %r" % type(wait_timeout_s).__name__)
        if (not wait_timeout_s == wait_timeout_s
                or wait_timeout_s in (float("inf"), float("-inf"))):
            raise ValueError(
                "ApprovalNeed refused: wait_timeout_s must be finite")
        if wait_timeout_s <= 0:
            raise ValueError(
                "ApprovalNeed refused: wait_timeout_s must be positive")
        if wait_timeout_s > _MAX_WAIT_HORIZON_SECS:
            raise ValueError(
                "ApprovalNeed refused: wait_timeout_s exceeds the "
                "fail-safe ceiling of %ss" % _MAX_WAIT_HORIZON_SECS)
        self.wait_timeout_s = float(wait_timeout_s)

    def as_dict(self):
        return {"tool": self.tool, "stakes": self.stakes,
                "channel": self.channel,
                "wait_timeout_s": self.wait_timeout_s}

    def __repr__(self):  # pragma: no cover - debugging aid
        return "ApprovalNeed(%r, %r)" % (self.tool, self.stakes)


# ---------------------------------------------------------------------------
# Registry: the deployment's single authority
# ---------------------------------------------------------------------------

_NEEDS = {}


def declare(need):
    """Register an ApprovalNeed. Duplicate tools are refused (no silent
    overwrite -- two deployments disagreeing about a tool's stakes is a
    configuration error, and the loud refusal beats a quiet merge)."""
    if not isinstance(need, ApprovalNeed):
        raise TypeError(
            "declare() refused: expected ApprovalNeed, got %s"
            % type(need).__name__)
    if need.tool in _NEEDS:
        raise ValueError(
            "declare() refused: an ApprovalNeed is already declared for "
            "tool %r" % (need.tool,))
    _NEEDS[need.tool] = need
    return need


def need_for(tool):
    """The declared ApprovalNeed for a tool, or None."""
    return _NEEDS.get(tool)


def requires_approval(tool):
    """Authoritative answer to "does this tool need a human?".

    Consults the registry ONLY -- never caller-supplied hints, never
    agent framing. The executor's dispatch path (follow-on wiring)
    must consult this before executing contract-covered tools.
    """
    return tool in _NEEDS


def reset_registry():
    """Test seam: clear all declarations."""
    _NEEDS.clear()


# ---------------------------------------------------------------------------
# Agent-initiated outer loop
# ---------------------------------------------------------------------------

_POLL_SECS = 0.05


class _ContractVerdict(object):
    """Minimal policy-verdict shim for the contract queue path.

    The outer loop queues through ApprovalQueue.queue(), which expects
    a decision object carrying policy_id / reason / flag. Building the
    real PolicyDecision here would import gov.policy, which imports
    gov.approvals -- a cycle (approvals imports this module for
    stakes validation). The shim carries exactly the three attributes
    queue() reads, nothing more.
    """

    def __init__(self, reason, policy_id, flag):
        self.reason = reason
        self.policy_id = policy_id
        self.flag = flag


def _check_timeout(timeout_s):
    if (isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))):
        raise TypeError(
            "timeout_s must be a number of seconds, got %r"
            % type(timeout_s).__name__)
    if (not timeout_s == timeout_s
            or timeout_s in (float("inf"), float("-inf"))):
        raise ValueError("timeout_s must be finite")
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    if timeout_s > _MAX_WAIT_HORIZON_SECS:
        raise ValueError(
            "timeout_s %s exceeds the fail-safe ceiling of %ss"
            % (timeout_s, _MAX_WAIT_HORIZON_SECS))
    return float(timeout_s)


def _check_poll(poll_s):
    if (isinstance(poll_s, bool)
            or not isinstance(poll_s, (int, float))):
        raise TypeError(
            "poll_s must be a number of seconds, got %r"
            % type(poll_s).__name__)
    if (not poll_s == poll_s
            or poll_s in (float("inf"), float("-inf"))):
        raise ValueError("poll_s must be finite")
    if poll_s <= 0:
        raise ValueError("poll_s must be positive")
    return float(poll_s)


def request_human_decision(queue, tool, args, agent_identity, need=None,
                           agent_justification=None, timeout_s=None,
                           poll_s=_POLL_SECS):
    """Agent-initiated outer loop: request -> wait -> decide -> resume.

    Queues a human approval request for ``tool``/``args`` (the request
    is PERSISTED in the approval store before this function returns
    control to the waiter), then blocks until a human decides or the
    wait lapses, and returns a ``HumanDecision``.

    ``need`` defaults to the registry declaration for ``tool``; an
    undeclared tool is refused fail-closed (a missing declaration is
    never silently treated as "no approval needed"). ``timeout_s``
    defaults to the need's horizon. ``agent_justification`` is stored
    verbatim but labeled UNVERIFIED everywhere it is displayed (the
    queue's standing posture) -- and it can NEVER suppress the request:
    the registry is the authority, not the agent's framing.

    Outcomes: APPROVED (run as requested), DENIED (do not run),
    EDITED (run the human-modified args -- ``decision.edited_args``),
    TIMED_OUT (the wait lapsed; the record is stamped request_expired
    and can never be decided -- fail-closed).
    """
    if not tool or not isinstance(tool, str):
        raise ValueError("request_human_decision refused: tool must be a "
                         "non-empty string")
    if need is None:
        need = need_for(tool)
    if need is None:
        raise ValueError(
            "request_human_decision refused: no ApprovalNeed declared for "
            "tool %r -- an undeclared tool is a contract violation, never "
            "an implicit no-approval" % (tool,))
    if not isinstance(need, ApprovalNeed):
        raise TypeError(
            "request_human_decision refused: need must be ApprovalNeed, "
            "got %s" % type(need).__name__)
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise TypeError(
            "request_human_decision refused: args must be a dict, got %r"
            % type(args).__name__)
    timeout_s = (_check_timeout(timeout_s) if timeout_s is not None
                 else need.wait_timeout_s)
    poll_s = _check_poll(poll_s)

    verdict = _ContractVerdict(
        reason=("human approval requested for tool %r (stakes %s, channel "
                "%s)" % (tool, need.stakes, need.channel)),
        policy_id="human-approval-contract",
        flag="human_approval_request")
    preview = ("Human approval requested for tool %r (stakes: %s, "
               "channel: %s)." % (tool, need.stakes, need.channel))
    approval_id = queue.queue(
        {"tool": tool,
         "args": copy.deepcopy(args),
         "agent_justification": agent_justification,
         "redactions": []},
        verdict,
        "agent_direct",
        preview,
        caller_identity=agent_identity,
        stakes_tier=need.stakes)

    def _read_live():
        # Fail-fast AND fail-closed: the record was queued by THIS
        # call and must remain visible for the whole wait. A vanished
        # record is NOT a timeout -- the request was destroyed outside
        # the audit-chained API (tamper or operator file removal), so
        # reporting "no human decided in time" would lie to the agent.
        # Refuse LOUDLY; the caller treats the request as untrusted,
        # never as unanswered.
        rec = queue.get(approval_id)
        if rec is None:
            raise ValueError(
                "request_human_decision refused: approval record %r "
                "vanished mid-wait -- the request was destroyed outside "
                "the audit chain and cannot be verified; it is not "
                "approved and is not a timeout" % (approval_id,))
        return rec

    deadline = time.monotonic() + timeout_s
    while True:
        rec = _read_live()
        outcome = _classify(rec)
        if outcome is not None:
            return outcome
        now = time.monotonic()
        if now >= deadline:
            break
        time.sleep(min(poll_s, deadline - now))
    # Last-gap race: re-read once after the deadline -- a decision that
    # landed in the final poll gap is still honored.
    rec = _read_live()
    outcome = _classify(rec)
    if outcome is not None:
        return outcome
    queue.mark_request_expired(
        approval_id,
        "human wait timed out after %ss (stakes %s, channel %s)"
        % (timeout_s, need.stakes, need.channel))
    return HumanDecision(TIMED_OUT, approval_id)


def _classify(rec):
    """Map a queue record to a HumanDecision, or None if still pending."""
    if rec is None:
        return None
    status = rec.get("status")
    approval_id = rec.get("id")
    if status == "approved":
        if rec.get("human_outcome") == "edited":
            return HumanDecision(EDITED, approval_id,
                                 edited_args=rec.get("args"), record=rec)
        return HumanDecision(APPROVED, approval_id, record=rec)
    if status == "rejected":
        return HumanDecision(DENIED, approval_id, record=rec)
    if status == "cancelled":
        # A cancelled elicitation can never execute (wave-278) -- for
        # the waiting agent it is the deny direction.
        return HumanDecision(DENIED, approval_id, record=rec)
    if rec.get("request_expired"):
        return HumanDecision(TIMED_OUT, approval_id, record=rec)
    return None
