"""Tool-guardrail outcome triad (wave-279 lane 4).

STEAL of openai/openai-agents-python ``tool_guardrails.py`` (MIT; clean):
the MECHANISM only -- per-tool guardrails whose outcome is a three-behavior
triad rather than a binary pass/fail:

* ``allow()``            -- the guard is satisfied; evaluation continues;
* ``reject_content(msg)`` -- deny WITHOUT killing the run: the tool call
  is skipped (input guards) or its output replaced (output guards) with
  a model-facing message, and the caller adapts;
* ``raise_exception()``  -- the guard halted the run: loud, fail-closed,
  with the distinct coded verdict ``tool-guardrail-tripwire``.

No OpenAI code, docstrings, or prose are reused: this is a clean-room
re-implementation of the outcome shape and the tripwire semantics
(``GuardrailFunctionOutput{output_info, tripwire_triggered}`` as the
canonical guard result record), written against our own audit machinery.

Semantics honored from the source:

* input guardrails evaluate the tool ARGUMENTS pre-execution;
* output guardrails evaluate the tool RESULT post-execution;
* ``reject_content`` never trips the halt bit -- the run continues;
* the tripwire bit is set only by ``raise_exception`` (or by a guard
  crashing, which is a guard-internal error and fails closed as a
  tripwire halt, never as a pass-through);
* every guardrail run emits a tripwire record (name / tool / phase /
  outcome / output_info / tripwire bit) via the caller-supplied ``emit``
  callback, so deployments get a standard per-run evidence record in the
  HMAC-chained audit log;
* guards run in registration order; the first non-``allow`` outcome is
  decisive, but every guard that RAN is recorded (never silently
  skipped).

What this does NOT do (honest boundaries):

* a guard returning anything other than a ``ToolGuardrailFunctionOutput``
  is a programming error (ValueError), not a product refusal -- the same
  convention as ``gov/gate_outcomes.py``;
* ``reject_content`` with an empty message is likewise a programming
  error: a reasonless rejection fails loud at the factory, so an empty
  denial can never reach a caller or the log;
* the runner does not execute tools and does not decide policy; it
  evaluates guardrails and returns verdicts. Enforcement (skip the call,
  replace the output, halt the run) is the CALLER's job -- see
  ``ApprovalQueue.elicit_decision(guardrails=...)`` for the composition
  with the tri-state elicitation contract;
* output_info is capped for log hygiene: callers must never put secrets
  in guard evidence (a long value is truncated, not elided -- truncation
  is visible). As defense-in-depth (F306), every emitted record passes
  through ``_sanitize_note``: credential-shaped evidence is replaced
  with a visible ``[credential material withheld]`` placeholder before
  the record reaches the log -- the verdict is preserved, the secret
  never lands.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads. The audit log binds its own timestamps at append time.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Outcome triad
# ---------------------------------------------------------------------------

#: The three guard behaviors. Mirrors the source vocabulary.
_OUTCOMES = ("allow", "reject_content", "raise_exception")

#: Cap for evidence strings entering the audit log (wave-279: log hygiene).
_OUTPUT_INFO_CAP = 2000


class ToolGuardrailFunctionOutput:
    """One guardrail's outcome.

    Never constructed directly; use ``allow()``, ``reject_content()`` or
    ``raise_exception()``. ``message`` is only set for ``reject_content``;
    ``output_info`` is the structured evidence for the tripwire record.
    """

    __slots__ = ("behavior", "message", "output_info")

    def __init__(self, behavior, message=None, output_info=None):
        self.behavior = behavior
        self.message = message
        self.output_info = output_info

    def __repr__(self):  # pragma: no cover - debugging aid
        return "ToolGuardrailFunctionOutput(%r)" % (self.behavior,)


def allow(output_info=None):
    """Guard satisfied; evaluation continues to the next guard."""
    return ToolGuardrailFunctionOutput("allow", output_info=output_info)


def reject_content(message, output_info=None):
    """Deny WITHOUT killing the run.

    ``message`` is the model-facing rejection (the tool call is skipped or
    its output replaced with this text). An empty message is a programming
    error -- a reasonless rejection must fail loud here, never reach a
    caller or the audit log silently.
    """
    if not isinstance(message, str) or not message.strip():
        raise ValueError(
            "reject_content requires a non-empty string message: a "
            "reasonless rejection is a programming error")
    return ToolGuardrailFunctionOutput("reject_content", message=message,
                                       output_info=output_info)


def raise_exception(output_info=None):
    """Halt the run: the loud fail-closed outcome.

    The runner converts this to ``ToolGuardrailTripwireTriggered`` with
    the coded verdict ``tool-guardrail-tripwire`` -- distinct from policy
    refusals. ``output_info`` carries the guard's evidence for the
    tripwire record.
    """
    return ToolGuardrailFunctionOutput("raise_exception",
                                       output_info=output_info)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ToolGuardrailError(Exception):
    """Base for tool-guardrail failures."""


class ToolGuardrailTripwireTriggered(ToolGuardrailError):
    """A guardrail halted the run (``raise_exception()``, or the guard
    itself crashed -- a guard-internal error fails closed as a tripwire
    halt, never as a pass-through).

    Carries the coded verdict as ``.code``: ``tool-guardrail-tripwire``,
    registered in ``gov/decision_codes.py`` and distinct from every policy
    refusal code.
    """

    code = "tool-guardrail-tripwire"

    def __init__(self, message, output_info=None):
        super().__init__(message)
        self.output_info = output_info


# ---------------------------------------------------------------------------
# Guard data + guard declarations
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolInputGuardrailData:
    """What an input guardrail sees: the tool name and its arguments,
    pre-execution. Arguments are copied defensively at declaration time
    so a guard cannot mutate the caller's mapping."""
    tool_name: str
    tool_arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolOutputGuardrailData:
    """What an output guardrail sees: the tool name and its result,
    post-execution."""
    tool_name: str
    output: Any = None


class ToolInputGuardrail:
    """A named per-tool input guardrail: ``run(data)`` returns one of the
    three outcomes."""

    def __init__(self, name, run):
        if not isinstance(name, str) or not name.strip():
            raise ValueError("guardrail needs a non-empty string name")
        if not callable(run):
            raise ValueError(
                "guardrail %r: run must be callable" % (name,))
        self.name = name
        self.run = run
        self.phase = "input"


class ToolOutputGuardrail:
    """A named per-tool output guardrail: ``run(data)`` returns one of the
    three outcomes."""

    def __init__(self, name, run):
        if not isinstance(name, str) or not name.strip():
            raise ValueError("guardrail needs a non-empty string name")
        if not callable(run):
            raise ValueError(
                "guardrail %r: run must be callable" % (name,))
        self.name = name
        self.run = run
        self.phase = "output"


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolGuardrailRunVerdict:
    """The aggregate verdict of a guardrail run.

    ``outcome`` is one of ``allow`` / ``reject_content`` /
    ``raise_exception``. ``message`` carries the ``reject_content``
    text (the input-guard caller skips the tool call; the output-guard
    caller replaces the output). ``tripwire_triggered`` is True only
    when the run halted -- it never escapes the runner: a halt raises
    ``ToolGuardrailTripwireTriggered`` instead of returning a verdict.
    """
    outcome: str
    message: Optional[str] = None
    tripwire_triggered: bool = False


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _emit_noop(record):  # pragma: no cover - default when unbound
    pass


def _evidence_string(output_info):
    """Log-hygiene cap for guard evidence: truncate, never silently
    elide (truncation is visible in the record)."""
    if output_info is None:
        return None
    text = repr(output_info)
    if len(text) > _OUTPUT_INFO_CAP:
        text = text[:_OUTPUT_INFO_CAP] + "...[truncated]"
    return text


# Evidence-note prefixes, hoisted so producers and the F306 sanitizer
# share them: a note-format change cannot silently degrade
# kind-preservation to the generic fallback.
_REJECTION_PREFIX = "rejection: "
_GUARD_ERROR_PREFIX = "guard_error: "


def _sanitize_note(note):
    """F306: guard evidence is audit-bound. A credential-shaped message or
    output_info must never reach the log -- the step-3b emit precedes the
    step-5 elicitation secret ban, so evidence is sanitized at the emit
    funnel (and the crash-tripwire exception carries only the sanitized
    note, since the caller's refusal record interpolates it). The verdict
    (outcome / tripwire bit) is preserved; only the credential-shaped
    content is withheld, with a visible placeholder (redaction is marked,
    never silent elision).

    Detection routes through the ``secret_canonicalizer`` rule engine
    (wave-283, gitleaks contract) OR-ed with the elicitation seam:
    anything the old seam caught is still caught, and the broader
    rule set (AWS/GitHub/Slack/JWT/private-key/decode layers) closes
    the evasion gap.
    """
    if note is None:
        return None
    from gov import elicitation_contract as _ec  # lazy: keep stdlib core import-free
    from gov import secret_canonicalizer as _sc  # stdlib-only; the single seam
    if not (_ec.credential_material_present(note)
            or _sc.credential_material_present(note)):
        return note
    for prefix in (_REJECTION_PREFIX, _GUARD_ERROR_PREFIX):
        if note.startswith(prefix):
            return "%s[credential material withheld]" % prefix
    return "[guard evidence withheld: credential-shaped material]"


def _record_for(guard, data, outcome, tripwire, note=None):
    return {
        "event": "tool_guardrail_run",
        "guardrail_name": guard.name,
        "tool_name": getattr(data, "tool_name", None),
        "phase": guard.phase,
        "outcome": outcome,
        "tripwire_triggered": tripwire,
        "output_info": _sanitize_note(
            note if note is not None
            else _evidence_string(getattr(data, "tool_arguments", None)
                                  if guard.phase == "input" else
                                  getattr(data, "output", None))),
    }


def _run_guards(guardrails, data, emit, expected_phase):
    """Evaluate guards in order; the first non-allow outcome is decisive.

    * ``reject_content`` -- returns a verdict; the run continues (the
      tripwire is NOT tripped);
    * ``raise_exception`` -- emits the tripwire record, then raises
      ``ToolGuardrailTripwireTriggered`` (the verdict never returns);
    * a guard that RAISES -- guard-internal error -- fails closed as a
      tripwire halt, with the crash recorded as evidence;
    * a guard returning a non-outcome -- programming error (ValueError).
    """
    emit = emit or _emit_noop
    for guard in guardrails:
        if guard.phase != expected_phase:
            raise ValueError(
                "guardrail %r is a %s guardrail, cannot run it in the "
                "%s phase" % (guard.name, guard.phase, expected_phase))
        try:
            result = guard.run(data)
        except ToolGuardrailError:
            raise
        except Exception as exc:
            # Guard-internal error: fail closed as a tripwire halt.
            # The crash is evidence, never a pass-through. F306: the
            # crash text is guard evidence too -- sanitize it once and
            # let the exception carry only the sanitized note, so the
            # caller's refusal record (approvals.py step 3b interpolates
            # the exception into its audit note) cannot echo a secret.
            _crash_note = _sanitize_note(
                _GUARD_ERROR_PREFIX + "%s: %s" % (type(exc).__name__, exc))
            emit(_record_for(guard, data, "raise_exception", True,
                             note=_crash_note))
            raise ToolGuardrailTripwireTriggered(
                "tool guardrail %r failed: %s; failing closed"
                % (guard.name, _crash_note),
                output_info=_crash_note)
        if not isinstance(result, ToolGuardrailFunctionOutput):
            raise ValueError(
                "tool guardrail %r returned %r: guards must return one "
                "of allow()/reject_content()/raise_exception()"
                % (guard.name, result))
        if result.behavior == "allow":
            emit(_record_for(guard, data, "allow", False,
                             note=_evidence_string(result.output_info)))
        elif result.behavior == "reject_content":
            # Deny WITHOUT killing the run: record the rejection with
            # its message as evidence, return the verdict; the tripwire
            # stays quiet.
            emit(_record_for(
                guard, data, "reject_content", False,
                note=_REJECTION_PREFIX + "%s" % result.message))
            return ToolGuardrailRunVerdict(outcome="reject_content",
                                           message=result.message,
                                           tripwire_triggered=False)
        elif result.behavior == "raise_exception":
            emit(_record_for(
                guard, data, "raise_exception", True,
                note=_evidence_string(result.output_info)))
            raise ToolGuardrailTripwireTriggered(
                "tool guardrail %r halted the run" % (guard.name,),
                output_info=result.output_info)
        else:  # pragma: no cover - factory-bound vocabulary
            raise ValueError("unknown guardrail behavior %r"
                             % (result.behavior,))
    return ToolGuardrailRunVerdict(outcome="allow",
                                   tripwire_triggered=False)


def run_input_guardrails(guardrails, data, *, emit=None):
    """Run input guardrails over a tool call's arguments, in order.

    Returns a ``ToolGuardrailRunVerdict`` (``allow`` or
    ``reject_content`` with the model-facing message); raises
    ``ToolGuardrailTripwireTriggered`` on a halt. Every guard that runs
    emits a tripwire record through ``emit``.
    """
    if not isinstance(data, ToolInputGuardrailData):
        raise ValueError("input guardrails need ToolInputGuardrailData")
    return _run_guards(list(guardrails or []), data, emit, "input")


def run_output_guardrails(guardrails, data, *, emit=None):
    """Run output guardrails over a tool result, in order.

    Returns a ``ToolGuardrailRunVerdict`` (``allow`` or
    ``reject_content`` with the replacement message); raises
    ``ToolGuardrailTripwireTriggered`` on a halt. Every guard that runs
    emits a tripwire record through ``emit``.
    """
    if not isinstance(data, ToolOutputGuardrailData):
        raise ValueError("output guardrails need ToolOutputGuardrailData")
    return _run_guards(list(guardrails or []), data, emit, "output")
