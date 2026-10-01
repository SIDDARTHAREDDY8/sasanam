"""Failure-action correction pipeline (wave-261 lane 2).

guardrails-ai OnFailAction ADAPT -- the 8-member named failure-action
vocabulary (reask / fix / fix_reask / filter / refrain / noop /
exception / custom) plus the FailResult diagnostics handoff. Pattern
only; no guardrails code and none of its LLM machinery.

Recombination: our fail-closed checks currently refuse and stop; they
lack a correction pipeline. This module supplies it: every refusal
can carry a FailResult (machine code + diagnostics + prescribed
action), and apply_action() executes the safe subset:

  - exception: raise the machine-coded error. Today's behavior, and
    the default for every unknown situation.
  - filter: redact the offending field -- named by
    diagnostics["field_path"] -- from a COPY of the caller's value
    and continue. Byte-level no-bypass guarantee: the offending
    subvalue is digested before redaction, and after redaction the
    whole copy is swept; if those bytes survive at any other path
    (aliasing the caller did not name), the filter refuses instead of
    returning a tainted value.
  - refrain: stop this step, continue the run. The run's own audit is
    never touched; only the context journal records the decision.
  - noop: record the decision and continue.
  - reask / fix / fix_reask: agentic actions. Returned as structured
    action-requests the CALLER honors -- this module never
    auto-repairs caller data; fail-closed stays the default. The
    decision is recorded.
  - custom: a caller-supplied handler taken from the context. A
    missing or raising handler fails closed to exception.

Fail-closed rules (all pinned by evals/w261_failaction_probes.py):
  - unknown action name -> exception. The FailResult's OWN machine
    code is re-raised; a code is never invented or widened.
  - an action handler that errors -> exception (Exception only;
    BaseException such as KeyboardInterrupt or SystemExit propagates
    raw and is never masked).
  - never silently downgrade a refusal to an allow: every path either
    raises the machine-coded error or returns an explicit disposition
    ("continued" / "refrained" / "requested" / "custom") the caller
    must interpret.

No new decision codes: every refusal raised here re-raises the
FailResult's own machine code, so the taxonomy pin does not move.

Stdlib only.
"""

import copy
import hashlib
import json
import re
from datetime import datetime, timezone

__all__ = [
    "DEFAULT_ACTION",
    "ActionRequest",  # documentation alias; see action_request()
    "FailResult",
    "FailureActionError",
    "OnFailAction",
    "action_request",
    "apply_action",
    "is_known_action",
]


class OnFailAction:
    """First-class failure-action vocabulary (8 members).

    Names are lowercase strings (the guardrails-ai OnFailAction shape,
    re-grounded). They are action names, never decision codes: they
    must never flow into a machine-code position.
    """

    REASK = "reask"
    FIX = "fix"
    FIX_REASK = "fix_reask"
    FILTER = "filter"
    REFRAIN = "refrain"
    NOOP = "noop"
    EXCEPTION = "exception"
    CUSTOM = "custom"


_VOCABULARY = frozenset((
    OnFailAction.REASK,
    OnFailAction.FIX,
    OnFailAction.FIX_REASK,
    OnFailAction.FILTER,
    OnFailAction.REFRAIN,
    OnFailAction.NOOP,
    OnFailAction.EXCEPTION,
    OnFailAction.CUSTOM,
))

# The default prescription for every unknown situation.
DEFAULT_ACTION = OnFailAction.EXCEPTION

# Dispositions returned by apply_action(). "continued" means the caller
# may proceed with payload["value"] (filter) or as before (noop);
# "refrained" means this step stops but the run continues; "requested"
# means the caller must honor the action-request; "custom" carries the
# caller handler's opaque result.
_DISPOSITIONS = ("continued", "refrained", "requested", "custom")

# Agentic actions: never executed here, returned as caller-honored
# structured requests.
_AGENTIC_ACTIONS = frozenset((
    OnFailAction.REASK,
    OnFailAction.FIX,
    OnFailAction.FIX_REASK,
))


def is_known_action(name):
    """True when name is a member of the OnFailAction vocabulary."""
    return isinstance(name, str) and name in _VOCABULARY


class FailResult:
    """Machine code + diagnostics + prescribed on-fail action.

    Pure data: constructing one performs no correction. Vocabulary
    membership is enforced by apply_action(), which fails closed on
    unknown action names (the FailResult's own machine code is
    re-raised).
    """

    __slots__ = ("code", "action", "detail", "diagnostics")

    def __init__(self, code, action, detail="", diagnostics=None):
        if not isinstance(code, str) or not code:
            raise TypeError(
                "FailResult code must be a non-empty string")
        if not isinstance(action, str) or not action:
            raise TypeError(
                "FailResult action must be a non-empty string")
        if not isinstance(detail, str):
            raise TypeError("FailResult detail must be a string")
        if diagnostics is not None and \
                not isinstance(diagnostics, dict):
            raise TypeError(
                "FailResult diagnostics must be a dict or None")
        self.code = code
        self.action = action
        self.detail = detail
        try:
            self.diagnostics = copy.deepcopy(diagnostics) \
                if diagnostics else {}
        except Exception:
            # Diagnostics are advisory; a hostile object here must not
            # break the refusal itself.
            self.diagnostics = {}

    def __repr__(self):
        return "FailResult(code=%r, action=%r)" % (self.code,
                                                   self.action)


class FailureActionError(Exception):
    """The machine-coded refusal, carrying the FailResult.

    The first positional argument is the machine code (the FailResult's
    own code, never invented here); the FailResult rides along so the
    caller can feed it back into apply_action().
    """

    def __init__(self, code, message, fail_result=None):
        super().__init__(message)
        self.code = code
        self.fail_result = fail_result


# Documentation alias: action_request() builds these dicts.
ActionRequest = dict


def action_request(fail_result, constraints=None):
    """Build the structured caller-honored request for an agentic action.

    The caller (an agent loop, an approval queue, a human) decides what
    reask / fix / fix_reask mean; this module only names the need and
    records the decision. Never auto-repairs caller data.
    """
    if not isinstance(fail_result, FailResult):
        raise TypeError("action_request requires a FailResult")
    if constraints is not None and not isinstance(constraints, dict):
        raise TypeError(
            "action_request constraints must be a dict or None")
    try:
        diagnostics = copy.deepcopy(fail_result.diagnostics)
    except Exception:
        diagnostics = {}
    return {
        "type": "action-request",
        "action": fail_result.action,
        "code": fail_result.code,
        "detail": fail_result.detail,
        "diagnostics": diagnostics,
        "constraints": dict(constraints) if constraints else {},
    }


# ---------------------------------------------------------------------------
# Journal (the pipeline's decision log; caller-owned via the context)
# ---------------------------------------------------------------------------

def _record(context, fail_result, disposition):
    """Append the decision to context["journal"] when it is a list.

    Returns True when recorded. Never touches anything else -- in
    particular never the run's own audit log.
    """
    journal = context.get("journal")
    if not isinstance(journal, list):
        return False
    journal.append({
        "action": fail_result.action,
        "code": fail_result.code,
        "disposition": disposition,
        "detail": fail_result.detail,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    })
    return True


def _outcome(fail_result, disposition, payload):
    return {
        "action": fail_result.action,
        "code": fail_result.code,
        "disposition": disposition,
        "detail": fail_result.detail,
        "payload": payload,
    }


def _raise_as_exception(fail_result, message):
    """Fail closed: re-raise the FailResult's own machine code."""
    raise FailureActionError(fail_result.code, message,
                             fail_result=fail_result)


# ---------------------------------------------------------------------------
# Field paths for the filter action
# ---------------------------------------------------------------------------

# One dot-separated segment: an optional dict key followed by zero or
# more [n] list indices. Paths are relative to context["value"]:
# "[1]", "items[2]", "[0].note". There is no root alias; the empty
# path (redact the whole value) is rejected -- that is refrain or
# exception territory, never a filter.
_SEGMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)?((?:\[\d+\])*)$")
_INDEX_RE = re.compile(r"\[(\d+)\]")


def _parse_field_path(path):
    """Parse a filter field path into [("key"|"index", selector)] steps.

    Raises ValueError on any malformed shape (fail-closed at the
    apply site).
    """
    if not isinstance(path, str) or not path:
        raise ValueError("field path must be a non-empty string")
    steps = []
    for part in path.split("."):
        match = _SEGMENT_RE.match(part)
        if not match or (match.group(1) is None
                         and not match.group(2)):
            raise ValueError("malformed field path segment %r in %r"
                             % (part, path))
        if match.group(1) is not None:
            steps.append(("key", match.group(1)))
        for index in _INDEX_RE.finditer(match.group(2)):
            steps.append(("index", int(index.group(1))))
    if not steps:
        raise ValueError("empty field path")
    return steps


def _navigate(value, steps):
    """Resolve steps against value; ValueError when unresolvable."""
    current = value
    for kind, selector in steps:
        if kind == "key":
            if not isinstance(current, dict) or \
                    selector not in current:
                raise ValueError("field path does not resolve")
            current = current[selector]
        else:
            if not isinstance(current, (list, tuple)) or \
                    not 0 <= selector < len(current):
                raise ValueError("field path does not resolve")
            current = current[selector]
    return current


def _delete_at(value, steps):
    """Delete the final step's target from a mutable copy.

    Tuples are immutable: a path through (or ending at) a tuple
    cannot be redacted in place and fails closed.
    """
    parent = _navigate(value, steps[:-1]) if len(steps) > 1 else value
    kind, selector = steps[-1]
    if kind == "key":
        if not isinstance(parent, dict) or selector not in parent:
            raise ValueError("field path does not resolve")
        del parent[selector]
    else:
        if not isinstance(parent, list) or \
                not 0 <= selector < len(parent):
            raise ValueError("field path does not resolve")
        del parent[selector]


def _canonical_digest(obj):
    """Stable digest of a subvalue for the no-bypass sweep."""
    try:
        blob = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        blob = ("repr:" + repr(obj)).encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()


class _SweepOverflow(Exception):
    """Internal: the no-bypass sweep exceeded its subvalue budget."""


_MAX_SWEEP_SUBVALUES = 50000


def _iter_subvalues(value):
    """Yield every subvalue exactly once; cycle-safe via id().

    Dict KEYS are byte-carrying positions of the value graph and are
    yielded too (F238): exact offending bytes surviving as a key must
    trip the no-bypass sweep just like an aliased value does.

    Raises _SweepOverflow past the budget: an unverifiable redaction
    fails closed rather than returning unchecked.
    """
    seen = set()
    stack = [value]
    count = 0
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        count += 1
        if count > _MAX_SWEEP_SUBVALUES:
            raise _SweepOverflow()
        yield current
        if isinstance(current, dict):
            stack.extend(current.values())
            stack.extend(current.keys())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)


def _apply_filter(fail_result, context):
    diagnostics = fail_result.diagnostics
    field_path = diagnostics.get("field_path") \
        if isinstance(diagnostics, dict) else None
    if not isinstance(field_path, str) or not field_path:
        _raise_as_exception(
            fail_result,
            "filter needs diagnostics['field_path'] (non-empty "
            "string); failing closed")
    if "value" not in context:
        _raise_as_exception(
            fail_result,
            "filter needs context['value']; failing closed")
    try:
        working = copy.deepcopy(context["value"])
    except Exception:
        _raise_as_exception(
            fail_result,
            "filter cannot copy context['value']; failing closed")
    try:
        steps = _parse_field_path(field_path)
        offending = _navigate(working, steps)
    except ValueError as exc:
        _raise_as_exception(
            fail_result,
            "filter field path unusable (%s); failing closed" % (exc,))
    target_digest = _canonical_digest(offending)
    try:
        _delete_at(working, steps)
    except ValueError as exc:
        _raise_as_exception(
            fail_result,
            "filter could not redact (%s); failing closed" % (exc,))
    # No-bypass sweep: the offending bytes must not survive at any
    # other path (aliasing the diagnostics did not name). Byte-level
    # guarantee: byte-identical survivors ARE the offending bytes.
    try:
        for subvalue in _iter_subvalues(working):
            if _canonical_digest(subvalue) == target_digest:
                _raise_as_exception(
                    fail_result,
                    "filter bypass: offending bytes survive at "
                    "another path; failing closed")
    except _SweepOverflow:
        _raise_as_exception(
            fail_result,
            "filter cannot verify redaction (value too large); "
            "failing closed")
    _record(context, fail_result, "continued")
    return _outcome(fail_result, "continued",
                    {"value": working, "redacted_path": field_path})


# ---------------------------------------------------------------------------
# apply_action()
# ---------------------------------------------------------------------------

def apply_action(fail_result, context=None):
    """Execute the safe subset of the failure-action vocabulary.

    fail_result: a FailResult (machine code + diagnostics + prescribed
      action). Anything else is a programming error -> TypeError.
    context: optional caller dict. Recognized keys:
      - "value": the offending payload (filter redacts a copy of it).
      - "journal": a list the decision is appended to.
      - "handler": callable(fail_result, context) for custom.
      - "constraints": dict attached to agentic action-requests.

    Returns a disposition dict {"action", "code", "disposition",
    "detail", "payload"} where disposition is one of "continued",
    "refrained", "requested", "custom". The exception action (and
    every fail-closed violation) RAISES FailureActionError carrying
    the FailResult's own machine code -- never silently downgraded.
    """
    if not isinstance(fail_result, FailResult):
        raise TypeError("apply_action requires a FailResult")
    if context is None:
        context = {}
    if not isinstance(context, dict):
        raise TypeError("apply_action context must be a dict or None")

    action = fail_result.action
    if not is_known_action(action):
        _raise_as_exception(
            fail_result,
            "unknown on-fail action %r for code %s; failing closed"
            % (action, fail_result.code))

    if action == OnFailAction.EXCEPTION:
        _raise_as_exception(
            fail_result,
            "%s: %s" % (fail_result.code, fail_result.detail))

    if action == OnFailAction.NOOP:
        recorded = _record(context, fail_result, "continued")
        return _outcome(fail_result, "continued",
                        {"recorded": recorded})

    if action == OnFailAction.REFRAIN:
        _record(context, fail_result, "refrained")
        return _outcome(fail_result, "refrained", {})

    if action in _AGENTIC_ACTIONS:
        request = action_request(
            fail_result, constraints=context.get("constraints"))
        _record(context, fail_result, "requested")
        return _outcome(fail_result, "requested", request)

    if action == OnFailAction.FILTER:
        return _apply_filter(fail_result, context)

    # OnFailAction.CUSTOM: the only remaining vocabulary member.
    handler = context.get("handler")
    if not callable(handler):
        _raise_as_exception(
            fail_result,
            "custom action needs context['handler'] (callable); "
            "failing closed")
    try:
        result = handler(fail_result, context)
    except Exception as exc:
        _raise_as_exception(
            fail_result,
            "custom handler raised %s; failing closed"
            % (type(exc).__name__,))
    _record(context, fail_result, "custom")
    return _outcome(fail_result, "custom", result)
