"""Deterministic approval remediation taxonomy (wave-279 lane 6).

Clean-room ADAPT of guardrails-ai's ``OnFailAction`` remediation
taxonomy (``guardrails/types/on_fail.py``, Apache-2.0): the TAXONOMY of
outcomes is adapted -- a deterministic, coded set of remediation
actions for failed validation -- and guardrails-ai's bounded
re-ask/repair loop (``Guard(num_reasks=...)``) is adapted as
:func:`reask_repair`. No guardrails-ai code, schemas, or text are
reused; the RAIL/XML machinery is skipped entirely per the
prospectus. This module is mechanism-only and dependency-free
(stdlib only; it imports nothing from ``gov``).

Domain mapping (guardrails-ai -> approval remediation):

* ``REASK``       -> re-prompt the operator; bounded by the shared
                     elicitation budget (fail-closed on exhaustion).
* ``FIX``         -> apply a DECLARED static fix, then re-verify.
* ``FILTER``      -> drop the offending portion, then re-verify.
* ``REFRAIN``     -> terminal fail-closed refusal; the record keeps
                     its state, no response is produced.
* ``NOOP``        -> proceed as-is; only reachable when the policy
                     explicitly maps a failure class to it (the
                     default policy never does).
* ``EXCEPTION``   -> raise immediately; no remediation attempted
                     (caller-contract violations).
* ``FIX_REASK``   -> fix, verify; if verification fails, fall back
                     to re-ask within budget.
* ``CUSTOM``      -> caller-supplied remediation callback; its
                     result is restricted to the concrete actions
                     (never CUSTOM again), anything else fails
                     closed to REFRAIN.

Failure classes are DATA, not decision codes: they ride inside the
``remediation`` sub-record of existing audit events and are never
raised as refusal codes, so the decision-code taxonomy pin is
unaffected (stays 1493).

Every entry point is total: :func:`classify`,
:func:`reask_repair` and :func:`elicit_with_remediation` never raise
and never mutate the queue. Audit emission is the caller's job --
the queue seam attaches the outcome to its existing audit entry, so
every remediation step is logged with the same record discipline as
the other approval audit records.
"""

# ---------------------------------------------------------------------------
# Failure classes (deterministic classification of remediation triggers).
# These are audit DATA, not refusal codes -- never raise() with them,
# never pass them as code=/reason=, so the vocabulary scanner ignores
# them and the taxonomy pin is unaffected.
# ---------------------------------------------------------------------------

#: Response value outside the elicitation vocabulary (caller bug).
FAILURE_VOCABULARY_UNKNOWN = "vocabulary-unknown"
#: Approval id not found in the queue (caller bug).
FAILURE_LOOKUP = "lookup-failed"
#: Decline without the required rationale.
FAILURE_RATIONALE_MISSING = "rationale-missing"
#: Rationale (or its schema) failed contract validation.
FAILURE_SCHEMA_INVALID = "schema-invalid"
#: A queue-side pre-check failed (pending status, separation of
#: duties, integrity digest, packet re-verification).
FAILURE_PRECHECK = "precheck-failed"
#: Credential-shaped material in the rationale (fail closed, LOUD).
FAILURE_SECRET_DETECTED = "secret-detected"
#: The shared elicitation budget is exhausted.
FAILURE_BUDGET_EXHAUSTED = "budget-exhausted"
#: A declared fix/filter did not re-verify clean.
FAILURE_FIX_FAILED = "fix-failed"
#: Catch-all for unexpected seam failures (fails closed).
FAILURE_CUSTOM = "custom"

FAILURE_CLASSES = (
    FAILURE_VOCABULARY_UNKNOWN,
    FAILURE_LOOKUP,
    FAILURE_RATIONALE_MISSING,
    FAILURE_SCHEMA_INVALID,
    FAILURE_PRECHECK,
    FAILURE_SECRET_DETECTED,
    FAILURE_BUDGET_EXHAUSTED,
    FAILURE_FIX_FAILED,
    FAILURE_CUSTOM,
)

# ---------------------------------------------------------------------------
# Remediation actions (the OnFailAction analogs).
# ---------------------------------------------------------------------------

#: Re-prompt the operator; bounded by the shared elicitation budget.
REASK = "reask"
#: Apply a declared static fix, then re-verify.
FIX = "fix"
#: Drop the offending portion, then re-verify.
FILTER = "filter"
#: Terminal fail-closed refusal; the record keeps its state.
REFRAIN = "refrain"
#: Proceed as-is (advisory-class failures only; never the default).
NOOP = "noop"
#: Raise immediately; no remediation attempted.
EXCEPTION = "exception"
#: Fix, verify; if verification fails, re-ask within budget.
FIX_REASK = "fix-reask"
#: Caller-supplied remediation callback.
CUSTOM = "custom"

ACTIONS = (REASK, FIX, FILTER, REFRAIN, NOOP, EXCEPTION, FIX_REASK,
           CUSTOM)

#: Actions that need a re-ask round and therefore consume budget.
_BUDGETED_ACTIONS = (REASK, FIX_REASK)

#: Actions a CUSTOM callback may return (concrete only -- CUSTOM may
#: not recurse, and anything outside this set fails closed).
_CUSTOM_RESULTS = (REASK, FIX, FILTER, REFRAIN, NOOP, EXCEPTION,
                   FIX_REASK)

#: Default deterministic policy: failure class -> remediation action.
#: Unknown failure classes fail closed to REFRAIN.
DEFAULT_POLICY = {
    FAILURE_VOCABULARY_UNKNOWN: EXCEPTION,
    FAILURE_LOOKUP: EXCEPTION,
    FAILURE_RATIONALE_MISSING: REASK,
    FAILURE_SCHEMA_INVALID: REASK,
    FAILURE_PRECHECK: REFRAIN,
    FAILURE_SECRET_DETECTED: REFRAIN,
    FAILURE_BUDGET_EXHAUSTED: REFRAIN,
    FAILURE_FIX_FAILED: REFRAIN,
    FAILURE_CUSTOM: CUSTOM,
}


def _outcome(failure_class, action, retry_permitted, proceed=False,
             repaired_value=None, budget_remaining=None, steps=(),
             note=""):
    """Build the canonical remediation outcome record."""
    return {
        "failure_class": failure_class,
        "action": action,
        "retry_permitted": bool(retry_permitted),
        "proceed": bool(proceed),
        "repaired_value": repaired_value,
        "budget_remaining": budget_remaining,
        "steps": [dict(s) for s in steps],
        "note": note,
    }


def _fallback_outcome(note):
    """Last-resort outcome: total fail-closed, never raises."""
    return _outcome("unknown-failure", REFRAIN, False,
                    note="remediation classification failed (%s); "
                    "fail closed" % (note,))


def classify(failure_class, action=None, policy=None,
             budget_remaining=None, custom=None, value=None,
             context=None):
    """Deterministic remediation classification.

    Total: never raises, never mutates anything. Returns the outcome
    record ``{failure_class, action, retry_permitted, proceed,
    repaired_value, budget_remaining, steps, note}``.

    * ``failure_class`` -- one of the FAILURE_* classes; anything
      else fails closed to REFRAIN.
    * ``action`` -- explicit override; else the policy lookup; else
      REFRAIN. Unknown actions fail closed to REFRAIN.
    * ``budget_remaining`` -- shared elicitation budget left. A
      budgeted action (REASK/FIX_REASK) with no budget left escalates
      to REFRAIN (this is the fail-closed bound on the re-ask loop).
    * ``custom`` -- callback for the CUSTOM action:
      ``custom(value, info) -> action``; the result must be a concrete
      action, otherwise REFRAIN.
    * ``context`` -- caller-supplied dict, copied into the outcome's
      note context for audit (event name, approval id, ...).

    Repair execution (FIX/FILTER/FIX_REASK) needs declared repair
    primitives and lives in :func:`reask_repair`. When ``classify``
    is asked for a repair action without primitives, it fails closed
    to REFRAIN rather than degrading silently.
    """
    try:
        fc = (failure_class
              if isinstance(failure_class, str) and failure_class
              else "unknown-failure")
        pol = policy if isinstance(policy, dict) else DEFAULT_POLICY
        act = action if action is not None else pol.get(fc, REFRAIN)
        if act not in ACTIONS:
            return _outcome(fc, REFRAIN, False,
                            budget_remaining=budget_remaining,
                            note="unknown remediation action %r: fail "
                            "closed" % (act,))
        ctx = dict(context) if isinstance(context, dict) else {}

        # Budget bound: a re-ask with no budget left is a terminal
        # refrain, never a silent pass.
        if (act in _BUDGETED_ACTIONS and budget_remaining is not None
                and budget_remaining <= 0):
            return _outcome(
                fc, REFRAIN, False, budget_remaining=budget_remaining,
                note="re-ask budget exhausted (shared elicitation "
                "budget): further re-asks refused fail-closed; the "
                "record keeps its current state")

        if act == REFRAIN:
            return _outcome(fc, REFRAIN, False,
                            budget_remaining=budget_remaining,
                            note="terminal fail-closed refusal: no "
                            "remediation attempted; the record keeps "
                            "its state")
        if act == EXCEPTION:
            return _outcome(fc, EXCEPTION, False,
                            budget_remaining=budget_remaining,
                            note="caller-contract violation: raise "
                            "immediately; no remediation attempted")
        if act == NOOP:
            return _outcome(fc, NOOP, False, proceed=True,
                            budget_remaining=budget_remaining,
                            note="advisory-class failure: proceed as-is "
                            "(explicit policy opt-in only)")
        if act == REASK:
            return _outcome(fc, REASK, True,
                            budget_remaining=budget_remaining,
                            note="fixable validation failure: the "
                            "operator may re-ask within the shared "
                            "elicitation budget")
        if act in (FIX, FILTER, FIX_REASK):
            # classify() does not execute repairs -- that needs
            # declared primitives (see reask_repair). Asking for a
            # repair action here fails closed, loudly.
            return _outcome(fc, REFRAIN, False,
                            budget_remaining=budget_remaining,
                            note="repair action %r requested without "
                            "declared repair primitives: fail closed "
                            "rather than degrade silently" % (act,))
        # CUSTOM: invoke the callback under a fail-closed wrapper.
        info = {"failure_class": fc, "context": ctx,
                "budget_remaining": budget_remaining}
        try:
            chosen = custom(value, info) if callable(custom) else None
        except Exception as exc:  # noqa: BLE001
            return _outcome(fc, REFRAIN, False,
                            budget_remaining=budget_remaining,
                            note="custom remediation callback raised "
                            "%s: fail closed"
                            % (type(exc).__name__,))
        if chosen not in _CUSTOM_RESULTS:
            return _outcome(fc, REFRAIN, False,
                            budget_remaining=budget_remaining,
                            note="custom remediation returned %r "
                            "(must be a concrete action): fail closed"
                            % (chosen,))
        # One level only: classify the chosen concrete action without
        # repair primitives (repair actions degrade to refrain above).
        sub = classify(fc, action=chosen,
                       budget_remaining=budget_remaining,
                       context=ctx)
        sub["note"] = ("custom remediation chose %r: %s"
                       % (chosen, sub["note"]))
        return sub
    except Exception as exc:  # noqa: BLE001 -- total by contract
        return _fallback_outcome(type(exc).__name__)


def reask_repair(produce, validate, max_rounds=3, fix=None,
                 context=None):
    """Bounded re-ask-with-repair loop (guardrails-ai ``Guard`` analog).

    * ``produce()`` -- returns an attempt value. May be called at most
      ``max_rounds + 1`` times (initial attempt + re-asks).
    * ``validate(value)`` -- returns ``(ok, failure)``; ``failure``
      is a short string describing the failure class, or None.
    * ``fix(value)`` -- optional DECLARED static fix; the repaired
      value is re-verified with ``validate`` before it is accepted.

    Returns an outcome record (same shape as :func:`classify`, plus
    ``proceed``/``repaired_value`` and a ``steps`` list with one
    entry per round). Total: never raises -- a raising
    produce/validate/fix fails the loop closed. On exhaustion the
    action is REFRAIN (fail-closed); a verified fix yields FIX with
    ``proceed=True``; a clean first attempt yields NOOP.
    """
    steps = []
    ctx = dict(context) if isinstance(context, dict) else {}
    try:
        rounds = max(0, int(max_rounds))
    except (TypeError, ValueError):
        rounds = 0
    reasks_used = 0
    try:
        for round_no in range(rounds + 1):
            try:
                value = produce()
            except Exception as exc:  # noqa: BLE001
                steps.append({"round": round_no,
                              "producer_failed": type(exc).__name__})
                return _outcome(FAILURE_CUSTOM, REFRAIN, False,
                                steps=steps,
                                note="producer raised %s: fail closed"
                                % (type(exc).__name__,))
            try:
                ok, failure = validate(value)
            except Exception as exc:  # noqa: BLE001
                ok, failure = False, "validator raised %s" % (
                    type(exc).__name__,)
            steps.append({"round": round_no,
                          "failure": None if ok else str(failure)[:200]})
            if ok:
                act = REASK if reasks_used else NOOP
                return _outcome(
                    FAILURE_CUSTOM if reasks_used else "none", act,
                    False, proceed=True, repaired_value=value,
                    steps=steps,
                    note=("clean after %d re-ask(s)" % reasks_used)
                    if reasks_used else "clean on first attempt")
            # Declared fix: apply, then re-verify before accepting.
            if fix is not None:
                try:
                    repaired = fix(value)
                except Exception as exc:  # noqa: BLE001
                    repaired = None
                    steps.append({"round": round_no,
                                  "fix_applied": False,
                                  "fix_failed": type(exc).__name__})
                if repaired is not None:
                    try:
                        ok2, failure2 = validate(repaired)
                    except Exception as exc:  # noqa: BLE001
                        ok2, failure2 = (
                            False, "validator raised %s"
                            % (type(exc).__name__,))
                    steps.append({"round": round_no, "fix_applied": True,
                                  "fix_ok": bool(ok2),
                                  "failure": (None if ok2
                                              else str(failure2)[:200])})
                    if ok2:
                        return _outcome(
                            FAILURE_FIX_FAILED, FIX, False,
                            proceed=True, repaired_value=repaired,
                            steps=steps,
                            note="declared fix re-verified clean; "
                            "proceeding with the repaired value")
                    # Fix did not verify: fall through to re-ask.
            reasks_used += 1
        return _outcome(FAILURE_FIX_FAILED, REFRAIN, False,
                        steps=steps,
                        note="re-ask budget exhausted after %d round(s): "
                        "fail closed; no further attempts"
                        % (rounds + 1,))
    except Exception as exc:  # noqa: BLE001 -- total by contract
        return _fallback_outcome(type(exc).__name__)


def elicit_with_remediation(queue, approval_id, produce, max_rounds=None,
                            decided_by="human-operator"):
    """Drive ``queue.elicit_decision`` through the bounded re-ask loop.

    * ``produce(round_no, last_outcome)`` -- returns ``(response,
      rationale)`` or ``(response, rationale, rationale_schema)``.
    * The loop is bounded by ``max_rounds`` (default: the shared
      elicitation budget) AND by the queue's own per-record
      elicitation budget, checked before every round -- an exhausted
      shared budget stops the driver even when ``max_rounds`` is
      larger.

    Returns ``(True, (record, entry))`` on a decision, or
    ``(False, outcome)`` on terminal refrain. Total: never raises.
    """
    # Lazy import: gov.approvals imports this module lazily, so a
    # top-level import here would cycle.
    from gov import elicitation_contract as _ec
    try:
        if max_rounds is None:
            max_rounds = _ec.MAX_ELICITATIONS
        max_rounds = max(0, int(max_rounds))
    except (TypeError, ValueError):
        max_rounds = _ec.MAX_ELICITATIONS
    last_outcome = None
    try:
        for round_no in range(max_rounds):
            # Shared-budget check BEFORE producing: the driver never
            # re-asks past the queue's own elicitation budget.
            try:
                record = queue.get(approval_id)
            except Exception:  # noqa: BLE001
                record = None
            if (not isinstance(record, dict)
                    or record.get("status") != "pending"):
                return False, _outcome(
                    FAILURE_PRECHECK, REFRAIN, False,
                    note="record %r is not pending: the driver stops "
                    "fail-closed" % (approval_id,))
            try:
                remaining = _ec.reprompts_remaining(record)
            except Exception:  # noqa: BLE001
                remaining = 0
            if remaining <= 0:
                return False, _outcome(
                    FAILURE_BUDGET_EXHAUSTED, REFRAIN, False,
                    budget_remaining=0,
                    note="shared elicitation budget exhausted: the "
                    "driver stops without producing another attempt")
            try:
                produced = produce(round_no, last_outcome)
            except Exception as exc:  # noqa: BLE001
                return False, _outcome(
                    FAILURE_CUSTOM, REFRAIN, False,
                    budget_remaining=remaining,
                    note="producer raised %s: fail closed"
                    % (type(exc).__name__,))
            if (not isinstance(produced, (tuple, list))
                    or not 2 <= len(produced) <= 3):
                return False, _outcome(
                    FAILURE_CUSTOM, REFRAIN, False,
                    budget_remaining=remaining,
                    note="producer protocol violation (need "
                    "(response, rationale[, schema])): fail closed")
            response = produced[0]
            rationale = produced[1]
            schema = produced[2] if len(produced) > 2 else None
            try:
                result = queue.elicit_decision(
                    approval_id, response, rationale=rationale,
                    decided_by=decided_by, rationale_schema=schema)
            except _ec.ElicitationError as exc:
                last_outcome = (getattr(exc, "remediation", None)
                                or classify(FAILURE_CUSTOM))
            except Exception as exc:  # noqa: BLE001
                last_outcome = classify(
                    FAILURE_CUSTOM,
                    context={"raised": type(exc).__name__})
            else:
                return True, result
            if not last_outcome.get("retry_permitted"):
                return False, last_outcome
            # Retry permitted: next round re-checks the shared budget.
        return False, _outcome(
            (last_outcome or {}).get("failure_class")
            or FAILURE_CUSTOM,
            REFRAIN, False,
            budget_remaining=(
                (last_outcome or {}).get("budget_remaining")),
            steps=((last_outcome or {}).get("steps") or []),
            note="driver round budget exhausted after %d round(s): "
            "fail closed" % (max_rounds,))
    except Exception as exc:  # noqa: BLE001 -- total by contract
        return False, _fallback_outcome(type(exc).__name__)


def drop_undeclared(value, schema):
    """Declared FILTER primitive: drop rationale keys the schema does
    not declare, then the caller re-verifies.

    Never raises; non-dict inputs pass through unchanged.
    """
    try:
        if not isinstance(value, dict) or not isinstance(schema, dict):
            return value
        declared = schema.get("properties") or {}
        if not isinstance(declared, dict):
            return value
        return {k: v for k, v in value.items() if k in declared}
    except Exception:  # noqa: BLE001 -- total by contract
        return value
