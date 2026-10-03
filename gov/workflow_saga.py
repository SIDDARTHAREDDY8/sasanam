"""Saga orchestration: forward steps with declared compensations, reverse-order rollback, transactional outbox.

Wave-301 lane 4. Stdlib only. Additive: this module changes no existing
API and does not depend on lane 3's ``gov/workflow.py``.

A SAGA is an ordered sequence of local steps; each step declares its
action AND its compensation up front (the SagaDefinition DSL). The
``SagaManager`` persists every saga instance (saga_id, step states,
append-only history) and executes forward; on a step failure it runs the
compensations of the completed steps in exact reverse order.

Design rule (wave-300 prospecting): "A workflow outlives its runner --
every step is checkpointed, and every resume re-proves its authority."

Key properties:

* Compensation is DECLARED, never invented at failure time: ``define()``
  refuses a step without a ``compensation_op``
  (``workflow-saga-definition-invalid``).
* Reverse order: compensations run for completed steps in exact reverse
  completion order; every attempt is recorded in the append-only
  history. Timelines are reconstructed, never edited.
* Failing compensation: retried up to ``max_compensation_attempts``,
  then the saga ESCALATES loudly
  (``workflow-saga-compensation-failed``) -- never silently skipped. An
  escalated saga refuses further ``run``/``resume`` until an operator
  intervenes (loud refusal carrying the escalation code).
* Authority re-verification: each step may carry an ``authority_ref``;
  the manager holds verifier callables keyed by ref (deployment
  provided). Every compensation re-verifies before executing; a revoked
  or unknown authority refuses loudly
  (``workflow-saga-compensation-unauthorized``) and escalates -- the
  step stays recorded as uncompensated, never silently skipped. Forward
  actions are authority-checked the same way.
* Transactional outbox: an action returns ``(result, outbox_payloads)``;
  the step commit atomically records the success AND the outbox intents.
  Intents dispatch only via ``drain_outbox``, exactly once per intent
  record (deduplicated by ``intent_id``). A crash between commit and
  drain loses nothing: ``resume`` re-presents committed, undispatched
  intents. Dispatchers must be idempotent -- the relay never invents or
  duplicates an intent record and never drops a committed one
  (at-least-once delivery, exactly-once records).
* Crash model: an action raising ``BaseException`` (but not
  ``Exception``) -- e.g. ``KeyboardInterrupt`` or a simulated crash --
  propagates UNCAUGHT, leaving the step in ``running``. ``resume()``
  marks such steps ``failed('interrupted')`` and compensates. Regular
  ``Exception`` marks the step failed and triggers compensation
  immediately.

New decision codes (3): ``workflow-saga-definition-invalid``,
``workflow-saga-compensation-failed``,
``workflow-saga-compensation-unauthorized`` (all high).

Threat model / honest residuals:

* Op implementations are deployment code: a lying op can falsify its
  result. The saga guarantees ordering, recording, and compensation
  discipline -- not op honesty.
* Compensations SHOULD be idempotent: the manager retries a failing
  compensation, so a non-idempotent compensation can double-apply
  across retries. Attempts are recorded; idempotency is a deployment
  contract.
* Authority verifiers are deployment-provided; a verifier that always
  returns True is a deployment misconfiguration, not a module bypass.
  A verifier that raises is treated as refusing (fail closed).
* ``time.time_ns()`` stamps history order; clocks are deployment-owned.
* The op registry is process-local: a resumed manager in a new process
  must re-register the same op names, and must be given the same
  authority verifier refs, or steps fail loudly at their own checks.
"""

import hashlib
import json
import time
import uuid

STEP_STATES = ("pending", "running", "succeeded", "failed",
               "compensating", "compensated", "compensation_failed")
INSTANCE_STATUSES = ("running", "compensating", "compensated",
                     "succeeded", "escalated")

# Codes minted by this module (see gov/decision_codes.py).
CODE_DEFINITION_INVALID = "workflow-saga-definition-invalid"
CODE_COMPENSATION_FAILED = "workflow-saga-compensation-failed"
CODE_COMPENSATION_UNAUTHORIZED = "workflow-saga-compensation-unauthorized"


class SagaError(Exception):
    """Code-first exception for saga orchestration failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise SagaError(detail, code=code)


# ---------------------------------------------------------------------------
# Op registry: steps name their action/compensation by string so saga
# instances stay JSON-serializable across a crash (dump/load).
# ---------------------------------------------------------------------------

_OPS = {}


def register_op(name, fn):
    """Register a named op. Action ops take ``params: dict`` and return
    ``(result, outbox_payloads: list[dict])``; compensation ops take
    ``params: dict`` and return anything."""
    if not isinstance(name, str) or not name:
        raise ValueError("op name must be a non-empty string")
    if not callable(fn):
        raise ValueError("op %r is not callable" % (name,))
    _OPS[name] = fn


def get_op(name):
    return _OPS.get(name)


def registered_ops():
    return dict(_OPS)


def clear_ops():
    _OPS.clear()


def _canonical_digest(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Definition DSL
# ---------------------------------------------------------------------------

class SagaStepDef:
    """One saga step: action + compensation, both declared up front."""

    def __init__(self, step_id, action_op, action_params=None,
                 compensation_op=None, compensation_params=None,
                 authority_ref=None):
        self.step_id = step_id
        self.action_op = action_op
        self.action_params = dict(action_params or {})
        self.compensation_op = compensation_op
        self.compensation_params = dict(compensation_params or {})
        self.authority_ref = authority_ref

    def to_dict(self):
        return {
            "step_id": self.step_id,
            "action_op": self.action_op,
            "action_params": self.action_params,
            "compensation_op": self.compensation_op,
            "compensation_params": self.compensation_params,
            "authority_ref": self.authority_ref,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            step_id=d["step_id"],
            action_op=d["action_op"],
            action_params=d.get("action_params") or {},
            compensation_op=d.get("compensation_op"),
            compensation_params=d.get("compensation_params") or {},
            authority_ref=d.get("authority_ref"),
        )


class SagaDefinition:
    """Validated, ordered, digest-bound saga definition."""

    def __init__(self, steps):
        steps = [s if isinstance(s, SagaStepDef) else SagaStepDef(**dict(s))
                 for s in steps]
        self._validate(steps)
        self.steps = tuple(steps)
        self.digest = _canonical_digest([s.to_dict() for s in steps])

    @staticmethod
    def _validate(steps):
        if not steps:
            _fail(CODE_DEFINITION_INVALID,
                  "saga definition must declare at least one step")
        seen = set()
        for s in steps:
            if not isinstance(s.step_id, str) or not s.step_id:
                _fail(CODE_DEFINITION_INVALID,
                      "step_id must be a non-empty string")
            if s.step_id in seen:
                _fail(CODE_DEFINITION_INVALID,
                      "duplicate step_id %r: step ids must be unique"
                      % (s.step_id,))
            seen.add(s.step_id)
            if not isinstance(s.action_op, str) or not s.action_op:
                _fail(CODE_DEFINITION_INVALID,
                      "step %r: action_op must be a non-empty string"
                      % (s.step_id,))
            # Compensation is declared up front, never invented at
            # failure time: a step without one is refused at define().
            if not isinstance(s.compensation_op, str) or not s.compensation_op:
                _fail(CODE_DEFINITION_INVALID,
                      "step %r: compensation_op is required -- compensation "
                      "is declared up front, never invented at failure time"
                      % (s.step_id,))
            for label, params in (("action_params", s.action_params),
                                  ("compensation_params",
                                   s.compensation_params)):
                if not isinstance(params, dict):
                    _fail(CODE_DEFINITION_INVALID,
                          "step %r: %s must be a dict" % (s.step_id, label))
                try:
                    json.dumps(params)
                except (TypeError, ValueError):
                    _fail(CODE_DEFINITION_INVALID,
                          "step %r: %s must be JSON-serializable "
                          "(saga instances persist across crashes)"
                          % (s.step_id, label))
            if (s.authority_ref is not None
                    and (not isinstance(s.authority_ref, str)
                         or not s.authority_ref)):
                _fail(CODE_DEFINITION_INVALID,
                      "step %r: authority_ref must be a non-empty string "
                      "or None" % (s.step_id,))


# ---------------------------------------------------------------------------
# Instance (persisted state)
# ---------------------------------------------------------------------------

class SagaInstance:
    """Persisted saga instance: step states + append-only history + outbox."""

    def __init__(self, saga_id, definition):
        self.saga_id = saga_id
        self.definition_digest = definition.digest
        self.step_defs = [s.to_dict() for s in definition.steps]
        self.steps = [
            {"step_id": s.step_id, "state": "pending", "attempts": 0,
             "comp_attempts": 0, "result": None, "error": None}
            for s in definition.steps
        ]
        self.status = "running"
        self.escalation_code = None
        self.history = []
        self.outbox = []
        self._seq = 0
        self._event("saga_started", None,
                    "definition %s with %d step(s)"
                    % (definition.digest[:12], len(definition.steps)))

    def _event(self, etype, step_id, detail):
        self._seq += 1
        self.history.append({
            "seq": self._seq,
            "type": etype,
            "step_id": step_id,
            "detail": detail,
            "at_ns": time.time_ns(),
        })

    def step_def(self, step_id):
        for d in self.step_defs:
            if d["step_id"] == step_id:
                return d
        raise KeyError(step_id)

    def to_dict(self):
        return {
            "saga_id": self.saga_id,
            "definition_digest": self.definition_digest,
            "step_defs": self.step_defs,
            "steps": self.steps,
            "status": self.status,
            "escalation_code": self.escalation_code,
            "history": self.history,
            "outbox": self.outbox,
            "seq": self._seq,
        }

    @classmethod
    def from_dict(cls, d):
        try:
            required = ("saga_id", "definition_digest", "step_defs", "steps",
                        "status", "history", "outbox", "seq")
            for k in required:
                if k not in d:
                    raise ValueError("missing key %r" % (k,))
            if d["status"] not in INSTANCE_STATUSES:
                raise ValueError("bad status %r" % (d["status"],))
            for s in d["steps"]:
                if s["state"] not in STEP_STATES:
                    raise ValueError("bad step state %r" % (s["state"],))
            inst = cls.__new__(cls)
            inst.saga_id = d["saga_id"]
            inst.definition_digest = d["definition_digest"]
            inst.step_defs = d["step_defs"]
            inst.steps = d["steps"]
            inst.status = d["status"]
            inst.escalation_code = d.get("escalation_code")
            inst.history = d["history"]
            inst.outbox = d["outbox"]
            inst._seq = d["seq"]
            return inst
        except (KeyError, TypeError, AttributeError) as e:
            raise ValueError("malformed saga dump: %s" % (e,))


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class SagaManager:
    """Executes saga definitions with reverse-order compensation."""

    def __init__(self, authority_verifiers=None, max_compensation_attempts=3):
        if max_compensation_attempts < 1:
            raise ValueError("max_compensation_attempts must be >= 1")
        self._verifiers = dict(authority_verifiers or {})
        self._max_comp = max_compensation_attempts

    # -- lifecycle ----------------------------------------------------
    def define(self, steps):
        return SagaDefinition(steps)

    def start(self, definition, saga_id=None):
        return SagaInstance(saga_id or uuid.uuid4().hex, definition)

    def dump(self, instance):
        return instance.to_dict()

    def load(self, data):
        if not isinstance(data, dict):
            raise ValueError("malformed saga dump: not a dict")
        return SagaInstance.from_dict(data)

    # -- authority ----------------------------------------------------
    def _check_authority(self, step_def):
        """Re-prove the step's authority. Missing/unknown/failing
        verifiers fail closed."""
        ref = step_def.get("authority_ref")
        if not ref:
            return True
        verifier = self._verifiers.get(ref)
        if verifier is None or not callable(verifier):
            return False
        try:
            return bool(verifier())
        except Exception:
            return False

    # -- outbox -------------------------------------------------------
    def _record_intent(self, instance, intent_id, step_id, payload):
        # Dedupe by intent_id: the relay never invents a duplicate record.
        for existing in instance.outbox:
            if existing["intent_id"] == intent_id:
                return False
        try:
            json.dumps(payload)
        except (TypeError, ValueError):
            _fail(CODE_DEFINITION_INVALID,
                  "outbox payload for step %r is not JSON-serializable"
                  % (step_id,))
        instance.outbox.append({
            "intent_id": intent_id,
            "step_id": step_id,
            "payload": payload,
            "dispatched": False,
        })
        return True

    def drain_outbox(self, instance, dispatcher):
        """Dispatch committed, undispatched intents exactly once per
        intent record. Returns the number dispatched. Dispatcher
        exceptions are recorded and re-raised; the intent stays
        undispatched for the next drain (at-least-once delivery --
        dispatchers must be idempotent)."""
        if not callable(dispatcher):
            raise ValueError("dispatcher must be callable")
        n = 0
        for intent in instance.outbox:
            if intent["dispatched"]:
                continue
            try:
                dispatcher(dict(intent))
            except Exception as e:
                instance._event(
                    "outbox_dispatch_failed", intent["step_id"],
                    "intent %s: %s: %s (left undispatched for redrain)"
                    % (intent["intent_id"], type(e).__name__, e))
                raise
            intent["dispatched"] = True
            n += 1
            instance._event("outbox_dispatched", intent["step_id"],
                            "intent %s" % (intent["intent_id"],))
        return n

    # -- forward ------------------------------------------------------
    def run(self, instance):
        """Execute pending steps forward; on failure, compensate."""
        if instance.status == "escalated":
            _fail(instance.escalation_code or CODE_COMPENSATION_FAILED,
                  "saga %s is escalated: operator intervention required; "
                  "run refused" % (instance.saga_id,))
        if instance.status in ("succeeded", "compensated"):
            return instance
        if instance.status == "compensating":
            self._compensate(instance)
            return instance
        for st in instance.steps:
            if instance.status != "running":
                break
            if st["state"] != "pending":
                continue
            self._execute_step(instance, st)
            if st["state"] == "failed":
                self._compensate(instance)
                break
        if (instance.status == "running"
                and all(s["state"] == "succeeded"
                        for s in instance.steps)):
            instance.status = "succeeded"
            instance._event("saga_succeeded", None,
                            "all %d step(s) succeeded"
                            % (len(instance.steps),))
        return instance

    def _execute_step(self, instance, st):
        step_def = instance.step_def(st["step_id"])
        if not self._check_authority(step_def):
            st["state"] = "failed"
            st["error"] = "authority-revoked-forward"
            instance._event(
                "step_failed", st["step_id"],
                "forward authority check refused (ref %r); compensating"
                % (step_def.get("authority_ref"),))
            return
        op = get_op(step_def["action_op"])
        if op is None:
            st["state"] = "failed"
            st["error"] = "unknown-op:%s" % (step_def["action_op"],)
            instance._event("step_failed", st["step_id"], st["error"])
            return
        st["attempts"] += 1
        st["state"] = "running"
        instance._event("step_started", st["step_id"],
                        "action %s" % (step_def["action_op"],))
        try:
            outcome = op(dict(step_def.get("action_params") or {}))
        except Exception as e:
            st["state"] = "failed"
            st["error"] = "%s: %s" % (type(e).__name__, e)
            instance._event("step_failed", st["step_id"], st["error"])
            return
        # NOTE: BaseException (crash, KeyboardInterrupt) is deliberately
        # NOT caught: the step stays 'running' so resume() can detect the
        # interruption instead of misclassifying it as a clean failure.
        try:
            result, payloads = outcome
        except (TypeError, ValueError):
            st["state"] = "failed"
            st["error"] = "bad-op-result: action must return (result, [payloads])"
            instance._event("step_failed", st["step_id"], st["error"])
            return
        if not isinstance(payloads, list) or any(
                not isinstance(p, dict) for p in payloads):
            st["state"] = "failed"
            st["error"] = "bad-op-result: payloads must be a list of dicts"
            instance._event("step_failed", st["step_id"], st["error"])
            return
        try:
            json.dumps(result)
        except (TypeError, ValueError):
            st["state"] = "failed"
            st["error"] = "bad-op-result: result not JSON-serializable"
            instance._event("step_failed", st["step_id"], st["error"])
            return
        # Commit: step success and outbox intents are recorded atomically
        # (in-memory). Intents dispatch only via drain_outbox.
        st["state"] = "succeeded"
        st["result"] = result
        for i, payload in enumerate(payloads):
            intent_id = payload.get("intent_id") or "%s:%s:%d" % (
                instance.saga_id, st["step_id"], i)
            self._record_intent(instance, intent_id, st["step_id"], payload)
        instance._event(
            "step_succeeded", st["step_id"],
            "action committed with %d outbox intent(s)" % (len(payloads),))

    # -- compensation -------------------------------------------------
    def _compensate(self, instance):
        failed = [s["step_id"] for s in instance.steps
                  if s["state"] == "failed"]
        instance.status = "compensating"
        instance._event(
            "compensation_started", None,
            "after failure of %s; compensating completed steps in "
            "reverse order" % (failed,))
        for st in reversed(instance.steps):
            if st["state"] not in ("succeeded", "compensating"):
                continue
            # May raise SagaError (escalation): never silently skipped.
            self._compensate_step(instance, st)
        instance.status = "compensated"
        instance._event("saga_compensated", None,
                        "all completed steps compensated in reverse order")

    def _compensate_step(self, instance, st):
        step_def = instance.step_def(st["step_id"])
        # Every resume re-proves its authority: the compensation runs
        # under the ORIGINAL step's authority, re-verified NOW.
        if not self._check_authority(step_def):
            instance.status = "escalated"
            instance.escalation_code = CODE_COMPENSATION_UNAUTHORIZED
            instance._event(
                "compensation_refused", st["step_id"],
                "authority ref %r revoked or unknown at compensation "
                "time; step left recorded as uncompensated (not skipped)"
                % (step_def.get("authority_ref"),))
            _fail(CODE_COMPENSATION_UNAUTHORIZED,
                  "saga %s: compensation of step %r refused: authority "
                  "%r revoked or unknown at compensation time"
                  % (instance.saga_id, st["step_id"],
                     step_def.get("authority_ref")))
        comp = get_op(step_def["compensation_op"])
        if comp is None:
            # Declared but unresolvable in this process: retrying cannot
            # help, so escalate immediately under the compensation-failed
            # code (the specific cause stays in the history event).
            st["state"] = "compensation_failed"
            instance.status = "escalated"
            instance.escalation_code = CODE_COMPENSATION_FAILED
            instance._event(
                "compensation_failed", st["step_id"],
                "compensation op %r not registered in this process; "
                "saga escalated -- operator intervention required"
                % (step_def["compensation_op"],))
            _fail(CODE_COMPENSATION_FAILED,
                  "saga %s: compensation op %r of step %r is not "
                  "registered; saga escalated"
                  % (instance.saga_id, step_def["compensation_op"],
                     st["step_id"]))
        st["state"] = "compensating"
        while True:
            instance._event(
                "compensation_started", st["step_id"],
                "compensation %s (attempt %d of %d)"
                % (step_def["compensation_op"], st["comp_attempts"] + 1,
                   self._max_comp))
            try:
                comp(dict(step_def.get("compensation_params") or {}))
            except Exception as e:
                # NOTE: BaseException (crash) propagates: the step stays
                # 'compensating' so a later resume() retries it.
                st["comp_attempts"] += 1
                instance._event(
                    "compensation_attempt_failed", st["step_id"],
                    "attempt %d: %s: %s"
                    % (st["comp_attempts"], type(e).__name__, e))
                if st["comp_attempts"] >= self._max_comp:
                    st["state"] = "compensation_failed"
                    instance.status = "escalated"
                    instance.escalation_code = CODE_COMPENSATION_FAILED
                    instance._event(
                        "compensation_failed", st["step_id"],
                        "exhausted %d attempt(s); saga escalated -- "
                        "operator intervention required"
                        % (self._max_comp,))
                    _fail(CODE_COMPENSATION_FAILED,
                          "saga %s: compensation of step %r failed after "
                          "%d attempt(s); saga escalated"
                          % (instance.saga_id, st["step_id"],
                             self._max_comp))
                continue
            break
        st["state"] = "compensated"
        instance._event(
            "compensation_succeeded", st["step_id"],
            "compensated after %d attempt(s)" % (st["comp_attempts"] + 1,))

    # -- crash recovery -----------------------------------------------
    def resume(self, instance):
        """Recover a crashed saga. Steps left 'running' were interrupted
        mid-action: they are marked failed('interrupted') and the saga
        compensates. Completed steps are never re-executed."""
        if instance.status == "escalated":
            _fail(instance.escalation_code or CODE_COMPENSATION_FAILED,
                  "saga %s is escalated: operator intervention required; "
                  "resume refused" % (instance.saga_id,))
        if instance.status in ("succeeded", "compensated"):
            return instance
        for st in instance.steps:
            if st["state"] == "running":
                st["state"] = "failed"
                st["error"] = "interrupted"
                instance._event(
                    "step_interrupted", st["step_id"],
                    "found 'running' at resume: marked failed(interrupted); "
                    "its outbox intents were never committed, so nothing "
                    "dispatches for it")
        if instance.status == "compensating":
            # Continue the interrupted compensation; already-compensated
            # steps are skipped by _compensate.
            self._compensate(instance)
            return instance
        if any(s["state"] == "failed" for s in instance.steps):
            self._compensate(instance)
            return instance
        return self.run(instance)
