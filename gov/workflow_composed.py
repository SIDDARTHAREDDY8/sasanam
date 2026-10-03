"""Composed workflow path: durable steps + saga compensation + routing slips + idempotency keys.

Wave-302 lane 2. Stdlib only. This module ADAPTS the four wave-301
workflow modules (``gov/workflow.py``, ``gov/workflow_saga.py``,
``gov/workflow_routing.py``, ``gov/workflow_idempotency.py``) into one
coherent execution path. No submodule's semantics are changed --
adapters only, following the wave-300 lane-3 ``gov/memory_composed.py``
pattern (read it first).

Standing design rule: "A workflow outlives its runner -- every step is
checkpointed, and every resume re-proves its authority."

DECISIONS (each resolves a documented seam hazard):

1. CANONICAL EXECUTION UNIT (seams 1+2: saga step vs workflow step;
   slip leg vs saga step vs workflow step -- three "step" notions).
   The WORKFLOW STEP is the canonical execution unit. Every saga
   action, every routing-slip leg, and every plain fn executes inside
   a workflow step slot (``run_step``), allocated in plan order. The
   composer assigns seq numbers across the whole plan execution: plain
   fns take one slot each, saga actions take one slot each (in
   definition order), slip legs take one slot each (in leg order),
   and compensations take additional slots as they occur (in the
   order they run -- reverse completion order). Rejected alternative:
   three parallel notions of "step" with three audit trails -- the
   design rule demands one checkpointed unit.

2. IDEMPOTENCY LAYERS (seam 3: idempotency keys vs workflow step-level
   keys -- two key namespaces). BOTH apply, in a defined order: the
   idempotency store is the OUTER contract, the workflow store is the
   INNER checkpoint.
   - Outer: every composed unit executes under
     ``op_class="composed-unit"`` (saga actions:
     ``"composed-saga-action"``; compensations:
     ``"composed-saga-comp"``; slip legs: ``"composed-slip-leg"``;
     outbox dispatches: ``"composed-outbox"``), keyed by the unit's
     idempotency key. The op_digest binds
     ``(plan_digest, op_class, key, unit inputs digest)`` -- the same
     key under a different plan (definition drift) refuses
     ``permit-idempotency-conflict``; a retry can never masquerade as
     a redefinition.
   - Inner: the workflow step slot replays from its checkpoint when
     the same (run_id, seq, name, inputs) recurs.
   - Interaction: an outer REPLAY short-circuits the inner layer
     entirely (the recorded result is resolved through the result_ref
     back to the workflow checkpoint -- see Decision 5); an outer
     RETRY re-enters the workflow store, which may itself replay from
     its checkpoint (crash between effect and checkpoint mark).
   - Divergence: if the outer store says REPLAY but the referenced
     workflow step is absent or its digest disagrees, the layers have
     forked -- refuse ``workflow-composed-divergent`` (fail closed,
     never silently re-execute and never silently trust).
   - Foreign pairs (F388): the composer only ever completes refs of
     the form ``wfstep:<current run>:<seq>`` under its plan actor
     (Decision 3). A replay whose ref names a different run, or whose
     record was begun by a different actor, is not a fork the
     composer can heal -- it is a foreign (poisoned) pair and refuses
     ``workflow-composed-replay-foreign``. Resolution attempted with
     no composed execution in progress refuses the same code.

3. AUTHORITY (seam 4: compensation authority vs resume authority --
   two re-verification paths). UNIFIED at the composed layer. The
   composed path carries ONE authority dict (the ``gov/workflow.py``
   shape: actor_id, action, chain, trust_roots, revocation_ledger).
   For saga units, the composer installs (same-trust-plane, in-process,
   documented -- the memory_composed precedent) a verifier on the saga
   manager under a plan-scoped ``authority_ref``; that verifier
   re-proves the workflow authority NOW via
   ``WorkflowStore._verify_authority`` -- the same check the resume
   path runs, not a second trust anchor. Every compensation therefore
   re-proves the original step's authority at compensation time; a
   lapsed authority escalates the saga (its own coded path) instead of
   compensating under stale authority.
   - Mismatch: the composer records the plan's initiating actor at
     first execute; a later call (resume/retry) presenting a different
     actor_id refuses ``workflow-composed-authority-mismatch`` -- the
     workflow store's per-run actor check already covers run hijack;
     this covers plan-level actor substitution across the composed
     units (e.g. the saga verifier's captured authority vs the
     presented one).

4. COMPOSED EVIDENCE RECORD (seam 5: receipt chain vs checkpoint log
   -- two audit trails). ONE trail: the workflow checkpoint log is
   canonical. Routing-slip receipt digests are BOUND INTO the leg's
   step outputs (``_composed_receipt_digest``), so the checkpoint
   digest commits to the receipt chain -- the receipts are referenced
   by digest, never duplicated. Saga outbox intents carry a stable
   step reference (run_id, unit, step_id) bound into a
   ``_composed_evidence`` key; it resolves through the idempotency
   record's result_ref to the exact checkpoint record, whose digest
   then binds intent to evidence. Rejected alternative: two parallel
   trails that can disagree about what happened.

5. TIME (seam 6: durable sleep vs idempotency retry -- and the saga
   module's notable ABSENCE of a timeout primitive). All instants are
   caller-supplied everywhere already (``at``/``now``); the composed
   path threads ONE ``at`` and ONE ``now`` through every layer of a
   single execute call, and records them on the plan execution record.
   The defined attack is clock mixing across resume (a sleep wake
   evaluated against a different clock than the checkpoint's); the
   fail-closed rule is monotonicity: a sleep/recv wake may complete
   only when ``now >= wake_at`` AND ``now >= step.at`` of the pending
   record -- time may not run backwards within a composed execution.
   Clocks remain deployment-owned (no trusted clock is invented).

6. OUTBOX x IDEMPOTENCY (seam 7: outbox intents vs idempotent
   operations -- exactly-once across both). Outbox dispatch goes
   THROUGH the idempotency store: each intent dispatches under
   ``op_class="composed-outbox"``, key ``"<saga_id>:<intent_id>"``,
   op_digest = intent payload digest. A redrain after a
   crash-before-mark re-executes the dispatcher safely (RETRY, not a
   duplicate); an already-completed dispatch replays the recorded
   result without calling the dispatcher. On the composed path,
   dispatchers need not be idempotent by themselves -- the composed
   layer enforces it. (The saga module's standalone contract --
   "dispatchers must be idempotent" -- is unchanged for direct users.)

7. SAGA-IN-WORKFLOW (discovered seam: whose failure semantics win?).
   The saga runs INSIDE the composed plan: each saga action executes
   as a workflow step slot (Decision 1); when the saga compensates,
   each compensation executes as a further workflow step slot, so the
   checkpoint log reads forward-steps-then-compensations-in-reverse --
   the whole story in one trail. An escalated saga fails the composed
   saga unit coded with the saga's escalation code (no silent partial
   state); the workflow run is failed with that code as the reason.

8. SLIP-IN-WORKFLOW (discovered seam: slip advance vs step failure).
   A routed unit advances the slip ONLY on leg success: accept_leg
   (full-slip re-verification) runs before the leg fn; complete_leg
   runs after, on the pre-leg slip, and is deterministic (same
   outputs -> byte-identical receipt), so a retry after a
   crash-before-checkpoint replays safely. A failed leg fn leaves the
   slip unadvanced (no receipt); the composed unit stops and returns
   the latest slip so the caller can resume from the outstanding leg.
   The receipt digest is bound into the step outputs (Decision 4).

New decision codes (4): ``workflow-composed-divergent`` (critical),
``workflow-composed-definition-invalid`` (high),
``workflow-composed-authority-mismatch`` (high),
``workflow-composed-replay-foreign`` (critical).

Threat model / honest residuals:

* The four submodules keep their own threat models; the composer adds
  the cross-layer fork model (Decision 2's divergence check).
* Op implementations, leg fns, dispatchers, and authority verifiers
  are deployment code: a lying fn falsifies its result. The composer
  guarantees ordering, recording, replay discipline, and authority
  re-proof -- not fn honesty.
* The saga op registry is process-global: wrapper op names are
  plan-scoped (``composed:<plan12>:...``) so concurrent plans do not
  collide; a resumed composer in a new process must re-execute (not
  resume mid-saga) or re-register -- saga instance dumps are offered
  via ``dump_state``/``load_state`` for the metadata, while the
  effects themselves are protected by the idempotency layer.
* ``at``/``now`` are caller-supplied freshness markers (Decision 5).
* In-memory per composer (wave-292 decay precedent): not distributed
  consensus. The audit sink is F345-class (never breaks the module).
"""

import hashlib
import json
import secrets

from gov import workflow as _wf
from gov import workflow_saga as _saga
from gov import workflow_routing as _wr
from gov import workflow_idempotency as _idem

# ---------------------------------------------------------------------------
# Codes (registered at true sorted positions in gov/decision_codes.py).
# ---------------------------------------------------------------------------

WC_DIVERGENT = "workflow-composed-divergent"
WC_DEFINITION_INVALID = "workflow-composed-definition-invalid"
WC_AUTHORITY_MISMATCH = "workflow-composed-authority-mismatch"
WC_REPLAY_FOREIGN = "workflow-composed-replay-foreign"

# Reused (not minted): the submodules' own coded refusals propagate with
# their codes -- workflow-*, workflow-saga-*, workflow-routing-*,
# workflow-idempotency-*, permit-idempotency-conflict.

__all__ = [
    "WorkflowComposer",
    "ComposedError",
    "WC_DIVERGENT",
    "WC_DEFINITION_INVALID",
    "WC_AUTHORITY_MISMATCH",
    "WC_REPLAY_FOREIGN",
    "UNIT_FN",
    "UNIT_SAGA",
    "UNIT_SLIP",
]

UNIT_FN = "fn"
UNIT_SAGA = "saga"
UNIT_SLIP = "slip"

_OP_UNIT = "composed-unit"
_OP_SAGA_ACTION = "composed-saga-action"
_OP_SAGA_COMP = "composed-saga-comp"
_OP_SLIP_LEG = "composed-slip-leg"
_OP_OUTBOX = "composed-outbox"

_SINK = None


def set_sink(fn):
    """Install an audit sink ``fn(record)``; None clears it."""
    global _SINK
    _SINK = fn


def _emit(event, detail=None):
    if _SINK is None:
        return
    try:
        _SINK({"event": event, "detail": detail or {}})
    except Exception:
        pass


class ComposedError(Exception):
    """Coded refusal from the composed workflow path."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise ComposedError(detail, code=code)


def _canon(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        _fail(WC_DEFINITION_INVALID,
              "composed plan material is not JSON-serializable")


def _digest(value):
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

class ComposedPlan:
    """An ordered list of execution units.

    Unit shapes (all JSON-able except ``fn`` callables):
    - {"kind": "fn", "name", "fn", "inputs"?, "idem_key"}
    - {"kind": "saga", "name", "definition": SagaDefinition,
       "action_fns": {step_id: fn}, "comp_fns": {step_id: fn},
       "idem_key"}
    - {"kind": "slip", "name", "slip": <routing slip dict>,
       "trust_roots": [...], "leg_fns": {leg_index: (seed, fn)},
       "idem_key"}
    """

    def __init__(self, units):
        if not isinstance(units, (list, tuple)) or not units:
            _fail(WC_DEFINITION_INVALID,
                  "a composed plan needs at least one unit")
        seen = set()
        normed = []
        for u in units:
            if not isinstance(u, dict):
                _fail(WC_DEFINITION_INVALID, "plan unit must be a dict")
            kind = u.get("kind")
            name = u.get("name")
            if kind not in (UNIT_FN, UNIT_SAGA, UNIT_SLIP):
                _fail(WC_DEFINITION_INVALID,
                      "unknown unit kind %r" % (kind,))
            if not isinstance(name, str) or not name:
                _fail(WC_DEFINITION_INVALID,
                      "unit name must be a non-empty string")
            if name in seen:
                _fail(WC_DEFINITION_INVALID,
                      "duplicate unit name %r" % (name,))
            seen.add(name)
            idem_key = u.get("idem_key")
            if not isinstance(idem_key, str) or not idem_key:
                _fail(WC_DEFINITION_INVALID,
                      "unit %r needs an idem_key" % (name,))
            if kind == UNIT_FN:
                if not callable(u.get("fn")):
                    _fail(WC_DEFINITION_INVALID,
                          "fn unit %r needs a callable fn" % (name,))
                inputs = u.get("inputs", {})
                _canon(inputs)  # checkpointable (refuses coded)
            elif kind == UNIT_SAGA:
                d = u.get("definition")
                if not isinstance(d, _saga.SagaDefinition):
                    _fail(WC_DEFINITION_INVALID,
                          "saga unit %r needs a SagaDefinition" % (name,))
                for label in ("action_fns", "comp_fns"):
                    fns = u.get(label)
                    if not isinstance(fns, dict) or not fns:
                        _fail(WC_DEFINITION_INVALID,
                              "saga unit %r needs %s" % (name, label))
                    for sid, fn in fns.items():
                        if not callable(fn):
                            _fail(WC_DEFINITION_INVALID,
                                  "saga unit %r: %s[%r] not callable"
                                  % (name, label, sid))
                missing_a = [s.step_id for s in d.steps
                             if s.step_id not in u["action_fns"]]
                missing_c = [s.step_id for s in d.steps
                             if s.step_id not in u["comp_fns"]]
                if missing_a or missing_c:
                    _fail(WC_DEFINITION_INVALID,
                          "saga unit %r missing fns for steps %r/%r"
                          % (name, missing_a, missing_c))
            else:  # UNIT_SLIP
                leg_fns = u.get("leg_fns")
                if not isinstance(leg_fns, dict) or not leg_fns:
                    _fail(WC_DEFINITION_INVALID,
                          "slip unit %r needs leg_fns" % (name,))
                for idx, pair in leg_fns.items():
                    if (not isinstance(pair, (list, tuple))
                            or len(pair) != 2
                            or not isinstance(pair[0], bytes)
                            or not callable(pair[1])):
                        _fail(WC_DEFINITION_INVALID,
                              "slip unit %r: leg_fns[%r] must be "
                              "(seed, fn)" % (name, idx))
                if not isinstance(u.get("trust_roots"), (list, tuple)):
                    _fail(WC_DEFINITION_INVALID,
                          "slip unit %r needs trust_roots" % (name,))
            normed.append(u)
        self.units = tuple(normed)
        self.digest = _digest([
            {"kind": u["kind"], "name": u["name"],
             "idem_key": u["idem_key"],
             "inputs_digest": _digest(u.get("inputs", {}))}
            for u in normed
        ])


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------

class WorkflowComposer:
    """The single composed execution path over the four workflow modules.

    ``namespace`` scopes the idempotency keys (the idempotency store
    already isolates by (namespace, op_class, key)).
    """

    def __init__(self, workflow_store, saga_manager, idem_store,
                 namespace="composed"):
        for label, obj, cls in (
                ("workflow_store", workflow_store, _wf.WorkflowStore),
                ("saga_manager", saga_manager, _saga.SagaManager),
                ("idem_store", idem_store, _idem.IdempotencyStore)):
            if not isinstance(obj, cls):
                _fail(WC_DEFINITION_INVALID,
                      "%s must be a %s" % (label, cls.__name__))
        if not isinstance(namespace, str) or not namespace:
            _fail(WC_DEFINITION_INVALID,
                  "namespace must be a non-empty string")
        self._wstore = workflow_store
        self._saga = saga_manager
        self._idem = idem_store
        self._namespace = namespace
        self._seq = 0
        self._plan_actor = None      # Decision 3: plan-level actor pin
        self._exec_ctx = None        # live execution context (sync only)
        self._saga_instances = {}    # unit name -> SagaInstance
        self._slips = {}             # unit name -> latest slip dict
        # F386: per-composer-instance nonce. Verifier refs installed on the
        # shared SagaManager are scoped with this nonce, so two composers
        # sharing one manager can never overwrite each other's verifier.
        self._verifier_nonce = secrets.token_hex(8)

    # -- authority ----------------------------------------------------

    def _authority_verifier(self, actor, at):
        """Idempotency-store verifier: re-prove the workflow authority."""
        def verify(caller=None, namespace=None, op_class=None, at=None):
            _ = (namespace, op_class)
            if caller != actor:
                return False
            try:
                _wf.WorkflowStore._verify_authority(
                    self._exec_ctx["authority"],
                    self._exec_ctx["run"], at if at is not None else self._exec_ctx["at"])
                return True
            except Exception:
                return False
        return verify

    def _install_saga_verifier(self, ref):
        """Decision 3: the saga's ref mechanism dispatches to the SAME
        workflow authority check, re-proven NOW. Same-trust-plane,
        in-process adaptation (memory_composed precedent).

        F386: ``ref`` must already be composer-instance-scoped (the
        caller builds it from the nonce-scoped unit tag). The shared
        SagaManager's ``_verifiers`` dict is process-global storage, so
        a plan-scoped ref alone lets a second composer overwrite the
        first composer's verifier. The entry is removed deterministically
        by ``_remove_saga_verifier`` when the unit completes.
        """

        def verify():
            ctx = self._exec_ctx
            if ctx is None:
                return False
            try:
                _wf.WorkflowStore._verify_authority(
                    ctx["authority"], ctx["run"], ctx["at"])
                return True
            except Exception:
                return False
        self._saga._verifiers[ref] = verify

    def _remove_saga_verifier(self, scoped_ref):
        """F386: deterministic removal when the unit completes (success,
        failure, or compensation end). A verifier entry that outlives its
        unit is exactly the collision surface -- a later composer sharing
        the manager could inherit or overwrite it."""
        self._saga._verifiers.pop(scoped_ref, None)

    def _remove_saga_ops(self, scoped_tag, unit):
        """Wave-305 hygiene: the nonce-scoped wrapper ops registered in
        the process-global op registry must not outlive the unit either.
        Stale entries are inert -- a post-completion invocation crashes
        on the torn-down ``_exec_ctx`` (``TypeError``), and the 64-bit
        nonce makes the names unguessable -- but the registry grows two
        entries per step per instance, a slow leak and a stale-name
        surface. Removal rides the same ``finally`` as the verifier
        removal; ``pop`` is best-effort so a failed wrapper build leaves
        nothing behind. Direct ``_OPS`` access mirrors the verifier
        pattern (no public unregister exists; ``clear_ops()`` would nuke
        unrelated registrations)."""
        for step in unit["definition"].steps:
            sid = step.step_id
            _saga._OPS.pop("composed:%s:action:%s" % (scoped_tag, sid),
                           None)
            _saga._OPS.pop("composed:%s:comp:%s" % (scoped_tag, sid),
                           None)

    def _check_plan_actor(self, actor):
        if self._plan_actor is None:
            self._plan_actor = actor
        elif self._plan_actor != actor:
            _fail(WC_AUTHORITY_MISMATCH,
                  "plan actor changed mid-execution: %r != %r "
                  "(authority substitution across composed units)"
                  % (actor, self._plan_actor))

    # -- idempotency outer --------------------------------------------

    def _begin_unit(self, op_class, key, op_digest, actor, at):
        outcome = self._idem.begin(
            self._namespace, op_class, key, op_digest, caller=actor,
            authority_verifier=self._authority_verifier(actor, at), at=at)
        return outcome

    def _step_binding(self, op_class, key):
        """F391: the workflow step's binding to the idempotency record.

        Step names are unique per (plan, unit) but NOT per run:
        ``execute()`` takes a caller-provided run_id and never binds a
        run to a single plan, so two plans executed under one run can
        record the same step name for different units' work (a poisoned
        pair naming the attacker's same-named step then passes the F390
        name check). The (namespace, op_class, key) triple identifies
        the exact idem record; the step records it as its
        idempotency_key and ``_resolve_replay`` verifies the binding.
        The ``\\x00`` separators mirror the idem store's record key so
        a key containing \":\" cannot blur the fields.
        """
        return "%s\x00%s\x00%s" % (self._namespace, op_class, key)

    def _resolve_replay(self, outcome, op_class, key, expected_step_name):
        """Decision 2/5: an outer REPLAY resolves through the result_ref
        back to the workflow checkpoint; digest disagreement is a fork.

        F388: the pair must be NATIVE to this composed execution. The
        composer only ever completes refs of the form
        ``wfstep:<current run>:<seq>`` under its plan actor (Decision 3,
        ``_complete_unit``), so a ref naming any other run -- or a
        record begun by any other caller -- is a foreign (poisoned)
        pair and refuses ``workflow-composed-replay-foreign``. A
        resolution attempted outside a composed execution has no run
        to bind to and refuses the same code.

        F390: the pair must also be NATIVE to the replaying unit. The
        ref's step must have been created by the unit now replaying
        (checked via the step's recorded name against
        ``expected_step_name``). A ref naming a different completed
        step of the same run -- same run_id, same caller, valid digest
        -- is foreign to this unit and refuses
        ``workflow-composed-replay-foreign``. The step name is stored
        in the workflow store (not attacker-controlled); the idempotency
        record's ref alone cannot establish which unit created the step.

        F391: the name binding is not unique per run. ``execute()``
        takes a caller-provided run_id and never binds a run to a
        single plan, so a different plan executed under the same run
        can record the SAME step name for a different unit's work; a
        poisoned pair naming the attacker's same-named step then passes
        the F390 name check. The step records the (namespace, op_class,
        key) triple of the idempotency record that created it (as its
        idempotency_key, via ``_step_binding``); the replaying unit's
        key must match, or the pair refuses
        ``workflow-composed-replay-foreign``. ``key`` is required --
        fail-closed by construction.
        """
        ctx = self._exec_ctx
        if ctx is None:
            _fail(WC_REPLAY_FOREIGN,
                  "idempotency replay resolved with no composed "
                  "execution in progress (%s): the pair cannot be bound "
                  "to a run the composer began" % (op_class,))
        ref = outcome.result_ref or ""
        if not ref.startswith("wfstep:"):
            _fail(WC_DIVERGENT,
                  "idempotency replay references an unknown record %r "
                  "(%s)" % (ref, op_class))
        try:
            _, run_id, seq_s = ref.split(":")
            seq = int(seq_s)
        except ValueError:
            _fail(WC_DIVERGENT,
                  "idempotency replay references a malformed record %r "
                  "(%s)" % (ref, op_class))
        if run_id != ctx["run_id"]:
            _fail(WC_REPLAY_FOREIGN,
                  "idempotency replay references run %r, but the composer "
                  "is executing run %r (%s): foreign pair refused"
                  % (run_id, ctx["run_id"], op_class))
        if outcome.record_caller != ctx["actor"]:
            _fail(WC_REPLAY_FOREIGN,
                  "idempotency replay record was begun by %r, not the "
                  "plan actor %r (%s): foreign pair refused"
                  % (outcome.record_caller, ctx["actor"], op_class))
        try:
            step = self._wstore.get_step(run_id, seq)
        except KeyError as e:
            _fail(WC_DIVERGENT,
                  "idempotency replay points at a missing workflow step "
                  "%r (%s): %s" % (ref, op_class, e))
        if step.get("status") != "completed":
            _fail(WC_DIVERGENT,
                  "idempotency replay points at an incomplete workflow "
                  "step %r (%s)" % (ref, op_class))
        if _digest(step.get("outputs")) != outcome.result_digest:
            _fail(WC_DIVERGENT,
                  "idempotency record and workflow checkpoint disagree "
                  "on %r (%s): layers have forked" % (ref, op_class))
        if step.get("name") != expected_step_name:
            _fail(WC_REPLAY_FOREIGN,
                  "idempotency replay references step %r (created by %r), "
                  "but the replaying unit expects step %r (%s): foreign "
                  "pair refused"
                  % (ref, step.get("name"), expected_step_name, op_class))
        expected_binding = self._step_binding(op_class, key)
        if step.get("idempotency_key") != expected_binding:
            _fail(WC_REPLAY_FOREIGN,
                  "idempotency replay references step %r, but that step "
                  "was recorded under a different idempotency binding: "
                  "step names are not unique per run (%s): foreign pair "
                  "refused" % (ref, op_class))
        return step["outputs"]

    def _complete_unit(self, outcome, outputs, run_id, seq, at):
        ref = "wfstep:%s:%d" % (run_id, seq)
        return outcome.complete(_digest(outputs), ref, at=at)

    # -- workflow inner -----------------------------------------------

    def _next_seq(self):
        self._seq += 1
        return self._seq

    def _run_unit_step(self, run_id, name, fn, inputs, authority, at,
                       step_binding):
        """Decision 1: every unit executes inside a workflow step slot.

        ``step_binding`` (from ``_step_binding``) is recorded as the
        step's idempotency_key so ``_resolve_replay`` can verify the
        step was created by the idempotency record now replaying
        (F391). Required -- fail-closed by construction.
        """
        seq = self._next_seq()
        outputs, replayed = self._wstore.run_step(
            run_id, seq, name, fn, inputs,
            idempotency_key=step_binding,
            authority=authority, at=at)
        return seq, outputs, replayed

    # -- saga unit ------------------------------------------------------

    def _saga_wrappers(self, scoped_tag, unit, authority_ref):
        """Register composer-instance-scoped wrapper ops so saga actions
        and compensations execute inside the composed path (Decisions
        1-3). F386: ``scoped_tag`` must be the nonce-scoped unit tag
        (see ``_execute_saga_unit``); plan-scoped names alone let a
        second composer overwrite the first's wrapper ops."""
        definition = unit["definition"]
        action_fns = unit["action_fns"]
        comp_fns = unit["comp_fns"]

        for step in definition.steps:
            sid = step.step_id

            def make_action(real_fn, step_id=sid):
                def action_op(params):
                    ctx = self._exec_ctx
                    op_digest = _digest({
                        "plan": ctx["plan_digest"], "op": "saga-action",
                        "unit": unit["name"], "step": step_id,
                        "params": _digest(params)})
                    ukey = "%s:action:%s" % (unit["idem_key"], step_id)
                    outcome = self._begin_unit(
                        _OP_SAGA_ACTION, ukey,
                        op_digest, ctx["actor"], ctx["at"])
                    if outcome.status == "replay":
                        saved = self._resolve_replay(
                            outcome, _OP_SAGA_ACTION, ukey,
                            "saga:%s:%s" % (unit["name"], step_id))
                        return saved["result"], saved["payloads"]
                    # Decision 4: the evidence binding uses STABLE
                    # identifiers (run_id, unit, step_id) -- computable
                    # before the step is recorded, hence identical on
                    # every replay. It resolves through the idempotency
                    # record's result_ref to the exact checkpoint
                    # record (whose digest then binds).
                    ev = {"run_id": ctx["run_id"], "unit": unit["name"],
                          "step_id": step_id}

                    def _run_action(i, _f=real_fn, _ev=ev,
                                    _uk=unit["idem_key"]):
                        res, pl = _f(dict(i))
                        if not isinstance(pl, list) or any(
                                not isinstance(p, dict) for p in pl):
                            raise ValueError(
                                "action must return (result, [payloads])")
                        stable = []
                        for j, p in enumerate(pl):
                            if not p.get("intent_id"):
                                p = dict(p, intent_id="%s:%s:%d" % (
                                    _uk, step_id, j))
                            stable.append(dict(p, _composed_evidence=_ev))
                        return {"result": res, "payloads": stable}

                    name = "saga:%s:%s" % (unit["name"], step_id)
                    seq, outputs, _ = self._run_unit_step(
                        ctx["run_id"], name, _run_action,
                        dict(params), ctx["authority"], ctx["at"],
                        self._step_binding(_OP_SAGA_ACTION, ukey))
                    result = outputs["result"]
                    payloads = outputs["payloads"]
                    self._complete_unit(outcome, outputs, ctx["run_id"],
                                        seq, ctx["at"])
                    return result, payloads
                return action_op

            def make_comp(real_fn, step_id=sid):
                def comp_op(params):
                    ctx = self._exec_ctx
                    op_digest = _digest({
                        "plan": ctx["plan_digest"], "op": "saga-comp",
                        "unit": unit["name"], "step": step_id,
                        "params": _digest(params)})
                    ukey = "%s:comp:%s" % (unit["idem_key"], step_id)
                    outcome = self._begin_unit(
                        _OP_SAGA_COMP, ukey,
                        op_digest, ctx["actor"], ctx["at"])
                    if outcome.status == "replay":
                        saved = self._resolve_replay(
                            outcome, _OP_SAGA_COMP, ukey,
                            "saga-comp:%s:%s" % (unit["name"], step_id))
                        return saved["result"]
                    name = "saga-comp:%s:%s" % (unit["name"], step_id)
                    seq, outputs, _ = self._run_unit_step(
                        ctx["run_id"], name,
                        lambda i, _f=real_fn: {"result": _f(dict(i))},
                        dict(params), ctx["authority"], ctx["at"],
                        self._step_binding(_OP_SAGA_COMP, ukey))
                    self._complete_unit(outcome, outputs, ctx["run_id"],
                                        seq, ctx["at"])
                    return outputs["result"]
                return comp_op

            _saga.register_op("composed:%s:action:%s" % (scoped_tag, sid),
                              make_action(action_fns[sid]))
            _saga.register_op("composed:%s:comp:%s" % (scoped_tag, sid),
                              make_comp(comp_fns[sid]))

        wrapped_steps = []
        for step in definition.steps:
            wrapped_steps.append(_saga.SagaStepDef(
                step_id=step.step_id,
                action_op="composed:%s:action:%s" % (scoped_tag, step.step_id),
                action_params=dict(step.action_params),
                compensation_op="composed:%s:comp:%s" % (scoped_tag,
                                                        step.step_id),
                compensation_params=dict(step.compensation_params),
                authority_ref=authority_ref))
        return self._saga.define(wrapped_steps)

    def _execute_saga_unit(self, unit, ctx):
        unit_tag = "%s:%s" % (ctx["plan_digest"][:12], unit["name"])
        # F386: everything this unit installs on SHARED registries -- the
        # saga manager's ``_verifiers`` dict and the process-global op
        # registry (whose names are built from the unit tag) -- must be
        # scoped to this composer instance. A second composer running the
        # same plan on the same manager would otherwise overwrite this
        # composer's verifier AND its wrapper ops, breaking reentrant
        # same-plan execution during compensation.
        scoped_tag = "%s:%s" % (self._verifier_nonce, unit_tag)
        authority_ref = "composed-auth:%s" % scoped_tag
        self._install_saga_verifier(authority_ref)
        try:
            wrapped = self._saga_wrappers(scoped_tag, unit, authority_ref)
            instance = self._saga.start(wrapped)
            self._saga_instances[unit["name"]] = instance
            try:
                self._saga.run(instance)
            except _saga.SagaError as e:
                # Decision 7: an escalated saga fails the composed unit
                # coded with the saga's escalation code.
                code = getattr(e, "code", None) or \
                    _saga.CODE_COMPENSATION_FAILED
                _fail(code,
                      "composed saga unit %r escalated: %s"
                      % (unit["name"], e))
            if instance.status == "escalated":
                _fail(instance.escalation_code or
                      _saga.CODE_COMPENSATION_FAILED,
                      "composed saga unit %r escalated" % (unit["name"],))
            # Decision 6: outbox dispatch goes through the idempotency
            # store, so a redrain after a crash-before-mark is a safe
            # retry, never a duplicate.
            dispatched = self._drain_outbox_composed(instance, unit, ctx)
            return {"saga_id": instance.saga_id,
                    "status": instance.status,
                    "steps": [
                        {"step_id": s["step_id"], "state": s["state"]}
                        for s in instance.steps],
                    "outbox_dispatched": dispatched}
        finally:
            # F386: the verifier entry must not outlive the unit --
            # removal is deterministic on success, failure, and
            # compensation end. The entry is needed only while
            # self._saga.run() executes (forward + compensation
            # authority checks); afterwards the composer's execution
            # context is torn down anyway.
            self._remove_saga_verifier(authority_ref)
            # Wave-305: the nonce-scoped wrapper ops must not outlive
            # the unit either -- same finally, same determinism. The
            # wrapped ops are needed only while self._saga.run() (and
            # the outbox drain above) execute; after the unit completes
            # they are dead names in a shared process-global registry.
            self._remove_saga_ops(scoped_tag, unit)

    def _drain_outbox_composed(self, instance, unit, ctx):
        # The idempotency key binds (unit idem_key, intent_id) -- never
        # the ephemeral saga instance id -- so a redrain of a
        # re-created instance replays the same dispatch records.
        unit_key = unit["idem_key"]

        def idem_dispatcher(intent):
            intent_id = intent["intent_id"]
            op_digest = _digest(intent["payload"])
            outcome = self._begin_unit(
                _OP_OUTBOX, "%s:%s" % (unit_key, intent_id),
                op_digest, ctx["actor"], ctx["at"])
            if outcome.status == "replay":
                return outcome.result_ref
            result = {"dispatched": True, "intent_id": intent_id}
            outcome.complete(_digest(result),
                             "outbox:%s:%s" % (unit_key, intent_id),
                             at=ctx["at"])
            return result
        return self._saga.drain_outbox(instance, idem_dispatcher)

    # -- slip unit --------------------------------------------------------

    def _execute_slip_unit(self, unit, ctx):
        slip = self._slips.get(unit["name"], unit["slip"])
        trust_roots = list(unit["trust_roots"])
        leg_fns = unit["leg_fns"]
        results = []
        idx = 0
        while idx < len(slip["legs"]):
            # Decision 8: accept (full-slip re-verification) BEFORE the
            # leg fn; the slip advances ONLY on leg success.
            leg = _wr.accept_leg(slip, idx, leg_fns[idx][0], ctx["at"],
                                 trust_roots)
            seed, fn = leg_fns[idx][0], leg_fns[idx][1]
            op_digest = _digest({
                "plan": ctx["plan_digest"], "op": "slip-leg",
                "unit": unit["name"], "leg": idx,
                "slip": slip["slip_id"],
                "input_digest": leg["input_digest"]})
            ukey = "%s:leg:%d" % (unit["idem_key"], idx)
            outcome = self._begin_unit(
                _OP_SLIP_LEG, ukey,
                op_digest, ctx["actor"], ctx["at"])
            if outcome.status == "replay":
                saved = self._resolve_replay(
                    outcome, _OP_SLIP_LEG, ukey,
                    "slip:%s:leg:%d" % (unit["name"], idx))
                # The receipt was already bound on first execution.
                slip = self._advance_slip(slip, idx, seed,
                                          saved["_result_digest"],
                                          ctx["at"], trust_roots)
                results.append({"leg": idx, "replayed": True,
                                "outputs": saved["outputs"]})
                idx += 1
                continue
            name = "slip:%s:leg:%d" % (unit["name"], idx)
            leg_inputs = {"leg_index": idx, "slip_id": slip["slip_id"],
                          "input_digest": leg["input_digest"]}
            try:
                outputs = fn(dict(leg_inputs))
            except Exception:
                # Decision 8: failed leg fn -> no receipt, slip not
                # advanced; the failure is checkpointed as a failed
                # step and the unit stops (caller may resume).
                seq = self._next_seq()
                try:
                    self._wstore.run_step(
                        ctx["run_id"], seq, name,
                        lambda i: (_ for _ in ()).throw(RuntimeError(
                            "leg fn failed before checkpoint")),
                        leg_inputs, authority=ctx["authority"], at=ctx["at"])
                except RuntimeError:
                    pass
                self._slips[unit["name"]] = slip
                return {"legs": results, "slip": slip,
                        "completed": False,
                        "failed_leg": idx}
            _canon(outputs)  # checkpointable (refuses coded)
            result_digest = _digest(outputs)
            # complete_leg is deterministic: same outputs ->
            # byte-identical receipt, so a retry after a
            # crash-before-checkpoint replays safely.
            new_slip = _wr.complete_leg(slip, idx, seed, result_digest,
                                        ctx["at"], trust_roots)
            receipt_digest = new_slip["receipts"][-1]["receipt_digest"]
            enriched = {"outputs": outputs,
                        "_result_digest": result_digest,
                        "_composed_receipt_digest": receipt_digest}
            seq, recorded, _ = self._run_unit_step(
                ctx["run_id"], name, lambda i, e=enriched: e,
                leg_inputs, ctx["authority"], ctx["at"],
                self._step_binding(_OP_SLIP_LEG, ukey))
            self._complete_unit(outcome, recorded, ctx["run_id"], seq,
                                ctx["at"])
            slip = new_slip
            results.append({"leg": idx, "replayed": False,
                            "outputs": outputs,
                            "receipt_digest": receipt_digest})
            idx += 1
        self._slips[unit["name"]] = slip
        return {"legs": results, "slip": slip, "completed": True}

    def _advance_slip(self, slip, idx, seed, result_digest, at, trust_roots):
        """Re-derive the deterministic receipt on idem replay."""
        return _wr.complete_leg(slip, idx, seed, result_digest, at,
                                trust_roots)

    # -- fn unit ----------------------------------------------------------

    def _execute_fn_unit(self, unit, ctx):
        op_digest = _digest({
            "plan": ctx["plan_digest"], "op": "unit",
            "unit": unit["name"],
            "inputs": _digest(unit.get("inputs", {}))})
        outcome = self._begin_unit(_OP_UNIT, unit["idem_key"], op_digest,
                                   ctx["actor"], ctx["at"])
        if outcome.status == "replay":
            return {"replayed": True,
                    "outputs": self._resolve_replay(
                        outcome, _OP_UNIT, unit["idem_key"],
                        "fn:%s" % unit["name"])}
        name = "fn:%s" % unit["name"]
        seq, outputs, _ = self._run_unit_step(
            ctx["run_id"], name, unit["fn"], dict(unit.get("inputs", {})),
            ctx["authority"], ctx["at"],
            self._step_binding(_OP_UNIT, unit["idem_key"]))
        self._complete_unit(outcome, outputs, ctx["run_id"], seq, ctx["at"])
        return {"replayed": False, "outputs": outputs}

    # -- main entry -------------------------------------------------------

    def execute(self, plan, *, run_id, authority, at, now=None):
        """Execute a composed plan inside a workflow run.

        ``run_id`` must identify a run started via
        ``workflow_store.start_run`` (its idempotency key is the
        plan-level dedup; the composer does not invent one). Authority
        is re-proved on every unit (Decision 3); ``at``/``now`` are
        threaded through every layer (Decision 5).
        """
        if not isinstance(plan, ComposedPlan):
            _fail(WC_DEFINITION_INVALID, "plan must be a ComposedPlan")
        if not isinstance(authority, dict):
            _fail(WC_DEFINITION_INVALID, "authority must be a dict")
        actor = authority.get("actor_id")
        if not isinstance(actor, str) or not actor:
            _fail(WC_DEFINITION_INVALID,
                  "authority must name an actor_id")
        if not _is_int(at) or at < 0:
            _fail(WC_DEFINITION_INVALID,
                  "at must be a non-negative int instant")
        now = at if now is None else now
        if not _is_int(now) or now < 0:
            _fail(WC_DEFINITION_INVALID,
                  "now must be a non-negative int instant")
        run = self._wstore.get_run(run_id)
        # Re-prove at entry (never trust a prior execute call).
        _wf.WorkflowStore._verify_authority(authority, run, at)
        self._check_plan_actor(actor)
        # Decision 5: monotonicity within a composed execution.
        if now < at:
            _fail(WC_DEFINITION_INVALID,
                  "now < at: time may not run backwards within a "
                  "composed execution")

        ctx = {"plan_digest": plan.digest, "run_id": run_id,
               "run": run, "authority": authority, "actor": actor,
               "at": at, "now": now}
        self._exec_ctx = ctx
        _emit("composed_execute", {"plan": plan.digest[:12],
                                   "run_id": run_id, "units": len(plan.units),
                                   "at": at})
        results = {}
        try:
            for unit in plan.units:
                kind = unit["kind"]
                if kind == UNIT_FN:
                    results[unit["name"]] = self._execute_fn_unit(
                        unit, ctx)
                elif kind == UNIT_SAGA:
                    results[unit["name"]] = self._execute_saga_unit(
                        unit, ctx)
                else:
                    results[unit["name"]] = self._execute_slip_unit(
                        unit, ctx)
        finally:
            self._exec_ctx = None
        return {"plan_digest": plan.digest, "run_id": run_id,
                "units": results}

    # -- crash-recovery metadata ------------------------------------------

    def dump_state(self):
        """JSON-able composer metadata (saga instances, latest slips).

        The effects themselves are protected by the idempotency and
        checkpoint layers; this covers the orchestration metadata."""
        return {
            "seq": self._seq,
            "plan_actor": self._plan_actor,
            "sagas": {name: self._saga.dump(inst)
                      for name, inst in self._saga_instances.items()},
            "slips": {name: slip for name, slip in self._slips.items()},
        }

    def load_state(self, data):
        if not isinstance(data, dict):
            raise ValueError("malformed composer dump: not a dict")
        self._seq = int(data.get("seq", 0))
        self._plan_actor = data.get("plan_actor")
        self._saga_instances = {
            name: self._saga.load(d)
            for name, d in data.get("sagas", {}).items()}
        self._slips = dict(data.get("slips", {}))
