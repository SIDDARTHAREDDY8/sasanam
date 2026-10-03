"""Durable workflow execution: checkpoint every step; resume re-proves authority.

STEAL from dbos-inc/dbos-transact-py (MIT): durable execution as a
library -- checkpoint every step, resume from the last completed step,
exactly-once via idempotency keys, workflow state as queryable rows,
durable sleep / durable notifications. Rebuilt here on Sasanam's own
discipline: stdlib only, append-only JSONL step records, content
digests over canonical JSON, no Postgres dependency.

Standing design rule: "A workflow outlives its runner -- every step is
checkpointed, and every resume re-proves its authority."

Authority model: every mutating call presents an ``authority`` dict::

    {"actor_id": "agent-b",
     "action": "tool.invoke",            # delegation action, default shown
     "chain": [...],                     # gov.delegation native receipts,
                                          # root-first
     "trust_roots": ["<hex>", ...],
     "revocation_ledger": DelegationRevoker}

Fresh execution verifies the chain (``gov.delegation.authorize`` --
``delegation-*`` coded errors propagate) AND revocation liveness
(``assert_live_native``; a revoked chain refuses
``workflow-authority-revoked`` -- revocation beats expiry, same as the
receipt layer). The ledger is REQUIRED on every verification: an
authority without one fails closed (``workflow-authority-revoked``)
because liveness cannot be proven (the F378 precedent; F380 closure).
A resume NEVER trusts the checkpoint's recorded
authority: the caller re-presents authority, it is re-verified, and the
actor must match the run's initiating actor (no resume hijacking --
``workflow-step-unauthorized``).

Payload contract: step inputs/outputs and notification payloads must be
JSON-serializable -- a step whose effects cannot be checkpointed cannot
be durable. Violations refuse ``workflow-checkpoint-tampered``
(documented mapping: the checkpoint contract is violated at write
time). Re-presenting different inputs for an already-completed step
slot is workflow definition drift and refuses
``workflow-step-unauthorized`` (checkpointed evidence is never
overwritten).

Crash model: the store is append-only JSONL. A trailing partial line
is a crash tear and is ignored; any other undecodable line or any
record whose digest does not recompute refuses
``workflow-checkpoint-tampered`` on load.
"""

import hashlib
import json
import os

from gov import delegation as _delegation
from gov import delegation_revocation as _revocation  # noqa: F401 (docs)

SCHEMA = "gov.workflow.v1"

WF_UNAUTHORIZED = "workflow-step-unauthorized"
WF_REVOKED = "workflow-authority-revoked"
WF_TAMPERED = "workflow-checkpoint-tampered"


class WorkflowError(Exception):
    """Coded refusal from the durable-workflow seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise WorkflowError(detail, code=code)


def _canon(value):
    """Canonical JSON for digests; unserializable payloads refuse coded."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        _fail(WF_TAMPERED,
              "payload is not JSON-serializable and cannot be checkpointed: "
              "%r" % (e,))


def _digest(value):
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _record_digest(record):
    body = {k: v for k, v in record.items() if k != "record_digest"}
    return hashlib.sha256(_canon(body).encode("utf-8")).hexdigest()


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


class WorkflowStore:
    """Durable workflow state: runs, step checkpoints, notifications."""

    def __init__(self, path=None):
        self._path = path
        self._runs = {}        # run_id -> run record
        self._run_status = {}  # run_id -> latest status
        self._steps = {}       # (run_id, seq) -> step record
        self._run_idem = {}    # idempotency_key -> run_id
        self._step_idem = {}   # (run_id, idempotency_key) -> (run_id, seq)
        self._notifications = []  # notification records, in append order
        self._consumed = set()    # notification record_digests consumed
        if path is not None:
            self._load()

    # -- persistence ----------------------------------------------------

    def _append(self, record, persist=True):
        """Append a record in memory, and persist it unless loading.

        ``_load()`` passes ``persist=False``: the records already exist
        in the journal file, so re-appending them would double the
        file on every restart (F382). The in-memory indexes rebuild
        identically either way.
        """
        record = dict(record)
        record["record_digest"] = _record_digest(record)
        rtype = record["type"]
        if rtype == "run":
            self._runs[record["run_id"]] = record
            self._run_status[record["run_id"]] = record["status"]
            if record.get("idempotency_key"):
                self._run_idem[record["idempotency_key"]] = record["run_id"]
        elif rtype == "run_status":
            self._run_status[record["run_id"]] = record["status"]
        elif rtype == "step":
            self._steps[(record["run_id"], record["seq"])] = record
            if record.get("idempotency_key"):
                self._step_idem[(record["run_id"],
                                 record["idempotency_key"])] = (
                    record["run_id"], record["seq"])
        elif rtype == "notification":
            self._notifications.append(record)
        elif rtype == "notification_consumed":
            self._consumed.add(record["notification_digest"])
        else:
            _fail(WF_TAMPERED, "unknown record type %r" % (rtype,))
        if persist and self._path is not None:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(_canon(record) + "\n")
        return record

    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        # A trailing partial line is a crash tear: ignore it, but only it.
        if lines and lines[-1] == "":
            lines.pop()
        for i, line in enumerate(lines):
            last = (i == len(lines) - 1)
            try:
                record = json.loads(line)
            except ValueError:
                if last:
                    continue  # crash tear: incomplete final write
                _fail(WF_TAMPERED,
                      "checkpoint line %d is not valid JSON" % (i,))
            if not isinstance(record, dict) or "record_digest" not in record:
                _fail(WF_TAMPERED,
                      "checkpoint line %d has no record digest" % (i,))
            if record["record_digest"] != _record_digest(record):
                _fail(WF_TAMPERED,
                      "checkpoint record digest mismatch at line %d "
                      "(stored state was tampered with)" % (i,))
            # populate memory without re-appending: reload is a fixed
            # point (F382) -- the records are already on disk.
            self._append(record, persist=False)

    # -- authority ------------------------------------------------------

    @staticmethod
    def _verify_authority(authority, run, at):
        """Re-prove authority on every entry: never trust the checkpoint."""
        if not isinstance(authority, dict):
            _fail(WF_UNAUTHORIZED, "authority must be a dict")
        actor = authority.get("actor_id")
        if not isinstance(actor, str) or not actor:
            _fail(WF_UNAUTHORIZED, "authority carries no actor_id")
        if actor != run["actor_id"]:
            _fail(WF_UNAUTHORIZED,
                  "actor %r is not this run's initiating actor" % (actor,))
        chain = authority.get("chain")
        trust_roots = authority.get("trust_roots")
        if not chain or not trust_roots:
            _fail(WF_UNAUTHORIZED,
                  "authority carries no verifiable delegation chain")
        action = authority.get("action", "tool.invoke")
        # Propagates gov.delegation's own coded errors (delegation-*).
        _delegation.authorize(chain, action, actor, at=at,
                              trust_roots=trust_roots)
        # F380 closure: the revocation ledger is REQUIRED on every
        # authority verification. A caller that omits it fails closed --
        # revocation liveness cannot be proven, so the authority is not
        # trusted (the F378 precedent).
        ledger = authority.get("revocation_ledger")
        if ledger is None:
            _fail(WF_REVOKED,
                  "authority carries no revocation ledger: revocation "
                  "liveness cannot be proven (fail closed)")
        try:
            ledger.assert_live_native(chain, at, trust_roots)
        except Exception as e:  # noqa: BLE001 -- map to workflow code
            _fail(WF_REVOKED,
                  "delegation chain not live at resume: %s "
                  "(underlying code: %s)"
                  % (e, getattr(e, "code", "?")))
        leaf = chain[-1]
        return hashlib.sha256(
            (leaf["receipt_id"] + leaf["delegator_id"]).encode("utf-8")
        ).hexdigest()

    # -- runs -----------------------------------------------------------

    def start_run(self, workflow_name, *, run_id=None,
                  idempotency_key=None, authority, at):
        """Start a run, or idempotently return the existing one.

        Exactly-once per event: a known ``idempotency_key`` (or a known
        ``run_id``) returns the existing run instead of creating a new
        one. Authority is re-proved on every call, including the
        idempotent path.
        """
        if not isinstance(workflow_name, str) or not workflow_name:
            raise ValueError("workflow_name must be a non-empty string")
        if not _is_int(at) or at < 0:
            raise ValueError("at must be a non-negative int instant")
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key:
                raise ValueError("idempotency_key must be a non-empty string")
            existing = self._run_idem.get(idempotency_key)
            if existing is not None:
                run = self._runs[existing]
                self._verify_authority(authority, run, at)
                return dict(run)
        if run_id is None:
            run_id = hashlib.sha256(
                ("%s:%d:%s" % (workflow_name, at,
                               idempotency_key or "")).encode("utf-8")
            ).hexdigest()[:32]
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        if run_id in self._runs:
            run = self._runs[run_id]
            self._verify_authority(authority, run, at)
            return dict(run)
        if not isinstance(authority, dict) \
                or not isinstance(authority.get("actor_id"), str):
            _fail(WF_UNAUTHORIZED, "authority must name an actor_id")
        # Verify before the run exists: build a provisional run record.
        provisional = {"actor_id": authority["actor_id"]}
        self._verify_authority(authority, provisional, at)
        record = {"type": "run", "schema": SCHEMA, "run_id": run_id,
                  "workflow_name": workflow_name,
                  "idempotency_key": idempotency_key,
                  "actor_id": authority["actor_id"],
                  "status": "running", "created_at": at}
        return dict(self._append(record))

    def complete_run(self, run_id, *, authority, at):
        run = self._get_run(run_id)
        self._verify_authority(authority, run, at)
        self._append({"type": "run_status", "schema": SCHEMA,
                      "run_id": run_id, "status": "completed", "at": at})

    def fail_run(self, run_id, reason, *, authority, at):
        run = self._get_run(run_id)
        self._verify_authority(authority, run, at)
        _canon(reason)  # reason must be checkpointable
        self._append({"type": "run_status", "schema": SCHEMA,
                      "run_id": run_id, "status": "failed", "at": at,
                      "reason": reason})

    def _get_run(self, run_id):
        try:
            return self._runs[run_id]
        except KeyError:
            raise KeyError("unknown run_id %r" % (run_id,))

    # -- steps ----------------------------------------------------------

    @staticmethod
    def _check_step_args(run_id, seq, name):
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        if not _is_int(seq) or seq < 0:
            raise ValueError("seq must be a non-negative int")
        if not isinstance(name, str) or not name or len(name) > 128:
            raise ValueError("name must be a 1-128 char string")

    def run_step(self, run_id, seq, name, fn, inputs=None, *,
                 idempotency_key=None, authority, at):
        """Execute (or replay) one checkpointed step.

        Returns ``(outputs, replayed)``. A completed step with matching
        inputs replays its recorded outputs WITHOUT calling ``fn``. A
        failed step re-executes. A step-level idempotency key replays
        across seq slots, but only for the same step name and inputs:
        a key hit on a different name/inputs is workflow definition
        drift and refuses ``workflow-step-unauthorized`` (F383), exactly
        as the seq-slot path does.
        """
        self._check_step_args(run_id, seq, name)
        run = self._get_run(run_id)
        if not _is_int(at) or at < 0:
            raise ValueError("at must be a non-negative int instant")
        if not callable(fn):
            raise ValueError("fn must be callable")
        inputs = {} if inputs is None else inputs
        # F380 closure: re-prove authority on EVERY entry, including the
        # completed-step replay paths below. A resume never trusts the
        # checkpoint's recorded authority.
        authority_digest = self._verify_authority(authority, run, at)
        inputs_digest = _digest(inputs)
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str) or not idempotency_key:
                raise ValueError("idempotency_key must be a non-empty string")
            hit = self._step_idem.get((run_id, idempotency_key))
            if hit is not None:
                rec = self._steps[hit]
                if rec["status"] == "completed":
                    if rec["name"] != name:
                        _fail(WF_UNAUTHORIZED,
                              "step under idempotency key %r already "
                              "completed as %r (workflow definition "
                              "drift)" % (idempotency_key, rec["name"]))
                    if rec["inputs_digest"] != inputs_digest:
                        _fail(WF_UNAUTHORIZED,
                              "step under idempotency key %r already "
                              "completed with different inputs "
                              "(workflow definition drift)"
                              % (idempotency_key,))
                    return rec["outputs"], True
        key = (run_id, seq)
        existing = self._steps.get(key)
        if existing is not None and existing["status"] == "completed":
            if existing["name"] != name:
                _fail(WF_UNAUTHORIZED,
                      "step slot %d already completed as %r "
                      "(workflow definition drift)" % (seq, existing["name"]))
            if existing["inputs_digest"] != inputs_digest:
                _fail(WF_UNAUTHORIZED,
                      "step slot %d already completed with different inputs "
                      "(workflow definition drift)" % (seq,))
            return existing["outputs"], True
        try:
            outputs = fn(inputs)
        except Exception:
            self._append({"type": "step", "schema": SCHEMA,
                          "run_id": run_id, "seq": seq, "name": name,
                          "idempotency_key": idempotency_key,
                          "inputs_digest": inputs_digest,
                          "outputs_digest": None, "outputs": None,
                          "status": "failed",
                          "authority_digest": authority_digest, "at": at})
            raise
        outputs_digest = _digest(outputs)  # refuses coded if unserializable
        self._append({"type": "step", "schema": SCHEMA, "run_id": run_id,
                      "seq": seq, "name": name,
                      "idempotency_key": idempotency_key,
                      "inputs_digest": inputs_digest,
                      "outputs_digest": outputs_digest, "outputs": outputs,
                      "status": "completed",
                      "authority_digest": authority_digest, "at": at})
        return outputs, False

    def replay(self, run_id, steps, *, authority, at):
        """Resume a run: replay completed steps, execute the rest.

        ``steps`` is a list of ``{"seq", "name", "fn", "inputs",
        "idempotency_key"}`` dicts. Returns a list of
        ``(seq, name, status, replayed, outputs)``. Stops after the first
        step that is not completed (failed steps re-execute; a raise
        propagates after checkpointing the failure).
        """
        run = self._get_run(run_id)
        results = []
        for spec in steps:
            seq = spec["seq"]
            name = spec["name"]
            out, replayed = self.run_step(
                run_id, seq, name, spec["fn"], spec.get("inputs"),
                idempotency_key=spec.get("idempotency_key"),
                authority=authority, at=at)
            results.append((seq, name, "completed", replayed, out))
        return results

    # -- durable sleep & notifications ------------------------------------

    def sleep_step(self, run_id, seq, name, wake_at, *, authority, at,
                   now=None):
        """Durable sleep: checkpoint the wake instant; resume completes it.

        Returns ``(awake, replayed)``. When ``now >= wake_at`` the step
        completes; otherwise it checkpoints as ``pending`` and a later
        call (the resume) completes it. No wall-clock sleeping happens
        inside the library -- ``now`` is an injected instant so the
        wake is deterministic and testable.
        """
        self._check_step_args(run_id, seq, name)
        run = self._get_run(run_id)
        if not _is_int(at) or at < 0:
            raise ValueError("at must be a non-negative int instant")
        if not _is_int(wake_at) or wake_at < 0:
            raise ValueError("wake_at must be a non-negative int instant")
        now = at if now is None else now
        if not _is_int(now) or now < 0:
            raise ValueError("now must be a non-negative int instant")
        # F380 closure (same defect class as run_step): re-prove
        # authority before trusting a completed checkpoint.
        authority_digest = self._verify_authority(authority, run, at)
        key = (run_id, seq)
        existing = self._steps.get(key)
        if existing is not None and existing["status"] == "completed":
            if existing["name"] != name:
                _fail(WF_UNAUTHORIZED,
                      "step slot %d already completed as %r "
                      "(workflow definition drift)" % (seq, existing["name"]))
            return True, True
        if now >= wake_at:
            self._append({"type": "step", "schema": SCHEMA,
                          "run_id": run_id, "seq": seq, "name": name,
                          "idempotency_key": None,
                          "inputs_digest": _digest({"wake_at": wake_at}),
                          "outputs_digest": _digest({"awake": True}),
                          "outputs": {"awake": True},
                          "status": "completed",
                          "authority_digest": authority_digest, "at": at})
            return True, False
        if existing is None or existing["status"] != "pending":
            self._append({"type": "step", "schema": SCHEMA,
                          "run_id": run_id, "seq": seq, "name": name,
                          "idempotency_key": None,
                          "inputs_digest": _digest({"wake_at": wake_at}),
                          "outputs_digest": None, "outputs": None,
                          "status": "pending",
                          "authority_digest": authority_digest, "at": at})
        return False, False

    def notify(self, run_id, event, payload, *, authority, at):
        """Record an external event arrival (durable notification)."""
        run = self._get_run(run_id)
        if not isinstance(event, str) or not event or len(event) > 128:
            raise ValueError("event must be a 1-128 char string")
        if not _is_int(at) or at < 0:
            raise ValueError("at must be a non-negative int instant")
        self._verify_authority(authority, run, at)
        payload_digest = _digest(payload)  # refuses coded if unserializable
        return dict(self._append(
            {"type": "notification", "schema": SCHEMA, "run_id": run_id,
             "event": event, "payload": payload,
             "payload_digest": payload_digest, "at": at}))

    def recv_step(self, run_id, seq, name, event, *, authority, at,
                  now=None, timeout_at=None):
        """Durable receive: consume the next ``event`` notification.

        Returns ``(payload, replayed)``. With no notification available
        the step checkpoints as ``pending`` and returns ``(None,
        False)``; a later call resumes it. If ``timeout_at`` is set and
        ``now >= timeout_at``, the step completes with
        ``{"timeout": True}``.
        """
        self._check_step_args(run_id, seq, name)
        run = self._get_run(run_id)
        if not isinstance(event, str) or not event:
            raise ValueError("event must be a non-empty string")
        if not _is_int(at) or at < 0:
            raise ValueError("at must be a non-negative int instant")
        now = at if now is None else now
        if timeout_at is not None \
                and (not _is_int(timeout_at) or timeout_at < 0):
            raise ValueError("timeout_at must be a non-negative int instant")
        # F380 closure (same defect class as run_step): re-prove
        # authority before trusting a completed checkpoint.
        authority_digest = self._verify_authority(authority, run, at)
        key = (run_id, seq)
        existing = self._steps.get(key)
        if existing is not None and existing["status"] == "completed":
            if existing["name"] != name:
                _fail(WF_UNAUTHORIZED,
                      "step slot %d already completed as %r "
                      "(workflow definition drift)" % (seq, existing["name"]))
            return existing["outputs"], True
        for note in self._notifications:
            if note["run_id"] == run_id and note["event"] == event \
                    and note["record_digest"] not in self._consumed:
                self._append({"type": "notification_consumed",
                              "schema": SCHEMA,
                              "notification_digest": note["record_digest"],
                              "consumed_by_seq": seq, "at": at})
                outputs = note["payload"]
                self._append({"type": "step", "schema": SCHEMA,
                              "run_id": run_id, "seq": seq, "name": name,
                              "idempotency_key": None,
                              "inputs_digest": _digest({"event": event}),
                              "outputs_digest": _digest(outputs),
                              "outputs": outputs, "status": "completed",
                              "authority_digest": authority_digest,
                              "at": at})
                return outputs, False
        if timeout_at is not None and now >= timeout_at:
            outputs = {"timeout": True}
            self._append({"type": "step", "schema": SCHEMA,
                          "run_id": run_id, "seq": seq, "name": name,
                          "idempotency_key": None,
                          "inputs_digest": _digest({"event": event}),
                          "outputs_digest": _digest(outputs),
                          "outputs": outputs, "status": "completed",
                          "authority_digest": authority_digest, "at": at})
            return outputs, False
        if existing is None or existing["status"] != "pending":
            self._append({"type": "step", "schema": SCHEMA,
                          "run_id": run_id, "seq": seq, "name": name,
                          "idempotency_key": None,
                          "inputs_digest": _digest({"event": event}),
                          "outputs_digest": None, "outputs": None,
                          "status": "pending",
                          "authority_digest": authority_digest, "at": at})
        return None, False

    # -- queries --------------------------------------------------------

    def run_status(self, run_id):
        self._get_run(run_id)
        return self._run_status[run_id]

    def get_run(self, run_id):
        return dict(self._get_run(run_id))

    def list_runs(self, status=None):
        runs = [dict(r) for r in self._runs.values()]
        if status is not None:
            runs = [r for r in runs
                    if self._run_status[r["run_id"]] == status]
        return sorted(runs, key=lambda r: r["run_id"])

    def get_step(self, run_id, seq):
        try:
            return dict(self._steps[(run_id, seq)])
        except KeyError:
            raise KeyError("no step %r in run %r" % (seq, run_id))

    def list_steps(self, run_id):
        self._get_run(run_id)
        recs = [dict(r) for (rid, _), r in self._steps.items()
                if rid == run_id]
        return sorted(recs, key=lambda r: r["seq"])
