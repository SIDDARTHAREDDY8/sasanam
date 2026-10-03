"""Idempotency-key discipline for agent operations.

Wave-301 lane 6. Stdlib only. Additive: standalone module, no changes to
existing APIs.

ADAPT from celery + airflow (wave-300 prospectus): at-least-once delivery
with an explicit idempotency contract, acks_late redelivery discipline,
and idempotency as an authoring rule.

Contract
--------
Every mutating operation carries an idempotency key scoped to
``(namespace, op_class, key)``:

* SAME key + SAME operation digest -> the recorded result is returned
  without re-executing (replay).
* SAME key + DIFFERENT operation digest -> refused coded
  ``permit-idempotency-conflict`` (key reuse across different operations
  is a confusion attack, never a retry).
* A key completed under one (namespace, op_class) is invisible to every
  other (namespace, op_class): isolation by composite index, so a key
  cannot be replayed across namespaces or operation classes to steal a
  recorded result or skip execution.

acks_late discipline: an operation is marked complete only AFTER its
effects are durably recorded. A crash before the mark leaves an
IN_FLIGHT record; the retry re-executes (safe retry, never silent loss,
never a phantom third execution).

Caller binding (wave-303, F381 closure): ``begin()`` records the
beginning caller in the returned ``BeginOutcome``. ``complete()`` and
``checkpoint()`` consult the binding and refuse coded
``workflow-idempotency-caller-mismatch`` when the outcome's caller is
not the record's beginning caller -- a different authorized caller
cannot complete or checkpoint another actor's in-flight operation
(result poisoning defeated). The binding is read from the live backing
record at call time, so an evicted record also fails closed.

Design rule: "A workflow outlives its runner -- every step is
checkpointed, and every resume re-proves its authority." ``begin()``
re-verifies the caller's authority on EVERY path (new, replay, retry)
through a deployment-supplied ``authority_verifier``; a retry whose
authority has lapsed is refused coded
``workflow-idempotency-authority-lapsed`` instead of replaying. A
verifier that raises fails closed.

Completed set: bounded (``max_completed``). Overflow evicts the oldest
completed record with a sink audit record (never silent); operators may
also evict explicitly via ``evict_completed`` (loud: returns an eviction
record AND emits a sink record -- the deployment chains it).
``evict_completed`` requires the operator's authority to be re-verified
through the deployment-supplied ``authority_verifier`` (the operator is
the caller; a refusing or raising verifier fails closed coded
``workflow-idempotency-authority-lapsed``): unauthenticated eviction is
refused, not just unnamed.

Progress checkpointing (airflow task-state-store discipline): an
in-flight record accepts ``checkpoint(note)`` progress notes so a retry
can resume rather than restart blind.

The store is in-memory over a deployment-owned ``backing`` dict: two
``IdempotencyStore`` instances sharing one backing dict simulate
crash+restart deterministically. Records are plain JSON-able dicts.

Keying-material grammar (fail-closed narrowing):
namespace/op_class ``^[a-z][a-z0-9-]{0,63}$``; key
``^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$``; digests 64 lowercase hex;
result_ref an opaque pointer (<=512 chars, no NUL) -- pointers, not
payloads (airflow XCom discipline). Violations refuse coded
``workflow-idempotency-key-invalid``.

Threat model: the authority_verifier is the trust anchor
(compromised-host class); ``at`` instants are caller-supplied freshness
markers (deployment-owned clock); sink delivery is best-effort and never
breaks the call path; an attacker that floods new keys can force
capacity eviction of completed records -- at-least-once makes the
resulting re-execution safe, not a vulnerability. Caller binding is
same-scope authorization: a caller authorized for the (namespace,
op_class) scope may still not complete, checkpoint, or evict another
caller's records -- authority re-verification gates entry (begin/evict),
the caller binding gates the in-flight mutation (complete/checkpoint).
"""

import re

# -- coded surface -------------------------------------------------------
# permit-idempotency-conflict: reused (existing, high).
CODE_CONFLICT = "permit-idempotency-conflict"
CODE_KEY_INVALID = "workflow-idempotency-key-invalid"
CODE_AUTHORITY_LAPSED = "workflow-idempotency-authority-lapsed"
CODE_CALLER_MISMATCH = "workflow-idempotency-caller-mismatch"

STATUS_NEW = "new"
STATUS_REPLAY = "replay"
STATUS_RETRY = "retry"

_REC_PREFIX = "rec\x00"
_ORDER_KEY = "\x00completed_order"

_NS_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class IdempotencyError(Exception):
    """Base; every subclass carries the refusal ``code``."""

    code = None

    def __init__(self, message, **evidence):
        super().__init__(message)
        self.evidence = evidence


class IdempotencyConflict(IdempotencyError):
    """Same key re-presented with a different operation digest."""

    code = CODE_CONFLICT


class IdempotencyKeyInvalid(IdempotencyError):
    """Keying material failed grammar."""

    code = CODE_KEY_INVALID


class IdempotencyAuthorityLapsed(IdempotencyError):
    """Authority re-verification failed at begin/retry/evict time."""

    code = CODE_AUTHORITY_LAPSED


class IdempotencyCallerMismatch(IdempotencyError):
    """The outcome's caller is not the in-flight record's beginning caller."""

    code = CODE_CALLER_MISMATCH


def _check(cond, exc):
    if not cond:
        raise exc


def _is_hex64(value):
    return isinstance(value, str) and _HEX64_RE.match(value) is not None


def _check_shape(namespace, op_class, key, op_digest, caller):
    _check(isinstance(namespace, str) and _NS_RE.match(namespace),
           IdempotencyKeyInvalid("namespace fails grammar",
                                field="namespace"))
    _check(isinstance(op_class, str) and _NS_RE.match(op_class),
           IdempotencyKeyInvalid("op_class fails grammar",
                                field="op_class"))
    _check(isinstance(key, str) and _KEY_RE.match(key),
           IdempotencyKeyInvalid("key fails grammar", field="key"))
    _check(_is_hex64(op_digest),
           IdempotencyKeyInvalid("op_digest must be 64 lowercase hex",
                                field="op_digest"))
    _check(isinstance(caller, str) and 1 <= len(caller) <= 256
           and "\x00" not in caller,
           IdempotencyKeyInvalid("caller fails grammar", field="caller"))


def _check_result_shape(result_digest, result_ref):
    _check(_is_hex64(result_digest),
           IdempotencyKeyInvalid("result_digest must be 64 lowercase hex",
                                field="result_digest"))
    _check(isinstance(result_ref, str) and 1 <= len(result_ref) <= 512
           and "\x00" not in result_ref,
           IdempotencyKeyInvalid("result_ref fails grammar",
                                field="result_ref"))


class BeginOutcome:
    """Result of ``IdempotencyStore.begin``.

    status "new"/"retry": execute the effect, then ``complete()``.
    status "replay": do NOT execute; use ``result_digest``/``result_ref``.

    The outcome is bound to the caller ``begin()`` was called with.
    ``complete()`` and ``checkpoint()`` refuse coded
    ``workflow-idempotency-caller-mismatch`` when the outcome's caller
    is not the in-flight record's beginning caller: whoever began the
    effects completes them; a different authorized caller cannot
    complete or checkpoint another actor's in-flight record.
    """

    def __init__(self, store, record_key, status, record, caller):
        self._store = store
        self._record_key = record_key
        self.status = status
        self._caller = caller
        self._record_caller = record.get("caller")
        self.result_digest = record.get("result_digest")
        self.result_ref = record.get("result_ref")
        self.notes = list(record.get("notes", []))

    def _check_caller_binding(self, action):
        """Fail closed unless this outcome's caller began the record.

        The binding is re-read from the live backing record (not the
        begin-time snapshot): a record evicted between begin() and
        complete()/checkpoint() also refuses.
        """
        record = self._store._backing.get(self._record_key)
        recorded = record.get("caller") if isinstance(record, dict) else None
        _check(recorded is not None and self._caller == recorded,
               IdempotencyCallerMismatch(
                   "%s refused: outcome issued to caller %r, but the "
                   "in-flight record was begun by %r"
                   % (action, self._caller, recorded),
                   action=action, outcome_caller=self._caller,
                   record_caller=recorded))

    def complete(self, result_digest, result_ref, at=None):
        """Mark the operation complete AFTER effects are durably recorded.

        Refuses coded ``workflow-idempotency-caller-mismatch`` when the
        outcome's caller is not the record's beginning caller.

        Returns an eviction record dict if a capacity eviction fired,
        else None.
        """
        self._check_caller_binding("complete")
        _check(self.status in (STATUS_NEW, STATUS_RETRY),
               ValueError("complete() only valid on new/retry outcomes"))
        _check_result_shape(result_digest, result_ref)
        return self._store._complete(self._record_key, result_digest,
                                    result_ref, at)

    def checkpoint(self, note, at=None):
        """Record a progress note on the in-flight record.

        Refuses coded ``workflow-idempotency-caller-mismatch`` when the
        outcome's caller is not the record's beginning caller.
        """
        self._check_caller_binding("checkpoint")
        _check(self.status in (STATUS_NEW, STATUS_RETRY),
               ValueError("checkpoint() only valid on new/retry outcomes"))
        _check(isinstance(note, str) and 1 <= len(note) <= 512
               and "\x00" not in note,
               IdempotencyKeyInvalid("note fails grammar", field="note"))
        self._store._checkpoint(self._record_key, note, at)
        self.notes.append(note)


class IdempotencyStore:
    """Idempotency-key registry with acks_late completion semantics."""

    def __init__(self, backing=None, max_completed=10000, sink=None):
        _check(isinstance(max_completed, int) and max_completed >= 1,
               ValueError("max_completed must be a positive int"))
        self._backing = backing if backing is not None else {}
        self._max_completed = max_completed
        self._sink = sink
        if _ORDER_KEY not in self._backing:
            self._backing[_ORDER_KEY] = []

    # -- internal ------------------------------------------------------

    def _emit(self, record):
        if self._sink is None:
            return
        try:
            self._sink(dict(record))
        except Exception:
            pass  # sink delivery is best-effort; never breaks the path

    @staticmethod
    def _record_key(namespace, op_class, key):
        return _REC_PREFIX + namespace + "\x00" + op_class + "\x00" + key

    def _order(self):
        order = self._backing.get(_ORDER_KEY)
        if not isinstance(order, list):
            order = []
            self._backing[_ORDER_KEY] = order
        return order

    def _verify_authority(self, verifier, caller, namespace, op_class, at,
                          stage="begin"):
        _check(callable(verifier),
               ValueError("authority_verifier must be callable"))
        try:
            ok = verifier(caller=caller, namespace=namespace,
                          op_class=op_class, at=at)
        except Exception:
            ok = False  # verifier failure fails closed
        _check(ok is True,
               IdempotencyAuthorityLapsed(
                   "caller authority lapsed or unverifiable at %s"
                   % (stage,),
                   caller=caller, namespace=namespace, op_class=op_class,
                   stage=stage))

    # -- public ----------------------------------------------------------

    def begin(self, namespace, op_class, key, op_digest, caller,
              authority_verifier, at=None):
        """Open an idempotent operation.

        Returns a BeginOutcome. Refuses coded on keying-material grammar
        (workflow-idempotency-key-invalid), lapsed authority
        (workflow-idempotency-authority-lapsed), or digest confusion
        (permit-idempotency-conflict).
        """
        _check_shape(namespace, op_class, key, op_digest, caller)
        # Every path re-proves authority -- including first execution.
        self._verify_authority(authority_verifier, caller, namespace,
                               op_class, at)
        rkey = self._record_key(namespace, op_class, key)
        record = self._backing.get(rkey)
        if record is None:
            record = {"namespace": namespace, "op_class": op_class,
                      "key": key, "op_digest": op_digest, "caller": caller,
                      "state": "in_flight", "notes": [],
                      "result_digest": None, "result_ref": None,
                      "began_at": at}
            self._backing[rkey] = record
            self._emit({"event": "begin-new", "namespace": namespace,
                        "op_class": op_class, "key": key, "caller": caller,
                        "at": at})
            return BeginOutcome(self, rkey, STATUS_NEW, record, caller)
        _check(record.get("op_digest") == op_digest,
               IdempotencyConflict(
                   "same key re-presented with a different operation "
                   "digest; refused, never a second release",
                   key=key, namespace=namespace, op_class=op_class))
        if record.get("state") == "completed":
            self._emit({"event": "begin-replay", "namespace": namespace,
                        "op_class": op_class, "key": key, "caller": caller,
                        "at": at})
            return BeginOutcome(self, rkey, STATUS_REPLAY, record, caller)
        self._emit({"event": "begin-retry", "namespace": namespace,
                    "op_class": op_class, "key": key, "caller": caller,
                    "at": at})
        return BeginOutcome(self, rkey, STATUS_RETRY, record, caller)

    def _complete(self, rkey, result_digest, result_ref, at):
        record = self._backing.get(rkey)
        _check(record is not None and record.get("state") == "in_flight",
               ValueError("complete() on a record that is not in-flight"))
        record["state"] = "completed"
        record["result_digest"] = result_digest
        record["result_ref"] = result_ref
        record["completed_at"] = at
        order = self._order()
        order.append(rkey)
        self._emit({"event": "complete",
                    "namespace": record["namespace"],
                    "op_class": record["op_class"], "key": record["key"],
                    "result_digest": result_digest, "at": at})
        evicted = None
        while len(order) > self._max_completed:
            oldest = order.pop(0)
            old = self._backing.pop(oldest, None)
            if old is None:
                continue
            evicted = {"evicted_key": old["key"],
                       "namespace": old["namespace"],
                       "op_class": old["op_class"],
                       "reason": "capacity", "at": at}
            self._emit({"event": "evict-auto", **evicted})
        return evicted

    def _checkpoint(self, rkey, note, at):
        record = self._backing.get(rkey)
        _check(record is not None and record.get("state") == "in_flight",
               ValueError("checkpoint() on a record that is not in-flight"))
        record.setdefault("notes", []).append(note)
        self._emit({"event": "checkpoint",
                    "namespace": record["namespace"],
                    "op_class": record["op_class"], "key": record["key"],
                    "note": note, "at": at})

    def evict_completed(self, namespace, op_class, key, operator,
                        authority_verifier, at=None):
        """Operator-initiated eviction of a completed record.

        Loud: returns the eviction record AND emits a sink record.
        The operator's authority is re-verified through the
        deployment-supplied ``authority_verifier`` (the operator is the
        caller): a refusing or raising verifier fails closed coded
        ``workflow-idempotency-authority-lapsed``; a missing or
        non-callable verifier is a programming error (ValueError).
        Unauthenticated eviction is refused, not just unnamed.
        Raises KeyError when the record is absent or not completed.
        """
        _check(isinstance(operator, str) and 1 <= len(operator) <= 256
               and "\x00" not in operator,
               IdempotencyKeyInvalid("operator fails grammar",
                                    field="operator"))
        # Authority required: same trust anchor as begin(). The operator
        # name is the caller identity presented to the verifier.
        self._verify_authority(authority_verifier, operator, namespace,
                               op_class, at, stage="evict")
        rkey = self._record_key(namespace, op_class, key)
        record = self._backing.get(rkey)
        if record is None or record.get("state") != "completed":
            raise KeyError("no completed record for key %r" % (key,))
        del self._backing[rkey]
        order = self._order()
        if rkey in order:
            order.remove(rkey)
        evicted = {"evicted_key": key, "namespace": namespace,
                   "op_class": op_class, "operator": operator,
                   "reason": "operator", "at": at}
        self._emit({"event": "evict-operator", **evicted})
        return evicted
