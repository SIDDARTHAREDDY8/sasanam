#!/usr/bin/env python3
"""Atomic single-use reserve -> admit -> reconcile lifecycle.

Re-derived (nothing copied). ADAPTs the external atomic single-use
receipt-lifecycle pattern (reserve before dispatch, admit into the
execution path, reconcile the consumption into the receipt) to the
Sasanam registry family:

* ``LifecycleRegistry.reserve(approval_digest, step_id, input_digest)``
  atomically consumes the (approval digest, step id, input digest)
  triple BEFORE dispatch. A threading lock makes check-and-set one
  critical section: two concurrent reserves of the same triple let
  exactly one through; the loser refuses with the DISTINCT code
  ``single-use-reserve-conflict`` (never a generic error). A
  reservation for an approval digest this registry never saw refuses
  ``single-use-reservation-unknown`` fail-closed. Reserving an
  already-reserved (or already-reconciled) triple also refuses
  ``single-use-reserve-conflict``.
* ``LifecycleRegistry.admit(reservation, step_id, input_digest)``
  binds the reservation into the execution path: the presented
  step id / input digest must equal the reservation's, otherwise
  ``single-use-reservation-mismatch``. A forged or foreign
  reservation refuses ``single-use-reservation-unknown``; malformed
  inputs refuse ``single-use-malformed``. Admitting the same
  reservation twice with the same triple is idempotent.
* ``LifecycleRegistry.reconcile(admission, execution_receipt_digest)``
  emits the consumption record and marks the reservation consumed.
  A second reconcile of the same reservation refuses
  ``single-use-reconcile-replayed``.
* ``LifecycleRegistry.require_reserved(approval_digest, step_id,
  input_digest)`` is the execution-path gate: no live reservation
  for the triple refuses ``single-use-not-reserved``.
* ``LifecycleRegistry.verify_consumption_binding(execution_receipt,
  consumption_record)`` re-derives the consumption digest and checks
  it against the receipt's carried ``observation["consumption_digest"]``
  -- digest equality, never claim trust. Mismatch or a malformed
  receipt/record fails closed.

Action-capsule composition (additive, no changes to
``gov/action_capsule.py``): ``attach_consumption(capsule,
consumption_record)`` replays a sealed capsule and seals a NEW one
whose effect carries the RECOMPUTED consumption digest and the
reservation id -- the digest enters the new capsule's digest chain,
a real fold rather than a carried claim. ``verify_capsule_consumption``
re-derives the link.

Composition (additive, no changes to existing files):

* gov/single_use.py: the lifecycle consumes approvals at the
  triple level; single-use attestation evidence (the wave-226
  ``SingleUseRegistry``) remains the underlying receipt-evidence
  primitive. Deployments may run an attestation consume alongside
  ``reserve`` under the same caller; the lifecycle never replaces
  the attestation registry and needs no hook into it.
* gov/receipt_pairs.py: the caller folds the consumption record's
  digest into the execution receipt's ``observation`` under the
  ``consumption_digest`` key. ``classify`` ignores extra observation
  fields, so re-classification is unchanged; ``recompute_pair`` still
  verifies the carried bytes; and ``verify_consumption_binding``
  re-derives the binding.

The machine codes emitted here are mapped in gov/decision_codes.py
(``single-use-reserve-conflict``, ``single-use-not-reserved``,
``single-use-reservation-mismatch``, ``single-use-reservation-unknown``,
``single-use-reconcile-replayed``).

Honest residuals:

* Registries are in-memory; crash-safe persistence and shared atomic
  state across processes are deployment-owned. A restarted process
  forgets reservations, so deployments MUST persist reservation
  state before they are replay-safe across restarts.
* The registry trusts the approval digests registered with it; the
  lifecycle detects reuse/mismatch of what it was given, it does
  not prove the approval itself is authentic.
* The consumption digest binds the triple to the receipt digest; it
  does not prove the execution happened.

Stdlib only. No network. $0.
"""

import hashlib
import json
import threading
import time

try:
    from .action_capsule import seal_capsule, verify_capsule
except ImportError:  # pragma: no cover - standalone use
    seal_capsule = None
    verify_capsule = None

# ----------------------------------------------------------------------
# Error vocabulary (idiom 1: class-level machine code, audited by the
# wave-228 whole-tree refusal scanner).
# ----------------------------------------------------------------------


class LifecycleError(Exception):
    """Base class for single-use lifecycle refusals. ``code`` is
    machine-readable."""

    code = "single-use-lifecycle-refused"


class _ReserveConflict(LifecycleError):
    code = "single-use-reserve-conflict"


class _NotReserved(LifecycleError):
    code = "single-use-not-reserved"


class _ReservationMismatch(LifecycleError):
    code = "single-use-reservation-mismatch"


class _ReservationUnknown(LifecycleError):
    code = "single-use-reservation-unknown"


class _ReconcileReplayed(LifecycleError):
    code = "single-use-reconcile-replayed"


class _Malformed(LifecycleError):
    code = "single-use-malformed"


_LIFECYCLE_VERSION = 1
_HEX = frozenset("0123456789abcdef")


def _require_digest(value, field):
    if not isinstance(value, str) or len(value) != 64 \
            or set(value) - _HEX:
        raise _Malformed(
            "lifecycle field %r must be a 64-char lowercase hex digest, "
            "got %r" % (field, value))
    return value


def _require_step(value, field):
    if not isinstance(value, str) or not value:
        raise _Malformed(
            "lifecycle field %r must be a non-empty string, got %r"
            % (field, value))
    if len(value) > 256:
        raise _Malformed(
            "lifecycle field %r must be at most 256 chars" % field)
    return value


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _reservation_id(approval_digest, step_id, input_digest):
    return hashlib.sha256(
        ("single-use-reservation/v1:"
         + approval_digest + ":" + step_id + ":"
         + input_digest).encode("utf-8")).hexdigest()


class LifecycleRegistry:
    """Atomic reserve -> admit -> reconcile for single-use approvals.

    One instance owns one approval space: approval digests must be
    registered with ``register_approval`` before ``reserve`` accepts
    them. All state transitions happen under one lock, so concurrent
    reserves of the same triple are serialized: exactly one wins.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._approvals = set()
        self._reservations = {}   # (approval, step, input) -> record
        self._reconciled = set()  # reservation_ids already reconciled

    # -- configuration -------------------------------------------------

    def register_approval(self, approval_digest):
        """Record an issued approval digest as reservable."""
        _require_digest(approval_digest, "approval_digest")
        with self._lock:
            self._approvals.add(approval_digest)

    # -- the lifecycle -------------------------------------------------

    def reserve(self, approval_digest, step_id, input_digest):
        """Atomically consume (approval digest, step id, input digest)
        BEFORE dispatch. Returns the reservation record."""
        approval_digest = _require_digest(approval_digest,
                                          "approval_digest")
        step_id = _require_step(step_id, "step_id")
        input_digest = _require_digest(input_digest, "input_digest")
        triple = (approval_digest, step_id, input_digest)
        with self._lock:
            if approval_digest not in self._approvals:
                raise _ReservationUnknown(
                    "approval digest %s is not known to this registry"
                    % approval_digest[:16])
            if triple in self._reservations:
                raise _ReserveConflict(
                    "the (approval digest, step id, input digest) triple "
                    "is already reserved; a second consumer loses")
            record = {
                "v": _LIFECYCLE_VERSION,
                "kind": "single-use-reservation",
                "reservation_id": _reservation_id(
                    approval_digest, step_id, input_digest),
                "approval_digest": approval_digest,
                "step_id": step_id,
                "input_digest": input_digest,
                "status": "reserved",
                "reserved_at": time.time(),
            }
            self._reservations[triple] = record
            return dict(record)

    def admit(self, reservation, step_id, input_digest):
        """Bind a reservation into the execution path. The presented
        step id / input digest must equal the reservation's."""
        step_id = _require_step(step_id, "step_id")
        input_digest = _require_digest(input_digest, "input_digest")
        triple = self._checked_reservation(reservation)
        bound = self._reservations[triple]
        if step_id != bound["step_id"] \
                or input_digest != bound["input_digest"]:
            raise _ReservationMismatch(
                "admission presents step id %r / input digest %s, but the "
                "reservation binds step id %r / input digest %s"
                % (step_id, input_digest[:16], bound["step_id"],
                   bound["input_digest"][:16]))
        with self._lock:
            bound = self._reservations[triple]
            if bound["status"] == "reconciled":
                raise _ReconcileReplayed(
                    "the reservation was already reconciled; the "
                    "execution path is closed")
            bound["status"] = "admitted"
            admission = {
                "v": _LIFECYCLE_VERSION,
                "kind": "single-use-admission",
                "admission_id": hashlib.sha256(
                    ("single-use-admission/v1:"
                     + bound["reservation_id"]).encode(
                         "utf-8")).hexdigest(),
                "reservation_id": bound["reservation_id"],
                "approval_digest": bound["approval_digest"],
                "step_id": bound["step_id"],
                "input_digest": bound["input_digest"],
                "status": "admitted",
                "admitted_at": time.time(),
            }
            return admission

    def reconcile(self, admission, execution_receipt_digest):
        """Emit the consumption record binding the reservation to the
        execution receipt digest; marks the reservation consumed."""
        execution_receipt_digest = _require_digest(
            execution_receipt_digest, "execution_receipt_digest")
        if not isinstance(admission, dict):
            raise _Malformed("admission must be a dict, got %r"
                             % type(admission).__name__)
        reservation_id = _require_digest(
            admission.get("reservation_id"), "reservation_id")
        expected_admission = hashlib.sha256(
            ("single-use-admission/v1:"
             + reservation_id).encode("utf-8")).hexdigest()
        if admission.get("admission_id") != expected_admission:
            raise _ReservationUnknown(
                "the admission id does not recompute from its "
                "reservation id; forged or foreign admission")
        with self._lock:
            triple = self._triple_for(reservation_id)
            if triple is None:
                raise _ReservationUnknown(
                    "no reservation with id %s is known to this registry"
                    % reservation_id[:16])
            if reservation_id in self._reconciled:
                raise _ReconcileReplayed(
                    "the reservation was already reconciled")
            bound = self._reservations[triple]
            if bound["status"] != "admitted":
                raise _ReservationMismatch(
                    "reconcile requires an admitted reservation; status "
                    "is %r" % bound["status"])
            record = {
                "v": _LIFECYCLE_VERSION,
                "kind": "single-use-consumption",
                "reservation_id": reservation_id,
                "approval_digest": bound["approval_digest"],
                "step_id": bound["step_id"],
                "input_digest": bound["input_digest"],
                "execution_receipt_digest": execution_receipt_digest,
                "status": "reconciled",
                "reconciled_at": time.time(),
            }
            record["consumption_digest"] = self.consumption_digest(record)
            bound["status"] = "reconciled"
            self._reconciled.add(reservation_id)
            return record

    def require_reserved(self, approval_digest, step_id, input_digest):
        """Execution-path gate: refuse unless the triple has a live
        (reserved or admitted, not reconciled) reservation."""
        approval_digest = _require_digest(approval_digest,
                                          "approval_digest")
        step_id = _require_step(step_id, "step_id")
        input_digest = _require_digest(input_digest, "input_digest")
        triple = (approval_digest, step_id, input_digest)
        with self._lock:
            bound = self._reservations.get(triple)
            if bound is None or bound["status"] == "reconciled":
                raise _NotReserved(
                    "no live reservation for the (approval digest, step "
                    "id, input digest) triple")
            return bound["reservation_id"]

    # -- verification --------------------------------------------------

    @staticmethod
    def consumption_digest(consumption_record):
        """Re-derive the consumption digest (excludes the digest field
        itself). Pure function: third parties re-run this."""
        if not isinstance(consumption_record, dict):
            raise _Malformed("consumption record must be a dict")
        body = {k: v for k, v in consumption_record.items()
                if k != "consumption_digest"}
        if body.get("kind") != "single-use-consumption":
            raise _Malformed(
                "not a single-use-consumption record, got kind %r"
                % (body.get("kind"),))
        return hashlib.sha256(
            ("single-use-consumption/v1:"
             + _canonical_bytes(body).decode("utf-8")).encode(
                 "utf-8")).hexdigest()

    def verify_consumption_binding(self, execution_receipt,
                                   consumption_record):
        """Check the execution receipt's carried
        ``observation["consumption_digest"]`` equals the re-derived
        consumption digest. Digest equality, never claim trust."""
        if not isinstance(execution_receipt, dict):
            raise _Malformed("execution receipt must be a dict")
        observation = execution_receipt.get("observation")
        if not isinstance(observation, dict):
            raise _Malformed("execution receipt carries no observation")
        carried = observation.get("consumption_digest")
        _require_digest(carried, "consumption_digest")
        recomputed = self.consumption_digest(consumption_record)
        if carried != recomputed:
            raise _ReservationMismatch(
                "execution receipt binds consumption digest %s but the "
                "consumption record re-derives to %s"
                % (carried[:16], recomputed[:16]))
        return True

    # -- internals -----------------------------------------------------

    def _checked_reservation(self, reservation):
        """Validate a presented reservation; return its triple key."""
        if not isinstance(reservation, dict):
            raise _Malformed("reservation must be a dict, got %r"
                             % type(reservation).__name__)
        reservation_id = _require_digest(
            reservation.get("reservation_id"), "reservation_id")
        approval_digest = reservation.get("approval_digest")
        step_id = reservation.get("step_id")
        input_digest = reservation.get("input_digest")
        for value, field in ((approval_digest, "approval_digest"),
                             (input_digest, "input_digest")):
            _require_digest(value, field)
        _require_step(step_id, "step_id")
        expected = _reservation_id(approval_digest, step_id, input_digest)
        if reservation_id != expected:
            raise _ReservationUnknown(
                "the reservation id does not recompute from its fields; "
                "forged or foreign reservation")
        triple = (approval_digest, step_id, input_digest)
        with self._lock:
            if triple not in self._reservations:
                raise _ReservationUnknown(
                    "the reservation is not known to this registry")
            return triple

    def _triple_for(self, reservation_id):
        """Find the triple key for a reservation id (lock held by
        caller)."""
        for triple, record in self._reservations.items():
            if record["reservation_id"] == reservation_id:
                return triple
        return None


# ----------------------------------------------------------------------
# Action-capsule composition (additive; gov/action_capsule.py untouched).
# Mirrors the decision-code capsule-linkage pattern: the consumption
# digest enters a NEW capsule's digest chain, so "folds into the
# execution receipt digest chain" is a real link, not a carried claim.
# ----------------------------------------------------------------------


def attach_consumption(capsule, consumption_record):
    """Attach a consumption record to a sealed action capsule as
    digest-linked evidence.

    Replays the capsule (tampering refuses at replay) and recomputes
    the consumption digest (never asserted), then seals a NEW capsule
    whose effect carries ``consumption_digest`` and ``reservation_id``.
    The digest is part of the new capsule's sealed bytes, so it enters
    that capsule's digest chain.
    """
    if seal_capsule is None or verify_capsule is None:
        raise _Malformed(
            "consumption composition needs gov.action_capsule")
    recomputed = LifecycleRegistry.consumption_digest(
        consumption_record)  # strict; tampering refuses here
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    new_effect = dict(body["effect"])
    new_effect["consumption_digest"] = recomputed
    new_effect["reservation_id"] = consumption_record["reservation_id"]
    return seal_capsule({"attempt": dict(body["attempt"]),
                         "effect": new_effect})


def verify_capsule_consumption(capsule, consumption_record):
    """Verify the digest link between a capsule and a consumption
    record. Replays the capsule, recomputes the consumption digest,
    and checks the effect's ``consumption_digest`` against it.
    Returns the linked digest. Mismatch refuses
    ``single-use-reservation-mismatch``; a capsule with no
    consumption link refuses ``single-use-malformed``.
    """
    if verify_capsule is None:
        raise _Malformed(
            "consumption composition needs gov.action_capsule")
    recomputed = LifecycleRegistry.consumption_digest(
        consumption_record)  # strict; tampering refuses here
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    effect = body.get("effect")
    if not isinstance(effect, dict):
        raise _Malformed("capsule carries no effect")
    carried = effect.get("consumption_digest")
    if carried is None:
        raise _Malformed("capsule carries no consumption link")
    if carried != recomputed:
        raise _ReservationMismatch(
            "capsule binds consumption digest %s but the consumption "
            "record re-derives to %s"
            % (carried[:16], recomputed[:16]))
    return recomputed
