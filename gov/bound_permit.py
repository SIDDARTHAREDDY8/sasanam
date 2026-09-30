#!/usr/bin/env python3
"""Bound-permit conjunction + saha follow-through verification order.

The conjunction (wave-235): a permit is issued only when three legs
verify independently -- the decision record, the mandate record, and
the local policy binding. Each leg can refuse; none overrules another:
a refusal in any leg refuses the permit carrying the leg's EXACT
refusal code. A permit issued without a mandate refuses
``permit-mandate-absent``; without a policy binding
``permit-policy-absent``; without a decision ``permit-decision-absent``.

The permit is frozen at issue time: the permit's (iss, jti) and the
three leg records are digested into an ``instance_digest`` -- each
permit its own consumable instance.

The follow-through (wave-240, re-derived -- nothing copied -- from
draft-saha-aadp-bound-permit-00, IETF Trust prose re-derive): the
recipient verifies a presented permit in a fixed 13-step order.
Cheap structural checks come BEFORE crypto, crypto BEFORE state, and
state is consumed LAST, so a request refused for any other reason
does not consume its permit. The order adapts saha S8.1 Table 3 to
this module's checks (our permit is a record, not a JWT; the
mandate/currentness/signature steps the draft names are caller-held
here -- legs verify at issue, the recipient re-checks the frozen
conjunction via digests):

 1. permit present and parses (absence is ``permit-no-fallback``:
    absence is malformed -- never a reason to accept another
    credential, saha S8.2)
 2. required fields present (``permit-malformed``)
 3. version supported (``permit-malformed``)
 4. iss/jti non-empty strings (``permit-malformed``)
 5. digest formats and record shapes (``permit-malformed``)
 6. instance digest recomputes -- crypto (``permit-tampered``)
 7. permit digest recomputes -- crypto (``permit-tampered``)
 8. reconciliation binding for re-issued permits
    (``permit-malformed``; ``could-not-check`` naming the
    permit-registry when no registry is available to check it)
 9. consume store available (``permit-consume-store-unavailable``:
    could-not-check naming the consume-store dependency, 503-style)
 10. admission gate: the store is durable/atomic/shared, or the
    deployment explicitly opts into single-node
    (``permit-consume-store-not-durable``)
 11. recipient-local policy permits -- BEFORE state, so a denial
    never consumes the permit (a leg-style verifier; the permit is
    not consumed on denial)
 12. (iss, jti) prior-consumption lookup: same content digest ->
    ``replayed``; different content digest ->
    ``permit-idempotency-conflict`` (409-style), never a second
    execution
 13. atomically consume (iss, jti) -- state consumed LAST.

``verify_presentation`` runs the order and returns the verification
record -- ``verified`` / ``refused`` (+reason+step) /
``could-not-check`` (+dependency) / ``replayed`` -- never partial
(saha S8.3). Refusal reasons carry the saha S9 advisory HTTP mapping
(403; 409 for idempotency-conflict; 503 for could-not-check).

Repeat semantics (saha S12): same (iss, jti) + same content digest
after completion returns the STORED result and records the
presentation as a repeat -- no fresh execution. A different content
digest under the same (iss, jti) refuses
``permit-idempotency-conflict``.

Admission gate (saha S12): a recipient that cannot keep a durable,
atomic, shared-across-every-node consume store MUST NOT accept bound
permits. ``verify_presentation`` / ``consume_permit`` /
``execute_permit`` refuse ``permit-consume-store-not-durable`` unless
the deployment passes ``require_durable_store=False`` -- the
explicit single-node deployment contract. The default in-memory
store (``InMemoryConsumeStore``) is single-node only: shared
atomicity and durability beyond one process are deployment-owned.

Budget accounting (saha S13, outcome-tied): ``BudgetLedger`` commits
the reservation on success AND on timeout (unknown outcome);
releases on ``not_attempted`` and on signed failure with
``no_effect: true``. An UNSIGNED refusal does NOT establish no
effect -- the presenter MUST NOT set ``no_effect`` on its strength:
unsigned claims refuse ``permit-no-effect-unattested`` and the
budget stays committed. Rate budgets are never released
(``permit-rate-budget-unreleasable``).

Reconciliation (saha S12): ``reconcile_unknown_outcome`` never mints
a permit and never retries execution. An unknown-outcome presenter
reconciles by ``jti`` (or the recipient action id it recorded),
never by obtaining a new permit.

Leg verifiers are caller-supplied callables ``verifier(record)``: a
verifier accepts by returning (the return value is ignored); it
refuses by raising. A raised refusal carrying a string ``code``
attribute propagates with that exact code; a refusal naming no code
refuses ``permit-leg-refusal-unmapped`` (fail closed: an unnamed
refusal is unauditable). The original exception is chained onto the
refusal, so a verifier that crashes on a programming error stays
visible in the traceback instead of being masked by the refusal.

Honest residuals: legs, verifiers, execution evidence, refusal
signatures, and the registry are caller-supplied; the module pins
digests of what it commits to, it does not establish the caller's
claims. The ledger detects edits to presented digests, not lies told
consistently from the start (the frozen legs are caller-supplied).
The in-memory consume store and budget ledger are single-node:
shared atomicity, durability, and cross-node budget coherence are
deployment-owned; durable store implementations MUST persist
(iss, jti) -> (content digest, stored result) or replays cannot
return stored results after a restart. In-progress (async)
presentations are modeled at the claim layer: a second presentation
of a claimed-but-uncompleted (iss, jti) raises
``permit-in-progress`` and verifies as ``retryable`` (503-style) --
the permit is not consumed and no result exists yet, so the caller
retries the presentation later. Once the first holder records its
result, the same presentation replays the stored result. The recipient-signed
confirmation (saha S10) has no wire form in this module. A
``no_effect`` signature proves the refuser signed the claim, not
that the claim is true.

Stdlib only. No network. $0.
"""

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

from gov import consumption_ledger as _consumption_ledger

# ----------------------------------------------------------------------
# Error vocabulary. The base class carries no string ``code`` (deliberate:
# the w228 refusal-vocabulary scanner must see only real product codes).
# ``_PermitLegRefused`` carries the REFUSING LEG'S code as an instance
# attribute (never a permit-namespaced literal): the permit refuses with
# the leg's exact refusal code, so no new literal exists to inventory.
# ----------------------------------------------------------------------


class BoundPermitError(Exception):
    """Base class for all bound-permit refusals. Subclasses set the
    machine-readable ``code``."""

    code = None


class _PermitDecisionAbsent(BoundPermitError):
    code = "permit-decision-absent"


class _PermitMandateAbsent(BoundPermitError):
    code = "permit-mandate-absent"


class _PermitPolicyAbsent(BoundPermitError):
    code = "permit-policy-absent"


class _PermitJtiDuplicate(BoundPermitError):
    code = "permit-jti-duplicate"


class _PermitLegRefusalUnmapped(BoundPermitError):
    code = "permit-leg-refusal-unmapped"


class _PermitMalformed(BoundPermitError):
    code = "permit-malformed"


class _PermitTampered(BoundPermitError):
    code = "permit-tampered"


class _PermitIdempotencyConflict(BoundPermitError):
    code = "permit-idempotency-conflict"


class _PermitInProgress(BoundPermitError):
    code = "permit-in-progress"

    def __init__(self, message, verification_record=None):
        super().__init__(message)
        self.verification_record = verification_record


class _PermitConsumeStoreUnavailable(BoundPermitError):
    code = "permit-consume-store-unavailable"

    def __init__(self, message, verification_record=None):
        super().__init__(message)
        self.verification_record = verification_record


class _PermitConsumeStoreNotDurable(BoundPermitError):
    code = "permit-consume-store-not-durable"


class _PermitRegistryUnavailable(BoundPermitError):
    code = "permit-registry-unavailable"

    def __init__(self, message, verification_record=None):
        super().__init__(message)
        self.verification_record = verification_record


class _PermitNoFallback(BoundPermitError):
    code = "permit-no-fallback"


class _PermitNoEffectUnattested(BoundPermitError):
    code = "permit-no-effect-unattested"


class _PermitRateBudgetUnreleasable(BoundPermitError):
    code = "permit-rate-budget-unreleasable"


class _PermitLegRefused(BoundPermitError):
    """A leg refused: carries the leg's exact refusal code (instance
    attribute, not a new literal) and names the refusing leg so no leg
    can silently overrule another."""

    def __init__(self, leg, code, message):
        super().__init__(message)
        self.leg = leg
        self.code = code


# ----------------------------------------------------------------------
# Internals.
# ----------------------------------------------------------------------

_PERMIT_DOMAIN = b"sasanam-bound-permit-v1:"
_PERMIT_VERSION = 1
_RECONCILIATION_VERSION = 1
_HEX64 = "0123456789abcdef"
_PERMIT_FIELDS = ("version", "iss", "jti", "issued_at", "decision_digest",
                  "mandate_digest", "policy_digest", "instance_digest",
                  "reconciliation_digest", "legs_verified")
_RECONCILIATION_FIELDS = ("version", "iss", "jti", "instance_digest",
                          "state", "reconciled_at", "evidence_digest",
                          "detail")
_RECONCILIATION_STATES = ("completed", "unknown", "not-executed")
_LEGS = ("decision", "mandate", "policy")


def _is_bare_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in _HEX64 for c in value)


def _canonical_dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _iso(now):
    return datetime.fromtimestamp(now, tz=timezone.utc).isoformat()


def _leg_digest(record):
    try:
        raw = _canonical_dumps(record).encode("utf-8")
    except (TypeError, ValueError):
        raise _PermitMalformed(
            "permit-malformed: leg record is not JSON-serializable")
    return hashlib.sha256(raw).hexdigest()


def _instance_digest(iss, jti, decision_digest, mandate_digest,
                     policy_digest, reconciliation_digest):
    """Freeze the conjunction: the permit's (iss, jti) AND the three leg
    digests bind into the instance digest. Consumption is atomic in
    (iss, jti): each permit is its own consumable instance. The trust
    tier (or any leg field) also binds in, so two permits differing
    only in trust tier are distinct instances and are never matched as
    one."""
    h = hashlib.sha256(_PERMIT_DOMAIN)
    for part in (iss, jti, decision_digest, mandate_digest,
                 policy_digest, reconciliation_digest or ""):
        raw = part.encode("utf-8")
        h.update(str(len(raw)).encode("ascii"))
        h.update(b"\x00")
        h.update(raw)
        h.update(b"\x00")
    return h.hexdigest()


def _body_digest(body):
    return hashlib.sha256(
        _canonical_dumps(body).encode("utf-8")).hexdigest()


def _verify_leg(leg, record, verifier):
    """Run one leg's verifier. Acceptance is silent; refusal
    propagates with the leg's exact code. The original exception is
    chained (``raise ... from exc``): a verifier that crashes on a
    programming error is still a refusal for the permit, but the bug
    stays visible in the traceback instead of being masked."""
    try:
        verifier(record)
    except Exception as exc:  # noqa: BLE001 - refusal, recorded not masked
        code = getattr(exc, "code", None)
        if isinstance(code, str) and code:
            raise _PermitLegRefused(
                leg, code,
                "%s leg refused with %r: the permit refuses with the "
                "leg's exact refusal code" % (leg, code)) from exc
        raise _PermitLegRefusalUnmapped(
            "permit-leg-refusal-unmapped: %s leg verifier refused "
            "without naming a machine code; unnamed refusals are "
            "unauditable and cannot issue" % (leg,)) from exc


# ----------------------------------------------------------------------
# Registry: (iss, jti) claim slots. In-memory; deployment-owned beyond.
# ----------------------------------------------------------------------


class PermitRegistry:
    """Claim registry for (iss, jti) permit slots.

    The first issue claims the slot. Re-issue is refused with
    ``permit-jti-duplicate`` until a reconciliation record is registered;
    the reconciliation survives re-issue so the settled outcome stays
    attached to the slot.
    """

    def __init__(self):
        self._entries = {}  # (iss, jti) -> {"permit":..., "reconciliation":...}

    def lookup(self, iss, jti):
        """The slot for (iss, jti), or None. Copies: the registry owns
        its entries."""
        entry = self._entries.get((iss, jti))
        if entry is None:
            return None
        return {
            "permit": dict(entry["permit"])
            if entry["permit"] is not None else None,
            "reconciliation": dict(entry["reconciliation"])
            if entry["reconciliation"] is not None else None,
        }

    def record_permit(self, permit):
        key = (permit["iss"], permit["jti"])
        prev = self._entries.get(key, {})
        self._entries[key] = {
            "permit": dict(permit),
            "reconciliation": prev.get("reconciliation"),
        }

    def record_reconciliation(self, record):
        key = (record["iss"], record["jti"])
        entry = self._entries.setdefault(
            key, {"permit": None, "reconciliation": None})
        entry["reconciliation"] = dict(record)


# ----------------------------------------------------------------------
# Consume store: recipient-side (iss, jti) consumption state (saha S12).
# ----------------------------------------------------------------------


class ConsumeStore:
    """Recipient-side (iss, jti) consume state.

    The atomic claim primitive is ``claim(permit)``: it returns
    ``("claimed", slot)`` on first presentation, ``("replayed", slot)``
    when the same (iss, jti) presents the same content digest again,
    raises ``_PermitIdempotencyConflict`` when the slot is already
    bound to a DIFFERENT content digest, and raises
    ``_PermitConsumeStoreUnavailable`` when the store is down.

    A slot records the content digest, the consumption receipt, and
    the stored execution result (``record_result``): a replay returns
    the stored result, never a fresh execution.

    ``durable`` is True only when the store is durable, atomic, and
    shared across every node that can serve the endpoint. The
    in-memory implementation below is single-node: the admission gate
    (``require_durable_store=True``) refuses it.
    """

    def __init__(self, ledger, *, durable=False, available=True):
        self._ledger = ledger
        self.durable = bool(durable)
        self._available = bool(available)
        # (iss, jti, reconciliation_digest) -> slot. The
        # reconciliation digest is part of the key: a re-issued permit
        # (after a not-executed reconciliation) is a DISTINCT
        # consumable instance and can never re-release the reconciled
        # one.
        self._slots = {}

    def is_available(self):
        """False simulates a store outage -> could-not-check."""
        return self._available

    def set_available(self, available):
        """Ops/test hook: simulate a store outage or recovery."""
        self._available = bool(available)

    @staticmethod
    def _slot_key(iss, jti, reconciliation_digest):
        return (iss, jti, reconciliation_digest or "")

    def lookup(self, iss, jti, reconciliation_digest=""):
        """The consumption slot for (iss, jti), or None. Copies: the
        store owns its slots."""
        slot = self._slots.get(
            self._slot_key(iss, jti, reconciliation_digest))
        return dict(slot) if slot is not None else None

    def _unavailable_record(self, iss, jti, content_digest):
        return _verification_record(
            "could-not-check", 9, "permit-consume-store-unavailable",
            iss=iss, jti=jti, content_digest=content_digest,
            dependency="consume-store", http_status=503)

    def claim(self, permit):
        """Atomically consume (iss, jti): saha S8.1 step 13 -- state
        consumed LAST. The wave-234 consumption ledger is used, never
        modified: its entity-bound idempotency key already refuses a
        different instance under one (iss, jti) key, which is
        translated here into the bound-permit-named
        ``permit-idempotency-conflict``."""
        iss, jti = permit["iss"], permit["jti"]
        content_digest = permit["instance_digest"]
        recon = permit.get("reconciliation_digest") or ""
        if not self.is_available():
            raise _PermitConsumeStoreUnavailable(
                "permit-consume-store-unavailable: the consume store "
                "is unavailable; could-not-check names the "
                "consume-store dependency",
                self._unavailable_record(iss, jti, content_digest))
        parts = ("bound-permit", iss, jti)
        if recon:
            parts = parts + (recon,)
        try:
            receipt = self._ledger.consume(content_digest, parts)
        except _consumption_ledger._PreviouslyConsumed as exc:
            slot = self._slots.get(self._slot_key(iss, jti, recon))
            if slot is None:
                # The ledger (e.g. via journal replay) knows a
                # consumption this store object never saw: rebuild the
                # slot from the original receipt. No result was
                # recorded here, so the effect is in progress.
                slot = {"iss": iss, "jti": jti,
                        "content_digest": content_digest,
                        "receipt": exc.receipt, "result": None,
                        "executed": False,
                        "claimed_at": exc.receipt.get("consumed_at")}
                self._slots[self._slot_key(iss, jti, recon)] = slot
            if not slot.get("executed"):
                # Same (iss, jti) + same content digest, but the
                # effect has not completed: in-progress -> retryable
                # (saha S12). This is NOT a replay: no stored result
                # exists yet, and reporting one would misread an
                # in-flight effect as complete.
                raise _PermitInProgress(
                    "permit-in-progress: (iss, jti) %r/%r is "
                    "in progress elsewhere; retry the presentation "
                    "later" % (iss, jti))
            return ("replayed", dict(slot))
        except _consumption_ledger._IdempotencyReused as exc:
            raise _PermitIdempotencyConflict(
                "permit-idempotency-conflict: (iss, jti) %r/%r is "
                "already bound to a different content digest; "
                "refusing (409-style), never a second execution"
                % (iss, jti)) from exc
        slot = {"iss": iss, "jti": jti,
                "content_digest": content_digest,
                "receipt": dict(receipt), "result": None,
                "executed": False,
                "claimed_at": receipt.get("consumed_at")}
        self._slots[self._slot_key(iss, jti, recon)] = slot
        return ("claimed", dict(slot))

    def record_result(self, iss, jti, result, reconciliation_digest=""):
        """Store the execution result for a claimed slot, so a replay
        returns it instead of executing again."""
        key = self._slot_key(iss, jti, reconciliation_digest)
        slot = self._slots.get(key)
        if slot is None:
            raise _PermitMalformed(
                "permit-malformed: no claimed (iss, jti) slot to "
                "record a result for")
        slot["result"] = result
        slot["executed"] = True


class InMemoryConsumeStore(ConsumeStore):
    """Single-node consume store. ``durable`` is False: shared
    atomicity and durability beyond this process are
    deployment-owned. Multi-node deployments MUST supply a durable
    shared store; the admission gate (``require_durable_store=True``)
    refuses this one."""


# ----------------------------------------------------------------------
# Budget ledger: outcome-tied budget accounting (saha S13).
# ----------------------------------------------------------------------


class BudgetLedger:
    """Outcome-tied budget accounting, re-derived from saha S13.

    The reservation is committed on "success" AND on "timeout"
    (unknown outcome); released on "not_attempted" and on signed
    failure with "no_effect": true. An unsigned refusal does NOT
    establish no effect. Rate budgets are never released.

    In-memory: shared accounting across nodes is deployment-owned.
    """

    _KINDS = ("spend", "rate")
    _RELEASE_ON = ("not_attempted", "signed_no_effect")

    def __init__(self):
        self._entries = {}  # (iss, jti) -> entry

    def commit(self, iss, jti, *, kind="spend"):
        """Commit the budget: called on success and on timeout."""
        if kind not in self._KINDS:
            raise _PermitMalformed(
                "permit-malformed: unknown budget kind %r" % (kind,))
        entry = self._entries.setdefault(
            (iss, jti),
            {"kind": kind, "committed": False, "released": False})
        entry["kind"] = kind
        entry["committed"] = True
        return dict(entry)

    def release(self, iss, jti, *, on):
        """Release the budget: only on "not_attempted" or
        "signed_no_effect". Releasing an uncommitted entry records
        the release (nothing was spent), never an error."""
        if on not in self._RELEASE_ON:
            raise _PermitMalformed(
                "permit-malformed: unknown budget release cause %r"
                % (on,))
        entry = self._entries.setdefault(
            (iss, jti),
            {"kind": "spend", "committed": False, "released": False})
        if entry["kind"] == "rate":
            raise _PermitRateBudgetUnreleasable(
                "permit-rate-budget-unreleasable: rate budgets are "
                "never released")
        entry["released"] = True
        return dict(entry)

    def state(self, iss, jti):
        """The budget entry for (iss, jti), or None. Copies."""
        entry = self._entries.get((iss, jti))
        return dict(entry) if entry is not None else None


# ----------------------------------------------------------------------
# Verification of presented records.
# ----------------------------------------------------------------------


def verify_permit(permit):
    """Verify a presented permit: shape, then digest recomputation.

    Refuses ``permit-malformed`` (wrong shape) and ``permit-tampered``
    (a digest does not recompute: the record was edited after issue).
    Returns True when valid. Detects edits to the permit record, not
    lies in the original legs (the leg records are caller-held; their
    digests are pinned here).
    """
    if not isinstance(permit, dict):
        raise _PermitMalformed(
            "permit-malformed: permit must be a dict")
    for field in _PERMIT_FIELDS + ("permit_digest",):
        if field not in permit:
            raise _PermitMalformed(
                "permit-malformed: missing field %r" % (field,))
    if permit.get("version") != _PERMIT_VERSION:
        raise _PermitMalformed(
            "permit-malformed: unsupported version")
    for field in ("iss", "jti"):
        if not isinstance(permit[field], str) or not permit[field]:
            raise _PermitMalformed(
                "permit-malformed: %r must be a non-empty string"
                % (field,))
    for field in ("decision_digest", "mandate_digest", "policy_digest",
                  "instance_digest", "permit_digest"):
        if not _is_bare_digest(permit[field]):
            raise _PermitMalformed(
                "permit-malformed: %r must be a bare 64-hex digest"
                % (field,))
    recon = permit["reconciliation_digest"]
    if recon != "" and not _is_bare_digest(recon):
        raise _PermitMalformed(
            "permit-malformed: reconciliation_digest must be empty or "
            "a bare 64-hex digest")
    if not isinstance(permit["legs_verified"], list):
        raise _PermitMalformed(
            "permit-malformed: legs_verified must be a list")
    if _instance_digest(permit["iss"], permit["jti"],
                        permit["decision_digest"],
                        permit["mandate_digest"],
                        permit["policy_digest"],
                        recon) != permit["instance_digest"]:
        raise _PermitTampered(
            "permit-tampered: instance digest does not recompute over "
            "the leg digests; the permit was edited after issue")
    body = {k: permit[k] for k in _PERMIT_FIELDS}
    if not hmac.compare_digest(_body_digest(body),
                               permit["permit_digest"]):
        raise _PermitTampered(
            "permit-tampered: permit digest does not recompute over "
            "the permit body; the permit was edited after issue")
    return True


def verify_reconciliation(record):
    """Verify a presented reconciliation record. Refuses
    ``permit-malformed`` / ``permit-tampered``. Returns True."""
    if not isinstance(record, dict):
        raise _PermitMalformed(
            "permit-malformed: reconciliation record must be a dict")
    for field in _RECONCILIATION_FIELDS + ("record_digest",):
        if field not in record:
            raise _PermitMalformed(
                "permit-malformed: reconciliation missing field %r"
                % (field,))
    if record.get("version") != _RECONCILIATION_VERSION:
        raise _PermitMalformed(
            "permit-malformed: unsupported reconciliation version")
    for field in ("iss", "jti"):
        if not isinstance(record[field], str) or not record[field]:
            raise _PermitMalformed(
                "permit-malformed: reconciliation %r must be a "
                "non-empty string" % (field,))
    if not _is_bare_digest(record["instance_digest"]) \
            or not _is_bare_digest(record["record_digest"]):
        raise _PermitMalformed(
            "permit-malformed: reconciliation digests must be bare "
            "64-hex")
    if record["state"] not in _RECONCILIATION_STATES:
        raise _PermitMalformed(
            "permit-malformed: unknown reconciliation state %r"
            % (record.get("state"),))
    ev = record["evidence_digest"]
    if ev != "" and not _is_bare_digest(ev):
        raise _PermitMalformed(
            "permit-malformed: evidence_digest must be empty or a "
            "bare 64-hex digest")
    body = {k: record[k] for k in _RECONCILIATION_FIELDS}
    if not hmac.compare_digest(_body_digest(body),
                               record["record_digest"]):
        raise _PermitTampered(
            "permit-tampered: reconciliation digest does not "
            "recompute; the record was edited after reconciliation")
    return True


# ----------------------------------------------------------------------
# The 13-step recipient verification order (saha S8.1, adapted).
# ----------------------------------------------------------------------


def _verification_record(outcome, step, reason=None, *, iss="", jti="",
                         content_digest="", dependency=None,
                         http_status=None, receipt=None,
                         repeat_recorded=False, result=None, leg=None):
    """One verification record (saha S8.3): ``verified`` /
    ``refused`` (+reason+step) / ``could-not-check`` (+dependency) /
    ``replayed`` -- never partial. ``http_status`` carries the saha
    S9 advisory mapping (403; 409 for idempotency-conflict; 503 for
    could-not-check)."""
    return {
        "outcome": outcome,
        "step": step,
        "reason": reason,
        "iss": iss,
        "jti": jti,
        "content_digest": content_digest,
        "dependency": dependency,
        "http_status": http_status,
        "receipt": receipt,
        "repeat_recorded": repeat_recorded,
        "result": result,
        "leg": leg,
    }


def verify_presentation(permit, *, consume_store,
                        require_durable_store=True,
                        local_policy_verifier=None, registry=None):
    """Verify a presented permit in the 13-step order and -- only at
    step 13 -- atomically consume (iss, jti).

    Returns the verification record (never partial): ``verified``
    (every step passed; the receipt is attached), ``refused`` (with
    the reason code and the step at which it stopped), ``replayed``
    (same (iss, jti) + same content digest: the stored result is
    returned and the presentation is recorded as a repeat), or
    ``could-not-check`` (with the unavailable dependency named).

    ``consume_store`` is required: the recipient-side (iss, jti)
    state. ``require_durable_store`` (default True) is the saha S12
    admission gate: a non-durable store refuses
    ``permit-consume-store-not-durable`` unless the deployment
    explicitly opts into the single-node contract.
    ``local_policy_verifier`` is an optional leg-style verifier run
    at step 11 -- before state, so a denial never consumes the
    permit. ``registry`` is the optional issuer-side PermitRegistry
    used at step 8 to check a re-issue binding.

    This function never raises for verification outcomes; only a
    missing consume_store (caller error) raises.
    """
    # Step 1: permit present and parses. Absence is malformed -- never
    # a reason to accept another credential (saha S8.2).
    if permit is None:
        return _verification_record("refused", 1, "permit-no-fallback",
                                    http_status=403)
    if consume_store is None:
        raise _PermitMalformed(
            "permit-malformed: verify_presentation requires a "
            "consume_store")
    if not isinstance(permit, dict):
        return _verification_record("refused", 1, "permit-malformed",
                                    http_status=403)
    # Step 2: required fields.
    for field in _PERMIT_FIELDS + ("permit_digest",):
        if field not in permit:
            return _verification_record("refused", 2, "permit-malformed",
                                        http_status=403)
    # Step 3: version.
    if permit.get("version") != _PERMIT_VERSION:
        return _verification_record("refused", 3, "permit-malformed",
                                    http_status=403)
    # Step 4: iss/jti.
    for field in ("iss", "jti"):
        if not isinstance(permit[field], str) or not permit[field]:
            return _verification_record("refused", 4, "permit-malformed",
                                        http_status=403)
    iss, jti = permit["iss"], permit["jti"]
    # Step 5: digest formats and record shapes (cheap structural).
    for field in ("decision_digest", "mandate_digest", "policy_digest",
                  "instance_digest", "permit_digest"):
        if not _is_bare_digest(permit[field]):
            return _verification_record("refused", 5, "permit-malformed",
                                        iss=iss, jti=jti, http_status=403)
    recon = permit["reconciliation_digest"]
    if recon != "" and not _is_bare_digest(recon):
        return _verification_record("refused", 5, "permit-malformed",
                                    iss=iss, jti=jti, http_status=403)
    if not isinstance(permit["legs_verified"], list):
        return _verification_record("refused", 5, "permit-malformed",
                                    iss=iss, jti=jti, http_status=403)
    # Step 6: instance digest recomputes (crypto).
    if _instance_digest(iss, jti, permit["decision_digest"],
                        permit["mandate_digest"],
                        permit["policy_digest"],
                        recon) != permit["instance_digest"]:
        return _verification_record("refused", 6, "permit-tampered",
                                    iss=iss, jti=jti,
                                    content_digest=permit[
                                        "instance_digest"],
                                    http_status=403)
    content_digest = permit["instance_digest"]
    # Step 7: permit digest recomputes (crypto).
    body = {k: permit[k] for k in _PERMIT_FIELDS}
    if not hmac.compare_digest(_body_digest(body),
                               permit["permit_digest"]):
        return _verification_record("refused", 7, "permit-tampered",
                                    iss=iss, jti=jti,
                                    content_digest=content_digest,
                                    http_status=403)
    # Step 8: reconciliation binding for re-issued permits.
    if recon:
        if registry is None:
            # The binding cannot be checked: fail closed, never a
            # partial record. The permit-registry is the dependency.
            return _verification_record(
                "could-not-check", 8, "permit-registry-unavailable",
                iss=iss, jti=jti, content_digest=content_digest,
                dependency="permit-registry", http_status=503)
        if not isinstance(registry, PermitRegistry):
            return _verification_record("refused", 8, "permit-malformed",
                                        iss=iss, jti=jti,
                                        content_digest=content_digest,
                                        http_status=403)
        entry = registry.lookup(iss, jti)
        registered = entry["reconciliation"] if entry else None
        if registered is None or \
                registered.get("record_digest") != recon:
            return _verification_record("refused", 8, "permit-malformed",
                                        iss=iss, jti=jti,
                                        content_digest=content_digest,
                                        http_status=403)
    # Step 9: consume store available -- could-not-check names the
    # dependency and is distinguished from a policy denial (saha S8.2).
    if not consume_store.is_available():
        return _verification_record(
            "could-not-check", 9, "permit-consume-store-unavailable",
            iss=iss, jti=jti, content_digest=content_digest,
            dependency="consume-store", http_status=503)
    # Step 10: admission gate -- durable, atomic, shared store, or an
    # explicit single-node deployment contract.
    if require_durable_store and not consume_store.durable:
        return _verification_record(
            "refused", 10, "permit-consume-store-not-durable",
            iss=iss, jti=jti, content_digest=content_digest,
            http_status=403)
    # Step 11: recipient-local policy permits -- BEFORE state, so a
    # denial never consumes the permit.
    if local_policy_verifier is not None:
        try:
            _verify_leg("local-policy", permit, local_policy_verifier)
        except BoundPermitError as exc:
            return _verification_record(
                "refused", 11,
                exc.code or "permit-leg-refusal-unmapped",
                iss=iss, jti=jti, content_digest=content_digest,
                http_status=403, leg="local-policy")
    # Step 12: (iss, jti) prior-consumption lookup -- the
    # replay-vs-conflict decision on the last-known state. A raced
    # claim between here and step 13 is still reported at this step:
    # the atomic claim enforces the decision made here.
    prior = consume_store.lookup(iss, jti, recon)
    if prior is not None and \
            prior.get("content_digest") != content_digest:
        return _verification_record(
            "refused", 12, "permit-idempotency-conflict",
            iss=iss, jti=jti, content_digest=content_digest,
            http_status=409)
    # Step 13: atomically consume (iss, jti) -- state consumed LAST.
    try:
        outcome, slot = consume_store.claim(permit)
    except _PermitIdempotencyConflict:
        return _verification_record(
            "refused", 12, "permit-idempotency-conflict",
            iss=iss, jti=jti, content_digest=content_digest,
            http_status=409)
    except _PermitInProgress:
        # Same (iss, jti) + same content digest, but the effect is
        # in flight elsewhere: retryable (saha S12), 503-style. The
        # permit is not consumed and no result exists yet.
        return _verification_record(
            "retryable", 13, "permit-in-progress",
            iss=iss, jti=jti, content_digest=content_digest,
            http_status=503)
    except _PermitConsumeStoreUnavailable as exc:
        # Backstop: step 9 checks first; a store that dies mid-step
        # reports could-not-check, not a denial.
        return exc.verification_record
    receipt = slot.get("receipt")
    if outcome == "replayed":
        return _verification_record(
            "replayed", 13, None, iss=iss, jti=jti,
            content_digest=content_digest, receipt=receipt,
            repeat_recorded=True, result=slot.get("result"))
    return _verification_record("verified", 13, None, iss=iss, jti=jti,
                                content_digest=content_digest,
                                receipt=receipt)


# ----------------------------------------------------------------------
# Issuance.
# ----------------------------------------------------------------------


_LEG_ABSENT = {
    "decision": (
        _PermitDecisionAbsent,
        "permit-decision-absent: a permit is decision AND "
        "mandate AND policy; the decision record is absent"),
    "mandate": (
        _PermitMandateAbsent,
        "permit-mandate-absent: a permit is decision AND "
        "mandate AND policy; the mandate record is absent"),
    "policy": (
        _PermitPolicyAbsent,
        "permit-policy-absent: a permit is decision AND mandate "
        "AND policy; the local policy binding is absent"),
}


def _check_leg_present(leg, record):
    if record is None:
        cls, message = _LEG_ABSENT[leg]
        raise cls(message)
    if not isinstance(record, dict):
        raise _PermitMalformed(
            "permit-malformed: %s record must be a dict, got %s"
            % (leg, type(record).__name__))


def _check_reissue(registry, iss, jti, reconciliation):
    """Enforce the (iss, jti) claim slot. Returns the reconciliation
    digest to bind ("" for a fresh issue)."""
    entry = registry.lookup(iss, jti)
    if entry is None or entry["permit"] is None:
        if reconciliation is not None:
            raise _PermitMalformed(
                "permit-malformed: reconciliation references the "
                "unclaimed (iss, jti) slot %r/%r" % (iss, jti))
        return ""
    registered = entry["reconciliation"]
    if registered is None:
        raise _PermitJtiDuplicate(
            "permit-jti-duplicate: (iss, jti) %r/%r is already claimed "
            "and no reconciliation record exists; reconcile the "
            "unknown outcome first -- never re-mint" % (iss, jti))
    if reconciliation is None:
        raise _PermitJtiDuplicate(
            "permit-jti-duplicate: (iss, jti) %r/%r has a "
            "reconciliation record; pass it to re-issue" % (iss, jti))
    verify_reconciliation(reconciliation)
    if reconciliation["record_digest"] != registered["record_digest"]:
        raise _PermitMalformed(
            "permit-malformed: presented reconciliation does not "
            "match the registered reconciliation record")
    if reconciliation["state"] != "not-executed":
        # Deliberately fail-closed: an outcome settled as completed or
        # still unknown must not be re-issued -- a second execution
        # would break at-most-once. A settled not-executed outcome is
        # the only safe re-issue path.
        raise _PermitJtiDuplicate(
            "permit-jti-duplicate: (iss, jti) %r/%r settled as %r; "
            "re-issue refused" % (iss, jti, reconciliation["state"]))
    return reconciliation["record_digest"]


def issue_permit(decision_record, mandate_record, local_policy_binding,
                 registry, *, iss, jti, verify_decision, verify_mandate,
                 verify_policy, reconciliation=None):
    """Issue a bound permit: the conjunction of three verified legs.

    ``registry`` is a ``PermitRegistry``. ``iss``/``jti`` are non-empty
    strings naming the permit authority and the unique permit identity.
    Verifiers are callables ``verifier(record)``: accept by returning,
    refuse by raising (a ``code`` attribute propagates as the permit's
    exact refusal code). Legs verify in fixed order; the first refusal
    aborts and the slot is NOT claimed.

    ``reconciliation`` is only for the recovery path: the reconciliation
    record for this (iss, jti) after an outcome settled as
    ``not-executed``. Returns the permit record (verified by
    ``verify_permit``).
    """
    if not isinstance(registry, PermitRegistry):
        raise _PermitMalformed(
            "permit-malformed: registry must be a PermitRegistry")
    for field, value in (("iss", iss), ("jti", jti)):
        if not isinstance(value, str) or not value:
            raise _PermitMalformed(
                "permit-malformed: %s must be a non-empty string"
                % (field,))
    for name, verifier in (("decision", verify_decision),
                           ("mandate", verify_mandate),
                           ("policy", verify_policy)):
        if not callable(verifier):
            raise _PermitMalformed(
                "permit-malformed: verify_%s must be callable"
                % (name,))
    _check_leg_present("decision", decision_record)
    _check_leg_present("mandate", mandate_record)
    _check_leg_present("policy", local_policy_binding)
    recon_digest = _check_reissue(registry, iss, jti, reconciliation)
    # Each leg verifies independently; none overrules another.
    _verify_leg("decision", decision_record, verify_decision)
    _verify_leg("mandate", mandate_record, verify_mandate)
    _verify_leg("policy", local_policy_binding, verify_policy)
    decision_digest = _leg_digest(decision_record)
    mandate_digest = _leg_digest(mandate_record)
    policy_digest = _leg_digest(local_policy_binding)
    instance_digest = _instance_digest(iss, jti, decision_digest,
                                       mandate_digest, policy_digest,
                                       recon_digest)
    body = {
        "version": _PERMIT_VERSION,
        "iss": iss,
        "jti": jti,
        "issued_at": _iso(time.time()),
        "decision_digest": decision_digest,
        "mandate_digest": mandate_digest,
        "policy_digest": policy_digest,
        "instance_digest": instance_digest,
        "reconciliation_digest": recon_digest,
        "legs_verified": list(_LEGS),
    }
    permit = dict(body)
    permit["permit_digest"] = _body_digest(body)
    registry.record_permit(permit)
    return permit


# ----------------------------------------------------------------------
# Consumption and execution (the 13-step order; state consumed LAST).
# ----------------------------------------------------------------------


_REFUSAL_CLASSES = {
    "permit-no-fallback": _PermitNoFallback,
    "permit-registry-unavailable": _PermitRegistryUnavailable,
    "permit-malformed": _PermitMalformed,
    "permit-tampered": _PermitTampered,
    "permit-consume-store-unavailable": _PermitConsumeStoreUnavailable,
    "permit-consume-store-not-durable": _PermitConsumeStoreNotDurable,
    "permit-idempotency-conflict": _PermitIdempotencyConflict,
    "permit-in-progress": _PermitInProgress,
}


def _exception_for_record(record):
    """Operationalize a non-verified record as a typed refusal
    carrying the record on ``.verification_record``."""
    reason = record["reason"]
    cls = _REFUSAL_CLASSES.get(reason)
    if cls is _PermitConsumeStoreUnavailable:
        return cls(
            "permit-consume-store-unavailable: the consume store is "
            "unavailable; could-not-check names the consume-store "
            "dependency (503-style)",
            verification_record=record)
    if cls is _PermitRegistryUnavailable:
        return cls(
            "permit-registry-unavailable: the re-issue binding cannot "
            "be checked without the permit registry; could-not-check "
            "names the permit-registry dependency (503-style)",
            verification_record=record)
    if cls is _PermitInProgress:
        # Not a refusal: the effect is in flight elsewhere. The
        # caller should retry the presentation later; nothing was
        # consumed and no result exists yet.
        return cls(
            "permit-in-progress: the effect for (iss, jti) is in "
            "progress elsewhere; retry the presentation later "
            "(503-style)",
            verification_record=record)
    if cls is not None:
        exc = cls("%s: verification stopped at step %d"
                  % (reason, record["step"]))
    else:
        # A leg-style (caller-named) code, e.g. from the step-11
        # local-policy verifier.
        exc = _PermitLegRefused(
            record.get("leg") or "local-policy", reason,
            "%s refused the presentation at step %d"
            % (reason, record["step"]))
    exc.verification_record = record
    return exc


def consume_permit(permit, ledger, *, consume_store=None,
                   require_durable_store=True, local_policy_verifier=None,
                   registry=None):
    """Verify (13 steps, state consumed LAST) and consume a permit.

    Returns the verification record: ``outcome`` is ``"consumed"``
    (fresh; the receipt is attached) or ``"replayed"`` (same (iss,
    jti) + same content digest: the ORIGINAL receipt is returned and
    the presentation is recorded as a repeat -- never a second
    release). A different content digest under the same (iss, jti)
    refuses ``permit-idempotency-conflict``.

    ``consume_store`` is the recipient-side (iss, jti) state; when
    omitted a single-node in-memory store is built over ``ledger``.
    ``require_durable_store`` (default True) is the saha S12
    admission gate: pass False only for an explicit single-node
    deployment contract.
    """
    store = consume_store if consume_store is not None \
        else InMemoryConsumeStore(ledger)
    record = verify_presentation(
        permit, consume_store=store,
        require_durable_store=require_durable_store,
        local_policy_verifier=local_policy_verifier, registry=registry)
    if record["outcome"] in ("refused", "could-not-check", "retryable"):
        raise _exception_for_record(record)
    record = dict(record)
    if record["outcome"] == "verified":
        record["outcome"] = "consumed"
    return record


def execute_permit(permit, ledger, *, execute, consume_store=None,
                   require_durable_store=True, budget=None,
                   budget_kind="spend", local_policy_verifier=None,
                   registry=None):
    """Verify (13 steps), consume write-ahead, then execute exactly once.

    Returns ``(record, result)``. The permit is consumed at step 13
    BEFORE ``execute`` runs. A replay (same (iss, jti) + same content
    digest) returns the STORED result without calling the executor --
    recorded as a repeat. An in-progress presentation (another holder
    claimed first) raises ``permit-in-progress``: retryable, nothing
    reserved. If ``execute`` raises after consumption, the outcome is
    unknown: the budget is committed -- for ANY exception, not only
    timeout. The attempt consumed budget, and saha S13's release
    causes (not_attempted, signed no_effect) do not cover a failed
    attempt; timeout is the named case. The caller reconciles via
    jti; the permit itself never re-releases.

    ``budget`` is an optional ``BudgetLedger``: the reservation is
    committed on success AND on timeout, never on refusal (a refused
    permit is never consumed, so nothing was reserved against).
    """
    if not callable(execute):
        raise _PermitMalformed(
            "permit-malformed: execute must be callable")
    store = consume_store if consume_store is not None \
        else InMemoryConsumeStore(ledger)
    record = verify_presentation(
        permit, consume_store=store,
        require_durable_store=require_durable_store,
        local_policy_verifier=local_policy_verifier, registry=registry)
    if record["outcome"] in ("refused", "could-not-check", "retryable"):
        raise _exception_for_record(record)
    iss, jti = record["iss"], record["jti"]
    recon = permit.get("reconciliation_digest") or ""
    if record["outcome"] == "replayed":
        # The stored result -- the executor is NOT called again.
        return record, record.get("result")
    # Fresh: consumed at step 13; perform the effect exactly once.
    try:
        result = execute(permit)
    except Exception:
        # Unknown outcome (timeout and friends): commit the budget,
        # do not refund (saha S13); reconcile by jti.
        if budget is not None:
            budget.commit(iss, jti, kind=budget_kind)
        raise
    store.record_result(iss, jti, result, recon)
    if budget is not None:
        budget.commit(iss, jti, kind=budget_kind)
    record = dict(record)
    record["outcome"] = "consumed"
    return record, result


# ----------------------------------------------------------------------
# Reconciliation of unknown outcomes.
# ----------------------------------------------------------------------


def reconcile_unknown_outcome(permit, ledger, registry, *,
                              execution_evidence=None,
                              verify_execution=None,
                              budget=None,
                              budget_kind="spend",
                              no_effect_refusal=None,
                              verify_refusal_signature=None,
                              consume_store=None,
                              refusal_outcome=None):
    """Reconcile an unknown outcome. NEVER mints a permit, never
    retries execution.

    Returns a reconciliation record naming (iss, jti) and its state:
    ``completed`` (execution evidence verified and bound to this
    permit), ``not-executed`` (the instance was never consumed, or a
    SIGNED refusal established no_effect), or ``unknown`` (consumed,
    no execution evidence). The record is registered in the
    registry, which unblocks the re-issue path only for a
    ``not-executed`` settlement.

    ``no_effect_refusal`` + ``verify_refusal_signature`` implement
    saha S13's signed-failure release: the refusal must be SIGNED by
    the recipient (``verify_refusal_signature`` returns True); an
    unsigned refusal refuses ``permit-no-effect-unattested`` and the
    budget stays committed -- the presenter MUST NOT set no_effect
    on its strength. ``budget`` (a ``BudgetLedger``) is released on
    ``not_attempted`` and on signed no_effect. ``budget_kind``
    labels the conservative commit for a missing entry.

    ``refusal_outcome`` names the outcome the signed no_effect
    attests to ("failure", "success", "timeout"; default None means
    "failure" for pre-W242 callers). A signed no_effect on a
    non-failure outcome is accepted and IGNORED (draft-saha-aadp-03
    section 4.1, adapted): no budget release, state "unknown", and
    the record's ``detail`` names "no-effect-asserted-and-ignored".
    """
    verify_permit(permit)
    iss = permit["iss"]
    jti = permit["jti"]
    instance_digest = permit["instance_digest"]
    recon = permit.get("reconciliation_digest") or ""
    if no_effect_refusal is not None and execution_evidence is not None:
        raise _PermitMalformed(
            "permit-malformed: cannot claim both execution evidence "
            "and no_effect for one reconciliation")
    # From here on the outcome is not provably not-attempted: the
    # effect was budgeted and its outcome is unknown, so a missing
    # budget entry is committed conservatively. Only not_attempted
    # and a signed no_effect release it (saha S13); an unsigned
    # refusal leaves it committed.
    if budget is not None and budget.state(iss, jti) is None:
        budget.commit(iss, jti, kind=budget_kind)
    detail = ""
    if no_effect_refusal is not None:
        if not isinstance(no_effect_refusal, dict):
            raise _PermitMalformed(
                "permit-malformed: no_effect refusal must be a dict")
        if verify_refusal_signature is None or \
                not callable(verify_refusal_signature):
            raise _PermitNoEffectUnattested(
                "permit-no-effect-unattested: no_effect claimed "
                "without a refusal-signature verifier; an unsigned "
                "refusal does not establish no effect")
        try:
            signed = verify_refusal_signature(no_effect_refusal)
        except Exception as exc:
            raise _PermitNoEffectUnattested(
                "permit-no-effect-unattested: the refusal-signature "
                "verifier failed") from exc
        if not signed:
            raise _PermitNoEffectUnattested(
                "permit-no-effect-unattested: the no_effect refusal "
                "is not signed by the recipient; the presenter MUST "
                "NOT set no_effect on its strength")
        # Wave-242 (draft-saha-aadp-03 section 4.1, adapted): a SIGNED
        # no_effect on a NON-failure outcome is accepted and IGNORED --
        # recorded in the record's detail, never a budget release.
        # The outcome the refusal pertains to is named by
        # ``refusal_outcome`` ("failure", "success", "timeout"); the
        # default None keeps the pre-W242 behavior (release) for
        # callers that predate the outcome vocabulary. Deployments
        # conforming to draft-saha-aadp-03 section 4.1 MUST pass
        # refusal_outcome explicitly. A signed refusal that names its
        # own outcome contradicting the caller's claim refuses
        # malformed -- contradictory claims fail closed.
        outcome = refusal_outcome if refusal_outcome is not None \
            else "failure"
        if outcome not in ("failure", "success", "timeout"):
            raise _PermitMalformed(
                "permit-malformed: refusal_outcome must be one of "
                "failure, success, timeout; got %r" % (refusal_outcome,))
        claimed = no_effect_refusal.get("outcome")
        if claimed is not None and claimed != outcome:
            raise _PermitMalformed(
                "permit-malformed: the signed no_effect refusal names "
                "outcome %r but the caller claims %r; contradictory "
                "outcome claims fail closed"
                % (claimed, outcome))
        detail = ""
        if outcome == "failure":
            if budget is not None:
                budget.release(iss, jti, on="signed_no_effect")
            state = "not-executed"
        else:
            # Accepted and ignored: the budget stays committed
            # (outcome-tied: committed on success and on timeout),
            # the record names the ignored assertion in its detail,
            # and the re-issue path stays closed (state unknown, not
            # not-executed).
            detail = "no-effect-asserted-and-ignored"
            state = "unknown"
        evidence_digest = hashlib.sha256(
            _canonical_dumps(no_effect_refusal).encode("utf-8")
        ).hexdigest()
    elif execution_evidence is not None:
        if verify_execution is None:
            raise _PermitMalformed(
                "permit-malformed: execution evidence supplied "
                "without an evidence verifier")
        if not callable(verify_execution):
            raise _PermitMalformed(
                "permit-malformed: verify_execution must be callable")
        if not isinstance(execution_evidence, dict):
            raise _PermitMalformed(
                "permit-malformed: execution evidence must be a dict")
        _verify_leg("execution-evidence", execution_evidence,
                    verify_execution)
        if execution_evidence.get("iss") != iss \
                or execution_evidence.get("jti") != jti:
            raise _PermitMalformed(
                "permit-malformed: execution evidence names a "
                "different (iss, jti) than the permit")
        state = "completed"
        evidence_digest = hashlib.sha256(
            _canonical_dumps(execution_evidence).encode("utf-8")
        ).hexdigest()
    elif consume_store is not None:
        if consume_store.lookup(iss, jti, recon) is None:
            state = "not-executed"
            evidence_digest = ""
            if budget is not None:
                budget.release(iss, jti, on="not_attempted")
        else:
            state = "unknown"
            evidence_digest = ""
    elif not ledger.is_consumed(instance_digest):
        state = "not-executed"
        evidence_digest = ""
        if budget is not None:
            budget.release(iss, jti, on="not_attempted")
    else:
        state = "unknown"
        evidence_digest = ""
    body = {
        "version": _RECONCILIATION_VERSION,
        "iss": iss,
        "jti": jti,
        "instance_digest": instance_digest,
        "state": state,
        "reconciled_at": _iso(time.time()),
        "evidence_digest": evidence_digest,
        "detail": detail,
    }
    record = dict(body)
    record["record_digest"] = _body_digest(body)
    registry.record_reconciliation(record)
    return record
