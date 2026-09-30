#!/usr/bin/env python3
"""Bound-permit conjunction: a permit is decision AND mandate AND local policy.

Re-derived (nothing copied) from the convergent industry direction
(draft-saha-aadp-bound-permit -00 "bound permit", at-most-once
consumption consensus): a permit is issued only when three legs verify
independently -- the decision record, the mandate record, and the local
policy binding. Each leg can refuse; none overrules another: a refusal
in any leg refuses the permit carrying the leg's EXACT refusal code.
A permit issued without a mandate refuses ``permit-mandate-absent``;
without a policy binding ``permit-policy-absent``; without a decision
``permit-decision-absent``.

The permit is frozen at issue time: the permit's (iss, jti) and the
three leg records are digested into an ``instance_digest`` -- consumption
is atomic in (iss, jti), each permit its own consumable instance.
Consumption is atomic in the wave-234 consumption-ledger semantics
(``gov/consumption_ledger.py`` is used, never modified): double-submit
of a consumed permit yields exactly one execution and the named
``previously-consumed`` outcome.

Unknown outcomes reconcile via jti, never by re-minting:
``reconcile_unknown_outcome`` never issues a permit and never retries
execution. It returns a reconciliation record naming (iss, jti) and its
state -- ``completed`` (execution evidence verified and bound),
``not-executed`` (never consumed), or ``unknown`` (consumed, no
execution evidence). A fresh permit under an already-claimed (iss, jti)
refuses ``permit-jti-duplicate`` until a reconciliation record exists;
re-issue is then allowed only when the outcome settled as
``not-executed``, and the new permit binds the reconciliation digest,
so the re-issued permit is a DISTINCT consumable instance (it can never
re-release the reconciled one). An outcome settled as ``completed`` or
``unknown`` keeps refusing ``permit-jti-duplicate``: re-issuing there
would risk a second execution.

Leg verifiers are caller-supplied callables ``verifier(record)``: a
verifier accepts by returning (the return value is ignored); it refuses
by raising. A raised refusal carrying a string ``code`` attribute
propagates with that exact code; a refusal naming no code refuses
``permit-leg-refusal-unmapped`` (fail closed: an unnamed refusal is
unauditable). The original exception is chained onto the refusal, so
a verifier that crashes on a programming error stays visible in the
traceback instead of being masked by the refusal.

Honest residuals: legs, verifiers, execution evidence, and the registry
are caller-supplied; the module pins digests of what it commits to, it
does not establish the caller's claims. The registry is in-memory:
shared atomicity and durability are deployment-owned. The ledger
detects edits to presented digests, not lies told consistently from
the start (the frozen legs are caller-supplied).

Stdlib only. No network. $0.
"""

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

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
                          "state", "reconciled_at", "evidence_digest")
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
# Consumption and execution (wave-234 ledger, used additively).
# ----------------------------------------------------------------------


def consume_permit(permit, ledger):
    """Consume a permit in the consumption ledger (write-ahead by the
    ledger). Returns the consumption receipt. A repeat raises the
    ledger's ``previously-consumed`` carrying the ORIGINAL receipt:
    replay is an explicit named outcome, never a silent release. A
    tampered permit is refused before the ledger is touched."""
    verify_permit(permit)
    parts = ("bound-permit", permit["iss"], permit["jti"])
    if permit.get("reconciliation_digest"):
        parts = parts + (permit["reconciliation_digest"],)
    return ledger.consume(permit["instance_digest"], parts)


def execute_permit(permit, ledger, *, execute):
    """Consume (write-ahead) then execute exactly once.

    Returns ``(receipt, execution_result)``. The permit is consumed
    BEFORE ``execute`` runs: a double-submit raises
    ``previously-consumed`` before the executor is called, so the
    executor runs exactly once per permit. If ``execute`` raises after
    consumption, the outcome is unknown -- reconcile it via jti; the
    permit itself never re-releases.
    """
    if not callable(execute):
        raise _PermitMalformed(
            "permit-malformed: execute must be callable")
    receipt = consume_permit(permit, ledger)
    result = execute(permit)
    return receipt, result


# ----------------------------------------------------------------------
# Reconciliation of unknown outcomes.
# ----------------------------------------------------------------------


def reconcile_unknown_outcome(permit, ledger, registry, *,
                              execution_evidence=None,
                              verify_execution=None):
    """Reconcile an unknown outcome. NEVER mints a permit, never
    retries execution.

    Returns a reconciliation record naming (iss, jti) and its state:
    ``completed`` (execution evidence verified and bound to this
    permit), ``not-executed`` (the instance was never consumed), or
    ``unknown`` (consumed, no execution evidence). The record is
    registered in the registry, which unblocks the re-issue path only
    for a ``not-executed`` settlement.
    """
    verify_permit(permit)
    iss = permit["iss"]
    jti = permit["jti"]
    instance_digest = permit["instance_digest"]
    if execution_evidence is not None:
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
    elif not ledger.is_consumed(instance_digest):
        state = "not-executed"
        evidence_digest = ""
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
    }
    record = dict(body)
    record["record_digest"] = _body_digest(body)
    registry.record_reconciliation(record)
    return record
