"""Closure-scoped approvals (wave-237, W237-6: OpenClaw bounding).

An approval is not a free-floating permission: it is a packet sealed to
the exact closure in which it may be exercised. This module binds an
approval packet to run + sandbox + requester + route + approval
identity + the canonical request digest + the state digest at issuance,
and refuses, by name, every attempt to replay the packet outside its
closure, to use a capability after settlement, or to effect a write
against state that moved since issuance.

The eight machine refusals:

* ``approval-run-mismatch`` -- the packet is presented against a
  different ``run_id`` than the one it was sealed to.
* ``approval-sandbox-mismatch`` -- presented against a different
  ``sandbox_id``. Each binding is checked independently and named:
  a sandbox mismatch is not reported as a run mismatch.
* ``approval-route-mismatch`` -- presented against a different
  ``route``. A pre-computed approval reused at a different route
  refuses here, never silently accepted.
* ``approval-capability-dead`` -- a capability (or the effecting
  write) attempted after the packet was settled. Settlement ends the
  packet; there is no second execution.
* ``approval-state-stale`` -- ``recheck_and_write`` saw
  ``current_state_digest`` differ from the packet's issuance-time
  state digest. The write-time recheck is the TOCTOU guard: state
  moved, the approval no longer covers this state.
* ``scoped-approval-malformed`` -- the presented packet (or an
  argument) is the wrong shape; refusing instead of guessing.
* ``scoped-approval-tampered`` -- the packet's ``approval_digest``
  does not recompute over its body; the record was edited after
  issuance. Tamper detection wins over every contextual check: an
  edited packet never reaches a capability, a settlement, or a write.
* ``scoped-approval-capability-unknown`` -- an attempt to exercise a
  capability the packet never granted.

Deterministic: no clock, no randomness, no I/O, no environment
reads. Sealing is domain-separated SHA-256 digest-binding
(``gov-closure-scoped-approvals/v1``); ``approval_digest`` detects
edits to the packet body.

Honest boundaries (what this does NOT prove):

* The digest binding detects EDITS, not forgery: anyone who can
  mint a packet can mint a self-consistent one. Authenticated
  minting is deployment-owned (e.g. a MAC over the packet via the
  deployment's signing path).
* Packets are plain in-memory mappings: ``settled`` flags and the
  consumption record live in the packet the caller holds. Shared
  atomicity across processes or hosts -- two callers racing the same
  packet -- is deployment-owned; this module makes the refusal
  vocabulary exact, not the storage durable.
* The ``apply`` callable in ``recheck_and_write`` is caller-supplied:
  the module sequences recheck-before-write (never write-before-recheck)
  but does not prove the write actually happened; the receipt is
  evidence of the recheck, not of the deployment's write.
* It does not bind wall-clock time: approvals have no expiry in this
  module; liveness is the deployment's job (see IR 8587 token hygiene,
  wave-234).

Stdlib only.
"""

import hashlib
import hmac
import json

_DOMAIN = b"gov-closure-scoped-approvals/v1"

# Fields covered by the seal, in canonical order.
_APPROVAL_FIELDS = ("version", "approval_id", "run_id", "sandbox_id",
                    "requester_id", "route", "approval_identity",
                    "capabilities", "request_digest", "state_digest")

_HEX64 = set("0123456789abcdef")


class ClosureScopedApprovalError(Exception):
    """Refusal with a machine code registered in gov/decision_codes.py."""

    code = "scoped-approval-malformed"

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _refuse(code, message):
    raise ClosureScopedApprovalError(code, message)


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in _HEX64 for c in value))


def _is_nonempty_str(value):
    return isinstance(value, str) and len(value) > 0


def _canonical_dumps(obj):
    """JCS-style canonical JSON: sorted keys, compact separators, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _body_digest(body):
    """Domain-separated digest over the canonical body mapping."""
    canonical = _canonical_dumps(
        {k: body[k] for k in _APPROVAL_FIELDS}).encode("ascii")
    return hashlib.sha256(_DOMAIN + canonical).hexdigest()


def _approval_id_for(body):
    """Deterministic approval id derived from the sealed body."""
    return hashlib.sha256(
        _DOMAIN + b"approval-id/" + _body_digest(body).encode("ascii")
    ).hexdigest()[:32]


def _check_packet_shape(packet):
    if not isinstance(packet, dict):
        _refuse("scoped-approval-malformed",
                "scoped-approval-malformed: approval packet is not a mapping")
    for field in ("version", "approval_id", "run_id", "sandbox_id",
                  "requester_id", "route", "approval_identity",
                  "capabilities", "request_digest", "state_digest",
                  "approval_digest"):
        if field not in packet:
            _refuse("scoped-approval-malformed",
                    "scoped-approval-malformed: packet missing field %r"
                    % (field,))
    if packet.get("version") != 1:
        _refuse("scoped-approval-malformed",
                "scoped-approval-malformed: unsupported version %r"
                % (packet.get("version"),))
    for field in ("run_id", "sandbox_id", "requester_id", "route",
                  "approval_identity", "approval_id"):
        if not _is_nonempty_str(packet[field]):
            _refuse("scoped-approval-malformed",
                    "scoped-approval-malformed: field %r must be a "
                    "non-empty string" % (field,))
    caps = packet["capabilities"]
    if (not isinstance(caps, list) or not caps
            or any(not _is_nonempty_str(c) for c in caps)
            or len(set(caps)) != len(caps)):
        _refuse("scoped-approval-malformed",
                "scoped-approval-malformed: capabilities must be a "
                "non-empty list of unique non-empty strings")
    for field in ("request_digest", "state_digest", "approval_digest"):
        if not _is_hex64(packet[field]):
            _refuse("scoped-approval-malformed",
                    "scoped-approval-malformed: field %r must be 64 "
                    "lowercase hex" % (field,))


def _check_seal(packet):
    """Tamper check: the digest must recompute. Always runs before any
    contextual check, so an edited packet never reaches capability,
    settlement, or write logic."""
    _check_packet_shape(packet)
    recomputed = _body_digest(packet)
    if not hmac.compare_digest(recomputed, packet["approval_digest"]):
        _refuse("scoped-approval-tampered",
                "scoped-approval-tampered: approval_digest does not "
                "recompute over the packet body; the packet was edited "
                "after issuance")


def issue_scoped_approval(run_id, sandbox_id, requester_id, route,
                          approval_identity, capabilities, request_digest,
                          state_digest, approval_id=None):
    """Seal an approval packet to its closure.

    The packet binds run + sandbox + requester + route + approval
    identity + the canonical request digest + the issuance-time state
    digest. Every field is a non-empty string; the digests are 64
    lowercase hex.
    """
    if approval_id is None:
        approval_id = ""  # empty = not supplied; derived below
    packet = {
        "version": 1,
        "approval_id": approval_id,
        "run_id": run_id,
        "sandbox_id": sandbox_id,
        "requester_id": requester_id,
        "route": route,
        "approval_identity": approval_identity,
        "capabilities": list(capabilities) if isinstance(capabilities, list)
        else capabilities,
        "request_digest": request_digest,
        "state_digest": state_digest,
    }
    # Shape-check with a non-empty stand-in id, then seal the real body.
    _check_packet_shape({**packet, "approval_digest": "00" * 32,
                         "approval_id": packet["approval_id"] or "pending"})
    if not packet["approval_id"]:
        packet["approval_id"] = _body_digest(packet)[:32]
    packet["approval_digest"] = _body_digest(
        {k: packet[k] for k in _APPROVAL_FIELDS})
    packet["settled"] = False
    packet["consumption"] = []
    return packet


def _check_context(packet, run_id=None, sandbox_id=None, route=None):
    """Independent named binding checks. Each binding is checked on its
    own and named; a sandbox mismatch is never reported as a run
    mismatch."""
    if run_id is not None and run_id != packet["run_id"]:
        _refuse("approval-run-mismatch",
                "approval-run-mismatch: packet sealed for run_id %r, "
                "presented against %r" % (packet["run_id"], run_id))
    if sandbox_id is not None and sandbox_id != packet["sandbox_id"]:
        _refuse("approval-sandbox-mismatch",
                "approval-sandbox-mismatch: packet sealed for sandbox_id "
                "%r, presented against %r" % (packet["sandbox_id"],
                                              sandbox_id))
    if route is not None and route != packet["route"]:
        _refuse("approval-route-mismatch",
                "approval-route-mismatch: packet sealed for route %r, "
                "presented against %r" % (packet["route"], route))


def verify_scoped_approval(packet, run_id=None, sandbox_id=None, route=None):
    """Verify the packet seal, then its context bindings.

    Returns True. Refuses ``scoped-approval-malformed`` /
    ``scoped-approval-tampered`` on shape/edit, then the named binding
    mismatch codes. ``None`` context arguments are not checked.
    """
    _check_seal(packet)
    _check_context(packet, run_id=run_id, sandbox_id=sandbox_id,
                   route=route)
    return True


def settle_attempt(packet, run_id=None, sandbox_id=None, route=None):
    """Mark the packet's attempt settled. Idempotent: settling twice
    returns the same receipt (deterministic over the approval digest),
    never a second execution."""
    _check_seal(packet)
    _check_context(packet, run_id=run_id, sandbox_id=sandbox_id,
                   route=route)
    receipt_digest = hashlib.sha256(
        _DOMAIN + b"settle/" + packet["approval_digest"].encode("ascii")
    ).hexdigest()
    packet["settled"] = True
    return {"approval_digest": packet["approval_digest"],
            "settled": True,
            "receipt_digest": receipt_digest}


def exercise_capability(packet, capability, run_id=None, sandbox_id=None,
                        route=None):
    """Exercise one granted capability. Requires an un-settled packet:
    after settlement the refusal is ``approval-capability-dead``.
    Records the consumption in the packet's consumption list."""
    _check_seal(packet)
    _check_context(packet, run_id=run_id, sandbox_id=sandbox_id,
                   route=route)
    if packet.get("settled"):
        _refuse("approval-capability-dead",
                "approval-capability-dead: the packet's attempt is "
                "settled; capabilities die at settlement, there is no "
                "second execution")
    if capability not in packet["capabilities"]:
        _refuse("scoped-approval-capability-unknown",
                "scoped-approval-capability-unknown: capability %r was "
                "never granted by this packet" % (capability,))
    consumption_digest = hashlib.sha256(
        _DOMAIN + b"consume/" + packet["approval_digest"].encode("ascii")
        + b"/" + capability.encode("utf-8")
    ).hexdigest()
    record = {"approval_digest": packet["approval_digest"],
              "capability": capability,
              "consumption_digest": consumption_digest}
    packet["consumption"].append(record)
    return record


def recheck_and_write(packet, current_state_digest, run_id=None,
                      sandbox_id=None, route=None, apply=None):
    """Re-verify everything immediately before the effecting write.

    Order is fixed: seal, then context bindings, then settlement
    state, then the state-digest TOCTOU recheck. On success the packet
    is settled (so the write cannot be repeated under the same
    approval) and a write receipt is returned. ``apply`` is the
    deployment-supplied write effect, called between the recheck and
    the settlement; if it raises, the packet is NOT settled and the
    exception propagates.
    """
    _check_seal(packet)
    _check_context(packet, run_id=run_id, sandbox_id=sandbox_id,
                   route=route)
    if packet.get("settled"):
        _refuse("approval-capability-dead",
                "approval-capability-dead: the packet's attempt is "
                "already settled; no further write may use this approval")
    if not _is_hex64(current_state_digest):
        _refuse("scoped-approval-malformed",
                "scoped-approval-malformed: current_state_digest must be "
                "64 lowercase hex")
    if not hmac.compare_digest(current_state_digest,
                               packet["state_digest"]):
        _refuse("approval-state-stale",
                "approval-state-stale: state moved since issuance "
                "(packet state_digest %s..., current %s...); the "
                "approval no longer covers this state"
                % (packet["state_digest"][:16], current_state_digest[:16]))
    if apply is not None:
        apply(packet)
    receipt_digest = hashlib.sha256(
        _DOMAIN + b"write/" + packet["approval_digest"].encode("ascii")
        + b"/" + current_state_digest.encode("ascii")
    ).hexdigest()
    packet["settled"] = True
    return {"approval_digest": packet["approval_digest"],
            "settled": True,
            "write_receipt_digest": receipt_digest}
