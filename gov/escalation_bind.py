#!/usr/bin/env python3
"""Escalation-to-effect binding: the escalation approval's digest is
cryptographically bound INTO the action capsule at seal time.

ADAPT of the draft-das-agentic-adaptive-authorization-00 direction
("escalation must reach the effect point"; re-derived prose, nothing
copied): an escalation that never reaches the effect point is a gap
an auditor must be able to detect. This module makes the drop
detectable by construction.

Protocol:

1. The action creator marks the attempt with
   ``escalation_required: True`` when the action went through
   escalation.
2. :func:`bind_escalation` takes the escalation approval record and
   the sealed capsule and seals a NEW capsule. The new attempt
   embeds an ``escalation`` block
   ``{approval_digest, action_digest, approval_body}``; the new
   effect carries ``escalation_digest``. The new capsule digest
   commits to both, so the binding is sealed by the capsule itself.
3. :func:`verify_escalation_bound` re-derives everything from the
   sealed bytes:

   * replay the capsule digests (``gov.action_capsule.verify_capsule``);
   * if the attempt is not escalated, there is nothing to bind —
     return ``None``;
   * if it is escalated but the escalation block is missing or
     invalid — refuse ``escalation-not-bound``;
   * recompute the approval digest over the embedded approval body —
     mismatch refuses ``escalation-approval-digest-mismatch``;
   * recompute the action digest over the attempt MINUS the
     escalation block (the action as approved) — mismatch refuses
     ``escalation-action-mismatch``;
   * the effect's ``escalation_digest`` must equal the recomputed
     approval digest — mismatch refuses ``escalation-not-bound``.

Bindings are recomputed, never asserted. A capsule records
evidence; it never grants authority.

Stdlib only. No network. $0.
"""

import hashlib

from .action_capsule import (
    canonical_json_bytes,
    seal_capsule,
    verify_capsule,
)


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class EscalationBindError(Exception):
    """Base class for escalation-binding refusals. ``code`` is
    machine-readable."""

    code = "escalation-bind-refused"


class _NotBound(EscalationBindError):
    code = "escalation-not-bound"


class _ActionMismatch(EscalationBindError):
    code = "escalation-action-mismatch"


class _ApprovalDigestMismatch(EscalationBindError):
    code = "escalation-approval-digest-mismatch"


class _Malformed(EscalationBindError):
    code = "escalation-malformed"


class _AlreadyBound(EscalationBindError):
    code = "escalation-already-bound"


# ----------------------------------------------------------------------
# Constants.
# ----------------------------------------------------------------------

ESCALATION_VERSION = 1

_HEX64 = frozenset("0123456789abcdef")


# ----------------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------------


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in _HEX64 for c in value))


def _recompute_approval_digest(approval_body):
    """Recompute the approval digest; fail closed on shape."""
    if not isinstance(approval_body, dict) or not approval_body:
        raise _Malformed(
            "approval_body must be a non-empty object")
    return _digest(canonical_json_bytes(approval_body))


def _validate_approval_record(approval_record):
    """Validate an approval record and return
    (approval_digest, action_digest, approval_body).

    The record is ``{v, approval_body, approval_digest,
    action_digest}``. The digest is RECOMPUTED from the body —
    never trusted as asserted.
    """
    if not isinstance(approval_record, dict):
        raise _Malformed("approval_record must be a dict")
    unknown = set(approval_record.keys()) - {"v", "approval_body",
                                             "approval_digest",
                                             "action_digest"}
    if unknown:
        raise _Malformed(
            "unknown approval fields: %s" % sorted(unknown))
    approval_body = approval_record.get("approval_body")
    recomputed = _recompute_approval_digest(approval_body)
    claimed = approval_record.get("approval_digest")
    if not _is_hex64(claimed):
        raise _Malformed(
            "approval_digest must be 64 lowercase hex chars")
    if claimed != recomputed:
        raise _ApprovalDigestMismatch(
            "approval_digest does not recompute from approval_body")
    action_digest = approval_record.get("action_digest")
    if not _is_hex64(action_digest):
        raise _Malformed(
            "action_digest must be 64 lowercase hex chars")
    return claimed, action_digest, approval_body


# ----------------------------------------------------------------------
# Binding.
# ----------------------------------------------------------------------


def bind_escalation(approval_record, capsule):
    """Seal a NEW action capsule with the escalation approval bound
    into it.

    ``approval_record`` is ``{v, approval_body, approval_digest,
    action_digest}`` where ``action_digest`` must equal the sealed
    capsule's ``verdict_digest`` (the action as approved) — a replay
    of an approval onto a different action refuses
    ``escalation-action-mismatch``. ``capsule`` is the sealed
    unbound capsule; binding an already-bound capsule refuses
    ``escalation-already-bound``. Returns the new sealed capsule.

    The binding block lives in the attempt (the action it belongs
    to) and the effect mirrors the approval digest, so the capsule
    digest commits to the binding on both sides.
    """
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    attempt = body["attempt"]
    effect = body["effect"]
    if "escalation" in attempt or "escalation_digest" in effect:
        raise _AlreadyBound(
            "capsule already carries an escalation binding")
    approval_digest, action_digest, approval_body = \
        _validate_approval_record(approval_record)
    if action_digest != str(capsule.get("verdict_digest")):
        raise _ActionMismatch(
            "approval was issued for a different action")
    escalation_block = {"v": ESCALATION_VERSION,
                        "approval_digest": approval_digest,
                        "action_digest": action_digest,
                        "approval_body": approval_body}
    new_attempt = dict(attempt)
    new_attempt["escalation"] = escalation_block
    new_effect = dict(effect)
    new_effect["escalation_digest"] = approval_digest
    return seal_capsule({"attempt": new_attempt, "effect": new_effect})


# ----------------------------------------------------------------------
# Verification.
# ----------------------------------------------------------------------


def verify_escalation_bound(capsule):
    """Verify the escalation binding, recomputed from sealed bytes.

    Returns the bound ``approval_digest`` when the capsule is an
    escalated action with a valid binding; returns ``None`` when the
    capsule is not an escalated action (no binding required). An
    escalated action (``attempt.escalation_required`` true) whose
    binding is missing or invalid refuses ``escalation-not-bound`` —
    the dropped escalation is detectable. A binding whose approval
    digest or action digest does not recompute refuses with the
    corresponding code.
    """
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    attempt = body["attempt"]
    effect = body["effect"]
    escalation_required = attempt.get("escalation_required") is True
    block = attempt.get("escalation")
    if not escalation_required and block is None:
        return None
    if block is None or not isinstance(block, dict):
        raise _NotBound(
            "escalated action has no escalation binding")
    unknown = set(block.keys()) - {"v", "approval_digest",
                                   "action_digest", "approval_body"}
    if unknown:
        raise _NotBound(
            "escalation block has unknown fields: %s"
            % sorted(unknown))
    approval_digest = block.get("approval_digest")
    action_digest = block.get("action_digest")
    approval_body = block.get("approval_body")
    if not _is_hex64(approval_digest) or not _is_hex64(action_digest):
        raise _NotBound("escalation block digests malformed")
    # Recompute the approval digest from the embedded body.
    recomputed_approval = _recompute_approval_digest(approval_body)
    if approval_digest != recomputed_approval:
        raise _ApprovalDigestMismatch(
            "approval_digest does not recompute from approval_body")
    # Recompute the action digest from the attempt MINUS the
    # escalation block: the action as the approver saw it.
    attempt_minus = {key: value for key, value in attempt.items()
                     if key != "escalation"}
    recomputed_action = _digest(canonical_json_bytes(attempt_minus))
    if action_digest != recomputed_action:
        raise _ActionMismatch(
            "escalation binds a different action than this attempt")
    # The effect must mirror the binding; a dropped mirror means the
    # binding did not fully reach the effect point.
    if effect.get("escalation_digest") != approval_digest:
        raise _NotBound(
            "effect does not carry the escalation binding")
    return approval_digest
