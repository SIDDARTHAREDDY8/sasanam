"""Revoke-after-approve (wave-131, row-7 second half).

An approval is a human decision under a specific intent. When the
intent changes after the grant (a countermand arrives before the
sweep executes), the grant must not silently survive: it is revoked
and any later consumption fails closed.

Public seam: ``revoke_approval(queue, approval_id, reason, revoker)``.
``ApprovalQueue.revoke`` (gov/approvals.py) is the thin delegating
method; this module holds the authorization rule so the executor's
execution-boundary re-validation and the queue share one decision.

Authorization: only the granter (``record["decided_by"]``) or the
reserved ``INTENT_SYSTEM`` principal (the executor's automatic
intent re-validation — not a human, not an agent) may revoke a
granted approval; the requester of a still-pending item may withdraw
it. Everyone else is refused and the attempt is audited LOUD.

Revocation is terminal: a revoked record can never be decided,
executed, or re-revoked, and ``mark_executed`` refuses it
fail-closed. Audit-before-state-change throughout (F167 lesson):
every refusal is chained to the log before the ValueError escapes.
"""
from datetime import datetime, timezone

# Reserved revoker for the executor's automatic intent re-validation
# (wave-131): not a human principal, not an agent id — the governed
# side revoking on intent change. Treated as authorized for every
# record; it can never be impersonated via decided_by because no
# human decision is ever recorded with this principal.
INTENT_SYSTEM = "intent-system"

REVOKED_STATUS = "revoked"

# Records in these statuses may be revoked. Terminal states
# (rejected, expired, revoked, ...) cannot.
_REVOKABLE_STATUSES = ("pending", "approved")


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _log(queue, entry):
    """Best-effort audit append: a logging outage must never turn a
    revocation (or its refusal) into silent state. Mirrors decide()'s
    _log_attempt posture."""
    try:
        queue._log(entry)
    except Exception:  # noqa: BLE001 - the decision stands regardless
        pass


def _log_attempt(queue, approval_id, outcome, note, record=None):
    _log(queue, {
        "event": "approval_revoke_attempt",
        "run_id": (record or {}).get("run_id"),
        "agent_id": "human-operator",
        "role": "approver",
        "principal": "human-operator",
        "decision": outcome,
        "approval_id": approval_id,
        "note": note,
    })


def revoke_approval(queue, approval_id, reason, revoker):
    """Revoke an approval so it can never be consumed.

    ``queue`` is an ApprovalQueue (duck-typed: ``get``/``_rewrite``/
    ``_log``). ``reason`` is a human-readable string (audited).
    ``revoker`` must be the granting principal
    (``record["decided_by"]``), the requester of a still-pending
    approval (``record["agent_id"]``), or ``INTENT_SYSTEM``.

    Returns the revoked record dict. Raises ValueError (fail-closed,
    audit-logged) when the id is unknown, the record already
    executed, already revoked, in a non-revokable status, or the
    revoker is not authorized.
    """
    record = None
    try:
        record = queue.get(approval_id)
    except Exception:  # noqa: BLE001 - unknown ids fail closed below
        record = None
    if record is None:
        _log_attempt(queue, approval_id, "rejected_attempt",
                     "revocation attempted on unknown approval id")
        raise ValueError("approval id %r not found" % (approval_id,))
    if record.get("executed"):
        _log_attempt(queue, approval_id, "rejected_attempt",
                     "revocation refused: approval already executed; "
                     "revocation cannot undo a side effect",
                     record=record)
        raise ValueError(
            "cannot revoke approval %r: already executed" % (approval_id,))
    if record.get("status") == REVOKED_STATUS:
        _log_attempt(queue, approval_id, "rejected_attempt",
                     "revocation refused: approval already revoked",
                     record=record)
        raise ValueError(
            "cannot revoke approval %r: already revoked" % (approval_id,))
    if record.get("status") not in _REVOKABLE_STATUSES:
        _log_attempt(queue, approval_id, "rejected_attempt",
                     "revocation refused: status %r is not revokable"
                     % (record.get("status"),),
                     record=record)
        raise ValueError(
            "cannot revoke approval %r: status %r is not revokable"
            % (approval_id, record.get("status")))
    granter = record.get("decided_by")
    requester = record.get("agent_id")
    # Standing tracks the record's lifecycle: before a decision the
    # REQUESTER owns the request (it may withdraw its own pending
    # item); after a decision the GRANTER owns the grant. The intent
    # system may always revoke (automatic re-validation). Everyone
    # else — including other agents and other humans — is refused.
    authorized = (
        revoker == INTENT_SYSTEM
        or (granter is not None and revoker == granter)
        or (granter is None and revoker == requester)
    )
    if not authorized:
        _log_attempt(queue, approval_id, "rejected_attempt",
                     "revocation refused: %r has no standing to revoke "
                     "this approval (granter %r, requester %r)"
                     % (revoker, granter, requester),
                     record=record)
        raise ValueError(
            "cannot revoke approval %r: %r is not authorized to revoke "
            "(only the granter %r, the requester of a pending approval, "
            "or the intent system may revoke)"
            % (approval_id, revoker, granter))
    revoked_at = _utcnow_iso()
    queue._rewrite(lambda records: [
        dict(r, status=REVOKED_STATUS, revoked_by=revoker,
             revoked_reason=str(reason), revoked_at=revoked_at)
        if r.get("id") == approval_id else r
        for r in records])
    _log(queue, {
        "event": "approval_revoked",
        "run_id": record.get("run_id"),
        "agent_id": record.get("agent_id"),
        "role": record.get("role"),
        "principal": record.get("principal"),
        "tool": record.get("tool"),
        "approval_id": approval_id,
        "decision": "revoked",
        "policy_id": "approval-revocation",
        "flag": "approval_revoked",
        "revoked_by": revoker,
        "revoked_reason": str(reason),
        "revoked_at": revoked_at,
        "reason": ("Approval %s revoked by %s: %s"
                   % (approval_id, revoker, reason)),
    })
    revoked = queue.get(approval_id)
    return revoked if revoked is not None else record
