"""Obligation binding (W241-6 / onedoor ND-038, re-derived prose only).

Re-derived invariant from onedoor's own honest gap ND-038 ("obligations
silently ignored"): a permit may declare *obligations* -- actions that
must be evidenced after execution (notify an operator, write a receipt,
anchor an audit entry). An obligation that is declared on the permit but
has no fulfillment evidence at settlement time is a silent ignore, and
settlement refuses ``obligation-unfulfilled`` naming the missing
obligations.

Obligations are evidence, not authority: verifying that every declared
obligation has a matching fulfillment record cannot make the
fulfillment truthful -- a forged fulfillment record is a different
attack (seal/digest binding, out of scope here). What this module
closes is the quiet drop: obligations that never even appear in the
execution record.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

OBLIGATION_UNFULFILLED = "obligation-unfulfilled"
OBLIGATION_MALFORMED = "obligation-malformed"


class ObligationError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(ObligationError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise ObligationError(code, detail)


def declare_obligations(permit_id, obligations):
    """Declare the obligations attached to a permit at issue time.

    ``obligations`` is an iterable of non-empty string obligation ids.
    Returns an immutable declaration record; duplicate declarations are
    refused (fail-closed) rather than deduplicated silently.
    """
    if not isinstance(permit_id, str) or not permit_id:
        _refuse(OBLIGATION_MALFORMED,
                "permit_id must be a non-empty string")
    if isinstance(obligations, str) or not hasattr(obligations, "__iter__"):
        _refuse(OBLIGATION_MALFORMED,
                "obligations must be an iterable of strings")
    seen = []
    for ob in obligations:
        if not isinstance(ob, str) or not ob:
            _refuse(OBLIGATION_MALFORMED,
                    "obligation ids must be non-empty strings")
        if ob in seen:
            _refuse(OBLIGATION_MALFORMED,
                    "duplicate obligation declared: %r" % (ob,))
        seen.append(ob)
    return {"permit_id": permit_id,
            "obligations": tuple(seen)}


def evidence_fulfilled(fulfilled):
    """Build a fulfillment-evidence set from an iterable of obligation
    ids with execution records. Caller-supplied; sealed binding is
    deployment-owned (see module docstring)."""
    if isinstance(fulfilled, str) or not hasattr(fulfilled, "__iter__"):
        _refuse(OBLIGATION_MALFORMED,
                "fulfilled must be an iterable of strings")
    for ob in fulfilled:
        if not isinstance(ob, str) or not ob:
            _refuse(OBLIGATION_MALFORMED,
                    "fulfilled obligation ids must be non-empty strings")
    return frozenset(fulfilled)


def verify_obligations(permit, evidence):
    """Verify every declared obligation has fulfillment evidence.

    Refuses ``obligation-unfulfilled`` naming the missing obligation
    ids when any declared obligation is silently ignored. A permit with
    no declared obligations verifies trivially (nothing to ignore).
    """
    if not isinstance(permit, dict) or "obligations" not in permit:
        _refuse(OBLIGATION_MALFORMED,
                "permit must be a declare_obligations record")
    if not isinstance(evidence, frozenset):
        _refuse(OBLIGATION_MALFORMED,
                "evidence must be an evidence_fulfilled record")
    missing = [ob for ob in permit["obligations"] if ob not in evidence]
    if missing:
        _refuse(OBLIGATION_UNFULFILLED,
                "obligations silently ignored at execution: %s"
                % (", ".join(sorted(missing)),))
    return {"permit_id": permit["permit_id"],
            "obligations_fulfilled": sorted(permit["obligations"])}


def settle_permit(permit, evidence):
    """Settle a permit only when its obligations are evidenced.

    Settlement is a receipt, never authority: it records that the
    obligation check ran and passed; it does not prove the underlying
    execution was truthful.
    """
    verified = verify_obligations(permit, evidence)
    return {"permit_id": verified["permit_id"],
            "obligations_fulfilled": verified["obligations_fulfilled"],
            "settled": True}
