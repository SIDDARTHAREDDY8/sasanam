"""Seeded refusal digests + denial-evidence durability invariant.

Wave-231 lane B. Stdlib only.

A denial record is seeded into the audit log OUTSIDE the denied
transaction: its digest chain anchors to the audit log's current head,
never to the transaction that was denied, so a rolled-back transaction
cannot erase its own denial::

    seed_denial(decision_digest, deny_reason_code, rule_path,
                log_head_digest, ...)
        -> {"v", "kind", "decision_digest", "deny_reason_code",
            "rule_path", "anchor", "denied_txn_head",
            "receipt_digest", "receipt_less_reason", "digest"}

``anchor`` is the audit-log head digest at seed time -- the deployment
commits the record's digest through the normal append path AFTER the
denied transaction is known. ``verify_denial`` recomputes the record
digest (never trusts the claim) and refuses
``denial-anchored-in-denied-transaction`` when the anchor lives inside
the denied transaction's digest chain.

When a signed denial receipt (gov/deny_receipts.py) CANNOT be formed --
evidence missing, the ``taxonomy-receipt-missing`` territory -- the
record is marked ``kind="receipt-less-denial"`` and carries an
explicit ``receipt_less_reason`` of the form
``denial-receipt-unavailable-<cause>``. Silence is never evidence: a
receipt-less record carrying neither a receipt digest nor a reason
refuses ``seeded-denial-malformed``.

``denial_survives_rollback(record, post_rollback_entries)`` enforces
the durability invariant: the record's digest must be found in a
committed entry of the post-rollback log (i.e. the commit was outside
the rolled-back region). Absence refuses ``denial-evidence-lost``.

This module is digest-level and works over digest lists alone (same
discipline as gov/checkpoints.py): it never touches the audit-log key
or format. The composition seam is :func:`denial_commit_entry`,
which returns the event dict a deployment appends through
``ActionLog.append`` -- no existing-file behavior changes, and no
import of gov.log (the deployment owns the wiring).

Denials are EVIDENCE, never authority: ``denial_as_authority``
refuses ``seeded-denial-not-authorization``.

Registries are in-memory; persistence and distribution are
deployment-owned. A seeded denial proves the anchor commitment and
the record's integrity; it does not prove the underlying decision was
correct.

Honest residual: ``seed_denial`` cannot verify that the
caller-supplied ``log_head_digest`` is truly the audit log's current
head -- a deployment that passes a stale or interior digest weakens
the rollback-safety guarantee this module enforces the exclusion
half of (anchor must not be inside the denied chain) but the
deployment owns the positive half (anchor really is the head).
Wave-233 honest-claim discipline (NON-CLAIMS.md): a seeded denial record proves the denial was anchored, not that the denied action was absent. This phrase is machine-checked by evals/doc_truth.py.
"""

import hashlib
import json
import re

SEED_VERSION = 1

# Domain separation for the record digest, so a seeded-denial digest
# can never be repurposed as another record's digest.
_DOMAIN = b"gov-seeded-denial/v1"

_RECEIPT_LESS_REASON_PREFIX = "denial-receipt-unavailable-"

_RECORD_FIELDS = (
    "v",
    "kind",
    "decision_digest",
    "deny_reason_code",
    "rule_path",
    "anchor",
    "denied_txn_head",
    "receipt_digest",
    "receipt_less_reason",
    "digest",
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Closed reason slugs: lowercase kebab. One shape under two names --
# _REASON validates emitted denial reason codes, _CAUSE validates
# receipt-unavailable cause slugs; same shape, distinct semantics.
_REASON = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_CAUSE = _REASON


# -- errors -------------------------------------------------------------

class SeededDenialError(Exception):
    """Base class for seeded-denial refusals. ``code`` is
    machine-readable and registered in gov/decision_codes.py."""
    code = "seeded-denial-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class DenialAnchoredInTransaction(SeededDenialError):
    """The record's anchor lives inside the denied transaction's
    digest chain: a rollback could erase the denial."""
    code = "denial-anchored-in-denied-transaction"


class DenialEvidenceLost(SeededDenialError):
    """The committed denial record is absent from the post-rollback
    log: the denial evidence did not survive."""
    code = "denial-evidence-lost"


class DenialMalformed(SeededDenialError):
    """The presented record is not a well-formed seeded-denial
    record (includes silence -- None is never evidence)."""
    code = "seeded-denial-malformed"


class DenialDigestMismatch(SeededDenialError):
    """The record's digest does not recompute from its body."""
    code = "seeded-denial-digest-mismatch"


class DenialNotAuthority(SeededDenialError):
    """A denial record was offered as authority. Denials are
    evidence, never authority."""
    code = "seeded-denial-not-authorization"


# -- helpers ------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _is_hex64(value):
    return isinstance(value, str) and _HEX64.match(value) is not None


def _record_digest(body):
    return hashlib.sha256(
        _DOMAIN + b"\x00" + _canonical(body)).hexdigest()


def record_digest(record):
    """Recompute the digest of a seeded-denial record (excludes the
    ``digest`` field itself). Raises :class:`DenialMalformed` on a
    non-record."""
    if not isinstance(record, dict):
        raise DenialMalformed("not a record: silence is never evidence")
    body = dict(record)
    body.pop("digest", None)
    return _record_digest(body)


def _check_receipt_less(record):
    """Enforce the receipt-less contract: kind and reason must agree,
    and silence (neither receipt nor reason) is malformed."""
    kind = record.get("kind")
    receipt_digest = record.get("receipt_digest")
    reason = record.get("receipt_less_reason")
    if kind == "receipt-less-denial":
        if receipt_digest is not None:
            raise DenialMalformed(
                "receipt-less-denial carries a receipt digest")
        if not isinstance(reason, str) or not reason.startswith(
                _RECEIPT_LESS_REASON_PREFIX):
            # Silence is never evidence: no reason, no record.
            raise DenialMalformed(
                "receipt-less-denial without an explicit "
                "denial-receipt-unavailable-<cause> reason")
        cause = reason[len(_RECEIPT_LESS_REASON_PREFIX):]
        if not _CAUSE.match(cause):
            raise DenialMalformed(
                "receipt-less cause is not a closed cause slug")
    elif kind == "seeded-denial":
        if receipt_digest is None:
            raise DenialMalformed(
                "seeded-denial without a receipt digest "
                "must be receipt-less-denial")
        if reason is not None:
            raise DenialMalformed(
                "seeded-denial carries a receipt-less reason")
    else:
        raise DenialMalformed("unknown kind %r" % (kind,))


def _check_record_shape(record):
    """Fail-closed structural validation shared by the verifiers."""
    if not isinstance(record, dict):
        # Silence is never evidence: None (or a non-record) is not a
        # record-shaped refusal, it is a refusal.
        raise DenialMalformed("no record presented")
    if set(record) != set(_RECORD_FIELDS):
        raise DenialMalformed(
            "record fields %s, expected %s"
            % (sorted(record), sorted(_RECORD_FIELDS)))
    if record.get("v") != SEED_VERSION:
        raise DenialMalformed("unsupported version %r"
                              % (record.get("v"),))
    for field in ("decision_digest", "anchor"):
        if not _is_hex64(record.get(field)):
            raise DenialMalformed(
                "%s must be 64-char lowercase hex" % field)
    head = record.get("denied_txn_head")
    if head is not None and not _is_hex64(head):
        raise DenialMalformed(
            "denied_txn_head must be 64-char lowercase hex")
    if record.get("receipt_digest") is not None and not _is_hex64(
            record.get("receipt_digest")):
        raise DenialMalformed(
            "receipt_digest must be 64-char lowercase hex")
    if not _REASON.match(str(record.get("deny_reason_code") or "")):
        raise DenialMalformed(
            "deny_reason_code must be a closed reason slug")
    if not isinstance(record.get("rule_path"), str) \
            or not record.get("rule_path"):
        raise DenialMalformed("rule_path must be a non-empty string")
    if _record_digest(
            {k: v for k, v in record.items() if k != "digest"}) != \
            record.get("digest"):
        raise DenialDigestMismatch(
            "record digest does not recompute from its body")
    _check_receipt_less(record)


# -- public API ---------------------------------------------------------

def seed_denial(*, decision_digest, deny_reason_code, rule_path,
                log_head_digest, denied_txn_head=None,
                receipt_digest=None, receipt_unavailable_cause=None):
    """Seed a denial record anchored to ``log_head_digest`` -- the
    audit-log head at seed time, outside the denied transaction.

    When a signed denial receipt exists, pass it as ``receipt_digest``
    (a 64-char hex digest of the receipt from gov/deny_receipts.py).
    When no receipt can be formed, pass ``receipt_unavailable_cause``
    (a closed cause slug); the record is marked
    ``receipt-less-denial`` with an explicit
    ``denial-receipt-unavailable-<cause>`` reason instead of silence.

    Receipt + cause together, or neither, refuses
    ``seeded-denial-malformed`` at seed time.
    """
    if not _is_hex64(decision_digest):
        raise DenialMalformed(
            "decision_digest must be 64-char lowercase hex")
    if not _is_hex64(log_head_digest):
        raise DenialMalformed(
            "log_head_digest must be 64-char lowercase hex")
    if denied_txn_head is not None and not _is_hex64(denied_txn_head):
        raise DenialMalformed(
            "denied_txn_head must be 64-char lowercase hex")
    if not _REASON.match(str(deny_reason_code or "")):
        raise DenialMalformed(
            "deny_reason_code must be a closed reason slug")
    if not isinstance(rule_path, str) or not rule_path:
        raise DenialMalformed("rule_path must be a non-empty string")
    if receipt_digest is not None and receipt_unavailable_cause is not None:
        raise DenialMalformed(
            "receipt digest and receipt-unavailable cause are "
            "contradictory: supply exactly one")
    if receipt_digest is not None and not _is_hex64(receipt_digest):
        raise DenialMalformed(
            "receipt_digest must be 64-char lowercase hex")
    if receipt_digest is None:
        kind = "receipt-less-denial"
        if not _CAUSE.match(str(receipt_unavailable_cause or "")):
            raise DenialMalformed(
                "a receipt-less denial must carry an explicit "
                "receipt_unavailable_cause slug")
        reason = _RECEIPT_LESS_REASON_PREFIX + receipt_unavailable_cause
    else:
        kind = "seeded-denial"
        reason = None
    body = {
        "v": SEED_VERSION,
        "kind": kind,
        "decision_digest": decision_digest,
        "deny_reason_code": deny_reason_code,
        "rule_path": rule_path,
        "anchor": log_head_digest,
        "denied_txn_head": denied_txn_head,
        "receipt_digest": receipt_digest,
        "receipt_less_reason": reason,
    }
    body["digest"] = _record_digest(body)
    return body


def verify_denial(record, *, denied_txn_digests):
    """Verify a seeded-denial record: recompute the digest, then
    refuse ``denial-anchored-in-denied-transaction`` when the record's
    anchor lives inside the denied transaction's digest chain
    (``denied_txn_digests``, an iterable of 64-char hex digests).
    The parameter is REQUIRED (keyword-only, no default): omitting
    the denied chain would silently skip the core anchor check."""
    _check_record_shape(record)
    txn = set(denied_txn_digests or ())
    if record["anchor"] in txn:
        raise DenialAnchoredInTransaction(
            "anchor %s lives inside the denied transaction's digest "
            "chain: a rollback could erase this denial"
            % record["anchor"])
    return {"ok": True, "digest": record["digest"],
            "anchor": record["anchor"], "kind": record["kind"]}


def denial_commit_entry(record):
    """Return the audit-log event a deployment appends through
    ``ActionLog.append`` to commit the denial OUTSIDE the denied
    transaction. The deployment wires this: this module never imports
    gov.log (the log's key and format are deployment-owned)."""
    _check_record_shape(record)
    return {
        "event_type": "seeded-denial",
        "kind": record["kind"],
        "seeded_denial_digest": record["digest"],
        "seeded_denial_anchor": record["anchor"],
        "deny_reason_code": record["deny_reason_code"],
    }


def denial_survives_rollback(record, *, post_rollback_entries):
    """Enforce the durability invariant: the record's digest must be
    found in a committed entry of the post-rollback log. Absence
    refuses ``denial-evidence-lost`` -- the commit was inside the
    rolled-back region, so the denial did not survive."""
    _check_record_shape(record)
    entries = post_rollback_entries or ()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("seeded_denial_digest") != record["digest"]:
            continue
        if entry.get("seeded_denial_anchor") is not None \
                and entry["seeded_denial_anchor"] != record["anchor"]:
            raise DenialDigestMismatch(
                "commit anchor disagrees with the record anchor")
        return {"ok": True, "digest": record["digest"],
                "seq": entry.get("seq")}
    raise DenialEvidenceLost(
        "denial record digest %s absent from the post-rollback log: "
        "the denial evidence was lost in the rollback" % record["digest"])


def denial_as_authority(record):
    """Refuse any authority-shaped use of a denial record. Denials
    are evidence, never authority."""
    raise DenialNotAuthority(
        "a seeded-denial record was offered as authority; "
        "denials are evidence, never authority")
