#!/usr/bin/env python3
"""At-most-once consumption ledger for grants/approvals/receipts.

Re-derived (nothing copied) from the convergent industry direction
(fissible/verdict ADR-0039 consumed-binding, EMILIA receipt-hook
consume-before-allow, APS approval-single-use, GRACE one-time
settlement): consume at authorization time, record consumption against
a digest, make replay an explicit outcome.

Two primitives:

1. ``ConsumptionLedger`` -- consumption keyed to the digest of the
   FROZEN authorization instance, never to an approval id appearing in
   a record. ``consume(instance_digest, key_parts)`` marks the
   instance consumed and returns a consumption receipt whose
   ``receipt_digest`` binds the instance; a second attempt with the
   same digest raises ``_PreviouslyConsumed`` (machine code
   ``previously-consumed``) carrying the ORIGINAL receipt -- replay is
   an explicit named outcome, never a silent release.

   Idempotency keys are length-prefixed, NUL-joined, entity-bound
   (``build_idempotency_key``): ``sha256(domain || len(p0) NUL p0 NUL
   || ...)``. Two grants sharing a raw key but targeting different
   entities bind to different key digests and do NOT collide (the
   EMILIA ``sha256(ref:type)`` regression). Reusing one entity-bound
   key for a DIFFERENT frozen instance refuses
   ``consumption-idempotency-reused`` -- a reused key cannot mint a
   release under another instance's receipt.

   Crash semantics are write-ahead: when a journal path is
   configured, the consumption record is appended and fsync'd BEFORE
   the receipt is returned. A ledger constructed over the same
   journal ("restart") replays the journal and reads every committed
   instance as consumed -- never double-releasable. Journal lines
   are the receipts themselves; a corrupt or digest-mismatched line
   refuses ``consumption-journal-unusable`` (fail closed: an
   untrustworthy journal must not release anything). A failed commit
   refuses ``consumption-journal-write-failed`` and marks nothing.

   ``verify_receipt`` recomputes the receipt digest; an edited
   receipt refuses ``consumption-receipt-tampered``, a shapeless one
   ``consumption-receipt-malformed``.

2. ``SingleUseConsumptionAdapter`` -- additive write-ahead wiring for
   the in-repo ``SingleUseRegistry`` (``gov/single_use.py`` is NOT
   modified; its default behavior is unchanged). ``consume_attestation``
   commits the instance to the ledger journal FIRST, then marks the
   attestation consumed in the registry. If the registry then refuses
   (unknown/malformed/revoked), the journal holds an orphan entry --
   fail-closed by design: that digest reads consumed and refuses
   ``previously-consumed`` rather than releasing.

Honest residuals: the ledger detects edits to presented digests, not
lies told consistently from the start (the frozen instance is
caller-supplied; ``gov/evaluation_function.py`` pins the instance it
commits to). The journal is a local file; shared atomicity across
processes and remote durability are deployment-owned. ``is_consumed``
answers what THIS ledger instance (plus its journal) has committed.

Stdlib only. No network. $0.
"""

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone

# ----------------------------------------------------------------------
# Error vocabulary. The base class carries no string ``code`` (deliberate:
# the w228 refusal-vocabulary scanner must see only real product codes).
# ----------------------------------------------------------------------


class ConsumptionError(Exception):
    """Base class for all consumption-ledger refusals. Subclasses set
    the machine-readable ``code``."""

    code = None


class _PreviouslyConsumed(ConsumptionError):
    code = "previously-consumed"

    def __init__(self, message, receipt):
        super().__init__(message)
        # The original consumption receipt: the replay is explicit and
        # auditable, never a silent new release.
        self.receipt = receipt


class _IdempotencyReused(ConsumptionError):
    code = "consumption-idempotency-reused"


class _InstanceMalformed(ConsumptionError):
    code = "consumption-instance-malformed"


class _KeyMalformed(ConsumptionError):
    code = "consumption-key-malformed"


class _JournalUnusable(ConsumptionError):
    code = "consumption-journal-unusable"


class _JournalWriteFailed(ConsumptionError):
    code = "consumption-journal-write-failed"


class _ReceiptMalformed(ConsumptionError):
    code = "consumption-receipt-malformed"


class _ReceiptTampered(ConsumptionError):
    code = "consumption-receipt-tampered"


# ----------------------------------------------------------------------
# Internals.
# ----------------------------------------------------------------------

_KEY_DOMAIN = b"sasanam-consumption-key-v1:"
_RECEIPT_VERSION = 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_FIELDS = ("version", "outcome", "instance_digest",
                   "bound_key_digest", "consumed_at")


def _is_bare_digest(value):
    """Bare sha256 hexdigests only: no ``sha256:`` prefix, no uppercase,
    exactly 64 hex chars. Prefixed or short forms are malformed here."""
    return isinstance(value, str) and _HEX64.match(value) is not None


def _canonical_dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _iso(now):
    return datetime.fromtimestamp(now, tz=timezone.utc).isoformat()


def build_idempotency_key(*parts):
    """Bind idempotency key parts into one digest.

    Each part is length-prefixed and NUL-separated, then hashed under
    a domain prefix::

        sha256(b"sasanam-consumption-key-v1:" ||
               len(p0) NUL p0 NUL || len(p1) NUL p1 NUL || ...)

    Length-prefixing means ``("ab", "c")`` and ``("a", "bc")`` bind
    differently (no concatenation ambiguity); NUL separation means
    empty/adjacent boundaries cannot merge parts. Parts must be
    non-empty strings and there must be at least two (a key type plus
    an entity identifier -- entity binding is what stops the
    cross-entity collision). Deterministic: equal parts, equal digest.
    """
    if len(parts) < 2:
        raise _KeyMalformed(
            "consumption-key-malformed: idempotency key needs at least "
            "two parts (key type + entity identifier), got %d"
            % (len(parts),))
    h = hashlib.sha256(_KEY_DOMAIN)
    for part in parts:
        if not isinstance(part, str) or not part:
            raise _KeyMalformed(
                "consumption-key-malformed: every key part must be a "
                "non-empty string")
        raw = part.encode("utf-8")
        h.update(str(len(raw)).encode("ascii"))
        h.update(b"\x00")
        h.update(raw)
        h.update(b"\x00")
    return h.hexdigest()


def _receipt_digest(body):
    return hashlib.sha256(
        _canonical_dumps(body).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Consumption ledger.
# ----------------------------------------------------------------------


class ConsumptionLedger:
    """At-most-once consumption keyed to frozen-instance digests.

    ``journal_path`` (optional): an append-only JSONL file. Every
    consumption commits (append + fsync) before the receipt returns;
    construction replays the journal so a restarted ledger reads
    committed instances as consumed.
    """

    def __init__(self, journal_path=None):
        self._consumed = {}    # instance_digest -> receipt dict
        self._bound_keys = {}  # bound_key_digest -> instance_digest
        self._journal_path = journal_path
        if journal_path is not None:
            self._replay_journal(journal_path)

    # -- journal ----------------------------------------------------

    def _replay_journal(self, path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return  # Fresh journal: nothing committed yet.
        except (OSError, UnicodeDecodeError) as exc:
            raise _JournalUnusable(
                "consumption-journal-unusable: cannot read journal %r: %s"
                % (path, exc))
        for lineno, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                receipt = json.loads(line)
            except (ValueError, TypeError):
                raise _JournalUnusable(
                    "consumption-journal-unusable: journal line %d is "
                    "not JSON" % (lineno,))
            try:
                self.verify_receipt(receipt)
            except ConsumptionError as exc:
                raise _JournalUnusable(
                    "consumption-journal-unusable: journal line %d "
                    "fails receipt verification (%s)"
                    % (lineno, exc.code))
            digest = receipt["instance_digest"]
            bound = receipt["bound_key_digest"]
            if digest in self._consumed or bound in self._bound_keys:
                raise _JournalUnusable(
                    "consumption-journal-unusable: journal line %d "
                    "duplicates an earlier entry" % (lineno,))
            self._consumed[digest] = receipt
            self._bound_keys[bound] = digest

    def _commit(self, receipt):
        """Write-ahead commit: append + fsync BEFORE the caller may
        release. On failure nothing is marked."""
        line = _canonical_dumps(receipt) + "\n"
        try:
            with open(self._journal_path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise _JournalWriteFailed(
                "consumption-journal-write-failed: could not commit "
                "instance %s: %s"
                % (receipt["instance_digest"][:16], exc))

    # -- public API --------------------------------------------------

    def consume(self, instance_digest, key_parts):
        """Consume the frozen authorization instance.

        ``instance_digest``: bare sha256 hex of the frozen instance.
        ``key_parts``: tuple/list of >= 2 non-empty strings, bound by
        ``build_idempotency_key``.

        Returns the consumption receipt on first consume. A repeat
        raises ``_PreviouslyConsumed`` (code ``previously-consumed``)
        carrying the original receipt. A different instance under an
        already-bound key raises ``_IdempotencyReused`` (code
        ``consumption-idempotency-reused``).
        """
        if not _is_bare_digest(instance_digest):
            raise _InstanceMalformed(
                "consumption-instance-malformed: instance digest must "
                "be a bare 64-hex sha256 digest")
        if not isinstance(key_parts, (tuple, list)):
            raise _KeyMalformed(
                "consumption-key-malformed: key parts must be a "
                "tuple/list of strings")
        bound = build_idempotency_key(*key_parts)
        if instance_digest in self._consumed:
            original = self._consumed[instance_digest]
            raise _PreviouslyConsumed(
                "previously-consumed: instance %s was already consumed "
                "at %s (receipt %s...)"
                % (instance_digest[:16], original["consumed_at"],
                   original["receipt_digest"][:16]),
                receipt=dict(original))
        if bound in self._bound_keys:
            raise _IdempotencyReused(
                "consumption-idempotency-reused: this entity-bound "
                "idempotency key already consumed instance %s; a "
                "different instance cannot release under it"
                % (self._bound_keys[bound][:16],))
        body = {
            "version": _RECEIPT_VERSION,
            "outcome": "consumed",
            "instance_digest": instance_digest,
            "bound_key_digest": bound,
            "consumed_at": _iso(time.time()),
        }
        receipt = dict(body)
        receipt["receipt_digest"] = _receipt_digest(body)
        if self._journal_path is not None:
            self._commit(receipt)  # write-ahead: commit before release
        self._consumed[instance_digest] = receipt
        self._bound_keys[bound] = instance_digest
        return dict(receipt)

    def is_consumed(self, instance_digest):
        """True when this ledger (in-memory + journal) has committed
        the instance digest. Pure read, no side effects."""
        return isinstance(instance_digest, str) \
            and instance_digest in self._consumed

    def consumption_receipt(self, instance_digest):
        """The original receipt for a consumed instance, else None."""
        receipt = self._consumed.get(instance_digest)
        return dict(receipt) if receipt is not None else None

    @staticmethod
    def verify_receipt(receipt):
        """Recompute the receipt digest. Edited receipts refuse
        ``consumption-receipt-tampered``; shapeless ones
        ``consumption-receipt-malformed``. Returns True when valid."""
        if not isinstance(receipt, dict):
            raise _ReceiptMalformed(
                "consumption-receipt-malformed: receipt must be a dict")
        for field in _RECEIPT_FIELDS:
            if field not in receipt:
                raise _ReceiptMalformed(
                    "consumption-receipt-malformed: missing field %r"
                    % (field,))
        if "receipt_digest" not in receipt:
            raise _ReceiptMalformed(
                "consumption-receipt-malformed: missing receipt_digest")
        if receipt.get("version") != _RECEIPT_VERSION:
            raise _ReceiptMalformed(
                "consumption-receipt-malformed: unsupported version")
        if receipt.get("outcome") != "consumed":
            raise _ReceiptMalformed(
                "consumption-receipt-malformed: unexpected outcome")
        if not _is_bare_digest(receipt["instance_digest"]) \
                or not _is_bare_digest(receipt["bound_key_digest"]) \
                or not _is_bare_digest(receipt["receipt_digest"]):
            raise _ReceiptMalformed(
                "consumption-receipt-malformed: digests must be bare "
                "64-hex")
        body = {k: receipt[k] for k in _RECEIPT_FIELDS}
        if not hmac.compare_digest(_receipt_digest(body),
                                   receipt["receipt_digest"]):
            raise _ReceiptTampered(
                "consumption-receipt-tampered: receipt digest does not "
                "recompute over the receipt body")
        return True


# ----------------------------------------------------------------------
# Additive adapter for the in-repo single-use registry.
# ----------------------------------------------------------------------


class SingleUseConsumptionAdapter:
    """Write-ahead consumption wiring for ``SingleUseRegistry``.

    Additive: ``gov/single_use.py`` is not modified. ``consume_attestation``
    commits the instance to the ledger journal FIRST (write-ahead), then
    marks the attestation consumed in the registry. If the registry
    then refuses (unknown/malformed/revoked), the journal holds an
    orphan entry -- fail-closed: that digest reads consumed and later
    attempts refuse ``previously-consumed`` instead of releasing.
    """

    def __init__(self, registry, ledger):
        self._registry = registry
        self._ledger = ledger

    def consume_attestation(self, record):
        """Consume one attestation record. Returns
        ``(ledger_receipt, registry_evidence_item)``."""
        if not isinstance(record, dict):
            raise _InstanceMalformed(
                "consumption-instance-malformed: attestation record "
                "must be a dict")
        instance_digest = hashlib.sha256(
            _canonical_dumps(record).encode("utf-8")).hexdigest()
        receipt = self._ledger.consume(
            instance_digest,
            ("single-use-attestation",
             record.get("issuer") or "",
             record.get("jti") or ""))
        evidence = self._registry.consume(record)
        return receipt, evidence
