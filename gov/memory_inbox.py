"""Pending-verification review inbox for memory writes (R7 steal, B-B).

omelas-tech/brain shape, rebuilt from the prospectus (do NOT steal their
instruction-shaped lint -- the steal is the human-gating plumbing, which
is detector-independent):

* Low-trust and instruction-shaped memory writes land in
  ``pending-verification`` instead of being silently trusted.
* ``quarantine_mode``: ``off`` (audit only) | ``flag`` (default:
  recallable but marked, never silently delivered) | ``enforce``
  (excluded from recall until approved).
* Approval CLEARS the flag but NEVER promotes trust: the inbox records
  review decisions in its own chain; the memory ledger's trust tier is
  never mutated (trust comes only from corroboration/elevation, not from
  review).
* SHA-256 baseline per memory: every inbox item names the exact bytes
  (content_sha256) it reviews, mirroring ``MemoryLedger.record_release``.
* Invariant re-verification: "never-decay must not mean never-checked" --
  long-lived facts with no review decision are surfaced for human
  re-confirm via :meth:`MemoryInbox.reverification_due`.
* Bounded-journal overflow valve: when the lineage journal hits its
  per-principal quota, the compaction tombstone routes to the inbox as
  ``journal_overflow`` for operator review instead of silent eviction.

The inbox is a separate HMAC-chained JSONL (``memory_inbox.jsonl``,
sibling of the memory ledger), with entry kinds ``pending_review`` /
``review_decision``. It stores digests and review metadata -- never
memory content.

Honest residuals (documented, not claimed away):

* Operator review is the bottleneck: a fatigued fleet rubber-stamps the
  inbox. The ceremony-timing signals (R7 #3) are the monitor for this,
  not the inbox itself.
* In ``flag`` mode a careless consumer can still act on marked bytes;
  the mark travels with the bytes and the delivery is audited, but the
  inbox does not judge truth.
* ``enforce`` mode only gates reads through
  :meth:`MemoryFirewall.check_memory_read`; a deployment that reads
  memory files directly bypasses the gate (same trust boundary as the
  ledger key).
"""

import json
import time

from .egress_ledger import (
    EgressLedger,
    _ledger_read_locked,
    _LedgerMissing,
)

#: Review gating modes.
QUARANTINE_OFF = "off"
QUARANTINE_FLAG = "flag"
QUARANTINE_ENFORCE = "enforce"
_QUARANTINE_MODES = (QUARANTINE_OFF, QUARANTINE_FLAG, QUARANTINE_ENFORCE)
DEFAULT_QUARANTINE_MODE = QUARANTINE_FLAG

#: Pending-review reason taxonomy. Fixed vocabulary so the review queue
#: stays auditable; the firewall assigns these, callers do not invent
#: new ones.
REASON_UNTRUSTED_TIER = "untrusted_tier"
REASON_INSTRUCTION_SHAPED = "instruction_shaped"
REASON_TAINTED_RUN = "tainted_run"
REASON_LINEAGE_SHAPED = "lineage_shaped_source"
REASON_LINEAGE_EXPIRED = "lineage_window_expired"
REASON_JOURNAL_OVERFLOW = "journal_overflow"
# F191 (wave-174): a carrier whose declared type disagrees with its
# magic bytes (audio bytes declared as text/plain, or a declared audio
# type whose bytes are not audio). Classification governs; the
# mismatch is contained, never silently accepted as declared.
REASON_CARRIER_MISMATCH = "carrier_mismatch"
_REASON_CLASSES = (
    REASON_UNTRUSTED_TIER,
    REASON_INSTRUCTION_SHAPED,
    REASON_TAINTED_RUN,
    REASON_LINEAGE_SHAPED,
    REASON_LINEAGE_EXPIRED,
    REASON_JOURNAL_OVERFLOW,
    REASON_CARRIER_MISMATCH,
)

#: Review decisions. ``approved`` clears the pending flag; ``rejected``
#: keeps the bytes out of recall in enforce mode.
DECISION_APPROVED = "approved"
DECISION_REJECTED = "rejected"
_DECISIONS = (DECISION_APPROVED, DECISION_REJECTED)

#: Synthetic mem_key namespace for journal-overflow items (the journal
#: is not a memory key, but the inbox is keyed by mem_key).
JOURNAL_MEM_KEY = "__lineage_journal__"

#: Default invariant re-verification horizon: facts older than this with
#: no review decision are surfaced for human re-confirm.
DEFAULT_REVERIFY_AFTER_S = 90 * 24 * 60 * 60


class InboxError(Exception):
    """Fail-loud inbox misuse (unknown mode, bad decision, resolving a
    non-pending item)."""


class InboxLedger(EgressLedger):
    """Append-only HMAC-chained JSONL of review-inbox records.

    One ledger per deployment (NOT per run). Entry kinds are
    ``pending_review`` and ``review_decision``; the two never share a
    file with the memory ledger or the lineage journal. Inherits seq
    chaining, checkpoints, file locking, and fail-closed reads from
    :class:`EgressLedger`.
    """

    def submit_review(self, principal, mem_key, content_sha256,
                      reason_class, detail=None, now=None):
        """Append one pending-verification item; returns the record.

        ``content_sha256`` is the SHA-256 baseline: the item reviews
        exactly these bytes. ``reason_class`` must be one of the fixed
        taxonomy values. Submissions are always appended (chained audit
        trail); :meth:`MemoryInbox.pending` presents the deduplicated
        open worklist.
        """
        if reason_class not in _REASON_CLASSES:
            raise InboxError(
                "unknown inbox reason_class %r; must be one of %s"
                % (reason_class, ", ".join(_REASON_CLASSES)))
        if not isinstance(content_sha256, str) or not content_sha256:
            raise InboxError("content_sha256 baseline is required")
        return self.append({
            "kind": "pending_review",
            "principal": principal,
            "mem_key": mem_key,
            "content_sha256": content_sha256,
            "reason_class": reason_class,
            "detail": detail or {},
            "ts": time.time() if now is None else now,
        })

    def record_decision(self, principal, mem_key, content_sha256,
                        reviewer, decision, review_note="", now=None):
        """Append one review decision; returns the record.

        ``decision`` is ``approved`` or ``rejected``. The decision names
        the reviewed bytes (content_sha256) -- a decision that does not
        name its bytes could be re-applied to later silent
        modifications. This NEVER mutates the memory ledger: approval
        clears the pending flag; it does not promote the trust tier.
        """
        if decision not in _DECISIONS:
            raise InboxError(
                "unknown inbox decision %r; must be approved|rejected"
                % (decision,))
        return self.append({
            "kind": "review_decision",
            "principal": principal,
            "mem_key": mem_key,
            "content_sha256": content_sha256,
            "reviewer": reviewer,
            "decision": decision,
            "review_note": review_note,
            "ts": time.time() if now is None else now,
        })

    def entries_for(self, principal):
        """All inbox entries for ``principal``, oldest first,
        verify-first under the shared lock (fail-closed like the memory
        ledger's scan)."""
        if not self.path.exists():
            return []
        try:
            with _ledger_read_locked(self.path):
                self.require_verified()
                out = []
                for line in self.path.read_text(
                        encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if (isinstance(entry, dict)
                            and entry.get("principal") == principal
                            and entry.get("kind") in (
                                "pending_review", "review_decision")):
                        out.append(entry)
                return out
        except _LedgerMissing:
            return []


class MemoryInbox:
    """The pending-verification review queue over memory writes.

    Constructed by the deployment (opt-in) and passed to
    ``MemoryFirewall(inbox=...)``. ``None`` (the firewall default) means
    zero behavior change.
    """

    def __init__(self, path, mode=DEFAULT_QUARANTINE_MODE):
        if mode not in _QUARANTINE_MODES:
            raise InboxError(
                "unknown quarantine_mode %r; must be one of %s"
                % (mode, ", ".join(_QUARANTINE_MODES)))
        self.ledger = InboxLedger(path)
        self.mode = mode

    # -- submission -------------------------------------------------

    def submit_review(self, principal, mem_key, content_sha256,
                      reason_class, detail=None, now=None):
        """Queue one pending-verification item; returns the record."""
        return self.ledger.submit_review(
            principal, mem_key, content_sha256, reason_class,
            detail=detail, now=now)

    # -- worklist ----------------------------------------------------

    def _open_triples(self, principal):
        """{(mem_key, content_sha256): pending_review record} for open
        items, oldest submission wins. A later review_decision for the
        same triple closes it; a still-later pending_review re-opens it
        (the bytes were written again and need re-review)."""
        open_items = {}
        for e in self.ledger.entries_for(principal):
            triple = (e.get("mem_key"), e.get("content_sha256"))
            if e.get("kind") == "pending_review":
                open_items.setdefault(triple, e)
            elif e.get("kind") == "review_decision":
                open_items.pop(triple, None)
        return open_items

    def pending(self, principal):
        """Open review items for ``principal``, oldest first."""
        items = list(self._open_triples(principal).values())
        items.sort(key=lambda e: (e.get("ts", 0), e.get("seq", 0)))
        return items

    def has_pending(self, principal, mem_key, content_sha256):
        """True when a pending-verification item is open for exactly
        these bytes."""
        return (mem_key, content_sha256) in self._open_triples(principal)

    def pending_for(self, principal, mem_key, content_sha256):
        """The open pending_review record for these bytes, or None."""
        return self._open_triples(principal).get(
            (mem_key, content_sha256))

    # -- resolution ---------------------------------------------------

    def resolve(self, principal, mem_key, content_sha256, reviewer,
                decision, review_note="", now=None):
        """Record a human review decision; returns the decision record.

        Approval clears the pending flag. The memory ledger is never
        touched: trust is not promoted by review. Fail-loud when no
        item is open for the triple (stale review state).
        """
        if not self.has_pending(principal, mem_key, content_sha256):
            raise InboxError(
                "no open inbox item for (%r, %r, %.16s...); refusing to "
                "resolve stale state" % (principal, mem_key,
                                         content_sha256 or ""))
        return self.ledger.record_decision(
            principal, mem_key, content_sha256, reviewer, decision,
            review_note=review_note, now=now)

    def confirm_reverification(self, principal, mem_key,
                               content_sha256, reviewer, review_note="",
                               now=None):
        """Explicit re-verification: record a human re-confirmation for
        bytes that are NOT currently pending (e.g. an invariant-review
        item from :meth:`reverification_due`). Appends a review_decision
        with ``approved``; the memory ledger is never touched. Fail-loud
        when the item IS pending (use :meth:`resolve` for those).
        """
        if self.has_pending(principal, mem_key, content_sha256):
            raise InboxError(
                "item is pending; resolve it, do not re-verify")
        return self.ledger.record_decision(
            principal, mem_key, content_sha256, reviewer,
            DECISION_APPROVED, review_note=review_note, now=now)

    # -- invariant re-verification ------------------------------------

    def reverification_due(self, principal, memory_records, now=None,
                           reverify_after_s=DEFAULT_REVERIFY_AFTER_S):
        """``never-decay != never-checked``: mem_keys whose newest memory
        record is older than ``reverify_after_s`` with no inbox review
        decision for those exact bytes.

        ``memory_records`` is the oldest-first list from
        ``MemoryLedger.records_for(principal)``. Returns
        ``[{mem_key, ts, content_sha256, trust_tier}]`` sorted by key.
        A re-verification approval appends a review_decision, which
        takes the key off the due list until the bytes change.
        """
        now = time.time() if now is None else now
        cutoff = now - reverify_after_s
        newest = {}
        for e in memory_records or ():
            if e.get("principal") == principal and e.get("mem_key"):
                newest[e["mem_key"]] = e
        decided = set()
        for e in self.ledger.entries_for(principal):
            if e.get("kind") == "review_decision":
                decided.add((e.get("mem_key"), e.get("content_sha256")))
        out = []
        for mem_key in sorted(newest):
            e = newest[mem_key]
            try:
                ts = float(e.get("ts", 0))
            except (TypeError, ValueError):
                continue
            triple = (mem_key, e.get("content_sha256"))
            if ts < cutoff and triple not in decided:
                out.append({
                    "mem_key": mem_key,
                    "ts": ts,
                    "content_sha256": e.get("content_sha256"),
                    "trust_tier": e.get("trust_tier"),
                })
        return out
