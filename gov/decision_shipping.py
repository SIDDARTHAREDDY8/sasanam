"""Decision-log shipping (OPA decision-log shipping discipline, ADAPTED).

Pattern lineage: open-policy-agent/opa ``docs/docs/management-decision-logs.md``
(Apache-2.0) -- behavior-level steal, nothing vendored. This module is what
happens *after* a decision-log v2 event exists (``gov.decision_log_v2``):

  1. **Mask-before-buffer ordering.** The shipper's ingest gate requires the
     event to have been built under this deployment's *compiled* mask plan
     (``CompiledMask``: the erased/masked pointer lists validated once, then
     matched exactly). The buffer never holds unmasked data: the gate runs
     ``decision_log_v2.verify_event`` (redaction lies refused loudly) *before*
     the event enters any buffer or chunk.
  2. **Chunked uploads with soft limits.** Buffered events are packed into
     chunks of at most ``chunk_limit_bytes``; each chunk goes to the sink as
     one upload.
  3. **Failure = requeue, not drop.** A non-2xx sink response requeues the
     chunk (it stays in the buffer) with exponential backoff; the chunk is
     only dropped *loudly* after the retry budget is exhausted.
  4. **Loud drops.** An event that cannot fit a chunk, or that overflows the
     bounded buffer, is dropped with an explicit ``dropped_events`` counter
     increment and a ``drop-record`` audit entry -- never silently lost. This
     is the OPA v1.9.0 lesson: their buffer limit was once reset to the 32kb
     default on upload, silently dropping logs. Here the config is an
     immutable (frozen) dataclass, so the upload path cannot mutate the
     limits by construction.
  5. **Oversize-event eviction.** If a single event exceeds the chunk limit,
     the non-determinism replay capture (``replay``) is evicted *loudly*:
     the stub keeps the replay fn name, declares ``evicted: true``, and
     commits to the dropped capture via ``capture_digest``; the
     ``decision_id`` is re-derived so the event stays tamper-evident.
     ``verify_event`` refuses an evicted event loudly (the capture is
     gone -- this is declared, not papered over); disk-tier recovery
     re-gates evicted events through ``_regat_evicted`` instead.
  6. **Freshness cadence.** ``max_delay_s`` bounds the time between uploads;
     ``min_delay_s`` floors it; ``flush`` is the manual trigger.
  7. **Durability tiers** (from the eOPA docs): ``memory`` (fast, honestly
     lossy-on-crash), ``disk`` (write-through to ``gov.durable_journal``,
     survives restarts; at-least-once -- a crash between the sink ack and
     the ``chunk_shipped`` journal write resurrects the chunk and it ships
     again, so duplicates are possible and silent loss is not),
     ``unbuffered`` (the action does not run until THIS event's chunk is
     acknowledged by the sink -- "prove it was logged before the action
     ran"; an ack for any other chunk never releases the action).

Stdlib-only. $0 spend: sinks are caller-supplied callables (tests use fakes).
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import time

from gov import decision_log_v2 as _dlv2
from gov import durable_journal as _dj

# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class ShippingError(Exception):
    """Base for all shipping failures."""


class ConfigError(ShippingError):
    """Invalid shipper configuration."""


class IngestError(ShippingError):
    """An event was refused at the ingest gate (never buffered)."""


class SinkError(ShippingError):
    """An upload failed and the chunk is being requeued (or was dropped)."""


# ---------------------------------------------------------------------------
# Configuration (frozen: the upload path cannot mutate the limits)
# ---------------------------------------------------------------------------

_DURABILITIES = ("memory", "disk", "unbuffered")


@dataclasses.dataclass(frozen=True)
class ShippingConfig:
    """Shipper configuration. Frozen so that no upload/retry code path can
    mutate the limits mid-run (the OPA v1.9.0 buffer-reset regression shape:
    a bug once reset the buffer limit to 32kb *on upload*, silently dropping
    logs -- here that mutation is impossible by construction)."""

    chunk_limit_bytes: int = 1_000_000
    buffer_limit_bytes: int = 5_000_000
    buffer_limit_events: int = 10_000
    max_delay_s: float = 600.0
    min_delay_s: float = 1.0
    backoff_base_s: float = 1.0
    backoff_max_s: float = 300.0
    max_retries: int = 5
    durability: str = "memory"
    journal_path: str | None = None

    def __post_init__(self):
        for name in ("chunk_limit_bytes", "buffer_limit_bytes",
                     "buffer_limit_events"):
            v = getattr(self, name)
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                raise ConfigError("%s must be a positive int" % name)
        for name in ("max_delay_s", "min_delay_s", "backoff_base_s",
                     "backoff_max_s"):
            v = getattr(self, name)
            if not isinstance(v, (int, float)) or isinstance(v, bool) \
                    or v < 0:
                raise ConfigError("%s must be a non-negative number" % name)
        if self.min_delay_s > self.max_delay_s:
            raise ConfigError("min_delay_s must not exceed max_delay_s")
        if not isinstance(self.max_retries, int) or \
                isinstance(self.max_retries, bool) or self.max_retries < 0:
            raise ConfigError("max_retries must be a non-negative int")
        if self.durability not in _DURABILITIES:
            raise ConfigError("durability must be one of %s"
                              % (_DURABILITIES,))
        if self.durability == "disk" and not self.journal_path:
            raise ConfigError("disk durability requires journal_path")


# ---------------------------------------------------------------------------
# Compiled mask plan (the mask-as-compiled-entrypoint discipline)
# ---------------------------------------------------------------------------

_MASKED = object()  # sentinel, never serialized


def _validate_pointers(pointers, what):
    """Compile-time validation of an RFC-6901 pointer list (fail-closed)."""
    if not isinstance(pointers, (list, tuple)):
        raise ConfigError("%s must be a list/tuple of pointers" % what)
    out = []
    for p in pointers:
        if not isinstance(p, str) or not p.startswith("/"):
            raise ConfigError("%s: bad pointer %r (must be a '/'-rooted "
                              "RFC-6901 pointer)" % (what, p))
        out.append(p)
    if len(set(out)) != len(out):
        raise ConfigError("%s: duplicate pointers" % what)
    return tuple(sorted(out))


class CompiledMask:
    """The deployment's redaction policy, compiled once.

    OPA evaluates ``mask_decision`` as a *plan entrypoint* before encoding and
    uploading; here the compiled plan is the exact (erased, masked) pointer
    pair. ``apply`` is the only path into a shipper's buffer: it runs full
    ``verify_event`` (redaction lies -- raw values under a mask claim --
    refused loudly) and demands the event was built under *this* plan. A
    caller cannot smuggle an unmasked event into the buffer.
    """

    def __init__(self, *, erased=(), masked=()):
        self.erased = _validate_pointers(erased, "erased")
        self.masked = _validate_pointers(masked, "masked")
        if set(self.erased) & set(self.masked):
            raise ConfigError("erased and masked must not overlap")

    def apply(self, event):
        """Gate an event into the buffer. Returns the event on success;
        raises IngestError (never buffers) on any failure."""
        if not _dlv2.is_v2_event(event):
            raise IngestError("not a v2 decision event -- the shipping "
                              "buffer only accepts masked v2 events")
        try:
            _dlv2.verify_event(event)
        except _dlv2.DecisionEventError as e:
            raise IngestError("event refused at the mask gate: %s" % (e,))
        if tuple(sorted(event.get("erased", []))) != self.erased or \
                tuple(sorted(event.get("masked", []))) != self.masked:
            raise IngestError(
                "event was not built under this deployment's compiled mask "
                "plan (erased=%r masked=%r) -- mask-before-buffer refused"
                % (self.erased, self.masked))
        return event


# ---------------------------------------------------------------------------
# Canonical bytes (same rules as decision_log_v2._canonical)
# ---------------------------------------------------------------------------

def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise IngestError("event is not JSON-canonicalizable: %s" % (e,))


def _decision_id_for(event):
    """Re-derive the content-derived decision_id (same exclusion rule as
    decision_log_v2: minus ``decision_id`` itself and ``audit``)."""
    preimage = {k: v for k, v in event.items()
                if k not in ("decision_id", "audit")}
    return hashlib.sha256(_canonical(preimage)).hexdigest()


# ---------------------------------------------------------------------------
# The shipper
# ---------------------------------------------------------------------------

_DROP_RTYPE = "drop_record"
_EVENT_RTYPE = "decision_event"
_SHIPPED_RTYPE = "chunk_shipped"


class DecisionShipper:
    """Batches masked v2 decision events and uploads them in chunks.

    ``sink``: callable ``upload(chunk_bytes: bytes) -> int`` returning an
    HTTP-style status code (2xx = accepted). ``audit``: optional list (or any
    object with ``.append``) receiving drop records; the shipper always keeps
    its own ``drop_records`` too.
    """

    def __init__(self, config, mask, sink, *, audit=None, journal=None):
        if not isinstance(config, ShippingConfig):
            raise ConfigError("config must be a ShippingConfig")
        if not isinstance(mask, CompiledMask):
            raise ConfigError("mask must be a CompiledMask")
        if not callable(sink):
            raise ConfigError("sink must be callable")
        self.config = config
        self.mask = mask
        self.sink = sink
        self.audit = audit
        # Buffer entries are (occurrence_id, decision_id, event, size).
        # The occurrence id is a per-ingest sequence number: shipment and
        # drop accounting always address exact occurrences, never
        # decision-id sets (duplicate decision_ids in the buffer must not
        # cause a sibling occurrence to be removed or resurrected).
        self._buffer = []
        self._next_occurrence = 0
        self._buffered_bytes = 0
        self._last_flush = None    # monotonic time of last flush attempt
        self._retry_at = None      # earliest time a requeued chunk may retry
        self._consecutive_failures = 0
        self.shipped_events = 0
        self.dropped_events = 0
        self.upload_failures = 0
        self.chunks_sent = 0
        self.drop_records = []
        # Disk tier: write-through journal (fsync'd at ingest).
        self._journal = journal
        if self._journal is None and config.durability == "disk":
            self._journal = _dj.Journal(config.journal_path)
        if config.durability == "disk":
            self._recover_from_journal()

    # -- ingest -----------------------------------------------------------

    def ingest(self, event):
        """Gate (mask-before-buffer), then buffer or drop loudly.

        Returns a dict ``{"status": "buffered"|"dropped", ...}``. A refused
        event raises IngestError and is never buffered; an accepted-but-
        unshippable event is dropped *loudly* (counter + drop record).
        """
        self.mask.apply(event)  # raises IngestError; buffer never sees it
        event = copy.deepcopy(event)
        self._next_occurrence += 1
        occurrence_id = self._next_occurrence
        payload = _canonical(event)
        if len(payload) > self.config.chunk_limit_bytes:
            event = self._evict_replay(event)
            payload = _canonical(event)
            if len(payload) > self.config.chunk_limit_bytes:
                return self._drop(event, "oversize", len(payload),
                                  occurrence_id)
        if (len(self._buffer) + 1 > self.config.buffer_limit_events or
                self._buffered_bytes + len(payload)
                > self.config.buffer_limit_bytes):
            return self._drop(event, "buffer-full", len(payload),
                              occurrence_id)
        if self._journal is not None:
            # Write-through: journal FIRST. If the journal write fails,
            # the event is not buffered -- ingest never claims durability
            # it does not have.
            try:
                self._journal.append(
                    _EVENT_RTYPE,
                    {"event": event, "occurrence_id": occurrence_id})
            except Exception as e:
                raise ShippingError(
                    "disk-tier journal write failed at ingest: %r -- "
                    "event not buffered" % (e,))
        self._buffer.append((occurrence_id, event.get("decision_id"),
                             event, len(payload)))
        self._buffered_bytes += len(payload)
        return {"status": "buffered",
                "decision_id": event.get("decision_id"),
                "occurrence_id": occurrence_id,
                "size_bytes": len(payload)}

    def _evict_replay(self, event):
        """OPA nd_builtin_cache discipline: drop the non-determinism replay
        capture *loudly* when the event cannot fit a chunk, then re-derive
        the decision_id so the event stays tamper-evident.

        The stub keeps the replay fn name, declares the eviction, and
        commits to the dropped capture via ``capture_digest``. The
        decision content (decision/body/erased/masked) is untouched, so
        the mask gate's guarantees still hold. Note ``verify_event``
        refuses an evicted event loudly (``replay.complete`` is not true)
        -- the eviction is declared, never silently papered over; see
        ``_regat_evicted`` for the recovery-time check.
        """
        event = copy.deepcopy(event)
        original = event.get("replay", {})
        fn_name = original.get("fn") if isinstance(original, dict) else None
        event["replay"] = {
            "fn": fn_name,
            "complete": "evicted",
            "evicted": True,
            "reason": "oversize-event: replay capture dropped to fit "
                      "the upload chunk limit",
            "capture_digest": hashlib.sha256(
                _canonical(original)).hexdigest(),
        }
        evictions = list(event.get("shipping_evictions", []))
        if "replay" not in evictions:
            evictions.append("replay")
        event["shipping_evictions"] = sorted(evictions)
        event["decision_id"] = _decision_id_for(event)
        return event

    def _regat_evicted(self, event):
        """Recovery-time gate for evicted events.

        The full mask gate (``verify_event``) cannot run without the
        dropped capture -- by design it refuses evicted events loudly.
        This re-gate checks what *can* still be checked: the event is a
        v2 event, it was built under this deployment's mask plan, the
        eviction is declared, and the decision_id binding re-derives
        (tamper-evident). Raises IngestError otherwise.
        """
        if not _dlv2.is_v2_event(event):
            raise IngestError("not a v2 decision event on recovery")
        if tuple(sorted(event.get("erased", []))) != self.mask.erased or \
                tuple(sorted(event.get("masked", []))) != self.mask.masked:
            raise IngestError("recovered event was not built under this "
                              "deployment's compiled mask plan")
        replay = event.get("replay")
        if not isinstance(replay, dict) or replay.get("evicted") is not True \
                or "replay" not in event.get("shipping_evictions", []):
            raise IngestError("recovered event has no declared eviction")
        recorded = event.get("decision_id")
        if not recorded or recorded != _decision_id_for(event):
            raise IngestError("recovered event decision_id does not "
                              "re-derive (tampered?)")

    def _drop(self, event, reason, size_bytes, occurrence_id=None):
        self.dropped_events += 1
        record = {
            "kind": "drop-record",
            "decision_id": event.get("decision_id"),
            "occurrence_id": occurrence_id,
            "reason": reason,
            "size_bytes": size_bytes,
            "dropped_total": self.dropped_events,
            "at": int(time.time()),
        }
        self.drop_records.append(record)
        if self._journal is not None:
            try:
                self._journal.append(_DROP_RTYPE, record)
            except Exception:
                # The drop is already decided; a journal failure must not
                # resurrect the event. The in-memory counter/record plus
                # the audit callback remain as the loud accounting.
                pass
        if self.audit is not None:
            try:
                self.audit.append(record)
            except Exception:
                pass  # the shipper's own counter/record is authoritative
        return {"status": "dropped", "reason": reason,
                "decision_id": event.get("decision_id"),
                "drop_record": record}

    # -- flushing ---------------------------------------------------------

    def _chunk_up(self):
        """Pack buffered events into chunks of at most chunk_limit_bytes
        (soft limit: an event that survived ingest always fits)."""
        chunks, current, current_bytes = [], [], 0
        for occurrence_id, decision_id, event, size in self._buffer:
            if current and current_bytes + size > \
                    self.config.chunk_limit_bytes:
                chunks.append(current)
                current, current_bytes = [], 0
            current.append((occurrence_id, decision_id, event, size))
            current_bytes += size
        if current:
            chunks.append(current)
        return chunks

    def _chunk_bytes(self, chunk):
        return b"\n".join(_canonical(event) for _, _, event, _ in chunk)

    def flush(self, now=None):
        """Upload every buffered chunk. Returns a summary dict.

        Non-2xx: the chunk is requeued (stays in the buffer) with
        exponential backoff; after ``max_retries`` consecutive failures the
        chunk is dropped loudly. ``now`` is injectable for tests; the
        freshness cadence in ``maybe_flush`` passes its clock through so
        both use the same time base.
        """
        now = time.monotonic() if now is None else now
        if self._retry_at is not None and now < self._retry_at:
            return {"status": "backoff",
                    "retry_in_s": self._retry_at - now}
        self._last_flush = now
        if not self._buffer:
            return {"status": "empty"}
        summary = {"status": "flushed", "chunks": [], "shipped": 0,
                   "requeued": 0, "dropped": 0}
        for chunk in self._chunk_up():
            body = self._chunk_bytes(chunk)
            try:
                status = int(self.sink(body))
            except Exception as e:
                raise SinkError("sink raised: %r" % (e,))
            if 200 <= status < 300:
                self._mark_shipped(chunk)
                self._consecutive_failures = 0
                self._retry_at = None
                summary["chunks"].append(
                    {"status": status, "events": len(chunk),
                     "occurrence_ids": [o for o, _, _, _ in chunk]})
                summary["shipped"] += len(chunk)
            else:
                self.upload_failures += 1
                self._consecutive_failures += 1
                if self._consecutive_failures > self.config.max_retries:
                    dropped = self._drop_chunk(chunk, status)
                    summary["chunks"].append(
                        {"status": status, "dropped": len(chunk)})
                    summary["dropped"] += dropped
                    self._consecutive_failures = 0
                    self._retry_at = None
                else:
                    backoff = min(self.config.backoff_base_s *
                                  (2 ** (self._consecutive_failures - 1)),
                                  self.config.backoff_max_s)
                    # Same clock as the injected ``now`` -- a fake clock
                    # in tests must not stall or skip the backoff.
                    self._retry_at = now + backoff
                    summary["chunks"].append(
                        {"status": status, "requeued": len(chunk),
                         "backoff_s": backoff})
                    summary["requeued"] += len(chunk)
        return summary

    def _mark_shipped(self, chunk):
        """Remove exactly this chunk's occurrences (never a decision-id
        set: duplicate decision_ids elsewhere in the buffer are untouched).

        At-least-once honesty (disk tier): the sink ack is recorded in the
        journal *after* the buffer removal. A crash in between resurrects
        the chunk on recovery and it is shipped again -- duplicates are
        possible, silent loss is not.
        """
        occs = set(o for o, _, _, _ in chunk)
        self._buffer = [(o, d, e, s) for o, d, e, s in self._buffer
                        if o not in occs]
        self._buffered_bytes = sum(s for _, _, _, s in self._buffer)
        self.shipped_events += len(chunk)
        self.chunks_sent += 1
        if self._journal is not None:
            try:
                self._journal.append(
                    _SHIPPED_RTYPE,
                    {"decision_ids": [d for _, d, _, _ in chunk],
                     "occurrence_ids": sorted(occs),
                     "chunk_digest": hashlib.sha256(
                         self._chunk_bytes(chunk)).hexdigest()})
            except Exception:
                # The ack already happened; a journal failure here is the
                # documented at-least-once window (recovery will reship).
                pass

    def _drop_chunk(self, chunk, status):
        occs = set(o for o, _, _, _ in chunk)
        self._buffer = [(o, d, e, s) for o, d, e, s in self._buffer
                        if o not in occs]
        self._buffered_bytes = sum(s for _, _, _, s in self._buffer)
        for occurrence_id, _decision_id, event, size in chunk:
            self._drop(event, "sink-unavailable(status=%s)" % (status,),
                       size, occurrence_id)
        return len(chunk)

    def maybe_flush(self, now=None):
        """Freshness cadence: flush when ``max_delay_s`` has elapsed since
        the last flush, or when the buffer holds data and this is the first
        flush. ``min_delay_s`` floors automatic flushes (manual ``flush``
        bypasses it)."""
        now = time.monotonic() if now is None else now
        if not self._buffer:
            return {"status": "empty"}
        if self._last_flush is None:
            return self.flush(now=now)
        elapsed = now - self._last_flush
        if elapsed < self.config.min_delay_s:
            # min_delay_s floors automatic flushes (manual flush bypasses).
            return {"status": "fresh",
                    "next_flush_in_s": self.config.max_delay_s - elapsed}
        if elapsed >= self.config.max_delay_s:
            return self.flush(now=now)
        return {"status": "fresh",
                "next_flush_in_s": self.config.max_delay_s - elapsed}

    # -- unbuffered tier ----------------------------------------------------

    def run_unbuffered(self, event, action_fn):
        """Unbuffered durability: the event is written and THIS event's
        chunk is acknowledged by the sink *before* ``action_fn`` runs. An
        ack for any other buffered chunk (e.g. a leftover from an earlier
        run) never releases the action. If the sink never acknowledges
        this event's chunk (retry budget exhausted), the action NEVER runs
        and the event is dropped loudly; raises SinkError.

        Only meaningful on a shipper whose durability is ``unbuffered``;
        calling it on another tier raises ConfigError (the tier choice is
        explicit, not emergent).
        """
        if self.config.durability != "unbuffered":
            raise ConfigError("run_unbuffered requires durability="
                              "'unbuffered' (this shipper is %r)"
                              % (self.config.durability,))
        result = self.ingest(event)
        if result["status"] != "buffered":
            raise SinkError("unbuffered ingest dropped the event: %s"
                            % (result["reason"],))
        occurrence_id = result["occurrence_id"]
        summary = self.flush()
        # Per-occurrence ack: the action runs only if THIS event's chunk
        # was acknowledged -- an ack for some other buffered chunk (e.g. a
        # leftover from an earlier run) must never release the action.
        acked = any(200 <= c.get("status", 0) < 300 and
                    occurrence_id in c.get("occurrence_ids", ())
                    for c in summary.get("chunks", []))
        if not acked:
            raise SinkError("unbuffered action refused: the log write for "
                            "this event was not acknowledged (sink "
                            "summary: %s)" % (summary,))
        return action_fn()

    # -- disk-tier recovery --------------------------------------------------

    def _recover_from_journal(self):
        """Rebuild the buffer from the write-through journal.

        Every ``decision_event`` record is re-buffered (re-gated through
        the compiled mask) UNLESS it is covered by a later ``chunk_shipped``
        record (addressed by occurrence id, so duplicate decision_ids are
        handled exactly) or by a ``drop_record`` -- a deliberately dropped
        event is never resurrected on restart (the drop is the terminal
        state, and it was already accounted loudly).
        """
        journal = self._journal
        pending = []
        shipped_occs, dropped_occs = set(), set()
        shipped_decision_ids, dropped_decision_ids = set(), set()
        for rec in journal.records:
            rtype, body = rec.get("type"), rec.get("body", {})
            if rtype == _EVENT_RTYPE and isinstance(body, dict):
                event = body.get("event")
                if isinstance(event, dict) and event.get("decision_id"):
                    # One entry per journaled ingest (no dedupe): every
                    # ingest is replayed unless covered below.
                    pending.append((rec.get("seq", 0),
                                    body.get("occurrence_id"),
                                    event["decision_id"], event))
            elif rtype == _SHIPPED_RTYPE and isinstance(body, dict):
                occs = body.get("occurrence_ids")
                if occs:
                    shipped_occs.update(occs)
                else:
                    # Legacy records predate occurrence ids.
                    shipped_decision_ids.update(
                        body.get("decision_ids", ()))
            elif rtype == _DROP_RTYPE and isinstance(body, dict):
                occ = body.get("occurrence_id")
                if occ is not None:
                    dropped_occs.add(occ)
                elif body.get("decision_id"):
                    dropped_decision_ids.add(body["decision_id"])
        for _seq, occurrence_id, decision_id, event in sorted(pending):
            if occurrence_id is not None:
                # Never reuse an occurrence id across the restart: new
                # ingests must not collide with recovered ones.
                self._next_occurrence = max(self._next_occurrence,
                                            occurrence_id)
                if occurrence_id in shipped_occs or \
                        occurrence_id in dropped_occs:
                    continue
            elif decision_id in shipped_decision_ids or \
                    decision_id in dropped_decision_ids:
                continue
            try:
                if event.get("shipping_evictions"):
                    self._regat_evicted(event)
                else:
                    self.mask.apply(event)
            except IngestError:
                # A journaled event that no longer passes the gate is
                # dropped loudly, not silently resurrected.
                self._drop(event, "gate-failed-on-recovery",
                           len(_canonical(event)), occurrence_id)
                continue
            payload = _canonical(event)
            if (len(self._buffer) + 1 > self.config.buffer_limit_events or
                    self._buffered_bytes + len(payload) >
                    self.config.buffer_limit_bytes):
                self._drop(event, "buffer-full-on-recovery",
                           len(payload), occurrence_id)
                continue
            self._buffer.append((occurrence_id, decision_id, event,
                                 len(payload)))
            self._buffered_bytes += len(payload)

    # -- introspection ------------------------------------------------------

    @property
    def buffered_events(self):
        return len(self._buffer)

    @property
    def buffered_bytes(self):
        return self._buffered_bytes

    def stats(self):
        return {
            "buffered_events": self.buffered_events,
            "buffered_bytes": self.buffered_bytes,
            "shipped_events": self.shipped_events,
            "dropped_events": self.dropped_events,
            "upload_failures": self.upload_failures,
            "chunks_sent": self.chunks_sent,
        }
