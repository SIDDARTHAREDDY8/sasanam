#!/usr/bin/env python3
"""CAEP/SSF-style revocation event intake with a session kill channel.

ADAPT of the OpenID Shared Signals Framework / Continuous Access
Evaluation Profile pattern (re-derived prose; nothing copied): security
events flow from transmitter to receiver as TYPED event envelopes --
event-type URIs, a subject, a unique event id, timestamps -- and the
receiver fans each event out to the sessions bound to that subject.
Closes F417: revocation was decision-time-only (``gov/revocation.py``
``check()`` consulted only when a decision point called it); an
in-flight session whose credential was revoked mid-flight kept
executing. This module is the push half: a revocation event now
terminates bound in-flight sessions promptly, instead of waiting for
the next decision point.

Wire shape (SSF-inspired; our own enforcement semantics, stdlib only,
no JWT -- the repo is stdlib-only):

    {
      "event_id": "<unique id, [A-Za-z0-9_-]{8,128}>",   # jti analog
      "event_type": "urn:sasanam:revocation-push:credential-revoked"
                  | "urn:sasanam:revocation-push:mission-cancelled"
                  | "urn:sasanam:revocation-push:agent-deauthorized",
      "subject": {"kind": "credential"|"agent"|"mission",
                  "id": "<opaque, non-empty, <=512 chars>"},
      "issued_at": <unix epoch, int/float, not bool>,
      "reason": "<optional human string>",
      "sig": "<hex HMAC-SHA256 over the canonical body>",  # see below
    }

Our enforcement semantics (these differ from CAEP's transport model):

- Subject matching is EXACT on (kind, id). Never prefix, never class,
  never wildcard -- the same exact-target discipline as
  ``gov/revocation.py``. A revocation event for one agent never touches
  another agent's sessions.
- Event authentication: the hub is constructed with an HMAC key and
  ``require_signed_events=True`` by DEFAULT. An unauthenticated kill
  channel is a session-DoS vector (anyone who can deliver an event can
  kill sessions), so unsigned events refuse coded
  ``revocation-push-event-unsigned`` unless the deployment explicitly
  opts out (``require_signed_events=False`` -- loud, documented, and
  the deployment's own risk to own).
- Ingestion is synchronous and total: ``ingest()`` never raises for a
  well-formed-but-hostile event; it returns an ``IngestReceipt`` dict
  carrying a machine ``code``. Malformed events refuse coded
  ``revocation-push-event-malformed`` (raised -- the caller sent
  garbage; there is nothing to receipt).
- Replay is idempotent: a bounded set of seen ``event_id``s is kept.
  Re-ingesting an ``event_id`` returns the ORIGINAL receipt with
  ``duplicate: True`` and code ``revocation-push-event-replayed``;
  bound sessions are NOT re-terminated and callbacks fire exactly once.
- Termination FAILS CLOSED. Each registered session supplies an
  ``on_terminate(reason)`` callback and may supply a ``liveness()``
  probe. ``ingest()`` marks the session ``terminating``, calls the
  callback, then checks liveness. If the callback raises, or the
  liveness probe reports the session did not stop, the session is
  marked ``suspended`` -- NOT live, NOT silently terminated.
  ``require_live()`` refuses coded
  ``revocation-push-session-suspended`` for suspended sessions. A kill
  that cannot be confirmed never lets the session continue silently.
- ``require_live(session_id)`` is the per-step gate deployments call
  between steps of an in-flight session. Unknown (never-registered)
  sessions refuse coded ``revocation-push-session-unknown`` -- liveness
  of something never registered cannot be proven.

Thread safety: all hub mutations run under one lock; callbacks run
under the lock too (callbacks must not re-enter the hub -- documented;
re-entry raises ``revocation-push-refused`` via the re-entrancy guard).

Stdlib only. No network. $0.
"""

import hashlib
import hmac
import json
import re
import threading
import time
from collections import OrderedDict

# ----------------------------------------------------------------------
# Error vocabulary. Every emitted machine code is registered in
# gov/decision_codes.py (domain ``revocation-push``).
# ----------------------------------------------------------------------


class RevocationPushError(Exception):
    """Base class for all revocation-push refusals. ``code`` is
    machine-readable."""

    code = "revocation-push-refused"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class RevocationPushEventMalformedError(RevocationPushError):
    """The event envelope violates the typed schema."""

    code = "revocation-push-event-malformed"


class RevocationPushEventUnsignedError(RevocationPushError):
    """Signature required but missing or invalid."""

    code = "revocation-push-event-unsigned"


class RevocationPushSessionSuspendedError(RevocationPushError):
    """The kill could not be confirmed; the session is suspended
    fail-closed and may not continue."""

    code = "revocation-push-session-suspended"


class RevocationPushSessionTerminatedError(RevocationPushError):
    """The session was terminated by a revocation event."""

    code = "revocation-push-session-terminated"


class RevocationPushUnknownSessionError(RevocationPushError):
    """``require_live`` on a session id the hub never registered."""

    code = "revocation-push-session-unknown"


# ----------------------------------------------------------------------
# Schema.
# ----------------------------------------------------------------------

_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

EVENT_TYPES = (
    "urn:sasanam:revocation-push:credential-revoked",
    "urn:sasanam:revocation-push:mission-cancelled",
    "urn:sasanam:revocation-push:agent-deauthorized",
)

SUBJECT_KINDS = ("credential", "agent", "mission")

_SUBJECT_ID_MAX = 512
_FUTURE_SKEW_S = 300.0
_SIG_DOMAIN = b"sasanam-revocation-push/v1:"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def _sign_body(hmac_key, body):
    """HMAC-SHA256 hex over the canonical body (everything but ``sig``)."""
    return hmac.new(hmac_key, _SIG_DOMAIN + _canonical(body).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _check_event_schema(event):
    """Validate the typed envelope. Raises
    RevocationPushEventMalformedError (coded) on any violation."""
    def bad(why):
        raise RevocationPushEventMalformedError(
            "revocation-push-event-malformed: %s" % why)

    if not isinstance(event, dict):
        bad("event is not a record (got %s)" % type(event).__name__)
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not _EVENT_ID_RE.match(event_id):
        bad("event_id must match [A-Za-z0-9_-]{8,128}")
    event_type = event.get("event_type")
    if event_type not in EVENT_TYPES:
        bad("event_type must be one of %s" % (", ".join(EVENT_TYPES),))
    subject = event.get("subject")
    if not isinstance(subject, dict):
        bad("subject must be a record")
    kind = subject.get("kind")
    if kind not in SUBJECT_KINDS:
        bad("subject.kind must be one of %s" % (", ".join(SUBJECT_KINDS),))
    sid = subject.get("id")
    if not isinstance(sid, str) or not sid or len(sid) > _SUBJECT_ID_MAX:
        bad("subject.id must be a non-empty string <= %d chars"
            % _SUBJECT_ID_MAX)
    issued_at = event.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)):
        bad("issued_at must be a unix epoch number")
    reason = event.get("reason")
    if reason is not None and not isinstance(reason, str):
        bad("reason must be a string when present")
    sig = event.get("sig")
    if sig is not None and (not isinstance(sig, str) or not sig):
        bad("sig must be a non-empty string when present")
    # Unknown extra fields are ignored (documented); only the typed
    # fields above carry semantics.
    return {
        "event_id": event_id,
        "event_type": event_type,
        "subject": {"kind": kind, "id": sid},
        "issued_at": float(issued_at),
        "reason": reason if isinstance(reason, str) else "",
    }


# ----------------------------------------------------------------------
# Hub.
# ----------------------------------------------------------------------

_STATUS_LIVE = "live"
_STATUS_TERMINATED = "terminated"
_STATUS_SUSPENDED = "suspended"
_STATUS_UNKNOWN = "unknown"


class _SessionRecord(object):
    __slots__ = ("session_id", "subjects", "on_terminate", "liveness",
                 "status", "terminated_by", "terminated_at")

    def __init__(self, session_id, subjects, on_terminate, liveness):
        self.session_id = session_id
        self.subjects = subjects  # list of (kind, id)
        self.on_terminate = on_terminate
        self.liveness = liveness
        self.status = _STATUS_LIVE
        self.terminated_by = None
        self.terminated_at = None


class RevocationPushHub(object):
    """In-memory CAEP/SSF-style revocation event intake.

    ``hmac_key``: 32-byte deployment key for event authentication.
    Required when ``require_signed_events`` is True (the default);
    ``None`` is allowed only with ``require_signed_events=False``.
    ``audit``: optional callable taking an event dict.
    ``clock``: injectable for tests; defaults to ``time.time``.
    ``max_seen_events``: bound on the replay cache (default 10000).
    """

    def __init__(self, *, hmac_key=None, require_signed_events=True,
                 clock=None, audit=None, max_seen_events=10000):
        if require_signed_events:
            if not isinstance(hmac_key, (bytes, bytearray)) \
                    or len(hmac_key) != 32:
                raise RevocationPushError(
                    "revocation-push-refused: require_signed_events=True "
                    "needs a 32-byte hmac_key")
        elif hmac_key is not None and (
                not isinstance(hmac_key, (bytes, bytearray))
                or len(hmac_key) != 32):
            raise RevocationPushError(
                "revocation-push-refused: hmac_key must be 32 bytes")
        if not isinstance(max_seen_events, int) or max_seen_events < 1:
            raise RevocationPushError(
                "revocation-push-refused: max_seen_events must be >= 1")
        self._hmac_key = bytes(hmac_key) if hmac_key is not None else None
        self._require_signed = bool(require_signed_events)
        self._clock = clock if clock is not None else time.time
        self._audit = audit
        self._max_seen = max_seen_events
        self._lock = threading.RLock()
        self._in_callback = False
        self._sessions = {}
        self._seen = OrderedDict()  # event_id -> IngestReceipt

    # -- audit ---------------------------------------------------------
    def _emit_audit(self, record):
        if self._audit is not None:
            try:
                self._audit(dict(record))
            except Exception:
                # Audit is evidence, never control: a failing sink must
                # not break the kill channel.
                pass

    # -- sessions ------------------------------------------------------
    def register_session(self, session_id, subjects, *, on_terminate=None,
                         liveness=None):
        """Bind an in-flight session to subjects.

        ``subjects``: non-empty list of ``{"kind","id"}`` records.
        ``on_terminate(reason)``: called synchronously at ingest when a
        revocation event matches; must not re-enter the hub.
        ``liveness()``: optional zero-arg probe returning truthy while
        the session is alive; after ``on_terminate`` it must report
        falsy or the session is suspended fail-closed.
        """
        with self._lock:
            if self._in_callback:
                raise RevocationPushError(
                    "revocation-push-refused: hub re-entry from a "
                    "terminate callback is refused")
            if not isinstance(session_id, str) or not session_id:
                raise RevocationPushError(
                    "revocation-push-refused: session_id must be a "
                    "non-empty string")
            if session_id in self._sessions:
                # Re-registration would let a caller swap in a no-op
                # on_terminate and neuter the kill channel: refuse.
                raise RevocationPushError(
                    "revocation-push-refused: session_id %r already "
                    "registered" % (session_id,))
            norm = []
            if not isinstance(subjects, (list, tuple)) or not subjects:
                raise RevocationPushError(
                    "revocation-push-refused: subjects must be a "
                    "non-empty list")
            for s in subjects:
                if not isinstance(s, dict) or s.get("kind") not in \
                        SUBJECT_KINDS:
                    raise RevocationPushError(
                        "revocation-push-refused: subject kind must be "
                        "one of %s" % (", ".join(SUBJECT_KINDS),))
                sid = s.get("id")
                if not isinstance(sid, str) or not sid \
                        or len(sid) > _SUBJECT_ID_MAX:
                    raise RevocationPushError(
                        "revocation-push-refused: subject id must be a "
                        "non-empty string <= %d chars" % _SUBJECT_ID_MAX)
                norm.append((s["kind"], sid))
            if on_terminate is not None and not callable(on_terminate):
                raise RevocationPushError(
                    "revocation-push-refused: on_terminate must be callable")
            if liveness is not None and not callable(liveness):
                raise RevocationPushError(
                    "revocation-push-refused: liveness must be callable")
            self._sessions[session_id] = _SessionRecord(
                session_id, norm, on_terminate, liveness)
            self._emit_audit({"event": "session-registered",
                              "session_id": session_id,
                              "subjects": [{"kind": k, "id": i}
                                           for k, i in norm]})
            return {"session_id": session_id, "status": _STATUS_LIVE}

    def unregister_session(self, session_id):
        """Remove a session (clean shutdown path). Returns True when a
        registration existed."""
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def session_status(self, session_id):
        """Never raises: live | terminated | suspended | unknown."""
        with self._lock:
            rec = self._sessions.get(session_id)
            return rec.status if rec is not None else _STATUS_UNKNOWN

    def require_live(self, session_id):
        """Per-step gate for in-flight sessions. Returns True only for
        live sessions; raises coded otherwise. Unknown sessions refuse:
        liveness of something never registered cannot be proven."""
        with self._lock:
            rec = self._sessions.get(session_id)
            if rec is None:
                raise RevocationPushUnknownSessionError(
                    "revocation-push-session-unknown: %r was never "
                    "registered" % (session_id,))
            if rec.status == _STATUS_LIVE:
                return True
            if rec.status == _STATUS_SUSPENDED:
                raise RevocationPushSessionSuspendedError(
                    "revocation-push-session-suspended: %r kill "
                    "unconfirmed; suspended fail-closed" % (session_id,))
            raise RevocationPushSessionTerminatedError(
                "revocation-push-session-terminated: %r terminated by %s"
                % (session_id, rec.terminated_by))

    # -- events --------------------------------------------------------
    def _check_signature(self, event, body):
        if not self._require_signed:
            return
        sig = event.get("sig")
        if not isinstance(sig, str) or not sig:
            raise RevocationPushEventUnsignedError(
                "revocation-push-event-unsigned: this hub requires "
                "signed events")
        try:
            want = _sign_body(self._hmac_key, body)
        except Exception:
            raise RevocationPushEventUnsignedError(
                "revocation-push-event-unsigned: signature computation "
                "failed")
        if not hmac.compare_digest(sig, want):
            raise RevocationPushEventUnsignedError(
                "revocation-push-event-unsigned: bad signature")

    def ingest(self, event):
        """Intake one revocation event; fan out to bound sessions.

        Returns an IngestReceipt dict (never raises for a schema-valid
        event). Schema violations raise
        RevocationPushEventMalformedError (coded); signature failures
        raise RevocationPushEventUnsignedError (coded).
        """
        body = _check_event_schema(event)
        now = float(self._clock())
        if body["issued_at"] > now + _FUTURE_SKEW_S:
            raise RevocationPushEventMalformedError(
                "revocation-push-event-malformed: issued_at is more "
                "than %ds in the future" % int(_FUTURE_SKEW_S))
        self._check_signature(event, body)
        event_id = body["event_id"]

        with self._lock:
            if self._in_callback:
                raise RevocationPushError(
                    "revocation-push-refused: hub re-entry from a "
                    "terminate callback is refused")
            seen = self._seen.get(event_id)
            if seen is not None:
                # Idempotent replay: original receipt, duplicate flag,
                # no re-termination, callbacks fire exactly once.
                dup = dict(seen)
                dup["duplicate"] = True
                dup["code"] = "revocation-push-event-replayed"
                return dup

            kind, sid = body["subject"]["kind"], body["subject"]["id"]
            matched = [rec for rec in self._sessions.values()
                       if rec.status == _STATUS_LIVE
                       and (kind, sid) in rec.subjects]
            outcomes = []
            for rec in matched:
                outcomes.append(self._terminate_locked(rec, body))

            if matched:
                code = "revocation-push-session-terminated"
            else:
                code = "revocation-push-subject-unbound"
            receipt = {
                "code": code,
                "event_id": event_id,
                "event_type": body["event_type"],
                "subject": dict(body["subject"]),
                "duplicate": False,
                "terminated": [o["session_id"] for o in outcomes
                               if o["outcome"] == _STATUS_TERMINATED],
                "suspended": [o["session_id"] for o in outcomes
                              if o["outcome"] == _STATUS_SUSPENDED],
                "outcomes": outcomes,
            }
            self._seen[event_id] = dict(receipt)
            while len(self._seen) > self._max_seen:
                self._seen.popitem(last=False)
            self._emit_audit({"event": "revocation-event-ingested",
                              "receipt": {k: v for k, v in receipt.items()
                                          if k != "outcomes"}})
            return receipt

    def _terminate_locked(self, rec, body):
        """Terminate one session. Fail-closed: any doubt suspends."""
        reason = ("revocation event %s (%s) for %s:%s"
                  % (body["event_id"], body["event_type"],
                     body["subject"]["kind"], body["subject"]["id"]))
        if body["reason"]:
            reason += ": " + body["reason"][:200]
        outcome = _STATUS_TERMINATED
        detail = ""
        self._in_callback = True
        try:
            if rec.on_terminate is not None:
                try:
                    rec.on_terminate(reason)
                except Exception as exc:
                    # The kill callback failed: we cannot confirm the
                    # session stopped. Suspend fail-closed -- never let
                    # it continue on an unconfirmed kill.
                    outcome = _STATUS_SUSPENDED
                    detail = "on_terminate raised %s: %s" % (
                        type(exc).__name__, exc)
            if outcome == _STATUS_TERMINATED and rec.liveness is not None:
                try:
                    alive = rec.liveness()
                except Exception as exc:
                    outcome = _STATUS_SUSPENDED
                    detail = "liveness probe raised %s: %s" % (
                        type(exc).__name__, exc)
                else:
                    if alive:
                        # The session reports it is STILL ALIVE after
                        # the terminate callback ran: the kill did not
                        # take. Suspend fail-closed.
                        outcome = _STATUS_SUSPENDED
                        detail = ("liveness probe still reports alive "
                                  "after on_terminate")
        finally:
            self._in_callback = False
        rec.status = outcome
        rec.terminated_by = body["event_id"]
        rec.terminated_at = float(self._clock())
        self._emit_audit({"event": "session-" + outcome,
                          "session_id": rec.session_id,
                          "event_id": body["event_id"],
                          "detail": detail})
        return {"session_id": rec.session_id, "outcome": outcome,
                "detail": detail}


def sign_event(hmac_key, event):
    """Attach ``sig`` to an event dict (transmitter side helper). The
    event must already satisfy the schema minus ``sig``. Returns a new
    dict; the input is not mutated."""
    body = _check_event_schema(event)
    if not isinstance(hmac_key, (bytes, bytearray)) \
            or len(hmac_key) != 32:
        raise RevocationPushError(
            "revocation-push-refused: hmac_key must be 32 bytes")
    out = dict(event)
    out["sig"] = _sign_body(bytes(hmac_key), body)
    return out


def registered_codes():
    """The machine codes this module emits (for the taxonomy check)."""
    return (
        "revocation-push-refused",
        "revocation-push-event-malformed",
        "revocation-push-event-unsigned",
        "revocation-push-event-replayed",
        "revocation-push-session-terminated",
        "revocation-push-session-suspended",
        "revocation-push-session-unknown",
        "revocation-push-subject-unbound",
    )
