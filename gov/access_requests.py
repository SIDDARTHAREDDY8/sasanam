"""State-machined access-request records + ephemeral TTL-bound grant minting.

Teleport ``api/``-module ADAPT (mechanism shapes only — the Teleport
workflow engine is AGPLv3 and off-limits; no Teleport code vendored).

An access request is a durable-by-construction record that moves through
the state machine::

    PENDING -> APPROVED | DENIED | EXPIRED

Every record carries: the requestor, the requested grants (tool scopes),
a mandatory reason, approve/deny reviewer thresholds, suggested
reviewers, and a max-duration. Transitions are fail-closed:

- self-review (requestor approving their own request) is refused;
- only ``suggested_reviewers`` may review when the set is non-empty;
- a reviewer votes at most once;
- nothing may be decided on a terminal (APPROVED/DENIED/EXPIRED) request;
- expiry is computed at read time (no live timers): a PENDING request
  past ``created_at + max_duration`` transitions to EXPIRED the moment
  anyone touches it.

Grant-as-reissued-identity: an APPROVED request mints ephemeral,
TTL-bound :class:`gov.ephemeral_grants.ContextualTuple` grants --
``valid_until = approved_at + max_duration`` -- scoped to the requested
tools only. There are no standing capabilities: a grant cannot exist for
a request that was never approved, and it dies at expiry with no
revocation list.

Decision<->evidence join key: every transition is appended as an
``access-request-event`` into the HMAC ``ActionLog`` AT DECISION TIME
(never batched), chained per writer via ``prev_access_request_digest``.
Each record carries ``join_key`` = the request id, so an auditor can
join the decision (request events) to the evidence (grant-issued events
and grant-decision records) without the engine, and
:func:`replay_state` re-derives the request state by folding the events.

Stdlib only.
"""

import hashlib
import json
import math
import secrets
import time

from gov import ephemeral_grants as _eg

# ---------------------------------------------------------------------------
# Errors: code-first subclasses, machine-readable ``code`` (repo convention:
# callers branch on ``code``, never on message text). Each class-level
# ``code`` is inventoried by the decision-code vocabulary scan and
# registered in gov/decision_codes.py.
# ---------------------------------------------------------------------------


class AccessRequestError(Exception):
    """Base for access-request state-machine refusals."""


class SelfReviewRefused(AccessRequestError):
    code = "access-request-self-review-refused"

    def __init__(self, detail=""):
        super().__init__("%s: %s" % (self.code, detail))
        self.detail = detail


class TerminalTransitionRefused(AccessRequestError):
    code = "access-request-terminal-refused"

    def __init__(self, detail=""):
        super().__init__("%s: %s" % (self.code, detail))
        self.detail = detail


class GrantNotApprovedRefused(AccessRequestError):
    code = "access-request-grant-refused"

    def __init__(self, detail=""):
        super().__init__("%s: %s" % (self.code, detail))
        self.detail = detail


class ReviewerIneligibleRefused(AccessRequestError):
    code = "access-request-reviewer-ineligible"

    def __init__(self, detail=""):
        super().__init__("%s: %s" % (self.code, detail))
        self.detail = detail


class DuplicateReviewRefused(AccessRequestError):
    code = "access-request-duplicate-review-refused"

    def __init__(self, detail=""):
        super().__init__("%s: %s" % (self.code, detail))
        self.detail = detail


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STATES = ("PENDING", "APPROVED", "DENIED", "EXPIRED")
RECORD_TYPE = "access-request-event"
SCHEMA_VERSION = 1
_GENESIS = "0" * 64
# 24h ceiling on max_duration (HumanLayer stakes precedent).
MAX_DURATION_S = 86400.0
_MAX_REASON_CHARS = 2000
_CONDITION_KEYS = ("valid_until", "max_budget", "arg_digest")

# ---------------------------------------------------------------------------
# Validators (fail-fast: malformed shapes are programming errors)
# ---------------------------------------------------------------------------


def _check_agent(value, what="agent"):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % (what,))
    kind, sep, ident = value.partition(":")
    if not sep or not ident or kind != "agent":
        raise ValueError(
            "%s must be 'agent:<id>', got %r" % (what, value))
    if any(ch.isspace() for ch in value):
        raise ValueError("%s must not contain whitespace: %r" % (what, value))
    return value


def _check_tool(value):
    if not isinstance(value, str) or not value:
        raise ValueError("grant tool must be a non-empty string")
    kind, sep, ident = value.partition(":")
    if not sep or not ident or kind != "tool":
        raise ValueError("grant tool must be 'tool:<name>', got %r" % (value,))
    if any(ch.isspace() for ch in value):
        raise ValueError("grant tool must not contain whitespace: %r"
                         % (value,))
    return value


def _check_conditions(conditions):
    if conditions is None:
        return {}
    if not isinstance(conditions, dict):
        raise ValueError("grant conditions must be a dict, got %r"
                         % (conditions,))
    for key in conditions:
        if key not in _CONDITION_KEYS:
            # Closed vocabulary (no CEL): unknown condition keys are a
            # programming/hostile shape, refused at construction.
            raise ValueError("unknown grant condition %r" % (key,))
    # valid_until is always (re)bound at mint time; arg_digest/max_budget
    # shapes are validated by ContextualTuple at mint.
    return dict(conditions)


def _check_grants(grants):
    if not isinstance(grants, list) or not grants:
        raise ValueError("grants must be a non-empty list")
    out = []
    for g in grants:
        if not isinstance(g, dict) or "tool" not in g:
            raise ValueError("each grant must be a dict with a 'tool' key, "
                             "got %r" % (g,))
        out.append({"tool": _check_tool(g["tool"]),
                    "conditions": _check_conditions(g.get("conditions"))})
    return out


def _check_reason(reason):
    if not isinstance(reason, str) or not reason.strip():
        # Teleport's mandatory reason: a request without a stated reason
        # is not submittable.
        raise ValueError("reason is mandatory and must be non-empty")
    if len(reason) > _MAX_REASON_CHARS:
        raise ValueError("reason exceeds %d chars" % (_MAX_REASON_CHARS,))
    return reason


def _check_duration(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("max_duration_s must be a finite number, got %r"
                         % (value,))
    if not math.isfinite(value) or value <= 0:
        raise ValueError("max_duration_s must be positive and finite, got %r"
                         % (value,))
    if value > MAX_DURATION_S:
        raise ValueError("max_duration_s exceeds the 24h ceiling")
    return float(value)


def _check_threshold(value, what):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("%s must be an int >= 1, got %r" % (what, value))
    return value


def _check_reviewers(reviewers):
    if reviewers is None:
        return []
    if not isinstance(reviewers, (list, tuple)):
        raise ValueError("suggested_reviewers must be a list")
    return [_check_agent(r, "suggested reviewer") for r in reviewers]


def _now(now):
    if now is None:
        return time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)) \
            or not math.isfinite(now):
        raise ValueError("now must be a finite number")
    return float(now)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _digest(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Store: process-local record registry with snapshot/restore (the durability
# seam a future wave persists; cf. the Temporal event-sourcing prospectus).
# ---------------------------------------------------------------------------


class AccessRequestStore(object):
    """Process-local registry of access-request records."""

    def __init__(self):
        self._records = {}

    def get(self, request_id):
        """A deep copy of the record (the state machine is the sole
        mutation path; callers cannot bypass review/thresholds/expiry
        by writing into a live dict)."""
        rec = self._records.get(request_id)
        return json.loads(_canonical(rec)) if rec is not None else None

    def all(self):
        return json.loads(_canonical(self._records))

    def snapshot(self):
        """JSON-safe deep copy of all records (crash-recovery seam)."""
        return {"schema_version": 1,
                "records": json.loads(_canonical(self._records))}

    @classmethod
    def restore(cls, snap):
        """Rebuild a store from :meth:`snapshot`. Malformed -> ValueError."""
        if not isinstance(snap, dict) or snap.get("schema_version") != 1:
            raise ValueError("snapshot must be a dict with schema_version 1")
        records = snap.get("records")
        if not isinstance(records, dict):
            raise ValueError("snapshot records must be a dict")
        store = cls()
        for rid, rec in records.items():
            if not isinstance(rec, dict) or rec.get("request_id") != rid:
                raise ValueError("snapshot record %r is malformed" % (rid,))
            if rec.get("state") not in STATES:
                raise ValueError("snapshot record %r has bad state" % (rid,))
            store._records[rid] = json.loads(_canonical(rec))
        return store


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def _live_record(store, request_id):
    """The store's live record dict (internal mutation path only).

    Public :meth:`AccessRequestStore.get` returns deep copies; the
    lifecycle functions below are the sole writers.
    """
    return store._records.get(request_id)


def _record_digest(payload):
    return _digest(_canonical(payload))


def submit(store, requestor, grants, reason, max_duration_s, *,
           approve_threshold=1, deny_threshold=1, suggested_reviewers=(),
           now=None, writer=None):
    """Create a PENDING access request. Returns the record dict.

    Malformed shapes raise ValueError (programming errors). The
    ``submitted`` transition is appended to the audit log at decision
    time when ``writer`` is given.
    """
    if not isinstance(store, AccessRequestStore):
        raise ValueError("store must be an AccessRequestStore")
    requestor = _check_agent(requestor, "requestor")
    grants = _check_grants(grants)
    reason = _check_reason(reason)
    max_duration_s = _check_duration(max_duration_s)
    approve_threshold = _check_threshold(approve_threshold,
                                         "approve_threshold")
    deny_threshold = _check_threshold(deny_threshold, "deny_threshold")
    suggested_reviewers = _check_reviewers(suggested_reviewers)
    now = _now(now)

    request_id = "ar_" + secrets.token_hex(16)
    record = {
        "request_id": request_id,
        "requestor": requestor,
        "grants": grants,
        "reason": reason,
        "max_duration_s": max_duration_s,
        "approve_threshold": approve_threshold,
        "deny_threshold": deny_threshold,
        "suggested_reviewers": suggested_reviewers,
        "state": "PENDING",
        "created_at": now,
        "decided_at": None,
        "reviews": [],
    }
    record["request_digest"] = _record_digest({
        k: v for k, v in record.items() if k != "request_digest"})
    store._records[request_id] = record
    if writer is not None:
        writer.record("submitted", request_id, {
            "requestor": requestor,
            "grants": grants,
            "reason_digest": _digest(reason),
            "max_duration_s": max_duration_s,
            "approve_threshold": approve_threshold,
            "deny_threshold": deny_threshold,
            "suggested_reviewers": suggested_reviewers,
            "created_at": now,
            "request_digest": record["request_digest"],
        })
    return json.loads(_canonical(record))


def _resolve_expiry(store, record, now, writer):
    """Read-time expiry: no live timers (Temporal prospectus lesson).

    A PENDING request past ``created_at + max_duration`` transitions to
    EXPIRED the moment it is touched. Returns the (possibly new) state.
    """
    if record["state"] == "PENDING" and \
            now > record["created_at"] + record["max_duration_s"]:
        record["state"] = "EXPIRED"
        record["decided_at"] = now
        if writer is not None:
            writer.record("expired", record["request_id"], {
                "created_at": record["created_at"],
                "max_duration_s": record["max_duration_s"],
                "expired_at": now,
            })
    return record["state"]


def resolve(store, request_id, now, writer=None):
    """Apply read-time expiry and return the request state."""
    if not isinstance(store, AccessRequestStore):
        raise ValueError("store must be an AccessRequestStore")
    record = _live_record(store, request_id)
    if record is None:
        raise ValueError("unknown request_id %r" % (request_id,))
    now = _now(now)
    return _resolve_expiry(store, record, now, writer)


def review(store, request_id, reviewer, approve, note="", *, now=None,
           writer=None):
    """Cast one review vote. Returns the (possibly new) state.

    Refusals (all fail-closed, machine-readable codes):
    - reviewer is the requestor -> ``access-request-self-review-refused``
    - reviewer outside suggested_reviewers -> ``access-request-reviewer-ineligible``
    - reviewer already voted -> ``access-request-duplicate-review-refused``
    - request not PENDING (incl. read-time EXPIRED) ->
      ``access-request-terminal-refused``
    """
    if not isinstance(store, AccessRequestStore):
        raise ValueError("store must be an AccessRequestStore")
    record = _live_record(store, request_id)
    if record is None:
        raise ValueError("unknown request_id %r" % (request_id,))
    reviewer = _check_agent(reviewer, "reviewer")
    if not isinstance(approve, bool):
        raise ValueError("approve must be a bool")
    now = _now(now)

    state = _resolve_expiry(store, record, now, writer)
    if state != "PENDING":
        raise TerminalTransitionRefused(
            "request %s is %s: reviews only on PENDING"
            % (request_id, state))
    if reviewer == record["requestor"]:
        # The requestor lacks the review verb on their own request
        # (Teleport reviewer-routing lesson).
        raise SelfReviewRefused(
            "requestor %s cannot review their own request" % (reviewer,))
    if record["suggested_reviewers"] and \
            reviewer not in record["suggested_reviewers"]:
        raise ReviewerIneligibleRefused(
            "reviewer %s not in suggested reviewers" % (reviewer,))
    if any(r["reviewer"] == reviewer for r in record["reviews"]):
        raise DuplicateReviewRefused(
            "reviewer %s already voted on %s" % (reviewer, request_id))

    vote = {"reviewer": reviewer, "approve": approve,
            "note": str(note or "")[:_MAX_REASON_CHARS], "at": now}
    record["reviews"].append(vote)
    if writer is not None:
        writer.record("review", request_id, {
            "reviewer": reviewer, "approve": approve,
            "note_digest": _digest(vote["note"]),
        })

    approvers = {r["reviewer"] for r in record["reviews"] if r["approve"]}
    deniers = {r["reviewer"] for r in record["reviews"] if not r["approve"]}
    if len(deniers) >= record["deny_threshold"]:
        record["state"] = "DENIED"
        record["decided_at"] = now
        if writer is not None:
            writer.record("denied", request_id, {"at": now})
    elif len(approvers) >= record["approve_threshold"]:
        record["state"] = "APPROVED"
        record["decided_at"] = now
        if writer is not None:
            writer.record("approved", request_id, {"at": now})
    return record["state"]


def mint_grant(store, request_id, *, now=None, lease=None,
               writer=None):
    """Mint ephemeral TTL-bound tool grants for an APPROVED request.

    Returns ``{"request_id", "join_key", "lease_ref", "expires_at",
    "tuples", "tuple_digests"}``. The tuples compose directly with
    :func:`gov.ephemeral_grants.check_grant`: ``valid_until =
    approved_at + max_duration`` -- the credential dies at expiry, no
    revocation list, no standing capabilities. ``lease="single-use"``
    binds a single-use lease (the wave-280 ephemeral-grants seam); the
    default (None) is the Teleport reissued-identity shape: usable for
    the whole TTL. A non-APPROVED request refuses
    ``access-request-grant-refused``, as does minting after the grant
    TTL has already elapsed (dead-on-arrival mints are an evidence
    wart, not a security hole -- ``check_grant`` would refuse them
    anyway).
    """
    if not isinstance(store, AccessRequestStore):
        raise ValueError("store must be an AccessRequestStore")
    record = _live_record(store, request_id)
    if record is None:
        raise ValueError("unknown request_id %r" % (request_id,))
    if lease not in (None, "single-use"):
        raise ValueError("lease must be None or 'single-use'")
    now = _now(now)

    state = _resolve_expiry(store, record, now, writer)
    if state != "APPROVED":
        raise GrantNotApprovedRefused(
            "request %s is %s: grants mint only from APPROVED"
            % (request_id, state))

    expires_at = record["decided_at"] + record["max_duration_s"]
    if now > expires_at:
        raise GrantNotApprovedRefused(
            "request %s: grant TTL already elapsed at mint time "
            "(approved_at=%r, max_duration=%r)" % (
                request_id, record["decided_at"],
                record["max_duration_s"]))
    lease_ref = ("arlease_" + secrets.token_hex(8)) if lease else None
    tuples = []
    for grant in record["grants"]:
        conditions = dict(grant["conditions"])
        conditions["valid_until"] = expires_at
        tuples.append(_eg.ContextualTuple(
            user=record["requestor"],
            relation="can_invoke",
            obj=grant["tool"],
            conditions=conditions,
            lease_ref=lease_ref,
        ))
    issued = {
        "request_id": request_id,
        "join_key": request_id,
        "lease_ref": lease_ref,
        "expires_at": expires_at,
        "tuples": tuples,
        "tuple_digests": [t.digest() for t in tuples],
    }
    if writer is not None:
        writer.record("grant-issued", request_id, {
            "lease_ref": lease_ref,
            "expires_at": expires_at,
            "tuple_digests": issued["tuple_digests"],
            "tools": [g["tool"] for g in record["grants"]],
        })
    return issued


# ---------------------------------------------------------------------------
# Audit writer: HMAC-chained access-request-event records, joined by
# join_key (the decision<->evidence spine for evidence bundles).
# ---------------------------------------------------------------------------


class AccessRequestWriter(object):
    """Chains ``access-request-event`` records into the HMAC audit log.

    One writer instance chains its own records via
    ``prev_access_request_digest`` (the wave-279 guardrail-evidence
    precedent). Records are appended AT DECISION TIME, never batched
    later. Fail-closed: if ``log.append`` raises, the exception
    propagates and the caller must not treat the transition as evidenced.
    """

    def __init__(self, log):
        self._log = log
        self._last_digest = _GENESIS

    def record(self, event, join_key, payload):
        """Build, digest, chain, and append one access-request event."""
        if event not in ("submitted", "review", "approved", "denied",
                         "expired", "grant-issued"):
            raise ValueError("unknown access-request event %r" % (event,))
        if not isinstance(join_key, str) or not join_key:
            raise ValueError("join_key must be a non-empty string")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        record = {
            "record_type": RECORD_TYPE,
            "schema_version": SCHEMA_VERSION,
            "event": event,
            "join_key": join_key,
            "payload": json.loads(_canonical(payload)),
            "prev_access_request_digest": self._last_digest,
        }
        record["record_digest"] = _digest(_canonical(record))
        entry = self._log.append(record)
        self._last_digest = record["record_digest"]
        return entry

    def verify(self, log):
        """Re-derive the per-writer digest chain over this log.

        Returns True iff every access-request-event record links to its
        predecessor and its record_digest recomputes. (The HMAC chain
        itself is verified separately by the log's own verifier.)
        """
        from gov.log import read_entries
        prev = _GENESIS
        seen = 0
        for e in read_entries(log.path):
            if e.get("record_type") != RECORD_TYPE:
                continue
            if e.get("prev_access_request_digest") != prev:
                return False
            # record_digest covers exactly the fields this writer wrote;
            # the log's own HMAC chain fields (hash, prev_hash, seq, ...)
            # are verified separately by the log verifier.
            body = {k: e.get(k) for k in (
                "record_type", "schema_version", "event", "join_key",
                "payload", "prev_access_request_digest")}
            if _digest(_canonical(body)) != e.get("record_digest"):
                return False
            prev = e["record_digest"]
            seen += 1
        return seen > 0


def access_request_events(log, join_key):
    """All access-request events for one join_key, in stored order."""
    from gov.log import read_entries
    return [e for e in read_entries(log.path)
            if e.get("record_type") == RECORD_TYPE
            and e.get("join_key") == join_key]


def replay_state(log, join_key):
    """Re-derive a request's state by folding its events (offline).

    The evidence-bundle spine: an auditor holding the sealed bundle
    recomputes the decision state without the engine.
    """
    state = None
    for e in access_request_events(log, join_key):
        ev = e.get("event")
        if ev == "submitted":
            state = "PENDING"
        elif ev == "approved":
            state = "APPROVED"
        elif ev == "denied":
            state = "DENIED"
        elif ev == "expired":
            state = "EXPIRED"
        # "review" and "grant-issued" do not move the state machine.
    return state
