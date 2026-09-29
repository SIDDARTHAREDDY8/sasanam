"""Durable approval workflows: the Temporal durability pattern, stdlib only.

The durability triple
---------------------
1. **Journal as source of truth** — every workflow event is a record in
   a :class:`gov.durable_journal.Journal` (hash-chained, append-only,
   fsync'ed). Workflow state is a *pure fold* over the journal, so a
   restart is just re-read + re-fold.
2. **Determinism guard** — the decision-code version (``sha256`` of this
   module's source, overridable via ``GOV_DURABLE_CODE_VERSION`` for
   tests) is pinned in ``WorkflowStarted`` and re-checked on every
   engine load. Skew raises :class:`NonDeterministicReplayError` and the
   check is read-only: the journal is byte-identical afterwards.
   In-flight workflows drain under the old code or are explicitly
   migrated — never silently replayed under new code.
3. **Durable timers** — ``TimerStarted`` is created in the SAME journal
   transaction as ``ApprovalRequested`` (adjacent records, shared txn
   id, single fsync); ``TimerFired`` is appended by the driver when the
   deadline passes. Expiry survives the driver being dead.

Execution semantics (honest, Temporal-like)
-------------------------------------------
Activities are AT-LEAST-ONCE. ``ActionClaimed`` is journaled BEFORE the
side effect and ``ActionExecuted`` after; a crash in between re-executes
on restart. :meth:`Engine.request` therefore LOUDLY REFUSES
non-idempotent actions (:class:`ActionNotIdempotent`), making the
*observable* outcome exactly-once. The claim is an attempt-scoped
``ActionClaimed`` record (plain append); the driver that holds the
LATEST claim for an approval runs the action
(:meth:`Engine._holds_latest_claim`), so two drivers racing serialize
best-effort: concurrent drivers may both run the side effect in the
overlap window (honest at-least-once), but the ``ActionExecuted``
record itself is taken with :meth:`Journal.append_if`, so exactly one
is ever journaled and the observable outcome stays exactly-once —
provided the action is idempotent, which ``request`` enforces.

Record types
------------
``WorkflowStarted`` (carries the approval-packet digest, the pinned code
version, and the audit-log cross-reference digest), ``ApprovalRequested``,
``ApprovalGranted``, ``ApprovalDenied``, ``TimerStarted``, ``TimerFired``,
``ActionClaimed``, ``ActionExecuted``.

The ``packet_digest`` carried in ``WorkflowStarted`` is opaque to this
engine: the CALLER must supply the v5 canonical approval-packet digest
(``gov.approvals.canonical_packet`` as stored on the queue record — the
exact bytes the human saw). The engine pins whatever digest it is given
immutably in the journal but cannot re-derive it without the record;
passing anything else silently weakens the WYSINWYS binding, so the
integration that opens a durable workflow for a queued approval must
pass the record's stored ``packet_digest`` through unchanged. For the
release ceremony (:class:`gov.release_approval.DurableReleaseWorkflow`)
the bound digest is the release digest (``release_digest``), which is
the release's WYSINWYS: ``verify_release`` recomputes it from the
candidate bits at decide time and fails closed on any drift.

The existing hash-chained audit log (``gov.log``) remains the
tamper-evident system of record: pass an ``audit_append`` callable
(e.g. ``ActionLog.append``) and the entry's chain digest is bound into
``WorkflowStarted``. Ordering note: the audit append happens BEFORE the
journal transaction; if the journal write then fails, the audit entry
is an orphan — use :func:`find_audit_orphans` to detect that
(fail-closed: no phantom workflow is ever journaled).

Timers and wall-clock
---------------------
Timers compare ``fire_at`` (UTC seconds, journaled at request time)
against the driver's wall clock. A clock jump can fire a timer early
or late; the journaled ``fire_at`` makes the decision auditable after
the fact. This is the accepted posture for approval expiry (a human
deadline, not a real-time guarantee) — never use durable timers where
a jumped clock would be a safety violation.

Upgrades (code-version skew)
-----------------------------
The pinned ``code_version`` blocks replay under changed decision code
(:class:`NonDeterministicReplayError`, journal untouched). There is no
in-library drain or migration API: the operator procedure is
drain-then-deploy — keep the old code driving until in-flight
workflows reach terminal states (``executed`` / ``denied`` /
``expired``), then deploy. The error message names the pinned and
current versions so the operator can tell a genuine skew from a
mis-deploy.

Snapshots
---------
The journal supports snapshots and compaction
(:meth:`gov.durable_journal.Journal.take_snapshot`,
:meth:`gov.durable_journal.Journal.compact`), but nothing in the
engine auto-compacts: compaction is operator-invoked, on a schedule
sized to the workload. An un-compacted journal grows unbounded —
size the schedule before production use.
"""

import hashlib
import json
import os
import time
import uuid

from .durable_journal import Journal, JournalCorrupted

# Record types (public; subclasses and auditors match on these).
WORKFLOW_STARTED = "WorkflowStarted"
APPROVAL_REQUESTED = "ApprovalRequested"
APPROVAL_GRANTED = "ApprovalGranted"
APPROVAL_DENIED = "ApprovalDenied"
TIMER_STARTED = "TimerStarted"
TIMER_FIRED = "TimerFired"
ACTION_CLAIMED = "ActionClaimed"
ACTION_EXECUTED = "ActionExecuted"

# Test hook: when set, the driver simulates kill -9 AFTER the side effect
# but BEFORE the ActionExecuted journal record (exit code 137).
_CRASH_ENV = "DURABLE_CRASH_AFTER_SIDE_EFFECT"


class NonDeterministicReplayError(Exception):
    """Decision code changed under a live journal. Replay BLOCKED."""


class GrantRefused(Exception):
    """grant/deny refused: unknown approval or not pending."""


class DuplicateApproval(Exception):
    """An approval_id may be requested exactly once."""


class ActionNotIdempotent(Exception):
    """Refusing a non-idempotent action: at-least-once execution would
    duplicate observable effects."""


def _code_version():
    """Pin the decision-code version: sha256 of this module's source."""
    override = os.environ.get("GOV_DURABLE_CODE_VERSION")
    if override:
        return "override:" + override
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "durable_approval.py")
    with open(src, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()[:16]


CODE_VERSION = _code_version()


def _utcnow():
    return time.time()


class Engine:
    """Drives durable approval workflows over a journal."""

    #: record types this engine's fold understands (subclasses extend).
    RECORD_TYPES = (WORKFLOW_STARTED, APPROVAL_REQUESTED, APPROVAL_GRANTED,
                    APPROVAL_DENIED, TIMER_STARTED, TIMER_FIRED,
                    ACTION_CLAIMED, ACTION_EXECUTED)

    def __init__(self, journal_path, outcome_dir, audit_append=None):
        self.journal_path = os.path.abspath(journal_path)
        self.journal = Journal(self.journal_path)
        self.outcome_dir = os.path.abspath(outcome_dir)
        os.makedirs(self.outcome_dir, exist_ok=True)
        self.audit_append = audit_append
        # Read dynamically (not just at import): the test seam for
        # skew (GOV_DURABLE_CODE_VERSION) must take effect for engines
        # constructed after the code changed, in the same process.
        self.code_version = _code_version()
        self._actions = {}
        self.register_action("default", _default_action)
        self._check_determinism()

    # ------------------------------------------------------------------
    # determinism guard (read-only: the journal is never mutated here)
    # ------------------------------------------------------------------
    def _check_determinism(self):
        for rec in self.journal.records:
            if rec["type"] == WORKFLOW_STARTED:
                pinned = rec["body"].get("code_version")
                if pinned != self.code_version:
                    raise NonDeterministicReplayError(
                        "decision code changed: journal pinned %r, "
                        "current %r; replay BLOCKED, journal intact"
                        % (pinned, self.code_version))

    # ------------------------------------------------------------------
    # state: pure fold over the journal (override point for subclasses)
    # ------------------------------------------------------------------
    def _reload(self):
        """Re-read the journal from disk into ``self.journal``.

        The single discipline for "which journal am I looking at":
        after ``_reload()``, ``self.journal.records`` is the current
        on-disk journal and every fold in the calling method uses it.
        Called at the top of :meth:`drive` and before the claim
        election, so a restarted or racing driver always folds current
        state. Appends stay safe on a reloaded journal because the
        journal's writer lock re-reads the tail under the lock.
        """
        self.journal = Journal(self.journal_path)

    def states(self):
        """{approval_id: state dict}. Pure function of the journal."""
        return self._fold(self.journal.records)

    def _fold(self, records):
        states = {}
        for rec in records:
            t, b = rec["type"], rec["body"]
            aid = b.get("approval_id")
            if t == WORKFLOW_STARTED:
                states[aid] = {"status": "pending",
                               "code_version": b.get("code_version"),
                               "requester": b.get("requester"),
                               "idempotency_key": b.get("idempotency_key"),
                               "action_kind": b.get("action_kind"),
                               "packet_digest": b.get("packet_digest"),
                               "audit_hash": b.get("audit_hash"),
                               "votes": []}
            elif t == APPROVAL_GRANTED and aid in states:
                if states[aid]["status"] == "pending":
                    states[aid]["status"] = "approved"
                    states[aid]["approver"] = b.get("approver")
            elif t == APPROVAL_DENIED and aid in states:
                if states[aid]["status"] == "pending":
                    states[aid]["status"] = "denied"
                    states[aid]["deny_reason"] = b.get("reason", "")
            elif t == TIMER_FIRED and aid in states:
                if states[aid]["status"] == "pending":
                    states[aid]["status"] = "expired"
            elif t == ACTION_CLAIMED and aid in states:
                states[aid]["claimed"] = True
            elif t == ACTION_EXECUTED and aid in states:
                states[aid]["status"] = "executed"
        return states

    # ------------------------------------------------------------------
    # workflow API
    # ------------------------------------------------------------------
    def request(self, approval_id, requester, packet_digest, action_kind,
                idempotency_key, ttl_seconds, idempotent=True,
                audit_kind="durable_workflow_started"):
        """Open a durable approval. Request + timer land in ONE atomic
        journal transaction (or neither does).

        ``packet_digest`` is opaque to the engine: the caller MUST pass
        the v5 canonical approval-packet digest (the exact bytes the
        human saw, as stored on the queue record). It is pinned
        immutably in ``WorkflowStarted``; only the digest is stored
        (material-free journal). Raises :class:`ActionNotIdempotent`
        for non-idempotent actions, :class:`DuplicateApproval` for a
        reused id.
        """
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("approval_id must be a non-empty string")
        if not idempotent:
            raise ActionNotIdempotent(
                "refusing non-idempotent action %r: at-least-once "
                "execution would duplicate observable effects"
                % (action_kind,))
        if approval_id in self.states():
            raise DuplicateApproval(
                "approval_id %r already exists" % (approval_id,))
        audit_hash = None
        if self.audit_append is not None:
            # Fail-closed ordering: the audit append happens first; if it
            # raises, nothing is journaled (no phantom workflow). If the
            # journal write then fails, the audit entry is an orphan —
            # detectable via find_audit_orphans, never a phantom approval.
            entry = self.audit_append({
                "kind": audit_kind,
                "approval_id": approval_id,
                "packet_digest": packet_digest,
                "action_kind": action_kind,
            })
            audit_hash = (entry or {}).get("hash")
        now = _utcnow()
        timer_id = "timer-%s" % approval_id
        self.journal.append_many([
            (WORKFLOW_STARTED,
             {"approval_id": approval_id, "code_version": self.code_version,
              "requester": requester, "packet_digest": packet_digest,
              "action_kind": action_kind,
              "idempotency_key": idempotency_key,
              "audit_hash": audit_hash}),
            (APPROVAL_REQUESTED,
             {"approval_id": approval_id, "requester": requester,
              "action_kind": action_kind}),
            (TIMER_STARTED,
             {"approval_id": approval_id, "timer_id": timer_id,
              "fire_at": now + ttl_seconds, "requested_at": now}),
        ])
        return timer_id

    def grant(self, approval_id, approver):
        st = self.states().get(approval_id)
        if st is None:
            raise GrantRefused("unknown approval_id %r" % (approval_id,))
        if st["status"] != "pending":
            raise GrantRefused(
                "grant refused: approval %r is %r, not pending"
                % (approval_id, st["status"]))
        appended, _ = self.journal.append_if(
            [(APPROVAL_GRANTED,
              {"approval_id": approval_id, "approver": approver})],
            lambda records, aid=approval_id: not any(
                r["type"] in (APPROVAL_GRANTED, APPROVAL_DENIED,
                              TIMER_FIRED)
                and r["body"].get("approval_id") == aid
                for r in records))
        if not appended:
            # Lost a cross-process race: the approval transitioned
            # (granted/denied/expired) between our read and the write.
            # The journal is untouched; refuse loudly, never journal a
            # grant on a non-pending approval.
            raise GrantRefused(
                "grant refused: approval %r transitioned concurrently"
                % (approval_id,))

    def deny(self, approval_id, approver, reason=""):
        st = self.states().get(approval_id)
        if st is None or st["status"] != "pending":
            raise GrantRefused("deny refused: %r not pending"
                               % (approval_id,))
        appended, _ = self.journal.append_if(
            [(APPROVAL_DENIED,
              {"approval_id": approval_id,
               "approver": approver, "reason": reason})],
            lambda records, aid=approval_id: not any(
                r["type"] in (APPROVAL_GRANTED, APPROVAL_DENIED,
                              TIMER_FIRED)
                and r["body"].get("approval_id") == aid
                for r in records))
        if not appended:
            raise GrantRefused(
                "deny refused: approval %r transitioned concurrently"
                % (approval_id,))

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def register_action(self, action_kind, fn):
        """Register the side-effect for ``action_kind``.

        ``fn(ctx)`` with ``ctx = {"approval_id", "idempotency_key",
        "outcome_dir"}``. The function MUST be idempotent by
        construction: the engine may run it more than once (crash
        between side effect and journal record), and the *observable*
        outcome must stay exactly-once.
        """
        if not callable(fn):
            raise ValueError("action must be callable")
        self._actions[action_kind] = fn

    # ------------------------------------------------------------------
    # driver
    # ------------------------------------------------------------------
    def drive(self, now=None, resolver=None):
        """Replay the journal and perform whatever is due.

        Re-reads the journal first, so a driver restarted after a
        kill -9 (or racing another driver) always folds current state.
        Safe to call any number of times and from any number of
        processes. Returns ``{"did": [...], "states": {...}}``.

        Execution rule (honest Temporal-style at-least-once): an
        approved workflow with no ``ActionExecuted`` record gets an
        attempt-scoped ``ActionClaimed`` record; the driver holding the
        LATEST claim runs the action. A crash between claim and
        ``ActionExecuted`` therefore re-executes on the next drive —
        which is exactly why actions must be idempotent, and why
        :meth:`request` refuses non-idempotent ones. Concurrent drivers
        may both run the action in the overlap window; the
        ``ActionExecuted`` record itself is taken atomically, so exactly
        one is ever journaled and the observable outcome stays
        exactly-once.
        """
        self._reload()  # re-fold current on-disk state
        now = _utcnow() if now is None else now
        did = []
        for approval_id, st in self.states().items():
            if st["status"] == "pending":
                fire_at = self._timer_fire_at(approval_id)
                if fire_at is not None and now >= fire_at \
                        and not self._timer_fired(approval_id):
                    appended, _ = self.journal.append_if(
                        [(TIMER_FIRED,
                          {"approval_id": approval_id, "fired_at": now})],
                        lambda records, aid=approval_id: not any(
                            r["type"] == TIMER_FIRED
                            and r["body"].get("approval_id") == aid
                            for r in records))
                    if appended:
                        did.append(("timer_fired", approval_id))
            if st["status"] == "approved":
                if self._action_executed(approval_id):
                    continue
                attempt = uuid.uuid4().hex
                self.journal.append(
                    ACTION_CLAIMED,
                    {"approval_id": approval_id,
                     "idempotency_key": st["idempotency_key"],
                     "attempt": attempt})
                if not self._holds_latest_claim(approval_id, attempt):
                    # Another driver claimed after us; back off.
                    continue
                self._run_action(approval_id, st, resolver)
                appended, _ = self.journal.append_if(
                    [(ACTION_EXECUTED,
                      {"approval_id": approval_id,
                       "idempotency_key": st["idempotency_key"],
                       "outcome": "ACTION_PERFORMED"})],
                    lambda records, aid=approval_id: not any(
                        r["type"] == ACTION_EXECUTED
                        and r["body"].get("approval_id") == aid
                        for r in records))
                if appended:
                    did.append(("action_executed", approval_id))
        return {"did": did, "states": self.states()}

    def _holds_latest_claim(self, approval_id, attempt):
        """Best-effort single-winner election: re-read the journal and
        check our attempt is the latest claim for this approval."""
        self._reload()
        latest = None
        for rec in self.journal.records:
            if rec["type"] == ACTION_CLAIMED \
                    and rec["body"].get("approval_id") == approval_id:
                latest = rec["body"].get("attempt")
        return latest == attempt

    def _action_executed(self, approval_id):
        return any(rec["type"] == ACTION_EXECUTED
                   and rec["body"].get("approval_id") == approval_id
                   for rec in self.journal.records)

    def _run_action(self, approval_id, st, resolver):
        """Run the side effect (raises on failure).

        ``ActionClaimed`` is already journaled: a crash from here on
        re-executes on restart, which is why actions must be idempotent.
        """
        kind = st.get("action_kind") or "default"
        ctx = {"approval_id": approval_id,
               "idempotency_key": st["idempotency_key"],
               "outcome_dir": self.outcome_dir}
        if resolver is not None:
            fn = lambda c: resolver(approval_id, kind, c)  # noqa: E731
        else:
            fn = self._actions.get(kind, self._actions["default"])
        fn(ctx)
        if os.environ.get(_CRASH_ENV) == "1":
            # TEST HOOK ONLY: simulate kill -9 between the side effect
            # and the ActionExecuted journal record.
            os._exit(137)

    def _timer_fire_at(self, approval_id):
        for rec in self.journal.records:
            if rec["type"] == TIMER_STARTED \
                    and rec["body"].get("approval_id") == approval_id:
                return rec["body"]["fire_at"]
        return None

    def _timer_fired(self, approval_id):
        return any(rec["type"] == TIMER_FIRED
                   and rec["body"].get("approval_id") == approval_id
                   for rec in self.journal.records)


def _default_action(ctx):
    """Idempotent-by-construction action: deterministic outcome bytes
    keyed by idempotency_key. Running it twice is unobservable."""
    runs_path = os.path.join(ctx["outcome_dir"], "side_effect_runs.log")
    with open(runs_path, "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (time.time(), ctx["approval_id"]))
        f.flush()
        os.fsync(f.fileno())
    out_path = os.path.join(ctx["outcome_dir"],
                            ctx["idempotency_key"] + ".done")
    payload = {"approval_id": ctx["approval_id"],
               "idempotency_key": ctx["idempotency_key"],
               "outcome": "ACTION_PERFORMED"}
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out_path)


def find_audit_orphans(audit_entries, journal):
    """Audit entries with no matching WorkflowStarted.

    ``audit_entries``: iterable of dicts with ``kind`` /
    ``approval_id``. Returns the orphan entries. A non-empty result
    means the audit append succeeded but the journal transaction did not
    (fail-closed ordering) — investigate, never silently drop.
    """
    started = {rec["body"].get("approval_id")
               for rec in journal.records
               if rec["type"] == WORKFLOW_STARTED}
    return [e for e in audit_entries
            if e.get("kind") == "durable_workflow_started"
            and e.get("approval_id") not in started]
