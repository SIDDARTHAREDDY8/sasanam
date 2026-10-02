"""Durable pending-approval ledger (LangGraph ADAPT).

LangGraph (``langchain-ai/langgraph``, MIT) built its human-in-the-loop
story on two primitives: a **checkpointer** (durability) and
``interrupt()`` (the human gate). This module adapts the DURABILITY
half as a mechanism -- no LangGraph code, text, or dependency is
reused, vendored, or contacted (stdlib ``sqlite3`` only):

* ``park(approval_id, proposal)`` writes a JSON snapshot to sqlite3
  BEFORE the executor parks. Restart recovery = re-list parked
  approvals (``list_parked`` / ``recover``); no live timers -- expiry
  is computed from event timestamps at read time (``check_at_use``,
  the Temporal pattern).
* ``resume(approval_id, decision, edited_args=None)`` -- the human
  verdict becomes the executor's resume input (the
  ``Command(resume=value)`` shape): ``{"decision", "args",
  "proposal_digest", "final_args_digest", "edited"}``. A denial
  carries ``args=None``: the agent must not run.
* **Edit-before-approve:** the reviewer rewrites the proposed tool
  args; the proposal -> edit -> execution diff is chained into the
  HMAC audit log as an ``approval_args_edited`` event -- the
  HumanLayer contract shape (``gov/human_approval_contract.py``,
  wave-280), composed not duplicated. Same event keys and value
  types; one deliberate semantic choice: ``edited_arg_keys`` lists
  only the keys whose values changed (what the base implementation's
  own comment describes -- "the changed keys" -- where its code emits
  every key of the edited args).
* **State history across the interrupt:** the parked proposal digest
  -> the edit's old/new digests -> the resumed final-args digest form
  a digest-linked triple in the audit log: "who changed what between
  proposal and execution", evidence-grade.

Fail-closed contract:

* tampered snapshot (stored bytes that no longer parse, or whose
  digest no longer matches the parked digest) -> refuse-to-resume,
  coded ``pending-approval-snapshot-tampered`` (critical: recomputed
  evidence disagrees with the claim). The record stays parked and
  never executes.
* unknown approval id / already-decided record / expired record /
  malformed resume value -> coded
  ``pending-approval-resume-refused`` (medium: fail-closed on
  malformed/unknown/expired input).
* ``park()`` takes malformed *construction* input as ``ValueError``
  (programming error, fail fast -- the FGA-lane precedent); ``resume()``
  is the trust boundary where the human verdict enters, so malformed
  verdicts refuse coded, never raise-and-continue.
* Queries (``list_parked``, ``status``, ``recover``) are read-only
  projections: they perform zero writes (the Temporal signal/query
  separation -- signals mutate, queries never do).

Residuals (honest, not findings):

* Cross-process double-resume: two processes resuming the same parked
  record race at sqlite; the loser's UPDATE affects zero rows, leaves
  a ``resume_refused`` trace (sqlite + HMAC), and is refused coded --
  at most one terminal decision lands, and no ``approval_args_edited``
  audit event is chained unless the winner's write lands (the edit
  event is chained AFTER the conditional UPDATE succeeds, so a race
  loser can never leave a dangling edit in the HMAC log). Audit
  ``resumed`` event ordering across processes follows commit order.
  Same class as the F305 in-process lock; the ledger is the
  cross-process half.
* An attacker who can rewrite BOTH the snapshot bytes AND the stored
  digest consistently defeats the tamper check (they control the
  store); the HMAC audit log's ``pending_approval_parked`` event still
  holds the original digest for forensics. The snapshot check binds
  the accidental/corrupt case and the single-field-tamper case.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import time

# ---------------------------------------------------------------------------
# Decision vocabulary (the resume-value contract).
# ---------------------------------------------------------------------------

#: The human approved; the agent runs ``args`` (edited or as proposed).
APPROVED = "approved"
#: The human refused; the agent must not run (resume carries args=None).
DENIED = "denied"

DECISIONS = (APPROVED, DENIED)

# Statuses stored in the ledger.
_STATUS_PARKED = "parked"
_STATUS_APPROVED = "approved"
_STATUS_DENIED = "denied"
_TERMINAL = (_STATUS_APPROVED, _STATUS_DENIED)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id       TEXT PRIMARY KEY,
    proposal_json     TEXT NOT NULL,
    proposal_digest   TEXT NOT NULL,
    args_digest       TEXT NOT NULL,
    status            TEXT NOT NULL,
    parked_at         REAL NOT NULL,
    ttl_s             REAL NOT NULL,
    decided_at        REAL,
    decision          TEXT,
    edited            INTEGER NOT NULL DEFAULT 0,
    final_args_digest TEXT
);
CREATE TABLE IF NOT EXISTS approval_events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id  TEXT NOT NULL,
    event        TEXT NOT NULL,
    at           REAL NOT NULL,
    detail_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_events_id
    ON approval_events (approval_id);
"""


# ---------------------------------------------------------------------------
# Errors: machine-readable codes (registered in gov/decision_codes.py).
# ---------------------------------------------------------------------------

class PendingApprovalError(Exception):
    """Coded refusal at the resume boundary.

    ``code`` is always ``pending-approval-resume-refused``;
    ``detail`` names the reason (unknown_approval_id |
    already_decided | expired | bad_decision | bad_edited_args).
    """

    code = "pending-approval-resume-refused"

    def __init__(self, detail, approval_id=None):
        self.detail = detail
        self.approval_id = approval_id
        super(PendingApprovalError, self).__init__(
            "%s: %s (approval_id=%r)"
            % (self.code, detail, approval_id))


class SnapshotTamperedError(PendingApprovalError):
    """The parked snapshot no longer matches its digest: refuse-to-resume.

    Critical: recomputed evidence disagrees with the claim. The record
    stays parked; nothing executes.
    """

    code = "pending-approval-snapshot-tampered"

    def __init__(self, approval_id, decided_by, expected, recomputed):
        self.decided_by = decided_by
        self.expected = expected
        self.recomputed = recomputed
        super(SnapshotTamperedError, self).__init__(
            "snapshot digest mismatch", approval_id)


# ---------------------------------------------------------------------------
# Canonical JSON + digests.
# ---------------------------------------------------------------------------

def _canonical(obj):
    """Canonical JSON for digesting (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def args_digest(args):
    """Digest of an args dict (public: lets callers verify the chain)."""
    if not isinstance(args, dict):
        raise ValueError("args_digest: args must be a dict")
    return _sha256_hex(_canonical(args))


def proposal_digest_of(proposal):
    """Digest of a proposal dict (public: lets callers verify the chain)."""
    if not isinstance(proposal, dict):
        raise ValueError("proposal_digest_of: proposal must be a dict")
    return _sha256_hex(_canonical(proposal))


# ---------------------------------------------------------------------------
# Input validation.
# ---------------------------------------------------------------------------

def _check_id(approval_id):
    if not isinstance(approval_id, str) or not approval_id.strip():
        raise ValueError(
            "approval_id must be a non-empty string")
    if len(approval_id) > 256:
        raise ValueError("approval_id exceeds 256 chars")
    return approval_id


def _check_jsonable_args(args, what):
    if not isinstance(args, dict):
        raise ValueError("%s: args must be a dict, got %s"
                         % (what, type(args).__name__))
    for key in args:
        if not isinstance(key, str):
            raise ValueError("%s: args keys must be strings, got %r"
                             % (what, key))
    try:
        _canonical(args)
    except (TypeError, ValueError) as exc:
        raise ValueError("%s: args must be JSON-serializable: %s"
                         % (what, exc))
    return dict(args)


def _check_proposal(proposal):
    if not isinstance(proposal, dict):
        raise ValueError("proposal must be a dict, got %s"
                         % type(proposal).__name__)
    tool = proposal.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("proposal['tool'] must be a non-empty string")
    _check_jsonable_args(proposal.get("args", {}), "proposal")
    for opt in ("run_id", "agent_id", "policy_id", "reason"):
        val = proposal.get(opt)
        if val is not None and not isinstance(val, str):
            raise ValueError("proposal[%r] must be a string or None"
                             % (opt,))
    clean = dict(proposal)
    clean["args"] = dict(proposal.get("args", {}))
    return clean


def _check_ttl(ttl_s):
    if isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float)):
        raise ValueError("ttl_s must be a number of seconds")
    if ttl_s != ttl_s or ttl_s in (float("inf"), float("-inf")):
        raise ValueError("ttl_s must be finite")
    if ttl_s <= 0:
        raise ValueError("ttl_s must be positive")
    return float(ttl_s)


# ---------------------------------------------------------------------------
# The ledger.
# ---------------------------------------------------------------------------

class PendingApprovalLedger(object):
    """Crash-safe pending-approval ledger (sqlite3).

    ``db_path`` is the sqlite file (parent dirs are created).
    ``log`` is an optional ``gov.log.ActionLog``: every transition is
    chained into the HMAC audit log at decision time (best-effort --
    the sqlite events table is the durable record and always lands;
    a log-write failure never un-decides a record, mirroring the
    HumanLayer ``approval_args_edited`` convention).
    """

    def __init__(self, db_path, log=None):
        if not db_path or not isinstance(db_path, str):
            raise ValueError("db_path must be a non-empty string")
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        self._log = log
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        # WAL: a killed process leaves a recoverable journal; readers
        # never block the writer.
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- internal ------------------------------------------------------

    def _chain(self, event):
        """Best-effort HMAC audit chaining (never un-decides a record)."""
        if self._log is None:
            return
        try:
            self._log.append(event)
        except Exception:
            pass  # the sqlite events table is the durable record

    def _event(self, approval_id, event, detail):
        self._conn.execute(
            "INSERT INTO approval_events (approval_id, event, at,"
            " detail_json) VALUES (?, ?, ?, ?)",
            (approval_id, event, time.time(), _canonical(detail)))

    def _row(self, approval_id):
        cur = self._conn.execute(
            "SELECT * FROM pending_approvals WHERE approval_id=?",
            (approval_id,))
        return cur.fetchone()

    def _expired(self, row, now):
        return now > row["parked_at"] + row["ttl_s"]

    def _parse_and_verify(self, row, decided_by=None):
        """Parse the parked snapshot and verify its digest.

        Any integrity failure -- unparseable bytes, non-dict JSON, or
        digest mismatch -- is a tampered snapshot: raise the coded
        ``SnapshotTamperedError``. Fail-closed: the caller never
        executes on this path.
        """
        try:
            proposal = json.loads(row["proposal_json"])
        except (TypeError, ValueError) as exc:
            raise SnapshotTamperedError(row["approval_id"], decided_by,
                                        None, None) from exc
        if not isinstance(proposal, dict):
            raise SnapshotTamperedError(row["approval_id"], decided_by,
                                        row["proposal_digest"], None)
        recomputed = _sha256_hex(row["proposal_json"])
        if not hmac.compare_digest(recomputed, row["proposal_digest"]):
            raise SnapshotTamperedError(row["approval_id"], decided_by,
                                        row["proposal_digest"], recomputed)
        return proposal

    def _log_refusal(self, approval_id, detail, decided_by=None,
                     code=None, row=None):
        """Write the refusal trace (sqlite event + HMAC chain); no raise."""
        if row is not None:
            with self._conn:
                self._event(approval_id, "resume_refused",
                            {"detail": detail})
        self._chain({"event": "pending_approval_resume_refused",
                     "approval_id": approval_id,
                     "code": code or PendingApprovalError.code,
                     "reason": detail,
                     "decided_by": decided_by})

    def _refuse(self, approval_id, detail, decided_by=None, row=None):
        """Record a coded refusal and raise (the trust-boundary path)."""
        self._log_refusal(approval_id, detail, decided_by=decided_by,
                          row=row)
        raise PendingApprovalError(detail, approval_id)

    # -- park: the interrupt boundary ----------------------------------

    def park(self, approval_id, proposal, *, ttl_s):
        """Park an approval BEFORE the executor parks on the human.

        Writes the JSON snapshot + digest to sqlite (crash-safe) and
        chains a ``pending_approval_parked`` audit event. Duplicate
        park of the same id is a programming error (ValueError).
        Returns a small dict with the digests and timestamps.
        """
        approval_id = _check_id(approval_id)
        proposal = _check_proposal(proposal)
        ttl_s = _check_ttl(ttl_s)
        now = time.time()
        canon = _canonical(proposal)
        digest = _sha256_hex(canon)
        args_d = _sha256_hex(_canonical(proposal["args"]))
        with self._conn:
            if self._row(approval_id) is not None:
                raise ValueError(
                    "park refused: approval_id %r is already parked"
                    % (approval_id,))
            self._conn.execute(
                "INSERT INTO pending_approvals (approval_id,"
                " proposal_json, proposal_digest, args_digest, status,"
                " parked_at, ttl_s) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (approval_id, canon, digest, args_d, _STATUS_PARKED,
                 now, ttl_s))
            self._event(approval_id, "parked",
                        {"proposal_digest": digest, "ttl_s": ttl_s})
        self._chain({"event": "pending_approval_parked",
                     "approval_id": approval_id,
                     "tool": proposal["tool"],
                     "agent_id": proposal.get("agent_id"),
                     "run_id": proposal.get("run_id"),
                     "policy_id": proposal.get("policy_id"),
                     "proposal_digest": digest,
                     "args_digest": args_d,
                     "ttl_s": ttl_s,
                     "reason": proposal.get("reason")})
        return {"approval_id": approval_id,
                "proposal_digest": digest,
                "args_digest": args_d,
                "parked_at": now,
                "ttl_s": ttl_s}

    # -- resume: the human verdict becomes the executor's input --------

    def resume(self, approval_id, decision, *, edited_args=None,
               decided_by=None):
        """Apply the human verdict; return the executor's resume value.

        ``decision`` is "approved" or "denied" (anything else refuses
        coded). ``edited_args`` (dict) is the reviewer's rewritten
        args: the proposal -> edit -> execution diff is chained into
        the audit log as an ``approval_args_edited`` event (the
        HumanLayer contract shape) and execution proceeds with the
        edited args. A denial returns ``args=None``.

        Fail-closed: unknown id, already-decided, expired, tampered
        snapshot, and malformed verdicts all refuse coded -- a refused
        resume never executes. The edit audit event is chained only
        AFTER the winner's conditional UPDATE lands, so a race loser
        can never leave a dangling edit in the HMAC log.
        """
        approval_id = _check_id(approval_id)
        row = self._row(approval_id)
        if row is None:
            self._refuse(approval_id, "unknown_approval_id",
                         decided_by=decided_by)
        if row["status"] in _TERMINAL:
            self._refuse(approval_id, "already_decided",
                         decided_by=decided_by, row=row)
        # Snapshot integrity BEFORE any state change: the parked bytes
        # must still parse and match the parked digest. Any integrity
        # failure refuses coded (tamper), with a refusal trace.
        try:
            proposal = self._parse_and_verify(row, decided_by=decided_by)
        except SnapshotTamperedError:
            self._log_refusal(approval_id, "snapshot_tampered",
                              decided_by=decided_by,
                              code=SnapshotTamperedError.code, row=row)
            raise
        now = time.time()
        if self._expired(row, now):
            self._refuse(approval_id, "expired", decided_by=decided_by,
                         row=row)
        if decision not in DECISIONS:
            self._refuse(approval_id, "bad_decision",
                         decided_by=decided_by, row=row)

        edited = False
        final_args = dict(proposal.get("args", {}))
        edit_event = None
        if decision == APPROVED and edited_args is not None:
            if not isinstance(edited_args, dict):
                self._refuse(approval_id, "bad_edited_args",
                             decided_by=decided_by, row=row)
            try:
                _check_jsonable_args(edited_args, "edited_args")
            except ValueError:
                # The resume boundary refuses coded, never
                # raise-and-continue: a malformed verdict must not
                # execute.
                self._refuse(approval_id, "bad_edited_args",
                             decided_by=decided_by, row=row)
            edited_args = dict(edited_args)
            old_d = row["args_digest"]
            new_d = _sha256_hex(_canonical(edited_args))
            if new_d != old_d:
                edited = True
                changed = sorted(
                    k for k in set(proposal["args"]) | set(edited_args)
                    if _canonical(proposal["args"].get(k)) !=
                    _canonical(edited_args.get(k)))
                # The HumanLayer approval_args_edited shape, composed
                # not duplicated (extra "ledger" marker names the
                # durable-ledger origin). edited_arg_keys lists only
                # the keys whose values changed -- the semantics the
                # base implementation's comment describes. Chained
                # only after the winning UPDATE below.
                edit_event = {
                    "event": "approval_args_edited",
                    "run_id": proposal.get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": proposal["tool"],
                    "decision": "approved",
                    "policy_id": proposal.get("policy_id"),
                    "approval_id": approval_id,
                    "decided_by": decided_by,
                    "related_agent": proposal.get("agent_id"),
                    "old_args_digest": old_d,
                    "new_args_digest": new_d,
                    "edited_arg_keys": changed,
                    "ledger": "pending_approvals",
                    "reason": ("durable-ledger edit-before-approve: the "
                               "reviewer rewrote the proposed args; "
                               "execution proceeds with the edited args"),
                }
            final_args = edited_args

        final_d = (_sha256_hex(_canonical(final_args))
                   if decision == APPROVED else None)
        status = _STATUS_APPROVED if decision == APPROVED else _STATUS_DENIED
        # Conditional write: at most one terminal decision lands even
        # if two processes race the same parked record.
        with self._conn:
            cur = self._conn.execute(
                "UPDATE pending_approvals SET status=?, decided_at=?,"
                " decision=?, edited=?, final_args_digest=?"
                " WHERE approval_id=? AND status=?",
                (status, now, decision, int(edited), final_d,
                 approval_id, _STATUS_PARKED))
            won = cur.rowcount == 1
            if won:
                if edit_event is not None:
                    self._event(approval_id, "edited",
                                {"old_args_digest": edit_event[
                                    "old_args_digest"],
                                 "new_args_digest": edit_event[
                                    "new_args_digest"],
                                 "edited_arg_keys": edit_event[
                                    "edited_arg_keys"]})
                self._event(approval_id, "resumed",
                            {"decision": decision, "edited": edited,
                             "final_args_digest": final_d})
        if not won:
            # Lost the race: the other writer's terminal decision
            # stands. Leave the same forensic refusal trace as the
            # in-process double-resume path, then refuse coded.
            self._log_refusal(approval_id, "already_decided",
                              decided_by=decided_by, row=row)
            raise PendingApprovalError("already_decided", approval_id)
        # Winner only: chain the edit BEFORE the resumed event so the
        # HMAC log reads park -> edit -> resumed in causal order.
        if edit_event is not None:
            self._chain(edit_event)
        self._chain({"event": "pending_approval_resumed",
                     "approval_id": approval_id,
                     "tool": proposal["tool"],
                     "decision": decision,
                     "decided_by": decided_by,
                     "proposal_digest": row["proposal_digest"],
                     "args_digest": row["args_digest"],
                     "final_args_digest": final_d,
                     "edited": edited})
        return {"approval_id": approval_id,
                "decision": decision,
                "args": (final_args if decision == APPROVED else None),
                "proposal_digest": row["proposal_digest"],
                "final_args_digest": final_d,
                "edited": edited}

    # -- read-only projections (signals mutate; queries never do) -----

    def status(self, approval_id):
        """Read-only projection of one record (None when unknown).

        A record whose snapshot fails integrity is reported with
        ``"tampered": True`` (tool unknowable, hence None) -- the
        inbox can show "corrupted" instead of crashing.
        """
        approval_id = _check_id(approval_id)
        row = self._row(approval_id)
        if row is None:
            return None
        try:
            proposal = self._parse_and_verify(row)
        except SnapshotTamperedError:
            return {"approval_id": row["approval_id"],
                    "tool": None,
                    "tampered": True,
                    "status": row["status"],
                    "decision": row["decision"],
                    "parked_at": row["parked_at"],
                    "ttl_s": row["ttl_s"],
                    "expired": self._expired(row, time.time()),
                    "proposal_digest": row["proposal_digest"],
                    "args_digest": row["args_digest"],
                    "final_args_digest": row["final_args_digest"],
                    "edited": bool(row["edited"]),
                    "decided_at": row["decided_at"]}
        return {"approval_id": row["approval_id"],
                "tool": proposal["tool"],
                "tampered": False,
                "status": row["status"],
                "decision": row["decision"],
                "parked_at": row["parked_at"],
                "ttl_s": row["ttl_s"],
                "expired": self._expired(row, time.time()),
                "proposal_digest": row["proposal_digest"],
                "args_digest": row["args_digest"],
                "final_args_digest": row["final_args_digest"],
                "edited": bool(row["edited"]),
                "decided_at": row["decided_at"]}

    def list_parked(self):
        """Read-only projection of all parked (undecided) approvals.

        Tampered records are included with ``"tampered": True`` so the
        inbox sees them; ``recover()`` is the integrity report.
        """
        now = time.time()
        cur = self._conn.execute(
            "SELECT approval_id, proposal_json, parked_at, ttl_s,"
            " proposal_digest FROM pending_approvals"
            " WHERE status=? ORDER BY parked_at",
            (_STATUS_PARKED,))
        out = []
        for row in cur.fetchall():
            try:
                proposal = self._parse_and_verify(row)
            except SnapshotTamperedError:
                out.append({"approval_id": row["approval_id"],
                            "tool": None,
                            "tampered": True,
                            "parked_at": row["parked_at"],
                            "ttl_s": row["ttl_s"],
                            "expired": (now > row["parked_at"]
                                        + row["ttl_s"]),
                            "proposal_digest": row["proposal_digest"]})
                continue
            out.append({"approval_id": row["approval_id"],
                        "tool": proposal["tool"],
                        "tampered": False,
                        "parked_at": row["parked_at"],
                        "ttl_s": row["ttl_s"],
                        "expired": now > row["parked_at"] + row["ttl_s"],
                        "proposal_digest": row["proposal_digest"]})
        return out

    def recover(self):
        """Restart recovery: verify every parked snapshot.

        Returns {"parked": [...ids...], "tampered": [...ids...]}.
        Read-only: reports, never repairs (resume refuses tampered
        records anyway).
        """
        parked, tampered = [], []
        cur = self._conn.execute(
            "SELECT approval_id, proposal_json, proposal_digest"
            " FROM pending_approvals WHERE status=?",
            (_STATUS_PARKED,))
        for row in cur.fetchall():
            try:
                self._parse_and_verify(row)
            except SnapshotTamperedError:
                tampered.append(row["approval_id"])
            else:
                parked.append(row["approval_id"])
        return {"parked": sorted(parked), "tampered": sorted(tampered)}

    def close(self):
        """Close the sqlite connection."""
        try:
            self._conn.close()
        except Exception:
            pass
