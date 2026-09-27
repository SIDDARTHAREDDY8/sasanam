"""Bounded archive of denied/superseded goals (row 11, wave-140 lane 3).

Row-11 residual after wave-139: the fresh-ID similarity check in
``detect_cross_run_laundering`` (signal 4) only consults the ACTIVE
persisted store — a denied goal that aged out of it is invisible
("Recency := the detector's prior-goals scope" in gov/goals.py).
This module is the bounded archive the check consults as well: it
keeps denied/superseded goals (target+effects+principal+decided_at)
past the active store's horizon, so a denied goal re-minted with a
fresh ID after aging out is still caught.

How it is used:
- ``GoalRegistry(denied_archive=...)`` records every goal the
  moment it transitions to ``"superseded"`` (denied via
  goal_conflict_review / goal_specificity_review, or superseded by
  an approval) — opt-in, None = zero behavior change. The archive
  write happens BEFORE the status mutation (F167 ordering): an
  archive failure fails the denial closed rather than recording a
  denial the archive forgot.
- ``detect_cross_run_laundering(..., denied_archive=...)``
  consults the archive's live records with the SAME conjunctive
  fresh-ID match rule (same verb, every new atom matches,
  ``target_similarity`` >= ``FRESH_ID_SIMILARITY_THRESHOLD`` — no
  new similarity invented) and the same exercised guard where the
  prior's run is still in executed history.

Sensitivity (stated explicitly, same local-data treatment as the
intent ledger): the archive stores DENIED INTENT TEXT —
descriptions, targets, effects — i.e. what the agent wanted to do
when it was denied. Like drift profiles and the intent ledger, it
is sensitive operational data: whoever holds the archive file can
read denied objectives. It never leaves the operator's store (no
network, $0).

On-disk format (same tamper-evident JSONL trust pattern as
gov/taint_ledger.py, reusing gov/chained_store.canonical /
sha256_hex): header, chained denial records (``prev``/``digest``
linkage), footer with ``chain_tip`` + ``file_digest``. Fail-closed:
a damaged file raises ``DeniedGoalArchiveError`` and is never
silently accepted as a clean history. Writes are atomic (tmp file
+ os.replace).

Bound and TTL are operator policy:
- ``max_records`` (default 1000): LRU eviction — inserting past
  the bound evicts the least-recently-used record (``last_used``
  is bumped on record and on every ``priors_for`` consultation).
- ``ttl_seconds`` (default 90 days): records older than the TTL
  are invisible to ``priors_for`` and reaped by ``sweep()``.
- ``purge(agent_id=None)`` is the explicit deletion API.

Honest ceilings (documented, not hidden):
- Bound and TTL are operator policy and become calibration
  targets: an attacker who learns them can wait out the TTL or
  flood the bound with junk denials to evict a real one (the flood
  itself is visible — every denial is a chained audit event — but
  the eviction is silent by design).
- An exercised-then-superseded goal whose run aged out of
  executed_history will flag on re-mint: the archive cannot
  distinguish it from a never-exercised denial once the run's
  history is gone. The operator disambiguates via the audit trail
  (the exercised atoms are still in the chained log).
- Cross-run identity depends on a STABLE agent identity: a fresh
  agent_id per run defeats the archive (same boundary as the
  detector's existing attribution key).
- Single-writer assumption per archive file (last-writer-wins on
  os.replace). One writer per file; the operator owns the path.

$0 spend, stdlib only, deterministic (``decided_at``/``now``
injectable; LRU ties broken by insertion order).
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

from .chained_store import canonical, sha256_hex

__all__ = [
    "DeniedGoalArchive",
    "DeniedGoalArchiveError",
    "DENIED_GOAL_ARCHIVE_VERSION",
    "DEFAULT_ARCHIVE_TTL_SECONDS",
    "DEFAULT_ARCHIVE_MAX_RECORDS",
]

DENIED_GOAL_ARCHIVE_VERSION = "denied-goal-archive/1.0"

#: Default archive time-to-live: 90 days. Operator policy — tune to
#: the threat model (an attacker who knows the TTL can wait it out).
DEFAULT_ARCHIVE_TTL_SECONDS = 90 * 24 * 3600

#: Default bound on archived denials. Operator policy — tune to the
#: denial rate (an attacker who knows the bound can flood it).
DEFAULT_ARCHIVE_MAX_RECORDS = 1000

#: Chain genesis marker.
_GENESIS = "genesis"


class DeniedGoalArchiveError(Exception):
    """Raised when the denied-goal archive cannot be saved or loaded.

    Fail-closed: a damaged file is never silently accepted as a
    clean history.
    """


def _coerce_ts(value, name):
    """Coerce an ISO-8601 string or datetime to an ISO-8601 string."""
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            raise DeniedGoalArchiveError(
                "%s is not a parseable ISO-8601 timestamp: %r"
                % (name, value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    raise DeniedGoalArchiveError(
        "%s must be an ISO-8601 string or datetime, got %r"
        % (name, type(value).__name__))


def _parse_ts(iso):
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class DeniedGoalArchive:
    """Durable bounded archive of denied/superseded goals.

    ``path`` is the single JSONL archive file (created on first
    save). ``max_records`` bounds the archive (LRU eviction);
    ``ttl_seconds`` bounds record lifetime (operator policy). Both
    must be positive.
    """

    def __init__(self, path, max_records=DEFAULT_ARCHIVE_MAX_RECORDS,
                 ttl_seconds=DEFAULT_ARCHIVE_TTL_SECONDS):
        if (not isinstance(max_records, int) or max_records < 1):
            raise ValueError("max_records must be a positive int")
        if (not isinstance(ttl_seconds, (int, float))
                or ttl_seconds <= 0):
            raise ValueError("ttl_seconds must be a positive number")
        self._path = str(path)
        self._max_records = max_records
        self._ttl = timedelta(seconds=ttl_seconds)
        self._ttl_seconds = ttl_seconds
        # goal_id -> record dict (insertion-ordered; LRU by last_used)
        self._records = {}
        if os.path.exists(self._path):
            self._load()

    # -- writes -------------------------------------------------------
    def record_denial(self, goal, decided_at=None):
        """Archive one denied/superseded goal.

        ``goal`` is a goal dict (as returned by
        ``GoalRegistry.register``): ``goal_id``, ``agent_id`` (the
        principal — the schema carries no principal field),
        ``run_id``, ``description``, and ``effects`` ([verb, target]
        atoms) are extracted. ``decided_at`` is the denial time
        (ISO-8601 or datetime; defaults to now).

        LRU: inserting past ``max_records`` evicts the
        least-recently-used record. Re-recording the same goal_id
        refreshes it (re-denial re-arms the TTL). Returns a dict
        with counts/ids only.
        """
        if not isinstance(goal, dict):
            raise DeniedGoalArchiveError(
                "goal must be a dict, got %r" % (type(goal).__name__,))
        goal_id = goal.get("goal_id")
        agent_id = goal.get("agent_id")
        if not goal_id or not agent_id:
            raise DeniedGoalArchiveError(
                "goal has no goal_id/agent_id: the archive keys on "
                "stable agent identity")
        decided_iso = _coerce_ts(decided_at, "decided_at")
        effects = [list(e) for e in (goal.get("effects") or [])]
        record = {
            "goal_id": str(goal_id),
            "agent_id": str(agent_id),
            "run_id": goal.get("run_id"),
            "description": goal.get("description"),
            "effects": effects,
            "targets": sorted({str(t) for _verb, t in effects}),
            "decided_at": decided_iso,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "last_used": decided_iso,
        }
        self.sweep()
        self._records.pop(str(goal_id), None)
        self._records[str(goal_id)] = record
        evicted = None
        while len(self._records) > self._max_records:
            victim = min(self._records,
                         key=lambda gid: self._records[gid]["last_used"])
            evicted = self._records.pop(victim)["goal_id"]
        self.save()
        return {"recorded": True, "goal_id": str(goal_id),
                "agent_id": str(agent_id),
                "records_kept": len(self._records),
                "evicted_goal_id": evicted}

    # -- queries ------------------------------------------------------
    def _live(self, record, now):
        age = now - _parse_ts(record["decided_at"])
        return age <= self._ttl

    def priors_for(self, agent_id, now=None):
        """Live archived denials for one agent, as goal-like dicts.

        Each record carries ``status: "superseded"`` so the
        detector's existing narrowings apply unchanged, plus
        ``archive: True`` marking its provenance. Consulting bumps
        ``last_used`` (LRU). ``now`` accepts a datetime or ISO-8601
        string (test seam for TTL determinism). Expired records are
        not returned (and are reaped on the next ``sweep``).
        """
        agent_id = str(agent_id)
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        out = []
        touched = False
        for goal_id in list(self._records):
            rec = self._records[goal_id]
            if rec.get("agent_id") != agent_id:
                continue
            if not self._live(rec, now_dt):
                continue
            rec["last_used"] = now_dt.isoformat()
            touched = True
            out.append({"goal_id": rec["goal_id"],
                        "agent_id": rec["agent_id"],
                        "run_id": rec["run_id"],
                        "description": rec["description"],
                        "effects": [list(e) for e in rec["effects"]],
                        "status": "superseded",
                        "archive": True,
                        "decided_at": rec["decided_at"]})
        if touched:
            self.save()
        return out

    def live_count(self, agent_id=None, now=None):
        """Number of live records (optionally for one agent)."""
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        return sum(
            1 for rec in self._records.values()
            if self._live(rec, now_dt)
            and (agent_id is None
                 or rec.get("agent_id") == str(agent_id)))

    # -- expiry / deletion --------------------------------------------
    def sweep(self, now=None):
        """Delete expired records. Returns the count removed."""
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        removed = 0
        for goal_id in list(self._records):
            if not self._live(self._records[goal_id], now_dt):
                del self._records[goal_id]
                removed += 1
        if removed:
            self.save()
        return removed

    def purge(self, agent_id=None):
        """Explicit deletion API.

        ``purge(agent_id)`` removes that agent's archived denials;
        ``purge()`` clears the whole archive. Returns the count of
        records removed. The deletion is persisted immediately.
        """
        removed = 0
        if agent_id is None:
            removed = len(self._records)
            self._records = {}
        else:
            agent_id = str(agent_id)
            for goal_id in list(self._records):
                if self._records[goal_id].get("agent_id") == agent_id:
                    del self._records[goal_id]
                    removed += 1
        self.save()
        return removed

    # -- persistence --------------------------------------------------
    def save(self):
        """Persist the archive atomically (tmp file + os.replace)."""
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        lines = []
        header = {"record": "header",
                  "denied_goal_archive": DENIED_GOAL_ARCHIVE_VERSION,
                  "created_at": datetime.now(timezone.utc).isoformat(),
                  "ttl_seconds": self._ttl_seconds,
                  "max_records": self._max_records}
        lines.append(canonical(header))
        prev = _GENESIS
        for goal_id in sorted(self._records):
            rec = self._records[goal_id]
            body = {"record": "denial",
                    "goal_id": rec["goal_id"],
                    "agent_id": rec["agent_id"],
                    "run_id": rec["run_id"],
                    "description": rec["description"],
                    "effects": rec["effects"],
                    "targets": rec["targets"],
                    "decided_at": rec["decided_at"],
                    "recorded_at": rec["recorded_at"],
                    "last_used": rec["last_used"],
                    "prev": prev}
            body["digest"] = sha256_hex(canonical(body))
            prev = body["digest"]
            lines.append(canonical(body))
        file_digest = sha256_hex("\n".join(lines))
        footer = {"record": "footer", "chain_tip": prev,
                  "file_digest": file_digest}
        lines.append(canonical(footer))
        fd, tmp = tempfile.mkstemp(dir=parent, prefix=".denyarch-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                raw_lines = [ln.rstrip("\n") for ln in fh]
        except OSError as e:
            raise DeniedGoalArchiveError(
                "cannot read denied-goal archive %r: %s" % (self._path, e))
        lines = [ln for ln in raw_lines if ln.strip()]
        if not lines:
            raise DeniedGoalArchiveError(
                "denied-goal archive %r is empty: refusing to treat as "
                "clean history" % self._path)
        try:
            records = [json.loads(ln) for ln in lines]
        except ValueError as e:
            raise DeniedGoalArchiveError(
                "denied-goal archive %r has a corrupt line: %s"
                % (self._path, e))
        header = records[0]
        if (not isinstance(header, dict)
                or header.get("record") != "header"
                or header.get("denied_goal_archive")
                != DENIED_GOAL_ARCHIVE_VERSION):
            raise DeniedGoalArchiveError(
                "denied-goal archive %r has a bad header: refusing to "
                "treat as clean history" % self._path)
        footer = records[-1]
        if not isinstance(footer, dict) or footer.get("record") != "footer":
            raise DeniedGoalArchiveError(
                "denied-goal archive %r is missing its footer: "
                "refusing to treat as clean history" % self._path)
        kept = {}
        prev = _GENESIS
        for entry in records[1:-1]:
            if (not isinstance(entry, dict)
                    or entry.get("record") != "denial"):
                raise DeniedGoalArchiveError(
                    "denied-goal archive %r has a non-denial record: "
                    "refusing to treat as clean history" % self._path)
            for field in ("goal_id", "agent_id", "run_id",
                          "description", "effects", "targets",
                          "decided_at", "recorded_at", "last_used",
                          "prev", "digest"):
                if field not in entry:
                    raise DeniedGoalArchiveError(
                        "denied-goal archive %r record is missing %r: "
                        "refusing to treat as clean history"
                        % (self._path, field))
            if entry["prev"] != prev:
                raise DeniedGoalArchiveError(
                    "denied-goal archive %r chain linkage broken at "
                    "%r: refusing to treat as clean history"
                    % (self._path, entry.get("goal_id")))
            body = {k: v for k, v in entry.items() if k != "digest"}
            if sha256_hex(canonical(body)) != entry["digest"]:
                raise DeniedGoalArchiveError(
                    "denied-goal archive %r record digest mismatch at "
                    "%r: refusing to treat as clean history"
                    % (self._path, entry.get("goal_id")))
            prev = entry["digest"]
            # Re-validate timestamps parse (fail-closed on garbage).
            _parse_ts(_coerce_ts(entry["decided_at"], "decided_at"))
            _parse_ts(_coerce_ts(entry["recorded_at"], "recorded_at"))
            _parse_ts(_coerce_ts(entry["last_used"], "last_used"))
            kept[str(entry["goal_id"])] = {
                k: entry[k] for k in
                ("goal_id", "agent_id", "run_id", "description",
                 "effects", "targets", "decided_at", "recorded_at",
                 "last_used")}
        self._records = kept
