"""Cross-run known-destination ledger (row 13, wave-140 lane 2).

Row-13 residual after wave-139: the taint ledger persists READ-taint
but not destination history — the behavioral tier's destination
novelty check stayed per-run. A destination first used in run 1 was
novel again in run 2, so a legit read-then-send to a known
destination flagged every run (pinned EXPECTED in
``evals/cross_run_taint_probes.py`` x7). This module is the durable
destination-side counterpart: it persists the egress destinations
an agent has used, keyed by stable agent identity, so a later run's
egress check evaluates "novel destination" against run-1..N
history, not just the current run.

How it is used:
- ``RareTokenTracker(destination_ledger=...)`` records each egress
  destination durably at check time and consults the ledger when
  computing destination novelty: a destination is novel iff it is
  neither seen in-run nor known in the ledger. ``destination_ledger``
  is opt-in (None = zero behavior change, pinned by
  ``test_no_ledger_zero_behavior_change`` in
  tests/test_destination_ledger.py and battery x0).
- Ledger failures propagate fail-closed (a check whose destination
  cannot be recorded raises rather than silently dropping
  history) — mirroring ``observe_read``'s taint-ledger discipline.

Privacy contract (stated explicitly, not assumed):
- Destinations are ALREADY audit-logged in plaintext: the tracker's
  verdict dict carries ``destination`` and the executor chains the
  LOUD ``read_then_egress_novel`` event with it. The ledger stores
  destinations in the same plaintext treatment as the audit log —
  it creates NO new sensitive category. It records WHERE bytes went
  (a URL, an email address, an API endpoint), never what the bytes
  contained.
- The ledger never leaves the operator's store (no network, $0),
  same local-data treatment as the audit log itself.

On-disk format (same tamper-evident JSONL trust pattern as
``gov/taint_ledger.py``, reusing ``gov/chained_store.canonical`` /
``sha256_hex``): one JSONL file with a header record, chained
destination records (``prev``/``digest`` linkage), and a footer
carrying ``chain_tip`` + ``file_digest``. Fail-closed: a damaged
file raises ``DestinationLedgerError`` and is never silently
accepted as a clean history. Writes are atomic (tmp file +
os.replace).

TTL/expiry is operator policy: ``ttl_seconds`` (default 7 days).
Expired destinations are invisible to ``known`` and reaped by
``sweep``. ``purge(agent_id=None)`` is the explicit deletion API.

Honest ceilings (documented, not hidden):
- Footer validation (chain_tip + file_digest checked on load) makes
  accidental or naive tampering fail closed, but a deliberate
  attacker who rewrites the whole file consistently (truncation +
  forged footer) can still evade it -- the local ledger has no
  external anchor. Same ceiling as the taint ledger and the goal
  registry: tamper-EVIDENT, not tamper-PROOF.
- TTL is operator policy and attacker-visible in effect: an
  attacker who knows the TTL can wait a destination out (a
  destination unused for the TTL window reads novel again).
- Cross-run identity depends on a STABLE agent identity: a fresh
  agent id per run defeats the ledger (same boundary as the taint
  ledger and the drift lane's per-agent profiles).
- Destination history proves WHERE bytes went, not WHAT they
  contained: knowing a destination is not knowing the payload.
- Recording happens at egress-CHECK time (attempted destinations):
  the ledger cannot distinguish a completed egress from one that
  was flagged and later blocked downstream.
- Single-writer assumption: concurrent writers to one ledger file
  are not safe (last-writer-wins on os.replace). One writer per
  ledger file; the operator owns the path.

$0 spend, stdlib only, deterministic (TTL tests inject
``observed_at``/``now``).
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

from .chained_store import canonical, sha256_hex

__all__ = [
    "DestinationLedger",
    "DestinationLedgerError",
    "DESTINATION_LEDGER_VERSION",
    "DEFAULT_DESTINATION_TTL_SECONDS",
    "MAX_DESTINATIONS_PER_AGENT",
]

DESTINATION_LEDGER_VERSION = "destination-ledger/1.0"

#: Default destination time-to-live: 7 days. Operator policy — tune
#: to the threat model (an attacker who knows the TTL can wait a
#: destination out).
DEFAULT_DESTINATION_TTL_SECONDS = 7 * 24 * 3600

#: Per-agent destination cap: keeps the file bounded (the ledger
#: records every distinct destination the agent ever used). Oldest
#: entries evict first when the cap is exceeded.
MAX_DESTINATIONS_PER_AGENT = 256

#: Destination strings longer than this are rejected fail-closed
#: (they would bloat the ledger; a real egress destination is a
#: URL/email/endpoint, not a megabyte blob).
MAX_DESTINATION_LENGTH = 2048

#: Chain genesis marker.
_GENESIS = "genesis"


class DestinationLedgerError(Exception):
    """Raised when the destination ledger cannot be saved or loaded.

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
            raise DestinationLedgerError(
                "%s is not a parseable ISO-8601 timestamp: %r"
                % (name, value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    raise DestinationLedgerError(
        "%s must be an ISO-8601 string or datetime, got %r"
        % (name, type(value).__name__))


def _parse_ts(iso):
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_destination(destination):
    """Normalize one destination string. Fail-closed on garbage."""
    if not isinstance(destination, str):
        raise DestinationLedgerError(
            "destination must be a string, got %r"
            % (type(destination).__name__,))
    dest = destination.strip()
    if not dest:
        raise DestinationLedgerError(
            "destination must be a non-empty string")
    if len(dest) > MAX_DESTINATION_LENGTH:
        raise DestinationLedgerError(
            "destination longer than %d chars: refusing to record"
            % MAX_DESTINATION_LENGTH)
    return dest


class DestinationLedger:
    """Durable known-destination history, keyed by stable agent identity.

    ``path`` is the single JSONL ledger file (created on first
    save). ``ttl_seconds`` is the operator-configurable destination
    lifetime — a construction-time policy; the header records the
    TTL at write time for audit, but the constructor value governs
    reads (an operator may legitimately retune TTL between runs).
    No key is needed: destinations are stored plaintext like the
    audit log (see the privacy contract in the module docstring).
    """

    def __init__(self, path,
                 ttl_seconds=DEFAULT_DESTINATION_TTL_SECONDS):
        if (not isinstance(ttl_seconds, (int, float))
                or ttl_seconds <= 0):
            raise ValueError("ttl_seconds must be a positive number")
        self._path = str(path)
        self._ttl = timedelta(seconds=ttl_seconds)
        self._ttl_seconds = ttl_seconds
        # agent_id -> {destination: record dict}
        self._agents = {}
        if os.path.exists(self._path):
            self._load()

    # -- writes -------------------------------------------------------
    def record(self, agent_id, destination, observed_at=None):
        """Record that ``agent_id`` used ``destination``.

        Re-recording refreshes the TTL. Expired destinations are
        swept first so the file stays bounded; a per-agent cap
        (``MAX_DESTINATIONS_PER_AGENT``) evicts the oldest entries.
        Returns a dict with counts/ids only.
        """
        agent_id = str(agent_id)
        dest = _normalize_destination(destination)
        self.sweep()
        dests = self._agents.setdefault(agent_id, {})
        dests[dest] = {"destination": dest,
                       "observed_at": _coerce_ts(observed_at,
                                                 "observed_at")}
        while len(dests) > MAX_DESTINATIONS_PER_AGENT:
            oldest = min(dests,
                         key=lambda d: dests[d]["observed_at"])
            del dests[oldest]
        self.save()
        return {"recorded": True, "agent_id": agent_id,
                "destination": dest,
                "destinations_known": len(dests)}

    # -- queries ------------------------------------------------------
    def _live(self, record, now):
        age = now - _parse_ts(record["observed_at"])
        return age <= self._ttl

    def known(self, agent_id, destination, now=None):
        """Is ``destination`` known for ``agent_id`` (live, unexpired)?

        ``now`` accepts a datetime or ISO-8601 string (test seam for
        TTL determinism). Unparseable destination strings read as
        unknown rather than raising (a query must never break a
        check; recording is the fail-closed half).
        """
        try:
            dest = _normalize_destination(destination)
        except DestinationLedgerError:
            return False
        agent_id = str(agent_id)
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        rec = self._agents.get(agent_id, {}).get(dest)
        return rec is not None and self._live(rec, now_dt)

    def destinations_for(self, agent_id, now=None):
        """Sorted live destinations known for one agent."""
        agent_id = str(agent_id)
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        return sorted(
            dest for dest, rec in self._agents.get(agent_id, {}).items()
            if self._live(rec, now_dt))

    # -- expiry / deletion --------------------------------------------
    def sweep(self, now=None):
        """Delete expired destinations. Returns the count removed."""
        now_dt = _parse_ts(_coerce_ts(now, "now")) if now is not None \
            else datetime.now(timezone.utc)
        removed = 0
        for agent_id in list(self._agents):
            dests = self._agents[agent_id]
            for dest in list(dests):
                if not self._live(dests[dest], now_dt):
                    del dests[dest]
                    removed += 1
            if not dests:
                del self._agents[agent_id]
        if removed:
            self.save()
        return removed

    def purge(self, agent_id=None):
        """Explicit deletion API.

        ``purge(agent_id)`` removes that agent's destinations;
        ``purge()`` clears the whole ledger. Returns the count of
        records removed. The deletion is persisted immediately.
        """
        removed = 0
        if agent_id is None:
            for dests in self._agents.values():
                removed += len(dests)
            self._agents = {}
        else:
            dests = self._agents.pop(str(agent_id), {})
            removed = len(dests)
        self.save()
        return removed

    # -- persistence --------------------------------------------------
    def save(self):
        """Persist the ledger atomically (tmp file + os.replace)."""
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        lines = []
        header = {"record": "header",
                  "destination_ledger": DESTINATION_LEDGER_VERSION,
                  "created_at": datetime.now(timezone.utc).isoformat(),
                  "ttl_seconds": self._ttl_seconds}
        lines.append(canonical(header))
        prev = _GENESIS
        for agent_id in sorted(self._agents):
            for dest in sorted(self._agents[agent_id]):
                rec = self._agents[agent_id][dest]
                body = {"record": "destination",
                        "agent_id": agent_id,
                        "destination": dest,
                        "observed_at": rec["observed_at"],
                        "prev": prev}
                body["digest"] = sha256_hex(canonical(body))
                prev = body["digest"]
                lines.append(canonical(body))
        file_digest = sha256_hex("\n".join(lines))
        footer = {"record": "footer", "chain_tip": prev,
                  "file_digest": file_digest}
        lines.append(canonical(footer))
        fd, tmp = tempfile.mkstemp(dir=parent,
                                    prefix=".dest-ledger-")
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
            raise DestinationLedgerError(
                "cannot read destination ledger %r: %s" % (self._path, e))
        lines = [ln for ln in raw_lines if ln.strip()]
        if not lines:
            raise DestinationLedgerError(
                "destination ledger %r is empty: refusing to treat as "
                "clean history" % self._path)
        try:
            records = [json.loads(ln) for ln in lines]
        except ValueError as e:
            raise DestinationLedgerError(
                "destination ledger %r has a corrupt line: %s"
                % (self._path, e))
        header = records[0]
        if (not isinstance(header, dict)
                or header.get("record") != "header"
                or header.get("destination_ledger")
                != DESTINATION_LEDGER_VERSION):
            raise DestinationLedgerError(
                "destination ledger %r has a bad header: refusing to "
                "treat as clean history" % self._path)
        footer = records[-1]
        if not isinstance(footer, dict) or footer.get("record") != "footer":
            raise DestinationLedgerError(
                "destination ledger %r is missing its footer: refusing "
                "to treat as clean history" % self._path)
        agents = {}
        prev = _GENESIS
        for entry in records[1:-1]:
            if (not isinstance(entry, dict)
                    or entry.get("record") != "destination"):
                raise DestinationLedgerError(
                    "destination ledger %r has a non-destination "
                    "record: refusing to treat as clean history"
                    % self._path)
            for field in ("agent_id", "destination", "observed_at",
                          "prev", "digest"):
                if field not in entry:
                    raise DestinationLedgerError(
                        "destination ledger %r record is missing %r: "
                        "refusing to treat as clean history"
                        % (self._path, field))
            if entry["prev"] != prev:
                raise DestinationLedgerError(
                    "destination ledger %r chain linkage broken at %r: "
                    "refusing to treat as clean history"
                    % (self._path, entry.get("destination")))
            body = {k: v for k, v in entry.items() if k != "digest"}
            if sha256_hex(canonical(body)) != entry["digest"]:
                raise DestinationLedgerError(
                    "destination ledger %r record digest mismatch at "
                    "%r: refusing to treat as clean history"
                    % (self._path, entry.get("destination")))
            prev = entry["digest"]
            # Re-validate the timestamp parses (fail-closed on garbage).
            _parse_ts(_coerce_ts(entry["observed_at"], "observed_at"))
            dest = _normalize_destination(entry["destination"])
            agents.setdefault(str(entry["agent_id"]),
                              {})[dest] = {
                "destination": dest,
                "observed_at": _coerce_ts(entry["observed_at"],
                                          "observed_at")}
        # Wave-140 audit fix: the footer binds the whole file. Without
        # these two checks a truncation (drop the last N records, forge
        # a fresh footer) would load silently -- record linkage and
        # per-record digests alone cannot catch it.
        if footer.get("chain_tip") != prev:
            raise DestinationLedgerError(
                "destination ledger %r chain_tip mismatch: refusing "
                "to treat as clean history" % self._path)
        if footer.get("file_digest") != sha256_hex("\n".join(lines[:-1])):
            raise DestinationLedgerError(
                "destination ledger %r file_digest mismatch: refusing "
                "to treat as clean history" % self._path)
        self._agents = agents
