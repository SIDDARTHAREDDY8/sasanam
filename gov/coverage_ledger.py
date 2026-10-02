"""Honest detection-coverage ledger for the monitor-but-count seam.

The monitor verdict accounting (``gov.gate_hardening.monitor_report`` /
``scan_summary``, wave-273 lane A) counts what the gate's own logic *would*
decide. This module turns those counters into an honest coverage story: a
dated score logbook per technique/attack-shape, a visibility-vs-detection
split, data-quality contracts on the telemetry sources, and a discipline
rule that a coverage percentage is never emitted without its denominator
and proof method. Coverage of monitor-mode verdicts never implies
prevention.

Pattern provenance: the measurement discipline (dated -1..5 score logbook,
visibility scored separately from detection, data-quality dimensions on
sources, denominator+proof-method required for any percentage) is adapted
from rabobank-cdc/DeTTECT, which is GPL-3.0. **Patterns only -- no DeTTECT
code was reused, no DeTTECT file format adopted, no ATT&CK mapping
borrowed.** This module is a clean-room reimplementation shaped for the
agent-governance domain (monitor-mode verdicts, not blue-team rules).

Score scale (per technique, dated entries):
  -1  no coverage (technique not observable, not scored)
   0  visible/logged only -- recorded, does NOT count toward detection
   1  signature-level (would-deny on a known shape)
   2  correlation (multi-signal)
   3  analytics (real-time scoring)
   4  very good (most known aspects)
   5  excellent (all known aspects)

The logbook is append-only and hash-chained: every score entry carries the
digest of the previous entry (``GENESIS`` first). New entries are chained
with HMAC-SHA256 under the deployment key via ``gov.chained_store`` (the
same idiom as the audit log); without a configured key this module makes
its own honestly-marked choice and chains with unkeyed SHA-256, recording
``chain_keyed: false`` (``gov.chained_store`` itself fails closed on
append without a key -- the fallback is this module's decision, not its).
``verify_chain`` re-computes every link; rewritten history refuses
``coverage-logbook-chain-broken``. Entries are timestamp-monotonic: a
score dated earlier than the previous entry refuses
``coverage-refused-backdated-entry``; a score dated more than
``MAX_FUTURE_SKEW`` (5 minutes) in the future refuses
``coverage-refused-future-dated-entry`` -- a far-future stamp would
otherwise brick the logbook, since every later honest append would
refuse as backdated relative to it (F298).

Visibility is recorded independently of detection: a technique may be
FULLY visible and score 0 (monitor-but-count sees it and counts it, but
does not detect it). ``emit_coverage`` counts only scores >= 1 whose
telemetry sources all pass their quality contract; score-0 techniques are
reported under ``visible_not_detected`` and never in the numerator.

Data quality: each telemetry source carries five dimensions
(completeness, freshness, depth, brittleness, integrity), each 0..5. A
source passes its contract iff every dimension is >= 3
(``QUALITY_CONTRACT_MIN``). A technique whose sources fail the contract
is excluded from the numerator with an explicit ``qualified_exclusions``
entry -- never silently counted, never silently dropped.

Honest limits: the ledger records *claimed* proof methods; it cannot run
them. A percentage is point-in-time. The ledger is always monitor-mode:
``declare_prevention`` refuses ``coverage-refused-monitor-implies-
prevention`` unconditionally -- monitor-mode coverage is evidence of
visibility, never of prevention.

$0, stdlib only, deterministic (timestamps are explicit arguments in
tests; ``utcnow_iso`` only fills the default).
"""

import copy
import hmac
from datetime import datetime, timedelta, timezone

from . import chained_store as _cs
from .keys import NoKeyConfiguredError

__all__ = [
    "CoverageLedger",
    "CoverageLedgerError",
    "SCORE_NONE",
    "SCORE_VISIBLE_ONLY",
    "SCORE_MIN",
    "SCORE_MAX",
    "VISIBILITIES",
    "QUALITY_DIMS",
    "QUALITY_CONTRACT_MIN",
    "GENESIS",
    "utcnow_iso",
]

# --- score scale ------------------------------------------------------------
SCORE_NONE = -1          # no coverage
SCORE_VISIBLE_ONLY = 0   # visible/logged only -- never counts as detection
SCORE_MIN = -1
SCORE_MAX = 5

VISIBILITIES = ("NONE", "PARTIAL", "FULL")

QUALITY_DIMS = ("completeness", "freshness", "depth",
                "brittleness", "integrity")
QUALITY_CONTRACT_MIN = 3

GENESIS = "GENESIS"
_CHAIN_DOMAIN = "coverage-ledger"

# Decision codes emitted by this module (registered in gov/decision_codes.py).
REFUSED_NO_DENOMINATOR = "coverage-refused-no-denominator"
REFUSED_NO_PROOF_METHOD = "coverage-refused-no-proof-method"
REFUSED_BACKDATED_ENTRY = "coverage-refused-backdated-entry"
REFUSED_FUTURE_DATED_ENTRY = "coverage-refused-future-dated-entry"
REFUSED_MONITOR_IMPlIES_PREVENTION = "coverage-refused-monitor-implies-prevention"
CHAIN_BROKEN = "coverage-logbook-chain-broken"

# Clock-skew tolerance for score timestamps. A stamp modestly in the
# future is accepted (operator/automation clock skew), but a stamp
# beyond this bound is refused fail-closed with
# coverage-refused-future-dated-entry: a single far-future stamp would
# otherwise brick the technique's logbook (F298), since every later
# honest append would refuse as "backdated" relative to it, with no
# recovery API. The tolerance is deliberately small -- scoring "now"
# is the normal case, and a loud refusal beats a silently poisoned
# evidence pipeline.
MAX_FUTURE_SKEW = timedelta(minutes=5)


class CoverageLedgerError(Exception):
    """Coded refusal from the coverage ledger. ``.code`` is the decision code."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value):
    try:
        dt = datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        raise ValueError("scored_at is not ISO-8601: %r" % (value,))
    if dt.tzinfo is None:
        raise ValueError("scored_at must carry a timezone: %r" % (value,))
    return dt


def _check_dims(dims):
    if not isinstance(dims, dict):
        raise ValueError("source quality must be a dict, got %r" % (dims,))
    missing = [d for d in QUALITY_DIMS if d not in dims]
    if missing:
        raise ValueError("source quality missing dimensions: %r" % (missing,))
    for dim in QUALITY_DIMS:
        value = dims[dim]
        if not isinstance(value, int) or isinstance(value, bool) \
                or not 0 <= value <= 5:
            raise ValueError(
                "quality dimension %r must be int 0..5, got %r" % (dim, value))
    return {dim: dims[dim] for dim in QUALITY_DIMS}


def _contract_ok(dims):
    return all(dims[dim] >= QUALITY_CONTRACT_MIN for dim in QUALITY_DIMS)


class CoverageLedger:
    """Dated, chained, honest coverage ledger for monitor-mode verdicts."""

    def __init__(self):
        # technique_id -> {"visibility": str,
        #                  "sources": {source_id: {dim: int}},
        #                  "logbook": [entry, ...]}
        self._techniques = {}
        self._code_map = {}  # would-deny code -> technique_id

    # -- technique registration ------------------------------------------
    def record_technique(self, technique_id, visibility, sources=None):
        """Register a technique with its visibility and telemetry sources."""
        tid = str(technique_id)
        if visibility not in VISIBILITIES:
            raise ValueError("visibility must be one of %r, got %r"
                             % (VISIBILITIES, visibility))
        checked = {}
        for source_id, dims in (sources or {}).items():
            try:
                checked[str(source_id)] = _check_dims(dims)
            except ValueError as exc:
                raise ValueError("source %r: %s" % (source_id, exc))
        entry = self._techniques.get(tid)
        if entry is None:
            self._techniques[tid] = {"visibility": visibility,
                                     "sources": checked,
                                     "logbook": []}
        else:
            entry["visibility"] = visibility
            entry["sources"].update(checked)
        return tid

    def register_code_mapping(self, code, technique_id):
        """Map a monitor would-deny code to a technique id."""
        self._code_map[str(code)] = str(technique_id)

    def set_source_quality(self, source_id, dims):
        """Update a telemetry source's quality everywhere it is referenced."""
        checked = _check_dims(dims)
        sid = str(source_id)
        found = False
        for tech in self._techniques.values():
            if sid in tech["sources"]:
                tech["sources"][sid] = dict(checked)
                found = True
        if not found:
            raise ValueError("unknown telemetry source: %r" % (sid,))

    # -- scoring (append-only, chained, monotonic) ------------------------
    def score(self, technique_id, score, proof_method,
              scored_at=None, recorded_by="operator", note=None):
        """Append a dated score entry to the technique's logbook.

        ``scored_at`` must be timezone-aware ISO-8601 (malformed values
        are a ValueError); a stamp earlier than the previous entry
        refuses ``coverage-refused-backdated-entry``; a stamp more than
        ``MAX_FUTURE_SKEW`` in the future refuses
        ``coverage-refused-future-dated-entry`` (F298 -- a far-future
        stamp would otherwise brick the logbook, since every later
        honest append would refuse as backdated relative to it).
        ``note`` is optional free-text metadata covered by the entry's
        digest.
        """
        tid = str(technique_id)
        if tid not in self._techniques:
            raise ValueError("unknown technique: %r" % (tid,))
        if not isinstance(score, int) or isinstance(score, bool) \
                or not SCORE_MIN <= score <= SCORE_MAX:
            raise ValueError("score must be int %d..%d, got %r"
                             % (SCORE_MIN, SCORE_MAX, score))
        if not isinstance(proof_method, str) or not proof_method.strip():
            raise CoverageLedgerError(
                REFUSED_NO_PROOF_METHOD,
                "a score entry must name its proof method")
        stamp = _parse_ts(scored_at) if scored_at is not None \
            else _parse_ts(utcnow_iso())
        if stamp > _parse_ts(utcnow_iso()) + MAX_FUTURE_SKEW:
            raise CoverageLedgerError(
                REFUSED_FUTURE_DATED_ENTRY,
                "scored_at %s is more than %s in the future; refused -- "
                "a far-future stamp would brick the logbook (F298)"
                % (stamp.isoformat(), MAX_FUTURE_SKEW))
        book = self._techniques[tid]["logbook"]
        if book and stamp < _parse_ts(book[-1]["scored_at"]):
            raise CoverageLedgerError(
                REFUSED_BACKDATED_ENTRY,
                "scored_at %s predates previous entry %s"
                % (stamp.isoformat(), book[-1]["scored_at"]))
        prev = book[-1]["digest"] if book else GENESIS
        entry = {"technique_id": tid,
                 "seq": len(book),
                 "scored_at": stamp.isoformat(),
                 "score": score,
                 "proof_method": proof_method.strip(),
                 "recorded_by": str(recorded_by),
                 "prev_digest": prev}
        if note is not None:
            entry["note"] = str(note)
        entry.update(self._chain_record(entry))
        book.append(entry)
        return copy.deepcopy(entry)

    def _chain_record(self, entry):
        """Digest for one logbook entry (keyed when a key is configured)."""
        try:
            key, epoch = _cs.resolve_chain_key()
        except NoKeyConfiguredError:
            # No key configured: unkeyed SHA-256 chain, honestly marked.
            # Only the keyprovider's loud absence error is caught -- any
            # other failure propagates rather than silently downgrading.
            body = _cs.canonical(entry)
            return {"chain_keyed": False,
                    "digest": _cs.sha256_hex(body)}
        record = dict(entry)
        record["chain_keyed"] = True
        record["key_epoch"] = epoch
        digest = _cs.keyed_digest(record, key,
                                  _cs.chain_domain(_CHAIN_DOMAIN))
        return {"chain_keyed": True, "key_epoch": epoch, "digest": digest}

    def _expected_digest(self, entry):
        """Recompute the digest a genuine entry must carry."""
        if entry.get("chain_keyed"):
            record = {k: v for k, v in entry.items() if k != "digest"}
            key, _epoch = _cs.resolve_chain_key()
            return _cs.keyed_digest(record, key,
                                    _cs.chain_domain(_CHAIN_DOMAIN))
        body = _cs.canonical({k: v for k, v in entry.items()
                              if k not in ("digest", "chain_keyed",
                                           "key_epoch")})
        return _cs.sha256_hex(body)

    # -- verification -----------------------------------------------------
    def verify_chain(self, entries):
        """Verify a logbook artifact: linkage, digests, monotonicity.

        Raises CoverageLedgerError(CHAIN_BROKEN) on rewritten history,
        dropped entries, broken linkage, or digest mismatch. Verifying a
        keyed chain without the deployment key configured raises the
        keyprovider's NoKeyConfiguredError (loud, never treated as
        intact). Returns the number of verified entries.
        """
        prev = GENESIS
        last_ts = None
        for entry in entries or []:
            if not isinstance(entry, dict):
                raise CoverageLedgerError(CHAIN_BROKEN,
                                          "logbook entry is not a dict")
            if entry.get("prev_digest") != prev:
                raise CoverageLedgerError(
                    CHAIN_BROKEN,
                    "entry %r breaks prev_digest linkage"
                    % (entry.get("seq"),))
            digest = entry.get("digest")
            if not isinstance(digest, str) or not hmac.compare_digest(
                    digest, self._expected_digest(entry)):
                raise CoverageLedgerError(
                    CHAIN_BROKEN,
                    "entry %r digest mismatch (rewritten history)"
                    % (entry.get("seq"),))
            stamp = _parse_ts(entry.get("scored_at"))
            if last_ts is not None and stamp < last_ts:
                raise CoverageLedgerError(
                    CHAIN_BROKEN,
                    "entry %r predates its predecessor"
                    % (entry.get("seq"),))
            last_ts = stamp
            prev = entry["digest"]
        return len(entries or [])

    def verify_all(self):
        """Verify every technique's logbook. Returns total entries verified."""
        total = 0
        for tid in self._techniques:
            total += self.verify_chain(self.logbook(tid))
        return total

    # -- reads ------------------------------------------------------------
    def logbook(self, technique_id):
        """Deep copy of a technique's score logbook (the auditable artifact)."""
        tid = str(technique_id)
        if tid not in self._techniques:
            raise ValueError("unknown technique: %r" % (tid,))
        return copy.deepcopy(self._techniques[tid]["logbook"])

    def latest_score(self, technique_id):
        """Latest score entry, or None if unscored/unknown."""
        tid = str(technique_id)
        if tid not in self._techniques:
            return None
        book = self._techniques[tid]["logbook"]
        return copy.deepcopy(book[-1]) if book else None

    # -- monitor wiring ---------------------------------------------------
    def ingest_monitor_report(self, report):
        """Turn lane-A monitor verdict counters into ledger entries.

        Accepts both lane-A shapes: ``monitor_report()``
        (``mode == "monitor"``, ``monitor_would_deny``) and
        ``scan_summary()`` (``would_deny``/``would_allow``, no mode key).
        Each would-deny code becomes (or extends) a technique with
        PARTIAL visibility -- a counter proves the monitor observed
        matching requests, not full technique visibility -- and a score-0
        entry (visible/logged only; monitor mode never detects). Codes
        without a registered mapping get an explicit ``unmapped:<code>``
        technique so nothing is silently absorbed. Re-ingesting an
        unchanged observation (same code, same counter) does not append
        a duplicate entry: the count is recorded in the entry's note, so
        a changed count is new information and an identical one is not.
        """
        if not isinstance(report, dict):
            raise ValueError("ingest_monitor_report needs a lane-A "
                             "report dict")
        if report.get("mode") == "monitor":
            deny = report.get("monitor_would_deny") or {}
            proof_method = "monitor-counts"
            origin = "monitor-ingest"
            n_allow = report.get("monitor_would_allow", 0)
            n_eval = report.get("monitor_evaluations", 0)
        elif "would_deny" in report and "mode" not in report:
            deny = report.get("would_deny") or {}
            proof_method = "scan-summary"
            origin = "scan-ingest"
            n_allow = report.get("would_allow", 0)
            deny_total = sum(v for v in deny.values()
                             if isinstance(v, int) and v > 0)
            n_eval = n_allow + deny_total
        else:
            raise ValueError(
                "ingest_monitor_report needs a lane-A monitor_report() "
                "or scan_summary() dict, got %r" % (report.get("mode"),))
        if not isinstance(deny, dict):
            raise ValueError("deny counters must be a dict")
        stamp = utcnow_iso()
        ingested = 0
        for code, count in deny.items():
            if not isinstance(count, int) or isinstance(count, bool) \
                    or count <= 0:
                continue
            tid = self._code_map.get(str(code), "unmapped:" + str(code))
            if tid not in self._techniques:
                self.record_technique(tid, visibility="PARTIAL")
            note = "would_deny_count=%d" % (count,)
            latest = self._techniques[tid]["logbook"]
            if latest and latest[-1]["score"] == SCORE_VISIBLE_ONLY \
                    and latest[-1].get("proof_method") == proof_method \
                    and latest[-1].get("note") == note:
                continue  # unchanged observation: not new information
            self.score(tid, SCORE_VISIBLE_ONLY,
                       proof_method=proof_method,
                       scored_at=stamp,
                       recorded_by="%s:%s" % (origin, code),
                       note=note)
            ingested += 1
        return {"techniques_ingested": ingested,
                "would_allow": n_allow,
                "evaluations": n_eval}

    # -- honest emission --------------------------------------------------
    def emit_coverage(self, denominator, proof_method):
        """Emit a coverage report. Refuses without denominator+proof method.

        Only scores >= 1 whose telemetry sources all pass their quality
        contract count. A technique with no recorded sources has
        ``sources_contract_ok`` None and is excluded (nothing to verify)
        rather than counted as True. Score-0 techniques are reported
        under ``visible_not_detected``; source-quality failures land in
        ``qualified_exclusions`` -- never silently counted, never silently
        dropped. The report always carries ``prevents: False``: this
        ledger is monitor-mode and never claims prevention.

        The denominator is deduplicated (first-occurrence order kept)
        before counting: a repeated technique id is one technique, and
        the number removed is reported as ``duplicates_removed``.
        """
        if not denominator or isinstance(denominator, str) \
                or not isinstance(denominator, (list, tuple)):
            raise CoverageLedgerError(
                REFUSED_NO_DENOMINATOR,
                "a coverage percentage requires a non-empty denominator "
                "list of technique ids (a bare string is malformed, not "
                "a denominator)")
        if not isinstance(proof_method, str) or not proof_method.strip():
            raise CoverageLedgerError(
                REFUSED_NO_PROOF_METHOD,
                "a coverage percentage requires its proof method")
        denominator = [str(t) for t in denominator]
        # F297: deduplicate the denominator at the honesty boundary. A
        # programmatically-built denominator (e.g. merging two technique
        # lists) can repeat a technique id; counting each occurrence
        # independently silently inflates the percentage, which is the
        # dishonest evidence artifact this module exists to prevent.
        # First-occurrence order is preserved so the detail mapping is
        # stable; the count removed is reported, never silently dropped.
        seen = set()
        unique_denominator = []
        for tid in denominator:
            if tid not in seen:
                seen.add(tid)
                unique_denominator.append(tid)
        duplicates_removed = len(denominator) - len(unique_denominator)
        denominator = unique_denominator
        covered = []
        visible_not_detected = []
        uncovered = []
        qualified_exclusions = []
        detail = {}
        for tid in denominator:
            tech = self._techniques.get(tid)
            latest = self.latest_score(tid)
            score = latest["score"] if latest else SCORE_NONE
            if tech is None or not tech["sources"]:
                sources_ok = None
            else:
                sources_ok = all(_contract_ok(d)
                                 for d in tech["sources"].values())
            entry = {"technique": tid,
                     "visibility": tech["visibility"] if tech else "NONE",
                     "score": score,
                     "sources_contract_ok": sources_ok,
                     "proof_method": latest["proof_method"]
                     if latest else None}
            detail[tid] = entry
            if score >= 1 and sources_ok is True:
                covered.append(tid)
            elif score == SCORE_VISIBLE_ONLY:
                visible_not_detected.append(tid)
            elif score >= 1 and sources_ok is not True:
                if sources_ok is None:
                    qualified_exclusions.append(
                        {"technique": tid, "reason": "no-sources",
                         "detail": "no telemetry sources recorded; "
                                   "detection has no evidentiary basis"})
                else:
                    qualified_exclusions.append(
                        {"technique": tid, "reason": "source-quality",
                         "detail": "telemetry source failed its quality "
                                   "contract; excluded from the numerator, "
                                   "not counted, not silently dropped"})
                uncovered.append(tid)
            else:
                uncovered.append(tid)
        total = len(denominator)
        return {"mode": "monitor",
                "prevents": False,
                "techniques": detail,
                "covered": len(covered),
                "denominator": total,
                "duplicates_removed": duplicates_removed,
                "percentage": 100.0 * len(covered) / total,
                "proof_method": proof_method.strip(),
                "visible_not_detected": visible_not_detected,
                "uncovered": uncovered,
                "qualified_exclusions": qualified_exclusions,
                "emitted_at": utcnow_iso()}

    def declare_prevention(self):
        """Always refuses: monitor-mode coverage never implies prevention."""
        raise CoverageLedgerError(
            REFUSED_MONITOR_IMPlIES_PREVENTION,
            "this ledger is monitor-mode; coverage is evidence of "
            "visibility, never of prevention")