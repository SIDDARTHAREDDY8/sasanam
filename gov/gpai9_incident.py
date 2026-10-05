"""GPAI Code of Practice chapter 9 serious-incident reporting artifacts.

Implements the Measure 9.2 / 9.3 / 9.4 reporting discipline from the
Code of Practice for General-Purpose AI Models, Safety and Security
chapter, as a machine-checkable artifact layer on top of governed
runs:

  * Measure 9.2 -- the nine-point serious-incident checklist:
    (1) start/end dates (or best approximations); (2) resulting harm
    + victim/affected group; (3) chain of events; (4) the model
    involved; (5) material describing the model's involvement;
    (6) the Signatory's response (done/intended); (7) recommendations
    to the AI Office / national competent authorities; (8) root-cause
    analysis incl. the model's outputs, contributing factors, inputs
    used, and failures/circumventions of systemic-risk mitigations;
    (9) post-market-monitoring patterns (Measure 3.5) reasonably
    connected, incl. near-miss data.  A point that is neither present
    nor EXPLICITLY marked unavailable refuses
    ``incident-gpai9-incomplete`` -- silent omission is never a valid
    report state ("If Signatories do not yet have certain relevant
    information from the preceding list, they will record that in
    their serious incident reports").
  * Measure 9.3 -- reporting timelines from awareness (awareness
    INCLUDES reasonable suspicion of model involvement): initial
    report covering points (1)-(7) not later than 2 days
    (critical-infrastructure disruption), 5 days (serious
    cybersecurity breach incl. (self-)exfiltration of model weights),
    10 days (death), 15 days (serious harm to health / fundamental
    rights / property / environment); intermediate report at least
    every 4 weeks while unresolved; final report not later than 60
    days after resolution.  Missed deadlines are flagged with coded
    timeliness verdicts, never silently absorbed.
  * Measure 9.4 -- retention: documentation kept at least 5 years
    from the later of the documentation date or the incident date.
    Disposal before the floor refuses
    ``incident-gpai9-retention-violation`` fail-closed.

Primary source (read 2026-10-05): Code of Practice for
General-Purpose AI Models, Safety and Security chapter, via
https://api.eubound.eu/docs/legal-corpus/archive/ec-gpai-code-safety-security-2025.pdf
(Measure 9.2 nine numbered points + unavailable-marking rule;
Measure 9.3 timelines incl. the suspicion-inclusive awareness
trigger and the 4-week/60-day cadence; Measure 9.4 five-year
retention).  Consolidated multiple-similar-incident reporting is
permitted by Measure 9.3 but is an operator decision -- this module
computes per-incident deadlines and never merges incidents itself.

Base: a40c2ef4 (wave-333 merge). Footer: open F417 / next F419.
Pin: 2077 -> 2083 (+6 incident-gpai9-*).

Regulatory-basis note (honest): this module maps FIELDS and
DEADLINES, it does not give legal advice and it does not determine
whether an event IS a serious incident -- classification is the
operator's call.  No regulator or auditor has accepted this format.
Timestamps are ISO-8601 UTC ("YYYY-MM-DDTHH:MM:SSZ"); malformed
timestamps refuse coded, never coerced.

Privacy: Measure 9.2 requires reporting "to the best of their
knowledge, redacted to the extent necessary to comply with other
Union law".  The builder carries an explicit ``redacted_fields``
list so redactions are declared, not silent.

$0 spend, synthetic/local only. No network.
"""

import calendar
import datetime
import hashlib
import json

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Measure 9.4 retention floor, in years, from the later of the
#: documentation date or the incident date.
GPAI9_RETENTION_YEARS = 5

#: Measure 9.3 intermediate cadence for unresolved incidents.
GPAI9_INTERMEDIATE_CADENCE_DAYS = 28

#: Measure 9.3 final-report deadline after resolution.
GPAI9_FINAL_AFTER_RESOLUTION_DAYS = 60

#: The nine Measure 9.2 checklist points, verbatim in substance.
GPAI9_POINT_TITLES = {
    1: "start and end dates of the serious incident, or best "
       "approximations thereof if the precise dates are unclear",
    2: "the resulting harm and the victim or affected group of the "
       "serious incident",
    3: "the chain of events that (directly or indirectly) led to the "
       "serious incident",
    4: "the model involved in the serious incident",
    5: "a description of material available setting out the model's "
       "involvement in the serious incident",
    6: "what, if anything, the Signatory intends to do or has done in "
       "response to the serious incident",
    7: "what, if anything, the Signatory recommends the AI Office and, "
       "as applicable, national competent authorities to do in "
       "response to the serious incident",
    8: "a root cause analysis with a description of the model's outputs "
       "that (directly or indirectly) led to the serious incident and "
       "the factors that contributed to their generation, including "
       "the inputs used and any failures or circumventions of systemic "
       "risk mitigations",
    9: "any patterns detected during postmarket monitoring (pursuant to "
       "Measure 3.5) that can reasonably be assumed to be connected to "
       "the serious incident, such as individual or aggregate data on "
       "near misses",
}

#: Measure 9.3 initial-report bands: class -> days from awareness.
#: Awareness INCLUDES reasonable suspicion ("establish or suspect with
#: reasonable likelihood").  When several classes apply, the shortest
#: deadline governs.
GPAI9_BANDS = {
    "critical-infrastructure": 2,
    "cybersecurity": 5,
    "death": 10,
    "serious-harm": 15,
}

#: Awareness basis values.  "suspected" starts the Measure 9.3 clock
#: exactly like "established" -- suspicion is not a grace period.
GPAI9_AWARENESS_BASES = frozenset({"established", "suspected"})

#: Report stages.  The initial report covers points (1)-(7); points
#: (8)-(9) are expected at intermediate/final but must still be
#: explicitly marked (e.g. "pending-investigation"), never omitted.
GPAI9_STAGES = frozenset({"initial", "intermediate", "final"})

PRESENT = "present"
UNAVAILABLE = "unavailable"

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


class Gpai9Error(Exception):
    """A GPAI chapter-9 artifact failed fail-closed.  Carries the
    decision code (``self.code``) and a human detail."""

    def __init__(self, code, detail=""):
        super(Gpai9Error, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Timestamps (strict; malformed input refuses coded, never coerced)
# ---------------------------------------------------------------------------

def _parse_ts(ts):
    """Parse a strict ISO-8601 UTC timestamp.  Refuses coded."""
    if not isinstance(ts, str):
        raise Gpai9Error("incident-gpai9-malformed",
                         "timestamp must be a string, got %s" % type(ts).__name__)
    try:
        return datetime.datetime.strptime(ts, _TS_FMT).replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        raise Gpai9Error(
            "incident-gpai9-malformed",
            "timestamp %r is not ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ)" % (ts,))


def _fmt_ts(dt):
    return dt.astimezone(datetime.timezone.utc).strftime(_TS_FMT)


def _add_days(ts, days):
    return _fmt_ts(_parse_ts(ts) + datetime.timedelta(days=days))


def _add_years(ts, years):
    """Calendar-aware year addition (Feb 29 -> Feb 28 on non-leap
    target years).  Refuses coded on malformed input."""
    dt = _parse_ts(ts)
    year = dt.year + years
    month = dt.month
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return _fmt_ts(dt.replace(year=year, month=month, day=day))


# ---------------------------------------------------------------------------
# Awareness (suspicion-inclusive per Measure 9.3)
# ---------------------------------------------------------------------------

def record_awareness(incident_id, awareness_ts, basis):
    """Record when the Signatory became aware of the model's
    involvement -- ``basis`` is "established" or "suspected".
    Suspicion starts the clock identically to establishment.

    Returns the awareness record.  Malformed input refuses
    ``incident-gpai9-malformed`` fail-closed.
    """
    if not isinstance(incident_id, str) or not incident_id:
        raise Gpai9Error("incident-gpai9-malformed",
                         "incident_id must be a non-empty string")
    _parse_ts(awareness_ts)  # validates shape, fail-closed
    if basis not in GPAI9_AWARENESS_BASES:
        raise Gpai9Error(
            "incident-gpai9-malformed",
            "awareness basis must be one of %s, got %r"
            % (sorted(GPAI9_AWARENESS_BASES), basis))
    return {"incident_id": incident_id,
            "awareness_ts": awareness_ts,
            "awareness_basis": basis}


# ---------------------------------------------------------------------------
# Measure 9.2 checklist builder
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _normalize_point(num, raw):
    """Normalize one checklist point to
    {"status": present|unavailable, "value"|"reason": ...}.

    A point that is neither present nor explicitly marked unavailable
    refuses ``incident-gpai9-incomplete``.  An unavailable marking
    with an empty reason refuses the same way -- the Code requires
    the absence to be RECORDED, not merely flagged.
    """
    if isinstance(raw, dict) and UNAVAILABLE in raw:
        reason = raw[UNAVAILABLE]
        if not isinstance(reason, str) or not reason.strip():
            raise Gpai9Error(
                "incident-gpai9-incomplete",
                "point (%d) marked unavailable without a recorded reason" % num)
        return {"status": UNAVAILABLE, "reason": reason.strip()}
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise Gpai9Error(
            "incident-gpai9-incomplete",
            "point (%d) %s is neither present nor explicitly marked "
            "unavailable" % (num, GPAI9_POINT_TITLES[num][:60]))
    return {"status": PRESENT, "value": raw}


def build_gpai9_report(incident, stage="initial"):
    """Build the Measure 9.2 nine-point checklist for one incident.

    ``incident``: {"incident_id": str, "points": {1..9: value |
    {"unavailable": reason}}, "redacted_fields": [str] (optional)}.
    ``stage``: "initial" | "intermediate" | "final".

    Every point must be present or explicitly marked unavailable with
    a recorded reason; anything else refuses
    ``incident-gpai9-incomplete`` and no report is emitted.
    Malformed incident shapes refuse ``incident-gpai9-malformed``.

    Returns {"incident_id", "stage", "points", "redacted_fields",
    "built_ts", "checklist_digest"} -- the digest binds the exact
    checklist bytes so a verifier can detect point tampering.
    """
    if stage not in GPAI9_STAGES:
        raise Gpai9Error(
            "incident-gpai9-malformed",
            "stage must be one of %s, got %r" % (sorted(GPAI9_STAGES), stage))
    if not isinstance(incident, dict):
        raise Gpai9Error("incident-gpai9-malformed",
                         "incident must be a dict")
    incident_id = incident.get("incident_id")
    if not isinstance(incident_id, str) or not incident_id:
        raise Gpai9Error("incident-gpai9-malformed",
                         "incident_id must be a non-empty string")
    points = incident.get("points")
    if not isinstance(points, dict):
        raise Gpai9Error("incident-gpai9-malformed",
                         "incident.points must be a dict of 1..9")
    redacted = incident.get("redacted_fields", [])
    if not isinstance(redacted, list) or any(
            not isinstance(f, str) for f in redacted):
        raise Gpai9Error("incident-gpai9-malformed",
                         "redacted_fields must be a list of strings")

    normalized = {}
    for num in range(1, 10):
        if num not in points:
            raise Gpai9Error(
                "incident-gpai9-incomplete",
                "point (%d) %s is neither present nor explicitly marked "
                "unavailable" % (num, GPAI9_POINT_TITLES[num][:60]))
        normalized[str(num)] = dict(
            {"title": GPAI9_POINT_TITLES[num]},
            **_normalize_point(num, points[num]))

    built_ts = datetime.datetime.now(datetime.timezone.utc).strftime(_TS_FMT)
    digest = hashlib.sha256(
        b"gpai9-checklist-v1\x00" + _canonical(normalized)).hexdigest()
    return {"incident_id": incident_id,
            "stage": stage,
            "points": normalized,
            "redacted_fields": sorted(redacted),
            "built_ts": built_ts,
            "checklist_digest": digest}


# ---------------------------------------------------------------------------
# Measure 9.3 cadence scheduler
# ---------------------------------------------------------------------------

def classify_gpai9_band(gpai9_classes):
    """Map applicable incident classes to the governing Measure 9.3
    band.  Returns (band, days).  When several classes apply, the
    SHORTEST deadline governs.  Empty or unknown classes refuse
    ``incident-gpai9-malformed``.
    """
    if not isinstance(gpai9_classes, (list, tuple)) or not gpai9_classes:
        raise Gpai9Error("incident-gpai9-malformed",
                         "gpai9_classes must be a non-empty list")
    unknown = [c for c in gpai9_classes if c not in GPAI9_BANDS]
    if unknown:
        raise Gpai9Error(
            "incident-gpai9-malformed",
            "unknown GPAI-9 classes %r; known: %s"
            % (unknown, sorted(GPAI9_BANDS)))
    band = min(gpai9_classes, key=lambda c: GPAI9_BANDS[c])
    return band, GPAI9_BANDS[band]


def initial_due(awareness_ts, gpai9_classes):
    """Measure 9.3 initial-report deadline from the awareness instant
    (suspicion-inclusive).  Returns the ISO-8601 UTC due timestamp."""
    _band, days = classify_gpai9_band(gpai9_classes)
    return _add_days(awareness_ts, days)


def intermediate_due(initial_report_ts):
    """Measure 9.3: intermediate report at least every 4 weeks after
    the initial report while the incident is unresolved."""
    return _add_days(initial_report_ts, GPAI9_INTERMEDIATE_CADENCE_DAYS)


def final_due(resolution_ts):
    """Measure 9.3: final report not later than 60 days after the
    serious incident has been resolved."""
    return _add_days(resolution_ts, GPAI9_FINAL_AFTER_RESOLUTION_DAYS)


def check_gpai9_timeliness(state, now_ts):
    """Check Measure 9.3 deadlines for one incident's reporting state.

    ``state``: {"awareness_ts", "gpai9_classes",
    "initial_report_ts" (optional), "intermediate_report_ts" (optional),
    "resolution_ts" (optional), "final_report_ts" (optional)}.
    ``now_ts``: the clock instant to evaluate against.

    Returns a list of verdict dicts, one per applicable check:
    {"check": "initial"|"intermediate"|"final", "due": ts,
    "status": "ok"|"overdue"|"not-yet-due", "code": <code>|None}.
    Overdue checks carry their coded timeliness verdict; nothing
    overdue is ever silently absorbed.
    """
    if not isinstance(state, dict):
        raise Gpai9Error("incident-gpai9-malformed",
                         "timeliness state must be a dict")
    _parse_ts(now_ts)
    awareness_ts = state.get("awareness_ts")
    _parse_ts(awareness_ts)
    classes = state.get("gpai9_classes")
    _band, days = classify_gpai9_band(classes)

    verdicts = []

    def _verdict(check, due, done_ts, overdue_code):
        if done_ts is not None:
            _parse_ts(done_ts)
            status = "ok" if done_ts <= due else "overdue"
        else:
            status = "overdue" if now_ts > due else "not-yet-due"
        return {"check": check, "due": due, "status": status,
                "code": overdue_code if status == "overdue" else None}

    # Initial: points (1)-(7), deadline from awareness.
    due_initial = _add_days(awareness_ts, days)
    verdicts.append(_verdict("initial", due_initial,
                             state.get("initial_report_ts"),
                             "incident-gpai9-initial-overdue"))

    # Intermediate: 4-week cadence while unresolved.  Anchored on the
    # latest filed report (intermediate if present, else initial);
    # only applies once an initial report exists and the incident is
    # not resolved.
    if state.get("initial_report_ts") and not state.get("resolution_ts"):
        anchor = state.get("intermediate_report_ts") or state["initial_report_ts"]
        verdicts.append(_verdict(
            "intermediate", _add_days(anchor, GPAI9_INTERMEDIATE_CADENCE_DAYS),
            None, "incident-gpai9-intermediate-overdue"))

    # Final: 60 days after resolution; only applies once resolved.
    if state.get("resolution_ts"):
        verdicts.append(_verdict(
            "final", _add_days(state["resolution_ts"],
                              GPAI9_FINAL_AFTER_RESOLUTION_DAYS),
            state.get("final_report_ts"),
            "incident-gpai9-final-overdue"))

    return verdicts


# ---------------------------------------------------------------------------
# Measure 9.4 retention
# ---------------------------------------------------------------------------

def retention_floor(doc_ts, incident_ts):
    """Measure 9.4: documentation kept at least 5 years from the LATER
    of the documentation date or the incident date.  Returns the
    ISO-8601 UTC floor timestamp."""
    _parse_ts(doc_ts)
    _parse_ts(incident_ts)
    later = doc_ts if doc_ts >= incident_ts else incident_ts
    return _add_years(later, GPAI9_RETENTION_YEARS)


def disposal_allowed(doc_ts, incident_ts, now_ts):
    """True iff the 5-year retention floor has passed (purge
    permitted).  Malformed timestamps refuse coded."""
    _parse_ts(now_ts)
    return now_ts >= retention_floor(doc_ts, incident_ts)


def assert_disposal_allowed(doc_ts, incident_ts, now_ts):
    """Fail-closed gate for incident-documentation disposal.  A purge
    attempted before the Measure 9.4 floor refuses
    ``incident-gpai9-retention-violation`` -- records are never
    silently dropped.
    """
    if not disposal_allowed(doc_ts, incident_ts, now_ts):
        raise Gpai9Error(
            "incident-gpai9-retention-violation",
            "incident documentation may not be disposed before %s "
            "(5-year Measure 9.4 floor)" % retention_floor(doc_ts, incident_ts))
    return True
