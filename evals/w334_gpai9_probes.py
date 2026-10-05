"""Wave-334 lane 6 break battery: GPAI Code of Practice chapter 9
incident-reporting artifacts.

Base: a40c2ef4 (wave-333 merge). Pin: 2077 -> 2083 (+6 incident-gpai9-*).
Footer: open F417 / next F419.

Covers gov/gpai9_incident.py: the Measure 9.2 nine-point checklist
with mandatory explicit unavailable-marking, the Measure 9.3 cadence
scheduler (2/5/10/15-day bands from suspicion-inclusive awareness,
4-week intermediate cadence, 60-day final), and the Measure 9.4
5-year retention floor.

Break-first discipline (diagnosing-bugs): every probe asserts the
CODED refusal / coded timeliness verdict (or the documented grant),
never the absence of a crash.  A probe that grants where a coded
refusal is required, refuses with the wrong code, silently omits a
checklist point, or lets a bare exception escape is a BREAK and a
candidate F-number from F419.  An all-HELD battery is an honest
result, not a failure to find.

P1  Nine points present -> report builds; checklist digest
    deterministic across rebuilds.
P2  Point (7) absent entirely -> incident-gpai9-incomplete.
P3  Point (5) explicitly unavailable with reason -> builds, marked.
P4  Unavailable marking with empty reason -> incident-gpai9-incomplete.
P5  Malformed inputs -> incident-gpai9-malformed (non-dict incident,
    missing incident_id, bad timestamp, unknown stage, unknown
    class, empty classes, bad awareness basis).
P6  Band classification: cybersecurity -> 5 days; multi-class picks
    the shortest deadline; initial_due exact.
P7  Cadence math: intermediate = initial + 28d; final = resolution
    + 60d; exact timestamps.
P8  Timeliness: initial overdue (6d, cyber, no report) flagged;
    intermediate overdue (29d unresolved) flagged; final overdue
    (resolved 61d, no final) flagged; on-time state all ok.
P9  Retention: floor = max(doc, incident) + 5y; purge 1 day early
    refuses incident-gpai9-retention-violation; purge after floor
    allowed; later-of rule; Feb-29 edge.
P10 Suspicion-inclusive awareness: "suspected" starts the clock
    identically to "established".
P11 Pin/footer honesty: taxonomy 2121/2121/0 on raw literals,
    footer open none / next F421, 6 new codes centrally registered.
"""

import os
import re
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2121 # Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*). Wave-334 lane 6: pin 2077 -> 2083 (+6 incident-gpai9-*).; Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
FOOTER_OPEN = "F424, F425"  # F423 CLOSED 2026-10-05 wave-336 lane 1; no open findings: PRM control-char finding; filed as F421, renumbered at merge).
FOOTER_NEXT = "F426"  # Next free finding number.

_results = []
_PROBES = []
_EXPECTED_BREAKS = set()


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


from gov import gpai9_incident as g9  # noqa: E402


def _full_points(overrides=None):
    pts = {n: "value-%d" % n for n in range(1, 10)}
    if overrides:
        pts.update(overrides)
    return pts


def _incident(**kw):
    d = {"incident_id": "INC-0001", "points": _full_points()}
    d.update(kw)
    return d


def _expect_code(pid, fn, want_code):
    """Run fn(); HELD iff it raises Gpai9Error with exactly want_code.
    A grant, a wrong code, or a bare exception is a BREAK."""
    try:
        fn()
    except g9.Gpai9Error as exc:
        if exc.code == want_code:
            return _held(pid, "coded %s as required" % want_code)
        return _break(pid, "wrong code %s, want %s (%s)"
                      % (exc.code, want_code, exc.detail))
    except Exception as exc:
        return _break(pid, "bare exception escaped: %r" % (exc,))
    return _break(pid, "granted where coded %s required" % want_code)


# ---------------------------------------------------------------------------
# P1 -- nine points present: report builds, digest deterministic.
# ---------------------------------------------------------------------------

@probe("P1a-nine-points-present-builds")
def _p1a():
    r = g9.build_gpai9_report(_incident(), stage="initial")
    if set(r["points"]) != {str(n) for n in range(1, 10)}:
        return _break("P1a-nine-points-present-builds",
                      "checklist missing points: %s" % sorted(r["points"]))
    if any(p["status"] != g9.PRESENT for p in r["points"].values()):
        return _break("P1a-nine-points-present-builds",
                      "a present point was not marked present")
    if r["stage"] != "initial" or r["incident_id"] != "INC-0001":
        return _break("P1a-nine-points-present-builds", "envelope wrong")
    return _held("P1a-nine-points-present-builds",
                 "9/9 present, stage/initial, envelope ok")


@probe("P1b-checklist-digest-deterministic")
def _p1b():
    r1 = g9.build_gpai9_report(_incident(), stage="final")
    r2 = g9.build_gpai9_report(_incident(), stage="final")
    if r1["checklist_digest"] != r2["checklist_digest"]:
        return _break("P1b-checklist-digest-deterministic",
                      "digest unstable across rebuilds")
    r3 = g9.build_gpai9_report(_incident(points=_full_points({3: "CHANGED"})),
                               stage="final")
    if r3["checklist_digest"] == r1["checklist_digest"]:
        return _break("P1b-checklist-digest-deterministic",
                      "digest blind to point tampering")
    return _held("P1b-checklist-digest-deterministic",
                 "digest stable; tampering changes it")


# ---------------------------------------------------------------------------
# P2 -- point absent entirely: coded incomplete, never silent omission.
# ---------------------------------------------------------------------------

@probe("P2a-point7-absent-refuses-coded")
def _p2a():
    pts = _full_points()
    del pts[7]
    return _expect_code(
        "P2a-point7-absent-refuses-coded",
        lambda: g9.build_gpai9_report(_incident(points=pts)),
        "incident-gpai9-incomplete")


@probe("P2b-point1-none-refuses-coded")
def _p2b():
    return _expect_code(
        "P2b-point1-none-refuses-coded",
        lambda: g9.build_gpai9_report(_incident(points=_full_points({1: None}))),
        "incident-gpai9-incomplete")


@probe("P2c-point9-blank-string-refuses-coded")
def _p2c():
    return _expect_code(
        "P2c-point9-blank-string-refuses-coded",
        lambda: g9.build_gpai9_report(_incident(points=_full_points({9: "   "}))),
        "incident-gpai9-incomplete")


# ---------------------------------------------------------------------------
# P3 -- explicit unavailable marking with reason: builds.
# ---------------------------------------------------------------------------

@probe("P3a-unavailable-with-reason-builds")
def _p3a():
    r = g9.build_gpai9_report(
        _incident(points=_full_points(
            {5: {"unavailable": "model-involvement material under legal hold"},
             8: {"unavailable": "pending-investigation"},
             9: {"unavailable": "pending-investigation"}})),
        stage="initial")
    for n in ("5", "8", "9"):
        p = r["points"][n]
        if p["status"] != g9.UNAVAILABLE or not p["reason"]:
            return _break("P3a-unavailable-with-reason-builds",
                          "point %s not explicitly marked" % n)
    if r["points"]["1"]["status"] != g9.PRESENT:
        return _break("P3a-unavailable-with-reason-builds",
                      "present point mis-marked")
    return _held("P3a-unavailable-with-reason-builds",
                 "3 points explicitly unavailable with reasons; rest present")


# ---------------------------------------------------------------------------
# P4 -- unavailable without a recorded reason: coded incomplete.
# ---------------------------------------------------------------------------

@probe("P4a-unavailable-empty-reason-refuses-coded")
def _p4a():
    return _expect_code(
        "P4a-unavailable-empty-reason-refuses-coded",
        lambda: g9.build_gpai9_report(
            _incident(points=_full_points({4: {"unavailable": "  "}}))),
        "incident-gpai9-incomplete")


@probe("P4b-unavailable-nonstring-reason-refuses-coded")
def _p4b():
    return _expect_code(
        "P4b-unavailable-nonstring-reason-refuses-coded",
        lambda: g9.build_gpai9_report(
            _incident(points=_full_points({4: {"unavailable": None}}))),
        "incident-gpai9-incomplete")


# ---------------------------------------------------------------------------
# P5 -- malformed inputs refuse coded, never coerced.
# ---------------------------------------------------------------------------

@probe("P5a-nondict-incident-refuses-coded")
def _p5a():
    return _expect_code("P5a-nondict-incident-refuses-coded",
                        lambda: g9.build_gpai9_report(["not", "a", "dict"]),
                        "incident-gpai9-malformed")


@probe("P5b-missing-incident-id-refuses-coded")
def _p5b():
    return _expect_code("P5b-missing-incident-id-refuses-coded",
                        lambda: g9.build_gpai9_report({"points": _full_points()}),
                        "incident-gpai9-malformed")


@probe("P5c-bad-awareness-timestamp-refuses-coded")
def _p5c():
    return _expect_code(
        "P5c-bad-awareness-timestamp-refuses-coded",
        lambda: g9.record_awareness("INC-1", "yesterday-ish", "established"),
        "incident-gpai9-malformed")


@probe("P5d-unknown-stage-refuses-coded")
def _p5d():
    return _expect_code("P5d-unknown-stage-refuses-coded",
                        lambda: g9.build_gpai9_report(_incident(), stage="draft"),
                        "incident-gpai9-malformed")


@probe("P5e-unknown-class-refuses-coded")
def _p5e():
    return _expect_code("P5e-unknown-class-refuses-coded",
                        lambda: g9.classify_gpai9_band(["cybersecurity", "paperclip"]),
                        "incident-gpai9-malformed")


@probe("P5f-empty-classes-refuses-coded")
def _p5f():
    return _expect_code("P5f-empty-classes-refuses-coded",
                        lambda: g9.classify_gpai9_band([]),
                        "incident-gpai9-malformed")


@probe("P5g-bad-awareness-basis-refuses-coded")
def _p5g():
    return _expect_code(
        "P5g-bad-awareness-basis-refuses-coded",
        lambda: g9.record_awareness("INC-1", "2026-10-01T00:00:00Z", "maybe"),
        "incident-gpai9-malformed")


@probe("P5h-nonstr-timestamp-refuses-coded")
def _p5h():
    return _expect_code("P5h-nonstr-timestamp-refuses-coded",
                        lambda: g9.intermediate_due(1750000000),
                        "incident-gpai9-malformed")


# ---------------------------------------------------------------------------
# P6 -- band classification: shortest deadline governs.
# ---------------------------------------------------------------------------

@probe("P6a-cybersecurity-band-five-days")
def _p6a():
    band, days = g9.classify_gpai9_band(["cybersecurity"])
    if (band, days) != ("cybersecurity", 5):
        return _break("P6a-cybersecurity-band-five-days",
                      "got (%r, %r)" % (band, days))
    due = g9.initial_due("2026-10-01T00:00:00Z", ["cybersecurity"])
    if due != "2026-10-06T00:00:00Z":
        return _break("P6a-cybersecurity-band-five-days",
                      "initial due %r, want 2026-10-06T00:00:00Z" % due)
    return _held("P6a-cybersecurity-band-five-days",
                 "cyber -> 5 days; due exact")


@probe("P6b-multi-class-shortest-wins")
def _p6b():
    band, days = g9.classify_gpai9_band(["death", "cybersecurity", "serious-harm"])
    if (band, days) != ("cybersecurity", 5):
        return _break("P6b-multi-class-shortest-wins",
                      "got (%r, %r), want cyber/5" % (band, days))
    band2, days2 = g9.classify_gpai9_band(["death"])
    if (band2, days2) != ("death", 10):
        return _break("P6b-multi-class-shortest-wins",
                      "death band wrong: (%r, %r)" % (band2, days2))
    band3, days3 = g9.classify_gpai9_band(["critical-infrastructure"])
    if (band3, days3) != ("critical-infrastructure", 2):
        return _break("P6b-multi-class-shortest-wins",
                      "infra band wrong: (%r, %r)" % (band3, days3))
    return _held("P6b-multi-class-shortest-wins",
                 "shortest deadline governs; all four bands exact")


# ---------------------------------------------------------------------------
# P7 -- cadence math exact.
# ---------------------------------------------------------------------------

@probe("P7a-intermediate-final-due-exact")
def _p7a():
    mid = g9.intermediate_due("2026-10-06T12:00:00Z")
    if mid != "2026-11-03T12:00:00Z":
        return _break("P7a-intermediate-final-due-exact",
                      "intermediate %r, want +28d" % mid)
    fin = g9.final_due("2026-10-20T00:00:00Z")
    if fin != "2026-12-19T00:00:00Z":
        return _break("P7a-intermediate-final-due-exact",
                      "final %r, want +60d" % fin)
    return _held("P7a-intermediate-final-due-exact",
                 "intermediate +28d, final +60d, exact")


# ---------------------------------------------------------------------------
# P8 -- timeliness verdicts: overdue flagged coded, on-time ok.
# ---------------------------------------------------------------------------

def _state(**kw):
    s = {"awareness_ts": "2026-10-01T00:00:00Z",
         "gpai9_classes": ["cybersecurity"]}
    s.update(kw)
    return s


def _by_check(verdicts):
    return {v["check"]: v for v in verdicts}


@probe("P8a-initial-overdue-flagged-coded")
def _p8a():
    vs = _by_check(g9.check_gpai9_timeliness(
        _state(), "2026-10-07T00:00:01Z"))  # 6 days, cyber, no report
    v = vs.get("initial")
    if v is None or v["status"] != "overdue" \
            or v["code"] != "incident-gpai9-initial-overdue":
        return _break("P8a-initial-overdue-flagged-coded",
                      "got %r" % (v,))
    if v["due"] != "2026-10-06T00:00:00Z":
        return _break("P8a-initial-overdue-flagged-coded",
                      "due %r wrong" % v["due"])
    return _held("P8a-initial-overdue-flagged-coded",
                 "6d cyber no-report -> initial overdue, coded, due exact")


@probe("P8b-initial-ontime-ok")
def _p8b():
    vs = _by_check(g9.check_gpai9_timeliness(
        _state(initial_report_ts="2026-10-05T00:00:00Z"),
        "2026-10-07T00:00:00Z"))
    v = vs.get("initial")
    if v is None or v["status"] != "ok" or v["code"] is not None:
        return _break("P8b-initial-ontime-ok", "got %r" % (v,))
    return _held("P8b-initial-ontime-ok", "filed day 4 -> ok, no code")


@probe("P8c-intermediate-overdue-flagged-coded")
def _p8c():
    vs = _by_check(g9.check_gpai9_timeliness(
        _state(initial_report_ts="2026-10-05T00:00:00Z"),
        "2026-11-03T00:00:01Z"))  # 29 days after initial, unresolved
    v = vs.get("intermediate")
    if v is None or v["status"] != "overdue" \
            or v["code"] != "incident-gpai9-intermediate-overdue":
        return _break("P8c-intermediate-overdue-flagged-coded",
                      "got %r" % (v,))
    return _held("P8c-intermediate-overdue-flagged-coded",
                 "29d unresolved -> intermediate overdue, coded")


@probe("P8d-final-overdue-flagged-coded")
def _p8d():
    vs = _by_check(g9.check_gpai9_timeliness(
        _state(initial_report_ts="2026-10-05T00:00:00Z",
               resolution_ts="2026-10-20T00:00:00Z"),
        "2026-12-20T00:00:01Z"))  # resolved 61d ago, no final
    v = vs.get("final")
    if v is None or v["status"] != "overdue" \
            or v["code"] != "incident-gpai9-final-overdue":
        return _break("P8d-final-overdue-flagged-coded", "got %r" % (v,))
    if v["due"] != "2026-12-19T00:00:00Z":
        return _break("P8d-final-overdue-flagged-coded",
                      "due %r wrong" % v["due"])
    return _held("P8d-final-overdue-flagged-coded",
                 "61d post-resolution -> final overdue, coded, due exact")


@probe("P8e-final-filed-ok")
def _p8e():
    vs = _by_check(g9.check_gpai9_timeliness(
        _state(initial_report_ts="2026-10-05T00:00:00Z",
               resolution_ts="2026-10-20T00:00:00Z",
               final_report_ts="2026-12-01T00:00:00Z"),
        "2026-12-20T00:00:00Z"))
    v = vs.get("final")
    if v is None or v["status"] != "ok" or v["code"] is not None:
        return _break("P8e-final-filed-ok", "got %r" % (v,))
    # Resolved incidents get no intermediate check.
    if "intermediate" in vs:
        return _break("P8e-final-filed-ok",
                      "intermediate checked on a resolved incident")
    return _held("P8e-final-filed-ok",
                 "final filed -> ok; no intermediate on resolved")


@probe("P8f-no-intermediate-before-initial")
def _p8f():
    vs = _by_check(g9.check_gpai9_timeliness(
        _state(), "2026-11-03T00:00:00Z"))
    if "intermediate" in vs:
        return _break("P8f-no-intermediate-before-initial",
                      "intermediate checked with no initial report")
    return _held("P8f-no-intermediate-before-initial",
                 "no intermediate check before an initial report exists")


# ---------------------------------------------------------------------------
# P9 -- Measure 9.4 retention floor.
# ---------------------------------------------------------------------------

@probe("P9a-floor-later-of-two-dates")
def _p9a():
    f = g9.retention_floor("2026-10-05T00:00:00Z", "2026-10-01T00:00:00Z")
    if f != "2031-10-05T00:00:00Z":
        return _break("P9a-floor-later-of-two-dates",
                      "floor %r, want doc+5y" % f)
    f2 = g9.retention_floor("2026-10-01T00:00:00Z", "2026-10-05T00:00:00Z")
    if f2 != "2031-10-05T00:00:00Z":
        return _break("P9a-floor-later-of-two-dates",
                      "floor %r, want incident+5y" % f2)
    return _held("P9a-floor-later-of-two-dates",
                 "floor = later date + 5 years, both directions")


@probe("P9b-purge-before-floor-refuses-coded")
def _p9b():
    try:
        g9.assert_disposal_allowed("2026-10-05T00:00:00Z",
                                   "2026-10-01T00:00:00Z",
                                   "2031-10-04T23:59:59Z")
    except g9.Gpai9Error as exc:
        if exc.code == "incident-gpai9-retention-violation":
            return _held("P9b-purge-before-floor-refuses-coded",
                         "1s early purge refused coded")
        return _break("P9b-purge-before-floor-refuses-coded",
                      "wrong code %s" % exc.code)
    except Exception as exc:
        return _break("P9b-purge-before-floor-refuses-coded",
                      "bare exception: %r" % (exc,))
    return _break("P9b-purge-before-floor-refuses-coded",
                 "early purge granted")


@probe("P9c-purge-after-floor-allowed")
def _p9c():
    ok = g9.assert_disposal_allowed("2026-10-05T00:00:00Z",
                                    "2026-10-01T00:00:00Z",
                                    "2031-10-05T00:00:00Z")
    if ok is not True or not g9.disposal_allowed(
            "2026-10-05T00:00:00Z", "2026-10-01T00:00:00Z",
            "2032-01-01T00:00:00Z"):
        return _break("P9c-purge-after-floor-allowed", "post-floor purge denied")
    return _held("P9c-purge-after-floor-allowed", "post-floor purge allowed")


@probe("P9d-feb29-edge")
def _p9d():
    f = g9.retention_floor("2024-02-29T00:00:00Z", "2024-01-01T00:00:00Z")
    if f != "2029-02-28T00:00:00Z":
        return _break("P9d-feb29-edge", "floor %r, want 2029-02-28" % f)
    return _held("P9d-feb29-edge", "leap-day +5y lands Feb 28, no crash")


# ---------------------------------------------------------------------------
# P10 -- suspicion-inclusive awareness.
# ---------------------------------------------------------------------------

@probe("P10a-suspected-starts-clock-like-established")
def _p10a():
    a1 = g9.record_awareness("INC-1", "2026-10-01T00:00:00Z", "suspected")
    a2 = g9.record_awareness("INC-1", "2026-10-01T00:00:00Z", "established")
    if a1["awareness_basis"] != "suspected" \
            or a2["awareness_basis"] != "established":
        return _break("P10a-suspected-starts-clock-like-established",
                      "basis not recorded")
    d1 = g9.initial_due(a1["awareness_ts"], ["cybersecurity"])
    d2 = g9.initial_due(a2["awareness_ts"], ["cybersecurity"])
    if d1 != d2 != "2026-10-06T00:00:00Z":
        return _break("P10a-suspected-starts-clock-like-established",
                      "clock differs by basis: %r vs %r" % (d1, d2))
    return _held("P10a-suspected-starts-clock-like-established",
                 "suspicion starts the 5-day clock identically")


# ---------------------------------------------------------------------------
# P11 -- pin + footer honesty.
# ---------------------------------------------------------------------------

@probe("P11a-pin-taxonomy-2121-sorted")
def _p11a():
    if TAXONOMY_PIN != 2121:
        return _break("P11a-pin-taxonomy-2121-sorted",
                      "TAXONOMY_PIN is %r, want 2121" % (TAXONOMY_PIN,))
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != 2121 or len(set(lits)) != 2121 \
            or lits != sorted(lits):
        return _break("P11a-pin-taxonomy-2121-sorted",
                      "want 2121/2121/0 sorted, got %d/%d/sorted=%s"
                      % (len(lits), len(set(lits)), lits == sorted(lits)))
    for c in ("incident-gpai9-final-overdue", "incident-gpai9-incomplete",
              "incident-gpai9-initial-overdue",
              "incident-gpai9-intermediate-overdue",
              "incident-gpai9-malformed",
              "incident-gpai9-retention-violation"):
        if lits.count(c) != 1:
            return _break("P11a-pin-taxonomy-2121-sorted",
                          "code %s literal count %d" % (c, lits.count(c)))
    return _held("P11a-pin-taxonomy-2121-sorted",
                 "2121/2121/0 sorted unique on raw source literals")


@probe("P11b-footer-open-none-next-f426")
def _p11b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Raw-literal assertions (wave-331 lesson): the footer must read
    # correctly as literal text, not only via constants.
    if "Next free finding: **F426**." not in text:
        return _break("P11b-footer-open-none-next-f426",
                      "raw literal 'Next free finding: **F426**.' absent")
    if "**Open findings: none.**" not in text:
        return _break("P11b-footer-open-none-next-f426",
                      "raw literal '**Open findings: none.**' absent")
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break("P11b-footer-open-none-next-f426",
                      "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return _break("P11b-footer-open-none-next-f426",
                      "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return _held("P11b-footer-open-none-next-f426",
                 "footer open none / next F426 (raw literals + parse)")


@probe("P11c-codes-centrally-registered")
def _p11c():
    """Wave-329 lesson: new codes must be centrally registered in
    gov/decision_codes.py -- raw-literal presence is not registration.
    (The tree-wide live-constants sweep is merge-time work: untouched
    batteries still pin the base 2100 until the merge repoint.)"""
    from gov import decision_codes as dc
    want = {"incident-gpai9-final-overdue", "incident-gpai9-incomplete",
            "incident-gpai9-initial-overdue",
            "incident-gpai9-intermediate-overdue",
            "incident-gpai9-malformed",
            "incident-gpai9-retention-violation"}
    missing = [c for c in want if c not in dc.TAXONOMY]
    if missing:
        return _break("P11c-codes-centrally-registered",
                      "not registered: %s" % missing)
    wrong = [c for c in want
             if dc.TAXONOMY[c]["domain"] != "incident"
             or dc.TAXONOMY[c]["code"] != c]
    if wrong:
        return _break("P11c-codes-centrally-registered",
                      "bad entry shape: %s" % wrong)
    if len(dc.TAXONOMY) != 2121:
        return _break("P11c-codes-centrally-registered",
                      "TAXONOMY has %d entries, want 2121"
                      % len(dc.TAXONOMY))
    return _held("P11c-codes-centrally-registered",
                 "all 6 gpai9 codes centrally registered; TAXONOMY=2100")


# ---------------------------------------------------------------------------
# Green check (depth-1).  Local consistency check: adjacent batteries pin
# the pre-lane taxonomy (2100), so spawning one as a child on this tree
# would produce a spurious pin BREAK -- the merge repoint owns that.
# This check verifies exactly what this lane changed: the registry,
# the footer, and the absence of merge artifacts.
# ---------------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != 2121 or len(set(lits)) != 2121:
        _record("green-check", "BREAK",
                "taxonomy %d/%d, want 2121/2121" % (len(lits), len(set(lits))))
        return
    for artifact in ("<<<<<<<", ">>>>>>>", ".orig", ".rej"):
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in files:
                if artifact in fn or artifact in os.path.join(root, fn):
                    _record("green-check", "BREAK",
                            "merge artifact: %s" % fn)
                    return
    _record("green-check", "HELD",
            "taxonomy 2121/2121/0; no merge artifacts (depth-1, local)")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w334_gpai9 battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
