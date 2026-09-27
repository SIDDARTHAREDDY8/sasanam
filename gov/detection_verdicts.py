"""Tiered detection verdicts T1 -> T2 -> T3 (row-13 paraphrase residual).

The residual: authorized-channel paraphrase exfil. Content detection
alone provably loses to a paraphrase-capable encoder (Simmons'
prisoners' problem; measured 4 BREAK / 3 HELD in
evals/row13_authorized_channel_expanded.py), and the behavioral tier
(read a token-bearing doc -> egress to a novel destination) is
triage-only by design (evals/read_then_egress_probes.py). An egress
carrying BOTH independent signals — a structural paraphrase
footprint AND the read->novel-destination behavior — previously got
at most two LOUD triage flags and no human review. This module
composes the two tiers into a single verdict with per-hit
field-level provenance.

Tier ontology (adapted from the Cisco Talos CAIRN concept — MIT
licensed; idea only, no CAIRN code is used or vendored here):

  T1 primitive  — content detectors, each reporting what it measured:
                  ``egress_content`` sub-signals (structured / dump /
                  entropy) and the rare-token overlap ladder. T1 can
                  already hold (require_approval) or flag on its own.
  T2 behavioral — content-blind sequence evidence: the tracker's
                  ``behavioral_flag`` (token-bearing read followed by
                  egress to a concrete novel destination). Triage-only
                  alone, never a hold.
  T3 composition— the AND the product was missing: a T1 paraphrase
                  footprint (a MATERIAL structure/dump/entropy
                  sub-signal with ZERO rare-token overlap after a
                  token-bearing read — the scrubbed-paraphrase
                  signature) together with an independent T2
                  behavioral flag escalates to ``require_approval``
                  (one human review). Neither signal alone escalates:
                  that is the FP control, and it is pinned by battery.

Monotonicity (the composition contract): the composed verdict is
never weaker than the strongest input verdict. The T3 rule only ADDS
an escalation; it never downgrades an existing hold or flag, and a
T1 require_approval keeps its T1 tier (provenance is attached, the
verdict is not relabeled).

Provenance (the Decision-BOM evidence story): every verdict carries
a ``provenance`` list; each record names the tier, the detector, the
signal, the measured value, the threshold it was judged against, and
its contribution. Provenance carries labels, counts, doc ids,
destinations (already audit-logged elsewhere) and scores — NEVER
token strings, canary values, or fragment strings (pinned by
evals/detection_verdict_tier_probes.py::t8 and
tests/test_detection_verdicts.py).

Integration contract: ``compose_egress_verdict(tracker, monitor,
agent_id, tool, args, payload_text=None)`` is the single-call seam —
it runs ``RareTokenTracker.check_egress`` and
``EgressContentMonitor.check`` and composes. Executor wiring is
deliberately NOT in this module (another seam owns the executor);
the returned dict is the contract the executor would consume:
``verdict`` drives the hold, ``provenance`` is the audit payload,
``inputs`` is the operator's triage summary.

Honest ceilings (documented, not hidden):
  - Footprint-free prose paraphrase (no structure/dump/entropy
    sub-signal) never reaches T3 — it stays triage-only under T2.
    Prose exfil is content-invisible by design; this seam narrows
    the footprinted subclass, it does not close the class.
  - A benign read-then-structured-send to a NEW destination now
    costs one human review. That is measured friction, not a false
    positive: the review is the price of the conjunction. Once the
    destination is established (or no read preceded the egress),
    the seam stays silent — pinned by battery t3/t4.
  - The underlying ledgers' residuals carry over unchanged: TTL
    wait-out, identity rotation, single-writer files (see
    gov/taint_ledger.py, gov/destination_ledger.py).
  - The footprint floor reuses ``egress_content.NOVELTY_MATERIAL_FLOOR``
    (0.25) — no new threshold invented. Density ratios are dilutable
    by benign padding, so the footprint test adds padding-robust
    ABSOLUTE presence legs: ``structured_lines >= 2`` (the
    structured_density fire gate) and ``suspicious_bytes >= 40``
    (the entropy_anomaly run floor). Measured in
    evals/detection_verdict_evasion_probes.py: padding dilution
    (e3/e4/e8) and coarse salami (e2) now reach review; only
    sub-2-line salami drips (e1/e1b) and destination warming
    (e5/e6) remain as pinned residuals.
  - Salami residual (e1/e1b): each egress is scored in isolation;
    one structured line per egress never reaches any footprint leg,
    so a dump split into single-line drips exfiltrates with at most
    triage flags. Closing this needs cross-egress footprint
    accumulation — a per-run contract change, deferred, not built
    at this seam.
  - Warmable-novelty residual (e5/e6): the behavioral tier's novel-
    destination precondition is warmable with benign traffic both
    before and after the sensitive read; closing it abandons the
    known-destination-silence FP control — a product-semantics
    decision for the hardening backlog.
  - Provenance is evidence, not enforcement: the ``provenance``
    list is advisory for the audit payload; the hold rides the
    ``verdict`` string, which survives even if a downstream
    consumer drops the provenance key (pinned by
    evals/detection_verdict_evasion_probes.py::e7). Tamper-evidence
    for provenance comes from the hash-chained audit log once the
    executor writes it there — the executor seam, not this module.

Deterministic, $0, stdlib-only. No I/O, no global state.
"""

from gov.egress_content import NOVELTY_MATERIAL_FLOOR

# The paraphrase footprint is a MATERIAL primitive sub-signal, not the
# graduated verdict: a scrubbed paraphrase usually scores under the
# content "flag" band on structure alone (0.25 * 1.3 = 0.325), which
# is exactly the subclass T3 exists to catch. Reuses the materiality
# floor the content tier already defines — no new threshold.
FOOTPRINT_SIGNAL_FLOOR = NOVELTY_MATERIAL_FLOOR

# Absolute presence legs (padding-robust). Density ratios are dilutable
# by benign padding — measured BREAKs in
# evals/detection_verdict_evasion_probes.py: 2 structured lines buried
# in 9 prose lines score (2/11)*1.35 = 0.245 < 0.25 (e3), 3 lines in 20
# prose score 0.176 (e4), and a 44-char high-entropy blob in ~600 prose
# chars scores (44/644)*3.0 = 0.205 < 0.25 (e8). The detectors' own
# presence conditions cannot be padded away: the lines and bytes are
# either in the egress or they are not.
#   structured_lines: structured_density already gates on >= 2 lines
#     ("a single key:value line in a long prose message must not move
#     the needle") — the absolute leg reuses that gate.
#   suspicious_bytes: entropy_anomaly only counts runs >= 40 chars —
#     the absolute leg reuses that run floor.
# dump needs no absolute leg: dump_repetition is already absolute
# (>= 3 records -> 1.0); single-record drips are the salami residual,
# closable only with cross-egress state (documented, not built here).
STRUCTURED_LINES_FLOOR = 2
SUSPICIOUS_BYTES_FLOOR = 40

# Threshold per footprint signal name (for field-level provenance).
FOOTPRINT_THRESHOLDS = {
    "structured": FOOTPRINT_SIGNAL_FLOOR,
    "dump": FOOTPRINT_SIGNAL_FLOOR,
    "entropy": FOOTPRINT_SIGNAL_FLOOR,
    "structured_lines": STRUCTURED_LINES_FLOOR,
    "suspicious_bytes": SUSPICIOUS_BYTES_FLOOR,
}

_STRENGTH = {
    "allow": 0,
    "flag": 1,
    "behavioral_flag": 1,
    "require_approval": 2,
}

_TIERS = ("T1", "T2", "T3")


def _strength(verdict):
    try:
        return _STRENGTH[verdict]
    except KeyError:
        raise ValueError("unknown verdict %r" % (verdict,))


def _int_or_zero(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def footprint_of(t1):
    """The T1 paraphrase-footprint test.

    ``t1`` is the normalized content record
    ``{"signals": {"structured":.., "dump":.., "entropy":..},
    "detail": {"structured": {"structured_lines":..},
    "entropy": {"suspicious_bytes":..}}}``.
    Returns ``(is_footprint, signal_name, measured)`` where the
    footprint is a material primitive sub-signal OR a padding-robust
    absolute presence leg (``structured_lines >= 2``,
    ``suspicious_bytes >= 40``). The threshold for the returned
    signal name lives in ``FOOTPRINT_THRESHOLDS``. The overlap==0 and
    read-happened conditions live in ``compose`` (they belong to the
    cross-tier rule, not to the content tier alone).
    """
    signals = (t1 or {}).get("signals") or {}
    detail = (t1 or {}).get("detail") or {}
    best_name, best_val = None, 0.0
    for name in ("structured", "dump", "entropy"):
        try:
            val = float(signals.get(name, 0.0))
        except (TypeError, ValueError):
            val = 0.0
        if val > best_val:
            best_name, best_val = name, val
    if best_val >= FOOTPRINT_SIGNAL_FLOOR:
        return (True, best_name, best_val)
    # Absolute legs: presence, not density. A record without a
    # "detail" section (e.g. synthetic test records) simply has no
    # absolute legs — the density test above is unchanged.
    s_lines = _int_or_zero(
        (detail.get("structured") or {}).get("structured_lines"))
    if s_lines >= STRUCTURED_LINES_FLOOR:
        return (True, "structured_lines", float(s_lines))
    e_bytes = _int_or_zero(
        (detail.get("entropy") or {}).get("suspicious_bytes"))
    if e_bytes >= SUSPICIOUS_BYTES_FLOOR:
        return (True, "suspicious_bytes", float(e_bytes))
    return (False, best_name, best_val)


def _prov(tier, detector, signal, measured, threshold, contribution):
    return {"tier": tier,
            "detector": detector,
            "signal": signal,
            "measured": measured,
            "threshold": threshold,
            "contribution": contribution}


def _content_signal_provenance(t1):
    """Provenance records for every material T1 content sub-signal."""
    signals = (t1 or {}).get("signals") or {}
    out = []
    for name in ("structured", "dump", "entropy"):
        try:
            val = float(signals.get(name, 0.0))
        except (TypeError, ValueError):
            val = 0.0
        if val >= FOOTPRINT_SIGNAL_FLOOR:
            out.append(_prov("T1", "egress_content", name,
                             round(val, 3), FOOTPRINT_SIGNAL_FLOOR,
                             "primitive sub-signal"))
    return out


def compose(t1, t2):
    """Compose one T1 content record and one T2 tracker record.

    ``t1``: ``{"verdict", "score", "signals": {"structured",
    "dump", "entropy"}}`` (from ``EgressContentMonitor.check``), plus
    the monitor's ``"detail"`` section when present — ``footprint_of``
    reads the padding-robust absolute presence legs
    (``structured_lines``, ``suspicious_bytes``) from it.
    ``t2``: ``{"verdict", "overlap", "destination_novel",
    "docs_read", "threshold", "source_ids", "destination"}`` (from
    ``RareTokenTracker.check_egress``).

    Returns ``{"tier", "verdict", "composed", "provenance", "reason"}``.
    Pure function — no I/O. Monotonic: the output verdict is never
    weaker than the strongest input verdict.
    """
    t1 = t1 or {}
    t2 = t2 or {}
    v1 = t1.get("verdict", "allow")
    v2 = t2.get("verdict", "allow")
    s1, s2 = _strength(v1), _strength(v2)
    try:
        overlap = int(t2.get("overlap", 0))
    except (TypeError, ValueError):
        overlap = 0

    is_fp, fp_signal, fp_val = footprint_of(t1)

    # Rule 1a: the content tier already holds — keep its verdict and
    # tier, attach provenance. The composition never relabels a hold.
    if v1 == "require_approval":
        prov = _content_signal_provenance(t1)
        prov.append(_prov("T1", "egress_content", "verdict",
                         t1.get("score"), "require>=0.60",
                         "graduated hold"))
        return {"tier": "T1", "verdict": "require_approval",
                "composed": False, "provenance": prov,
                "reason": "T1 content hold stands; no composition needed"}

    # Rule 1b: the tracker's rare-token overlap ladder holds — that is
    # a CONTENT primitive (token overlap), so it reports as T1.
    if v2 == "require_approval":
        prov = [_prov("T1", "rare_token_tracker", "token_overlap",
                      overlap, t2.get("threshold", "n/a"),
                      "overlap >= K to novel destination")]
        return {"tier": "T1", "verdict": "require_approval",
                "composed": False, "provenance": prov,
                "reason": "T1 token-overlap hold stands"}

    # Rule 2: the T3 composition — footprint AND independent
    # behavioral flag, with zero token overlap (any overlap is owned
    # by the content ladder above). This is the only rule that
    # escalates past both inputs.
    if (v2 == "behavioral_flag" and overlap == 0 and is_fp):
        prov = [_prov(
            "T1", "egress_content", fp_signal, round(fp_val, 3),
            FOOTPRINT_THRESHOLDS.get(fp_signal, FOOTPRINT_SIGNAL_FLOOR),
            "paraphrase footprint: material structure with zero "
            "rare-token overlap after a token-bearing read"),
            _prov(
            "T2", "rare_token_tracker", "read_then_egress_novel",
            {"docs_read": t2.get("docs_read", 0),
             "destination_novel": bool(t2.get("destination_novel", False)),
             "source_ids": list(t2.get("source_ids", []) or [])},
            "concrete novel destination",
            "independent behavioral sequence")]
        return {"tier": "T3", "verdict": "require_approval",
                "composed": True, "provenance": prov,
                "reason": "T3: footprinted paraphrase + independent "
                          "read->novel-destination behavior -> human review"}

    # Rule 3: carry the strongest flag (content precedence on ties —
    # the existing "content tier takes precedence" discipline).
    if s1 >= s2 and s1 > 0:
        prov = _content_signal_provenance(t1)
        if v2 == "flag":
            # Overlap-flag provenance: the overlap leg is a T1
            # primitive even though it arrives via the tracker.
            prov.append(_prov("T1", "rare_token_tracker", "token_overlap",
                              overlap, t2.get("threshold", "n/a"),
                              "overlap in [1, K)"))
        return {"tier": "T1", "verdict": v1, "composed": False,
                "provenance": prov,
                "reason": "strongest input is the T1 content verdict"}
    if s2 > 0:
        if v2 == "flag":
            prov = [_prov("T1", "rare_token_tracker", "token_overlap",
                          overlap, t2.get("threshold", "n/a"),
                          "overlap in [1, K)")]
            tier = "T1"
        else:  # behavioral_flag, triage-only
            prov = [_prov(
                "T2", "rare_token_tracker", "read_then_egress_novel",
                {"docs_read": t2.get("docs_read", 0),
                 "destination_novel": bool(
                     t2.get("destination_novel", False)),
                 "source_ids": list(t2.get("source_ids", []) or [])},
                "concrete novel destination",
                "triage-only behavioral sequence")]
            tier = "T2"
        return {"tier": tier, "verdict": v2, "composed": False,
                "provenance": prov,
                "reason": "strongest input is the tracker verdict"}

    # Rule 4: nothing fired.
    return {"tier": "T1", "verdict": "allow", "composed": False,
            "provenance": [],
            "reason": "no T1 signal and no T2 behavior"}


def compose_egress_verdict(tracker, monitor, agent_id, tool, args,
                           payload_text=None):
    """Run both detectors on one egress and compose the tiered verdict.

    ``tracker`` is a ``RareTokenTracker`` (T2 behavioral + T1 overlap
    ladder); ``monitor`` is an ``EgressContentMonitor`` (T1 content
    signals). Returns the ``compose()`` dict plus an ``inputs``
    triage summary. The integration contract for the executor seam:
    ``verdict`` drives the hold, ``provenance`` is the audit payload.
    """
    t2 = tracker.check_egress(agent_id, tool, args or {},
                              payload_text=payload_text)
    t1 = monitor.check(agent_id, tool, args or {},
                       payload_text=payload_text)
    out = compose(
        {"verdict": t1.get("verdict", "allow"),
         "score": t1.get("score", 0.0),
         "signals": t1.get("signals") or {},
         # F186: the monitor record's "detail" section carries the
         # padding-robust absolute presence legs (structured_lines,
         # suspicious_bytes). Dropping it here silently disabled those
         # legs on the documented seam while the tracker-internal path
         # (which passes the full record) kept them. Pass it through;
         # footprint_of treats a missing/empty detail as "no absolute
         # legs", so detail-less records behave exactly as before.
         "detail": t1.get("detail") or {}},
        {"verdict": t2.get("verdict", "allow"),
         "overlap": t2.get("overlap", 0),
         "destination_novel": bool(t2.get("destination_novel", False)),
         "docs_read": t2.get("docs_read", 0),
         "threshold": t2.get("threshold", "n/a"),
         "source_ids": t2.get("source_ids", []) or [],
         "destination": t2.get("destination")})
    out["inputs"] = {
        "t1_verdict": t1.get("verdict", "allow"),
        "t1_score": t1.get("score", 0.0),
        "t2_verdict": t2.get("verdict", "allow"),
        "overlap": t2.get("overlap", 0),
        "destination": t2.get("destination"),
        "destination_novel": bool(t2.get("destination_novel", False)),
    }
    return out
