"""Rate-independent enumeration signal (prospecting R7 #5 follow-up prototype).

THE GAP (pinned residual p8 in ``evals/shadow_agent_battery.py``):
``gov/shadow_scan.py``'s ``machine_cadence`` needs 0.5..30 actions/min
and its ``orchestration_patterns`` needs list->read coupling inside
120s/300s windows. A patient shadow agent enumerating the
tool/document surface at 0.25/min -- or one query per hour -- over
distinct targets trips neither: the rate band and the timing windows
are the evasion surface.

THE SIGNAL: enumeration STRUCTURE, never rate. Over whatever window
the caller scans (the window is the caller's choice -- MandateZ's
30-day action distribution is the prior art for the LONG window, not
the signal), per principal:

  * enumeration runs: a LIST-class action followed -- order-only, any
    gap -- by >= 3 READ-class actions attributed to it. No timing
    windows anywhere: entry times are used ONLY for ordering, so the
    signal is rate-independent by construction (1/min and 1/hour
    produce identical structure).
  * distinct-target coverage: distinct extracted targets / targeted
    actions. Systematic enumeration touches each target once
    (coverage ~1.0); organic use re-reads the same few targets
    (coverage low). This is the industry-standard breadth-not-speed
    principle (distinct-username spray rules carry no time window;
    low-and-slow scan detectors key on distinct ports over 24h).

Present = runs >= ENUM_MIN_RUNS and coverage >= ENUM_MIN_COVERAGE
and n >= ENUM_MIN_ACTIONS and targeted fraction >=
ENUM_MIN_TARGETED_FRACTION.

ADVISORY ONLY. This module never refuses, never blocks, never
auto-registers. The signal feeds ``gov/discovery.py``'s signal
vocabulary ("signals, not verdicts"): a present signal makes the
principal a discovery candidate through the existing
unregistered-candidates path, the same advisory surface as
``machine_cadence``. No enforcement gate is touched.

BOUNDED MEMORY: the per-principal distinct-target set is capped at
ENUM_MAX_DISTINCT_TARGETS (10_000 -- the lineage-journal quota
precedent from ``gov/memory_provenance.py``). On cap the set stops
growing and the record carries ``target_cap_hit=True``; the strength
is computed on what was seen (fail-open, documented, never silent).

HONEST RESIDUALS (documented, not claimed away):

* List-less enumeration evades: a principal that already knows its
  targets and reads them in any order (no LIST actions) has no loop
  structure to detect. Coverage alone is deliberately NOT enough to
  fire -- an organic researcher reading many distinct documents
  looks the same, and this signal refuses to buy that
  false-positive class.
* Dilution: interleaving organic repeated reads lowers coverage
  below the threshold; the signal degrades rather than firing
  weakly (fail-open on ambiguity).
* Target-blind logs: entries without an extractable target do not
  contribute; if fewer than half the actions carry targets the
  signal stays silent ("insufficient target data") instead of
  guessing from event text.
* A sighting is not a verdict: systematic research over a corpus is
  structurally identical to hostile enumeration. The operator
  decides; the ledger records.

$0 spend, synthetic/local only, stdlib only.
"""

from . import shadow_scan as _shadow_scan

# NOTE on the mutual import: gov/shadow_scan.py imports this module
# (to wire the signal into fingerprint_principal) and this module
# imports gov/shadow_scan (for the entry helpers). Both sides touch
# the other only through PUBLIC names at call time, never at import
# time, so either import order resolves. Do not add import-time
# attribute access in either direction.

__all__ = [
    "ENUM_MIN_ACTIONS",
    "ENUM_MIN_RUNS",
    "ENUM_MIN_COVERAGE",
    "ENUM_MIN_TARGETED_FRACTION",
    "ENUM_MAX_DISTINCT_TARGETS",
    "ENUM_RUN_MIN_READS",
    "enumeration_structure",
]

#: Minimum actions before the signal can fire (sample-size floor).
ENUM_MIN_ACTIONS = 20
#: Minimum list->read runs (a run = one LIST followed, order-only, by
#: >= ENUM_RUN_MIN_READS attributed READs).
ENUM_MIN_RUNS = 3
#: Reads attributed to one LIST needed to count it as a run.
ENUM_RUN_MIN_READS = 3
#: Runs at which the strength factor saturates: beyond ~6 runs the
#: evidence is already conclusive; additional runs add no strength.
ENUM_RUNS_SATURATE = 6
#: Distinct targets / targeted actions needed for "systematic".
ENUM_MIN_COVERAGE = 0.6
#: Fraction of actions that must carry an extractable target;
#: below this the log is target-blind and the signal stays silent.
ENUM_MIN_TARGETED_FRACTION = 0.5
#: Per-principal distinct-target cap (lineage-journal quota precedent:
#: gov/memory_provenance.py DEFAULT_LINEAGE_JOURNAL_QUOTA).
ENUM_MAX_DISTINCT_TARGETS = 10_000

#: Entry keys consulted (in order) for an explicit target. Deliberately
#: conservative: free-text fields like "event" are NEVER used as
#: targets (they collapse distinct actions into one bucket and would
#: both hide enumeration and invent false coverage).
_TARGET_KEYS = ("target", "resource", "path", "object", "file",
                "document", "key", "uri", "url")

#: Signal kind registered in gov/discovery.py SIGNAL_WEIGHTS.
SIGNAL_KIND = "enumeration_structure"


def _target_of(entry):
    """Extract a target string from an audit entry, or None.

    Checks explicit target-ish keys top-level, then inside an
    args/arguments dict. Never raises; never invents a target from
    free text.
    """
    for key in _TARGET_KEYS:
        v = entry.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:512]
    args = entry.get("args")
    if args is None:
        args = entry.get("arguments")
    if isinstance(args, dict):
        for key in _TARGET_KEYS:
            v = args.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()[:512]
    elif isinstance(args, str) and args.strip() and len(args.strip()) <= 512:
        return args.strip()
    return None


def enumeration_structure(entries):
    """Rate-independent enumeration-structure test for one principal.

    ``entries``: the principal's audit entries (any mapping with
    ``tool``/``event``/``ts``-ish fields; malformed entries are
    skipped and counted, never trusted).

    Returns ``(present, strength, detail)`` where strength is 0..1
    and detail is a JSON-serializable dict. Deterministic: the same
    entries always produce the same triple. Never raises on content
    problems.
    """
    ordered = []
    skipped = 0
    for e in entries:
        if not isinstance(e, dict):
            skipped += 1
            continue
        try:
            ts = _shadow_scan.entry_timestamp(e)
        except ValueError:
            skipped += 1
            continue
        ordered.append((ts, e))
    ordered.sort(key=lambda pair: pair[0])

    n = len(ordered)
    distinct = set()
    targeted = 0
    cap_hit = False
    runs = 0
    open_reads = None  # reads attributed to the most recent LIST

    for _, e in ordered:
        tgt = _target_of(e)
        if tgt is not None:
            targeted += 1
            if not cap_hit:
                if len(distinct) >= ENUM_MAX_DISTINCT_TARGETS:
                    cap_hit = True
                else:
                    distinct.add(tgt)
        cls = _shadow_scan.classify_action(e)
        if cls == "list":
            if open_reads is not None and len(open_reads) >= ENUM_RUN_MIN_READS:
                runs += 1
            open_reads = []
        elif cls == "read" and open_reads is not None:
            open_reads.append(e)
    if open_reads is not None and len(open_reads) >= ENUM_RUN_MIN_READS:
        runs += 1

    coverage = (len(distinct) / targeted) if targeted else 0.0
    targeted_fraction = (targeted / n) if n else 0.0
    present = (
        n >= ENUM_MIN_ACTIONS
        and runs >= ENUM_MIN_RUNS
        and coverage >= ENUM_MIN_COVERAGE
        and targeted_fraction >= ENUM_MIN_TARGETED_FRACTION
    )
    if present:
        strength = round(
            min(1.0, (runs / ENUM_RUNS_SATURATE) * (0.5 + 0.5 * coverage)), 3)
    else:
        strength = 0.0
    detail = {
        "actions": n,
        "skipped": skipped,
        "enumeration_runs": runs,
        "distinct_targets": len(distinct),
        "targeted_actions": targeted,
        "coverage": round(coverage, 3),
        "targeted_fraction": round(targeted_fraction, 3),
        "target_cap_hit": cap_hit,
        "present": present,
    }
    return present, strength, detail
