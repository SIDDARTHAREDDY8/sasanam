"""Behavioral shadow-agent fingerprinting over the governed audit trail.

PROSPECTING R6 PROTOTYPE, integrated wave-171 via
gov/discovery.py scan_action_log (behavioral shadow-agent
fingerprinting over the governed audit trail).
Steal target: MandateZ Shadow Scan (mandatez/core, MIT) — deterministic
behavioral signatures that distinguish agent traffic from human traffic:

  Signature 1 — machine-rate action cadence (1-20 actions/min sustained,
  low inter-arrival variance; humans pause).
  Signature 2 — tool-use patterns of LLM orchestration (list-then-read
  loops, enumeration runs, embedding-then-write sequences).
  Signature 3 — credential shape (long-lived, broad-scope tokens).

OUR DELTA vs gov/discovery.py: the in-tree discovery substrate scans
filesystem/config/process signals ONLY (its docstring: "no network
traffic analysis"). It never reads the action log, so a principal that
acts at machine rate through the governed executor is invisible to it.
This module closes exactly that surface: it fingerprints PRINCIPALS
from audit-log entries and reports agent-like-but-unregistered ones in
the discovery.py vocabulary (signals, not verdicts; a candidate is a
sighting, never an accusation; registration stays an explicit operator
act).

DESIGN RULES (same honesty discipline as gov/discovery.py):
* Deterministic: pure functions, sorted iteration, no randomness, no
  wall-clock reads. The same entries always produce the same findings.
* Signals, not verdicts: findings carry weighted signals and a score;
  nothing is auto-registered or auto-blocked.
* Credential shape is OPERATOR-SUPPLIED (credential_hints): the audit
  log does not carry token metadata, and this module will not invent
  it. Without hints the signal is simply absent (weight 0).
* Fail-closed on malformed input: entries missing principal/ts are
  skipped and counted, never silently trusted.

$0 spend, synthetic/local only, stdlib only.
"""

import math
from datetime import datetime, timezone

from . import enumeration_signal as _enumeration_signal

# --- event classification -------------------------------------------------

_LIST = {"list", "enumerate", "search", "query", "scan", "discover"}
_READ = {"read", "get", "fetch", "load", "describe"}
_WRITE = {"write", "put", "update", "create", "patch"}
_EMBED = {"embed", "chunk", "index"}
_EXPORT = {"export", "download", "send", "publish"}
_DELETE = {"delete", "remove", "drop"}
_CALL = {"api_call", "invoke", "call", "execute"}


def _classify(entry):
    """Map an audit entry to an action class for pattern detection."""
    tool = str(entry.get("tool") or "").lower()
    event = str(entry.get("event") or "").lower()
    blob = tool + " " + event
    for cls, names in (("list", _LIST), ("read", _READ), ("write", _WRITE),
                       ("embed", _EMBED), ("export", _EXPORT),
                       ("delete", _DELETE), ("call", _CALL)):
        if any(n in blob for n in names):
            return cls
    return "other"


#: Public aliases for the entry helpers shared with
#: gov/enumeration_signal.py (the R7 #5 rate-independent signal).
#: The underscore names above stay as the intra-module convention;
#: cross-module callers use these.
def entry_timestamp(entry):
    """Entry timestamp as epoch seconds. Raises ValueError on garbage."""
    return _ts(entry)


def classify_action(entry):
    """Map an audit entry to an action class for pattern detection."""
    return _classify(entry)


def _ts(entry):
    """Entry timestamp as epoch seconds. Raises ValueError on garbage."""
    ts = entry.get("ts")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        s = ts.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    raise ValueError("unparseable ts %r" % (ts,))


# --- cadence analysis -------------------------------------------------------


def _cadence_stats(times):
    """Return (n, span_s, median_gap_s, cv) for sorted epoch times."""
    n = len(times)
    if n < 2:
        return n, 0.0, float("inf"), float("inf")
    gaps = [b - a for a, b in zip(times, times[1:]) if b >= a]
    if not gaps:
        return n, 0.0, 0.0, 0.0
    span = times[-1] - times[0]
    sg = sorted(gaps)
    median = sg[len(sg) // 2]
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = math.sqrt(var) / mean if mean > 0 else float("inf")
    return n, span, median, cv


def machine_cadence(times):
    """MandateZ signature 1: machine-rate vs human-rate cadence.

    Machine-rate: sustained ACTION RATE in the 0.5..30/min band (their
    1-20/min, widened for governed batching) over a >= 30 min span,
    with REGULAR per-minute buckets (coefficient of variation < 1.5).
    Humans are bursty-with-pauses: mostly-empty buckets punctuated by
    clusters, which drives bucket CV up; pure rate alone is not enough
    because a human pasting 40 reads in 2 minutes is fast but not
    machine-regular.
    Returns (is_machine, strength 0..1, detail).
    """
    times = sorted(times)
    n = len(times)
    if n < 25:
        return False, 0.0, "too few actions (n=%d)" % n
    span = times[-1] - times[0]
    if span < 1800.0:
        return False, 0.0, "span too short (%.1f min)" % (span / 60.0)
    rate = n / (span / 60.0)  # actions per minute
    in_band = 0.5 <= rate <= 30.0
    buckets = {}
    t0 = times[0]
    for t in times:
        b = int((t - t0) // 60)
        buckets[b] = buckets.get(b, 0) + 1
    counts = list(buckets.values())
    mean = sum(counts) / len(counts)
    var = sum((c - mean) ** 2 for c in counts) / len(counts)
    bcv = math.sqrt(var) / mean if mean > 0 else float("inf")
    regular = bcv < 1.5
    passed = sum((in_band, regular))
    strength = 1.0 if passed == 2 else (passed / 2.0) * 0.4
    detail = ("n=%d span=%.1fh rate=%.2f/min bucket_cv=%.2f"
              % (n, span / 3600.0, rate, bcv))
    return passed == 2, strength, detail


# --- orchestration pattern analysis ------------------------------------------


def orchestration_patterns(entries):
    """MandateZ signature 2: LLM-orchestration tool-use patterns.

    Counts, over the principal's time-ordered entries:
      * list_then_read: a LIST-class action followed by a READ-class
        action within 120s (search-then-read coupling);
      * enumerate_runs: a LIST followed by >= 3 READs within 300s;
      * embed_then_write: an EMBED-class action followed by a WRITE
        within 600s (chunking/indexing pipelines).
    Returns (density 0..1, detail). Density = pattern events / actions,
    capped at 1.0.
    """
    ordered = sorted(entries, key=_ts)
    classes = [_classify(e) for e in ordered]
    times = [_ts(e) for e in ordered]
    n = len(ordered)
    if n == 0:
        return 0.0, "no actions"
    hits = 0
    ltr = 0
    enum_runs = 0
    e2w = 0
    i = 0
    while i < n:
        if classes[i] == "list":
            reads = 0
            coupled = False
            j = i + 1
            while j < n and times[j] - times[i] <= 300:
                if classes[j] == "read":
                    reads += 1
                    if times[j] - times[i] <= 120:
                        coupled = True
                j += 1
            if coupled:
                ltr += 1
            if reads >= 3:
                enum_runs += 1
                hits += 1 + reads
            i += 1
            continue
        if classes[i] == "embed":
            j = i + 1
            while j < n and times[j] - times[i] <= 600:
                if classes[j] == "write":
                    e2w += 1
                    hits += 2
                    break
                j += 1
        i += 1
    hits += ltr  # each list->read coupling counts once more
    density = min(1.0, hits / n)
    detail = ("list_then_read=%d enumerate_runs=%d embed_then_write=%d "
              "actions=%d" % (ltr, enum_runs, e2w, n))
    return density, detail


# --- scan ---------------------------------------------------------------------


def fingerprint_principal(principal, entries, credential_hints=None):
    """Weighted agent-likeness fingerprint for one principal.

    Returns a dict with score 0..1 and the contributing signals.
    Credential shape (MandateZ signature 3) is operator-supplied via
    credential_hints: {principal: {"long_lived": bool,
    "broad_scope": bool}}; absent hints contribute nothing.

    The rate-independent enumeration-structure signal
    (gov/enumeration_signal.py, R7 #5) is carried as a fourth signal.
    It does not enter the weighted score -- it is an independent
    sighting: a present enumeration structure makes the principal a
    candidate even when every rate-gated signature is dark (the slow
    shadow-agent residual). Advisory only, like every other signal
    here.
    Note: the three legacy signals carry string ``detail`` values;
    the enumeration signal carries a structured (dict) detail --
    see gov/enumeration_signal.py. Consumers must not assume
    ``detail`` is always a string.
    """
    times = []
    skipped = 0
    usable = []
    for e in entries:
        try:
            times.append(_ts(e))
            usable.append(e)
        except ValueError:
            skipped += 1
    is_machine, cad_strength, cad_detail = machine_cadence(times)
    density, pat_detail = orchestration_patterns(usable)
    cred_strength = 0.0
    cred_detail = "no credential hints supplied"
    if credential_hints and principal in credential_hints:
        hint = credential_hints[principal]
        flags = [bool(hint.get("long_lived")), bool(hint.get("broad_scope"))]
        cred_strength = sum(flags) / 2.0
        cred_detail = "long_lived=%s broad_scope=%s" % tuple(flags)
    enum_present, enum_strength, enum_detail = \
        _enumeration_signal.enumeration_structure(usable)
    score = (0.45 * cad_strength + 0.45 * min(1.0, density * 2.0)
             + 0.10 * cred_strength)
    # NOTE: the enumeration signal is the only fingerprint signal that
    # can independently set agent_like. The three legacy signals feed
    # only the weighted score; enumeration_structure is an OR-gate
    # because it is a distinct structural sighting the rate-gated
    # score cannot express by design.
    return {
        "principal": principal,
        "score": round(score, 3),
        "agent_like": score >= 0.5 or enum_present,
        "actions": len(usable),
        "skipped": skipped,
        "signals": [
            {"kind": "machine_cadence", "strength": round(cad_strength, 3),
             "detail": cad_detail, "present": is_machine},
            {"kind": "orchestration_patterns",
             "strength": round(min(1.0, density * 2.0), 3),
             "detail": pat_detail, "present": density >= 0.25},
            {"kind": "credential_shape", "strength": round(cred_strength, 3),
             "detail": cred_detail, "present": cred_strength >= 0.5},
            {"kind": _enumeration_signal.SIGNAL_KIND,
             "strength": enum_strength, "detail": enum_detail,
             "present": enum_present},
        ],
    }


def scan(entries, registered_principals, credential_hints=None):
    """Shadow-scan audit entries; return findings for agent-like but
    UNREGISTERED principals.

    registered_principals: set of principal strings (or agent_ids) the
    deployment knows about. Findings are sightings, never accusations:
    each carries weighted signals and one of MandateZ's three
    remediations (register / wrap / decommission) as a SUGGESTION for
    the operator. Deterministic: principals iterated in sorted order.
    """
    by_principal = {}
    for e in entries:
        p = e.get("principal") or e.get("agent_id") or "unknown"
        by_principal.setdefault(p, []).append(e)
    findings = []
    for principal in sorted(by_principal):
        if principal in registered_principals:
            continue
        fp = fingerprint_principal(principal,
                                   by_principal[principal],
                                   credential_hints)
        if fp["agent_like"]:
            fp["remediation"] = ("register (install the governance SDK and "
                                 "mint an identity), wrap (policy proxy at "
                                 "the network edge), or decommission (revoke "
                                 "the credential)")
            findings.append(fp)
    return findings
