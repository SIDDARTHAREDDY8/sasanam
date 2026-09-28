"""Versioned behavioral-signature registry for the discovery stream.

R7 SHORTLIST #6 (Sysdig/Marimo behavioral signature extension).
Steal lineage: MandateZ Shadow Scan (mandatez/core, MIT) supplied the
signature *vocabulary* for gov/shadow_scan.py (machine cadence,
orchestration patterns, credential shape); the Sysdig/Marimo field
incident (disclosed 2026-05-30: 12 API calls across 11 IPs in 22 s,
parallel sessions, Secrets-Manager read -> full PostgreSQL dump in
<2 min) supplies the new *signatures*. No vendored code: these
signatures are original constructions informed by the incident's
disclosed facts. Falco's rule schema (falcosecurity/falco, Apache-2.0)
informed the registry shape (id / desc / versioned params / tags) —
design input only.

WHAT THIS IS: a deterministic, stdlib-only registry of behavioral
signatures that identify agent-like activity from OBSERVABLE BEHAVIOR
rather than identity claims. It extends the discovery stream
(gov/discovery.py, gov/shadow_scan.py): findings are ADVISORY —
``to_discovery_signals()`` renders matches in discovery.py's
(signal_kind, weight, detail) vocabulary (signals, not verdicts; a
candidate is a sighting, never an accusation; nothing is
auto-registered or auto-blocked).

EVENT MODEL (input): a list of dicts, each with:
  ts         epoch seconds (int/float) or ISO-8601 string — required
  principal  actor label — required
  tool       tool name (str) — optional
  event      event class (str) — optional
  dest       egress destination (str) — optional, for fanned_egress
  target     acted-on target (str) — optional
  session_id session label (str) — optional, for parallel_sessions
Malformed entries (missing/unparseable ts or principal) are SKIPPED
and counted via normalize_entries() — never silently trusted
(fail-closed, same discipline as gov/shadow_scan.py).

CREDENTIAL HINTS: operator-supplied regexes, same house rule as
shadow_scan — without hints the credential_then_export signature is
absent (strength 0), never invented.

DESIGN RULES:
* Deterministic: pure functions, sorted iteration, no randomness, no
  wall-clock reads. Same entries -> same findings.
* Versioned: every signature pins (signature_id, version, params);
  findings carry the version that matched. Changing a threshold is a
  new version, never a silent edit.
* Advisory only: strengths are ordinal 0..1, not probabilities.

$0 spend, synthetic/local only, stdlib only.
"""

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

REGISTRY_VERSION = "1"

# ---------------------------------------------------------------------------
# Event normalization (fail-closed)
# ---------------------------------------------------------------------------


def _parse_ts(entry):
    """Epoch seconds for an entry. Raises ValueError on garbage."""
    ts = entry.get("ts")
    if isinstance(ts, (int, float)):
        if math.isnan(ts) or math.isinf(ts):
            raise ValueError("non-finite ts %r" % (ts,))
        return float(ts)
    if isinstance(ts, str):
        s = ts.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    raise ValueError("unparseable ts %r" % (ts,))


def normalize_entries(entries):
    """Split entries into (valid, skipped).

    valid: list of dicts with _t (epoch float), principal, tool, event,
    dest, target, session_id normalized to str/None. skipped: count of
    malformed entries (missing/unparseable ts or principal). Sorted by
    (_t, tool, event) for determinism.
    """
    valid, skipped = [], 0
    for e in entries or []:
        try:
            t = _parse_ts(e)
            principal = e.get("principal")
            if not principal or not isinstance(principal, str):
                raise ValueError("missing principal")
        except (ValueError, TypeError, AttributeError):
            skipped += 1
            continue
        valid.append({
            "_t": t,
            "principal": principal,
            "tool": str(e.get("tool") or ""),
            "event": str(e.get("event") or ""),
            "dest": e.get("dest"),
            "target": e.get("target"),
            "session_id": e.get("session_id"),
        })
    valid.sort(key=lambda x: (x["_t"], x["tool"], x["event"]))
    return valid, skipped


# ---------------------------------------------------------------------------
# Small deterministic statistics helpers
# ---------------------------------------------------------------------------


def _gap_stats(times):
    """(n, median_gap, cv) for sorted epoch times."""
    n = len(times)
    if n < 2:
        return n, float("inf"), float("inf")
    gaps = [b - a for a, b in zip(times, times[1:]) if b >= a]
    if not gaps:
        return n, 0.0, 0.0
    sg = sorted(gaps)
    median = sg[len(sg) // 2]
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = math.sqrt(var) / mean if mean > 0 else float("inf")
    return n, median, cv


def _sliding_windows(times, window_s):
    """Yield (count, span) per maximal window of width window_s.

    Deterministic: windows anchored at each event's timestamp.
    """
    times = sorted(times)
    out = []
    for i, start in enumerate(times):
        j = i
        while j + 1 < len(times) and times[j + 1] - start <= window_s:
            j += 1
        out.append((j - i + 1, times[j] - start))
    return out


# ---------------------------------------------------------------------------
# Signature matchers: (events, credential_hints) -> (matched, strength, detail)
# ---------------------------------------------------------------------------


def _match_fanned_egress(events, hints):
    p = {"window_s": 120, "min_distinct_dests": 8, "strength_scale": 16}
    dest_times = [(e["_t"], str(e["dest"]))
                  for e in events if e.get("dest")]
    if len(dest_times) < p["min_distinct_dests"]:
        return (False, 0.0,
                "too few egress events (%d)" % len(dest_times))
    times_by_dest = {}
    for t, d in dest_times:
        times_by_dest.setdefault(d, []).append(t)
    best = 0
    for d, ts in times_by_dest.items():
        for start in ts:
            distinct = {dd for dd, tts in times_by_dest.items()
                        if any(start <= t <= start + p["window_s"]
                               for t in tts)}
            best = max(best, len(distinct))
    if best >= p["min_distinct_dests"]:
        return (True, min(1.0, best / p["strength_scale"]),
                "%d distinct egress dests in %ds window "
                "(Marimo: 11 in 22s)" % (best, p["window_s"]))
    return (False, 0.0,
            "max %d distinct dests in %ds window" % (best, p["window_s"]))


def _match_parallel_sessions(events, hints):
    p = {"window_s": 300, "min_sessions": 3, "min_events_per_session": 2,
         "strength_scale": 6}
    by_session = {}
    for e in events:
        sid = e.get("session_id")
        if sid:
            by_session.setdefault(str(sid), []).append(e["_t"])
    active = {s: ts for s, ts in by_session.items()
              if len(ts) >= p["min_events_per_session"]}
    if len(active) < p["min_sessions"]:
        return (False, 0.0,
                "too few active sessions (%d)" % len(active))
    best = 0
    anchors = sorted(t for ts in active.values() for t in ts)
    for start in anchors:
        n = sum(1 for ts in active.values()
                if any(start <= t <= start + p["window_s"] for t in ts))
        best = max(best, n)
    if best >= p["min_sessions"]:
        return (True, min(1.0, best / p["strength_scale"]),
                "%d parallel active sessions in %ds window" %
                (best, p["window_s"]))
    return (False, 0.0,
            "max %d parallel sessions in %ds window" % (best, p["window_s"]))


_EXPORT_WORDS = ("export", "download", "send", "publish", "dump", "exfil")


def _is_export(e):
    blob = (e["tool"] + " " + e["event"] + " " +
            str(e.get("target") or "")).lower()
    return any(w in blob for w in _EXPORT_WORDS)


def _match_credential_then_export(events, hints):
    p = {"window_s": 120}
    if not hints:
        return (False, 0.0,
                "no credential hints supplied (house rule: never invented)")
    try:
        rxs = [re.compile(h, re.IGNORECASE) for h in hints]
    except re.error as ex:
        return (False, 0.0, "bad credential hint regex: %s" % ex)
    cred_ts = [e["_t"] for e in events
               if any(rx.search(e["tool"] + " " +
                                str(e.get("target") or ""))
                      for rx in rxs)]
    export_ts = [e["_t"] for e in events if _is_export(e)]
    if not cred_ts or not export_ts:
        return (False, 0.0,
                "credential_events=%d export_events=%d" %
                (len(cred_ts), len(export_ts)))
    for ct in cred_ts:
        follows = [x for x in export_ts if 0 <= x - ct <= p["window_s"]]
        if follows:
            return (True, 1.0,
                    "credential-shaped access -> export %.0fs later "
                    "(Marimo: Secrets-Manager read -> DB dump <2min)" %
                    (follows[0] - ct))
    return (False, 0.0, "no export within %ds of credential access" %
            p["window_s"])


def _match_burst_cadence(events, hints):
    p = {"window_s": 60, "min_actions": 10, "max_gap_cv": 1.0,
         "min_median_gap_s": 0.3}
    times = [e["_t"] for e in events]
    if len(times) < p["min_actions"]:
        return (False, 0.0, "too few actions (%d)" % len(times))
    # Contiguous regular runs: for each anchor, grow the run while it
    # stays inside the window; a run matches on its OWN gap stats, so
    # follow-on stages (e.g. the Marimo secrets-read at +40 s) do not
    # pollute the burst's regularity. O(n^2); fine for trajectory
    # scale — document, do not stream-optimize prematurely.
    best = None
    n = len(times)
    for i in range(n):
        for j in range(i + p["min_actions"] - 1, n):
            if times[j] - times[i] > p["window_s"]:
                break
            run = times[i:j + 1]
            _n, median, cv = _gap_stats(run)
            if median >= p["min_median_gap_s"] and cv < p["max_gap_cv"]:
                if best is None or len(run) > best[0]:
                    best = (len(run), median, cv)
    if best:
        ln, median, cv = best
        return (True, min(1.0, ln / 20.0),
                "%d-action machine-regular run in %ds, median_gap=%.1fs "
                "cv=%.2f" % (ln, p["window_s"], median, cv))
    return (False, 0.0,
            "no %d-action regular run in %ds window" %
            (p["min_actions"], p["window_s"]))


def _match_memory_write_heavy(events, hints):
    p = {"min_writes": 10, "min_write_read_ratio": 5.0}
    writes = reads = 0
    for e in events:
        blob = (e["tool"] + " " + e["event"]).lower()
        if "memory" not in blob:
            continue
        if "write" in blob:
            writes += 1
        elif "read" in blob:
            reads += 1
    ratio = writes / max(reads, 1)
    if writes >= p["min_writes"] and ratio >= p["min_write_read_ratio"]:
        return (True, min(1.0, ratio / 10.0),
                "%d memory writes / %d reads (ratio %.1f)" %
                (writes, reads, ratio))
    return (False, 0.0,
            "%d memory writes / %d reads (ratio %.1f)" %
            (writes, reads, ratio))


def _match_approval_queue_spam(events, hints):
    p = {"window_s": 300, "min_requests": 8, "strength_scale": 16}
    times = [e["_t"] for e in events
             if "approv" in (e["tool"] + " " + e["event"]).lower()]
    if len(times) < p["min_requests"]:
        return (False, 0.0, "too few approval submissions (%d)" %
                len(times))
    best = max((c for c, _s in _sliding_windows(times, p["window_s"])),
               default=0)
    if best >= p["min_requests"]:
        return (True, min(1.0, best / p["strength_scale"]),
                "%d approval-queue submissions in %ds window" %
                (best, p["window_s"]))
    return (False, 0.0,
            "max %d submissions in %ds window" % (best, p["window_s"]))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    signature_id: str
    version: str
    name: str
    desc: str
    tags: tuple
    params: dict
    fp_control: str
    evasion_note: str
    # match_fn is attached post-construction (kept out of the frozen
    # dataclass to preserve hashability/serializability of the record).
    match_fn: object = field(default=None, compare=False, repr=False)

    def to_dict(self):
        return {
            "signature_id": self.signature_id,
            "version": self.version,
            "name": self.name,
            "desc": self.desc,
            "tags": list(self.tags),
            "params": dict(self.params),
            "fp_control": self.fp_control,
            "evasion_note": self.evasion_note,
        }


def _sig(sig_id, version, name, desc, tags, params, fp_control,
         evasion_note, match_fn):
    return Signature(signature_id=sig_id, version=version, name=name,
                     desc=desc, tags=tuple(tags), params=dict(params),
                     fp_control=fp_control, evasion_note=evasion_note,
                     match_fn=match_fn)


SIGNATURES = {
    "fanned_egress": _sig(
        "fanned_egress", "v1", "Fanned-out egress (Marimo)",
        "Many distinct egress destinations inside a short window — "
        "the Sysdig/Marimo post-exploitation shape (12 API calls "
        "across 11 IPs in 22 s).",
        ("egress", "lateral-movement", "marimo"),
        {"window_s": 120, "min_distinct_dests": 8, "strength_scale": 16},
        fp_control="Benign control: routine automation polling 1-2 "
                   "endpoints (e.g. cloud SDK health checks) stays far "
                   "below 8 distinct destinations per 120 s.",
        evasion_note="Rotate through <=7 destinations, stretch the fan "
                     "past 120 s, or proxy all egress through one host.",
        match_fn=_match_fanned_egress),
    "parallel_sessions": _sig(
        "parallel_sessions", "v1", "Parallel sessions (Marimo)",
        "Several sessions with overlapping activity inside a short "
        "window — the Marimo parallel-session shape.",
        ("session", "orchestration", "marimo"),
        {"window_s": 300, "min_sessions": 3,
         "min_events_per_session": 2, "strength_scale": 6},
        fp_control="Benign control: a single interactive session never "
                   "reaches 3 distinct active sessions.",
        evasion_note="Serialize sessions: finish one before opening "
                     "the next.",
        match_fn=_match_parallel_sessions),
    "credential_then_export": _sig(
        "credential_then_export", "v1", "Credential theft then exfiltration",
        "Credential-shaped access (operator-hinted) followed by an "
        "export-class action within a short window — the Marimo "
        "Secrets-Manager read -> PostgreSQL dump <2 min shape.",
        ("credential-access", "exfiltration", "marimo"),
        {"window_s": 120},
        fp_control="Benign controls: a secrets read with no following "
                   "export, and an export with no preceding "
                   "credential-shaped access, both stay silent. Without "
                   "operator hints the signal is absent, never invented.",
        evasion_note="Separate theft and exfiltration by >120 s, or "
                     "exfiltrate through a non-export-class tool.",
        match_fn=_match_credential_then_export),
    "burst_cadence": _sig(
        "burst_cadence", "v1", "Machine-regular burst cadence",
        "A short-window burst of actions at machine-regular gaps — "
        "the complement to shadow_scan's long-dwell machine_cadence "
        "(which needs >=25 actions over >=30 min and cannot see a "
        "22-second Marimo burst).",
        ("cadence", "machine-speed", "marimo"),
        {"window_s": 60, "min_actions": 10, "max_gap_cv": 1.0,
         "min_median_gap_s": 0.3},
        fp_control="Benign control: a human paste burst (irregular "
                   "gaps, high CV) and slow human operation (<10 "
                   "actions per 60 s) do not match. KNOWN CONFOUND: "
                   "regular benign automation (cron-like, CV near 0) "
                   "is indistinguishable from a machine burst on "
                   "cadence alone — this signature is advisory and "
                   "must compose with other signals.",
        evasion_note="Jitter inter-action gaps (drive CV >= 1.0), or "
                     "slow below 10 actions per 60 s.",
        match_fn=_match_burst_cadence),
    "memory_write_heavy": _sig(
        "memory_write_heavy", "v1", "Write-heavy memory footprint",
        "Memory writes dominating reads — the memory-poisoning "
        "footprint (many planted writes, few reads).",
        ("memory", "poisoning-footprint"),
        {"min_writes": 10, "min_write_read_ratio": 5.0},
        fp_control="Benign control: balanced memory use (e.g. 10 "
                   "writes / 10 reads) stays below the ratio gate.",
        evasion_note="Interleave reads to keep the write/read ratio "
                     "below 5.",
        match_fn=_match_memory_write_heavy),
    "approval_queue_spam": _sig(
        "approval_queue_spam", "v1", "Approval-queue submission spam",
        "Many approval-queue submissions in a short window — the "
        "agent-side approval-surface abuse shape (contrast "
        "ceremony_integrity, which watches the decider side).",
        ("approval", "queue", "abuse"),
        {"window_s": 300, "min_requests": 8, "strength_scale": 16},
        fp_control="Benign control: occasional human approval "
                   "requests (1-2) never reach 8 per 300 s.",
        evasion_note="Stay under 8 submissions per 300 s, or batch "
                     "requests into fewer submissions.",
        match_fn=_match_approval_queue_spam),
}


@dataclass(frozen=True)
class Finding:
    signature_id: str
    signature_version: str
    matched: bool
    strength: float  # 0..1 ordinal, not a probability
    detail: str

    def to_dict(self):
        return {
            "signature_id": self.signature_id,
            "signature_version": self.signature_version,
            "matched": self.matched,
            "strength": self.strength,
            "detail": self.detail,
        }


def scan(entries, credential_hints=None):
    """Run the full registry over entries. Returns [Finding], one per
    signature, sorted by signature_id. Deterministic. Advisory only."""
    events, _skipped = normalize_entries(entries)
    out = []
    for sig_id in sorted(SIGNATURES):
        sig = SIGNATURES[sig_id]
        try:
            matched, strength, detail = sig.match_fn(events,
                                                     credential_hints)
        except Exception as ex:  # fail-closed: a broken matcher
            matched, strength = False, 0.0  # never claims a match
            detail = "matcher error (fail-closed): %s" % ex
        strength = max(0.0, min(1.0, float(strength)))
        out.append(Finding(signature_id=sig_id,
                           signature_version=sig.version,
                           matched=bool(matched), strength=strength,
                           detail=str(detail)))
    return out


def to_discovery_signals(findings):
    """Render matched findings in gov/discovery.py's signal vocabulary.

    Returns [{signal_kind, weight, detail}]: weights are ordinal 1..4
    (discovery.py's scale), advisory only — a sighting, never an
    accusation. Registration stays an explicit operator act.
    """
    out = []
    for f in findings:
        if not f.matched:
            continue
        weight = max(1, min(4, 1 + int(f.strength * 3)))
        out.append({
            "signal_kind": f.signature_id,
            "weight": weight,
            "detail": "[behavioral_sigs %s] %s" %
                      (f.signature_version, f.detail),
        })
    return out
