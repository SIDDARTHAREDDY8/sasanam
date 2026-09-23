#!/usr/bin/env python3
"""Generate a severity-ranked audit report (Markdown + HTML) from a demo run.

Reads the run's hash-chained action log, verifies the chain, derives findings
from denied / flagged / queued actions, and writes the reports to reports/.
"""

import argparse
import html as htmlmod
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gov.log import _verify  # noqa: E402  (verdict carries the key binding)

BANNER = "SYNTHETIC DEMONSTRATION \u2014 no real systems were inspected."
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# F29: epochs that are clearly non-production BY LABEL. Wave-81 deleted
# the published dev key from gov/, so "anyone who read the docs" can no
# longer forge entries -- but a non-production label still means the
# operator did not declare production custody, and the report must say
# so loudly instead of claiming "tamper-evident" unqualified. Integrity
# always depends on the operator's key custody, never on the label.
_NON_PROD_EPOCHS = {"dev", "development", "devkey", "test", "unknown"}


def key_status(entries, verified_epoch):
    """F29/F32: derive the signing-key status from the VERIFIED key/epoch
    binding, never from a self-declared entry label alone.

    ``verified_epoch`` is the key epoch the verifier bound the log to —
    the CONFIGURED epoch from the ``gov.log._verify`` verdict, not an
    entry label. Under the fail-closed single-key verifier (F32), a log
    that verifies clean carries that epoch on every entry; a forged log
    (labels != configured epoch) FAILS verification, and the report then
    renders the configured status with the label mismatch flagged as
    forgery evidence — forged labels can never render a clean
    production banner, no matter what they claim.

    Returns a dict with:

    - ``epochs``: sorted list of distinct ``key_epoch`` labels seen
      (forensic metadata only — never used for the status).
    - ``verified_epoch``: the verifier-bound epoch the status derives from.
    - ``status``: "dev" (verified epoch carries a non-production label),
      "nondev" (verified epoch is operator-configured without a
      non-production label), or "none" (no entries).
    - ``label_mismatch``: labels that differ from the verified epoch —
      forgery evidence, rendered loudly.
    - ``banner_line`` / ``integrity_note``: qualified integrity language
      — never an unqualified "tamper-evident" claim (F29).
    """
    epochs = sorted({str(e.get("key_epoch", "unknown"))
                     for e in entries if isinstance(e, dict)})
    vepoch = str(verified_epoch) if verified_epoch is not None else "unknown"
    mismatched = sorted(ep for ep in epochs if ep != vepoch)
    dev_epochs = [ep for ep in epochs if ep.lower() in _NON_PROD_EPOCHS]
    prod_epochs = [ep for ep in epochs if ep.lower() not in _NON_PROD_EPOCHS]
    if not entries:
        status = "none"
    elif vepoch.lower() in _NON_PROD_EPOCHS:
        status = "dev"
    else:
        status = "nondev"
    if status == "dev":
        banner_line = (f"Non-production epoch label (verified epoch `{vepoch}`) — "
                       "not a production custody claim")
        integrity_note = (
            "All agent actions, policy decisions, and human approvals in "
            "this report come from the run's hash-chained action log. The "
            f"log was verified under key epoch `{vepoch}` "
            "(a non-production label chosen by the operator): integrity is "
            "qualified — tamper-evident only against parties that do NOT "
            "hold the key, and the label itself is not a custody claim. "
            "Wave-81 removed the published development key from gov/, so "
            "there is no docs-reader-forgeable key anymore; forging "
            "entries requires the operator's configured key. The "
            "hash-chain replay below is a consistency check on this local "
            "copy, not tamper-evidence against third parties. "
            "Approval-queue integrity digests are HMAC-keyed to this same "
            "key (F34). Entry sequence numbers cite the exact records.")
    elif status == "nondev":
        banner_line = (f"Operator-configured key (verified epoch `{vepoch}`) — "
                       "tamper-evident only against parties without the key")
        integrity_note = (
            "All agent actions, policy decisions, and human approvals in "
            "this report come from the run's hash-chained action log, "
            f"verified under key epoch `{vepoch}`. Integrity is qualified: "
            "tamper-evident only against parties that do NOT hold the "
            "key. Approval-queue integrity digests are HMAC-keyed to this "
            "same key (F34): forging one requires the key. Key custody "
            "and rotation are outside this report's scope; epoch labels "
            "are self-declared metadata. Entry sequence numbers cite the "
            "exact records.")
    else:
        banner_line = "No entries — nothing was signed."
        integrity_note = ("No entries in this run's log; nothing was "
                          "signed and no integrity claim is made.")
    if mismatched:
        # F32: the labels lied (or the epoch was misconfigured). Say so
        # loudly — this is exactly the forgery shape from the wave-9 red
        # team, and it must never render as a clean production banner.
        banner_line += (" LABEL MISMATCH: entries declare key_epoch %s but "
                        "the verifier bound this log to `%s` — treat the "
                        "labels as forgery evidence, not as key identity." %
                        (", ".join("`%s`" % m for m in mismatched), vepoch))
        integrity_note += (" Self-declared labels %s do NOT match the "
                           "verified epoch; they are forensic evidence of "
                           "label forgery or misconfiguration, not proof of "
                           "which key signed the log." %
                           (", ".join("`%s`" % m for m in mismatched)))
    return {"epochs": epochs, "status": status,
            "verified_epoch": vepoch, "label_mismatch": mismatched,
            "banner_line": banner_line, "integrity_note": integrity_note,
            "dev_epochs": dev_epochs, "prod_epochs": prod_epochs}


def latest_run_dir():
    runs = Path.cwd() / "runs"
    cands = [d for d in runs.iterdir() if d.is_dir()] if runs.exists() else []
    if not cands:
        raise SystemExit("no runs found; run python demo/run_demo.py first")
    return max(cands, key=lambda d: d.stat().st_mtime)


def load_entries(run_dir):
    path = Path(run_dir) / "actions.jsonl"
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip()]


def short_args(args, limit=90):
    bits = []
    for k, v in (args or {}).items():
        text = v if isinstance(v, str) else json.dumps(v, default=str)
        if len(text) > limit:
            text = text[:limit] + "..."
        bits.append('%s="%s"' % (k, text) if isinstance(v, str) else "%s=%s" % (k, text))
    return " ".join(bits)


def attribution_fields(e):
    """Wave-68: render the wave-67 attribution mark as first-class export
    fields — VERBATIM from the verified chain entry, never invented.

    Returns "" when the entry carries no attribution key (e.g. tool_call
    records), " | attribution=<...>" for unattributed acks, and
    " | attribution=authenticated | token_id=<...>" for authenticated
    acks. The exporter never upgrades (an entry without the mark never
    renders "authenticated") and never downgrades; a tampered label
    breaks the hash-chain verification, which the report renders FAILED.
    """
    att = e.get("attribution")
    if att is None:
        return ""
    tid = e.get("token_id")
    if tid is None:
        return " | attribution=%s" % att
    return " | attribution=%s | token_id=%s" % (att, tid)


def evidence_line(e):
    return ("seq %(seq)s | %(ts)s | %(agent_id)s (%(role)s) | %(tool)s | %(args)s | "
            "%(decision)s | policy %(policy_id)s | %(reason)s%(attribution)s" % {
                "seq": e.get("seq"), "ts": e.get("ts"),
                "agent_id": e.get("agent_id"), "role": e.get("role"),
                "tool": e.get("tool"), "args": short_args(e.get("args")),
                "decision": e.get("decision"), "policy_id": e.get("policy_id"),
                "reason": e.get("reason"),
                "attribution": attribution_fields(e)})


# Wave-68: validity-at-time semantics for the attribution export. The
# exporter does not hold the registration authority's revocation ledger
# (it reads only the run dir), so it cannot — and must not — assert
# CURRENT token validity. What it preserves is validity-at-time:
# token_id + ts lets the auditor check the revocation ledger as of the
# ack's recorded time. A token revoked or expired AFTER the ack does not
# rewrite history: the chained record keeps its mark, honestly.
VALIDITY_AT_TIME_NOTE = (
    "\"attribution\": \"authenticated\" means the ack presented a "
    "consumer token that verified against the deployment's registration "
    "authority AT THE ACK'S RECORDED TIME (ts) — validity-at-time, not "
    "current validity. A token revoked or expired AFTER the ack does "
    "not rewrite history: the chained record keeps its mark. To audit: "
    "check the registration authority's revocation ledger as of the ack "
    "ts; token_id distinguishes independent registrations of the same "
    "consumer_id. \"attribution\": \"unattributed\" is the always-open "
    "anonymous path — honestly marked, never silently upgradable to "
    "\"authenticated\" by the exporter. A forged label breaks the "
    "hash-chain verification above, which is this export's tamper "
    "evidence (qualified by the signing-key status).")


def ack_records(entries):
    """Wave-68: the chained acknowledgment records (wave-65 D5 ack trail
    with wave-67 attribution marks), in chain order."""
    return [e for e in entries if e.get("event") == "unvetted_acknowledged"]


def ack_line(e):
    return ("seq %(seq)s | %(ts)s | consumer=%(consumer)s | origin=%(origin)s"
            "%(attribution)s" % {
                "seq": e.get("seq"), "ts": e.get("ts"),
                "consumer": e.get("consumer"), "origin": e.get("origin"),
                "attribution": attribution_fields(e)})


def build_findings(entries):
    approvals = {}
    for e in entries:
        if e.get("event") == "approval_decision" and e.get("approval_id"):
            approvals[e["approval_id"]] = e

    def approval_status(entry):
        d = approvals.get(entry.get("approval_id"))
        if d is None:
            return "open: awaiting human review"
        if d.get("decision") == "approved":
            return "resolved: approved by a human and executed"
        return "resolved: rejected by a human"

    findings = []
    for e in entries:
        if e.get("event") != "tool_call":
            continue
        tool, decision = e.get("tool"), e.get("decision")

        if e.get("flag") == "secret_access_attempt":
            findings.append({
                "severity": "critical",
                "title": "Blocked attempt to read a secret-like path",
                "status": "blocked by policy",
                "policy_id": e.get("policy_id"),
                "description": (
                    "The scout agent attempted to read a path matching secret-like "
                    "patterns (~/.aws/credentials). The read was denied before any "
                    "data was accessed, and the attempt was flagged for review. No "
                    "real credentials exist in this demo; the path itself was the trigger."),
                "evidence": [e],
            })
        elif decision == "denied" and tool == "delete_file":
            findings.append({
                "severity": "high",
                "title": "Blocked destructive action outside the sandbox",
                "status": "blocked by policy",
                "policy_id": e.get("policy_id"),
                "description": (
                    "The builder agent attempted to delete a file resolving outside "
                    "its run sandbox. The delete was denied and nothing was removed."),
                "evidence": [e],
            })
        elif decision == "queued_pending" and tool in ("send_email", "http_post"):
            findings.append({
                "severity": "medium",
                "title": "Outbound communication held for human approval",
                "status": approval_status(e),
                "policy_id": e.get("policy_id"),
                "description": (
                    "The publisher agent attempted an outbound %s. Policy requires a "
                    "human to approve outbound communication, so the action was "
                    "queued with full context instead of executing." % tool),
                "evidence": [e] + ([approvals[e["approval_id"]]]
                                   if e.get("approval_id") in approvals else []),
            })
        elif decision == "queued_pending" and tool == "api_call":
            findings.append({
                "severity": "medium",
                "title": "External API rate guard triggered",
                "status": approval_status(e),
                "policy_id": e.get("policy_id"),
                "description": (
                    "The scout agent exceeded the per-run budget of 5 external API "
                    "calls. The 6th call was queued for human approval instead of "
                    "executing silently."),
                "evidence": [e] + ([approvals[e["approval_id"]]]
                                   if e.get("approval_id") in approvals else []),
            })
        elif decision == "queued_pending" and tool == "write_file":
            findings.append({
                "severity": "medium",
                "title": "File write outside the sandbox held for approval",
                "status": approval_status(e),
                "policy_id": e.get("policy_id"),
                "description": (
                    "The builder agent attempted to write a file outside its run "
                    "sandbox. The write was queued for human approval rather than "
                    "executing."),
                "evidence": [e] + ([approvals[e["approval_id"]]]
                                   if e.get("approval_id") in approvals else []),
            })

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


def anchor_status_text(anchors):
    """Wave-72: qualified external-anchoring language (F29 discipline).

    ``anchors`` is the dict from ``gov.anchorer.anchor_summary`` (or None
    when the summary was not provided / could not be computed). Returns
    plain text — callers escape for HTML. Never claims third-party
    timestamping when no anchor exists.
    """
    if anchors is None:
        return ("External anchor status not provided in this report "
                "rendering; no claim is made about third-party timestamping.")
    epochs = anchors.get("epochs") or []
    anchored = [e for e in epochs if e.get("grade") == "anchored"]
    bad = [e for e in epochs if e.get("grade") != "anchored"]
    backends = sorted({e.get("backend") for e in anchored
                       if e.get("backend")}) or ["none"]
    last = anchors.get("last_anchor") or {}
    open_ep = anchors.get("open_epoch") or {}
    parts = ["Wave-72 Haber-Stornetta anchoring: %d of %d closed epochs "
             "anchored (witness backends: %s)." % (
                 len(anchored), len(epochs), ", ".join(backends))]
    # Evidence-export vocabulary (research intake 2026-09-22: EU AI Act
    # Art 12 + CSA agentic NIST profile). The automatic-recording
    # statement lives here; traceability fields (who/when/resource/
    # outcome), the retention manifest, and delegation-chain monitoring
    # are collected by the Wave-73 provenance export
    # (provenance_export_text below) — the wave-72 deferral is now
    # discharged, no rework here.
    parts.append("Anchor receipts are recorded automatically by the anchor "
                 "daemon on the anchor cadence (EU AI Act Art 12 automatic "
                 "recording), never at the agent's invocation.")
    for e in bad:
        reasons = "; ".join(e.get("reasons") or ["no reason recorded"])
        parts.append("Epoch %s grades %s: %s." % (
            e.get("epoch_id"), e.get("grade"), reasons))
    if last:
        parts.append("Last anchor: epoch %s at %s." % (
            last.get("epoch_id"), last.get("witness_time")))
    if open_ep:
        parts.append("Open epoch %s holds %d unanchored record(s) "
                     "(the soft window)." % (
                         open_ep.get("epoch_id"),
                         open_ep.get("unanchored_records", 0)))
    if not anchors.get("chain_ok"):
        parts.append("NOTE: the HMAC chain could not be verified in this "
                     "rendering, so anchor grades are witness-half only.")
    parts.append("Guarantee: %s" % anchors.get("guarantee", ""))
    return " ".join(parts)


def provenance_export_text(provenance):
    """Wave-73: the Art 12 provenance export — collects the wave-72 deferral.

    Renders traceability fields (who/when/resource/outcome), the
    retention manifest, delegation-chain monitoring, and session-timing
    findings from ``gov.provenance.provenance_export``. ``provenance``
    None renders honestly as not-provided, never as a claim about the
    log. Returns plain text — callers escape for HTML.
    """
    if provenance is None:
        return ("Provenance export not provided in this report rendering; "
                "no claim is made about traceability coverage.")
    parts = [provenance.get("automatic_recording", "")]
    rows = provenance.get("traceability_rows") or []
    parts.append("Traceability (who/when/resource/outcome) — %d provenance "
                 "record(s):" % len(rows))
    for r in rows:
        parts.append(
            "seq %(seq)s | %(ts)s | principal %(principal)s | "
            "action %(action)s | resource %(resource)s | outcome "
            "%(outcome)s | policy %(policy_version)s | tier "
            "%(payload_tier)s | delegation hops %(delegation_hops)s | "
            "anchor %(anchor_grade)s" % {k: r.get(k) for k in
            ("seq", "ts", "principal", "action", "resource", "outcome",
             "policy_version", "payload_tier", "delegation_hops",
             "anchor_grade")})
    manifest = provenance.get("retention_manifest") or {}
    parts.append("Retention manifest (policy %s; floor %s):"
                 % (manifest.get("policy_ref"),
                    manifest.get("retention_floor")))
    for tier in sorted((manifest.get("tiers") or {})):
        t = manifest["tiers"][tier]
        parts.append("- tier %s: %d record(s), retain until %s .. %s"
                     % (tier, t["records"], t["earliest_until"],
                        t["latest_until"]))
    for flag in manifest.get("flags") or []:
        parts.append("RETENTION FLAG: %s" % flag)
    dm = provenance.get("delegation_monitoring") or {}
    parts.append("Delegation-chain monitoring: %d record(s) carry chained "
                 "delegation paths; hop depths %s. %s"
                 % (dm.get("records_with_delegation"),
                    dm.get("distinct_hop_depths"), dm.get("note", "")))
    findings = provenance.get("session_timing_findings") or []
    if findings:
        parts.append("Session-timing findings:")
        for f in findings:
            parts.append("- [%s] session %s: %s"
                         % (f["kind"], f["session_id"], f["detail"]))
    else:
        parts.append("Session-timing findings: none.")
    # Wave-83: the detection section — per-identity baseline windows /
    # thresholds / current levels / breaker state, chained trip
    # history, and the explicit slow-boil boundary.
    if provenance.get("detection") is not None:
        parts.append(detection_state_text(provenance["detection"]))
    return "\n".join(parts)


def detection_state_text(det):
    """Wave-83: per-identity detection state, rendered verbatim from
    the provenance export's ``detection`` section — baseline windows,
    thresholds, current EWMA/CUSUM levels, breaker state; the chained
    detector_trip history; and the explicit slow-boil boundary (what
    drift would NOT trip). Absent a snapshot the section states so
    honestly, never by omission. Returns plain text — callers escape
    for HTML. Every number below comes from the snapshot or the
    chained log; nothing is hand-copied."""
    parts = []
    parts.append("Detection state (behavioral circuit breakers, wave-83):")
    parts.append(det.get("note") or "")
    slow = det.get("slow_boil_boundary")
    if isinstance(slow, dict):
        parts.append("Slow-boil boundary: %s" % slow.get("statement", ""))
        for m in slow.get("measurements") or []:
            parts.append("- %s: %s" % (m.get("id"), m.get("claim")))
    elif slow:
        parts.append("Slow-boil boundary: %s" % slow)
    idents = det.get("identities")
    if idents is None:
        parts.append("Per-identity baselines: not included in this "
                     "rendering (no detection snapshot was supplied).")
    else:
        for ik in sorted(idents):
            row = idents[ik]
            parts.append("- identity %s | role %s | breaker %s | "
                         "consecutive opens %s"
                         % (ik, row.get("role"), row.get("breaker_state"),
                            row.get("consecutive_opens")))
            for sig in sorted(row.get("signals") or {}):
                s = row["signals"][sig]
                parts.append(
                    "    signal %s: basis %s | window %s/%s buckets | "
                    "baseline mean %s sigma %s | spike threshold %s "
                    "(z>%s) | CUSUM threshold %s (k=%s,h=%s) | EWMA "
                    "level %s | CUSUM sh %s | training %s"
                    % (sig, s.get("basis"), s.get("window_buckets"),
                       s.get("buckets_seen"), s.get("baseline_mean"),
                       s.get("baseline_sigma"), s.get("spike_threshold"),
                       s.get("spike_z"), s.get("cusum_threshold"),
                       s.get("cusum_k_sigmas"), s.get("cusum_h_sigmas"),
                       s.get("ewma_level"), s.get("cusum_sh"),
                       s.get("baseline_training")))
    trips = det.get("trip_history") or []
    parts.append("Detector trip history (chained records): %d" % len(trips))
    for t in trips:
        parts.append("- seq %s | %s | %s | signal %s | observed %s | "
                     "threshold %s | baseline %s±%s (%s, %s/%s buckets) | "
                     "anchor %s"
                     % (t.get("seq"), t.get("ts"), t.get("trip_kind"),
                        t.get("signal"), t.get("observed"),
                        t.get("threshold"), t.get("baseline_mean"),
                        t.get("baseline_sigma"), t.get("basis"),
                        t.get("buckets_seen"), t.get("window_buckets"),
                        t.get("anchor_grade")))
    return "\n".join(parts)


def detection_boundary_text(boundary):
    """Wave-76: the behavioral detection parameters, rendered verbatim
    from ``gov.detection.export_boundary`` — baseline windows,
    thresholds, the measured CUSUM lag, and the slow-boil sentence.
    ``boundary=None`` renders honestly as not-provided, never as a
    claim about detection coverage. Returns plain text — callers
    escape for HTML. Every number below comes from ``gov.detection``;
    nothing is hand-copied."""
    if boundary is None:
        return ("Behavioral detection parameters not provided in this "
                "report rendering; no claim is made about detection "
                "coverage.")
    parts = []
    sigs = boundary.get("signals") or {}
    first = next(iter(sigs.values())) if sigs else {}
    parts.append(
        "Behavioral circuit breakers (wave-76, gov/detection.py): EWMA "
        "alpha=%s / spike z>%s; CUSUM k=%s sigma / h=%s sigma; "
        "bucket=%ss; baseline window=%s buckets (enforced rolling "
        "window); cold-start=%s buckets on purpose-group defaults "
        "(approximate, conservative)." % (
            first.get("ewma_alpha"), first.get("spike_z"),
            first.get("cusum_k"), first.get("cusum_h"),
            first.get("bucket_seconds"), first.get("window_buckets"),
            first.get("min_training_buckets")))
    parts.append("Monitored signals: %s." % ", ".join(sorted(sigs)))
    parts.append("Measured CUSUM lag: %s buckets (%s)" % (
        boundary.get("measured_cusum_lag_buckets"),
        boundary.get("measured_cusum_lag_note")))
    parts.append("SLOW-BOIL BOUNDARY: %s" % boundary.get("slow_boil"))
    parts.append("Alerting is harmful-direction-only; trip -> the human "
                 "approval queue (fail-closed); the monitor never "
                 "executes tools and never approves queue items.")
    return "\n".join(parts)


def render_markdown(run_id, generated_at, chain_ok, chain_count, stats,
                    findings, key, acks=None, anchors=None,
                    provenance=None, detection=None):
    """F29: ``key`` is the dict from :func:`key_status` — the report's
    integrity language is derived from the entries' ``key_epoch``
    values, never an unqualified "tamper-evident" claim.
    ``acks`` are the chained ``unvetted_acknowledged`` records rendered
    with their wave-68 first-class attribution fields (verbatim).
    ``acks=None`` (legacy callers) renders the section as not-provided,
    never as a claim about the log. ``anchors`` is the wave-72
    ``gov.anchorer.anchor_summary`` dict; ``anchors=None`` (legacy)
    renders honestly as not-provided. ``provenance`` is the wave-73
    ``gov.provenance.provenance_export`` dict (collects the wave-72
    Art 12 deferral: traceability fields, retention manifest,
    delegation-chain monitoring); None renders as not-provided.
    ``detection`` is the wave-76 ``gov.detection.export_boundary``
    dict (baseline windows, thresholds, measured lag, slow-boil
    sentence); None renders as not-provided."""
    lines = []
    lines.append("> **%s**" % BANNER)
    lines.append("")
    lines.append("# Agent Governance Audit Report")
    lines.append("")
    lines.append("- Run: `%s`" % run_id)
    lines.append("- Generated: %s" % generated_at)
    lines.append("- Log entries: %d" % chain_count)
    lines.append("- Hash-chain verification: **%s**" % ("OK" if chain_ok else "FAILED"))
    lines.append("")
    lines.append("## Signing key status")
    lines.append("")
    lines.append("**%s**" % key["banner_line"])
    lines.append("")
    lines.append(key["integrity_note"])
    lines.append("")
    lines.append("## External anchoring (wave-72)")
    lines.append("")
    lines.append(anchor_status_text(anchors))
    lines.append("")
    lines.append("## Provenance export (wave-73)")
    lines.append("")
    lines.append(provenance_export_text(provenance))
    lines.append("")
    # Wave-76: behavioral detection parameters (baseline windows,
    # thresholds, measured lag, slow-boil boundary) rendered verbatim
    # from gov.detection -- never hand-copied.
    lines.append("## Behavioral detection (wave-76)")
    lines.append("")
    lines.append(detection_boundary_text(detection))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Outcome | Count |")
    lines.append("|---|---|")
    for name, count in stats:
        lines.append("| %s | %d |" % (name, count))
    lines.append("")
    sev_counts = {s: sum(1 for f in findings if f["severity"] == s)
                  for s in ("critical", "high", "medium", "low")}
    lines.append("Findings: %s." % ", ".join("%d %s" % (sev_counts[s], s)
                                            for s in ("critical", "high", "medium", "low")))
    lines.append("")
    lines.append("## Findings (severity-ranked)")
    lines.append("")
    for f in findings:
        lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines.append("")
        lines.append("- Status: %s" % f["status"])
        lines.append("- Policy: `%s`" % f["policy_id"])
        lines.append("")
        lines.append(f["description"])
        lines.append("")
        lines.append("Evidence (exact log entries):")
        lines.append("")
        for e in f["evidence"]:
            lines.append("    %s" % evidence_line(e))
        lines.append("")
    # Wave-68: acknowledgment attribution as first-class export fields.
    # acks=None (legacy callers) is rendered honestly as not-provided —
    # never as a claim about the log's contents.
    lines.append("## Acknowledgments (consumer attribution)")
    lines.append("")
    if acks is None:
        lines.append("Acknowledgment records were not included in this "
                     "report rendering.")
    elif acks:
        for e in acks:
            lines.append("    %s" % ack_line(e))
    else:
        lines.append("No acknowledgment records in this run's log.")
    lines.append("")
    lines.append(VALIDITY_AT_TIME_NOTE)
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- %s" % BANNER)
    lines.append("- %s" % key["integrity_note"])
    lines.append("")
    return "\n".join(lines)


CSS = """
body{font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  max-width:960px;margin:0 auto;padding:24px;color:#1a1a1a;line-height:1.55}
.banner{background:#7a1f1f;color:#fff;padding:14px 18px;font-weight:700;
  text-align:center;border-radius:6px;margin-bottom:24px;letter-spacing:.02em}
h1{font-size:26px;margin-bottom:4px}
h2{font-size:20px;border-bottom:2px solid #eee;padding-bottom:6px;margin-top:32px}
h3{font-size:16px;margin-bottom:4px}
.meta{color:#555;font-size:14px}
.meta li{margin:2px 0}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #ddd;padding:8px 10px;text-align:left;font-size:14px}
th{background:#f4f4f4}
code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:13px}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
  font-weight:700;color:#fff;vertical-align:middle}
.critical{background:#b00020}.high{background:#c96a00}
.medium{background:#1a6fb5}.low{background:#5a5a5a}
.evidence{background:#fafafa;border:1px solid #e5e5e5;border-radius:6px;
  padding:10px 14px;margin:8px 0;font-size:13px;font-family:ui-monospace,
  SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.finding{margin-bottom:22px}
.footer{margin-top:36px;color:#555;font-size:13px;border-top:1px solid #eee;padding-top:12px}
.keystatus{border:2px solid #b00020;background:#fdeceb;padding:12px 16px;
  border-radius:6px;margin:16px 0;font-size:14px}
.keystatus.ok{border-color:#1a6fb5;background:#eaf2fb}
.keystatus p{margin:6px 0}
"""


def render_html(run_id, generated_at, chain_ok, chain_count, stats,
                findings, key, acks=None, anchors=None, provenance=None,
                detection=None):
    """F29: see :func:`render_markdown` — integrity language derives from
    the entries' ``key_epoch`` values. ``anchors`` is the optional
    wave-72 anchor summary (None renders honestly as not-provided).
    ``provenance`` is the optional wave-73 provenance export dict.
    ``detection`` is the optional wave-76 detection boundary dict."""
    esc = htmlmod.escape
    parts = []
    parts.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    parts.append("<title>Agent Governance Audit Report (Synthetic Demonstration)</title>")
    parts.append("<style>%s</style></head><body>" % CSS)
    parts.append("<div class=\"banner\">%s</div>" % esc(BANNER))
    parts.append("<h1>Agent Governance Audit Report</h1>")
    # F29: key status is the prominent box right under the title — the
    # report's first substantive content, before the meta list.
    box_class = "keystatus" if key["status"] == "dev" else "keystatus ok"
    parts.append("<div class=\"%s\"><strong>Signing key status:</strong> %s<p>%s</p></div>"
                 % (box_class, esc(key["banner_line"]),
                    esc(key["integrity_note"])))
    parts.append("<ul class=\"meta\">")
    parts.append("<li>Run: <code>%s</code></li>" % esc(run_id))
    parts.append("<li>Generated: %s</li>" % esc(generated_at))
    parts.append("<li>Log entries: %d</li>" % chain_count)
    parts.append("<li>Hash-chain verification: <strong>%s</strong></li>"
                 % ("OK" if chain_ok else "FAILED"))
    parts.append("</ul>")
    # Wave-72: external anchoring status (qualified language, F29).
    parts.append("<h2>External anchoring (wave-72)</h2>")
    parts.append("<p>%s</p>" % esc(anchor_status_text(anchors)))
    # Wave-73: provenance export (Art 12 traceability + retention
    # manifest + delegation-chain monitoring; collects the wave-72
    # deferral). Rendered as preformatted text; provenance=None renders
    # honestly as not-provided.
    parts.append("<h2>Provenance export (wave-73)</h2>")
    parts.append("<div class=\"evidence\">%s</div>"
                 % esc(provenance_export_text(provenance)))
    # Wave-76: behavioral detection parameters, verbatim from
    # gov.detection (numbers, never hand-copied).
    parts.append("<h2>Behavioral detection (wave-76)</h2>")
    parts.append("<div class=\"evidence\">%s</div>"
                 % esc(detection_boundary_text(detection)))
    parts.append("<h2>Summary</h2>")
    parts.append("<table><tr><th>Outcome</th><th>Count</th></tr>")
    for name, count in stats:
        parts.append("<tr><td>%s</td><td>%d</td></tr>" % (esc(name), count))
    parts.append("</table>")
    parts.append("<h2>Findings (severity-ranked)</h2>")
    for f in findings:
        sev = f["severity"]
        parts.append("<div class=\"finding\">")
        parts.append("<h3><span class=\"chip %s\">%s</span> %s</h3>"
                     % (sev, sev.upper(), esc(f["title"])))
        parts.append("<div class=\"meta\">Status: %s &nbsp;|&nbsp; Policy: <code>%s</code></div>"
                     % (esc(f["status"]), esc(str(f["policy_id"]))))
        parts.append("<p>%s</p>" % esc(f["description"]))
        parts.append("<p><strong>Evidence (exact log entries):</strong></p>")
        for e in f["evidence"]:
            parts.append("<div class=\"evidence\">%s</div>" % esc(evidence_line(e)))
        parts.append("</div>")
    # Wave-68: acknowledgment attribution as first-class export fields
    # (acks=None renders honestly as not-provided — see render_markdown).
    parts.append("<h2>Acknowledgments (consumer attribution)</h2>")
    if acks is None:
        parts.append("<p>Acknowledgment records were not included in this "
                     "report rendering.</p>")
    elif acks:
        for e in acks:
            parts.append("<div class=\"evidence\">%s</div>" % esc(ack_line(e)))
    else:
        parts.append("<p>No acknowledgment records in this run's log.</p>")
    parts.append("<p>%s</p>" % esc(VALIDITY_AT_TIME_NOTE))
    parts.append("<div class=\"footer\">%s<br>%s</div>"
                 % (esc(BANNER), esc(key["integrity_note"])))
    parts.append("</body></html>")
    return "\n".join(parts)


def main():
    # Wave-81: the dev-key opt-in is deleted from gov/. This report
    # tool renders synthetic demo runs, not production — it provisions
    # an explicit test key process-wide. Production entry points
    # never do this — they fail closed without a key.
    import os
    import secrets as _secrets
    os.environ.setdefault("GOV_LOG_KEY", _secrets.token_hex(32))
    os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")
    # Wave-69: the report tool renders synthetic demo runs, not production
    # (wave-61 deployment_mode discipline).
    os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    parser = argparse.ArgumentParser(description="Generate the audit report for a run.")
    parser.add_argument("--rundir", default=None, help="run directory (default: latest)")
    args = parser.parse_args()

    run_dir = Path(args.rundir) if args.rundir else latest_run_dir()
    run_id = run_dir.name
    entries = load_entries(run_dir)
    # F32: the verdict carries the VERIFIED key/epoch binding (the
    # configured epoch, never a self-declared label); key_status derives
    # the production/dev banner from that binding alone.
    verdict = _verify(run_dir / "actions.jsonl")
    chain_ok, broken_seq, chain_count = (
        verdict["ok"], verdict["broken_seq"], verdict["entries"])

    tool_entries = [e for e in entries if e.get("event") == "tool_call"]
    stats = []
    for name in ("allowed_executed", "denied", "queued_pending", "approved_executed"):
        stats.append((name, sum(1 for e in tool_entries if e.get("decision") == name)))
    stats.append(("approval decisions", sum(1 for e in entries
                                           if e.get("event") == "approval_decision")))

    findings = build_findings(entries)
    # F29/F32: key status derives from the VERIFIED key/epoch binding —
    # never from a self-declared label alone — and never an unqualified
    # "tamper-evident" claim.
    key = key_status(entries, verdict["key_epoch"])
    findings.append({
        "severity": "low",
        "title": "Audit trail integrity verified",
        "status": "verified" if chain_ok else "FAILED at seq %s" % broken_seq,
        "policy_id": "n/a (log integrity)",
        "description": (
            "The run's action log is hash-chained: each entry commits to the hash "
            "of the previous entry. Replaying the chain over %d entries %s. %s" %
            (chain_count, "succeeded" if chain_ok else "failed",
             key["integrity_note"])),
        "evidence": [],
    })

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    reports = Path.cwd() / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    md_path = reports / ("%s_audit_report.md" % run_id)
    html_path = reports / ("%s_audit_report.html" % run_id)
    # Wave-68: the wave-67 attribution marks flow into the export as
    # first-class fields (verbatim from the verified chain).
    acks = ack_records(entries)
    # Wave-72: external anchor summary — optional, never blocks the
    # report; failure renders honestly as not-provided.
    try:
        from gov.anchorer import (audit_anchors, anchor_summary,
                                  backend_for_receipt)
        _arep = audit_anchors(str(run_dir / "actions.jsonl"),
                              backend_for_receipt)
        anchors = anchor_summary(_arep)
    except Exception:
        anchors = None
    # Wave-73: provenance export — the Art 12 traceability fields,
    # retention manifest, and delegation-chain monitoring wave-72
    # deferred. Computed live from the log; failure renders honestly as
    # not-provided (never blocks the report).
    #
    # Wave-83: the per-identity detection snapshot (baseline windows,
    # thresholds, current levels, breaker state) rides along as the
    # export's ``detection`` section. It comes from the run's
    # persisted baselines (run_dir/detection/baselines.json) when the
    # run recorded any; otherwise the section renders honest absence
    # (trip history still from the chained detector_trip records;
    # baselines are never invented).
    try:
        from gov.provenance import provenance_export
        try:
            from gov.detection import BehavioralMonitor as _BM83
            _mon83 = _BM83(run_dir=str(run_dir))
            detection_snapshot = (_mon83.export_snapshot()
                                  if _mon83.load_baselines() else None)
        except Exception:
            detection_snapshot = None
        provenance = provenance_export(
            entries, anchors, detection_snapshot=detection_snapshot)
    except Exception:
        provenance = None
    # Wave-76: behavioral detection boundary — operative baseline
    # windows, thresholds, measured lag, slow-boil sentence. Computed
    # live from gov.detection; failure renders honestly as
    # not-provided (never blocks the report).
    try:
        from gov.detection import BehavioralMonitor
        detection = BehavioralMonitor().export_boundary()
    except Exception:
        detection = None
    md_path.write_text(render_markdown(run_id, generated_at, chain_ok, chain_count,
                                       stats, findings, key, acks, anchors,
                                       provenance, detection), encoding="utf-8")
    html_path.write_text(render_html(run_id, generated_at, chain_ok, chain_count,
                                     stats, findings, key, acks, anchors,
                                     provenance, detection), encoding="utf-8")
    print("wrote %s" % md_path)
    print("wrote %s" % html_path)
    print("chain: %s (%d entries)" % ("OK" if chain_ok else "BROKEN", chain_count))
    print("findings: %d" % len(findings))


if __name__ == "__main__":
    main()
