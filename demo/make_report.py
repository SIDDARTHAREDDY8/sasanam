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

# F29: epochs that are clearly non-production. Entries signed under these
# epochs are NOT tamper-evident against anyone who holds the key (the dev
# key is literally published in the source tree), and the report must say
# so loudly instead of claiming "tamper-evident" unqualified.
_NON_PROD_EPOCHS = {"dev", "development", "devkey", "test", "unknown"}


def key_status(entries, verified_epoch):
    """F29/F32: derive the signing-key status from the VERIFIED key/epoch
    binding, never from a self-declared entry label alone.

    ``verified_epoch`` is the key epoch the verifier bound the log to —
    the CONFIGURED epoch from the ``gov.log._verify`` verdict, not an
    entry label. Under the fail-closed single-key verifier (F32), a log
    that verifies clean carries that epoch on every entry; a forged log
    (labels != configured epoch) FAILS verification, and the report then
    renders the configured (dev) status with the label mismatch flagged
    as forgery evidence — a dev-key forgery can never render a production
    banner, no matter what the labels claim.

    Returns a dict with:

    - ``epochs``: sorted list of distinct ``key_epoch`` labels seen
      (forensic metadata only — never used for the status).
    - ``verified_epoch``: the verifier-bound epoch the status derives from.
    - ``status``: "dev" (verified epoch is non-production), "nondev"
      (verified epoch is operator-configured), or "none" (no entries).
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
        banner_line = (f"PUBLIC/DEVELOPMENT key (verified epoch `{vepoch}`) — NOT "
                       "tamper-evident against anyone with the key")
        integrity_note = (
            "All agent actions, policy decisions, and human approvals in "
            "this report come from the run's hash-chained action log. The "
            f"log was verified under key epoch `{vepoch}` "
            "(PUBLIC/DEVELOPMENT key, published in the source tree): it is "
            "NOT tamper-evident against anyone with the key — anyone who "
            "read the docs can forge entries. The hash-chain replay below "
            "is a consistency check on this local copy, not tamper-evidence "
            "against third parties. Entry sequence numbers cite the exact "
            "records.")
    elif status == "nondev":
        banner_line = (f"Operator-configured key (verified epoch `{vepoch}`) — "
                       "tamper-evident only against parties without the key")
        integrity_note = (
            "All agent actions, policy decisions, and human approvals in "
            "this report come from the run's hash-chained action log, "
            f"verified under key epoch `{vepoch}`. Integrity is qualified: "
            "tamper-evident only against parties that do NOT hold the "
            "key. Key custody and rotation are outside this report's "
            "scope; epoch labels are self-declared metadata. Entry "
            "sequence numbers cite the exact records.")
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


def evidence_line(e):
    return ("seq %(seq)s | %(ts)s | %(agent_id)s (%(role)s) | %(tool)s | %(args)s | "
            "%(decision)s | policy %(policy_id)s | %(reason)s" % {
                "seq": e.get("seq"), "ts": e.get("ts"),
                "agent_id": e.get("agent_id"), "role": e.get("role"),
                "tool": e.get("tool"), "args": short_args(e.get("args")),
                "decision": e.get("decision"), "policy_id": e.get("policy_id"),
                "reason": e.get("reason")})


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


def render_markdown(run_id, generated_at, chain_ok, chain_count, stats,
                    findings, key):
    """F29: ``key`` is the dict from :func:`key_status` — the report's
    integrity language is derived from the entries' ``key_epoch``
    values, never an unqualified "tamper-evident" claim."""
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
                findings, key):
    """F29: see :func:`render_markdown` — integrity language derives from
    the entries' ``key_epoch`` values."""
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
    parts.append("<div class=\"footer\">%s<br>%s</div>"
                 % (esc(BANNER), esc(key["integrity_note"])))
    parts.append("</body></html>")
    return "\n".join(parts)


def main():
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
    md_path.write_text(render_markdown(run_id, generated_at, chain_ok, chain_count,
                                       stats, findings, key), encoding="utf-8")
    html_path.write_text(render_html(run_id, generated_at, chain_ok, chain_count,
                                     stats, findings, key), encoding="utf-8")
    print("wrote %s" % md_path)
    print("wrote %s" % html_path)
    print("chain: %s (%d entries)" % ("OK" if chain_ok else "BROKEN", chain_count))
    print("findings: %d" % len(findings))


if __name__ == "__main__":
    main()
