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

from gov import verify_chain  # noqa: E402

BANNER = "SYNTHETIC DEMONSTRATION \u2014 no real systems were inspected."
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def latest_run_dir():
    runs = ROOT / "runs"
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


def render_markdown(run_id, generated_at, chain_ok, chain_count, stats, findings):
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
    lines.append("- All agent actions, policy decisions, and human approvals in this "
                 "report come from the run's tamper-evident log; entry sequence "
                 "numbers above cite the exact records.")
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
"""


def render_html(run_id, generated_at, chain_ok, chain_count, stats, findings):
    esc = htmlmod.escape
    parts = []
    parts.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    parts.append("<title>Agent Governance Audit Report (Synthetic Demonstration)</title>")
    parts.append("<style>%s</style></head><body>" % CSS)
    parts.append("<div class=\"banner\">%s</div>" % esc(BANNER))
    parts.append("<h1>Agent Governance Audit Report</h1>")
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
    parts.append("<div class=\"footer\">%s<br>"
                 "All agent actions, policy decisions, and human approvals in this report "
                 "come from the run's tamper-evident log; entry sequence numbers cite "
                 "the exact records.</div>" % esc(BANNER))
    parts.append("</body></html>")
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Generate the audit report for a run.")
    parser.add_argument("--rundir", default=None, help="run directory (default: latest)")
    args = parser.parse_args()

    run_dir = Path(args.rundir) if args.rundir else latest_run_dir()
    run_id = run_dir.name
    entries = load_entries(run_dir)
    chain_ok, broken_seq, chain_count = verify_chain(run_dir / "actions.jsonl")

    tool_entries = [e for e in entries if e.get("event") == "tool_call"]
    stats = []
    for name in ("allowed_executed", "denied", "queued_pending", "approved_executed"):
        stats.append((name, sum(1 for e in tool_entries if e.get("decision") == name)))
    stats.append(("approval decisions", sum(1 for e in entries
                                           if e.get("event") == "approval_decision")))

    findings = build_findings(entries)
    findings.append({
        "severity": "low",
        "title": "Audit trail integrity verified",
        "status": "verified" if chain_ok else "FAILED at seq %s" % broken_seq,
        "policy_id": "n/a (log integrity)",
        "description": (
            "The run's action log is hash-chained: each entry commits to the hash "
            "of the previous entry. Replaying the chain over %d entries %s. Any "
            "tampering with a historical entry would break every later hash." %
            (chain_count, "succeeded" if chain_ok else "failed")),
        "evidence": [],
    })

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    md_path = reports / ("%s_audit_report.md" % run_id)
    html_path = reports / ("%s_audit_report.html" % run_id)
    md_path.write_text(render_markdown(run_id, generated_at, chain_ok, chain_count,
                                       stats, findings), encoding="utf-8")
    html_path.write_text(render_html(run_id, generated_at, chain_ok, chain_count,
                                     stats, findings), encoding="utf-8")
    print("wrote %s" % md_path)
    print("wrote %s" % html_path)
    print("chain: %s (%d entries)" % ("OK" if chain_ok else "BROKEN", chain_count))
    print("findings: %d" % len(findings))


if __name__ == "__main__":
    main()
