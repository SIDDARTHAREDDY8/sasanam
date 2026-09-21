#!/usr/bin/env python3
"""Synthetic agent-governance demo.

A fake OSS-contribution pipeline (scout -> triage -> builder -> publisher) runs
through the governance layer: every action is attributed to an identity,
checked against YAML policies, and written to a hash-chained action log.
Risky actions are queued for human approval instead of executing.

Everything is synthetic: simulated tools, fake data, no network calls, no real
credentials, nothing read or written outside this project directory.
"""

import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gov import ActionLog, AgentIdentity, ApprovalQueue, PolicyEngine, ToolExecutor, verify_chain

PRINCIPAL = "siddartha-reddy (account owner)"


def seed_sandbox(sandbox: Path):
    (sandbox / "repo").mkdir(parents=True, exist_ok=True)
    (sandbox / "repo" / "issues.json").write_text(json.dumps({
        "repo": "synthetic-repo",
        "issues": [
            {"id": 42, "title": "Crash on empty config file", "labels": ["bug"]},
            {"id": 43, "title": "Add retry to flaky sync step", "labels": ["enhancement"]},
        ],
    }, indent=2), encoding="utf-8")
    (sandbox / "repo" / "README.md").write_text(
        "# synthetic-repo\n\nA fake repository used only for this demo.\n",
        encoding="utf-8")


def show(desc, result):
    status = result.get("status")
    seq = result.get("seq")
    if status == "executed":
        print("  [allowed+executed] %s (log seq %s)" % (desc, seq))
    elif status == "denied":
        print("  [DENIED] %s" % desc)
        print("           reason: %s (log seq %s)" % (result.get("reason"), seq))
    elif status == "queued":
        print("  [QUEUED for human approval] %s" % desc)
        print("           approval_id=%s (log seq %s)" % (result.get("approval_id"), seq))


def main():
    run_id = "demo-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = ROOT / "runs" / run_id
    sandbox = run_dir / "sandbox"
    seed_sandbox(sandbox)

    log = ActionLog(run_dir / "actions.jsonl")
    policy = PolicyEngine(ROOT / "policies" / "default.yaml")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals)

    def ident(agent_id, role):
        return AgentIdentity(agent_id=agent_id, role=role,
                             run_id=run_id, principal=PRINCIPAL)

    scout = ident("scout-01", "scout")
    triage = ident("triage-01", "triage")
    builder = ident("builder-01", "builder")
    publisher = ident("publisher-01", "publisher")

    log.append({"event": "run_started", "run_id": run_id, "agent_id": "orchestrator",
                "role": "orchestrator", "principal": PRINCIPAL,
                "decision": "n/a", "reason": "Synthetic demo run started."})

    print("=" * 70)
    print("AGENT GOVERNANCE DEMO (synthetic - no real systems involved)")
    print("run_id: %s" % run_id)
    print("=" * 70)

    print("\n[1] SCOUT gathers candidate issues from the (fake) issue tracker")
    for page in range(1, 7):
        r = ex.call(scout, "api_call", endpoint="issues.list",
                    params={"repo": "synthetic-repo", "page": page})
        show("scout api_call issues.list page=%d" % page, r)

    r = ex.call(scout, "read_file", path="~/.aws/credentials")
    show("scout read_file ~/.aws/credentials", r)

    r = ex.call(scout, "read_file", path="repo/issues.json")
    show("scout read_file repo/issues.json", r)

    print("\n[2] TRIAGE picks one issue and records the decision")
    r = ex.call(triage, "read_file", path="repo/issues.json")
    show("triage read_file repo/issues.json", r)
    r = ex.call(triage, "write_file", path="triage/decision.md",
                content="# Triage decision\n\nTake issue #42 (crash on empty config).\n")
    show("triage write_file triage/decision.md", r)

    print("\n[3] BUILDER writes a fix, then tries two out-of-bounds actions")
    r = ex.call(builder, "read_file", path="repo/README.md")
    show("builder read_file repo/README.md", r)
    r = ex.call(builder, "write_file", path="fixes/issue-42.patch",
                content="--- synthetic patch for issue #42 ---\n")
    show("builder write_file fixes/issue-42.patch", r)
    r = ex.call(builder, "delete_file", path="../../outside-sandbox.txt")
    show("builder delete_file ../../outside-sandbox.txt", r)
    r = ex.call(builder, "write_file", path="/tmp/rogue-patch.diff",
                content="synthetic patch content\n")
    show("builder write_file /tmp/rogue-patch.diff", r)

    print("\n[4] PUBLISHER tries outbound actions")
    r = ex.call(publisher, "http_post", url="https://hooks.synthetic.local/ci",
                payload={"run_id": run_id, "status": "ready"})
    show("publisher http_post to CI webhook", r)
    r = ex.call(publisher, "send_email", to="maintainer@synthetic.local",
                subject="Fix for issue #42 ready for review",
                body="Synthetic outreach email body.")
    show("publisher send_email to maintainer@synthetic.local", r)

    print("\n[5] HUMAN REVIEW via the approval CLI (python -m gov.approve)")
    pending = approvals.pending()
    print("  %d action(s) waiting for a human:" % len(pending))
    for rec in pending:
        print("    - %s | %s %s | %s" % (rec["id"], rec["agent_id"],
                                         rec["tool"], rec["policy_reason"]))
    by_tool = {rec["tool"]: rec["id"] for rec in pending}

    def decide(cmd, aid, reason):
        proc = subprocess.run(
            [sys.executable, "-m", "gov.approve", "--rundir", str(run_dir),
             cmd, aid, "--reason", reason],
            cwd=str(ROOT), capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        if proc.returncode != 0:
            sys.stdout.write(proc.stderr)
            raise SystemExit("approval CLI failed")

    print("\n  Approving the 6th issue-tracker API call (read-only, needed for triage)...")
    decide("approve", by_tool["api_call"],
           "Read-only API call needed to finish triage; one-time budget exception granted.")
    print("\n  Approving the publisher's outreach email (content reviewed; recipient is synthetic)...")
    decide("approve", by_tool["send_email"],
           "Email content reviewed; recipient is synthetic. Approved.")
    print("\n  Rejecting the builder's write outside the sandbox...")
    decide("reject", by_tool["write_file"],
           "Writes outside the run sandbox are not permitted, even with approval.")
    print("\n  Leaving the CI webhook post pending for later human review.")

    print("\n[6] Executing approved actions")
    for item in ex.execute_approved():
        print("  [approved+executed] %s %s (log seq %s)"
              % (item["agent_id"], item["tool"], item["seq"]))

    log.append({"event": "run_finished", "run_id": run_id, "agent_id": "orchestrator",
                "role": "orchestrator", "principal": PRINCIPAL,
                "decision": "n/a", "reason": "Synthetic demo run finished."})

    ok, broken, count = verify_chain(run_dir / "actions.jsonl")
    print("\n[7] Audit summary")
    entries = [json.loads(l) for l in
               (run_dir / "actions.jsonl").read_text(encoding="utf-8").splitlines()
               if l.strip()]
    decisions = Counter(e.get("decision") for e in entries
                        if e.get("event") == "tool_call")
    for decision_name, n in sorted(decisions.items()):
        print("  tool_call decisions: %s: %d" % (decision_name, n))
    n_approvals = sum(1 for e in entries if e.get("event") == "approval_decision")
    print("  approval decisions recorded: %d" % n_approvals)
    print("  hash chain: %s (%d entries)"
          % ("OK" if ok else "BROKEN at seq %s" % broken, count))
    print("\nRun directory: %s" % run_dir)
    print("Next steps:")
    print("  python3 demo/make_report.py --rundir %s" % run_dir)
    print("  python3 -m gov.approve --rundir %s list" % run_dir)


if __name__ == "__main__":
    main()
