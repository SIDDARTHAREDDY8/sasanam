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
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# Wave-85: this is a SYNTHETIC demo script, not a production entry
# point. The governed core (policy store + delegation context) is out
# of scope for the demo narrative, so the demo declares its bypass
# explicitly at the construction site below and runs in staging.
# A real integration installs the full core and runs in production.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gov import ActionLog, ApprovalQueue, PolicyEngine, ToolExecutor, verify_chain
from gov.policy import default_policy_path

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


def find_pending_by_tool(pending, tool):
    """First pending approval record's id for *tool* — or fail loudly.

    F159: the demo used to hardcode a tool name + ordinal ("approve the
    6th api_call") and crashed with KeyError when the policy's verdicts
    changed. Every human-review decision now derives from the actual
    pending queue — and a demo that approves nothing is a lie, so a
    missing record is a loud SystemExit, never a silent skip.
    """
    for rec in pending:
        if rec.get("tool") == tool:
            return rec["id"]
    raise SystemExit(
        "demo honesty: the current policy queued no '%s' action for human "
        "approval, so the hero path cannot approve one — the demo refuses "
        "to silently skip the approval step. The policy verdicts have "
        "changed; update the demo narrative." % tool)


def _print_usage():
    print("usage: gov-demo [-h]")
    print()
    print("Synthetic agent-governance demo: a fake OSS-contribution pipeline")
    print("(scout -> triage -> builder -> publisher) runs through the")
    print("governance layer. Writes runs/<run-id>/ into the current working")
    print("directory. Everything is synthetic: simulated tools, fake data,")
    print("no network calls, no real credentials.")
    print()
    print("Options:")
    print("  -h, --help   show this help and exit")


def _new_run_id(prefix):
    # Microsecond resolution: two demos started in the same second must
    # not share a run directory (concurrent runs would interleave their
    # logs and queues in one dir).
    return "%s-%s" % (prefix, datetime.now().strftime("%Y%m%d-%H%M%S-%f"))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-h" in argv or "--help" in argv:
        _print_usage()
        return 0
    unknown = [a for a in argv if a not in ("-h", "--help")]
    if unknown:
        print("gov-demo: unknown argument(s): %s" % " ".join(unknown),
              file=sys.stderr)
        _print_usage()
        return 2
    # Wave-81: the dev-key opt-in is deleted from gov/. This synthetic
    # demo, not production, provisions an explicit test key
    # process-wide. Production entry points never do this — they fail
    # closed without a key.
    import secrets as _secrets
    os.environ.setdefault("GOV_LOG_KEY", _secrets.token_hex(32))
    os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")
    # Wave-69: the demo is synthetic, not production (wave-61 discipline).
    os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    run_id = _new_run_id("demo")
    run_dir = Path.cwd() / "runs" / run_id
    sandbox = run_dir / "sandbox"
    seed_sandbox(sandbox)

    log = ActionLog(run_dir / "actions.jsonl")
    policy = PolicyEngine(default_policy_path())
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      # Wave-85: synthetic demo — the governed core is out
                      # of scope for the demo narrative (see the staging
                      # declaration at the top). The bypass is declared
                      # and chained, never silent.
                      ungoverned_ack=(
                          "synthetic run_demo: multi-agent pipeline demo; "
                          "governed core out of scope for the narrative"),
                      # Packaging (defect 9): per-run egress ledger. Each
                      # demo provisions a fresh random HMAC key, so a
                      # shared runs/egress_ledger.jsonl from an earlier
                      # run (different key) would fail closed on verify.
                      # The ledger is per-run evidence here; production
                      # deployments with a stable key keep the shared
                      # cross-run ledger default.
                      ledger_path=run_dir / "egress_ledger.jsonl")

    # Identities are minted by the executor: the only identities it honors.
    scout = ex.mint_identity("scout-01", "scout", PRINCIPAL)
    triage = ex.mint_identity("triage-01", "triage", PRINCIPAL)
    builder = ex.mint_identity("builder-01", "builder", PRINCIPAL)
    publisher = ex.mint_identity("publisher-01", "publisher", PRINCIPAL)

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

    def decide(cmd, aid, reason):
        # Wave-81: the approval CLI is a production entry point (never
        # provisions a key itself), so the demo harness invokes its
        # main() IN-PROCESS: the explicit test key above is
        # process-local and would not cross a subprocess boundary,
        # while nothing about the harness environment may let the CLI
        # conjure a key.
        import io
        from contextlib import redirect_stdout, redirect_stderr
        from gov.approvals import main as approve_main
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            rc = approve_main(["--rundir", str(run_dir), cmd, aid,
                               "--reason", reason])
        sys.stdout.write(buf_out.getvalue())
        if rc != 0:
            sys.stdout.write(buf_err.getvalue())
            raise SystemExit("approval CLI failed")

    # F159: every decision below derives from the ACTUAL pending queue —
    # never a hardcoded tool name + ordinal. If the policy queues nothing
    # approvable for one of these beats, the demo fails loudly instead of
    # silently skipping the approval step (a demo that approves nothing
    # is a lie).
    print("\n  Approving the publisher's outreach email (content reviewed; recipient is synthetic)...")
    decide("approve", find_pending_by_tool(pending, "send_email"),
           "Email content reviewed; recipient is synthetic. Approved.")
    print("\n  Rejecting the builder's write outside the sandbox...")
    decide("reject", find_pending_by_tool(pending, "write_file"),
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
    print("  gov-report --rundir %s" % run_dir)
    print("  gov-approve --rundir %s list" % run_dir)


if __name__ == "__main__":
    raise SystemExit(main())
