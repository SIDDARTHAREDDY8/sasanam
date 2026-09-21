"""File-based human approval queue.

When the policy engine returns "require_approval", the action is NOT executed.
It is stored as a pending approval with full context. A human reviews it with:

    python -m gov.approve --rundir <run dir> list
    python -m gov.approve --rundir <run dir> approve <id> --reason "..."
    python -m gov.approve --rundir <run dir> reject <id> --reason "..."

(Use --latest instead of --rundir to target the most recent run.)

Every decision is appended to the tamper-evident action log, so the full
lifecycle - queued -> approved/rejected -> executed - is auditable.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

from .identity import AgentIdentity
from .log import ActionLog


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


class ApprovalQueue:
    def __init__(self, run_dir, log):
        self.run_dir = Path(run_dir)
        self.log = log
        self.path = self.run_dir / "approvals.jsonl"

    def queue(self, action, decision):
        """Store a pending approval; returns the approval id."""
        identity = action.get("identity") or {}
        record = {
            "id": uuid.uuid4().hex[:8],
            "ts": _utcnow(),
            "run_id": identity.get("run_id"),
            "agent_id": identity.get("agent_id"),
            "role": identity.get("role"),
            "identity": identity,
            "tool": action.get("tool"),
            "args": action.get("args") or {},
            "policy_id": decision.policy_id,
            "policy_reason": decision.reason,
            "status": "pending",
            "decided_by": None,
            "decided_at": None,
            "decision_reason": None,
            "executed": False,
        }
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
        return record["id"]

    def all(self):
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def pending(self):
        return [r for r in self.all() if r["status"] == "pending"]

    def get(self, approval_id):
        for r in self.all():
            if r["id"] == approval_id:
                return r
        return None

    def _rewrite(self, records):
        with open(self.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=True, default=str) + "\n")

    def decide(self, approval_id, approved, reason, decided_by="human-operator"):
        """Record a human decision and log it. Returns (record, log_entry)."""
        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break
        if target is None:
            raise ValueError("approval id %r not found" % approval_id)
        if target["status"] != "pending":
            raise ValueError("approval %r is already %s" % (approval_id, target["status"]))
        target["status"] = "approved" if approved else "rejected"
        target["decided_by"] = decided_by
        target["decided_at"] = _utcnow()
        target["decision_reason"] = reason
        self._rewrite(records)

        approver = AgentIdentity(
            agent_id="human-operator",
            role="approver",
            run_id=target.get("run_id") or "",
            principal="human-operator",
        )
        entry = self.log.append({
            "event": "approval_decision",
            "run_id": target.get("run_id"),
            "agent_id": approver.agent_id,
            "role": approver.role,
            "principal": approver.principal,
            "tool": target["tool"],
            "args": target["args"],
            "decision": "approved" if approved else "rejected",
            "policy_id": target["policy_id"],
            "approval_id": target["id"],
            "reason": reason,
            "related_agent": target["agent_id"],
        })
        return target, entry

    def mark_executed(self, approval_id):
        records = self.all()
        for r in records:
            if r["id"] == approval_id:
                r["executed"] = True
        self._rewrite(records)


def _resolve_rundir(args):
    root = Path(__file__).resolve().parent.parent
    if args.latest or not args.rundir:
        runs = root / "runs"
        if args.rundir:
            return Path(args.rundir)
        cands = [d for d in runs.iterdir()] if runs.exists() else []
        cands = [d for d in cands if d.is_dir()]
        if not cands:
            raise SystemExit("no runs found; run python demo/run_demo.py first")
        return max(cands, key=lambda d: d.stat().st_mtime)
    return Path(args.rundir)


def _print_records(records):
    if not records:
        print("  (none)")
        return
    print("  %-10s %-14s %-12s %s" % ("ID", "AGENT", "TOOL", "STATUS / POLICY REASON"))
    for r in records:
        extra = r["decision_reason"] or r["policy_reason"] or ""
        print("  %-10s %-14s %-12s %s -- %s" % (r["id"], r["agent_id"], r["tool"], r["status"], extra))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="gov.approve",
        description="Review the human approval queue for a governance run.",
    )
    parser.add_argument("--rundir", default=None, help="run directory (default: --latest)")
    parser.add_argument("--latest", action="store_true", help="use the most recent run")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list approvals and their status")

    p_approve = sub.add_parser("approve", help="approve a pending action")
    p_approve.add_argument("id", help="approval id")
    p_approve.add_argument("--reason", required=True, help="why this is approved")

    p_reject = sub.add_parser("reject", help="reject a pending action")
    p_reject.add_argument("id", help="approval id")
    p_reject.add_argument("--reason", required=True, help="why this is rejected")

    args = parser.parse_args(argv)
    run_dir = _resolve_rundir(args)
    log = ActionLog(run_dir / "actions.jsonl")
    queue = ApprovalQueue(run_dir, log)

    if args.cmd == "list":
        print("Approvals for run %s:" % run_dir.name)
        _print_records(queue.all())
        return 0

    try:
        record, entry = queue.decide(args.id, args.cmd == "approve", args.reason)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print("%s approval %s (%s %s by %s)" % (
        "Approved" if args.cmd == "approve" else "Rejected",
        record["id"], record["agent_id"], record["tool"], record["agent_id"]))
    print("reason: %s" % args.reason)
    print("logged as entry seq %d" % entry["seq"])
    if args.cmd == "approve":
        print("Note: the action is approved but not yet executed; the executor")
        print("runs approved actions separately so execution itself is logged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
