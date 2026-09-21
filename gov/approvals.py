"""File-based human approval queue.

When the policy engine returns "require_approval", the action is NOT executed.
It is stored as a pending approval with full context. A human reviews it with:

    python -m gov.approve --rundir <run dir> list
    python -m gov.approve --rundir <run dir> approve <id> --reason "..."
    python -m gov.approve --rundir <run dir> reject <id> --reason "..."

(Use --latest instead of --rundir to target the most recent run.)

Approval hardening:

* **Integrity binding.** Each record stores ``args_digest``, a SHA-256 over
  the queued (redacted) arguments plus the policy id. The executor refuses
  to run an approval whose arguments changed after queueing.
* **Policy pinning.** The record stores the ``policy_hash`` it was queued
  under; execution under a different policy version is refused.
* **Expiry.** Approvals expire ``approvals.ttl_hours`` after the decision
  (default 24h); the executor refuses stale approvals.
* **Separation of duties.** The requesting agent cannot approve its own
  action: ``decide()`` raises if ``decided_by`` equals the agent id.
* **No trust in agent framing.** ``agent_justification`` is stored verbatim
  but labeled UNVERIFIED everywhere it is displayed; the reviewer sees the
  executor-generated ``preview`` (what the action would do) instead.

Every decision is appended to the tamper-evident action log, so the full
lifecycle - queued -> approved/rejected -> executed - is auditable.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from .identity import AgentIdentity
from .log import ActionLog


def _utcnow():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def record_digest(tool, args, policy_id):
    """Integrity digest binding a queued approval to its exact arguments."""
    payload = json.dumps({"tool": tool, "args": args, "policy_id": policy_id},
                         sort_keys=True, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


class ApprovalQueue:
    def __init__(self, run_dir, log):
        self.run_dir = Path(run_dir)
        self.log = log
        self.path = self.run_dir / "approvals.jsonl"

    def queue(self, action, decision, provenance="agent_direct", preview="",
              policy_hash=None, delegation_attempted=False):
        """Store a pending approval; returns the approval id.

        ``action`` carries tool, redacted args, identity, the agent's
        justification (unverified), and the redaction list.
        """
        identity = action.get("identity") or {}
        args = action.get("args") or {}
        record = {
            "id": uuid.uuid4().hex[:8],
            "ts": _utcnow(),
            "run_id": identity.get("run_id"),
            "agent_id": identity.get("agent_id"),
            "role": identity.get("role"),
            "identity": identity,
            "tool": action.get("tool"),
            "args": args,
            "redactions_applied": action.get("redactions") or [],
            "agent_justification": action.get("agent_justification"),
            "provenance": provenance,
            "preview": preview,
            "delegation_attempted": delegation_attempted,
            "policy_id": decision.policy_id,
            "policy_reason": decision.reason,
            "policy_hash": policy_hash,
            "args_digest": record_digest(action.get("tool"), args,
                                         decision.policy_id),
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

    def _rewrite(self, fn_or_records):
        """Rewrite the queue file.

        Accepts either a list of records (legacy contract) or a function
        fn(records) -> new_records, so callers can do atomic transforms
        without a read-modify-write race in their own code.
        """
        if callable(fn_or_records):
            records = fn_or_records(self.all())
        else:
            records = fn_or_records
        with open(self.path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=True, default=str) + "\n")

    def decide(self, approval_id, approved, reason, decided_by="human-operator"):
        """Record a human decision and log it. Returns (record, log_entry).

        Rejected decision *attempts* (unknown id, self-approval, or a
        record that is no longer pending) are also appended to the audit
        log before the ValueError propagates, so abuse of the approval
        workflow itself leaves a trace.
        """
        records = self.all()
        target = None
        for r in records:
            if r["id"] == approval_id:
                target = r
                break

        def _log_attempt(outcome, note, agent_id=None, role=None, tool=None):
            try:
                self.log.append({
                    "event": "approval_decision_attempt",
                    "run_id": (target or {}).get("run_id"),
                    "agent_id": "human-operator",
                    "role": "approver",
                    "principal": "human-operator",
                    "tool": tool if tool is not None else (target or {}).get("tool"),
                    "decision": outcome,
                    "approval_id": approval_id,
                    "decided_by": decided_by,
                    "related_agent": agent_id if agent_id is not None
                                     else (target or {}).get("agent_id"),
                    "reason": note,
                })
            except Exception:
                # The attempt is rejected regardless; a logging outage must
                # not turn a rejection into an approval.
                pass

        if target is None:
            _log_attempt("rejected_attempt",
                         "decision attempted on unknown approval id")
            raise ValueError("approval id %r not found" % approval_id)
        # Separation of duties: the requesting agent can never approve (or
        # reject) its own action, even via a confused-deputy prompt.
        if decided_by == target.get("agent_id"):
            _log_attempt(
                "rejected_attempt",
                "separation of duties: requesting agent attempted to decide "
                "its own approval",
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError(
                "separation of duties: agent %r cannot decide its own "
                "approval %s" % (decided_by, approval_id))
        if target["status"] != "pending":
            _log_attempt(
                "rejected_attempt",
                "decision attempted on %s approval" % target["status"],
                agent_id=target.get("agent_id"), role=target.get("role"),
                tool=target.get("tool"))
            raise ValueError("approval %r is already %s" % (approval_id, target["status"]))
        target["status"] = "approved" if approved else "rejected"
        target["decided_by"] = decided_by
        target["decided_at"] = _utcnow()
        target["decision_reason"] = reason
        # NOTE: all() re-parses from disk, so the mutated `target` dict
        # must be spliced into the rewritten records explicitly.
        self._rewrite(lambda records: [
            target if r["id"] == target["id"] else r for r in records])

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
            "redactions_applied": target.get("redactions_applied", []),
            "provenance": target.get("provenance", "agent_direct"),
            "preview": target.get("preview", ""),
            "policy_hash": target.get("policy_hash"),
            "decision": "approved" if approved else "rejected",
            "policy_id": target["policy_id"],
            "approval_id": target["id"],
            "reason": reason,
            "decided_by": decided_by,
            "related_agent": target["agent_id"],
        })
        return target, entry

    def mark_executed(self, approval_id):
        self._rewrite(lambda records: [
            dict(r, executed=True) if r["id"] == approval_id else r
            for r in records])


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
    for r in records:
        # First line: routing facts only. The agent's justification is NEVER
        # on this line (or anywhere unlabeled): it is unverified input.
        print("  ID: %s | agent: %s | tool: %s | status: %s | policy: %s" % (
            r["id"], r["agent_id"], r["tool"], r["status"], r["policy_id"]))
        print("    args: %s" % json.dumps(r["args"], ensure_ascii=True,
                                          default=str)[:400])
        print("    provenance: %s" % r.get("provenance", "agent_direct"))
        if r.get("preview"):
            print("    preview: %s" % r["preview"])
        if r.get("redactions_applied"):
            print("    redactions: %s" % ", ".join(r["redactions_applied"]))
        if r.get("delegation_attempted"):
            print("    WARNING: delegation framing detected "
                  "(on_behalf_of/delegated_by)")
        if r.get("agent_justification"):
            print("    agent justification (UNVERIFIED, do not trust): %s"
                  % r["agent_justification"])
        if r["status"] != "pending":
            print("    decision: %s by %s at %s: %s" % (
                r["status"], r.get("decided_by"), r.get("decided_at"),
                r.get("decision_reason")))


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
    p_approve.add_argument("--by", default="human-operator",
                           help="who is deciding (default: human-operator)")

    p_reject = sub.add_parser("reject", help="reject a pending action")
    p_reject.add_argument("id", help="approval id")
    p_reject.add_argument("--reason", required=True, help="why this is rejected")
    p_reject.add_argument("--by", default="human-operator",
                          help="who is deciding (default: human-operator)")

    args = parser.parse_args(argv)
    run_dir = _resolve_rundir(args)
    log = ActionLog(run_dir / "actions.jsonl")
    queue = ApprovalQueue(run_dir, log)

    if args.cmd == "list":
        print("Approvals for run %s:" % run_dir.name)
        _print_records(queue.all())
        return 0

    try:
        record, entry = queue.decide(args.id, args.cmd == "approve",
                                     args.reason, decided_by=args.by)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print("%s approval %s (%s %s)" % (
        "Approved" if args.cmd == "approve" else "Rejected",
        record["id"], record["agent_id"], record["tool"]))
    print("decided by: %s" % args.by)
    print("reason: %s" % args.reason)
    print("logged as entry seq %d" % entry["seq"])
    if args.cmd == "approve":
        print("Note: the action is approved but not yet executed; the executor")
        print("runs approved actions separately so execution itself is logged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
