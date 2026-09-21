"""Tool executor: every agent action flows through identity -> policy -> log.

Simulated tools (no network, no real side effects outside the run directory):
  read_file(path)                  read a file (real read only inside the sandbox)
  write_file(path, content)        write a file (sandbox, or quarantine after approval)
  delete_file(path)                delete a file (sandbox only)
  api_call(endpoint, params)       simulated external API read
  http_post(url, payload)          simulated outbound webhook post
  send_email(to, subject, body)    simulated outbound email (never really sent)

Policy outcomes:
  allow            -> execute now, log "allowed_executed"
  deny             -> do not execute, log "denied"
  require_approval -> do not execute; queue for a human, log "queued_pending".
                     After human approval, execute_approved() runs approved
                     actions and logs "approved_executed".
"""

import os
from pathlib import Path

from .identity import AgentIdentity


class ToolExecutor:
    def __init__(self, run_dir, policy, log, approvals):
        self.run_dir = Path(run_dir)
        self.run_id = self.run_dir.name
        self.policy = policy
        self.log = log
        self.approvals = approvals
        self.sandbox = self.run_dir / "sandbox"
        self.quarantine = self.run_dir / "quarantine"
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self._sandbox_resolved = self.sandbox.resolve()
        self.api_calls = 0  # external api_call executions this run

    # -- path handling ----------------------------------------------------

    def _resolve(self, path):
        p = Path(path)
        if not p.is_absolute():
            p = self.sandbox / p
        return p

    def _is_outside_sandbox(self, path):
        p = self._resolve(path)
        try:
            rp = p.resolve()
        except OSError:
            rp = Path(os.path.abspath(str(p)))
        return rp != self._sandbox_resolved and self._sandbox_resolved not in rp.parents

    def _context(self, tool, args):
        ctx = {"api_calls": self.api_calls}
        if "path" in args:
            ctx["path_outside_sandbox"] = self._is_outside_sandbox(args["path"])
        return ctx

    # -- simulated tools ---------------------------------------------------

    def _simulate(self, tool, args, ctx):
        if tool == "read_file":
            p = self._resolve(args["path"])
            if not ctx.get("path_outside_sandbox") and p.is_file():
                return {"source": "sandbox", "content": p.read_text(encoding="utf-8")[:4000]}
            return {"source": "simulated", "content": "[synthetic file contents]"}
        if tool == "write_file":
            content = args.get("content", "")
            if ctx.get("path_outside_sandbox"):
                # Even approved, an outside-sandbox write never touches the real
                # path: it is quarantined inside the run directory.
                q = self.quarantine / Path(args["path"]).name
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text(content, encoding="utf-8")
                return {"path": str(q), "note": "outside sandbox; quarantined inside run dir"}
            p = self._resolve(args["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return {"path": str(p), "bytes": len(content)}
        if tool == "delete_file":
            p = self._resolve(args["path"])
            if not ctx.get("path_outside_sandbox") and p.is_file():
                p.unlink()
                return {"deleted": True, "path": str(p)}
            return {"deleted": False, "note": "simulated; no file touched"}
        if tool == "api_call":
            return {"status": 200, "synthetic": True,
                    "endpoint": args.get("endpoint"), "items_returned": 2}
        if tool == "http_post":
            return {"status": 202, "synthetic": True, "url": args.get("url")}
        if tool == "send_email":
            return {"status": "sent (simulated; no real email leaves this machine)",
                    "to": args.get("to")}
        return {"note": "unknown tool; simulated no-op"}

    @staticmethod
    def _summarize(tool, result):
        bits = []
        for k, v in result.items():
            if k == "content":
                continue
            bits.append("%s=%s" % (k, v))
        text = "; ".join(bits)
        return text[:300]

    # -- main entry points --------------------------------------------------

    def call(self, identity, tool, **kwargs):
        """Run one tool call through the governance pipeline."""
        action = {"tool": tool, "args": kwargs, "identity": identity.as_dict()}
        ctx = self._context(tool, kwargs)
        decision = self.policy.evaluate(action, ctx)

        base = {
            "event": "tool_call",
            "run_id": identity.run_id,
            "agent_id": identity.agent_id,
            "role": identity.role,
            "principal": identity.principal,
            "tool": tool,
            "args": kwargs,
            "policy_id": decision.policy_id,
            "reason": decision.reason,
        }

        if decision.effect == "allow":
            result = self._simulate(tool, kwargs, ctx)
            if tool == "api_call":
                self.api_calls += 1
            entry = self.log.append(dict(base, decision="allowed_executed",
                                         result_summary=self._summarize(tool, result)))
            return {"status": "executed", "result": result, "seq": entry["seq"]}

        if decision.effect == "deny":
            entry = self.log.append(dict(base, decision="denied", flag=decision.flag))
            return {"status": "denied", "reason": decision.reason,
                    "policy_id": decision.policy_id, "seq": entry["seq"]}

        # require_approval: queue for a human, do NOT execute.
        approval_id = self.approvals.queue(action, decision)
        entry = self.log.append(dict(base, decision="queued_pending",
                                     approval_id=approval_id))
        return {"status": "queued", "approval_id": approval_id,
                "reason": decision.reason, "seq": entry["seq"]}

    def execute_approved(self):
        """Execute approved-but-not-yet-executed actions; log each execution."""
        done = []
        for rec in self.approvals.all():
            if rec["status"] != "approved" or rec["executed"]:
                continue
            identity = AgentIdentity(**rec["identity"])
            ctx = self._context(rec["tool"], rec["args"])
            result = self._simulate(rec["tool"], rec["args"], ctx)
            if rec["tool"] == "api_call":
                self.api_calls += 1
            entry = self.log.append({
                "event": "tool_call",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": rec["tool"],
                "args": rec["args"],
                "decision": "approved_executed",
                "policy_id": rec["policy_id"],
                "approval_id": rec["id"],
                "reason": "Executed after human approval %s: %s" % (rec["id"], rec["decision_reason"]),
                "result_summary": self._summarize(rec["tool"], result),
            })
            self.approvals.mark_executed(rec["id"])
            done.append({"agent_id": identity.agent_id, "tool": rec["tool"], "seq": entry["seq"]})
        return done
