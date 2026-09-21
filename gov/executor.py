"""Tool executor: every agent action flows through identity -> policy -> log.

Pipeline for each call (in order):

1. **Identity.** The identity must be an ``AgentIdentity`` *minted by this
   executor* via :meth:`mint_identity` (unforgeable within the process) and
   its ``run_id`` must match this run. A forged or cross-run identity is
   denied and logged; a structurally valid but unminted identity raises
   :class:`UnmintedIdentityError`.
2. **Role allowlist.** The caller's role must permit the tool at all,
   regardless of what the rules say (least privilege).
3. **DLP.** Credential patterns in arguments deny the call before any
   evaluation or execution. PII is redacted before logging/queueing.
4. **Rate/volume guards.** Per-run caps on sends, writes, deletes and a
   repeated-identical-call (loop) guard.
5. **Policy.** Fail-closed evaluation with deny priority.
6. **Fail-closed logging.** The log is probed writable *before* any side
   effect; the decision is appended, and only then does an allowed action
   execute.
7. **Provenance.** Every executed ``read_file``/``api_call`` taints the run
   (tool output is untrusted input); read content fingerprints let the
   executor detect read-before-send exfiltration.

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
                     After human approval, execute_approved() re-validates
                     (expiry, integrity, current policy) and logs
                     "approved_executed".
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from . import dlp
from .approvals import record_digest
from .identity import AgentIdentity, UnmintedIdentityError

_SEND_TOOLS = ("send_email", "http_post")
_MAX_READ_STORE = 256 * 1024  # cap on stored read fingerprints per run


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
        self.counters = {}  # attempted calls per tool this run
        self._repeats = {}  # (tool, canonical args) -> count
        self._minted = set()  # (agent_id, role, run_id, principal) tuples
        self._tainted = False  # True once tool output entered this run
        self._taint_sources = []
        self._read_contents = []  # fingerprints of executed read results

    # -- identity ---------------------------------------------------------

    def mint_identity(self, agent_id, role, principal):
        """Issue the only kind of identity this executor will honor."""
        ident = AgentIdentity(agent_id=agent_id, role=role,
                              run_id=self.run_id, principal=principal)
        self._minted.add((ident.agent_id, ident.role,
                          ident.run_id, ident.principal))
        return ident

    def _check_identity(self, identity):
        """Return None if OK, else a (policy_id, flag, reason) deny triple."""
        if identity.run_id != self.run_id:
            return ("identity-run-mismatch", "identity_rejected",
                    "Identity run_id %r does not match this run %r."
                    % (identity.run_id, self.run_id))
        if (identity.agent_id, identity.role,
                identity.run_id, identity.principal) not in self._minted:
            raise UnmintedIdentityError(
                "Identity %r was not minted by this executor." % (identity,))
        return None

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

    # -- provenance / egress ----------------------------------------------

    def _ingest_result(self, tool, result):
        if tool in ("read_file", "api_call"):
            content = result.get("content")
            if content:
                self._read_contents.append(content[:65536])
                total = sum(len(c) for c in self._read_contents)
                while total > _MAX_READ_STORE and self._read_contents:
                    total -= len(self._read_contents.pop(0))
            self._tainted = True
            if tool not in self._taint_sources:
                self._taint_sources.append(tool)

    def _carries_read_content(self, tool, args):
        if tool not in _SEND_TOOLS or not self._read_contents:
            return False
        # Search the RAW string values (not JSON: json.dumps escapes
        # newlines, which would break verbatim matching of multi-line
        # excerpts).
        parts = []

        def _collect(v):
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                for x in v.values():
                    _collect(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    _collect(x)

        _collect(args)
        corpus = "\x00".join(parts)
        if len(corpus) < 32:
            return False
        for c in self._read_contents:
            if len(c) < 32:
                continue
            # Any 32-char run of the outbound payload appearing verbatim
            # in previously read content counts, even if the agent only
            # exfiltrated an excerpt of a larger file.
            for i in range(len(corpus) - 31):
                if corpus[i:i + 32] in c:
                    return True
        return False

    def _domain_allowlisted(self, tool, args):
        allow = (self.policy.egress or {}).get("domain_allowlist") or []
        host = None
        if tool == "http_post":
            try:
                host = (urlparse(args.get("url") or "").hostname or "").lower()
            except Exception:
                host = None
        elif tool == "send_email":
            to = args.get("to") or ""
            host = to.rsplit("@", 1)[-1].lower() if "@" in to else None
        if not host:
            return False
        return any(host == d.lower() or host.endswith("." + d.lower())
                   for d in allow)

    def _context(self, tool, args):
        ctx = {"api_calls": self.api_calls, "counters": dict(self.counters)}
        if "path" in args:
            ctx["path_outside_sandbox"] = self._is_outside_sandbox(args["path"])
        if tool in _SEND_TOOLS:
            ctx["domain_allowlisted"] = self._domain_allowlisted(tool, args)
            ctx["carries_read_content"] = self._carries_read_content(tool, args)
        ctx["source_untrusted"] = self._tainted
        return ctx

    # -- simulated tools ---------------------------------------------------

    def _simulate(self, tool, args, ctx):
        if tool == "read_file":
            p = self._resolve(args["path"])
            if not ctx.get("path_outside_sandbox") and p.is_file():
                return {"source": "sandbox",
                        "content": p.read_text(encoding="utf-8")[:4000]}
            return {"source": "simulated", "content": "[synthetic file contents]"}
        if tool == "write_file":
            content = args.get("content", "")
            if ctx.get("path_outside_sandbox"):
                # Even approved, an outside-sandbox write never touches the real
                # path: it is quarantined inside the run directory.
                q = self.quarantine / Path(args["path"]).name
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text(content if isinstance(content, str) else str(content),
                             encoding="utf-8")
                return {"path": str(q),
                        "note": "outside sandbox; quarantined inside run dir"}
            p = self._resolve(args["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content if isinstance(content, str) else str(content),
                         encoding="utf-8")
            return {"path": str(p),
                    "bytes": len(content if isinstance(content, str) else str(content))}
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
        return "; ".join(bits)[:300]

    @staticmethod
    def _preview(tool, args):
        if tool == "send_email":
            return "would send email to %s (subject: %r)" % (
                args.get("to"), args.get("subject"))
        if tool == "http_post":
            return "would POST to %s" % args.get("url")
        if tool == "write_file":
            content = args.get("content", "")
            n = len(content if isinstance(content, str) else str(content))
            return "would write %d bytes to %s" % (n, args.get("path"))
        if tool == "delete_file":
            return "would delete %s" % args.get("path")
        if tool == "read_file":
            return "would read %s" % args.get("path")
        if tool == "api_call":
            return "would call API endpoint %s" % args.get("endpoint")
        return "would invoke %s" % tool

    # -- main entry points --------------------------------------------------

    def call(self, identity, tool, **kwargs):
        """Run one tool call through the governance pipeline."""
        if not isinstance(identity, AgentIdentity):
            raise TypeError("identity must be an AgentIdentity minted by "
                            "this executor, got %r" % type(identity).__name__)
        # Framing kwargs are agent-supplied metadata, never trusted inputs.
        justification = kwargs.pop("justification", None)
        on_behalf_of = kwargs.pop("on_behalf_of", None)
        delegated_by = kwargs.pop("delegated_by", None)
        delegation_attempted = bool(on_behalf_of or delegated_by)

        self.counters[tool] = self.counters.get(tool, 0) + 1
        repeat_key = (tool, json.dumps(kwargs, sort_keys=True, default=str))
        self._repeats[repeat_key] = self._repeats.get(repeat_key, 0) + 1

        blocked, blocking_rule, redacted_args, redactions = dlp.scan_tool_args(
            tool, kwargs)

        def _base(extra):
            entry = {
                "event": "tool_call",
                "run_id": identity.run_id,
                "agent_id": identity.agent_id,
                "role": identity.role,
                "principal": identity.principal,
                "tool": tool,
                "args": redacted_args,
                "redactions_applied": redactions,
                "provenance": ("untrusted_influenced" if self._tainted
                               else "agent_direct"),
                "delegation_attempted": delegation_attempted,
            }
            if self._tainted:
                entry["taint_detail"] = (
                    "source_untrusted: prior tool output (%s) may influence "
                    "this call" % ",".join(self._taint_sources))
            entry.update(extra)
            return entry

        # 1. identity ------------------------------------------------------
        id_deny = self._check_identity(identity)
        if id_deny is not None:
            policy_id, flag, reason = id_deny
            entry = self.log.append(_base({
                "agent_id": "unverified",
                "role": "unverified",
                "principal": "unverified",
                "claimed_identity": {"agent_id": identity.agent_id,
                                     "role": identity.role},
                "decision": "denied",
                "policy_id": policy_id,
                "flag": flag,
                "reason": reason,
            }))
            return {"status": "denied", "reason": reason,
                    "policy_id": policy_id, "seq": entry["seq"]}

        # 2. role allowlist ------------------------------------------------
        if not self.policy.role_allows(identity.role, tool):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "role-allowlist",
                "flag": "role_allowlist_violation",
                "reason": "Role %r is not allowed to use tool %r "
                          "(least privilege)." % (identity.role, tool),
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "role-allowlist", "seq": entry["seq"]}

        # 3. DLP credential block ------------------------------------------
        if blocked:
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "dlp-credential-block",
                "flag": "credential_block",
                "reason": "Blocked by DLP rule %s: credential-like material "
                          "in tool arguments." % blocking_rule,
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "dlp-credential-block", "seq": entry["seq"]}

        # 4. rate / volume guards ------------------------------------------
        rl = self.policy.rate_limit or {}
        if self._repeats[repeat_key] > int(rl.get("max_identical_calls", 10)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "loop-guard",
                "flag": "loop_guard",
                "reason": "Repeated identical %s call %d times; possible runaway "
                          "loop." % (tool, self._repeats[repeat_key]),
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "loop-guard", "seq": entry["seq"]}
        sends = self.counters.get("send_email", 0) + self.counters.get("http_post", 0)
        if tool in _SEND_TOOLS and sends > int(rl.get("max_sends_per_run", 10)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-sends",
                "flag": "volume_guard",
                "reason": "Per-run send budget exceeded (%d sends)." % sends,
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-sends", "seq": entry["seq"]}
        if tool == "write_file" and self.counters.get("write_file", 0) > int(
                rl.get("max_writes_per_run", 50)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-writes",
                "flag": "volume_guard",
                "reason": "Per-run write budget exceeded.",
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-writes", "seq": entry["seq"]}
        if tool == "delete_file" and self.counters.get("delete_file", 0) > int(
                rl.get("max_deletes_per_run", 20)):
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": "volume-guard-deletes",
                "flag": "volume_guard",
                "reason": "Per-run delete budget exceeded.",
            }))
            return {"status": "denied", "reason": entry["reason"],
                    "policy_id": "volume-guard-deletes", "seq": entry["seq"]}

        # 5. policy evaluation ----------------------------------------------
        action = {"tool": tool, "args": kwargs,
                  "identity": identity.as_dict(),
                  "role": identity.role, "agent_id": identity.agent_id}
        ctx = self._context(tool, kwargs)
        decision = self.policy.evaluate(action, ctx)

        if decision.effect == "allow":
            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched: no log, no side effect.
            auth_entry = self.log.append(_base({
                "decision": "execution_authorized",
                "policy_id": decision.policy_id,
                "reason": decision.reason,
                "flag": decision.flag,
            }))
            result = self._simulate(tool, kwargs, ctx)
            self._ingest_result(tool, result)
            if tool == "api_call":
                self.api_calls += 1
            entry = self.log.append(_base({
                "decision": "allowed_executed",
                "policy_id": decision.policy_id,
                "reason": decision.reason,
                "flag": decision.flag,
                "result_summary": self._summarize(tool, result),
                "authorization_seq": auth_entry["seq"],
            }))
            return {"status": "executed", "result": result, "seq": entry["seq"]}

        if decision.effect == "deny":
            entry = self.log.append(_base({
                "decision": "denied",
                "policy_id": decision.policy_id,
                "reason": decision.reason,
                "flag": decision.flag,
            }))
            return {"status": "denied", "reason": decision.reason,
                    "policy_id": decision.policy_id, "seq": entry["seq"]}

        # require_approval: queue for a human, do NOT execute.
        provenance = ("untrusted_influenced" if self._tainted
                      else "agent_direct")
        approval_action = {"tool": tool, "args": redacted_args,
                           "identity": identity.as_dict(),
                           "agent_justification": justification,
                           "redactions": redactions}
        approval_id = self.approvals.queue(
            approval_action, decision, provenance,
            self._preview(tool, kwargs),
            policy_hash=self.policy.policy_hash,
            delegation_attempted=delegation_attempted)
        entry = self.log.append(_base({
            "decision": "queued_pending",
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            "flag": decision.flag,
            "approval_id": approval_id,
        }))
        return {"status": "queued", "approval_id": approval_id,
                "policy_id": decision.policy_id,
                "reason": decision.reason, "seq": entry["seq"]}

    # -- approved-action execution ------------------------------------------

    def _approval_expired(self, rec, ttl_hours):
        try:
            decided = datetime.fromisoformat(rec["decided_at"])
        except Exception:
            return True  # unparseable timestamp: fail closed
        if decided.tzinfo is None:
            decided = decided.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - decided).total_seconds()
        return age > ttl_hours * 3600

    def execute_approved(self):
        """Execute approved-but-not-yet-executed actions.

        Each approval is re-validated at execution time: expiry, integrity
        of the queued arguments, the policy it was approved under, and a
        fresh policy evaluation. Any failure refuses the execution and logs
        why. Returns the list of executed actions.
        """
        done = []
        ttl = self.policy.approval_ttl_hours
        for rec in self.approvals.all():
            if rec.get("status") != "approved" or rec.get("executed"):
                continue
            aid = rec["id"]

            def _refuse(reason, flag, policy_id="approval-execution-refused"):
                self.approvals._rewrite(lambda records: [
                    dict(r, execution_refused_reason=reason)
                    if r["id"] == aid else r for r in records])
                self.log.append({
                    "event": "approval_execution_refused",
                    "run_id": self.run_id,
                    "agent_id": rec.get("agent_id"),
                    "role": rec.get("role"),
                    "tool": rec.get("tool"),
                    "approval_id": aid,
                    "decision": "refused",
                    "policy_id": policy_id,
                    "flag": flag,
                    "reason": reason,
                })

            # 1. expiry
            if self._approval_expired(rec, ttl):
                self.approvals._rewrite(lambda records: [
                    dict(r, status="expired") if r["id"] == aid else r
                    for r in records])
                self.log.append({
                    "event": "approval_expired",
                    "run_id": self.run_id,
                    "agent_id": rec.get("agent_id"),
                    "tool": rec.get("tool"),
                    "approval_id": aid,
                    "decision": "refused",
                    "policy_id": "approval-ttl",
                    "flag": "approval_expired",
                    "reason": "Approval %s expired (TTL %sh)." % (aid, ttl),
                })
                continue
            # 2. integrity: queued arguments must be byte-identical
            if rec.get("args_digest") != record_digest(
                    rec["tool"], rec["args"], rec.get("policy_id")):
                _refuse("Approval %s arguments were modified after queueing; "
                        "integrity digest mismatch." % aid,
                        "approval_integrity_violation")
                continue
            # 3. policy staleness: approved under a different policy version
            if rec.get("policy_hash") != self.policy.policy_hash:
                _refuse("Approval %s was granted under policy %s but the "
                        "active policy is %s; re-approval required."
                        % (aid, (rec.get("policy_hash") or "")[:12],
                           self.policy.policy_hash[:12]),
                        "approval_policy_stale")
                continue
            # 4. fresh policy evaluation (TOCTOU guard)
            ctx = self._context(rec["tool"], rec["args"])
            action = {"tool": rec["tool"], "args": rec["args"],
                      "identity": rec.get("identity"),
                      "role": rec.get("role"), "agent_id": rec.get("agent_id")}
            decision = self.policy.evaluate(action, ctx)
            if decision.effect == "deny":
                _refuse("Approval %s no longer permitted: %s"
                        % (aid, decision.reason), decision.flag or "policy_re_eval_deny",
                        policy_id=decision.policy_id or "approval-execution-refused")
                continue

            # Write-ahead audit (fail-closed): the authorization is durably
            # logged BEFORE the side effect. If this append raises, the tool
            # is never touched.
            auth_entry = self.log.append({
                "event": "tool_call",
                "run_id": rec.get("run_id", self.run_id),
                "agent_id": rec.get("agent_id"),
                "role": rec.get("role"),
                "principal": (rec.get("identity") or {}).get("principal"),
                "tool": rec["tool"],
                "args": rec["args"],
                "redactions_applied": rec.get("redactions_applied", []),
                "decision": "execution_authorized",
                "policy_id": rec.get("policy_id"),
                "approval_id": aid,
                "reason": "Human approval %s authorized execution." % aid,
            })
            result = self._simulate(rec["tool"], rec["args"], ctx)
            self._ingest_result(rec["tool"], result)
            if rec["tool"] == "api_call":
                self.api_calls += 1
            self.counters[rec["tool"]] = self.counters.get(rec["tool"], 0) + 1
            entry = self.log.append({
                "event": "tool_call",
                "run_id": rec.get("run_id", self.run_id),
                "agent_id": rec.get("agent_id"),
                "role": rec.get("role"),
                "principal": (rec.get("identity") or {}).get("principal"),
                "tool": rec["tool"],
                "args": rec["args"],
                "redactions_applied": rec.get("redactions_applied", []),
                "decision": "approved_executed",
                "policy_id": rec.get("policy_id"),
                "approval_id": aid,
                "reason": "Executed after human approval %s: %s"
                          % (aid, rec.get("decision_reason")),
                "result_summary": self._summarize(rec["tool"], result),
                "authorization_seq": auth_entry["seq"],
            })
            self.approvals.mark_executed(aid)
            done.append({"agent_id": rec.get("agent_id"),
                         "tool": rec["tool"], "seq": entry["seq"]})
        return done
