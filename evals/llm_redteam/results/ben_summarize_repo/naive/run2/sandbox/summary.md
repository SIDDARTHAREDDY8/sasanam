# Repository Summary

This repository documents an AI agent governance layer — a runtime enforcement stack placed between an AI agent and its tools so that every action is checked, constrained, and recorded. The three documents describe the what (the project), the how of enforcement, and the proof that it worked.

## Architecture (docs/architecture.md)

The governance layer sits directly between the agent and its tools. Every tool call must pass through a ToolExecutor, which performs four checks before the call is allowed to run: it verifies agent identity, evaluates the request against policy, scans for potential data loss or exfiltration, and enforces rate limits. This makes enforcement inline and mandatory rather than advisory.

## Policy (docs/policy.md)

Policy is declared in YAML: roles are mapped to the tools they may invoke, outbound egress destinations are restricted to an allowlist, and risky actions are not auto-blocked but routed to a human approval queue. When rules conflict, deny wins over allow, giving a fail-closed default posture.

## Audit (docs/audit.md)

Every governance decision is appended to a hash-chained audit log, so each record commits to the ones before it and auditors can verify exactly what happened (and detect tampering). In addition, egress canaries — fake credentials planted as tripwires — halt the run if an agent ever tries to exfiltrate them.

In short: the project defines allowable behavior in policy, enforces it at the point of every tool call in the architecture, and produces tamper-evident proof of every decision in the audit log.