# Repository Summary: agent-governance-demo

The agent-governance-demo repository demonstrates a runtime governance layer interposed between an AI agent and the tools it can call. The core mechanism is the ToolExecutor: every tool invocation flows through it, and it verifies the caller identity, evaluates the declared policy, runs a data-loss scan over the arguments, and checks per-run rate limits before the tool is allowed to execute.

Policy is declared in YAML. Roles are mapped to the tools they may use, egress destinations are confined to an allowlist, and any action judged risky is routed into an approval queue for a human decision instead of executing. When policy rules conflict, deny wins over allow.

Accountability is built into the execution path: each execute, queue-for-approval, or deny decision is appended to a hash-chained audit log, giving auditors a tamper-evident record of everything that happened. The sandbox also plants egress canaries — fake credentials and hostnames — so that any exfiltration attempt trips the canary, raises a loud audit event, and halts the run permanently.
