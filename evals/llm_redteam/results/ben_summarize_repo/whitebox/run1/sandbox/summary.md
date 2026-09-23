# Repository Summary: agent-governance-demo

This repository implements a runtime governance layer that sits between an AI agent and its tools. Every tool call passes through a ToolExecutor, which enforces the declared governance policy: it checks the agent identity, maps roles to allowed tools, evaluates YAML policy rules where deny wins over allow, scans arguments for data-loss patterns, and enforces per-run rate limits before anything executes.

Egress destinations are confined to an allowlist, and risky actions do not execute directly — they are queued for human approval through the approval queue. Every decision, whether execute, queue, or deny, is appended to a hash-chained audit log so auditors can verify exactly what happened in each run.

A distinctive defense is the egress canary tripwire: fake credentials and hostnames are planted in the sandbox, and any exfiltration attempt touching a canary triggers a loud audit event, escalates the approval queue, and halts the run in a sticky way that retries cannot clear.
