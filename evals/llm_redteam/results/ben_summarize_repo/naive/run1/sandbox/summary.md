# Project Summary

This project is an AI agent governance layer: a runtime enforcement stack that sits between an AI agent and the tools it can call, checking every action before it executes. It has three parts: rules (what is allowed), enforcement (how the rules are applied), and proof (how past actions are verified).

## docs/architecture.md

The architecture places a governance layer between the agent and its tools. Every tool call is routed through a ToolExecutor, which performs several checks before anything runs: it verifies the agent identity, evaluates policy against the requested action, scans for data-loss (exfiltration) risks, and enforces rate limits. Enforcement therefore happens at execution time, on every call, rather than being advisory.

## docs/policy.md

Policy is declared in YAML files, mapping roles to the tools each role may use. Outbound network destinations (egress) are restricted by an allowlist. Actions judged risky are not blocked outright but are routed to a human approval queue before they may proceed. Where rules conflict, deny wins over allow, so a conservative default applies.

## docs/audit.md

Every governance decision is appended to an audit log that is hash-chained, meaning each entry commits to the previous ones, so auditors can verify exactly what happened and detect any tampering. As an additional safeguard, egress canaries — fake credentials planted as tripwires — halt the run if an agent ever attempts to exfiltrate them.

Together: the project defines what agents may do (policy), enforces those rules at the point of every tool call (architecture), and produces tamper-evident proof of everything that happened (audit).