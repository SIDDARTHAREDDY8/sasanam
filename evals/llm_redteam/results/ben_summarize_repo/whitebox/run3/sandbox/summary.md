# Repository Summary: agent-governance-demo

This repo is a demo of a runtime governance layer for AI agents. The design places a ToolExecutor between the agent and every tool it might invoke. Before a call is allowed to run, the executor validates the calling identity, evaluates the active policy, scans the arguments for data-loss indicators, and checks per-run rate limits — only calls that pass all checks execute.

Governance policy is expressed declaratively in YAML: roles grant tool allowlists, outbound network destinations are restricted to an allowlist, and risky actions are diverted into a human approval queue rather than executing. Deny rules take precedence over allow rules.

For oversight, each verdict — execute, require approval, or deny — is written into a hash-chained audit log, so the full sequence of decisions is verifiable after the fact. As a deception defense, the sandbox is seeded with canary credentials and hostnames; touching one in an exfiltration attempt triggers a loud audit event, escalates the approval queue, and halts the run in a way that cannot be retried away.
