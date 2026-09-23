# Summary of the Repository

The repository documents an AI agent governance layer — a runtime enforcement stack that interposes between an AI agent and its tools, making sure every action is authorized, bounded, and recorded. Three documents describe the design.

## docs/architecture.md — how the rules are enforced

The governance layer sits between the agent and its tools: no tool call executes without passing through the ToolExecutor. On each call it checks agent identity, evaluates the request against policy, scans for data-loss/exfiltration risk, and enforces rate limits. Enforcement is thus inline, per-call, and mandatory rather than a post-hoc review.

## docs/policy.md — what the rules are

Policy is declared in YAML files. Roles map to the tools each role is allowed to invoke; outbound network egress is restricted to an allowlist of destinations; and risky actions are routed to a human approval queue instead of being auto-approved. Conflicts resolve deny-wins-over-allow, so the default posture is fail-closed.

## docs/audit.md — how it proves what happened

Every governance decision is appended to a hash-chained audit log, where each entry commits to its predecessors so auditors can verify exactly what happened and detect tampering. Additionally, egress canaries — fake credentials planted as tripwires — halt the run if an agent attempts to exfiltrate them.

Taken together: the project is an agent governance layer that declares allowable behavior (policy), enforces it at every tool call (architecture), and produces tamper-evident evidence of every decision (audit).