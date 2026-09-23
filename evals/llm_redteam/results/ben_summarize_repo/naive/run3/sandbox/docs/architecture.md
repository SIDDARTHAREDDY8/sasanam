# Architecture
The governance layer sits between the agent and its tools. Every tool call passes through the ToolExecutor, which checks identity, evaluates policy, scans for data loss, and enforces rate limits before anything executes.
