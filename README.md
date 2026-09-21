# Agent Governance Demo

A working, self-contained demonstration of a governance layer for AI agents. Every agent action flows through three checks before anything happens: it is attributed to an identity, evaluated against YAML policies, and written to a tamper-evident (hash-chained) action log. Actions the policy flags as risky are not executed; they wait in a file-based approval queue until a human approves or rejects them from the CLI, and the decision itself is logged. The demo scenario mirrors a small OSS-contribution pipeline (scout, triage, builder, publisher agents) but is fully synthetic: simulated tools, fake data, no network calls, no real credentials, and nothing read or written outside this project directory.

## Run it (3 commands)

From this directory:

```
python3 demo/run_demo.py
python3 demo/make_report.py
python3 -m gov.approve --latest list
```

1. `run_demo.py` runs the synthetic four-agent scenario, injects policy-triggering actions, resolves several queued approvals through the real CLI, and prints a narrative plus an audit summary.
2. `make_report.py` verifies the log's hash chain and writes a severity-ranked audit report (Markdown and HTML) to `reports/`.
3. `gov.approve --latest list` shows the approval queue so you can inspect (or manually decide) any items still pending.

## Architecture

```
  +------------------+       +--------------------+       +-------------------+
  | Agents           |       | Policy Engine      |       | Human approver    |
  | scout / triage / | ----> | policies/*.yaml    | ----> | python -m         |
  | builder /        |       | allow | deny |     |       |   gov.approve     |
  | publisher        |       | require_approval   |       |                   |
  +--------+---------+       +---------+----------+       +--------+----------+
           |                           |                           |
           v                           v                           v
  +--------+-------------------------------------------------------+---------+
  | ToolExecutor: simulated tools (read_file, write_file, delete_file,      |
  | api_call, http_post, send_email). Nothing real is ever touched.         |
  +--------+-------------------------------------------------------+---------+
           |
           v
  +---------------------+           +----------------------+
  | Action log          | <-------- | Approval queue       |
  | append-only JSONL,  |  decisions| file-based; approve / |
  | hash-chained        |  logged   | reject via CLI        |
  +---------------------+           +----------------------+
           |
           v
  +---------------------+
  | Audit report        |
  | demo/make_report.py |
  | Markdown + HTML     |
  +---------------------+
```

## Files

- `gov/identity.py` - `AgentIdentity`: agent_id, role, run_id, principal. Every action is attributed.
- `gov/log.py` - Append-only JSONL action log. Each entry hash-chains to the previous via SHA-256; `verify_chain()` replays the file and reports OK or the first broken entry.
- `gov/policy.py` - `PolicyEngine`: loads YAML policies and evaluates each action to allow / deny / require_approval with a reason.
- `gov/yamlmini.py` - Minimal YAML-subset parser (stdlib only) so policies stay readable YAML without dependencies.
- `gov/approvals.py` - File-based approval queue plus the `python -m gov.approve` CLI (list / approve / reject). Decisions are appended to the action log.
- `gov/executor.py` - Simulated tool layer. Every call goes identity -> policy check -> execute, deny, or queue -> log the outcome.
- `policies/default.yaml` - The default policy set: outbound sends need approval; deletes outside the run sandbox are denied; reads of secret-like paths are denied and flagged; writes outside the sandbox need approval; more than 5 external API calls per run need approval.
- `demo/run_demo.py` - The synthetic scenario: four agents do a plausible OSS-contribution run while triggering each policy, then a human resolves approvals through the real CLI.
- `demo/make_report.py` - Verifies the hash chain and generates the severity-ranked audit report (Markdown + HTML) with exact log entries cited as evidence.
- `runs/` - Generated per-run state: `actions.jsonl` (the log), `approvals.jsonl`, `sandbox/`, `quarantine/`.
- `reports/` - Generated audit reports.

## What this is NOT (yet)

- It is not connected to any real agent framework, repository, or inbox. All tools are simulated and all data is fake.
- The policy language is simple match rules, not a full policy engine (no time windows, no per-user roles, no policy versioning).
- The approval queue is file-based with a single implicit operator; there is no authentication, no multi-approver workflow, no notifications.
- The hash chain makes tampering evident, not impossible: there is no external anchoring, no signatures, and no protection against someone deleting the log file itself.
- It runs on one machine with no concurrency control; two writers to the same run directory could interleave log lines.
- There is no dashboard, no alerting, and no long-term storage story beyond the JSONL files.

These are deliberate demo boundaries. The point is to show the shape of the governance loop - attribute, check, log, approve - running for real, not to ship production infrastructure.
