# Agent Governance — policy enforcement, human approvals, tamper-evident audit for AI agents

**SYNTHETIC DEMONSTRATION.** Every tool is simulated, every byte stays on
this machine: no network calls, no real credentials, no real systems.
What *is* real: the enforcement pipeline. Every agent action flows
through identity verification → role allowlist → DLP → rate/volume
guards → a fail-closed policy engine → write-ahead audit logging, before
anything executes.

## Five-minute quickstart

```bash
pip install -e .                      # stdlib only; no dependencies

gov-demo                              # 1. run the 4-agent synthetic scenario
gov-report                            # 2. verify the log, write reports/audit-*.md|html
gov-verify runs/<latest>/actions.jsonl  # 3. offline chain verification (exit 0 = OK)

python3 tests/run_tests.py             # 4. red-team suite: 36 tests, all green
gov-policy-lint policies/default.yaml  # 5. lint the policy set
```

Then try the attack yourself:

```bash
gov-approve --latest list             # inspect the human approval queue
```

## What it enforces (all demonstrated, all tested)

| Control | Where | Test |
|---|---|---|
| Fail-closed policy engine (deny > require_approval > allow; default-deny) | `gov/policy.py` | `test_policy_config.py` |
| Executor-minted identities; role→tool least privilege | `gov/executor.py` | `test_privilege_escalation.py` |
| Credential/PII DLP blocks + redaction-before-log | `gov/dlp.py` | `test_injection_exfiltration.py` |
| HMAC-SHA256 chained log, key epochs, signed checkpoints, offline verify | `gov/log.py` | `test_log_integrity.py`, `test_new_controls.py` |
| Write-ahead audit: authorization logged before any side effect | `gov/executor.py` | `test_new_controls.py` |
| Input provenance / taint tracking, read-before-send correlation | `gov/executor.py` | `test_injection_exfiltration.py`, `test_new_controls.py` |
| Domain egress allowlist | `policies/default.yaml` | `test_injection_exfiltration.py` |
| Integrity-bound, expiring, separation-of-duty approvals | `gov/approvals.py` | `test_approval_abuse.py` |
| TOCTOU-safe approved execution (re-validate at execution time) | `gov/executor.py` | `test_approval_abuse.py` |
| Per-run rate, volume, repeated-call guards | `gov/executor.py` | `test_rate_limits.py` |
| Policy linter | `gov/policy_lint.py` | — (CLI) |

## Architecture

```
agents ──▶ ToolExecutor ──▶ identity minted? ──▶ role allowlist? ──▶ DLP clean?
              (simulated      (reject forged/       (least           (block creds,
               tools:           foreign ids)         privilege)        redact PII)
               read/write/
               delete/api/
               post/email)
                                │ pass
                                ▼
                        policy engine (deny ≻ require_approval ≻ allow,
                                       default-deny, taint + egress context)
                          ┌─────────┴──────────┐
                     allow/deny          require_approval
                          │                      │ (no execution)
                          ▼                      ▼
              write-ahead audit log ◀── approval queue (file-based)
              HMAC-chained JSONL     │   integrity digest · policy-hash pin
              + signed checkpoints   │   TTL expiry · SoD · preview
                          │          └── human: gov-approve list/approve/reject
                          ▼                    (decisions logged)
                    gov-verify / gov-report
```

## The demo scenario

`gov-demo` runs four agents (scout → triage → builder → publisher) through
a synthetic OSS-contribution pipeline. Along the way it exercises every
control: a prompt-injected ticket steers the support agent toward
exfiltration (denied by egress + DLP), a builder tries to write outside
the sandbox (quarantined for approval), high-volume API reads trip the
approval budget, and a human resolves the queue through the real CLI.
The run ends with a verified audit summary; `gov-report` turns the log
into a severity-ranked Markdown + HTML report under `reports/`.

## Red-team suite

`tests/` holds the harness plus six attack modules (`weaknesses-a.md`,
`weaknesses-b.md` record all 30 weaknesses the suite was built from).
Phase 2 baseline: 30 failing / 1 passing. After the Phase-3 build:
**36 tests, all passing** (`python3 tests/run_tests.py`). `BUILD_LOG.md`
records every batch, regression, and test correction.

## Files

- `gov/identity.py` — `AgentIdentity`; only `executor.mint_identity()` can
  create callable identities (`UnmintedIdentityError` otherwise).
- `gov/log.py` — HMAC-SHA256 chained JSONL, key epochs, signed
  checkpoints, offline verification. `GOV_LOG_KEY` sets the HMAC key;
  without it a documented dev key is used (zero integrity — the warning
  says so).
- `gov/dlp.py` — credential blockers + PII redaction + payload
  summarization, applied before policy evaluation and before logging.
- `gov/policy.py` — fail-closed engine: deny ≻ require_approval ≻ allow,
  default-deny, rule validation, `policy_hash`.
- `gov/policy_lint.py` — policy linter CLI.
- `gov/approvals.py` — approval queue + `gov-approve` CLI. Records bind
  args digest + policy hash; decisions are separation-of-duty checked,
  TTL-expired, and logged (including rejected attempts).
- `gov/executor.py` — the enforcement pipeline: identity, roles, DLP,
  guards, provenance/taint, egress, write-ahead logging, approvals,
  TOCTOU-safe execution.
- `gov/verify.py` — offline log verifier CLI (`gov-verify`).
- `policies/default.yaml` — the default policy set (v2, fail-closed).
- `demo/run_demo.py`, `demo/make_report.py` — scenario + audit reports.
- `THREAT_MODEL.md`, `REQUIREMENTS.md`, `research/` — design basis.
- `BUILD_LOG.md` — implementation journal.

## Honest limitations

- Tools are simulated: "execution" never leaves the process. The
  enforcement logic is real; the tool effects are not.
- Log integrity rests on `GOV_LOG_KEY` custody. The dev fallback is
  explicitly insecure; multi-epoch keyring verification is not built.
- Approved actions re-run from redacted/summarized args — large
  secret-bearing payloads don't round-trip byte-identically.
- No real LLM quarantine: "prompt injection" here is simulated tool
  output containing injected instructions, which is the correct layer
  for testing the *governance* response.
- Production hardening (Ed25519, Merkle proofs, public anchoring,
  OPA/Cedar) is deferred — see REQUIREMENTS.md.

## Threat-model mapping

Every control above traces to `THREAT_MODEL.md` (T1–T12) and
`REQUIREMENTS.md` (R1–R14, P0 product bar). The 30 red-team weaknesses
in `tests/weaknesses-a.md` / `tests/weaknesses-b.md` are each covered by
at least one passing test.
