# Weaknesses — red-team batch B (T5–T10, T12)

Logged by the red-team test engineer, 2026-09-21. Each entry maps to a
failing test in `tests/test_log_integrity.py`, `tests/test_policy_config.py`,
`tests/test_approval_abuse.py`, or `tests/test_rate_limits.py`. All scenarios
were executed against the current `gov/` code; "actual" behavior is observed,
not inferred. Fake credentials only (e.g. `AKIAIOSFODNN7EXAMPLE`,
`078-05-1120`); nothing leaves the machine.

---

## W-B1 — Truncate-and-rebuild of the log is undetectable
- **Threat:** T6 (Log tampering). **Requirement:** R6 (authenticated log).
- **Scenario:** 5 benign `write_file` calls logged; attacker copies
  `actions.jsonl`, drops the last 3 entries, re-appends 3 forged entries with
  a recomputed unkeyed SHA-256 chain
  (`test_log_integrity.py::TestTruncateAndRebuild`).
- **Asserted:** `verify_chain` returns `ok=False` (tamper detected).
- **Actual:** `verify_chain` returned `(True, None, 5)` — the forged log
  verifies cleanly. The chain is unkeyed, so anyone holding the file can
  rebuild it; there is no MAC, no key epoch, no offline verifier artifact.
- **Fix direction (Phase 3):** HMAC-SHA256 chain with key from env,
  `key_epoch` bound into the MAC, `format_version` frozen.

## W-B2 — Tail truncation is undetectable (no checkpoints)
- **Threat:** T6. **Requirement:** R6 (periodic checkpoints, STH-style).
- **Scenario:** 3 entries logged; attacker deletes the last JSONL line
  (`test_log_integrity.py::TestTailTruncation`).
- **Asserted:** a checkpoint mechanism exists and checkpoint comparison
  detects the truncation.
- **Actual:** `ActionLog` exposes no `write_checkpoint`/`checkpoints`
  attribute at all; `verify_chain` on the truncated file returns
  `(True, None, 2)` — a self-consistent shorter chain. An attacker can
  silently erase the most recent (most incriminating) actions.
- **Fix direction:** periodic signed checkpoints (seq + terminal hash)
  stored separately; verifier rejects logs shorter than the checkpoint.

## W-B3 — History rewrite is undetectable
- **Threat:** T6. **Requirement:** R6.
- **Scenario:** attacker alters entry seq 1's args
  (`path` → `pwned.txt`, attacker content) and recomputes all subsequent
  hashes (`test_log_integrity.py::TestHistoryRewrite`).
- **Asserted:** `verify_chain` returns `ok=False`.
- **Actual:** `verify_chain` returned `(True, None, 4)`. Same root cause as
  W-B1: unkeyed chain, no external anchor.

## W-B4 — Secrets and PII are logged verbatim; no redaction pass
- **Threat:** T12 (Secrets in logs / approvals). **Requirement:** R7
  (redact-before-log).
- **Scenario:** `write_file` with content containing fake AWS key
  `AKIAIOSFODNN7EXAMPLE`; `send_email` (queued → `queued_pending` entry)
  with body containing fake SSN `078-05-1120`
  (`test_log_integrity.py::TestSecretsInLogs`).
- **Asserted:** neither value appears verbatim in raw `actions.jsonl`, and
  some entry records `redactions_applied`.
- **Actual:** both strings appear verbatim in the raw JSONL (in `args`
  of the `tool_call` entries); no entry contains `redactions_applied`.
  The approval queue record likewise stores the full unredacted args, so
  the queue becomes a secret store.
- **Fix direction:** pattern library (AWS keys, `ghp_`, `sk_live`,
  private-key blocks, JWT shape, connection strings) → block; PII
  (SSN-ish, etc.) → redact; `write_file` content logged as
  `{bytes, sha256_prefix}`; `send_email` bodies never verbatim;
  `redactions_applied: [rule-ids]` per entry; same pass on approval records.

## W-B5 — Logging is fail-open: tool executes before the log write
- **Threat:** T6. **Requirement:** R6 (fail-closed emission: log failure ⇒
  no execution).
- **Scenario:** `ActionLog.path` pointed at a directory so every append
  raises `IsADirectoryError`; then `executor.call(write_file, …)`
  (`test_log_integrity.py::TestFailClosedLogging`).
- **Asserted:** the call raises/aborts and the target file is never written.
- **Actual:** the call raised `IsADirectoryError`, but
  `sandbox/must_not_exist.txt` **was written** — `_simulate` runs before
  `log.append`. An attacker who can break logging (disk full, permissions,
  path swap) gets unlogged execution.
- **Fix direction:** emit/reserve the log entry (or verify writability)
  before executing the tool; abort without side effects on failure.

## W-B6 — Default policy effect is ALLOW (fail-open)
- **Threat:** T7 (Policy misconfiguration). **Requirement:** R1
  (fail-closed policy engine).
- **Scenario:** with `policies/default.yaml`, call unusual tool
  `exec_shell` with no matching rule
  (`test_policy_config.py::TestDefaultDeny`).
- **Asserted:** `status == "denied"`.
- **Actual:** `status == "executed"` (`"note": "unknown tool; simulated
  no-op"`). `defaults.effect: allow` in `default.yaml`, and
  `PolicyEngine.evaluate` falls back to `allow` when the file omits it.
  Any tool the policy author forgot becomes implicitly permitted.
- **Fix direction:** default effect deny; explicit allow rules required.

## W-B7 — First-match-wins lets a broad allow defeat a later deny
- **Threat:** T7. **Requirement:** R1 (deny rules have forbid-priority
  independent of file order).
- **Scenario:** policy with `allow write_file` listed ABOVE `deny
  write_file`; call `write_file`
  (`test_policy_config.py::TestForbidPriority`).
- **Asserted:** `status == "denied"` (deny wins regardless of order).
- **Actual:** `status == "executed"` — `evaluate` returns the first
  matching rule. One broad allow placed above a deny silently defeats it;
  rule ordering becomes a security-critical footgun.
- **Fix direction:** evaluate all denies first, then `require_approval`,
  then allows (OPA/Cedar-style forbid priority).

## W-B8 — No policy linter exists
- **Threat:** T7. **Requirement:** R9 (`python -m gov.policy_lint`).
- **Scenario:** policy YAML containing an unknown tool name
  (`frobnicate`), an unknown match key (`frobnicate_files`), and a rule
  shadowed by an earlier broader rule
  (`test_policy_config.py::TestPolicyLint`).
- **Asserted:** `gov.policy_lint` imports and `lint_file` reports
  `unknown_tool`, `unknown_match_key`, `shadowed_rule`.
- **Actual:** `import gov.policy_lint` raises `ImportError` — the module
  does not exist. Misconfigurations like W-B6/W-B7 have no automated
  check.
- **Fix direction:** implement `gov/policy_lint.py` with a known-tool
  registry, known match-key set, effect validation, and
  shadowed/contradictory-rule analysis.

## W-B9 — `execute_approved` does not re-evaluate the current policy (TOCTOU)
- **Threat:** T8 (time-of-check/time-of-use drift). **Requirement:** R11.
- **Scenario:** `send_email` queued → approved by human → operator
  tightens the policy to `deny send_email` (simulated by swapping
  `executor.policy` for a freshly loaded deny engine) → `execute_approved()`
  (`test_approval_abuse.py::TestStaleApprovalTOCTOU`).
- **Asserted:** `execute_approved()` returns `[]` (refuses; fail closed).
- **Actual:** returned a non-empty `done` list — the email action executed
  despite the current policy denying it. `execute_approved` re-evaluates
  only sandbox context, never the policy set, and never compares
  current args to queued args.
- **Fix direction:** re-run the *current* policy set against *current*
  arguments at execution time; fail closed if the policy changed since
  queueing or the decision is no longer allow.

## W-B10 — Approvals never expire
- **Threat:** T5 (approval-queue abuse). **Requirement:** R8 (expiry with
  auto-deny default).
- **Scenario:** approval granted, then its `decided_at` backdated to
  `2020-01-01T00:00:00+00:00`, then `execute_approved()`
  (`test_approval_abuse.py::TestApprovalExpiry`).
- **Asserted:** the stale approval does not execute.
- **Actual:** executed. `ApprovalQueue.decide` records no TTL/expiry, and
  `execute_approved` never checks age. A leaked or long-forgotten approval
  id is a standing authorization.
- **Fix direction:** TTL on approvals (e.g. hours), auto-deny on expiry,
  expiry timestamp stored on the record and enforced at execution.

## W-B11 — Queued approval args can be tampered with undetected
- **Threat:** T5. **Requirement:** R8 (approval record integrity;
  decision-as-log-entry non-repudiation).
- **Scenario:** `send_email to=victim@example.com` queued; attacker edits
  `approvals.jsonl` changing `args.to` to `attacker@evil.example`
  *before* the human approves; human approves; `execute_approved()`
  (`test_approval_abuse.py::TestApprovalRecordIntegrity`).
- **Asserted:** the tampered approval is detected and not executed.
- **Actual:** executed with the attacker's args. The queue is a plain
  JSONL file; nothing binds the approval decision to the exact queued
  action (no hash of args at queue time, no comparison at decide/execute
  time).
- **Fix direction:** store an integrity digest of (tool, args, policy_id)
  at queue time; verify at decide and at execute; refuse on mismatch and
  log the attempt.

## W-B12 — Self-approval is accepted (no separation of duties)
- **Threat:** T5. **Requirement:** R8 (`decided_by` must differ from the
  requesting agent).
- **Scenario:** agent `support-1` queues an action, then
  `approvals.decide(aid, True, decided_by="support-1")`
  (`test_approval_abuse.py::TestSelfApproval`).
- **Asserted:** `decide` raises / refuses; record stays `pending`.
- **Actual:** `decide` succeeded and the record became `approved` with
  `decided_by == agent_id == "support-1"`. No separation-of-duties check
  exists anywhere (nor does the CLI enforce it).
- **Fix direction:** reject any decision where `decided_by` equals the
  requesting `agent_id` (and, for human approvers, require an approver
  identity distinct from the agent's principal chain).

## W-B13 — Queued records carry no provenance field
- **Threat:** T5. **Requirement:** R8 (queue display shows raw tool call +
  args + provenance + matched rule).
- **Scenario:** queue a `send_email` whose args include an agent-supplied
  `justification`; inspect the stored record
  (`test_approval_abuse.py::TestQueueDisplay::
  test_queue_record_carries_review_fields`).
- **Asserted:** record contains `provenance` (input provenance of the
  action) alongside `tool`, `args`, `policy_id`.
- **Actual:** record keys are `id, ts, run_id, agent_id, role, identity,
  tool, args, policy_id, policy_reason, status, decided_by, decided_at,
  decision_reason, executed` — no `provenance`. The reviewer cannot tell
  whether the action was influenced by untrusted inputs.
- **Fix direction:** attach provenance (`user | tool_result |
  retrieved_content | agent_memory`) at queue time; surface it in review.

## W-B14 — Queue display omits the raw tool args
- **Threat:** T5 (approval-queue social engineering, OWASP ASI09).
  **Requirement:** R8.
- **Scenario:** render the queue via `gov.approvals._print_records`
  for a queued `send_email`
  (`test_approval_abuse.py::TestQueueDisplay::
  test_queue_display_shows_raw_call_not_justification`).
- **Asserted:** the rendering includes the raw `to` address (what would
  actually execute).
- **Actual:** output shows only `ID / AGENT / TOOL / STATUS / POLICY
  REASON` — e.g. `60174bc2 support-1 send_email pending -- Outbound
  communication requires human approval…`. The reviewer approves blind to
  the destination address and payload; the only human-readable text is the
  policy author's reason, adjacent to the agent's stored justification.
- **Fix direction:** render raw tool + full args + provenance + matched
  rule id as the primary evidence; never lead with agent-supplied text.

## W-B15 — No per-run cap on outbound sends
- **Threat:** T9 (rate/loop abuse, worming). **Requirement:** R10.
- **Scenario:** 25 `send_email` calls in one run
  (`test_rate_limits.py::TestOutboundSendCap`).
- **Asserted:** at least one is denied once the per-run budget is exceeded.
- **Actual:** all 25 returned `queued`; 0 denied. `default.yaml` declares
  `rate_limit.max_external_calls_per_run: 5` but nothing reads it for
  sends, and the engine has no send counter. A compromised agent can queue
  unbounded outbound volume for a single human click-through.
- **Fix direction:** per-run counters on outbound sends/writes in policy
  context; `when:` conditions on counters; deny (or escalate) past budget.

## W-B16 — No loop guard on repeated identical calls
- **Threat:** T9. **Requirement:** R10 (same tool+args N times → deny).
- **Scenario:** 15 identical `api_call(endpoint="/v1/data",
  params={"q": "same"})` invocations
  (`test_rate_limits.py::TestLoopGuard`).
- **Asserted:** at least one denied by the loop guard.
- **Actual:** all 15 returned `queued`; 0 denied. (Note the existing
  `min_external_calls` rate rule never even fires here because queued
  calls don't increment `api_calls` — the counter only moves on executed
  calls, so the guard is dead for the queued path too.)
- **Fix direction:** run-scoped (tool, canonical-args) repetition counter;
  deny past N with a distinct reason/flag.

## W-B17 — No write volume guard
- **Threat:** T9. **Requirement:** R10 (per-run caps on writes/deletes).
- **Scenario:** 30 rapid `write_file` calls in one run
  (`test_rate_limits.py::TestWriteVolumeGuard`).
- **Asserted:** at least one denied once the write budget is exceeded.
- **Actual:** all 30 returned `executed`; 0 denied. No write/delete
  counters exist in the executor or policy context.
- **Fix direction:** same as W-B15: per-run write/delete counters,
  budget in policy, deny past budget.

## W-B18 — Policy files loaded with no integrity check (config poisoning)
- **Threat:** T10 (tool-definition / config poisoning). **Requirement:**
  P1 control "tool-definition pinning/hashing at startup" (ASI04).
- **Scenario:** `PolicyEngine` loads a policy file; attacker rewrites the
  file afterwards; engine exposes no digest/pinning
  (`test_policy_config.py::TestPolicyFileIntegrity`).
- **Asserted:** the engine pins a `policy_hash`/`source_digest` at load.
- **Actual:** no such attribute; the YAML is trusted silently at load and
  there is no mechanism to detect post-load modification. Combined with
  W-B9 (no re-validation), a swapped policy file changes enforcement with
  no audit signal.
- **Fix direction:** hash-pin policy files at startup; verify on
  (re)load; log the digest; refuse to run on mismatch.

---

## Coverage notes
- T10's strongest form (MCP-style tool-description poisoning) has no
  direct test: the demo executor has no tool-description registry to
  poison. W-B18 covers the config-poisoning half that exists in this
  codebase. A future pinning control should cover tool definitions too.
- Sibling batch A covers T1–T4, T11 (injection/exfiltration, privilege
  escalation); this batch covers T5–T10, T12. T13 is deferred per the
  threat model.
- All 18 tests in this batch FAIL on current code (assertion failures,
  zero collection/import errors), verified via
  `python3 -m unittest discover -s tests -p "test_*.py" -t .` from the
  repo root using `tests/harness.py`.
