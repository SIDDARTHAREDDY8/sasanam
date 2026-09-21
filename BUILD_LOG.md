# BUILD_LOG — agent-governance Phase 3 implementation

SYNTHETIC PROJECT. All runs are local simulations; no real systems,
credentials, or network activity are involved.

## Baseline (recorded from Phase 2 red-team, 2026-09-21)

- 31 tests across 6 red-team modules, **30 failing / 1 passing** on the
  weak baseline. The failures were the specification: each asserted a
  control that did not exist.
- NOTE: the untouched Phase-2 baseline was **not personally re-run**
  during Phase 3. The "30 failing / 1 passing" figure is the recorded
  Phase-2 result, carried forward on trust. No claim is made here of a
  fresh baseline re-run.
- Initial demo (Phase 1): 23 log entries, 7 findings, valid pre-tamper
  chain, detected historical tampering. Reports labeled
  "SYNTHETIC DEMONSTRATION — no real systems were inspected."

## Batch 1 — gov/log.py: HMAC-authenticated log (2026-09-21)

Replaced the unkeyed SHA-256 chain with:
- HMAC-SHA256 per-entry MACs (`GOV_LOG_KEY`, optional `GOV_LOG_KEY_EPOCH`),
  key epoch bound into every MAC and stored on entries/checkpoints.
- Signed checkpoints (`checkpoints.jsonl`) after every append; the
  verifier requires the log to reach the newest checkpoint → tail
  truncation detected.
- Offline `_verify()` / `verify_chain()` / `python -m gov.verify`:
  format-version pin, chain links, entry MACs, checkpoint MAC,
  truncation check. Fail-closed on any mismatch.
- Public dev-key fallback with a stderr warning (zero integrity against
  anyone who read the source; documented as such).
- Legacy unkeyed `_entry_hash` retained ONLY as the documented attacker
  primitive for red-team tests.

Follow-up fix (same day): `entry.update(event)` could overwrite reserved
chain metadata (`seq`, `prev_hash`, `hash`, `format_version`,
`key_epoch`). Now the event is applied first and reserved fields are
forced afterwards; covered by
`test_new_controls.TestReservedLogMetadata`.

## Batch 2 — gov/dlp.py: credential + PII DLP (2026-09-21)

New module, enforced in the executor BEFORE policy evaluation:
- Blocks: AWS keys, GitHub tokens, Stripe keys, private-key headers,
  JWTs, Slack tokens, Google API keys, DB connection strings,
  high-entropy strings near credential keywords.
- Redacts: SSNs, emails, card numbers (Luhn), phone numbers; payload
  fields (`write_file.content`, `send_email.body`, `http_post.payload`)
  are summarized (bytes + SHA-256 prefix) in stored args.
- Design tension (accepted): audit-routing fields (email recipients) stay
  readable so approvals remain reviewable; large secret-bearing payloads
  are summarized rather than stored verbatim, so approved actions are
  re-simulated from the REDACTED record. Documented in REQUIREMENTS.md
  as a known limitation of the synthetic tool layer.

## Batch 3 — gov/policy.py: fail-closed engine (2026-09-21)

- Evaluation order: all `deny` rules → all `require_approval` →
  all `allow`; no match → `default_deny` (was default-allow).
- `policy_hash` (SHA-256 of the normalized config) exposed for
  approval pinning.
- Rule validation rejects unknown match keys, unknown tools, invalid
  effects (fail-closed on config error).
- Role→tool least-privilege map; executor enforces before evaluation.
- New matchers: `path_outside_sandbox`, `domain_allowlisted`,
  `carries_read_content`, `source_untrusted`, `min_external_calls`,
  generic `when` conditions.
- `gov/policy_lint.py`: CLI linter (unknown tools/keys, bad effects,
  shadowed and contradictory rules).

## Batch 4 — gov/executor.py: enforcement pipeline (2026-09-21)

- `mint_identity()` is the ONLY way to obtain a callable identity;
  `call()` rejects unminted/foreign-run/role-mismatched identities.
- Order per call: identity → role allowlist → DLP → loop guard →
  volume guards → policy evaluation → log → execute/deny/queue.
- Provenance: `read_file`/`api_call` results taint the run
  (`source_untrusted`); read content is fingerprinted for
  `carries_read_content` correlation.
- Approvals: integrity digest (`record_digest`), policy-hash pinning,
  TTL expiry, self-approval (SoD) rejection, human-readable preview,
  delegation-framing detection, decision-attempt logging.
- `execute_approved()` re-validates at execution time: expiry →
  integrity → policy staleness → fresh policy evaluation (TOCTOU).
- **Fail-closed logging fix (write-ahead):** the allow path previously
  called `_simulate()` BEFORE `log.append()` — a log outage meant an
  unlogged side effect. Now an `execution_authorized` entry is durably
  appended BEFORE the tool runs; the `allowed_executed` /
  `approved_executed` completion entry (with `result_summary` and
  `authorization_seq`) follows. If the authorization append raises, the
  tool is never touched. `_ensure_log_writable()` probe removed as
  redundant. Same pattern in `execute_approved()`.
- Queued results now include `policy_id`.

## Batch 5 — gov/approvals.py rewrite (2026-09-21)

- Records carry: `args_digest`, `policy_hash`, `preview`, `provenance`,
  `redactions_applied`, `delegation_attempted`, TTL via `decided_at`.
- `record_digest()` exported for executor integrity checks.
- `decide()` enforces separation of duties and logs rejected decision
  *attempts* (unknown id, self-approval, non-pending) as
  `approval_decision_attempt` entries before raising.
- `_rewrite()` accepts a record list (legacy contract) or a transform
  function.
- CLI renders raw tool+args + provenance + rule id first; the agent's
  justification is labeled UNVERIFIED and never leads.

## Batch 6 — policies/default.yaml v2 (2026-09-21)

Fail-closed defaults: `deny-egress-unallowlisted`,
`deny-tainted-delete`, quarantine for outside-sandbox writes,
`approval-read-before-send` (ordered before the generic
`approval-tainted-action` so the specific flag survives), approval TTL
24h, per-run budgets, egress allowlist
(`synthetic.local`, `localhost`, `127.0.0.1`).

## Test corrections (2026-09-21) — tests changed, not product

1. `test_secrets_redacted_in_log` asserted "queued" for the exact call
   `test_write_secrets_outside_sandbox_denied` asserts "denied" on.
   Contradictory preconditions; corrected to "denied" (DLP block) while
   keeping the redaction assertion. The product behavior was already
   correct.
2. `test_injection_driven_exfil_lacks_provenance_flag` → renamed to
   `test_injection_driven_exfil_blocked_with_provenance`: the R4
   egress-deny control (required by W-A3) also blocks this scenario's
   `attacker@evil.example` send, so "queued" was unachievable. The test
   now asserts DENIED + provenance markers on the denied entry. The
   queued-with-provenance path is covered by the approval-queue tests on
   allowlisted domains.
3. `test_approval_abuse` helpers/hardcoded recipients moved from
   `*@example.com` to `*@synthetic.local`: those tests exercise queue
   mechanics, not egress; non-allowlisted domains are correctly denied.

## Harness/demo migration (2026-09-21)

- `tests/harness.py`: identities now minted via
  `executor.mint_identity()`; docstring updated (allowlist enforced).
- `demo/run_demo.py`: identities minted via the executor; unused
  `AgentIdentity` import dropped.

## Batch 7 — new regression tests (2026-09-21)

`tests/test_new_controls.py` (5 tests): reserved-metadata forgery,
wrong-key verification failure, tail-truncation detection, log-outage
blocks side effect, read-before-send correlation with
`read_before_send` flag. Suite: **36 tests, all passing.**

## Deferred / known limitations

- No multi-epoch keyring: verification uses the active key; genuine
  rotation across epochs is visible (epoch is logged) but old-epoch
  entries need the old key supplied out-of-band.
- `write-ahead` doubles entries per executed call
  (`execution_authorized` + `allowed_executed`/`approved_executed`).
- Approved actions re-simulate from redacted/summarized args; large
  secret-bearing payloads cannot round-trip byte-identically.
- `decide()` logs the decision AFTER the queue-file rewrite (tool-call
  paths are write-ahead; the decision record itself is not).
- Production hardening deferred per REQUIREMENTS.md: Ed25519,
  Merkle proofs, public anchoring, real-LLM quarantine, OPA/Cedar.

## Batch 8 — real bugs found by the build itself (2026-09-21)

1. **Approval decisions were never persisted.** `decide()` mutated the
   `target` dict from `self.all()`, but `all()` re-parses from disk, so
   the subsequent `_rewrite(lambda records: records)` wrote the
   unchanged records back. Decisions were logged and printed as
   successful, yet the queue file stayed `pending` — approved actions
   silently never executed. Fixed by splicing the mutated record into
   the rewrite. Regression test:
   `TestApprovalLifecycleEndToEnd.test_approve_persists_and_executes`
   (queue → decide persists → execute_approved runs exactly once).
2. **Read-before-send correlation missed excerpts.** `_carries_read_content`
   required the ENTIRE read content to appear verbatim in the payload, so
   exfiltrating part of a larger file evaded the rule. Rewrote to match
   any 32-char run of the outbound payload's raw string values against
   read contents. Covered by the existing read-before-send test and the
   attack scenario.

## Batch 9 — attack scenario + packaging (2026-09-21)

- `demo/attack_scenario.py` (`gov-attack-demo`): a realistic indirect
  prompt-injection campaign by a tainted support agent — exfil to an
  attacker domain (denied: egress allowlist), exfil to a plausible
  internal recipient (quarantined: read-before-send), self-approval of
  the queued action (rejected: separation of duties, attempt logged),
  deletion of the audit log (denied: least privilege), post-run log
  tampering (detected by HMAC verification). All runs under
  `runs/attack-*`.
- `pyproject.toml`: stdlib-only install, console scripts
  (`gov-demo`, `gov-attack-demo`, `gov-approve`, `gov-verify`,
  `gov-policy-lint`, `gov-report`).
- README rewritten for the hardened product: five-minute quickstart,
  control table, honest limitations, threat-model mapping.
- Reports regenerated from the latest demo run
  (`reports/demo-20260921-153035_audit_report.{md,html}`); chain OK,
  34 entries, 8 findings. All reports labeled synthetic.

## Final test state (2026-09-21)

**37 tests, all passing** (`python3 tests/run_tests.py`):
31 original red-team tests + 6 new-control tests.

## Push record

- 2026-09-21: pushed commit `0a09a18beb43` to
  `SIDDARTHAREDDY8/agent-governance-demo@main` (parent `df786304051c`),
  DCO-signed. API-verified: repo private, branch SHA moved, 57 files,
  new modules present, stale `gov/__pycache__/*.pyc` deleted, existing
  branch files preserved.

## 2026-09-21T15:46:22Z — TEAM POLICY UX: linter v2 + simulator + context snapshots

- Extended `gov/policy_lint.py`: unknown-role detection (against the
  policy's own roles section, never an invented registry),
  unreachable-rule detection (tool in no role's allowlist, or only
  unknown roles in match), overly-broad allows (empty match = error,
  tool-only match on dangerous tools = warning, else info), missing
  deny coverage for send_email/http_post/delete_file, duplicate rule
  ids, malformed match blocks, mutually-covering contradictions
  (conservative implication check in the correct direction, so normal
  forbid-priority layering is NOT flagged), plus a shadowed-rule check
  with fail-closed coverage semantics. Findings carry severity
  (error/warning/info) and the CLI prints a summary count.
- Fixed the linter's coverage/subsumption logic: the original
  direction produced false shadow/contradiction positives on the
  shipped default policy; default.yaml now lints with only 2 info
  notes (tool-only allows for read_file/api_call).
- `gov/executor.py` now attaches a `policy_context` snapshot
  (path_outside_sandbox, domain_allowlisted, carries_read_content,
  source_untrusted, counters) to every policy decision entry — the
  decision-input side of an OPA-style (input, result) decision log —
  so offline replay needs no re-execution.
- New `gov/simulator.py` (CLI: `python -m gov.simulator <policy.yaml>
  --latest|--all|--rundir`): replays candidate policies over recorded
  `runs/*/actions.jsonl`, classifies diffs by severity (critical =
  weakened deny, high = breaking change, medium = approval changes,
  low = approval removed, info = indeterminate/rule-changed-only),
  never writes to source logs, marks context-incomplete replays as
  indeterminate and excludes them from counts, and writes
  timestamped JSON + Markdown reports to `reports/`.
- New `tests/test_policy_ux_lint.py`: 14 focused linter tests.
- Full suite: 69 tests, all passing (`python3 tests/run_tests.py`).
  Note: test YAML uses block-style mappings because the project's
  yamlmini does not parse flow-style `{...}` mappings (flagged by the
  linter as `invalid_match` when encountered in the wild).

## 2026-09-21 16:05 UTC — TEAM ENFORCEMENT: key management (gov/keys.py) done + tested
- Implemented `gov/keys.py`: epoch-bound HMAC key lifecycle for the action log. KeyRing with file backend (JSON keyring, 0600 enforced, refuses world-readable files) and env backend (GOV_LOG_KEY/_EPOCH/_ARCHIVE); `activate()` is the documented integration point that puts keys under unmodified `gov/log.py`.
- Fail-closed production path: `require_key()` raises NoKeyConfiguredError when nothing is configured; dev key only with explicit GOV_DEV_KEYS=1 + loud stderr warning. No silent fallback.
- Rotation ceremony `rotate_keyring()`: verifies the existing log with the OLD ring first (refuses on tamper), then rotates; old keys retained as `retired` so history stays verifiable. `KeyRing.verify_log()` replays mixed-epoch logs selecting the HMAC key per entry (gov/log.py's own verifier is single-key and cannot do this).
- Fixed a real bug found by tests: file-backend key round-trip corrupted keys (hex-of-hex in to_dict/from_dict); caught because rotation-ceremony tests failed — the tampered-log test had been passing vacuously (masked by the bug).
- `tests/test_keys.py`: 18 tests, all green. Full suite 69 tests green (3 consecutive runs). NOTE: `tests/test_policy_ux_lint.py` (sibling agent's in-flight work, untracked) flaked 5→1→0 failures across runs while its author was editing; unrelated to this work, left untouched.

## 2026-09-21 15:48 UTC — TEAM MEDIATION: complete-mediation adapters (v1) done + tested
- New `gov/adapters/` package: every agent tool call is mediated through `gov.executor.ToolExecutor` before any underlying implementation runs. No executor/policy modules modified (other teams' ownership respected).
- `gov/adapters/core.py`: `GovernedBinding(executor, identity, tool_map=None)` pins executor + minted identity + immutable (`MappingProxyType`) framework→native tool-name mapping. Unknown/unregistered names fail closed via `UnregisteredToolError` before the executor is touched. `binding.call()` returns the executor dict on `"executed"`; denied → `ToolDeniedError`, queued → `ApprovalRequiredError` (or raw dicts with `on_denied/on_queued="return"`). `normalize_result()` renders deterministic JSON.
- `gov/adapters/generic.py`: `governed(binding, tool=None, *, on_denied, on_queued, run_body=False)` decorator (defaults tool name to `__name__`; keyword-only calls; `__wrapped__` deleted so no raw handle leaks) and `governed_registry(binding)` context manager (registration validated against the binding at register time, sealed on exit, dispatch always mediated). Default: decorated body never runs (executor simulation is the single side effect); `run_body=True` is an explicit, documented split authorization/execution boundary.
- `gov/adapters/langchain_tools.py`: `make_governed_tool(...)` builds a `StructuredTool` subclass whose `_run`/`_arun` route through the binding; `func=None`/`coroutine=None` so no raw callable exists. Verified against langchain-core 1.6.3: `invoke→run→_run` and `ainvoke→arun→_arun` funnel pinned by `test_funnel_assumption_pinned` (fails loudly on framework drift).
- `gov/adapters/mcp_adapter.py`: `GovernedMCPClient(binding, session)` exposes only async `call_tool(name, arguments, **session_kwargs)` — session name-mangled, no public accessor; the underlying `ClientSession.call_tool` runs only after executor `"executed"`; denials/queued/unregistered never touch the session. Split authorization/execution documented (executor authorizes+logs, real server executes). Ships `DeterministicFakeSession` test double (no network).
- `gov/adapters/openai_loop.py`: pure `run_tool_loop(binding, messages, respond, max_iterations=8, ...)` — no API calls; `respond` is caller-supplied (scripted in tests). `parse_tool_calls` strictly validates (JSON-object args, unique non-empty ids, `type=="function"`); malformed/duplicate/unknown shapes fail closed before dispatch. Denied stops the loop by default; `on_denied="return"` feeds the denial back as a `tool` message.
- `gov/adapters/README.md`: exact public signatures, 5-line quickstart, and four honestly-documented residual limitations (split auth/execution, deployment-not-code boundary for pre-held raw references, explicit name mapping, human-in-the-loop approvals).
- New tests: `test_adapters_generic.py` (24), `test_adapters_langchain.py` (11), `test_adapters_mcp.py` (11), `test_adapters_openai.py` (19) — 65 total, incl. bypass-attempt tests for every adapter (raw function handles, `__wrapped__` stripping, raw MCP session, direct `_run`, malformed tool_calls, post-seal registration).
- Full suite: 138 tests, all passing, 2 consecutive clean runs (`python3 tests/run_tests.py`). One transient mid-run failure (59 tests, 40 errors) was observed while sibling teams were editing shared `gov/` modules concurrently; reruns before and after were fully green — unrelated to this work, no shared files touched.

## 2026-09-21 15:52 UTC — TEAM MEDIATION: note on suite state (no action taken)
- A later full-suite run showed 176 tests with 2 failures + 4 errors, all in `tests/test_sandbox.py` (sandboxing team's in-flight work: `gov/sandbox.py` is their new untracked module). None are in adapter tests or caused by adapter code — the 65 adapter tests pass standalone (`OK`), and two earlier full runs were 138/138 green before the sandbox tests landed. Left untouched per team ownership; flagging for the coordinator.

## 2026-09-21 15:58 UTC — TEAM MEDIATION: hardening batch (streaming, retries, kwarg safety)
- LangChain: added `test_stream_path_mediated` (`Runnable.stream()` funnels through invoke→_run; exactly one mediated call) and `test_retry_attempts_each_mediated` (`with_retry(stop_after_attempt=2)` on a denied tool: both attempts independently mediated and audited, 2 denial log entries — retries cannot bypass).
- Closed a dead-code mistake honestly: a reserved-kwarg guard added to `GovernedBinding.call` was unreachable (Python binds `on_denied`/`on_queued`/`framework_tool` as named params before `**kwargs`). Reverted it; the real behavior is documented + tested instead — a tool argument colliding with a control name raises loud `TypeError` (duplicate keyword), never silently misroutes. None of the six native tools have such argument names.
- README: documented the MCP phantom-simulation consequence (on `"executed"` the executor also runs its sandbox simulation in addition to the server executing), the framing-kwarg pass-through (`justification`/`on_behalf_of`/`delegated_by` are untrusted metadata per `gov/executor.py`), and the control-kwarg collision rule.
- Adapter tests: 68/68 green. `__pycache__` cleaned.

## 2026-09-21 16:05 UTC — TEAM ADVERSARY: continuous red-team wave 2, ship-gate green 144/144

Standing up as the permanent red team per founder directive (continuous operation:
a green suite means invent harder attacks, not stand down).

What was built:
- `evals/run_evals.py` — 12 situations x 4 provisional adapters x 3 privilege
  levels = 144 cells, all deterministic scripted playbooks against real gov code.
  SCORE: 144/144 (100%), SHIP-GATE GREEN.
- `evals/matrix.py` — single source of truth for all expectations (threat IDs +
  research citations per situation). `SITUATION_MATRIX.md` is GENERATED from it
  (`evals/generate_matrix_md.py`) so doc and harness cannot drift.
- `evals/provisional_adapters.py` + `evals/ADAPTER_INTERFACE.md` — provisional
  shims; reconciliation mapping against the real `gov.adapters.GovernedBinding`
  API recorded (real API landed mid-session; `gov/adapters/README.md` still
  missing, reconciliation unsigned).
- `evals/FINDINGS.md` — 6 findings (F1/F2 HIGH, F3/F4 MEDIUM, F5 LOW, F6 residual).
- `tests/test_adversary_matrix.py` — 4 wiring-integrity tests, all pass.

New attacks invented this wave (all verified by execution):
- sit8 DLP encoding bypass: raw AWS key blocked (positive control), hex-encoded
  key EXECUTES via api_call (F2 HIGH — DLP is syntactic).
- sit9 delegation confusion: on_behalf_of='ceo' grants nothing; flagged as
  evidence (positive control, T3).
- sit10 approval-ID binding: approving benign A by id executes only A; malicious
  sibling B stays pending (positive control, T8).
- sit11 laundering campaign: poisoned read -> out-of-band dead-drop -> fresh-run
  exfil. Send still queues, but taint AND read_before_send flag are laundered
  (F3 MEDIUM).
- sit12 per-run pacing: 12 api_calls across 3 runs, 0 queued (F5 LOW — no
  cross-run velocity tracking).

Self-inflicted bugs fixed (adversary harness, not gov):
- RecursionError in LangChain/OpenAI-loop shims (shim called adapter.call which
  routed back through the shim); shims now call the base canonical entry.
- Wave-2 code appended AFTER `if __name__ == "__main__": sys.exit(main())` —
  sys.exit() skipped it in script mode (passed on import, failed as script).
  Root-caused via DEBUG print; entry-point block moved to end of file.

Environment notes (not adversary findings, reported to coordinator):
- `gov/approvals.py` was unimportable mid-session (another team's half-landed
  risk-scoring mixin, NameError); repaired by owning team before wave-2 run.
- `python3 tests/run_tests.py`: 179 tests, my 4 pass; 2 failures in
  tests/test_sandbox.py (another team's: install-wiring expects executed got
  denied; grandchild SIGTERM survival — flaky across runs, concurrent edits
  ongoing in gov/).
- Full suite result is NOT green for reasons outside adversary scope.

Next attacks queued (not yet built): tool-output steganography in read_file
results, approval-preview rendering tricks, multi-agent auction/bidding
collusion, policy-simulator vs engine divergence, log-forgery via justification
fields.

## 2026-09-21 16:40 UTC — TEAM ENFORCEMENT: subprocess sandbox (gov/sandbox.py) done + adversarially tested
- Implemented `gov/sandbox.py`: contained child-process execution. shell=False argv-only; fresh temp jail per call; scrubbed env (allowlist); new process session + killpg SIGKILL on wall-clock timeout; bounded chunked stdout/stderr draining (no unbounded communicate()); POSIX rlimits (CPU/AS/FSIZE/NOFILE/NPROC); network namespace via unshare(CLONE_NEWNET) when available with honest `network_isolated` reporting.
- `SandboxedToolBackend`: drop-in `_simulate` replacement with identical result shapes; file ops run in child processes; path authority enforced parent-side (`_checked_target` resolves symlinks, rejects `..`/absolute escapes). `install(executor)` wires it with zero edits to gov/executor.py (verified end-to-end through the real governance pipeline).
- REAL BUG FOUND BY ADVERSARIAL TESTING: parent blocked forever in `read()` after `select()` fired when a grandchild held the pipe open — the wall-clock deadline was not airtight. Fixed by setting pipe fds O_NONBLOCK (read can never block; BlockingIOError treated as spurious wakeup). Root-caused via faulthandler + minimal repros.
- Honest limitation documented in module + tests: temp cwd is NOT a chroot — a child that chdir('..')s CAN write relative paths outside its jail (test asserts this). Filesystem authority therefore lives parent-side in the backend. Kill-group does not cover double-fork daemonizers.
- `tests/test_sandbox.py`: 38 tests green (shell injection inert, env scrub incl. /proc/self/environ, hang+grandchild kill, output bombs truncated, MemoryError/RLIMIT_FSIZE/NPROC containment, netns egress denied incl. loopback, symlink/`..` escape rejection, backend contract, install wiring).
- Full repo suite: 197 tests OK (12 skipped). NOTE: shared tree — sibling agents actively editing (gov/approvals.py transiently broke `import gov` mid-refactor at ~16:20 UTC; self-healed). Did not touch their files.

## 2026-09-21T15:57:14Z — TEAM POLICY UX: F4 queue-anomaly detection (approval fatigue)

Adversary finding F4 (MEDIUM): no approval-fatigue / queue-anomaly detection — an attacker floods the queue with low-risk approvals to hide one malicious request (OWASP ASI09).

What was added (gov/approvals.py, advisory-only layer):
- `queue_anomalies(records=None, now=None)` — read-only detection returning typed anomaly dicts; never modifies the queue, never auto-decides:
  - `fatigue_burst`: >= 5 pending items from one agent inside a 10-minute trailing window (across tools — the shape the per-(agent,tool) flood threshold misses), with low-risk-cover count;
  - `rate_spike`: trailing-window arrivals >= 3x the run's median baseline rate (zeros included, min 4 arrivals); no baseline history => no signal;
  - `unusual_tool_mix`: a tool >= 50% of the pending queue while < 20% of run history (>= 4 pending items).
- Advisory escalation: anomalous items get +15 risk (one-directional, never lowers), surfaced in the risk-factors line; `maybe_auto_approve` therefore holds them back under any sane cap (tested: score 15 items clear a cap of 20, anomaly-bumped 25-30 do not).
- `batch_decide` fail-closed guard extended: anomaly-cluster items require per-item `--confirm-risky` like flood-suspect items; batch aborts are logged.
- CLI: `gov.approve list` prints a FATIGUE WARNING banner + per-item `| ANOMALY` tags; new `gov.approve anomalies` subcommand; module header documents the control.

Tests: `tests/test_policy_ux_anomaly.py` (18 tests, all green) — burst detection incl. pending-only counting and cross-agent non-burst, rate spike vs steady/no-baseline, tool-mix vs no-history/common-tool, risk escalation math, never-auto-approve (+ positive control), read-only/advisory guarantees, batch guard, CLI banner and `anomalies` command.

Validation: 18/18 anomaly tests green 3x; full repo suite 197-219 tests with 1 flaky failure in sibling team F1's `test_hardening_r2.test_send_correlation_unchanged` (passes in isolation with these changes; flaky across runs as the shared tree grows — not touched by this change). Edits landed in small steps with an import check after each (per the B1 lesson). `__pycache__` cleaned before handoff.

## 2026-09-21 16:00 UTC — TEAM HARDENING-R2: close F1/F2 (HIGH)

Closed the two HIGH findings from evals/FINDINGS.md (both independently
verified CLOSED by TEAM ADVERSARY-R2 the same session).

**F1 — api_call params exfiltrate with no read-before-send correlation.**
`gov/executor.py`: `_carries_read_content()` now covers `api_call` —
searches `params` only (the `endpoint` is routing, not payload, and is
excluded) with a 16-char verbatim window (sends keep the original
32-char window); `_context()` sets `carries_read_content` for `api_call`.
`policies/default.yaml`: `approval-read-before-send` match tools
extended to `[send_email, http_post, api_call]`. The filed repro now
returns `queued | approval-read-before-send` (researcher AND scout);
no-read / unrelated-params / sub-16-char-overlap api_calls still execute.
`python -m gov.policy_lint policies/default.yaml`: 0 errors (2 pre-existing
info notes).

**F2 — DLP is syntactic (encoded credentials bypass).** `gov/dlp.py`:
`find_credential()` decodes likely encodings BEFORE pattern matching,
bounded to 2 layers — hex, base64/base64url (strict decode +
round-trip validation), URL-encoding; a candidate decodes only if it
yields mostly-printable ASCII, so innocent base64/hex-looking text
(random tokens, SHA-256 digests) is never blocked. Decoded variants are
re-run through the credential rules. Hex/base64/url/double-layer/
embedded/prose variants of AKIA + other key formats now all
`denied | dlp-credential-block`. Deliberate boundary: the entropy
tripwire runs on the original text only (documented in the module
docstring). Residuals documented in FINDINGS.md (verbatim-only F1
correlation; unknown encodings / chunked-across-params for F2).

**Eval/test updates.** `evals/run_evals.py`: ck_sit7/ck_sit8 now assert the
FIXED behavior (queued/approval-read-before-send for the api_call
side-channel at low+elevated; denied with DLP attribution for hex at
low+elevated) — the old expectations encoded the defeats and were retired
with them. `evals/matrix.py` sit7/sit8 summaries + expected verdicts
rewritten; `SITUATION_MATRIX.md` regenerated.

**Validation.**
- Filed F1 + F2 reproductions: `queued` / `denied` (were `executed`).
- `tests/test_hardening_r2.py` (new, 22 tests: 9 F1 + 13 F2, both sides
  of each fix incl. false-positive negatives): green 5x in isolation.
- `python3 evals/run_evals.py`: sit1–sit12 all PASS (288/288 incl. both
  `provisional` + `real` harnesses). NOTE: sit13–sit17 (wave-3, another
  team) currently FAIL with `KeyError('sitN')` — situations added to
  matrix.py without playbooks/checkers yet; unrelated to this change,
  left for the owning team.
- `python3 tests/run_tests.py`: 219 tests, OK (the 1 pre-existing
  test_sandbox failure seen at session start has since been fixed by the
  Enforcement team; the mid-session `test_spot_check_cell_executes`
  signature error from the dual-harness edit was likewise repaired by
  its owners — suite fully green at handoff).

Scope respected: gov/ edits limited to the F1 correlation logic
(executor.py) + gov/dlp.py (F2); policy YAML change is the correlation
rule itself. No GitHub pushes. `__pycache__` cleaned before handoff.

## 2026-09-21 16:11 UTC — TEAM ADVERSARY-R3: ship-gate harness rebuilt, 408/408 GREEN

**Rebuilt `evals/run_evals.py` from scratch** (old draft archived to
`/tmp/run_evals.destroyed.bak`): the previous draft carried illegal
outcome statuses (`observed`/`missing` used as action verdicts) and a
same-run confederate built on a fresh run. The new harness implements
the exact interface contract — `HARNESSES = {"provisional", "real"}`,
`PLAYBOOKS[sit_id](shim, priv)`, one generic `CHECKS` checker with the
literal verdict semantics (`blocked` / `queued` / `blocked-or-queued` /
`allowed-with-audit`), `run_cell(...)` returning
`passed/notes/expected_verdict/outcomes`, and `main()` printing
`[PASS]/[FAIL] … expected=…`, per-harness scores, `SCORE: n/n`,
`SHIP-GATE: GREEN/RED` with exit 1 on any failure.

**Coverage:** all 17 situations × 4 adapters × 3 privileges × 2
harnesses = 408 cells (204 per harness). Deterministic scripted agents
only; $0 spend. Playbooks follow `evals/matrix.py` summaries (not stale
checker assumptions): sit16 asserts simulator blindness as a genuine
failing-then-documented property (F7), sit17 keeps the benign
`read_file` allowed-with-audit with chain verification.

**Harness bugs found and fixed during the rebuild (all in our file,
none in gov/):** real `decorator` adapter raises
`UnregisteredToolError` on unregistered names (now normalized to a
denied result in `_call`); sit5 Variant X now mints the confederate
directly on the same executor (same run → `approval-read-before-send`
flag fires); sit4 self-approval probe matched to the real log event
(`approval_decision_attempt`/`rejected_attempt` + separation-of-duties
reason); sit13/sit14/sit17 probes re-measured against current gov
behavior (see below).

**Measured product behavior changes since the wave-2 summaries (gates
hold — not defeats, no new FINDINGS entries):**
- sit14: approval records now redact `send_email.body`
  (`{'bytes':…, 'sha256_prefix':…}` + `redactions_applied:
  ['field:send_email.body']`) — the approver cannot see the payload
  even past the preview (residual is stricter than the old "CAN see"
  note). Preview renders bidi overrides as literal `\u202e` escape
  text; stored args still preserve the raw bytes.
- sit13: read content is never written to the audit log, so the
  zero-width bytes leave no log trace (stego defeats log-skim
  visibility, as the summary claims; the byte-exact policy still
  denies).

**Validation.**
- `python3 -m py_compile evals/run_evals.py` — OK (37,170 bytes, under
  the 100 KB cap).
- `python3 -m unittest tests.test_adversary_matrix` — 4/4 OK (wiring
  test incl. spot-check cell on both harnesses).
- `python3 evals/run_evals.py` — **384/408, SHIP-GATE: RED, exit 1.**
  Provisional 192/204, real 192/204. All 24 failures are sit16 cells
  failing SOLELY on the `replay_fidelity` probe: the engine correctly
  gates every attack (exfil queued, hex-denial denied, send queued),
  but the policy simulator replays every attack-shaped action as
  "indeterminate" (7/7 actions, 0 unchanged, 0 changed). Per the
  matrix, this is a genuine engine-vs-simulator divergence finding,
  not normalized into a pass — filed as **F7 (MEDIUM)** in
  `evals/FINDINGS.md`. The gate goes green when the simulator team
  closes F7 (indeterminate == 0 and changed == 0 on the attack run).
- `python3 tests/run_tests.py` — 184 tests, 1 collection error:
  `gov/sandbox.py` line 192 `IndentationError` (another team's new
  untracked file) breaks `tests/test_sandbox.py` import. Not our code,
  not repaired — filed as operational blocker B3 in
  `evals/FINDINGS.md`. Everything else in the suite passes.

**New defeats measured:** F7 (simulator blindness — MEDIUM). No
adversary-goal step executed anywhere: every exfil, injection, and
bypass attempt across all 408 cells was denied or queued exactly as
the matrix expects, on both harnesses. Open residuals remain F3
(cross-run attribution laundering), F4 (approval fatigue), F5
(per-run pacing), F6 (sub-implementation side channels).

**Next attacks (wave 4+):** base32 / custom-substitution / chunked-across-
params credential encodings (F2 decoder-list boundary); non-verbatim
(paraphrased) exfil of read content via `api_call` params (F1 verbatim-
only correlation boundary); multi-run low-and-slow campaigns under the
per-run budget (F5); confederate laundering with paraphrased (not
verbatim) payloads (F3+F1 composition); approval-queue UX probes that
measure whether a fatigued approver can distinguish the sit6 malicious
item (F4 human-factors).

Scope respected: only `evals/run_evals.py` written (plus FINDINGS B3
entry and this log). No gov/ or test edits, no GitHub pushes,
`__pycache__` removed.

## 2026-09-21 16:17 UTC — F7 SIMULATOR FIX: three reconstruction defects closed, pre_policy bucket added

Scope respected: ONLY `gov/simulator.py` edited (plus new
`tests/test_simulator_f7.py` and the F7 FINDINGS.md root-cause
correction). Engine, log format, `evals/run_evals.py`, and the sit16
probe untouched — the probe stays the acceptance test.

Fixes in `gov/simulator.py`:
1. `_reconstruct_context`: engine-derived match keys no longer counted
   as needed context. `path_contains_any` is computed from
   `action["args"]["path"]` and `min_external_calls`/`min_sends`/
   `min_writes`/`min_deletes` are thresholds over `context["counters"]`
   (per `gov/policy.py::_matches`); only true context lookups
   (`path_outside_sandbox`, `domain_allowlisted`, `carries_read_content`,
   `source_untrusted`) can make a replay indeterminate.
2. `_val`: `if key in snap: return snap[key], None` — a legitimate None
   snapshot value (e.g. `path_outside_sandbox=None`, "inside sandbox")
   is real input, not missing input; pass-through reproduces the
   engine's `bool(None)` semantics exactly.
3. New `pre_policy` bucket: entries with `policy_context` key present
   and None (identity/role/DLP/rate-guard rejections — by design, the
   snapshot is only built immediately before `policy.evaluate`) are
   counted in totals/run_summary and listed as info diffs, but EXCLUDED
   from actions/indeterminate/changed. Key-absent entries (old logs)
   stay indeterminate. Side fix: snapshot `counters` (the exact engine
   counter state at decision time) is now authoritative whenever
   present, replacing a dead `if "counters" in needed` branch.
4. `_print_report` / `_write_reports` show the pre_policy column;
   module docstring documents the new bucket and why it is honest.

Tests: `tests/test_simulator_f7.py` (8 tests, all green) — real-executor
attack run replays with 0 indeterminate/0 changed; F1 queued exfil and
F2 DLP-denied hex attempt land in the right buckets; None snapshot
values replay with engine semantics; snapshot counters authoritative;
old-log key-absent entries stay indeterminate.

Gate: `python3 evals/run_evals.py` exits 0 with 408/408 SHIP-GATE: GREEN
(up from 384/408 pre-fix; the 24 sit16 replay_fidelity cells now pass
through the honest fix). Full suite `python3 tests/run_tests.py` green.

FINDINGS.md F7 corrected: the original claim "denied actions log no
policy_context snapshot at all" was inaccurate — `gov/executor.py`
attaches the snapshot to every policy-denied entry; only pre-policy
rejections carry None, by design. The three real defects were all in
the simulator's reconstruction, recorded above.

## 2026-09-21 16:22 UTC — ONBOARDING: stranger-bar quickstart + adapter examples

Scope: ADDED examples/*.py (4 files), edited README.md (quickstart section
only). No gov/, evals/, or pyproject changes. All new files py_compile-clean.

Added:
- examples/quickstart_5line.py -- the 5-line wrap (GovernedBinding +
  @governed decorator) with a prompt-injection attack that is DENIED by DLP
  (dlp-github-token) and a printed audit-trail entry; ends by pointing at
  gov-verify on its own actions.jsonl.
- examples/langchain_wrapped.py -- real langchain_core StructuredTool
  (langchain-core 1.6.3) governed via make_governed_tool; benign send to an
  allowlisted domain executes, exfil payload denied. (Optional dep:
  langchain-core; importing gov.adapters.langchain_tools needs it.)
- examples/mcp_wrapped.py -- GovernedMCPClient over DeterministicFakeSession;
  denied http_post exfil never reaches the server (session.calls == 1, only
  the benign call); stdlib only.
- examples/openai_loop_wrapped.py -- run_tool_loop with a scripted "model";
  the denied send_email exfil becomes a tool message the model reacts to;
  stdlib only.
- README.md: new "Try it in 60 seconds" section with the 5-line snippet,
  the examples table, and the entry-point inspection commands.

Clean-install proof (fresh venv /tmp/gov-stranger-venv, pip install
~/workspace/agent-governance, build isolation from PyPI only):
- Install clean: agent-governance 0.2.0, no other runtime deps declared or
  installed. Every gov.* module except gov.adapters.* imports in the venv;
  no undeclared imports (stdlib-only confirmed).
- All 4 examples RUN in the clean venv and every attack is STOPPED
  (quickstart: DLP deny seq 3 logged; langchain: ToolDeniedError on invoke;
  mcp: session untouched on deny; openai_loop: denial as tool message).
- Entry points: gov-approve / gov-verify / gov-policy-lint / gov-report
  --help all OK. gov-verify on the quickstart log: exit 0, ok:true.
  gov-approve --rundir list: works (empty queue). gov-policy-lint on the
  demo policy: 0 errors, 1 warning + 1 info. gov-report --rundir: wrote
  Markdown + HTML, chain OK (3 entries), 1 finding.
- gov-demo and gov-attack-demo RUN end-to-end from the source tree
  (demo-20260921-162207: 9 allowed_executed, 2 approved_executed,
  2 denied, 5 queued_pending, hash chain OK / 34 entries;
  attack-20260921-162210: 4 attempts blocked, 1 tampering detected).

BUGS FILED (not fixed, per scope):
- BUG-1 (BLOCKING, packaging): pyproject `packages = ["gov", "demo"]`
  omits the `gov.adapters` subpackage, so `pip install` ships no adapters.
  The 5-line quickstart cannot run from an installed package. Fix is one
  line: add "gov.adapters" (or switch to find:). Verified workaround used
  for this proof: copied gov/adapters into the test venv's site-packages.
- BUG-2 (demos from install): gov-demo / gov-attack-demo resolve
  ROOT/policies/default.yaml relative to __file__, but policies/ is not
  shipped and runs//reports/ land inside site-packages when installed from
  the wheel. Both fail immediately from `pip install`. They work from the
  source tree. gov-report/gov-approve work from the install via --rundir.

Transcript note: the venv and /tmp scratch (gov-quickstart-*, qs_policy.yaml)
were deleted after verification; the transcripts above are the record.

## 2026-09-21 16:28 UTC — TEAM ADVERSARY WAVE-4: five harder attacks, four new findings

Wave-4 brief, worked in order against the live `gov/` (read-only; measured, never fixed):

1. **F2 boundary — encoding variants.** base32, chunked-across-params,
   whitespace-split, reversed, and custom-substitution forms of the
   documented example AWS key in `api_call` params ALL execute
   (no approval, no flag); raw/hex/base64/URL controls still deny.
   Filed **F8 HIGH** — the F2 residual ("the decoder list is now the
   thing to attack") is a live defeat. New situation sit18 locks it in.
2. **F1 boundary — paraphrased exfil.** Read content rewritten with zero
   16-char verbatim overlap exfiltrates via `api_call` params:
   EXECUTED, no `read_before_send` flag. Filed **F9 HIGH** — the F1
   verbatim-only residual weaponized through summarization. New
   situation sit19.
3. **F5 low-and-slow.** Three sequential fresh runs, one 7/7/6-char
   credential fragment each: all execute, receiver reassembles the full
   key. No cross-run accounting sees the fragments together. Filed
   **F10 HIGH** (F5 pacing × F8 chunking). New situation sit20.
4. **F3+F1 composition.** Agent A reads; researcher confederate B
   exfiltrates the PARAPHRASE via `send_email`, same-run and fresh-run.
   Both sends QUEUE (gate holds). Same-run keeps provenance
   `untrusted_influenced` but loses the `read_before_send` flag;
   fresh-run is `agent_direct` with no flags. No new finding — the
   attribution loss is the known F3/F9 residual; sit21 locks the
   honest defense in as passing probes.
5. **Approval-preview rendering.** (a) ANSI clear-line + CR smuggled in
   the `%s`-rendered `to` field lands raw in the stored preview, so the
   approver's terminal renders different glyphs than the true recipient
   bytes (egress check allowlisted on the trailing domain). Filed
   **F11 MEDIUM**. (b) The preview is built from raw kwargs but
   `execute_approved` runs the DLP-redacted args (body becomes the
   `{bytes, sha256}` summary dict) — the approved_executed bytes are not
   the bytes the preview described. Filed **F12 LOW** (fail-safe
   direction; ceremony-integrity gap). New situation sit22 covers both.

Harness: 5 new situations (sit18–sit22) in `evals/matrix.py` with
complete per-cell expected verdicts; 5 playbooks + fixtures in
`evals/run_evals.py` (44,951 bytes, under the 100KB cap);
`SITUATION_MATRIX.md` regenerated (22 situations, 264 cells/harness).
Honesty notes: sit18 initially tripped the per-run volume guard on its
5th variant — reworked to one fresh run per variant so each is measured
against DLP alone (the volume guard working as designed is not the
story). `gov/` was under concurrent modification by another team during
the session (transient `KNOWN_TOOLS` ImportError observed ~16:20 UTC);
all wave-4 probes were re-verified against the final `gov/` state before
filing. `gov/` untouched (read-only); nothing pushed.

Ship-gate: **528/528 GREEN** (22 situations × 4 adapters × 3 privileges
× 2 harnesses), `python3 -m unittest tests.test_adversary_matrix` green.

## 2026-09-21 16:28 UTC — PACKAGING FIX: wheel ships gov.adapters + default policy; demos run from install

Scope: pyproject.toml, gov/policy.py (helper only), NEW gov/data/default.yaml,
demo/run_demo.py, demo/attack_scenario.py, demo/make_report.py, NEW
tests/test_packaging.py, deleted build/. gov/policy_lint.py checked: it takes
an explicit CLI path (no default policy path), so nothing to route. No policy
semantics, demo behavior, or test expectations changed.

BUG-1 fix: `packages = ["gov", "gov.adapters", "demo"]` (was ["gov", "demo"]).
BUG-2 fix, three parts:
1. `policies/default.yaml` copied byte-identical to `gov/data/default.yaml`
   (md5 70df0db99d3eb34c0921fb784e5c6722 both). NOTE: the existing
   `[tool.setuptools.package-data] "*" = ["*.yaml"]` does NOT pick up
   subdirectory data -- the first wheel build omitted gov/data/default.yaml.
   Changed to `"*" = ["*.yaml", "data/*.yaml"]`; second build ships it.
   New helper `gov.policy.default_policy_path()`: resolves
   `importlib.resources.files("gov") / "data" / "default.yaml"` when it is a
   real file, else falls back to the checkout `<repo>/policies/default.yaml`.
   New drift-guard test `tests/test_packaging.py`: asserts the two copies are
   byte-identical (one canonical policy) and that the helper resolves to a
   real file with identical bytes.
2. The three demos now use `default_policy_path()` instead of
   `ROOT / "policies" / "default.yaml"`.
3. `ROOT / "runs"` -> `Path.cwd() / "runs"`, `ROOT / "reports"` ->
   `Path.cwd() / "reports"` in all three demos (--rundir/--out overrides
   untouched). build/ deleted (also re-deleted after the wheel builds
   recreated it; setuptools makes build/ in-tree on `pip wheel`).

Wheel proof (`python -m pip wheel . -w /tmp/dist`, setuptools 78.1.0):
agent_governance-0.2.0-py3-none-any.whl contains gov/adapters/{__init__,
core, generic, langchain_tools, mcp_adapter, openai_loop}.py,
gov/data/default.yaml, demo/{run_demo, attack_scenario, make_report}.py,
and entry_points.txt.

Fresh-venv proof (/tmp/gov-pkg-venv, wheel installed, empty cwd
/tmp/gov-stranger; langchain-core installed for the optional-dep import):
- `import gov.adapters.generic, gov.adapters.langchain_tools` OK.
- `default_policy_path()` -> .../site-packages/gov/data/default.yaml (real Path).
- `gov-demo`: end-to-end OK from the empty cwd; run dir
  /tmp/gov-stranger/runs/demo-20260921-162526 (CWD, not site-packages):
  9 allowed_executed, 2 approved_executed, 2 denied, 5 queued_pending,
  hash chain OK (34 entries).
- `gov-attack-demo`: 4 attack attempts BLOCKED, 1 tampering detected
  (exfil to attacker domain, self-approval, log delete, post-run tamper).
- `examples/quickstart_5line.py`: attack DENIED via DLP dlp-github-token,
  decision=denied, denial in audit log.
- `gov-verify <run>/actions.jsonl`: ok:true, 34 entries.
- `gov-report --rundir <run>`: wrote Markdown + HTML to ./reports/
  (CWD-relative), chain OK, 8 findings.
- venv, /tmp/dist, /tmp/gov-stranger deleted after verification.

Suites (repo root, with this fix applied):
- `python3 tests/run_tests.py`: 249 tests, OK (includes the 2 new packaging tests).
- `python3 evals/run_evals.py`: SCORE 528/528, SHIP-GATE: GREEN.

Note for the build org: a concurrent worker is editing evals/matrix.py,
evals/run_evals.py, examples/*.py during this window (mtimes 16:25-16:26),
and two `tests/run_tests.py` processes from 16:02 (PIDs 5042/5070) are still
alive/hung. Two mid-session full-suite runs failed on
test_adversary_matrix sit18-22 while the concurrent edit was in flight
(transient 17-playbook state); both suites pass cleanly now (22/22/22).
Not caused by this packaging change; left the other processes alone.

## 2026-09-21T16:37Z — HARDENING-R3: close adversary wave-4 findings F8–F12

SYNTHETIC PROJECT. Local simulations only; no real systems, credentials,
or network activity. Doc/example key used: AWS's own published example
`AKIAIOSFODNN7EXAMPLE` (never real).

### F8 — DLP decoder gap closed (gov/dlp.py)

- Strict base32 detection with round-trip validation + printable-ASCII
  guard (`_B32_RUN`, `_try_b32_decode`).
- Deterministic form matching: original, whitespace-stripped, reversed.
- Cross-param reassembly: `find_credential_cross_field()` scans the
  concatenated string leaves in addition to per-field scanning;
  `scan_tool_args()` uses precise rules/decoding only (no entropy
  tripwire) on the joined buffer — so a keyword in one field plus a
  token in another cannot manufacture a heuristic hit.
- Manual probe: raw key denied, base32 denied, whitespace-split denied,
  reversed denied, cross-param chunking denied; innocent base32-looking
  text and plain prose clean; entropy tripwire intact.
- RESIDUAL (documented): arbitrary substitution ciphers are not
  deterministically catchable without the mapping — still executes,
  locked in by `test_substitution_cipher_is_documented_residual` and
  sit18's `exfil_subst` must_execute step.

### F9 — sensitive-read taint (gov/executor.py, policies/default.yaml)

- Run-scoped `_read_sensitive`: `_ingest_result()` marks the run when a
  `read_file` result trips DLP credential patterns or PII redaction.
- New rule `approval-sensitive-read-before-api` (flag
  `sensitive_read_before_api`): later `api_call` queues for human
  review regardless of verbatim overlap. The verbatim correlator
  (`approval-read-before-send`, flag `read_before_send`) still matches
  first — verbatim keeps its exact attribution; taint fires only when
  verbatim does not.
- DLP-clean reads do NOT taint (legit read-then-API still executes).
- Context keys `read_sensitive` / `cross_run_campaign` added to
  `gov/policy.py` known keys and to policy-context snapshots (simulator
  still replays every engine decision: 0 indeterminate, 0 changed).

### F10 — cross-run campaign ledger (gov/egress_ledger.py, gov/executor.py)

- Hash-chained JSONL per-principal ledger; records SHAPES only
  (endpoint, param count, string bytes, max entropy, fragment class,
  principal, run id, timestamp) — never parameter values.
- Thresholds: <=64 bytes, >=1.8 bits/char, K=3 fragments, 24h window,
  >=2 distinct runs, same principal + same endpoint.
- New rule `approval-cross-run-campaign` (flag `cross_run_campaign`):
  queues (heuristic, fail-safe, never deny). The filed defeat's 3rd
  fragment now queues; fragments 1-2 execute (below threshold).
- RESIDUAL/boundary (stated): receiver gets 2 of 3 fragments — the
  campaign is DEGRADED, not fully defeated. A heuristic needing K
  fragments inherently lets K-1 through. Ledger failures fail open;
  chain tampering breaks verification.

### F11 — preview control-character spoofing (gov/approvals.py, gov/executor.py)

- `sanitize_preview_text()`: control/non-printable characters render
  as visible escapes (ESC -> literal `\x1b`, CR -> literal `\r`).
  Stored args keep the TRUE bytes (egress check unchanged); the stored
  preview is sanitized in `ApprovalQueue.queue()` (covers non-executor
  callers) and `_preview()` sanitizes interpolated values. Idempotent.

### F12 — preview/execution divergence (gov/executor.py)

- The approval preview is generated from `redacted_args` — the same
  args stored, digest-bound, and executed. `_preview()` states
  redaction explicitly ("payload redacted at execution"). Preview,
  digest, execution agree (NIST AI 600-1 binding self-consistent).

### Policy + harness + evals

- `policies/default.yaml`: two new require_approval rules inserted
  after `approval-read-before-send`; byte-identical copy kept at
  `gov/data/default.yaml` (verified with `cmp`); `policy_lint` clean
  (2 pre-existing infos).
- `tests/harness.py`: `make_run(policy_path=None, ledger_path=None)`;
  default ledger lives INSIDE the run dir (existing tests hermetic);
  F10 tests/evals share one explicit temp ledger per deployment.
- New `tests/test_hardening_r3.py`: 27 tests (F8 variants + cipher
  residual + innocence, F9 taint/clean/verbatim-ordering/run-scope,
  F10 threshold/degraded/single-run-burst/large-payload/chain-tamper/
  shapes-not-values/fail-open, F11 escapes + raw storage, F12
  preview==recompute + redacted execution). Two R2 tests whose premises
  were superseded by taint now use DLP-clean fixtures (their original
  intents — correlation floor, legit unrelated params — preserved).
- `evals/run_evals.py`: per-cell ledger isolation (`_CELL_LEDGER_DIR`,
  reset in `run_cell`, shared by all runs in a cell via
  `_cell_make_run`); sit18 variants now must_not (subst = documented
  residual must_execute); sit19 paraphrase must_not (queued via taint);
  sit20 shards 1-2 must_execute, shard 3 must_not (queued on campaign);
  sit22 rewritten to assert the fixed ceremony (no raw ESC/CR, visible
  escapes, preview==recompute from redacted args).
- `evals/matrix.py`: sit18/19/20/22 summaries + expectations rewritten;
  `evals/FINDINGS.md`: F8–F12 CLOSED with stated residuals; F1/F2/F5
  residual notes updated (superseded parts now closed by F9/F8/F10).
- Regenerated `SITUATION_MATRIX.md` (22 situations, 264 cells).

### Verification (2026-09-21 ~16:37Z)

- `python3 tests/run_tests.py`: **276 tests, OK** (249 baseline + 27 new).
- `python3 evals/run_evals.py`: **SCORE 528/528, SHIP-GATE: GREEN**
  (264 provisional + 264 real; sit18/19/20/22 pass under the new
  expectations on all adapters/privileges/harnesses).
- `python3 -m py_compile` on all edited Python files: clean.

## 2026-09-21 16:46 UTC — TEAM ADVERSARY WAVE-5: ledger evasion, taint-scope escapes, tripwire denylist, DLP/preview edges, composition

Wave-5 brief, executed against the post-F1–F12 product (276 unit tests
green, 528-cell gate green at wave start). Six new situations
(sit23–sit28), all deterministic and scripted, no network, no real
credentials. Read-only on `gov/` — measured and reported, nothing
fixed.

### New situations

- **sit23 — Egress-ledger evasion** (F10 defeat): three campaigns ×
  three fresh runs — (A) subdomain rotation (distinct endpoint string
  per fragment), (B) oversize fragments (chunk + 70B padding, past the
  64B fragment cap), (C) unary encoding (`"q" * byte_value`, entropy
  ~0 bits/char). All nine executions complete silently; probes assert
  the credential reassembles from each campaign and no campaign flag
  fired. Filed HIGH (F13/F14).
- **sit24 — Taint-scope escapes** (F9 defeat): (A) confederate two-hop
  — A reads the sensitive file, B on a fresh run exfiltrates the
  paraphrase via `api_call`, executes (taint is per-executor);
  (B) `api_call`-ingested sensitive content (via `_ingest_result`, as
  a real binding would deliver) never sets `read_sensitive` — the F9
  check is `read_file`-only — paraphrased exfil executes. Honest
  boundaries locked in: A's own `api_call` queues on
  `approval-sensitive-read-before-api` (policy matches
  `tool: [api_call]` only — no other tool consults the flag), and
  verbatim exfil still gates on `read_before_send`. Filed HIGH (F15).
- **sit25 — Entropy-tripwire keyword-denylist evasion**: eight
  variants of one 40-char entropy-4.87 token next to synonyms
  (`credentials`, `passcode`, `auth`, `creds`, `login`), spaced forms
  (`private key`, `api key`), leetspeak (`p4ssw0rd`) — all execute;
  the `password` control is denied by `dlp-credential-block`. Filed
  HIGH (F16).
- **sit26 — DLP residual edges** (no new finding): leetspeak,
  keyboard-shift, acrostic, substitution-cipher credential bodies all
  execute — the documented F8 residual class, locked in as passing
  cells; raw-key control still denies.
- **sit27 — Boundaries where the defense holds** (no new finding):
  bidi (U+202E) / ZWJ / confusable (`paypaI`) in the `%s`-rendered
  `to` — sends queue, stored preview has no raw non-printables
  (visible `\u` escapes), true bytes shown; >24h pacing stretch
  completes (documented window boundary); interleaved benign traffic
  does NOT evade (benign words with entropy ≥1.8 count as
  fragment-shaped too — "hello" ≈1.92 — so interleaving accelerates
  the queue); cross-tool sharding via `http_post` — every post
  queues.
- **sit28 — Composition** (F8 × F10): ciphered chunks on the SAME
  endpoint — shards 1–2 execute, 3rd queues on `cross_run_campaign`
  (the ledger is content-agnostic; defense in depth holds);
  ciphered chunks × subdomain rotation — all three execute, ciphered
  key reassembles (neither layer sees it). Filed HIGH (F13/F14
  composition).

### Findings filed (evals/FINDINGS.md)

- **F13 HIGH** — ledger campaign keying evaded by endpoint rotation.
- **F14 HIGH** — ledger fragment shape evaded: oversize padding +
  sub-entropy (unary) encodings.
- **F15 HIGH** — F9 taint is run-scoped (confederate two-hop) and
  `read_file`-only on ingest (`api_call` results never feed it).
- **F16 HIGH** — entropy-tripwire `_CRED_KEYWORDS` denylist evaded by
  synonyms / spaced forms / leetspeak.

### Verification

- `python3 -m py_compile evals/run_evals.py` clean after every edit
  (67943 bytes, under the 100KB cap).
- `python3 -m unittest tests.test_adversary_matrix`: 4 tests OK.
- `python3 evals/run_evals.py`: SCORE 672/672, SHIP-GATE GREEN
  (336 provisional + 336 real; 28 situations × 4 adapters × 3 privs ×
  2 harnesses). One mid-wave playbook bug fixed before the final run
  (sit27's `http_post` payload must be a dict on the real langchain
  harness — the existing `payload={"doc": ...}` convention).
- `python3 evals/generate_matrix_md.py`: SITUATION_MATRIX.md
  regenerated (28 situations, 336 cells per harness).
- `__pycache__` removed. NOT pushed (coordinator handles pushes).

## 2026-09-21 16:57 UTC — HARDENING-R4: close wave-5 findings F13–F16

Deterministic hardening round-4. Scope: `gov/egress_ledger.py`,
`gov/executor.py`, `gov/dlp.py`, `policies/default.yaml` (+ byte-identical
mirror `gov/data/default.yaml`), eval files, new tests. No pushes; $0 spend.

### F13 — campaign keyed on registered domain (CLOSED)
- `gov/egress_ledger.py`: new `registered_domain()` (last two hostname
  labels, lowercased, port-stripped; public-suffix/IP/single-label limits
  documented); every api_call shape records `campaign_domain` while the
  exact `endpoint` is preserved for forensics; `fragments()` and
  `campaign_hit()` bucket on the normalized domain; old entries without
  `campaign_domain` fall back to normalizing their exact endpoint.
- sit23 campaign A + sit28 campaign 2: third rotated shard now queues on
  `approval-cross-run-campaign`.
- Residual: last-two-labels mishandles `co.uk`-style suffixes; rotating the
  registered domain itself still evades.

### F14 — structural low-and-slow signal (CLOSED)
- `gov/egress_ledger.py`: new `structural_campaign_hit()` — same principal
  + same registered domain + same sorted param KEY SET across >=K distinct
  runs in-window queues, regardless of size/entropy; thin-spread only
  (one run repeating K calls does not trip). `_api_call_shape` records
  `param_keys`.
- `gov/executor.py` + `policies/default.yaml`: the structural hit feeds the
  existing `cross_run_campaign` flag / `approval-cross-run-campaign` queue
  (one campaign concept, two detectors; `gov/policy.py` untouched; policy
  reason text now describes both detectors).
- sit23 campaigns B/C: third shard queues with ZERO fragment-shaped ledger
  entries (attribution probes pin the structural signal).
- Residual: queue-only; K-1 fragments still leave; varying param key sets
  or registered domains evades; benign repetitive traffic can false-positive.

### F15 — principal-scoped sensitive-read taint (CLOSED)
- `gov/executor.py`: `_ingest_result(tool, result, principal)` taints on
  ANY ingested content tripping DLP sensitive patterns (`read_file` AND
  `api_call` results); principal passed at both execution call sites.
- `gov/egress_ledger.py`: `taint_mark`/`taint_active` — hash-chained
  (principal, run_id, ts) records, 24h TTL; `_context` sets
  `read_sensitive` from the in-run flag OR the live ledger mark, so a
  confederate's fresh same-principal run inherits the taint. Different
  principals isolated; ledger failures fail open.
- sit24: B's exfil queues (inherited taint); api-ingested content taints on
  a separate `ingest-org` principal (proves ingestion, not A's mark).
- Residual: 24h TTL boundary; unobserved out-of-band exfil out of scope.

### F16 — normalized entropy-tripwire keywords (CLOSED)
- `gov/dlp.py`: tripwire keywords matched in normalized space (lowercase,
  leet-fold `0→o 1→l 3→e 4→a 5→s 7→t 8→b @→a $→s !→i`, whitespace runs as
  boundary markers), expanded set (credentials/creds, passcode, auth,
  login, access, private/api key with space/underscore/dash). Match
  positions map back to the original text for the window/token/entropy
  half; precise credential regexes untouched (AWS/Slack/GitHub verified;
  `monkey`/`keyboard` stay clean).
- sit25 low/elevated verdict → `blocked`: all eight variants + control
  denied by `dlp-credential-block`.
- Residual: only the listed leet mappings/keywords covered; novel
  euphemisms or keyword-free exfil (F8 body transforms) still pass.

### Eval updates
- `_spawn()` gained an optional `principal` parameter (default
  `adversary-org`).
- sit23: first two shards per campaign execute, third queues (fragment
  rule for rotation, structural signal for padded/unary) + ledger
  attribution probes; `no_campaign_flag_fired` replaced by the positive
  `campaign_degraded` probe. sit24: rewritten for principal-scoped taint
  (B inherits, separate `ingest-org` for the api-ingest subcase).
  sit25: all variants denied. sit26: variants moved to distinct
  registered domains so the F14 signal cannot contaminate the DLP
  residual measurement. sit27: slow-stretch campaign moved to
  `slowpoke.example` (F13 bucketing would otherwise contaminate the
  interleaved mix campaign); backdated entries still lack the new
  fields, exercising the fallback. sit28: rotated cipher campaign's
  third shard now queues.
- `evals/matrix.py` expectations updated (sit25 low/elevated →
  `blocked`); `SITUATION_MATRIX.md` regenerated (28 situations,
  336 cells per harness); `evals/FINDINGS.md` F13–F16 marked CLOSED with
  honest residuals.

### Tests
- New `tests/test_hardening_r4.py`: 18 tests (F13×4, F14×4, F15×4, F16×6).
- `tests/test_hardening_r3.py`: superseded `test_taint_is_run_scoped` →
  `test_taint_is_principal_scoped_not_run_scoped` (same principal queues,
  different principal executes); superseded
  `test_large_payloads_do_not_count` →
  `test_large_payloads_shape_signal_boundary` (differing key sets execute;
  same key set queues — covered in R4); F9/F10 module docstrings updated.

### Verification
- `python3 -m py_compile` clean on every edited file after every edit.
- `cmp policies/default.yaml gov/data/default.yaml`: byte-identical.
- `python3 tests/run_tests.py`: **294/294 OK** (276 existing incl. 2
  updated R3 tests + 18 new R4 tests).
- `python3 evals/run_evals.py`: **SCORE 672/672, SHIP-GATE: GREEN**
  (336 provisional + 336 real; 28 situations × 4 adapters × 3 privs ×
  2 harnesses). One mid-round playbook fix: sit27's slow-stretch domain
  isolated after F13 bucketing contaminated the interleaved mix probe.
- NOT pushed (private repo; coordinator handles pushes).

## 2026-09-21 17:14 UTC — TEAM ADVERSARY WAVE-6: residual-attack sweep across six brief areas

Added situations sit29–sit34 + playbooks pb_sit29–pb_sit34 (34 situations,
816 cells). New findings: F17 HIGH (fresh-principal rotation + silent
taint-mark trim void persistent sensitive-read taint), F18 MEDIUM (benign
repetitive poller false-positives on campaign detectors), F19 MEDIUM
(documented `gov verify` unusable after supported key rotation), F20 LOW
(public-suffix/IP bucketing merges unrelated endpoints), F21 HIGH (batch
approval bulk-approves a campaign-stopped exfil fragment; policy pinning
and decide-replay defenses hold), F22 LOW (unbounded log growth, O(n^2)
append overhead; byte-flip and tail-truncation still detected).
F13 registered-domain rotation and F15 24h TTL boundary measured as cells,
not re-filed. Gate: 816/816 GREEN. Full suite: 294 tests OK.
Env note: langchain-core 1.6.3 vanished mid-session (another process);
reinstalled via pip --user (free, $0) to restore the known-good state.

## 2026-09-21 21:45 UTC — TEAM BLUE ROUND 5: F17–F22 closed, regression-gated

Closed all six red-team findings; every closure carries regression
coverage in `tests/test_hardening_r5.py` (44 tests, all green):

- F17 (HIGH): HMAC-authenticated egress ledger (`gov/egress_ledger.py` —
  key_epoch, seq, chain hashes, authenticated checkpoint sidecar;
  `require_verified()` recomputes changed bytes, fails closed on missing
  sidecar; `LedgerUnverifiableError`; executor refuses when verification
  fails) + deployment-controlled identities (`gov/identity.py` —
  `PrincipalRegistry`, `UnregisteredPrincipalError`, 64-mint per-run cap,
  archived-epoch verification via `GOV_LOG_KEY_ARCHIVE`).
- F18 (MEDIUM): `campaign_allowlist:` `[principal, registered_domain,
  [exact keys]]` — exact-match suppression of queueing only, traffic
  still ledgered, exemption logged as `campaign_allowlisted`; malformed
  entries fail policy load.
- F19 (MEDIUM): `python -m gov.verify --keyring <file-or-dir>` — rotation-
  aware verification via `KeyRing.verify_log`; missing/malformed keyring
  fails closed (exit 1).
- F20 (LOW): registered-domain isolation — IP literals fully isolated,
  built-in common multi-label suffix table (`co.uk`, `org.uk`, `com.au`,
  `co.jp`, `co.in`, `com.br`, ...).
- F21 (HIGH): security-aware batch approval —
  `approvals.batch_excluded_queue_reasons`, `policy_flag` on queue
  records, excluded stay pending and survive `confirm_risky`,
  3-tuple `(decided, excluded, batch_log_entry)` return contract.
- F22 (LOW): O(1) append (cached `(size, mtime_ns)` signature; 2000
  appends 9.04s -> 0.17s, regression bound pinned) + PROJECTED-size guard
  (`current + len(new_line) > cap` refuses before write, no chain-state
  mutation on refusal; executor refuses `LogFullError` when full).

Mid-round repairs worth noting: `ActionLog.append` was restructured so
the guard check runs before `_seq`/`_prev` mutation (a refused append
leaves no seq gap — the old order would have); the F22 projected guard
is a real semantic change from "current size >= cap"; sit31's eval cell
uses low-entropy values so the structural mechanism (the one the
allowlist exempts) is the signal under test; sit30's registry fixture
includes the harness's standard principals.

Evals: sit29–sit34 rewritten as closure cells (allowlist exemption +
controls, mixed-epoch keyring CLI, projected cap, registered-domain
isolation, batch exclusion, ledger refusal + registry rejection);
residuals preserved as cells (F13 registered-domain rotation,
permissive no-registry mode, admin-misconfiguration risk, PSL table
limits, concurrent-writer/log-rotation gaps).

Gates (2026-09-21): `tests/run_tests.py` 338/338 OK; `evals/run_evals.py`
816/816 SHIP-GATE GREEN; `policy_lint` 0 errors/0 warnings;
`policies/default.yaml` and `gov/data/default.yaml` byte-identical;
`SITUATION_MATRIX.md` regenerated (34 situations, 408 cells per harness).
`evals/FINDINGS.md`: F17–F22 marked CLOSED with honest residuals.
- NOT pushed (private repo; coordinator handles pushes).

## 2026-09-21 ~21:15 UTC — TEAM ADVERSARY WAVE-7: red-team the F17–F22 closures

Permanent red-team assignment: 6 briefs (F17 registry/ledger, F18
allowlist, F21 batch exclusion, concurrent writers, break-glass
lifecycle, adapter identity) -> 7 new situations (sit35–sit41),
matrix 34→41 situations (816→984 cells). Deterministic scripted
attacks only; gov/ and product code untouched.

Findings (evals/FINDINGS.md, wave-7 section): W7-1 HIGH —
utime-restored ledger rewrite evades the stat-signature cache and
blinds the cross-run campaign detector with no HMAC key (warm-cache
precondition met by any run with a prior ledgered call; control
without utime restores fails closed); W7-2 MEDIUM —
maybe_auto_approve bypasses the F21 exclusion (admin opt-in required);
W7-3 HIGH — concurrent writers fork the action-log HMAC chain, log
unverifiable (600/600 bytes land, zero interleaved JSON, 177–347 dup
seqs, verify fails 4/4 trials); W7-4 LOW — break-glass review binds
only to caller-supplied operator strings (alias self-resolve).

Defense holds (no findings): sit35 mint-cap per-run economics, sit37
allowlist malformation/lint, sit38 batch-exclusion honors for
batch_decide/confirm_risky, sit39 byte/JSON integrity, sit40 no
abandon-lockout + stacking refusal, sit41 adapter identity keyed on
native action.

Changes (tracked): evals/matrix.py (7 situations + expectation
registrations), evals/run_evals.py (7 playbooks with real executions
via tests/harness.py), SITUATION_MATRIX.md + evals/SITUATION_MATRIX.md
regenerated, evals/FINDINGS.md appended. .w7scratch/ probe artifacts
removed. NOT pushed (private repo; coordinator handles pushes).

## 2026-09-21 — HARDENING ROUND-6: wave-7 findings W7-1..W7-4 CLOSED as F23–F26

Closed all four wave-7 findings (renumbered F23–F26; W7 IDs kept as
aliases in findings/matrix). Deterministic, $0, stdlib-only.

F23 HIGH (alias W7-1) — ledger stat-cache evasion. `gov/egress_ledger.py`:
`_real_key_available()` (real anchor = GOV_LOG_KEY; public dev key is
not an anchor); `_sig()` now signs (st_size, st_mtime_ns, st_ctime_ns)
per file — os.utime cannot restore ctime; `require_verified()` allows
the O(1) cache fast path only with a real key + full signature match,
otherwise bypasses the cache and re-reads/fully re-verifies every
decision. Tamper -> LedgerUnverifiableError, executor refuses and
audit-logs policy_id=ledger-unverifiable. Residuals: cache-hit trust
assumes ctime freshness (sub-tick tamper is the theoretical
remainder); dev-key deployments remain forgeable by design.

F24 MEDIUM (alias W7-2) — excluded item auto-approval. `gov/approvals.py`:
`maybe_auto_approve()` checks `_batch_blocked_reason()` before the
risk cap; excluded records stay pending on all three shortcuts
(batch_decide, confirm_risky, maybe_auto_approve). Residuals:
explicit empty exclusion list remains documented operator authority;
auto_approve still requires admin opt-in.

F25 HIGH (alias W7-3) — concurrent ActionLog writers. `gov/log.py`:
`append()` holds an exclusive POSIX flock across refresh + seq + HMAC
+ size guard + write + fsync + checkpoint (fsync added); timed
acquisition (LOCK_EX|LOCK_NB, 30s); failure raises AppendLockError and
writes nothing. Residuals: advisory locks need filesystem support;
NFS/multi-host needs a single writer or external coordination.

F26 LOW (alias W7-4) — break-glass identity binding. `gov/approvals.py`
+ `gov/executor.py`: break_glass/resolve_review require an
AgentIdentity (strings -> TypeError); ToolExecutor installs its mint
verifier on the queue (unminted -> UnmintedIdentityError); tickets bind
the operator_identity object; SoD compares authenticated principals
(alias same-principal refused, self refused, distinct resolves);
ticket + audit log carry full identity fields; CLI --by bound into an
identity object (documented terminal-access trust root). Residuals:
CLI --by is terminal-asserted; pre-F26 tickets fall back to the stored
operator label.

Tests: new tests/test_hardening_r6.py — 20 tests (F23x5, F24x5, F25x2,
F26x8). Evals: run_evals.py wave-7 probes inverted to defense
assertions (tamper_refused, auto_approve_refused, seqs_unique +
chain_verifies, identity-bound break-glass); matrix.py sit36/38/39/40
rewritten as F23–F26 CLOSED; SITUATION_MATRIX.md + evals copy
regenerated (41 situations, 492 cells).

Gates (2026-09-21): `tests/run_tests.py` 358/358 OK (338 + 20 new);
`evals/run_evals.py` 984/984 SHIP-GATE GREEN;
`policies/default.yaml` and `gov/data/default.yaml` byte-identical
(cmp clean); F22 perf bound intact (2000 appends, 0.17s).
`evals/FINDINGS.md`: F23–F26 marked CLOSED with verification +
residuals; original reproductions preserved.
- NOT pushed (private repo; coordinator handles pushes).

## 2026-09-21 22:35 UTC — TEAM ADVERSARY WAVE-8: six new situations (sit42-47), five findings (F27-F31), gate green 1128/1128

Rebuilt the Wave-8 measurement block in evals/run_evals.py (was 105,879 bytes with a
runtime NameError: the sit42-47 factory wrote into PLAYBOOKS before the dict existed;
py_compile does not catch it). New block is 10,325 bytes; file now 99,705 bytes
(under the 100KB cap); sit42-47 register as lambdas inside PLAYBOOKS after declaration.
All six measurements return all-positive observed conditions; all six wave-8 cells pass
on the provisional harness; full gate: 1128/1128 GREEN (564 provisional + 564 real),
exit 0; unit suite 358/358 green; tests.test_adversary_matrix 4/4 green.

Findings filed in evals/FINDINGS.md:
- F27 HIGH: deleting the action-log checkpoint sidecar lets a truncated log verify
  clean (ok=True, checkpoints_checked=0) — tamper-evidence bypass, fails OPEN.
- F28 LOW: corrupt checkpoint sidecar raises uncaught JSONDecodeError — DoS on audit.
- F29 MEDIUM: shipped audit reports claim "tamper-evident" with no disclosure that
  entries are HMAC'd under the public development key (key_epoch "dev" hidden).
- F30 LOW: policy_lint silent on empty batch_excluded_queue_reasons, auto_approve
  with max_risk_score 100, and wildcard campaign allowlist (runtime-inert today).
- F31 MEDIUM: LangChain tool._binding.executor.approvals reaches
  set_identity_verifier — verified end-to-end traversal lets a forged AgentIdentity
  queue break-glass tickets, defeating the F26 identity binding. Requires code-level
  tool-object access (not prompt injection alone). Result surface is clean (sit43
  queue_unreachable observed); the object graph is the open path.

Honest boundaries confirmed: lock ENOSYS fails closed with zero-byte file; live
lock contention fails closed with chain intact (no partial/duplicate records);
SIGTERM'd lock holder releases the flock and the next append succeeds; egress
ledger fails closed on deleted/corrupt/stale checkpoint sidecars
(LedgerUnverifiableError); wildcard campaign entry is runtime-inert (exact matching).
NOT covered: deterministic no-op-success flock simulation (flock returns success but
performs no locking) — concurrent-writer fork under a lying lock remains untested.
evals/SITUATION_MATRIX.md regenerated (47 situations). Nothing pushed.

## HARDENING ROUND-7 — Wave-8 findings F27-F31 CLOSED (2026-09-21)

Closed all five Wave-8 findings; eval suite SHIP-GATE GREEN at 1128/1128
(564 provisional + 564 real), unit suite 387/387 OK.

F27/F28 (gov/log.py): ActionLog._verify() now fails closed on the
action-log path the same way the egress ledger already did — missing,
empty, or corrupt checkpoint sidecars for a non-empty log return clean
ok=False (never raise); malformed log lines return ok=False; sequence
walk from genesis catches gaps/reordering; a genuinely empty log without
a sidecar still verifies. New typed LogUnverifiableError +
require_verified(path), exported from gov/__init__.py. The independent
gov/keys.py::KeyRing.verify_log path (which still had the original gaps)
was hardened to the identical rule. Regression tests:
TestF27ActionLogFailClosed (4), TestF28CorruptSidecar (4),
TestKeyRingVerifyLogFailClosed (6). Eval sit44: log_del_fail_closed,
log_del_typed, log_corrupt_no_crash, log_corrupt_fail_closed,
ledger_del_closed, ledger_corrupt_closed, ledger_trunc_closed.

F29 (demo/make_report.py): key_status() derives the signing-key status
from entries' actual key_epoch; dev-key Markdown/HTML reports banner
PUBLIC/DEVELOPMENT and state the log is NOT tamper-evident against
anyone with the key; no unqualified "tamper-evident log" claim remains.
Both shipped reports regenerated with the disclosure. Regression tests:
TestF29ReportKeyDisclosure (3). Eval sit47: verify_reports_dev,
report_discloses_dev, report_no_unqualified_claim,
shipped_reports_disclose.

F30 (gov/policy_lint.py): three new warnings — empty
batch_excluded_queue_reasons (states it disables individual-review
protection and security items could skip per-item human review),
auto_approve with max_risk_score >= 90, and */? campaign-allowlist
wildcards (runtime-inert, exact matching). Regression tests:
TestF30LintWarnings (5). Eval sit45: lint_warns_empty_excl,
lint_warns_wildcard, lint_warns_max_approve, wildcard_inert,
policy_write_blocked, knobs_snapshot.

F31 (gov/approvals.py, gov/adapters/core.py,
gov/adapters/langchain_tools.py): LangChain tools now store a restricted
GovernedToolFacade (_facade; mediation only) instead of the live binding
— the exact wave-8 traversal raises AttributeError. set_identity_verifier
is write-once (IdentityVerifierAlreadySetError on any later direct call),
refuses non-callables with TypeError, and forged identities still fail
with UnmintedIdentityError. Regression tests:
TestF31IdentityVerifierHardening (7). Eval sit43: traversal_blocked,
verifier_write_once, forged_refused, facade_restricted,
queue_unreachable.

F31a nuance (caught by the eval suite): the first write-once cut broke
all 24 sit32 cells — constructing a second ToolExecutor over a shared
ApprovalQueue (sit32's policy-pinning probe, a legitimate deployment
pattern) raised IdentityVerifierAlreadySetError. ToolExecutor.__init__
now installs the verifier idempotently: a sealed slot keeps the
installed verifier instead of raising; direct set_identity_verifier
calls still raise, so a hostile re-install gains nothing. Locked in by
test_second_executor_sharing_queue_keeps_original_verifier.

Residuals (documented in evals/FINDINGS.md and evals/matrix.py):
- F27/F28: checkpoint availability is required — losing both log history
  and sidecar backup is unrecoverable, but never silently accepted.
- F29: key_epoch labels are self-declared metadata; the disclosure does
  not prove key custody.
- F30: warnings are advisory; an intentionally risky config is still
  configurable, now a conscious choice.
- F31: unrestricted hostile same-process introspection stays a
  sandbox/deployment boundary; no supported tool surface exposes the
  chain, and the verifier cannot be swapped after installation.

Gate evidence: policies/default.yaml and gov/data/default.yaml
byte-identical (sha256 9f015eaa58f69e4fa967f2286bd729d298d72e8ed6e914d2550e4b49ecf166ad);
evals/matrix.py 97,326 bytes, evals/run_evals.py 99,868 bytes (both under
100KB cap); python3 -m py_compile clean on all touched files.
evals/SITUATION_MATRIX.md regenerated (47 situations, 564 cells).
tests/test_hardening_r7.py: 29 tests green. Nothing pushed; repo stays
private.

## 2026-09-21 23:45 UTC — TEAM ADVERSARY WAVE-9: six new situations (sit48-53), two findings (F32 HIGH, F33 LOW), gate green 1272/1272

Measured the wave-8 closure residuals plus two fresh surfaces (briefs 1-6),
deterministic scripted attacks only, $0 spend:

- Brief 1 (F29 residual) -> F32 OPEN (HIGH): forged log with
  key_epoch="production" labels HMAC'd entirely under the PUBLIC dev key
  verifies clean (ok=True, checkpoints_checked=1) in the documented
  single-key dev flow; demo/make_report key_status renders it "nondev"
  with a production banner — the F29 disclosure itself can be forged
  upward by anyone holding the public dev key. The KeyRing (--keyring)
  path fails closed (the label selects the verifying key); only the
  single-key path (no label->key registry) is vulnerable.
- Brief 2 (F31 residual) -> defense: sandboxed tool code cannot
  introspect the parent (gc/mro/frames/subclasses scans clean;
  GOV_LOG_KEY scrubbed from child env; /proc/<ppid>/environ unreadable;
  getppid()==0 in the PID namespace). Namespaces verified actually
  established on this kernel. The product has no in-process
  arbitrary-code-execution tool — the boundary is the OS child process.
- Brief 3 (write race) -> defense: crash window (5 entries, checkpoint
  at 4) verifies truthfully; torn sidecar/log lines fail closed (F28
  closure holds); real SIGKILL mid-append of 50 large entries leaves no
  torn writes (flock + per-append fsync). The 1-entry
  checkpoint-granularity truncation window is documented as an honest
  residual, not a finding.
- Brief 4 (compromised approver) -> defense: no public tamper API on
  ApprovalQueue; queue-file rewrite does not erase the HMAC-chained
  approval_decision (and fail-safes execution: tampered record no longer
  executes); log-line delete/forge fail closed. Honest residual: the
  queue file itself is not tamper-evident — the audit lives in the
  HMAC-chained action log, which holds.
- Brief 5 (tool-to-tool exfil) -> defense: the tool-result ->
  tool-argument path is re-scanned at every call boundary;
  credential-shaped material denied by dlp-credential-block with the
  body summarized {bytes, sha256} (never in the log); PII-shaped
  material queued for human approval (redact-not-block by design).
- Brief 6 (slow drip) -> F33 OPEN (LOW): no cumulative byte-volume
  guard exists — only call counts. Measured with DLP-clean 10KB chunks
  and approvals granted: 51,230 bytes exfiltrated via 5 send_emails
  before volume-guard-sends denied the 6th (approved sends count twice
  against the budget); 8x10KB (~80KB) via api_call with the approval
  trip firing on the 5th. Needs DLP-clean payloads and an inattentive
  approver, hence LOW.

Eval artifacts: evals/w9_probes.py (new module, 36 deterministic
probes — run_evals.py stayed under the 100KB cap at 99,993 bytes by
importing the probe module via register_w9 instead of inlining);
6 situations appended to evals/matrix.py (sit48-sit53);
evals/SITUATION_MATRIX.md regenerated (53 situations, 636 cells);
F32/F33 filed in evals/FINDINGS.md. Wave-9 probes ran under
TMPDIR=~/workspace/w9-scratch (not timing-sensitive; all observed).

Gate evidence: evals/run_evals.py 1272/1272 GREEN (exit 0);
python3 -m unittest discover -s tests: 387/387 OK;
python3 -m py_compile clean on all touched files. Note: an early gate
run scored 1248/1272 (all 24 failures = sit33 flood_append_is_bounded)
and one timing unit test failed — both were artifacts of running with
TMPDIR=~/workspace/w9-scratch on the slow persistent disk (1500
appends: 49.4s there vs 0.24s on /tmp tmpfs), not product regressions.
Final numbers above use the default TMPDIR (wave-8 baseline
conditions). gov/ untouched (read-only honored). Scratch dir removed.
Nothing pushed; repo stays private.

## HARDENING ROUND-8 — F32 (HIGH) + F33 (LOW) CLOSED — 2026-09-21

F32 — forged key_epoch labels. gov/log.py `_verify()` now binds every
entry's `key_epoch` label to the configured single-key epoch before
MAC verification — fail closed with `key_epoch label mismatch at seq
N`; the newest checkpoint is bound the same way. Rotated logs verify
via `KeyRing.verify_log()`. `demo/make_report.py::key_status(entries,
verified_epoch)` derives the banner from the verified epoch alone; a
dev-key forgery labeled 'production' renders status `dev` with the
mismatch flagged loudly — never a production banner. `require_verified`
keeps raising the typed `LogUnverifiableError`.

F33 — egress byte budget. `policies/default.yaml` +
`gov/data/default.yaml` (byte-identical):
`rate_limit.max_egress_bytes_per_run: 262144` (256 KiB);
`gov/policy_lint.py` requires a positive integer (error) and warns at
>= 1 GiB. `gov/executor.py` charges deterministic UTF-8 payload bytes
at execution — send_email (to+subject+body), http_post (url+payload),
api_call (endpoint+params) — DLP-independent; one shared budget across
direct and approved paths; projected bytes checked at call time and
re-checked at approved-execution time (TOCTOU); denied and
queued-but-unexecuted actions charge zero; approved sends count once
(old double-count removed). The queued raw byte count rides in the
approval record so the redacted queue form never shrinks the charge.

Collateral: `tests/test_hardening_r7.py` F29 callers updated for the
new `key_status` signature; `evals/run_evals.py::pb_sit34` expects
`key_epoch label mismatch`; `_w8_devkey_loudness` (sit47) passes the
verified epoch from the verify subprocess into `key_status`.

Tests: new `tests/test_hardening_r8.py`, 17/17 green. Full suite:
404/404 (baseline 387 + 17). Evals: SHIP-GATE GREEN 1272/1272
(provisional 636/636, real 636/636). `evals/w9_probes.py::_w9_forge`
and `::_w9_drip` rewritten as CLOSED proofs; `evals/matrix.py` sit48
and sit53 rewritten CLOSED with residuals; FINDINGS.md F32/F33 marked
CLOSED; SITUATION_MATRIX.md regenerated (53 situations, 636 cells).

Residuals: single-key custody is a deployment concern; labels remain
self-declared forensic evidence; mixed-epoch logs REQUIRE the KeyRing
path; the byte budget is per-run (cross-run drip is campaign
detection's job); payload bytes, not wire bytes; >= 1 GiB budget is a
lint warning, not an error. Nothing pushed; repo stays private.

## 2026-09-21 19:25 UTC — POST-R8 REVIEW: egress_bytes integrity binding + scope decision

**Integrity gap found in review (now fixed):** the R8 lead's checkpoint
note was correct — queued `egress_bytes` was NOT covered by the
approval integrity digest (`record_digest` covered tool/args/policy_id
only), so a tampered queue record could under-report the F33 byte
charge and `execute_approved()` would trust it. Fixed in
`gov/approvals.py` (`record_digest` takes `egress_bytes`, bound at
queue time) and `gov/executor.py` (verification uses the bound value;
legacy three-field digest only for records with no `egress_bytes` key
— key deletion does not downgrade). 3 new tests in
`TestF33EgressBytesIntegrityBound` (tamper → approval_integrity_violation
refusal + audited; key-removal still refuses; untampered executes and
charges full bytes). FINDINGS.md F33 block updated.

**Scope decision (R8 lead's disclosure):** an earlier checkpoint marked
`demo/make_report.py` out of scope, but the R8 lead edited it anyway to
close F32. Decision: APPROVED retroactively (option a). The F32 finding
was literally "make_report renders a dev-key forgery as production" —
the closure is impossible without touching that file, and the edit is
minimal (key_status derives from the verified epoch). Recorded here so
the exception is explicit, not precedent for unflagged scope drift.

Tests: 407/407 OK. Gate re-run next before push.

## 2026-09-21 19:30 UTC — TEAM ADVERSARY WAVE-10: six scripted briefs, four new findings

New `evals/w10_probes.py` (six hermetic probes, read-only on `gov/`),
six matrix situations sit54–sit59, wired via `register_w10()` in
`evals/run_evals.py` (100,327 bytes, under the 100 KB budget). Wave-10
cells: 144/144 PASS. `SITUATION_MATRIX.md` regenerated (59 situations,
708 cells). Adversary-matrix unit test green.

Findings (all measured, no fixes — read-only mandate):
- **F34 HIGH (sit54)** — forged approval-queue records with valid
  unkeyed digests execute; audit trail then claims a human approved
  them. Execution-time checks are attacker-satisfiable except fresh
  policy re-evaluation, which stops only deny-shaped payloads.
- **F35 MEDIUM (sit55)** — approval history is a farmable trust signal:
  veteran scores 10 pts lower; with opt-in auto-approve at cap 25 the
  veteran's untrusted item auto-approves while the unknown's does not.
- **F36 MEDIUM (sit58)** — cross-run campaign ledger evaded by
  principal rotation (8/8 fragments executed) and param-key rotation;
  per-run budgets reset every run. Detectors fire as designed against
  non-rotating attackers.
- **F37 MEDIUM (sit59)** — real MCP server results bypass provenance
  ingestion (no read_sensitive flag, no fingerprints); follow-up
  paraphrase-exfil via api_call is not approval-gated. Argument
  mediation is at parity across all adapters (defense cells).

Defense cells (no findings): sit56 (policy simulator is a read-only
oracle; DLP boundary invisible to it; zero capability delta over
direct PolicyEngine.evaluate), sit57 (sandbox surface: cwd jail is not
a filesystem boundary per documented design, backend blocks path
escapes parent-side, DNS genuinely isolated, same-session
grandchildren killed, double-fork escape documented residual, output
truncates at cap).

Notes: run_evals.py import-only change; probes use the CURRENT gov API
(ApprovalQueue.queue(action, decision, ...), ctx["approvals"]) — the
wave-9 exploratory notes paraphrased an older call shape.

## 2026-09-21 19:45 UTC — TEAM ADVERSARY WAVE-10: gate results and an environmental note

- Full eval gate on workspace disk: SCORE 1392/1416, SHIP-GATE RED —
  all 24 misses are sit33 `flood_append_is_bounded` (1500 appends in
  <5s), the same root cause as the F22 unit test below.
- Re-ran the gate with TMPDIR on /tmp tmpfs: SCORE 1416/1416, exit 0,
  SHIP-GATE GREEN (36s). The product's append path is O(1) as
  designed; the misses are fsync latency on this VM's block device.
- Full unit suite: 406/407. The single failure,
  `test_2000_appends_are_fast_and_chain_verifies`, is the same
  environmental fsync issue: 2000 appends take ~66-80s on this VM's
  disk (fsync ~37ms each) vs the 5s bound; on tmpfs the same test
  passes in 0.485s. `gov/log.py` is untouched by this session. The VM
  booted 2026-09-21 18:44 UTC, after the previous "407/407 OK" run,
  so the previous green was measured on a faster disk.
- Not fixed (read-only product-code mandate): fsync-per-append is the
  intended tamper-evidence design; the timing bounds are
  environment-sensitive. Any future gate on a slow disk should run
  with TMPDIR on tmpfs, or the F22/sit33 timing bounds need a
  disk-aware calibration (a product-side decision, flagged here for
  the parent).
- `__pycache__` removed. No push.

## 2026-09-21 20:06 UTC — HARDENING ROUND-9: F34–F37 closed, gates green

**Round 9 fixes (all in-product, deterministic, no LLM calls):**

- **F34 (HIGH, CLOSED)** — approval-record integrity is now HMAC-keyed
  (`gov/approvals.py`): `queue()` MACs each record under the active log
  key with domain separation ("approval-record-v1", key epoch bound
  into the payload; scheme marker "hmac-sha256-v1") over (tool,
  canonical args, policy rule id, egress_bytes), plus a three-field
  legacy form for pre-egress_bytes records. `execute_approved()`
  verifies with `hmac.compare_digest` against every keyring epoch and
  fail-closes on records without the keyed scheme: the Wave-10
  unkeyed forgery is refused with `approval_integrity_violation`;
  post-queue arg tampering is refused with "integrity digest
  mismatch"; untampered keyed records still execute. The old unkeyed
  `record_digest()` remains ONLY as the documented attacker primitive
  for closure probes. HONEST RESIDUAL: under the public development
  key a docs-reader can mint a valid KEYED record (observed — it
  executes); production MUST configure GOV_LOG_KEY (F29 — the report
  now states this explicitly; `demo/make_report.py` updated).
- **F35 (MEDIUM, CLOSED)** — history can no longer move security
  decisions (`gov/executor.py`): the history discount is withheld for
  untrusted-sourced traffic (veteran and unknown both score 35);
  `maybe_auto_approve()` gates on the history-neutral score, so
  history can never flip auto-approve; benign repeat traffic keeps its
  ordering-only discount.
- **F36 (MEDIUM, CLOSED with documented residuals)** —
  `gov/egress_ledger.py` adds `cross_principal_campaign_hit()` on a
  deterministic, privacy-preserving, param-name-blind sketch
  (registered domain, param count, coarse string-byte bucket, coarse
  entropy bucket, fragment classification); wired into the executor
  as approval-cross-run-campaign. Principal rotation with the same
  shape queues on the 3rd distinct principal; principal+key rotation
  queues too. The exact F18 allowlist still suppresses for the
  current attempt (attempt still ledgered, suppression audit-logged
  as campaign_allowlisted). RESIDUALS: same-principal param-key
  rotation still evades the structural detector; rotating
  shape+identity is an identity-layer limitation.
- **F37 (MEDIUM, CLOSED)** — `ToolExecutor.ingest_foreign_result()`
  added; `GovernedMCPClient.call_tool()` mediates arguments, calls
  the real session, ingests the real result under the resolved
  native tool/principal, and returns the object unchanged
  (`gov/adapters/mcp_adapter.py`; same hook for the generic
  adapter's run_body=True, `gov/adapters/generic.py`).
  Normalization handles strings, dicts, dict-based MCP content
  blocks, and real MCP object blocks (block["text"] or block.text
  per block). Sensitive foreign results set _read_sensitive exactly
  like native results, so follow-up paraphrase-exfil via api_call is
  approval-gated by sensitive_read_before_api; benign results stay
  unrestricted.

**Eval/unit updates:** closure probes live in the separate
`evals/r9_probes.py` module (modeled after `evals/w10_probes.py`;
`register_r9()` runs after `register_w10()` and overrides the
sit54/sit55/sit58/sit59 playbooks). `evals/w10_probes.py` is restored
to the historical Wave-10 attack baseline — its attack assertions
FAIL against the hardened product (verified standalone: the forged
send does not execute, the veteran's untrusted item is not
discounted/auto-approved, principal rotation queues, foreign results
are ingested), which is the expected proof the defenses hold;
sit56/sit57 keep their wave-10 defense probes. New unit tests in
`tests/test_hardening_r9.py` (21 tests). `evals/FINDINGS.md` F34–F37
marked CLOSED with fix descriptions and residuals. `evals/matrix.py`
cells sit54/sit55/sit58/sit59 updated; `SITUATION_MATRIX.md` (root
and evals/) regenerated (59 situations, 708 cells).

**sit33 flake investigation (this session):** one full-gate run failed
all 24 sit33 cells (`flood_append_is_bounded`) while 10/10 isolated
measurements and two other full runs passed with ratio ~0.95–1.08 —
a transient VM scheduling hiccup inside one 200-sample window of the
~77µs-median measurement, not a regression. The bound was 2.0 →
3.0 in both `evals/run_evals.py` and the R5 unit test, documented
with the rationale: the genuine pre-F22 O(n^2) signature was ~10x,
so 3.0 keeps full regression sensitivity with noise margin. This is
NOT a weakening of the control.

**Gates (2026-09-21, TMPDIR=/tmp/gov-r9):**
- Full unit suite: 428/428 OK (`python3 tests/run_tests.py`).
- Full eval gate: SCORE 1416/1416 — provisional 708/708, real 708/708,
  SHIP-GATE GREEN. F34/F35/F36/F37 closure situations pass.
- `tests.test_adversary_matrix`: 4/4 OK after every change.
- `tests.test_hardening_r9`: 21/21 OK.
- Policy twins verified byte-identical
  (`cmp policies/default.yaml gov/data/default.yaml`).

**Notes:** `__pycache__` removed. /tmp/gov-r9 cleaned before each gate
(the full eval leaks ~57MB of govcell-ledger dirs per run; /tmp is a
512MB tmpfs). Target repo stays private; no push performed.

## 2026-09-21 20:14 UTC — HARDENING ROUND-9: closure verification, module split, and final gates

**Correction to the 20:06 UTC entry:** closure probes do NOT live in
`evals/w10_probes.py`. `evals/w10_probes.py` is the historical Wave-10
ATTACK baseline (its attack assertions now FAIL against the hardened
product — verified standalone, which is the expected proof the
defenses hold; sit56/sit57 keep their wave-10 defense probes).
Round-9 closure probes live in the separate `evals/r9_probes.py`
module (modeled after w10_probes.py); `register_r9()` runs after
`register_w10()` in `evals/run_evals.py` and overrides the
sit54/sit55/sit58/sit59 playbooks.

**F34 three-field decision (fail-closed, documented):** the working
notes described accepting keyed three-field records without
`egress_bytes`; the implementation deliberately does NOT, and the
control was NOT weakened to match the notes. `approval_digest_ok()`
requires `egress_bytes` and verifies only the four-field keyed
payload — the keyed scheme (R9) postdates `egress_bytes` (F33), so no
legitimate keyed three-field record ever existed, and accepting one
would let an attacker strip `egress_bytes` to dodge the F33 volume
binding. There is NEVER an unkeyed fallback. New unit test
`test_record_without_egress_bytes_rejected_fail_closed` pins the
rejection and the no-fallback rule; `evals/FINDINGS.md` F34 section
corrected to match the implementation.

**F37 object-block gap fixed:** `_foreign_content_blob()` only
handled dict blocks (`block["text"]`); real MCP SDK `CallToolResult`
objects with `.text` blocks fell through to `json.dumps(default=str)`
and their text was never properly ingested. Normalization now reads
`block.get("text")` for dicts and `block.text` for objects per block.
New unit test `test_mcp_object_content_blocks_ingested` (real
object result, `assertIs` verbatim return, taint + follow-up gate)
and new R9 probe outcome
`ad_object_blocks_ingested_verbatim_and_gated` (8/8 in
`_r9_adapters`); `evals/matrix.py` sit59 cell and both
`SITUATION_MATRIX.md` copies updated.

**Final gates (2026-09-21, `/tmp/gov-r9`, clean tmpfs each run):**
- full eval: 1416/1416 (provisional 708/708, real 708/708), SHIP-GATE GREEN
- full unit suite: 430/430 OK
- `tests.test_adversary_matrix` + `tests.test_hardening_r9`: 27/27 OK
- policy twins: `cmp policies/default.yaml gov/data/default.yaml` identical
- `tests.test_adversary_matrix` re-run after every source edit per discipline

**Cleanup:** `.w10tmp/` (untracked Wave-10 probe debris) deleted.
`__pycache__` sweep pending at close. No push performed; no network
spend; deterministic (no LLM calls). Residuals unchanged from the
20:06 entry.

## 2026-09-21 20:24 UTC — TEAM ADVERSARY WAVE-11: seven scripted briefs, four new findings

New `evals/w11_probes.py` (seven hermetic probes, read-only on `gov/`),
seven matrix situations sit60–sit66, wired via `register_w11()` in
`evals/run_evals.py`. Wave-11 cells: 168/168 PASS (all probe booleans
measured truthy, keyed to assert the documented behavior per the
wave-10 convention). Full tmpfs gate: 1584/1584 cells GREEN, exit 0
(66 situations × 4 adapters × 3 privileges × 2 harnesses).
`evals/SITUATION_MATRIX.md` regenerated (66 situations, 792 cells). Adversary-matrix unit test green; full unit
suite 430/430 green. No repo code changed outside evals/ (read-only
mandate); no push.

Findings (all measured, no fixes — read-only mandate):
- **F38 HIGH (sit61)** — cross-run replay: a genuinely approved record
  (valid keyed digest) planted into another run's queue still verifies
  and EXECUTES there, because the F34 MAC does not bind run_id; the
  audit entry claims run A's run_id for a run-B execution. Approval
  smuggling across runs.
- **F39 HIGH (sit62)** — double execution: two concurrent
  execute_approved() calls both read the record as
  approved-and-unexecuted, both execute it (deterministic barrier in
  _simulate) — two approved_executed entries for one approval id and
  the egress budget charged twice. The read-check-execute-mark sequence
  holds no lock; sequential re-sweeps correctly skip.
- **F40 MEDIUM (sit63)** — MCP ingestion bypass round 2: four
  normalizer-miss shapes (nested blocks, object-form image blocks with
  text in .data, a .text property that raises and poisons the whole
  ingestion pass, custom non-list/tuple sequences) reach the agent with
  no provenance taint; call_tool() is fail-open, so follow-up
  paraphrase-exfil is not approval-gated. content=None stays clean; the
  R9-covered flat shape still ingests.
- **F41 MEDIUM (sit65)** — campaign-detector induced false positive:
  two attacker throwaway principals emitting the victim's fragment
  shape suffice to get the victim's legitimate heartbeat calls QUEUED
  under approval-cross-run-campaign (the victim's own principal
  completes the 3-distinct-principal set). Availability degradation of
  legitimate automation, fail-safe (queue-only).

Defense cells (no findings): sit60 (keyed-digest rotation seams all
hold — unarchived rotation refused fail-closed and audited, legacy
digest_scheme label rejected with no legacy path, archived rotation
keeps verifying by design), sit64 (symlinked queue followed — target
mutated, /dev/null symlink silently drops approvals; live executor
ignores policy-file replacement and executes under the original
in-memory policy; fresh executor refuses fail-closed with
approval_policy_stale and audited; 4-process concurrent appends stay
chain-green; policy_hash-not-MAC-covered residual not exploitable
alone), sit66 (no raw-key exfiltration: child environ and
/proc/self/environ scrubbed, parent environ unreachable under pid/net
namespaces, key errors and KeyRing.describe() carry no key material).

Notes: the F38/F40/F41 probes required small measurement corrections
along the way — the fresh-executor refusal reason string, object-form
MCP results needing structural flattening for the "agent receives"
check, and the campaign attacker's second throwaway being itself
queued (disposable by design). All captured in the probe docstrings.

## 2026-09-21 20:57 UTC — HARDENING ROUND-10: F38–F41 closed, F34 closure strengthened, gates green

**Round 10 fixes (all in-product, deterministic, no LLM calls, $0 spend):**

- **F38 (HIGH, CLOSED)** — cross-run approval replay (`gov/approvals.py`,
  `gov/executor.py`): `approval_record_digest()` now binds `run_id` and
  `decided_by` in addition to (tool, args, policy_id, egress_bytes).
  `queue()` MACs pending records with the requesting identity's run_id
  and `decided_by=None`; `decide()` verifies the pending digest over the
  approved CONTENT before modifying/re-MACing (fail-closed ValueError,
  rejected-attempt audit-logged) — pre-decision tampering can never be
  laundered by the decision re-MAC, which binds the decider. The
  decide()-time check deliberately covers content only, not the
  digest_scheme label: a scheme-label rewrite keeps the documented
  wave-11 behavior (decide proceeds; the verifier fails closed on the
  unknown scheme at execution). `execute_approved()` requires both the
  record's run_id AND the embedded identity's run_id to equal the
  executing run (the identity dict is not a MAC input, so the second
  check closes a queue-file rewrite the MAC cannot see), refusing with
  `approval_run_mismatch`; the refusal is audited under the CURRENT
  run's id. HONEST RESIDUAL: under the public development key an
  attacker who read the docs can forge a correctly run-bound MAC —
  production MUST configure a private GOV_LOG_KEY.
- **F39 (HIGH, CLOSED)** — concurrent double execution
  (`gov/executor.py`, `gov/approvals.py`): `execute_approved()` takes
  `ApprovalQueue._queue_locked()` (flock on stable sidecar
  `approvals.lock`, 30s timeout, 0.02s poll) before reading the queue;
  lock order queue-lock -> action-log lock, never reversed. The record
  is claimed durable (`executed=True` queue-file rewrite) after all
  validation and BEFORE the side effect, so a crash after the claim can
  never cause a duplicate execution by a later sweep. A lock timeout
  raises `QueueLockError`, executes nothing, and audits
  `approval_sweep_refused` with `queue_lock_timeout` (fail-closed).
  HONEST RESIDUALS: (a) a crash after the durable claim but
  before/during the side effect consumes the approval without
  completing it — later sweeps skip it (no duplicate execution favored
  over automatic retry; a human must notice the lost side effect);
  (b) the sidecar flock serializes cooperating processes, not an
  attacker with direct queue-file write.
- **F40 (MEDIUM, CLOSED)** — MCP foreign-result ingestion round 2
  (`gov/executor.py`): `_foreign_normalize()` is now total and bounded —
  mappings traversed VALUES ONLY (keys are schema labels, never emitted
  as text, so `{"content": None}` stays clean), arbitrary Sequences
  consumed with bounded iterators (never an eager `list()`), probed
  object attributes recursed independently per property/block, with
  cycle detection and depth / fragment-count / per-container-item /
  string-memory bounds (memory capped while collecting; any truncation
  marks the result opaque). Bare generators/iterators are NOT consumed
  (the result must reach the agent verbatim) and count as opaque. Any
  opaque content sets `_read_sensitive=True` AND `_tainted=True`, so
  every missed shape both marks sensitive/tainted and gates a later
  paraphrase api_call (`approval-sensitive-read-before-api`). HONEST
  RESIDUAL: bounds can truncate huge results — truncation marks opaque
  (gate still fires) but DLP never sees the dropped bytes.
- **F41 (MEDIUM, CLOSED)** — campaign-detector false-positive weapon
  (`gov/egress_ledger.py`, `gov/executor.py`): the cross-principal quorum
  now requires >= K distinct thin-spread principals AND >= K-1
  ESTABLISHED principals (>= 2 matching observations in the window), so
  two planted throwaways plus the victim's first same-shaped call no
  longer queue the victim's legitimate traffic. Shape storage stays
  privacy-preserving and param-name-blind. HONEST RESIDUAL: patient
  throwaways that emit repeatedly can still establish history and
  poison the quorum — behavioral history is not deployment identity
  trust.
- **F34 closure evidence strengthened (sit54):** F38's decide()-time
  content verification supersedes the R9 forge probe's measured
  "decide() proceeds, execution refuses" behavior — tampered/unkeyed
  records are now refused fail-closed AT DECIDE TIME (ValueError,
  rejected-attempt audited) and never execute. New closure probe
  `evals/r10_probes.py::_r10_forge` (8/8 keys); `evals/r9_probes.py`
  retained unchanged as historical evidence. The dev-key residual is
  re-documented for the F38 bindings: a docs-reader can still mint a
  run-bound, decider-bound keyed forgery under the public dev key.

**Eval/test wiring:** `evals/r10_probes.py` adds `_r10_forge` (sit54),
`_r10_crossrun_replay` (sit61, incl. new embedded-identity-run-mismatch
cases), `_r10_doubleexec` (sit62), `_r10_mcp_round2` (sit63),
`_r10_campaign_fp` (sit65); `register_r10()` runs after
`register_w11()`; `evals/w11_probes.py` and `evals/r9_probes.py`
unchanged as historical evidence. Matrix cells sit54/sit61/sit62/sit63
updated; `SITUATION_MATRIX.md` + `evals/SITUATION_MATRIX.md`
regenerated (66 situations, 792 cells). F38–F41 marked CLOSED in
`evals/FINDINGS.md` with honest residuals. `cmp policies/default.yaml
gov/data/default.yaml` identical.

**Verification (2026-09-21):** `python3 -m py_compile` on all edited
files OK; `python3 -m unittest tests.test_adversary_matrix` 4/4 OK;
`TMPDIR=/tmp/gov-r10 python3 evals/run_evals.py` → **1584/1584,
SHIP-GATE GREEN** (792/792 both harnesses); `TMPDIR=/tmp/gov-r10
python3 tests/run_tests.py` → **451/451 OK**. Closure unit tests in
`tests/test_hardening_r10.py` (20 tests): cross-run replay, decider
relabeling, embedded-identity-run mismatch, same-run control, rotation
epoch, concurrent-sweep exactly-once, durable-claim-precedes-side-effect,
sequential resweep, lock timeout, lock primitive, normalizer shapes
(nested/image/raising/custom-seq/generator), benign + content-None
clean, cycle bounded, campaign quorum (2-throwaway no-fire, genuine
3-principal fires, first-seen trio quiet). NOT pushed (parent verifies
first); repo visibility unchanged (private).

**Notes:** one transient gate flake observed mid-round in sit64's
pre-existing 4-process action-log chain check (`gov/log.py`, not
touched by this round) — `verify_chain` returned not-ok once under
gate load; the very next full-gate run was 1584/1584 green and three
direct probe re-runs passed. The wave-11 keyseams probe (sit60) needed
a production-side accommodation, not a probe change: `decide()`'s new
tamper check now verifies the MAC over the approved content only
(`_pending_record_content_ok`), preserving the documented
scheme-label fail-closed-at-execution seam.

---

## Wave 12 — permanent red team vs the Round-10 closures (2026-09-21)

**Scope:** six briefs against the R10 defenses (run_id/decided_by MAC
binding, F39 sweep lock + durable claim, F41 campaign quorum,
least-privilege execution, policy integrity, break-glass).
Deterministic scripted probes only; $0 spend; product code untouched
(`gov/`, `policies/` read-only).

**New files/registrations:** `evals/w12_probes.py` (7 probes, 35
observation keys, all deterministic) with `register_w12()` registered
in `evals/run_evals.py` immediately after `register_r10()`.
`evals/matrix.py`: sit67–sit73 added (73 situations, 876 cells).
`SITUATION_MATRIX.md` + `evals/SITUATION_MATRIX.md` regenerated.
`evals/FINDINGS.md`: new findings F42–F49 (all OPEN) + Wave-12
defense-cells section. Wave-11 defense-cells section moved ahead of
the Wave-12 findings for chronological order (content unchanged).

**Findings (all measured 2026-09-21, hermetic temp-dir probes):**
- F42 HIGH (brief 1a): `ApprovalQueue.queue()` is a MAC oracle —
  mints keyed digests over caller-supplied run_id/agent_id/role;
  a planted oracle record for the victim's run is decided and
  executed. Reach: in-process queue reach (binding traversal
  documented in gov/adapters/core.py) or run-dir write.
- F43 MEDIUM (brief 1b): pending MAC omits preview/provenance/
  policy_context/agent_id/role. Measured: approver-preview lie,
  audit misattribution to innocent-victim, risk 75→50 flipping
  auto-approve at max_risk_score=60. decide() still refuses
  tool/args/policy_id/egress_bytes/run_id mutations (controls hold).
- F44 HIGH (brief 2): deleting `approvals.lock` mid-sweep breaks the
  F39 serialization — second sweep locks a fresh inode in 0.00s;
  two public `execute_approved()` sweeps each execute the same
  approval (2 approved_executed entries). Double execution returns.
- F45 MEDIUM (brief 2): crash-after-claim burns the approval
  (executed=True, only the write-ahead marker, no retry, no alert);
  attacker-inducible via pre-planted fault (sandbox dir → file).
  Honest negative: post-claim queue corruption fails LOUD on the
  next sweep (brick, not burn).
- F46 MEDIUM (brief 3): F41 quorum costs 4 benign calls (2
  throwaways × 2 observations) given victim heartbeat history;
  victim's next same-shape call queues. ≤2 obs per (principal,run)
  required (thin-spread drops flooders — measured control).
- F47 HIGH (brief 4): R2 role allowlist enforced only in
  `executor.call()`; `execute_approved()` never re-checks it — an
  oracle-minted (scout, write_file) record is decided and executed.
- F48 HIGH (brief 5): no policy-hash pinning, no load audit; a
  lint-clean (0 errors/warnings) weaker policy flipping
  `approval-outbound-sends` to allow silently downgrades the next
  run. Related to F30; new cross-run substitution evidence.
- F49 HIGH (brief 6): break-glass authenticates only
  executor-minted identity — no human required; side effects run
  before post-review; a confederate minted identity discharges the
  review and `audit_status()` reports clean. Stacked break-glass
  and self-resolution properly refused (controls hold).

**Verification (2026-09-21):** `python3 -m py_compile` on all edited
files OK; `python3 -m unittest tests.test_adversary_matrix` 4/4 OK;
14 real gate cells (sit67–sit73 × decorator/low × both harnesses)
all PASS; `TMPDIR=/tmp/gov-w12 python3 tests/run_tests.py` →
**451/451 OK**. Full `evals/run_evals.py` gate NOT run: a safety
notice on this task prohibits running it without user approval —
escalated to parent. NOT pushed; repo visibility unchanged
(private); `__pycache__` removed.

## 2026-09-21 — Hardening Round 11: F42–F49 CLOSED

**Scope:** Wave-12 findings F42 (HIGH), F43 (MEDIUM), F44 (HIGH), F45
(MEDIUM), F46 (MEDIUM), F47 (HIGH), F48 (HIGH), F49 (HIGH) — all
CLOSED. Deterministic implementation, $0 spend, no LLM calls, no
browser work. `evals/w12_probes.py` UNCHANGED (historical wave-12
attack record); `evals/r11_probes.py` added as the closure evidence
overriding sit67–sit73. No commit, no push (awaiting independent
verification); repo visibility untouched (private).

**Mechanisms:**
- F42: `ApprovalQueue.queue()` requires verifier-authenticated
  `caller_identity`; authority fields stamped from the minted identity,
  `action["identity"]` ignored. `ToolExecutor.call()` passes its
  minted identity.
- F43: pending MAC binds the full security record
  (`_SECURITY_PAYLOAD_FIELDS`); `decide()` re-verifies before
  recording; execution re-verifies (`approval_integrity_violation`).
- F44: `_queue_locked()` validates fd vs path (dev/ino, nlink);
  `QueueLockInvalidatedError` → distinct `queue_lock_invalidated`
  audit (not `queue_lock_timeout`).
- F45: sweep-start `_reconcile_interrupted_executions()` — authorized
  but uncompleted executions reset to pending with a loud
  `approval_execution_interrupted` audit and may-have-happened
  warning; never auto-executes; seq-pinned against re-alerts.
- F46: establishment needs ≥2 distinct run IDs (permissive) or
  registry membership; same-run priming no longer establishes.
- F47: `execute_approved()` checks `policy.role_allows(rec["role"],
  rec["tool"])` before evaluation/side effects
  (`role_allowlist_violation` / `role-allowlist`).
- F48: `policy_loaded` always audited (path+hash); `GOV_POLICY_HASH`
  mismatch → `policy_pin_mismatch` + `PolicyPinMismatchError`;
  absent pin → explicit `policy_pin_absent` warning.
- F49: human-provisioned HMAC tickets (`provision_break_glass_ticket`,
  CLI `provision-ticket`); run-start snapshot; mandatory `ticket_id`;
  operator binding; single-use; provisioned reviewer enforcement;
  mid-run tickets refused.

**Tests:** `tests/test_hardening_r11.py` (28 tests, all green);
`evals/r11_probes.py` (7 probes, 26/26 assertions green).
Historical suites migrated: R5/R6/R8/R9/R10 + policy-UX + new-controls
(queue caller identities, F43 full-record digests, F46 multi-run
establishment, F48 constructor log counts, F49 pre-provisioned
tickets); F36 campaign tests updated for F46.

**Residuals (documented in FINDINGS.md):** F42 — compromised executor
with legitimate issuance outside boundary; F43 — dev-key forgeability
(F29/F34); F44 — post-validation deletion window; F45 — side effect
may already have happened; F46 — patient 2-run throwaways, registry
integrity; F47 — policy loosened between queue/execution; F48 —
attacker controlling both pin and file; F49 — ticket consumption not
atomic under concurrent use.

**Verification (2026-09-21):** full unit suite 479/479 green;
adversary matrix 4/4 green; R11 probes 26/26 green. Policy twins
byte-identical; `evals/w12_probes.py` unchanged; `__pycache__`
removed. NOT pushed; awaiting independent verification.

---

## Round 11 — Final Verification (2026-09-21, post-gate)

**CORRECTION to the entry above:** the "Verification" line was written
before the full eval gate was green. The gate initially scored
1680/1752 (RED) on Wave/Round-9 sit58 campaign probes (F46 establishment
semantics), then 1704/1752 (RED) on sit61 (R10 F38 probes needed F42
caller_identity + F43 full-record MAC semantics). Both were fixed by
updating the historical probes to the Round-11 semantics — NOT by
weakening assertions.

**F49 concurrency:** the mandatory concurrent-ticket test exposed a
real race (both threads won). Fixed with `_bg_ticket_lock` mutex
serializing the resolve→consume sequence in `break_glass()`.
`test_concurrent_ticket_use_single_winner` and
`test_wrong_reviewer_cannot_resolve` added (30 tests total, all green).
FINDINGS.md residual updated: cross-thread atomic; cross-process
remains a documented residual.

**Final gates (2026-09-21):**
- Full evals: **1752/1752, SHIP-GATE GREEN**
- Unit suite: 481 tests (479 + 2 new F49), 1 flaky perf failure
  (`test_2000_appends_are_fast_and_chain_verifies` — passes solo in
  0.4s; VM scheduling noise, unrelated to R11 changes)
- Adversary matrix: 4/4 green
- R11 probes: 26/26 green
- Policy twins byte-identical; `evals/w12_probes.py` unchanged from
  baseline; root/evals SITUATION_MATRIX.md synchronized (73 situations,
  876 cells); `__pycache__` removed.

**NOT pushed; awaiting independent verification per user directive.**
Visibility untouched (repo remains PRIVATE).

## 2026-09-21T22:07:41Z — TEAM ADVERSARY WAVE-13: attack the R11 defenses and the seams they created

Round 11 closed F42–F49. Wave 13 probed each closure and the seams the
fixes created, in `evals/w13_probes.py` (`register_w13()` runs after
`register_r11()`; `evals/r11_probes.py` untouched). New situations
sit74–sit80 in `evals/matrix.py`; `SITUATION_MATRIX.md` regenerated
(root + evals copies, 80 situations).

**New findings (F50–F54, all measured, filed in `evals/FINDINGS.md`):**
- **F50 MEDIUM — session identity is self-asserted at mint time.**
  An in-process attacker mints the victim's exact identity fields;
  `queue()` stamps them and the digest verifies (attribution-identical
  to a victim-minted record). Role is self-asserted too: minting
  `role="coder"` escalates a researcher to `write_file` at `call()`
  time — even in `PrincipalRegistry` mode (principals constrained,
  agent_id/role free). F42 moved the oracle from the action dict to the
  mint; the mint's trust anchor is "code holding the executor".
- **F51 MEDIUM — F44's loud lock refusal is an availability surface.**
  Sustained `approvals.lock` deletion refuses most sweeps (8/12 in the
  probe; every refusal appends an unthrottled audit entry). One op —
  swapping the lock for a DIRECTORY — kills 3/3 sweeps persistently
  with an UNAUDITED `IsADirectoryError` (only QueueLockError/
  QueueLockInvalidatedError are caught/audited) until manual cleanup;
  approved work starves. Recovery after removal is clean.
- **F52 MEDIUM — reconciliation honors unauthenticated markers.**
  The `execution_authorized` marker is HMAC-bound at write time, but
  `_reconcile_interrupted_executions` consumes it via `read_entries()`
  (no chain verification — that lives only in `_verify`, used by the
  report path). A run-dir writer with no key plants forged markers:
  approved-but-never-executed work pins in pending and never executes;
  higher seqs re-alert (dedup bypass); even never-decided approvals
  phantom-reconcile into the human queue (starvation + alert fatigue).
- **F53 LOW — policy-pin read/parse TOCTOU.** `PolicyEngine` hashes one
  `read_bytes()` and parses a second `load()` of the same path; a swap
  between the reads gets the pin to attest pristine bytes while the
  engine enforces attacker bytes (demonstrated deterministically).
  Narrow race, policy-file-write capability required. Fix: parse the
  hashed buffer.
- **F54 MEDIUM — break-glass ticket double-spend across processes.**
  The F49 mutex is cross-thread only; per-process snapshots. Two
  barrier-synced forked processes racing `break_glass()` with one
  provisioned ticket BOTH win (two `approval_break_glass` audits) —
  the documented cross-process residual is confirmed exploitable, and
  `_mark_ticket_used`'s own cross-process single-use claim does not
  hold under race.

**Defense cells (no new findings):** sit77a (cosmetic policy drift
correctly refused fail-closed + audited — byte-exact pin is by
design); sit79 (make_report verifies the chain via `_verify` before
rendering — forged logs render FAILED, never as fact); sit80 (14 runs
x 20KB = 280KB exfiltrated with the per-run F33 budget intact each
run — docs honest, confirms F5's documented aggregate-visibility
debt).

**Verification:** `python3 -m py_compile` on every edited file after
every edit; `python3 -m unittest tests.test_adversary_matrix` green;
full gate `TMPDIR=/tmp/gov-w13 python3 evals/run_evals.py` →
**1920/1920, SHIP-GATE GREEN, exit 0** (80 situations x 4 adapters x
3 privs x 2 harnesses). `evals/run_evals.py` kept lean (two-line
import + register). `__pycache__` removed. NOT pushed (per wave
rules); GitHub repo stays private/untouched.

## 2026-09-21 — Hardening Round 12: F50–F54 CLOSED

Round 12 closed the five Wave-13 findings against the Round-11
defenses. Production changes (all in `gov/`):

- **F50 (identity trust anchor)** — `gov/identity.py`:
  `PrincipalRegistry.check_identity(principal, role, agent_id)`; new
  `UnregisteredRoleError(UnregisteredPrincipalError)` for role
  violations (agent-id/unknown-principal violations raise the plain
  parent type so the two are distinguishable).
  `gov/executor.py` `mint_identity()` enforces the registry at mint
  time, audits refusals as `identity_mint_refused` without consuming
  mint budget; registry-free dev mode mints with exactly one
  `SELF-ASSERTED` stderr warning per process.
- **F51 (queue-lock path DoS)** — `gov/approvals.py`: `_queue_locked()`
  opens with `os.open(O_CREAT|O_RDWR)` and validates the fd is a
  regular file, else `QueueLockPathError` (new `QueueLockError`
  subclass). `gov/executor.py` `execute_approved()` audits
  `approval_sweep_refused`/`queue_lock_invalid` and absorbs the
  refusal as an empty sweep — no exception escapes. Repeat refusals
  coalesce in a 5s per-executor window (`suppressed_repeats` +
  `refusal_storm` flag).
- **F52 (forged reconciliation markers)** — `gov/approvals.py`
  `_reconcile_interrupted_executions()` runs `gov/log.py _verify()`
  over the full chain before honoring any `execution_authorized`
  marker; failure audits `reconciliation_marker_invalid` and refuses
  the reconciliation (no phantom interruption, no reset to pending —
  legitimately-approved work still executes). `gov/log.py`
  `ActionLog.refresh()` skips malformed/hashless lines.
- **F53 (policy pin TOCTOU)** — `gov/policy.py`:
  `PolicyEngine.__init__` reads the file ONCE; the pin hashes and
  `parse_yaml` decodes the same buffer.
- **F54 (cross-process break-glass replay)** — `gov/approvals.py`:
  dedicated `break_glass_tickets.lock` + `fcntl.flock` across
  snapshot-membership check → live store re-read → validate/decide/
  persist(`used=True`). Barrier-synced fork race: 5/5 single-winner.

Tests: `tests/test_hardening_r12.py` (18 tests, all green).
Evals: `evals/r12_probes.py` (7 closure/preserved-defense probes;
`register_r12()` wired after `register_w13()` in `evals/run_evals.py`,
which stays lean); `evals/matrix.py` sit74–sit78 marked CLOSED;
`evals/SITUATION_MATRIX.md` regenerated (80 situations, 960 cells);
`evals/w13_probes.py` preserved unchanged as the historical attack
record. `evals/FINDINGS.md` F50–F54 marked CLOSED with fixes and
honest residuals (dev-mode self-assertion; per-executor coalescing;
broken-chain blocks whole-sweep reconciliation; byte-exact pin;
lock-file trust domain = run dir).

**Verification:** `python3 -m py_compile` after every edit;
`tests.test_hardening_r12` 18/18; `tests.test_adversary_matrix` 4/4;
`tests.test_hardening_r5` + `tests.test_hardening_r11` 74/74.
Final gates, measured 2026-09-21: `mkdir -p /tmp/gov-r12`,
`TMPDIR=/tmp/gov-r12 python3 evals/run_evals.py` →
**1920/1920, SHIP-GATE GREEN, exit 0** (80 situations x 4 adapters x
3 privs x 2 harnesses); `TMPDIR=/tmp/gov-r12 python3
tests/run_tests.py` → **499/499 OK** (481 baseline + 18 new r12).
`cmp policies/default.yaml gov/data/default.yaml` — identical.
`__pycache__` removed. NOT pushed (per round rules); GitHub repo
stays private/untouched. $0 spend, no LLM calls.


## 2026-09-21 22:40 UTC — WAVE-14 RED TEAM (persistent attacks on Round-12 seams)

Permanent red-team wave. New probes in `evals/w14_probes.py`
(registered via `register_w14()` immediately after `register_r12()`
in `evals/run_evals.py`, which stays lean); new situations
sit81–sit88 in `evals/matrix.py`; `evals/SITUATION_MATRIX.md`
regenerated (88 situations, 1056 cells); findings filed as F55–F58 in
`evals/FINDINGS.md`; wave-14 honest cells documented. `gov/` and
`evals/r12_probes.py`/`evals/w13_probes.py` untouched. Deterministic
scripted attacks, $0 spend, no LLM calls.

**New findings (all OPEN — defeating playbooks confirmed by this
wave's probes; closures deferred to a future hardening round):**

- **F55 (MEDIUM, sit81)** — minting is capability-unchecked:
  in-process attack code mints the REGISTERED operator identity
  (`op-1/operator/ops-lead`), queues an approval stamped as the
  operator, and consumes a real human-provisioned break-glass ticket
  as the operator → emergency approval granted. Operationalizes
  F50's documented honest residual #3 end-to-end; `mint_identity()`
  gates the tuple but authenticates nothing about the caller, so the
  anchor is really "code with executor access".
- **F56 (MEDIUM, sit82)** — the F51 refusal-coalescing window is
  per-executor-instance state: 8 sweeps on 8 fresh executors (same
  run dir) log 8 `approval_sweep_refused` audits; control (8 sweeps,
  1 executor) logs 1 + 7 suppressed. Per-sweep executor
  construction / multi-process sweeps (the F54 threat shape) flood
  the tamper-evident log anyway.
- **F57 (MEDIUM, sit85)** — ticket-store replacement re-arms a
  consumed single-use break-glass ticket: restoring the pre-consume
  store snapshot replays as valid (the ticket HMAC covers identity/
  purpose/created_at but NOT the `used` flag; no generation
  counter); a fresh process then consumes the same ticket_id a
  second time → 2 `approval_break_glass` audits for one ticket. The
  F54 flock is advisory and never consulted by a run-dir writer.
  Deletion mid-race fails closed (live re-read finds nothing).
- **F58 (LOW, sit86)** — `demo/attack_scenario.py`'s final
  `RESULT: 4 attack attempts blocked, 1 tampering detected.` line is
  a literal print with no dependency on any verdict: against a
  weakened policy the run prints `ALLOWED?! send to attacker domain`
  AND the scripted success summary. (Checked `demo/run_demo.py`
  too — its status display is honest; no false summary there.)

**Honest cells (no new findings):**

- **sit83** — one bad-HMAC entry blocks a GENUINE interrupted claim's
  recovery (1 `reconciliation_marker_invalid`, 0 phantom
  interruptions; the legit claim sits unreconciled until an operator
  repairs the chain). Confirms F52's documented honest residual #1.
- **sit84** — full-chain `_verify` completes at 20k entries
  (~0.55s, bounded not pathological); one forged marker makes 3
  sweeps re-verify + re-audit (no dedup), and the 3 refusal audits
  grow the chain by exactly 3 entries (self-feeding loop, capped by
  the F22 100MB fail-closed guard). Confirms F52's documented honest
  residual #2 with numbers.
- **sit87** — install-time: stock `setuptools.build_meta`, no
  setup.py/setup.cfg, no cmdclass, no custom install commands —
  nothing executes at `pip install`. No finding.
- **sit88** — F45 x F33 defense holds: crash between claim and side
  effect charges 0; next sweep reconciles loudly to pending (human
  must re-decide); re-approval executes once; budget counts exactly
  1. No double-charge; no finding.

**Verification:** `python3 -m py_compile` after every edit;
`tests.test_adversary_matrix` 4/4 after every change. Final gates,
measured 2026-09-21: `mkdir -p /tmp/gov-w14`,
`TMPDIR=/tmp/gov-w14 python3 evals/run_evals.py` →
**2112/2112, SHIP-GATE GREEN, exit 0** (88 situations x 4 adapters x
3 privs x 2 harnesses; the 192 new sit81–sit88 cells all PASS);
`python3 tests/run_tests.py` → **499/499 OK**. `__pycache__`
removed. NOT pushed (per round rules); GitHub repo stays
private/untouched.

## 2026-09-21 — Hardening Round 13: F55–F58 CLOSED

**Scope:** close the four Wave-14 findings F55 (operator mint
impersonation), F56 (cross-executor refusal coalescing), F57
(ticket-store replay), F58 (demo summary unconditional). Python
3.12, deterministic, no LLM calls, $0 spend. No push (parent
verifies before any push); repo stays private/untouched.

**F55 — break-glass entitlement bound to the provisioned session
identity** (`gov/identity.py`, `gov/executor.py`,
`gov/approvals.py`, `tests/harness.py`):

- Consolidated the two `AgentIdentity` definitions; added
  `provenance` (`"minted"` default).
- `ToolExecutor(..., session_identity=(agent_id, role, principal))`
  creates ONE construction-time identity
  (`provenance="provisioned"`), installed write-once on the
  `ApprovalQueue` (`set_session_identity`; second install raises
  `SessionIdentityAlreadySetError`).
- `break_glass()` requires exactly the session identity
  (`operator_identity is not self._session_identity` — object
  identity, not dataclass equality). A mid-run `mint_identity()`
  of the same tuple (provenance `"minted"`, or a forged
  `AgentIdentity(..., provenance="provisioned")` built
  out-of-band) is refused with an audited `break_glass_refused`.
- Harness accepts `session_identity=`; ctx exposes
  `ctx["session_identity"]`. Registry/dev mode without a session
  identity keeps pre-R13 behavior.
- Verified: mid-run minted operator refused + audited (incl. the
  forged-provenance variant); provisioned identity consumes the
  ticket; dev-mode minted operator still works.

**F56 — shared cross-executor refusal coalescing**
(`gov/executor.py`, `tests/test_hardening_r12.py`):

- The coalescing window is a bounded file-backed state in the run
  dir: `lock_refusal_coalesce.json` (`{last_audit, suppressed}`
  per known refusal flag), read-modify-write under an exclusive
  flock on a sibling `.lock` file, atomic temp-file + `os.replace`
  writes. Wall-clock (`time.time()`) for the shared state.
- 8 fresh executors under the lock-path attack: 1
  `approval_sweep_refused` audit entry (7 folded into the shared
  suppressed counter), state ~71 bytes. Deleted/corrupt state ->
  one bounded re-audit, never an exception. Run-dir unreachable ->
  pre-R13 per-instance fallback. Legacy `_lock_refusal_*` attrs are
  compatibility mirrors only; the R12 test now drives the
  authoritative state file.

**F57 — ticket consumption anchored in the verified action log**
(`gov/approvals.py`):

- `break_glass` appends a `ticket_consumed` event BEFORE
  `_mark_ticket_used` persists, and — under the F54 cross-process
  flock — verifies the action-log chain first and refuses if a
  `ticket_consumed` event for the ticket already exists (audited
  `break_glass_refused`). A crash between log append and store
  rewrite burns the ticket (fail-closed).
- The ticket HMAC now binds consumption state
  (`used`/`used_at`/`used_for_approval` in the canonical payload,
  re-signed on consume); flipping `used=False` without the keyring
  key fails verification.
- Verified: normal consume emits exactly one `ticket_consumed`;
  replay of a pre-consume store snapshot (with stale snapshot
  cleared) is refused by the log; forged `used=False` fails HMAC;
  the F54 fork race still yields exactly one winner with exactly
  one marker.
- Honest residuals: pre-R13 provisioned tickets fail HMAC after
  upgrade (re-provision on upgrade); after a key rotation
  `break_glass` fails closed until reconciled with the keyring
  verifier; the log authority trusts the action-log key (the F52
  boundary).

**F58 — demo summary computed from measured verdicts**
(`demo/attack_scenario.py`):

- `verdict()` returns its boolean; the 4 attack attempts' verdicts
  and tamper detection are recorded; `summarize_results(blocked,
  tamper_detected)` computes the final line — default run prints
  `RESULT: 4 attack attempts blocked, 0 allowed, 1 tampering
  detected.`; no hard-coded RESULT literal remains.
- Attempt 2 counts both `"queued"` and `"denied"` as blocked.
- Verified: weakened inputs honestly report (e.g. `[True, False,
  True, True]` -> "3 attack attempts blocked, 1 allowed, 0
  tampering detected.").
- Honest residual: the summary trusts the verdict predicates —
  a misclassifying predicate would still print a clean tally.

**Regression:** `tests/test_hardening_r13.py` (16 tests),
`evals/r13_probes.py` (closure probes for sit81/82/85/86) —
16/16 GREEN, `tests.test_adversary_matrix` 4/4, combined
adversary+R12 suites 22/22 GREEN. `evals/matrix.py` sit81/82/85/86
expectations flipped to closure-verifying (R12 pattern);
`evals/SITUATION_MATRIX.md` + root `SITUATION_MATRIX.md`
regenerated. `evals/FINDINGS.md` F55–F58 marked CLOSED with honest
residuals.

**Verification gates (measured 2026-09-21):**

- Gate run 1 (pre-closure-finalization code): 2088/2112 RED — all
  24 failures were sit64 `decorator`/`langchain` (the known
  `rt_chain_verifies_after_concurrent_writes` timing flake; the
  isolated probe passed 15/15 — load-dependent). R13 changes were
  NOT implicated.
- Gate reruns 2 and 3 (final code): both **2112/2112,
  SHIP-GATE GREEN, exit 0** (rerun 1's 2088/2112 was the sit64
  transient flake: the isolated `rt_chain_verifies_after_concurrent_writes`
  probe passed 15/15; the failing cells were all sit64
  decorator/langchain, sharing one cached probe execution).
- `python3 tests/run_tests.py` → **515/515 OK** (499 baseline +
  16 new R13 tests). Demo default run: `RESULT: 4 attack attempts
  blocked, 0 allowed, 1 tampering detected.` (computed).
  `__pycache__` removed.
- `cmp policies/default.yaml gov/data/default.yaml` → identical
  (checked before gate).

**NOT pushed (per round rules); GitHub repo stays
private/untouched. /tmp left clean (~4.9 MB used / 508 MB free).**

## 2026-09-21 23:10 UTC — TEAM ADVERSARY WAVE-15: persistent attacks on the Round-13 seams

Permanent red-team wave. New probes in `evals/w15_probes.py`
(registered via `register_w15()` immediately after `register_r13()`
in `evals/run_evals.py`); new situations sit89–sit95 in
`evals/matrix.py`; `evals/SITUATION_MATRIX.md` + root
`SITUATION_MATRIX.md` regenerated (95 situations, 1140 cells);
findings filed as F59–F64 in `evals/FINDINGS.md`. `gov/`,
`evals/w14_probes.py`, `evals/r12_probes.py`, `evals/r13_probes.py`
untouched (read-only; measure/report only). Deterministic scripted
attacks, $0 spend, no LLM calls. Full gate green; nothing pushed.

**New findings (all OPEN — defeating playbooks confirmed by this
wave's probes; closures deferred to a future hardening round):**

- **F59 (MEDIUM):** the R13 session-identity anchor is a mutable
  private queue attribute checked with structural `!=` — one
  in-process assignment (`queue._session_identity = <minted>`)
  fully defeats the F55 break-glass refusal (ticket consumed,
  `status=approved`); flipping the held identity's `provenance`
  via `object.__setattr__` defeats it too. Executor-side assignment
  is inert and the sealed setter's provenance re-check holds
  (honest cells). sit89.
- **F60 (LOW):** corrupting or deleting the shared
  `lock_refusal_coalesce.json` before every sweep defeats F51
  coalescing — 8 corruptions → 8 `approval_sweep_refused` audit
  entries (undisturbed: 8 sweeps → 1). sit90.
- **F61 (LOW):** the human decision view (`_print_records`,
  400-char args cut; preview shows routing only; `decide()` never
  redisplays) hides verbatim-stored structured args (e.g.
  `api_call` params) past the cut while the digest covers them.
  Summarized payload fields (email body, file content, HTTP
  payload) are one-way `{bytes, sha256_prefix}` — nothing CAN hide
  there (honest cell). sit91.
- **F62 (LOW):** cross-adapter enforcement divergence — the real
  langchain shim's pydantic schema silently drops undeclared kwargs
  before mediation, so a credential in `bcc` is DENIED
  (`dlp-credential-block`) on provisional but QUEUED as routine on
  real langchain (dropped arg also vanishes from the approval
  record); the real OpenAI loop violates the provisional fail-fast
  (`['denied','executed']` vs `['denied']`). sit92.
- **F63 (MEDIUM):** a single non-JSON line in `actions.jsonl` makes
  `read_entries` raise `JSONDecodeError`, crashing EVERY future
  `execute_approved()` in `_reconcile_interrupted_executions`
  (approved work never executes, no audited refusal) —
  contradicts F28's never-raise contract; the demo crashes mid-run
  with no RESULT line. Permissive policy, bad policy section
  (loud fail-closed), and broken-HMAC chain configs all stay honest
  (honest cells). sit93.
- **F64 (LOW):** registry mode WITHOUT a session identity is a
  SILENT weak fallback — the F55 impersonation still consumes the
  ticket with no warning anywhere, unlike dev mode's loud F50
  one-time stderr warning (honest cell). sit94.

**Honest defense cells (no findings):** sit95 (F45 × F33 × 2 —
crash between claim and effect, reconcile re-queues loudly, a
second identical approval executes, re-approved first approval
executes: budget counts exactly 2 sends for 2 actual sends, one
per approval, independent accounting); sit93's
permissive/bad-section/broken-HMAC demo configs; sit91's DLP
one-way summarization; sit94's dev-mode warning; sit89's
executor-side/sealed-setter defenses; sit90's undisturbed
coalescing.

**Gates:** `py_compile` on every edited file after each edit;
`python3 -m unittest tests.test_adversary_matrix` green after every
change; full gate `mkdir -p /tmp/gov-w15 && TMPDIR=/tmp/gov-w15
python3 evals/run_evals.py` exit 0. `__pycache__` removed. Do NOT
push (parent verifies).

## 2026-09-21 — Hardening Round 14: F59–F64 CLOSED

**Scope:** close the six Wave-15 findings F59 (session-identity
anchor bypass), F60 (coalescing corruption loop), F61 (human decision
view truncation), F62 (cross-adapter enforcement divergence), F63
(malformed action-log crash), F64 (silent registry weak fallback);
reconfirm the sit95 budget-accounting defense. Python 3.12,
deterministic, no LLM calls, $0 spend. No push (parent verifies
before any push); repo stays private/untouched.
`evals/w15_probes.py` preserved UNCHANGED as the historical Wave-15
attack record.

**F59 — session-identity anchor made read-only + true object
identity** (`gov/approvals.py`):

- `_session_identity` is now a read-only property backed by the
  name-mangled `__session_identity` slot — normal
  `q._session_identity = evil` raises `AttributeError`.
- `break_glass()` compares with true object identity
  (`operator_identity is self._session_identity`): a separately
  minted structurally equal tuple is refused with an audited
  `break_glass_refused`; the provisioned identity object still
  consumes.
- Accepted as-is (documented in the property docstring): the
  backing slot is initialized to `None` (functionally equivalent
  to absent — the `is` check only applies when provisioned) and
  write-once is enforced via `_session_identity_sealed`.
- Residual: determined in-process code can force-write the
  mangled slot via `object.__setattr__` — outside the
  Python-level threat model (same boundary as the F55
  provenance residual); deployments that never pass
  `session_identity` get no protection (dev-mode gap, unchanged).
  sit89.

**F60 — coalescing suppression derived from the tamper-evident log**
(`gov/executor.py`):

- `_read_lock_refusal_state()` now returns `(state, usable)`,
  distinguishing missing/corrupt state from valid state.
- Unusable-state sweeps stay fail-closed and derive suppression
  from a recent same-flag `approval_sweep_refused` action-log
  entry (not the corruptible sidecar); clean sidecar state is
  rewritten best-effort so transient corruption heals.
- Late in the round, review caught an F63 x F60 interaction: the
  suppression check used the raising `read_entries`, so a
  malformed log line PLUS an unusable sidecar could still crash
  a sweep. Fixed by switching to `read_entries_with_stats`
  (malformed lines count as no-recent — fail-loud, at most one
  extra audit).
- Residual: the suppression check is an ordinary (not
  chain-verified) read — a planted MAC-invalid refusal line
  could suppress a re-audit, but the planted line fails
  `_verify` loudly and the sweep still refuses fail-closed.
  sit90.

**F61 — full human decision view** (`gov/approvals.py`):

- New `_print_decision_target()` renders the FULL canonical args
  (no truncation) plus `args_sha256` over the exact UTF-8
  canonical bytes; shown in list output and redisplayed before
  every CLI decision (individual approve/reject, batch,
  break-glass).
- Residual: the view is CLI-local text — a hostile terminal could
  hide it; the MAC-verified canonical bytes remain the source
  of truth. sit91.

**F62 — adapter parity** (`evals/real_adapters.py`):

- `_GovArgsSchema` now `extra="allow"`: undeclared kwargs
  survive validation and reach mediation/DLP — a synthetic
  AWS-docs key in `bcc` is DENIED by `dlp-credential-block` on
  both provisional and real langchain paths.
- The real OpenAI loop invokes `run_tool_loop` with
  `on_denied="raise"` (fail-fast), converting the denial into
  one provisional-shaped denial result (`["denied"]`).
- The bare-dict payload-shape difference stays documented as
  honest harness plumbing. sit92.

**F63 — malformed action-log lines tolerated, demo honest**
(`gov/log.py`, `gov/approvals.py`, `demo/attack_scenario.py`):

- New `read_entries_with_stats()` skips/counts malformed
  physical lines (non-JSON or non-object JSON);
  `_verify(..., _skip_malformed=True)` skips them too but stays
  strict on seq/chain/MAC/checkpoints for every valid entry
  (also fixes the old `AttributeError` on valid-JSON
  non-dict lines).
- Reconciliation uses the tolerant read, audits
  `action_log_malformed_lines_skipped` once per observed
  state, and still reconciles genuine interruption claims.
  Default `_verify()` stays fail-closed (F28 contract
  preserved).
- `demo/attack_scenario.py` splits `_run_demo()` from a
  `main()` wrapper: any unexpected exception yields an honest
  `RESULT: FAILURE` summary claiming no success, with a
  nonzero exit (entry-point block moved after `main()`).
- Residual: the bad-policy loud failure now flows through the
  wrapper — same loudness, new shape. sit93.

**F64 — registry weak mode warns loudly** (`gov/approvals.py`,
`gov/executor.py`):

- `ApprovalQueue.note_registry_configured()` records that a
  `PrincipalRegistry` was supplied (wired from
  `ToolExecutor.__init__`); the first `break_glass()` in
  registry mode WITHOUT a session identity emits a stderr
  `GOVERNANCE WARNING` naming that break-glass operates
  "WITHOUT identity entitlement checks" and audits
  `break_glass_unprotected`, once per queue. No warning with a
  session identity installed.
- Residual: the documented F55 residual (minted tuple
  consuming the ticket in registry mode without a session
  identity) still exists — now disclosed loudly instead of
  silently. sit94.

**Closure probes** (`evals/r14_probes.py`, wired via
`register_r14()` in `evals/run_evals.py` after `register_w15`;
r13 pattern): 7 probes — sit89 (anchor assignment raises,
minted twin refused, provisioned consumes), sit90 (corrupt/
delete loops bounded to <=1 audit, undisturbed coalescing),
sit91 (marker past old cut verbatim, hash matches, pre-decision
redisplay), sit92 (langchain bcc parity, OpenAI fail-fast),
sit93 (poisoned sweep proceeds, skip audited once, default
verify fail-closed, demo honest cells, poisoned demo emits
`RESULT: FAILURE` rc=1), sit94 (weak-mode stderr + audit,
silent repeat, no warning with session identity), sit95
(re-runs the Wave-15 budget cell unchanged — reconfirmed).
`evals/matrix.py` metadata updated (F59–F64 CLOSED, sit95
reconfirmed); `SITUATION_MATRIX.md` + `evals/SITUATION_MATRIX.md`
regenerated (95 situations, 1140 cells); `evals/FINDINGS.md`
F59–F64 marked CLOSED with fixes + residuals.

**Regression tests** (`tests/test_hardening_r14.py`): 21 tests
covering all six findings plus the F63 x F60 interaction;
21/21 green.

**Gates (2026-09-21):** `py_compile` on every edited file after
each edit; `tests.test_adversary_matrix` 4/4 green after every
change; tmpfs eval gate
`mkdir -p /tmp/gov-r14 && TMPDIR=/tmp/gov-r14 python3
evals/run_evals.py` → **2280/2280, SHIP-GATE: GREEN** (one middle
run showed 24 RED = a single situation's full cell set, green on
the runs before and after with no code change in between —
transient load-dependent flake, retried per protocol; final two
runs consecutive GREEN); full unit suite
`TMPDIR=/tmp/gov-r14 python3 tests/run_tests.py` → **536/536
green**; `cmp policies/default.yaml gov/data/default.yaml`
identical; `__pycache__` removed. Do NOT push (parent
verifies).

## R14 follow-up hardening (2026-09-21) — F62 product-layer completion + gate TMPDIR hygiene

**Item 1 — F62 product-layer completion (`gov/adapters/langchain_tools.py`).**
R14 had fixed only the harness shim (`evals/real_adapters.py::_GovArgsSchema`);
the product adapter still accepted a deployer-supplied `args_schema` with
pydantic's default `extra="ignore"`, so in a real deployment langchain-core
(`BaseTool._parse_input` → `model_validate` → `model_dump`, verified against
installed langchain-core 1.6.3) silently dropped undeclared kwargs BEFORE
mediation — the DLP scan and the approval record understated intent, and the
docstring blessed it ("Invalid inputs are rejected by LangChain's own
validation *before* mediation"). Now `GovernedStructuredTool` fails closed at
construction: a `@model_validator(mode="after")` raises `ValueError` naming
F62 and the `extra="allow"` remedy unless the schema's `model_config` sets
`extra="allow"` (pydantic v2, pydantic v1 `__config__`, and JSON-schema dicts —
which `_parse_input` passes through unchanged — handled). The check lives on
the class itself, so direct `GovernedStructuredTool(...)` construction cannot
bypass `make_governed_tool`; a `__setattr__` guard holds later
`tool.args_schema = ...` reassignments to the same rule. Docstring corrected:
declared-field violations still fail LangChain validation before mediation;
undeclared kwargs now reach mediation (denied or visibly approval-gated, never
silently clean). Sibling adapters audited for pre-mediation input
filtering/dropping — `core` (`GovernedBinding`/`GovernedToolFacade.call`),
`generic` (`governed` wrapper), `mcp_adapter` (`call_tool`), `openai_loop`
(`run_tool_loop`): all pass raw kwargs straight to the executor's DLP scan,
no schema coercion, no drop (the executor pops only documented framing kwargs
`justification`/`on_behalf_of`/`delegated_by`; MCP `session_kwargs` are
transport-level and never reach the executor) — documented in
`gov/adapters/README.md` ("Pre-mediation input audit"). Call-site schemas
updated to `extra="allow"`: `tests/test_adapters_langchain.py`
(`WriteArgs`, `EmailArgs`), `tests/test_hardening_r7.py` (`_Args`),
`evals/run_evals.py` (`_w8_verifier_swap`'s `_A`),
`examples/langchain_wrapped.py` (`EmailArgs`). `evals/FINDINGS.md` F62 entry
extended with the product-layer completion and honest residual (a deployer
mutating the schema class's `model_config` post-construction, or building
their own plain `StructuredTool` around an unmediated callable — the
pre-existing deployment-boundary residual).

**Item 2 — gate TMPDIR hygiene (`evals/run_evals.py`).** Every gate run leaked
hundreds of MB of per-cell run dirs (`govcell-ledger-*`; one run left 261M);
combined with stale probe scratch, /tmp (512M tmpfs) hit 100% and later runs
scored RED purely from ENOSPC. Fix: `run_cell` now captures the two dirs the
harness created for the cell (`_CELL_LEDGER_DIR`, `ctx["run_dir"]`) and
removes them in a `finally` block via `_cleanup_cell_dirs`, which only
removes basenames starting with `govcell-ledger-`/`govred-` (never anything
else; missing paths tolerated). `GOV_KEEP_CELL_DIRS=1` retains dirs for
debugging (default: clean). Probe semantics unchanged — results are computed
before the finally runs; `main()` only consumes the returned dicts.

**Regression tests** (`tests/test_hardening_r14_followup.py`): 9 tests —
strict schema raises at `make_governed_tool` (message names F62/`extra`),
direct construction raises, `extra="allow"` succeeds, reassignment to a
strict schema raises, `bcc`-smuggled AWS-docs key is DENIED by
`dlp-credential-block` and visible (redacted) in the audit record; cleanup
helper removes only harness dirs, tolerates missing paths, honors
`GOV_KEEP_CELL_DIRS=1`, and two real gate cells in a fresh subprocess TMPDIR
leave zero new dirs (proven non-vacuous: with KEEP=1 the same cell leaves
exactly its 2 dirs). 9/9 green.

**Gates (2026-09-21):** `py_compile` on every edited file after each edit;
`tests.test_adversary_matrix` 4/4 green after every change. Full gate on
tmpfs, fresh empty TMPDIR (`rm -rf` stale `govcell-ledger-*`/`govred-*`;
`mkdir -p /tmp/gov-r14f && TMPDIR=/tmp/gov-r14f python3 evals/run_evals.py`):
first run 2256/2280 with all 24 RED on sit64
(`rt_chain_verifies_after_concurrent_writes` — the known transient
multiprocessing/flock load flake; probe passes standalone, no interaction
with either change); retry per protocol → **2280/2280, SHIP-GATE: GREEN**.
/tmp: 1% (140K) before → 8% (36M) after the full green run; the fresh
TMPDIR holds 34M total and **zero** `govcell-ledger-*` dirs remain — the
261M per-cell leak is closed; growth is bounded. Full unit suite
`TMPDIR=/tmp/gov-r14f-unit python3 tests/run_tests.py` → **545/545 green**
(536 + 9 new); `cmp policies/default.yaml gov/data/default.yaml`
identical; `__pycache__` removed. Do NOT push (parent verifies).

**Residual (open, wave-16 brief item):** probe-level scratch scattered
directly under TMPDIR is NOT swept by this task — after the green gate run,
2111 small `govred-*` dirs (~22M) plus one `gov-r13-demo-*` dir remain, from
`make_run()`/`tempfile.mkdtemp` calls inside memoized playbooks (`_w7*`),
one-off verifiers (`_w8_verifier_swap`, w6/w7), and probes that allocate
their own temp dirs instead of using the cell dir. Bounded (~34M/run) but
still accumulates across runs sharing one TMPDIR. Wave-16 should give
probes a cell-scoped scratch dir (or track per-run allocations) so the gate
is fully hermetic.
