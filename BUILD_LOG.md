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

- (pending) push to `SIDDARTHAREDDY8/agent-governance-demo`, existing
  branch; repo stays PRIVATE; API-verify branch SHA moved afterwards.
