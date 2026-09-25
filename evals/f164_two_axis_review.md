# F164 two-axis code review (Wave-110) — review artifact

Lane: F164 closure (wire agent `read_file` through the F163 exchange ledger).
Reviewer: the closure lane itself (no subagent spawn available at depth
2/2; both axes executed inline, kept separate, no reranking — per the
code-review skill's separation rule).

Diff under review (no git in this tree; fixed point = pre-lane scratch
copy `/tmp/f164red-tree`, captured before the first edit):
- `gov/executor.py` MODIFIED (4 hunks: import, `_exchange_entry_count`
  helper, two-phase guard in `_simulate`'s read_file branch, `bind_reader`
  around tool execution at the `call()` allow path and the
  `_execute_approved_locked` sweep path)
- `tests/test_f164_readfile_ledger.py` NEW (10 tests, red-first)
- `evals/f164_readfile_ledger_spec.md` NEW (to-spec output)
- `evals/FINDINGS.md`, `BUILD_LOG.md` (closure bookkeeping; not code)

Spec source: `evals/f164_readfile_ledger_spec.md`.
Standards sources: none documented in repo (no CODING_STANDARDS.md /
CONTRIBUTING.md) → smell baseline + repo conventions (F-tagged
comments, fail-closed idioms, `_X` import aliases, module-level
`GOV_DEPLOYMENT_MODE=staging` in new test/battery modules per the
wave-95 lesson).

## Standards

- Import `from . import exchange_ledger as _exchange_ledger` matches the
  existing `from . import X as _X` alias block (canary, delegation_tokens,
  …). The ledger module imports no `gov` modules — the no-cycle invariant
  is preserved; a regression test pins it (`test_exchange_ledger_has_no_gov_imports`).
- Comments follow the repo's `F### (SEVERITY):` convention and explain
  *why* at each site (two-phase rationale, why the simulated branch needs
  no guard, precommit-thunk synchronicity, sweep-path attribution).
- Smell baseline, hunk by hunk:
  - *Duplicated Code*: the two `bind_reader` blocks differ legitimately
    (calling-identity vs approval-record principal/run_id). Extracting a
    shared helper would be Speculative Generality — declined, judgement call.
  - *Feature Envy / Middle Man*: none — the guard calls the ledger's own
    public API (`check_exchange_read`, `bind_reader`), which is the seam's
    contract.
  - *Mysterious Name*: none — `_exchange_entry_count` says what it counts.
  - *Message Chains*: `(rec.get("identity") or {}).get("principal")`
    repeats the identical expression already used in the same sweep
    function for the auth entry and the tempo audit identity — repo
    convention overrides the baseline.
  - *Divergent Change*: one reason per hunk (all four serve the single
    closure); no unrelated edits.
- Denial-after-write-ahead-audit ordering matches the F162 tempo-wire
  precedent exactly (authorization logged, then the fail-closed tripwire
  raises before the side effect). Consistent with the repo's
  execution-boundary idiom.
- Test module: `GOV_DEPLOYMENT_MODE=staging` at module level right after
  imports (wave-95 lesson honored); env save/restore mirrors
  `test_f163_exchange_ledger.py`; assertions at public seams
  (status/content/records); internals used only where repo convention
  allows (`ex._sandbox_resolved`, `ex.run_id`, `xl._current_reader()` —
  same white-box level as neighboring test modules).
- Line length / whitespace: lane lines within the repo's evident style;
  no TODO/DEBUG leftovers.

**Standards verdict: PASS — no blocking findings.** Non-blocking nits:
`_exchange_entry_count` sits among module constants rather than near
`_simulate` (harmless); the no-gov-imports test assumes the `tests/`
layout (same assumption the suite runner makes).

## Spec

Checked against `evals/f164_readfile_ledger_spec.md`:

- *Single choke point* (Implementation Decisions): the guard lives in the
  read_file sandbox branch of `_simulate`, through which the allow path,
  the approved-sweep path, and the precommit commit thunk (synchronous
  inside `commit()`, verified in `gov/precommit.py`) all funnel. Verified
  in code; no other tool returns real file bytes (the only `read_text`
  into an agent result is this branch; all other tools are synthetic or
  metadata; adapters route through `ex.call`).
- *Two-phase pattern*: before-phase `check_exchange_read(str(p))` with
  `n_entries=None` runs before any bytes are touched; after-phase passes
  the entry count computed from the FULL file text
  (`_exchange_entry_count(text)`), never the 4000-char tool truncation.
  Matches the log seam's contract.
- *Reader binding*: `bind_reader(principal, run_id, action_log=self.log)`
  around tool execution at both boundaries; `bind_reader` is thread-local
  with restore-on-exit, so nested/spawned executions attribute to the
  innermost reader (pinned by `test_nested_binding_innermost_reader_wins`).
- *Own-run frictionless / allowlist / strict posture*: semantics identical
  to the seam (bound run_id = the calling identity's run; allowlist and
  strict checks are the ledger module's, unchanged).
- *Denial fail-closed*: `ExchangeAccessDenied` propagates out of
  `_simulate`; no result dict is built; the agent never receives the
  bytes. The `exchange_read_denied` record is appended by the guard
  itself and mirrored onto the chained log via the bound `action_log`.
- *No scope creep*: no hunks outside `gov/executor.py`; no changes to
  F165/F166/F167/F168/F170 (their defects are inherited by the tool path
  and remain separately tracked); no DLP/redaction; no ownership
  registry.
- *Testing decisions*: red-first demonstrated on a scratch copy of the
  unfixed tree (7/10 fail pre-fix — the 3 passing are the by-design
  non-guard pins; 10/10 green post-fix in normal env and
  `env -u GOV_DEPLOYMENT_MODE`); the A1 audit repro flips BREAK→recorded;
  the agent-path bulk battery trips at the 51st distinct run exactly like
  the seam.

**One gap found and fixed during this review** (non-blocking, fixed
red-first): the denied-record mirror onto the chained log was asserted
for allowed reads but not for denials on the tool path. Added the
`exchange_read_denied` chained-log assertion to
`test_bulk_readfile_harvest_trips_tempo_denial`; re-verified 10/10 green
in both envs and 7 failures on the unfixed scratch tree.

**Spec verdict: PASS — no blocking findings**, all 10 user stories pinned
by tests or batteries, out-of-scope items honored.

## Summary

- Standards: 0 findings (2 non-blocking nits noted above).
- Spec: 0 blocking findings (1 gap found and fixed during review).
- Worst issue per axis: Standards — none; Spec — the denied-mirror
  assertion gap (fixed).
