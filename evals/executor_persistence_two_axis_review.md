# Two-Axis Code Review — Wave-110 Executor-Persistence Lane (F167 + F168)

- **Reviewer:** Wave-110 executor-persistence lane agent (Krishna crew)
- **Date:** 2026-09-24
- **Scope:** `gov/executor.py` changes for F167 (tempo-pause rotation
  persistence) and F168 (foreign-result metering); new tests
  `tests/test_f167_pause_persistence.py`,
  `tests/test_f168_foreign_metering.py`; specs
  `evals/f167_pause_persistence_spec.md`,
  `evals/f168_foreign_metering_spec.md`
- **Fixed point:** pristine pre-change tree at
  `~/workspace/audits/wave110/scratch_unfixed/` (this tree carries no
  `.git`, so the skill's `git diff <fixed-point>...HEAD` step was
  replaced by `diff -u` against the scratch copy; both axes were run
  by the lane agent directly — a depth-2 subagent cannot spawn review
  subagents — as two separate passes with no cross-axis reranking)

## Standards

Verdict: **PASS** — no hard violations. Two judgement-call notes
(baseline smells, not breaches); one real robustness finding was
raised and fixed during the review.

**Notes (judgement calls, non-blocking):**

1. *Duplicated Code (possible):* `_rehydrate_tempo_pause` contains a
   ~12-line tolerant-JSONL parse loop whose shape mirrors
   `gov/log.py::read_entries_with_stats`. Reuse was deliberately
   declined: the canonical reader calls `check_exchange_read`, which
   at construction time would mis-attribute the executor's own
   bookkeeping as a cross-run read and pollute the harvest ledger.
   The local parse is the smaller evil; the docstring states the
   reason. Suppressed per "the repo overrides" — no action.
2. *Fail-open construction read:* the scan's `except ...: return`
   starts the executor unpaused on I/O/content trouble. This follows
   the documented in-tree precedent (canary marker,
   `test_marker_best_effort_read_only_dir`) and the scan only ever
   ADDS a pause; a truly unreadable log fails closed at first append.
   Documented in the docstring. No action.

**Finding raised and fixed in-review:**

- R1 (robustness): the scan's `except OSError` did not cover
  `UnicodeDecodeError` (a `ValueError`) from `read_text` on a
  non-UTF8 log file — a content problem crashing construction,
  against the F28 convention and the method's own documented
  best-effort posture. Fixed: `except (OSError, ValueError)` with a
  comment citing F28. Re-verified: new tests green post-fix.

Other checks: naming is honest (`_rehydrate_tempo_pause`,
`metered_src`); no speculative generality (no new params, files, or
hooks); comment style matches the repo's finding-tagged convention;
the nested `self._accrue_result_usage(self._mint_result_usage(...))`
is dense but within the repo's idiom; reordering edits in
`_charge_tempo` / `resume_after_velocity_pause` add no new branches.

## Spec

Verdict: **PASS** — every requirement in both specs is implemented;
no scope creep; no missing behavior.

Against `evals/f167_pause_persistence_spec.md`:

- (a) Rehydration at `__init__` via `_rehydrate_tempo_pause()`:
  present; latest `velocity_paused`/`velocity_resumed` decision wins;
  fresh run_dir (no entries) starts unpaused — quoted spec line
  "The run starts paused iff the latest such entry is a pause"
  holds, covered by `test_rotation_preserves_pause` and
  `test_fresh_run_dir_starts_unpaused`.
- (b) Adversarial posture: `seq`/`hash` shape check present;
  malformed/planted lines skipped (F28/F52 cited); direct file read
  bypassing the F163 check, with the reason documented;
  `test_planted_resume_line_does_not_unpause` covers the forged-line
  case.
- (c) Ordering hardening: trip record chained before the flag is set;
  resume record chained before the flag is cleared — both present
  with F167 comments; `test_trip_record_is_chained_when_pause_reports`
  pins the invariant.
- (d) Wire deliberately NOT rehydrated; `_tempo_resume_aid` /
  `_tempo_trip_class` not rehydrated — both as specified, with the
  cross-boot rationale in the code comment; resume-via-operator-branch
  covered by `test_resume_on_rotated_executor_clears_pause_exactly_once`.
- No behavior outside the spec (no wire snapshot, no new run_dir
  files).

Against `evals/f168_foreign_metering_spec.md`:

- (a) Mint via `_mint_result_usage(tool, {}, ...)` on the normalized
  blob; adapter-asserted `_usage` never read — present;
  `test_adapter_asserted_usage_is_ignored` covers it.
- (b) Accrue through `_accrue_result_usage` (RESULT path) — present;
  `test_foreign_blob_accrues_governed_shaped_usage` asserts the
  worked example (10080 tokens).
- (c) Metering loud and before/outside the taint `try/except: pass`;
  taint fail-open posture byte-identical — present;
  `test_metering_is_loud_while_taint_stays_fail_open` covers the
  ordering.
- (d) Exactly-once: `_ingest_result` receives a `_usage`-less dict
  (internal accrual 0, no-op), pinned by comment and by
  `test_no_double_count`.
- (e) Opaque-only → base rate; `result=None` → clean no-op — present
  (`test_opaque_result_accrues_base_rate`,
  `test_none_result_accrues_nothing`).
- No signature changes; governed path untouched; no scope creep.

## Summary

- Standards: 0 hard violations, 2 judgement-call notes (both
  suppressed/documented), 1 finding raised and fixed (R1,
  UnicodeDecodeError hardening). Worst: R1, fixed.
- Spec: 0 missing requirements, 0 scope-creep items across both
  specs. Worst: none.
- **Blocking findings: none.** The change is approved for the wave
  record (no push per lane orders).
