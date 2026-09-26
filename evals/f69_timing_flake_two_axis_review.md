# Two-axis review: F69 timing-flake hardening + F72 pin-scan optimization

Date: 2026-09-26. Change under review: `gov/log.py` (F72 replay-freshness pin scan now O(new bytes) via `pin_off`) + `tests/test_hardening_r16.py` (F69 warm-sweep bound asserted on `time.process_time()` instead of `time.perf_counter()`; new `TestF69PinScanIncremental`).

## Standards axis (independent subagent review)

Reviewed against code smells (no documented style guide exists in-repo; `docs/STANDARDS_MAPPING.md` is a compliance mapping, not a style guide).

Findings (all fixed in-lane):

1. **Test class placed after the `__main__` guard.** `TestF69PinScanIncremental` was added after `if __name__ == "__main__": unittest.main()`, so direct file execution skipped it. Fixed: guard moved to the file's true end. (Side discovery: direct-file execution runs 10 tests with 8 errors because it doesn't trigger `tests/__init__.py` key provisioning — a pre-existing harness gap, not in scope; module-style unittest is the supported path and is green.)
2. **`cp_size` validation split from the validation block.** Fixed by moving both range checks into the main validation sequence.
3. **Unnecessary local `import gov.log`.** Removed; module-level import used.
4. **Long production performance comment.** Trimmed to the honest residual statement.

## Spec axis (independent subagent review, first pass)

Reviewed against the original brief: harden the F69 timing flake; never break F72 replay-freshness (replayed older tip degrades to full re-verification, never silent staleness); F72's documented residual must hold; 150ms bound must still discriminate pre-R16 behavior.

Findings:

1. **Metric change faithful to the brief.** Asserting the bound on process CPU matches the "bounded CPU work" regression property; the 150ms threshold is unchanged; no sleeps or threshold inflation.
2. **The naive `cp_size`-suffix scan was unsound under concurrent tip writers** (multi-process sweeps sharing a run dir are supported). Interleaving: writer A appends pin gen 8; writer B appends pin gen 9; A measures a sidecar prefix that already contains gen 9, then writes the stale tip with `cp_size` covering gen 9; a later reader scanning from `cp_size` misses gen 9 and can silently accept the stale tip. Reproduced as a red test pre-fix.
3. **Fix adopted: `pin_off` instead of `cp_size`.** The tip records the sidecar offset measured *before* its own pin is appended; the scan starts there. The reviewer's exact race is now rejected (red-capable regression test added).

## Spec axis re-review of the `pin_off` design: CONDITIONAL PASS

The reviewer constructed and empirically confirmed a residual hole in the author's case analysis: a writer that races an interleaved pin append *before* its `pin_off` measurement can leave a genuine higher-generation pin before `pin_off`, and a stale-but-genuine tip may then be accepted. Verdict: **benign, land it**, because:

- The accepted tip is always MAC-authentic and vouches a genuinely-verified prefix; the incremental walk still re-verifies the entire live tail with full per-entry checks — staleness costs redundant work, never trust in unverified bytes.
- The new scan window `[pin_off:]` is a superset of the old `[cp_size:]` window (`pin_off <= cp_size` is validated), so every tip accepted under the new code was also accepted under the old — the change only adds rejections; the F52 attacker gains no new silent-acceptance shape.
- MAC scheme intact (`_canonical` uses `sort_keys=True`; old tips without `pin_off` fail closed and reseed via full re-verify; both write sites include `pin_off`).
- The 150ms bound is unaffected; the O(entire-sidecar) amplifier stays fixed.

**Condition (done):** the production comment's case-(b) claim ("this genuine tip is newer") was replaced with the honest statement above; `evals/FINDINGS.md` carries the same residual.

## Verification summary (all with fresh bytecode; a stale-`.pyc` incident during the lane was caught and cleared)

- Focused F69 flake test: pre-fix 3/3 red under 2-CPU saturation (301/328/391ms wall); post-fix 5/5 green under the same load; quiet green.
- New `TestF69PinScanIncremental` (2 tests): red against pre-fix code and against the naive `cp_size` scan; green with `pin_off`.
- Full `tests.test_hardening_r16` + `tests.test_hardening_r23` + `tests.test_log_merkle`: 42/42 green normally and under `env -u GOV_DEPLOYMENT_MODE`.
- Discrimination: simulated pre-R16 full verify costs 759-773ms CPU vs the 150ms bound (bound still trips).
- Warm-sweep CPU: ~16ms post-fix (was ~95ms), 9x headroom under the bound.
