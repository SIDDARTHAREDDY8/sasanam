# Two-axis code review: Wave-110 ledger robustness (F165, F166, F170)

- **Reviewer:** Krishna (ledger-robustness lane; self-review — no peer
  agents available at this depth)
- **Date:** 2026-09-25
- **Scope:** `gov/exchange_ledger.py` (F165/F166/F170 hardening),
  `tests/test_ledger_robustness_f165_166_170.py` (18 tests),
  `evals/f165_f166_f170_ledger_robustness_spec.md`
- **Process note:** the code-review skill prescribes parallel sub-agents
  per axis; subagent spawning is unavailable at this depth, so the two
  axes were executed as separate sequential passes and are reported
  separately below, not merged or re-ranked.

## Standards axis — PASS

**Standards sources:** no CODING_STANDARDS.md/CONTRIBUTING.md in-tree;
the applicable conventions are the module's own documented contracts
(stdlib-only, no gov imports, fail-closed currency
`ExchangeAccessDenied`, env read at call time, fcntl locking + fsync
discipline, thorough docstrings) plus the skill's smell baseline
(judgement calls, repo overrides win).

**Hard checks:** stdlib-only preserved (no new imports;
`contextlib`/`threading` were already imported); `__all__` unchanged
(no new public names); every new helper has a docstring stating its
fail-closed rationale; env knobs read at call time per the module's
`# -- env config (read at call time ...)` contract; OSError paths all
converge to `ExchangeAccessDenied`; no `[DEBUG-…]` instrumentation left
(grep verified); no `consumer_token=` literals.

**Baseline smells (all judgement calls):**

1. **Thread-safety of compaction — FOUND AND FIXED DURING REVIEW.**
   fcntl locks do not exclude threads of one process, and the first
   version of `_compact_and_append` used a pid-only temp name with no
   in-process serialization: two threads compacting concurrently could
   lose records through the shared temp-file/replace window (the old
   plain-append path was atomic per `write()` under O_APPEND; the new
   read-modify-replace path was not). Fix: module-level
   `_APPEND_LOCK = threading.Lock()` held across `_append_locked`, and
   the temp name now includes `threading.get_ident()`. Regression test
   `test_concurrent_compacting_appends_lose_no_records` (8 threads x 25
   compacting appends, all 200 records must survive) fails 5/5 runs
   against a lock-removed variant and passes 3/3 with the fix.
2. **Duplicated Code (possible):** the parse loop (strip / skip-empty /
   `json.loads` / `isinstance` dict) appears in both `_read_window_full`
   and `_compact_and_append`. Left as-is deliberately: the two loops do
   different things with the parsed record (window-filter vs keep-raw-
   line), and extracting a helper would trade 10 lines of duplication
   for indirection at a security-critical seam. Documented call.
3. **Data Clumps (possible):** `(now_mono, now_wall, window_sec,
   cur_boot)` travel together into `_record_in_window` from two call
   sites. Left as-is: bundling would obscure the fail-closed
   predicate's inputs; the tuple is computed identically at both sites.
4. No Mysterious Name, Feature Envy, Primitive Obsession, Repeated
   Switches, Shotgun Surgery (single module), Divergent Change (one
   theme: ledger robustness), Speculative Generality, Message Chains,
   Middle Man (`_read_window` delegating to `_read_window_full`
   preserves the existing seam used by audit repros — justified), or
   Refused Bequest.

**Worst within axis:** the thread-safety race (#1) — caught and fixed
with a red-validated regression test before landing.

## Spec axis — PASS

**Spec sources:** `evals/f165_f166_f170_ledger_robustness_spec.md`;
FINDINGS.md closure directions for F165/F166/F170.

**F165 — requirements met:** non-positive parsed window denies
window-dependent (default-posture) cross-run reads with an audited
`exchange_read_denied` record naming the value (`test_zero_window_…`,
`test_negative_window_…`, `test_zero_window_never_silently_allows`);
own-run reads unaffected (early return precedes validation);
allowlisted/strict paths unaffected (they never consult the window);
unparseable values keep the documented default 900 (pinning test);
deny (not clamp, not ValueError) per spec rationale. Threshold knobs
analyzed, no change (already fail-closed).

**F166 — requirements met:** records carry `mono` + `boot`
(`test_records_carry_monotonic_stamp_and_boot_epoch`); same-epoch
accounting is monotonic-only — forward wall jump leaves all 49 records
visible and grants no fresh budget; cross-epoch/legacy records keep
counting by wall `ts` (fail-closed: restart does not launder);
boot epoch from `/proc/sys/kernel/random/boot_id`, cached, with a
conservative per-process fallback; `ts` retained for audit.

**Considered deviation (not a miss):** FINDINGS.md's F166 closure line
says wall-clock "must not gate the tripwire"; the design gates
cross-epoch/legacy records by wall-clock `ts`. This is explicitly
authorized by the lane brief ("an attacker who restarts the process
wants the boot-id trick — pick the fail-closed direction") and
specified in the spec: the alternative (cross-epoch ⇒ expired) would
introduce a restart-launders-budget fail-open strictly worse than the
finding. Residuals documented in spec and FINDINGS entry.

**F170 — requirements met:** tail-bounded scan
(`_tail_budget`, default max(2MB, window·512), env override, garbage ⇒
default); truncation without a tripwire trip denies fail-closed
(trip from partial data still denies with the tripwire reason —
ordering verified in code); append-time compaction past
`_compact_threshold` (default max(1MB, window·256)) keeping only
window-relevant records; atomic temp-file + `os.replace` with temp
fsync + directory fsync; stale-fd identity check with ≤3 retries
against the replace-vs-concurrent-appender race; any compaction
failure ⇒ `ExchangeAccessDenied` (degrade to deny, never unbounded);
20k stale records compact to <210KB and per-read cost stays <0.01s
(post-fix repro).

**No scope creep:** every addition traces to a spec requirement; the
`_APPEND_LOCK` traces to F170 compaction correctness. Pinning tests
(own-run/allowlist/malformed/backward-jump/legacy) pin spec'd
"must not change" behaviors.

**Worst within axis:** the F166 cross-epoch wall-clock arm is the one
place the implementation goes beyond the FINDINGS one-liner — reviewed
as authorized-by-brief and spec'd, with residuals documented.

## Summary

- Standards: PASS — 1 finding (thread-safety race), fixed during
  review with a red-validated regression test; 2 deliberate
  judgement-call non-fixs documented above.
- Spec: PASS — all F165/F166/F170 requirements implemented and
  verified; 1 considered deviation documented; no scope creep.
- **Blocking findings: none.**
