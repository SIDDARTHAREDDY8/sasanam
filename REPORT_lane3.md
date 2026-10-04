# Wave-316 Lane 3 (summary-form migration follow-on) — REPORT

**Lane:** Wave-316 LANE 3 · **Base:** `b636446` (wave-315 merge) · **Date:** 2026-10-03/04
**Task:** Migrate remaining non-canonical batteries to canonical probe-line form per `evals/SUMMARY_FORM_POLICIES.md` (D1–D8). Definition of done: every battery emits canonical probe lines; zero non-canonical verdicts tree-wide (spec Done #2).
**Skills used:** `implement` (migration), `diagnosing-bugs` (break-first verification).

## Outcome

**126 files changed** (125 `evals/*_probes.py` + `evals/FINDINGS.md` for F401). **Zero non-canonical verdicts in recorded probe positions tree-wide** (verified static + dynamic). Pin **1888** unchanged. `gov/` untouched. Registry gate **GREEN**.

### What was migrated (125 batteries)

| Worker | Scope | Files | Key decisions |
|---|---|---|---|
| 1 | GAP family | 32 | GAP→BREAK at emission; 25 named D1 exit-contract exceptions (exit doesn't treat GAP as red); rc byte-identical |
| 2 | PASS/FAIL family | 34 | PASS/HELD/GREEN→HELD; FAIL/BROKEN/GAP/RED→BREAK; ERROR→ERROR; SKIP/SKIPPED→SKIP; pid sanitization; w224_agile genuine BREAK+ERRORs preserved |
| 3 | Misc verdicts | 23 | EXPECTED→HELD+`expected: `; ok/MISMATCH→HELD/BREAK; skip→SKIP; FAIL→BREAK; RESIDUAL→HELD+`residual: ` |
| 4 | Registry-consumed | 25 | Canonical mains; RESULTS vocabulary intact (oracle reads lowercase); 212/212 registry matches |
| 5 | Rot pins | 9 | w310 F394, w283 F343-345, w273 pin 1888, w308 footer, 7 stale D8 parents |
| Lead | w266/w267 + D8 | 4 | RESIDUAL→HELD+`residual: `, BASELINE→HELD+`baseline: `, EXPECTED→HELD+`expected: `; w282_agentscan + w270_bundlescan + w267 parser D8 fixes |

### Lane-lead judgment calls (break-first documented)

1. **EXPECTED → HELD + `expected: ` prefix.** EXPECTED marks a pinned unavoidable limitation (exit-neutral). Maps to HELD (not a break) with the expectation preserved in the note. Applied to 7 batteries (canary_normalized_match, covert_channel, durable_approval, mcp_description_drift, row1_diversity, skill_fastpath_content, skill_supplychain_evasion).

2. **`ok`/`MISMATCH` → HELD/BREAK.** `ok` (w276_f293, w278_sandbox, w279_f300, w275_redteam, w277_conflict) = pass → HELD. `MISMATCH` = fail → BREAK. Exit-equivalent.

3. **lowercase `skip` → SKIP** (w242_aee_parity). Case normalization, D1.

4. **Uppercase RESIDUAL → HELD + `residual: ` prefix** (w269, w270, w266, w267). Exit-neutral; battery exit is `1 if (brk or errors)`.

5. **BASELINE → HELD + `baseline: ` prefix** (w266, w267). Baseline/control measurement, exit-neutral.

6. **GAP→BREAK at emission** (worker 1). Keeps rc byte-identical even where GAPs fire on real tree (w233_dsseone 1 GAP, w263_recipient 5 GAPs → now visible `[BREAK]` lines, rc unchanged).

7. **w265_redteam REMOVED from scope** (false positive). Its PASS/FAIL are in a `RESULT:` conclusion line; RED is a green-check prefix check. Not recorded probe verdicts. Reverted to pristine.

8. **sigma_detection: worker 2's version wins.** Worker 3's pids (`"red: ..."`) violate the pid class; worker 2's are properly sanitized.

### Accepted (not migrated)

- **Registry-consumed no-main modules** (~30): lowercase RESULTS consumed by `run_evals.py` oracle. Migrated only their standalone mains; RESULTS vocabulary intact.
- **Historical registration modules** (r9–r16, w10–w20): consumed via `register_*`, not probe batteries.
- **OTHER-class domain vocabulary**: dict:allow/permit/DENY/admitted in test data, not probe verdicts (verified false positives).
- **Columnar with canonical verdicts** (w243 etc.): shape migration is a separate wave.
- **Docstring/test-data literals**: `[BASELINE]` in w265_replay docstring, `[ok]` in b1exp falsified transcript — not recorded verdicts.

### F401 filed (MEDIUM, OPEN)

`gov/decision_bom.py:64` carries `from .mode_ledger import LADDER_MODES` (wave-198), a package-relative import that raises `ImportError` outside the package. `evals/decision_packet_probes.py::probe_offline_verify` copies only 3 files to an isolated dir and imports standalone — **LIVE RED on base** (`[BREAK] offline_verify`). Fail-closed (verification fails, never falsely passes), but the offline evidence-verification property is broken. Close-when: 3-file standalone import works with `gov` absent; probe HELD; regression pin on the standalone import set.

**Footer:** open F398, F399, F400, F401 / next F402. The wave-316 merge coordinator must re-pin footer-state probes to F402.

### Pre-existing rot pinned (worker 5)

- w310_redteam: F394 probes → `at=AT+1`
- w283_defectdojo: F343–F345 → verified
- w273_fanout: 1700 → 1888
- w308_new_attack_rows: footer → F401/F398-400
- 7 stale D8 parents updated

**Flag:** decision_packet offline_verify is a REAL PRODUCT REGRESSION (F401), not rot.

### D8 parent fixes (lane lead)

- **w270_bundlescan**: parser blind to w221_admission's new `[BREAK]`/`[ERROR]` lines → extended to cover both forms.
- **w282_agentscan**: parser (`ln.split()[0].startswith("e")`) blind to skill_supplychain_evasion's new `[BREAK] e7:` → extracts pid from bracketed form.
- **w267_f249**: `_verdict_of` misreads w266's canonical summary as BREAK → skips `N BREAK / N HELD / N ERROR` lines.

### Verification

- **Static:** zero `[PASS]`/`[FAIL]`/`[GAP]`/`[EXPECTED]`/`[RESIDUAL]`/`[BASELINE]`/`[SKIPPED]`/`[ok]`/`[RED]`/`[GREEN]`/`[BROKEN]` in `evals/*_probes.py` (2 hits in docstrings/test-data, not verdicts).
- **Dynamic:** sample of migrated batteries (w213, w215, w266, w267, skill_supplychain_evasion, sigma_detection) — all clean, rc as expected.
- **Registry gate:** GREEN (with workstream symlinks).
- **Pin:** 1888 (97 files); 1 comment-mention of 1080 (not a pin).
- **gov/:** untouched (empty diff).
- **Coherence:** `probe_lines.check_coherence` clean on w266/w267 (SKIP tallied separately per contract).

## Commits (lane tree, detached HEAD, nothing pushed)

- `02a6e242` — F401 filed
- `53fcec5b` — D8 fix w270_bundlescan
- `c02fabed` — w266/w267 migration + D8 fixes
- `701799fe` — merge workers 1-5 (123 files)

**REPORT AND STOP.**
