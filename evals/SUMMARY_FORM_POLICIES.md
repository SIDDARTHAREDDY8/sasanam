# Summary-Form Migration: Policy Decisions (Wave-314 Lane 4)

**Status:** design spec for a future migration lane. No product code touched; test-infra only.
**Base:** `fa0b0ed1` (wave-313 merge). **Measured baseline:** 72/711 `evals/*_probes.py`
batteries canonical (`probe_lines.emit`-based). Codemod reference copies:
`tools/summary-form-migration/`.
**Authority:** this spec decides the policies the wave-312 migration lane (summform5)
deferred: GAP→? mapping, dict-result emission, truncation. It additionally catalogues a
sixth probe-line shape the codemod's S1–S5 taxonomy misses.

## Problem Statement

The canonical probe-line form (`[VERDICT] pid: note`, one line per probe, before the
`N BREAK / M HELD / K ERROR` summary) is what makes the green-check coherence rule
sound: probe lines must cohere with the summary, and every line must parse via
`probe_lines.parse_line`. The mechanical codemod exhausted its pool at 72/711. The 86
batteries it refused are not mechanical problems — each needs a *policy decision* about
verdict vocabulary, result shapes, or summary form before a lane may touch it. Until
those decisions exist, the rollout is stuck and the coherence check cannot be promoted
from advisory to enforcing.

## Decisions

### D1 — Verdict mapping: every non-canonical verdict maps to a canonical one, red-first

The codemod refuses GAP/RED/BROKEN/PENDING-style verdicts because `probe_lines.emit`
would print e.g. `[GAP]`, which `parse_line` cannot parse. The mapping below is the
policy. Its governing rule is **red-first**: a mapping must never make a battery
greener than its own exit contract says it is. Where the battery's own contract treats
a verdict as red (non-zero exit), the canonical verdict must be BREAK or ERROR.

| Source verdict | Maps to | Rationale |
|---|---|---|
| `GAP` — "gap demonstrated", the battery's red phase (41 batteries incl. `claim_bounds`) | **BREAK** | Every GAP battery's own exit contract treats GAP as red (`exit 2 on any GAP`, `bad = any(v not in ("HELD",))`). The note keeps the evidence (`capability absent on pristine base`, `refused but wrong code`). Mapping to SKIP would green-wash red-phase batteries and drop GAP counts out of the coherence equality (SKIP lines are excluded). |
| `RED` — child process rc != 0 (`w284_f312_315`, `w285_f324_f316`) | **BREAK** | Battery exit is `1 if (breaks or reds) else 0` — red by its own contract. Fold `reds` into the BREAK count; the summary becomes canonical `%d BREAK / %d HELD / %d ERROR`. |
| `BROKEN` — probe assertion failed (`claim_bounds`) | **BREAK** | The battery's own comment calls the sibling GAP "genuine red"; a failed probe assertion is demonstrated non-conformance. Exit contract `if broken or errors ...` becomes `if breaks or errors ...`. |
| `GREEN` — child rc == 0 (`w284_f312_315`, `w285_f324_f316`) | **HELD** | Exact semantic match. |
| `SKIPPED` — green-check skip marker (`GOV_SKIP_GREEN=1`; 12 dict batteries) | **SKIP** | Exact semantic match. Pid `green-check` already class-conforming. |
| `EXPECTED` (`f204_closure`) | **dropped** | Dead class: no probe records it (only the docstring and summary counter reference it). The summary column is removed; counts reconcile to `held + brk + err`. |
| `FP` — false positive demonstrated (`row12_undeclared_path`) | **BREAK**, note prefixed `FP: ` | Post-seam exit is `bad = BREAK + FP + ERROR` — red by its own contract. The `FP:` prefix keeps the measurement legible. |
| `PASS` / `FAIL` (5 demonstration batteries) | **HELD** / **BREAK** | |
| `stopped` / `break` / `error` (`w72`–`w75`) | **HELD** / **BREAK** / **ERROR** | Exit-equivalent: old exit `1 if n_miss` where `n_miss = break + error`; new exit `1 if (brk or err)`. |
| `residual` (`w84`, `w85`) | **HELD**, note prefixed `residual: ` | The battery's own contract is green on residuals (`n_miss` excludes them; exit 0). They are documented accepted residuals, not findings. The prefix keeps them visible on the line; the migration lane must list every residual pid in its report for human audit. |
| lowercase `"error"` (`w280_redteam`, one reachable site) | **ERROR** | **Known delta (see D9).** The battery currently records lowercase `"error"` but counts only uppercase `"ERROR"` — a genuine error would print `[error]`, miss the tally, and exit 0. Mapping fixes a real under-reporting bug. |

The full audited vocabulary across the 86 (2026-10-03): BREAK, HELD, ERROR, SKIP in 74–75
files; GAP 41; SKIPPED 12; PASS/FAIL 9/14 (FAIL mostly summary-line text); RED 2
(+1 test-data false hit in `w283_osquery`); GREEN 2; BROKEN 1; EXPECTED 1 (dead);
FP 1; lowercase stopped/break/error/residual in the w72–w85 family; lowercase `"error"`
1 live site (`w280_redteam`).

Per-battery verdict exceptions (a battery whose author can show, from the battery's own
exit contract, that a row above mis-states *its* semantics) are allowed, but they must
be filed as explicit, named exceptions in the migration lane's report — never silent.

### D2 — Dict-result emission: one adapter seam in `probe_lines`

The 13 dict batteries (`w279_guardev`, `w280_decisionrecords`, `w280_fga`, `w280_shields`,
`w281_portkey`, `w281_pyrit`, `w281_teleport`, `w282_atomicredteam`, `w282_ratify`,
`w283_osquery`, `w284_tink`, `w285_exceptions`, `w287_ear`) are **uniform**: results are
`{"probe_id", "verdict", "note"}` dicts, printed by
`print("  [%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))`. This is mechanical
after the verdict mapping (D1): add **one** function to `evals/probe_lines.py`:

```
emit_dicts(results, *, verdict_key="verdict", pid_key="probe_id",
           note_key="note", note_getter=None)
```

Contract: each row must carry the three keys (or a `note_getter(row)` callable for
nested shapes like the w72 family's `{"id", "verdict", "detail": {"note"|"error"}}` —
`note_getter=lambda r: r["detail"].get("note") or r["detail"].get("error", "")`).
**Strict on verdicts**: a row whose verdict is not in `VALID_VERDICTS` after D1 mapping
prints an `[ERROR]` line for that pid (fail-closed, loud) — the adapter never silently
maps. Missing keys are likewise `[ERROR]` lines, never skipped rows. The migration
replaces only the print loop; count code is unchanged.

### D3 — Truncation policy: `first_line(note)[:160]`, width owned by the battery

The 10 truncation batteries (`w280_redteam`, `w281_f306`, `w281_redteam`, `w282_redteam`,
`w283_f311`, `w283_redteam`, `w284_redteam`, `w285_f318`, `w285_f320_f323`,
`w286_f327_f328`) print `note[:160]` — all uniform, all S2. Policy: the canonical note
is **`probe_lines.first_line(note)[:160]`**. The 160-char width is a display decision the
red-team batteries already made; the spec does not change it. Rationale for
`first_line` first: the canonical contract requires single-line notes; `note[:160]` on
a multi-line note would emit a line break mid-line that no parser consumes. The
migration lane verifies per battery: diff the probe lines before/after — the only
permitted difference is the 2-space de-indent, plus any multi-line note collapsing to
its first line, which must be enumerated in the lane report. (If no multi-line note
exists in practice, output is byte-identical modulo indent.)

### D4 — Note normalization: `probe_lines.first_line` is the single normalizer

The 3 `str(d).splitlines()[0]` batteries (`w302_redteam`, `w303_f381`, `w303_f382f383`)
migrate to `probe_lines.first_line(d)`. `first_line` is strictly safer than the
hand-rolled idiom: it never raises on empty/odd input (returns `""`), where the
idiom raises `IndexError` on an empty note. The migration can only fix a crash, never
introduce one; before/after probe lines must be byte-identical modulo indent (notes are
non-empty in practice; the lane verifies).

### D5 — Summary reformation: canonical summary first, human conclusions retained

For the 17 non-standard-summary batteries, the mechanical "summary byte-identical"
rule is replaced by **count reconciliation**: the exit code must be byte-identical,
and the canonical `N BREAK / M HELD / K ERROR` summary's counts must reconcile with
the old summary's semantics per the recipe below. Phase/conclusion lines
(`ALL %d PROBES PASS`, `GAP SHOWN: ...`, `RESULT OK/FAIL`, `PRE/POST-SEAM check`,
`green=%s`) are **retained as human conclusions after the canonical summary** — they
carry meaning the canonical form does not, and deleting them would lose information.

Per-class recipes:

1. **HOLD/MISS vocabulary (6: `w72`–`w75`, `w84`, `w85`).** Lowercase columnar
   `%-62s` prints. Map verdicts per D1 (stopped→HELD, break→BREAK, error→ERROR,
   residual→HELD with `residual: ` prefix). Record shape is
   `{"id", "verdict", "detail"}` — use `emit_dicts` with `pid_key="id"` and the
   `note_getter` from D2. Summary: canonical counts; exit `return 1 if (brk or err)
   else 0` — provably equivalent to the old `1 if n_miss`.
2. **Red/green-phase demonstration (5: `decision_packet`, `provisioner`,
   `token_claims`, `tuf_corpus`, `typed_context`).** Two modes: `--red-phase`
   demonstrates the gap (exit 0 = gap shown), default is the green phase. Map
   PASS→HELD, non-PASS→BREAK (D1); emit canonical lines for the executed phase with
   the phase noted in each line's note prefix (`red-phase: ` / `green-phase: `);
   canonical summary; then the phase conclusion line (`GAP SHOWN: ...` /
   `ALL %d PROBES PASS`). Exit codes unchanged. The lane must verify **both modes**
   before/after.
3. **Multi-phase (1: `row12_other_file_tools`).** Three phases (RED with neutralized
   seam, GREEN, GREEN-repeat), all canonical verdicts already. Emit all three
   phases' lines with phase-prefixed pids (`red_<name>`, `green_<name>`,
   `green2_<name>` — pid-class safe, keeps per-line pid uniqueness for coherence);
   canonical summary over the union; keep `GREEN: %d/%d HELD` and
   `ALL EXPECTATIONS MET`/`FAILURES:` as conclusions. Exit unchanged. The red-phase
   BREAKs are expected by the battery's own `expect_break` set — the lane must
   audit parent green checks for this battery (D8).
4. **Dict/kv summaries (2: `row12_undeclared_path`, `w260_f227`).**
   `row12_undeclared_path`: FP→BREAK per D1; canonical summary; keep the
   `PRE-SEAM`/`POST-SEAM check: OK/FAIL` conclusions; exit unchanged.
   `w260_f227`: probe lines are S3 with canonical verdicts (held/broken is an
   aggregate) — emit per-verdict lines, canonical summary from per-verdict counts,
   keep `green=%s` as a conclusion; exit `0 if (broken == 0 and ok)` is
   `0 if (brk == 0 and err == 0 and ok)`.
5. **Conditional-expression summary tuple (2: `w272_isolation`,
   `w273_monitor_accounting`).** Probe lines are S3 with canonical verdicts —
   migrate the print loop with `emit` only. Keep the `RESULT OK/FAIL: ...` line as
   a human conclusion after the canonical summary (the tuple's conditional first
   element is what defeated count-var extraction; leaving the line verbatim
   sidesteps it). Exit unchanged.
6. **`f204_closure` (1).** S3 probe lines with canonical verdicts — `emit` only.
   Drop the dead `EXPECTED` column from the summary (D1); keep `green=%s` as a
   conclusion. Exit unchanged.

### D6 — S6: the literal-`[VERDICT]` shape gets migrated too

Eight batteries (`w310_redteam`, `w311_f395`, `w311_offline_verifier`, `w311_redteam`,
`w312_f396`, `w312_redteam`, `w312_witness_log`, `w313_f397`) print
`"[VERDICT] %s: %s: %s" % (verdict, pid, first)` — the literal word VERDICT. The
codemod classifies them S5 and the green-check `BREAK_ID_RE` captures **nothing**
from them, which makes every `expect_break_ids` list naming their probes **vacuous**
today. They already iterate a `_results` triple list and compute counts from it, so
migration is one loop-body swap to `probe_lines.emit(_results)`. **Consequence the
lane must handle (D8):** after migration, `BREAK_ID_RE` starts capturing their BREAK
ids, turning previously-vacuous `expect_break_ids` lists into enforced ones. The lane
must re-run every parent green check and reconcile each list (wave-305 lesson) —
including stale lists the vacuousness was masking (e.g. lists naming probes for
findings that have since closed).

### D7 — Pid renaming prerequisite (3 batteries)

`w213b_promotion_gate` (`:determinism`), `w214_measurement_policy` and
`w216_jail_policy` (`:determinism`, `green:test_*`) use pids outside the
`[A-Za-z0-9_.\-]+` class. Per the existing spec rule, fix the pid first, separately:
`:determinism` → `determinism`, `green:test_x` → `green_test_x`. Value-only renames;
verify no green-check `expect_break_ids` references the old form.

### D8 — Green-check sweep after every migration

After each battery migration, the lane must: (a) grep the tree for the battery's
filename in any `check_battery`/`expect_break_ids`/`expected_summary` argument and
re-verify each parent; (b) reconcile every `expect_break_ids` list against the
battery's new canonical output — a list that was vacuous under the old shape must
now be accurate, and a list naming closed-finding probes must be swept
(wave-305/306 lesson); (c) confirm no parent depended on the old summary string or
the old per-probe line format. This is per-battery, not per-wave — the S6 and
GAP→BREAK migrations change what `BREAK_ID_RE` captures, which is exactly the
mechanism the green-check contract keys on.

### D9 — Known delta: `w280_redteam` lowercase `"error"`

`w280_redteam` records lowercase `"error"` (reachable: `_seal_verdict`'s
`except Exception` arm) but counts only uppercase `"ERROR"`. Today a genuine error
prints `[error]`, misses the tally, and exits 0. Under D1 it becomes `ERROR` —
the summary and exit code may change. This is a **real bug fix**, not a mechanical
migration: the lane must demonstrate the before/after delta and report it as a
finding fix, never as a quiet byte-identity pass.

## User Stories

1. As a **migration-lane agent**, I want the verdict-mapping table (D1) decided in
   advance, so that I never invent a GAP→? mapping mid-lane.
2. As a **migration-lane agent**, I want the dict adapter contract (D2) specified,
   so that 13 uniform batteries migrate with one code path.
3. As a **migration-lane agent**, I want the truncation rule (D3) and the note
   normalizer (D4) fixed, so that before/after verification has a byte-level oracle.
4. As a **merge coordinator**, I want the summary-reformation recipes (D5) and the
   S6 consequence (D6/D8), so that gates catch regressions instead of the merge.
5. As a **red-team battery author**, I want to know that new batteries must emit
   canonical lines from day one (no new `[VERDICT]`-literal or GAP-verdict
   batteries), so the pool stops growing.
6. As the **repo owner**, I want the falsifiable definition of done, so that
   "migration complete" is checkable, not claimed.

## Implementation Decisions

- **One new seam only:** `probe_lines.emit_dicts` (D2). Everything else reuses
  `probe_lines.emit` / `first_line` / `check_coherence`. No `gov/` changes;
  test-infra only.
- **No new verdicts are added to the canonical vocabulary.** BREAK / HELD / ERROR /
  SKIP stays closed; `check_coherence` is unchanged.
- **Coherence promotion stays gated** on the existing condition: zero non-canonical
  batteries remaining (now including the S6 eight and these 86), then promote
  `check_coherence` from advisory to enforcing in `green_check.py` per
  SUMMARY_FORM_MIGRATION.md §4.
- **The codemod is extended, not forked:** add the S6 classifier + the `emit_dicts`
  path to the canonical `tools/summary-form-migration/` copies, with the D1 table
  encoded as its refusal/mapping rules.
- **Baseline for the lane:** 72/711 canonical (measured 2026-10-03 on `fa0b0ed1`).
  The lane's target set is the 86 below + the 8 S6 batteries.

**The 86 (disjoint classes, verified 2026-10-03):**

- **Unsafe/print-shape (26):** truncation-160 ×10
  (`w280_redteam`, `w281_f306`, `w281_redteam`, `w282_redteam`, `w283_f311`,
  `w283_redteam`, `w284_redteam`, `w285_f318`, `w285_f320_f323`, `w286_f327_f328`);
  dict-results ×13 (`w279_guardev`, `w280_decisionrecords`, `w280_fga`,
  `w280_shields`, `w281_portkey`, `w281_pyrit`, `w281_teleport`,
  `w282_atomicredteam`, `w282_ratify`, `w283_osquery`, `w284_tink`,
  `w285_exceptions`, `w287_ear`); `str(d).splitlines()[0]` ×3
  (`w302_redteam`, `w303_f381`, `w303_f382f383`).
- **Verdict mapping (43):** GAP ×41
  (`claim_bounds` (also BROKEN), `w213b_promotion_gate`, `w214_measurement_policy`,
  `w216_jail_policy`, `w217_quorum`, `w219_regcompile`, `w225_reverify`,
  `w226_gitsan`, `w232_spiffe`, `w236_closebind`, `w237_canonrecord`,
  `w237_gateoutcomes`, `w238_checkpoint`, `w240_boundpermit_followthrough`,
  `w241_aauth_egress`, `w241_probe_classes`, `w241_recompute_check`,
  `w242_absence_epoch`, `w242_containment`, `w242_ir8587_conformance`,
  `w242_stale_authority`, `w243_cosign_interop`, `w243_finality_bound`,
  `w243_transactional_tokens`, `w243_verifier_failclosed`, `w244_config_trust`,
  `w244_guest_host_budget`, `w245_agent_shaped_attack`, `w245_spawn_context`,
  `w246_attested_identity`, `w246_incident_replay`, `w246_policy_delta`,
  `w246_uri_normalization`, `w247_uri_normalize`, `w248_policy_combine`,
  `w248_skill_update`, `w250_decision_log`, `w250_f211_closure`, `w251_redteam`,
  `w252_f212_f213_closure`, `w253_incident`); RED ×2
  (`w284_f312_315`, `w285_f324_f316`).
- **Summary redesign (17):** HOLD/MISS/RESIDUAL ×6
  (`w72`, `w73`, `w74`, `w75`, `w84`, `w85`); red/green-phase ×5
  (`decision_packet`, `provisioner`, `token_claims`, `tuf_corpus`, `typed_context`);
  multi-phase ×1 (`row12_other_file_tools`); dict/kv summaries ×2
  (`row12_undeclared_path`, `w260_f227`); conditional-tuple ×2
  (`w272_isolation`, `w273_monitor_accounting`); `f204_closure` ×1.

(Note: the wave-312 summform5 report's subtotals "44" and "16" were off-by-one; the
true split is 26/43/17 = 86. The battery lists themselves were correct.)

- **S6 (8, not in the 86):** `w310_redteam`, `w311_f395`, `w311_offline_verifier`,
  `w311_redteam`, `w312_f396`, `w312_redteam`, `w312_witness_log`, `w313_f397`.

## Testing Decisions

The migration lane's per-battery checklist (mechanical, verifiable):

1. **Classify** with the extended codemod; confirm the battery is in the 86+S6 set
   and its class.
2. **Map verdicts** per D1 (no invention; named exceptions only, reported).
3. **Migrate the print loop only** (D2/D3/D4/D5/D6 recipes). Probe logic, verdict
   computation, and count code are untouched; `git diff` shows only the print loop
   (+ import) moving, except the D5/D7/D9 named deltas.
4. **Before/after runs** under staging AND `env -u GOV_DEPLOYMENT_MODE`, fresh
   unique TMPDIRs (`mkdir -p` first): exit code byte-identical; canonical summary
   counts reconcile per the recipe; every line parses via `probe_lines.parse_line`;
   probe-line diffs beyond the recipe are enumerated, never silent.
5. **Coherence**: `check_coherence` passes on the migrated battery (advisory
   print today; the lane records any WARNING as a must-fix).
6. **Green-check sweep** (D8): re-run every parent green check referencing the
   battery; reconcile `expect_break_ids`/`expected_summary`.
7. **Pid class**: every pid matches `[A-Za-z0-9_.\-]+` (D7 renames done first).
8. **`w280_redteam`** follows the D9 known-delta procedure.

What makes a good migration test: external behavior only — the battery's stdout
shape, summary counts, and exit code. Never test the adapter's internals from the
battery; `probe_lines` gets its own unit tests.

## Definition of Done (falsifiable)

The migration is complete when **all** of these hold on the tree:

1. Every `evals/*_probes.py` battery either emits canonical probe lines via
   `probe_lines.emit`/`emit_dicts` (parseable by `parse_line`) or is on the
   accepted-summary-only list with a recorded reason (batteries with no per-probe
   data, e.g. TAP-style S5).
2. Zero occurrences of the non-canonical verdict literals (`"GAP"`, `"RED"`,
   `"BROKEN"`, `"SKIPPED"`, `"EXPECTED"`, `"FP"`, lowercase verdicts) in any
   battery's *recorded* verdict position.
3. Zero `print("[VERDICT] ...")` literal-form emitters.
4. `check_coherence` promoted to enforcing in `green_check.py` with zero
   coherence-WARNINGs tree-wide.
5. The merge-time sweep (SUMMARY_FORM_MIGRATION.md §6.5) fails closed on any new
   battery whose probe lines do not parse.
6. Rollout counter: 72/711 → (72 + 86 + 8)/711 = **166/711** canonical minimum
   (plus any S5 batteries the lane triages as migratable along the way).

## Out of Scope

- Changing probe logic, verdict semantics, or product code (`gov/` untouched).
- Migrating summary-only S5 batteries with no per-probe data (they stay on the
  accepted list; synthesising lines is out of scope per the existing spec).
- The `check_coherence` promotion itself (a later wave, once Done holds).
- New canonical vocabulary (no fifth verdict).

## Further Notes

- **New-battery rule (standing):** from this spec forward, every new
  `evals/*_probes.py` battery emits canonical lines from day one — no new
  literal-`[VERDICT]` emitters, no new non-canonical verdicts. The merge-time
  sweep (Done #5) enforces it.
- The 8 S6 batteries are the project's *newest* red-team batteries. Their authors
  believed the `[VERDICT]`-literal form was canonical; the codemod never agreed.
  The D6 migration also fixes the wave-312 red-team observation that
  `expect_break_ids` is vacuous for these batteries — after migration the lists
  are enforced, which is the point, but every list must be re-audited (D8).
- `w215_identity_policy` (migrated wave-312) is the precedent for a dead GAP
  counter: it counted GAP but no code path recorded it. The lane should grep for
  other dead counters while migrating.
- The 18 batteries added between wave-312 (693) and wave-313 (711) were all born
  canonical — the "no new non-canonical batteries" norm is already holding
  informally; this spec makes it a rule.
- Rollout arithmetic: pilot 5 + wave-2 13 + wave-3 32 + wave-4 11 + wave-5 6 = 67
  at wave-312; 72 at wave-313 (4 new wave-313 batteries + 1 reclassified).
