# Canonical probe-line form — spec and migration

**Status:** pilot (wave-308 lane F). Target: every `evals/*_probes.py`
battery prints one canonical probe line per probe.

## 1. Canonical spec

```
[VERDICT] pid: note
```

- `VERDICT` — exactly one of `BREAK`, `HELD`, `ERROR`, `SKIP`, uppercase,
  inside square brackets, at line start (no indent).
- `pid` — the probe id, matching `[A-Za-z0-9_.\-]+`. This class is
  load-bearing: `green_check.BREAK_ID_RE` captures
  `\[BREAK\] ([A-Za-z0-9_.\-]+)`, so any other character silently breaks
  expected-break matching.
- `note` — the probe's human note, **first line only**
  (`note.splitlines()[0]`). Notes stay human text; only verdict/pid are
  machine-parsed.
- **Policy: print every probe, including HELD**, in recording order,
  before the `----` separator and the `N BREAK / M HELD / K ERROR`
  summary line. A battery whose probes all hold must still emit one line
  per probe — otherwise a "≥ 1 probe line" liveness rule cannot
  distinguish "all green" from "printed nothing".

Reference implementation: `evals/probe_lines.py` (`emit`, `format_line`,
`parse_line`, `check_coherence`).

## 2. The five pre-migration shapes (catalogued wave-308)

Probe-line **format** and print **policy** are orthogonal axes; the
observed combinations:

| # | Format | Policy | Example | Who |
|---|--------|--------|---------|-----|
| S1 | `[V] pid: note`, no indent | all probes | `[BREAK] f389-x: ...` | w306, w307_redteam (canonical already) |
| S2 | `  [V] pid: note`, 2-space indent | all probes | `  [HELD] f297-x: ...` | w270, w281–w283, w294–w301 era |
| S3 | columnar `pid VERDICT note`, no brackets | all probes | `f388-foreign-run-replay            HELD   ...` | w217, w219, w225, w246, w260, w272, w273, w303_f388, w303_f390 |
| S4 | S1/S2 format | **non-HELD only** (`if v != "HELD"`) | *(nothing on all-green)* | w297–w302 era, incl. w302_workflow_composed |
| S5 | summary-only or exotic (TAP `ok/FAIL`, `%-42s`, `--` separators, no per-probe lines at all) | n/a | `ok 1 - ...` | older batteries (anchoring, arabic_negation, canary_*, …) |

Notes:

- S2 matches `BREAK_ID_RE` (unanchored) but is not string-canonical;
  normalise by de-indenting.
- S4 is the shape that made a hard "≥ 1 probe line" rule unsound: an
  all-HELD battery legitimately prints zero probe lines.
- S5 batteries keep a results list internally in most cases; where no
  per-probe data exists, synthesising lines is out of scope — S5
  batteries are migrated only if their results list is complete.

## 3. Migration rules

| Shape | Rule |
|-------|------|
| S1 | No change. Assert with `probe_lines.parse_line` in review. |
| S2 | Replace the print loop body with `probe_lines.emit(_results)` (or de-indent the format string). |
| S3 | Replace with `probe_lines.emit(_results)`; pid was field 1, verdict field 2 — the canonical order is `[verdict] pid`. |
| S4 | Remove the `if v != "HELD"` (or `if verdict == "BREAK"`) guard; emit all probes via `probe_lines.emit(_results)`. |
| S5 | If the battery holds a complete `(pid, verdict, note)` results list, emit it. Otherwise leave the battery unmigrated and record it in the rollout plan. |

Mechanical constraints for every migration:

1. **Probe logic untouched.** The diff must show only the print loop
   (and the import) changing. Verify with `git diff`: no probe-body,
   verdict, or count computation may move.
2. **Same summary, same exit code.** Run before/after under staging and
   `env -u GOV_DEPLOYMENT_MODE`; the `N BREAK / M HELD / K ERROR` line
   and process rc must be byte-identical.
3. **pid class.** Every pid must already match `[A-Za-z0-9_.\-]+`; the
   codemod refuses to migrate a battery with a nonconforming pid
   (fix the pid first, separately).
4. **Footer-state probes** keep asserting the current footer
   (`open F391 / next F393` at wave-308); value-only changes.
5. **Coherence check is advisory during migration.** Each migrated
   battery calls `probe_lines.check_coherence(_results, n_break, n_held,
   n_err)` after computing counts; on mismatch it prints
   `coherence-WARNING: ...` (inert to green-check parsers) and keeps its
   verdicts. A printing-hygiene problem must not move a battery's own
   result.

## 4. Coherence semantics (what becomes enforceable)

When every battery is canonical, the following check is sound and may
be promoted from advisory to enforcing in `green_check.py`:

- `len(canonical probe lines) == n_break + n_held + n_err` (SKIP lines
  tallied separately and excluded from the equality),
- every line parses via `probe_lines.parse_line`,
- per-verdict tallies over the lines equal the summary counts.

Until the tree-wide migration completes, the check stays advisory:
a mixed tree cannot distinguish "old shape" from "broken battery".

## 5. Pilot (wave-308 lane F)

Migrated: `w297_supervision_probes.py`, `w299_capability_manifest_probes.py`,
`w300_memory_composed_probes.py` (S2+S4 → canonical), `w302_workflow_composed_probes.py`
(S2+S4 → canonical), `w303_f388_probes.py` (S3 → canonical).
Before/after verification in `~/workspace/teams/wave308-summform/REPORT.md`.

## 6. Rollout plan (for a future wave)

1. Run the codemod (`codemod_summary_form.py` in the lane team dir) in
   `--check` mode tree-wide to classify every battery S1–S5.
2. Migrate S2 and S3 batteries in batches (mechanical, codemod-assisted);
   S4 policy fixes ride along with the format migration.
3. Triage S5: migrate those with complete results lists; schedule the
   rest (or accept summary-only for batteries whose probes are not
   individually addressable).
4. When zero non-canonical batteries remain, promote
   `check_coherence` from advisory to enforcing in `green_check.py`
   (contract rule addition, minor version note in
   `GREEN_CHECK_CONTRACT.md`).
5. Add a merge-time sweep: fail closed on any new battery whose probe
   lines do not parse via `probe_lines.parse_line`.
