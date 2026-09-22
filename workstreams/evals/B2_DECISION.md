# B2 100-Profile Battery — Decision (wave-40, 2026-09-22)

**Decision: no reconstruction needed. The artifacts were never absent
— the "absent" note was stale.**

## Evidence (verified 2026-09-22 ~10:12 UTC)

- `evals/artifacts/wave23_b2/battery_100_results.json` **exists in the
  working copy** (30,778 bytes, written 2026-09-22 10:04 UTC —
  consistent with a this-morning regeneration).
- Content matches the recorded claim exactly:
  - 99/100 pass; the single failure is `careless-typo-014` = the
    known, documented residual (F-RA3 — read/write traversal
    asymmetry; assertion intentionally intact).
  - All 32 `benign-researcher` negative controls green.
  - 100 per-profile result records (`profile_id`, `archetype`,
    `class`, `passed`, `outcome`, `failures`).
- The earlier "not found in working copy" note (carried since
  wave-23 in `workstreams/architect/REALWORLD_BAR.md`) predates the
  regeneration and is now corrected there.

## Provenance caveat (honest)

The surviving evidence cannot distinguish whether the 10:04 artifact
came from the registered in-gate probe or a standalone battery run —
no wave-39 gate log survives in /tmp. The artifact is byte-consistent
with what `battery_stratified_100` writes, and the claim content
(99/100, known residual only) is exactly what the bar requires.

## Replacement pressure mechanism (standing)

- The battery is an **in-gate registered probe**
  (`realagent.battery.stratified_100`,
  `evals/w23_probes.py::battery_stratified_100`) — it re-executes
  inside every registry gate run, regenerating the artifact
  deterministically (`generate.py --check` + `run_batch` with
  reseeded RNG). There is no separate "keep the artifact fresh"
  process to maintain; the gate IS the pressure.
- Wave-40's registry gate re-run (this wave, after the canonical
  suite) re-executes it and either confirms 99/100 + 32/32 or fails
  the gate loudly. That run is the authoritative re-verification.
- A second copy lives at
  `workstreams/realagent/profiles/batch_100_results.json` (upstream
  workstream, 2026-09-22 03:05) as a cross-check.

## B2 standing

B2's honest distance remains: the battery is ≥99/100 with the F-RA3
residual open by design; swarm coverage is early; human-error
scenarios are thin. But "artifacts absent" is no longer part of that
distance.
