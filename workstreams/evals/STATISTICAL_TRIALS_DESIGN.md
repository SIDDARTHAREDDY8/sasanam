# Statistical-Trial Methodology for the Adversary Matrix (Wave-54, Priority 2)

**Status: methodology VALIDATED, standing-gate adoption VALIDATED-NOT-NEEDED.**
Pilot: 17 targets × 25 trials, 2026-09-22 — 15 DETERMINISTIC-HOLD,
2 DETERMINISTIC-RESID, 0 FLAKY. The matrix is deterministic within a
25-trial budget, as expected for a rule engine. The runner
(`evals/trial_runner.py`) is kept for break-first lanes, timing-
sensitive cells, and spot-checks — NOT as a standing full-matrix gate.

## Why: the RAMPART import (method, not harness)

Wave-53 intake established RAMPART as a pytest-native safety/security
harness on PyRIT — a *testing* tool, not runtime governance. The
stop-duplicating list forbids building a pytest-harness clone. What we
import is the *method*: repeated randomized trials with statistical
treatment of the results. The problem it solves here is real and
documented in-tree: full-matrix runs under concurrent-lane load
produced moving failures (F86 entry: sit105/sit117/sit132, then sit64
failed across two runs; every failing situation passed in isolation;
failure modes were timing/concurrency-sensitive). A single gate run
cannot distinguish "the control holds" from "the control held this
time". The trial layer makes that distinction explicit.

## What the layer measures

For one probe (a matrix cell or a registry probe), run N trials with
fixed seeds and report:

- **pass rate** p = passes/N, with a **Wilson score 95% confidence
  interval**. With N=25 and 25/25 passes, CI = [0.867, 1.000] — i.e.
  "deterministic hold *within a 25-trial budget*", never a proof of
  determinism. The interval is the honest unit, not the point estimate.
- **ASR (attack-success-rate)** = 1 − p. For matrix cells, "attack
  success" = the cell FAILS its gate expectation. For registry probes,
  "attack success" = observed verdict outside the registry oracle's
  accept set. For a holding control: ASR 0.00, 95% CI [0.00, 0.13].
- **Flakiness as signal.** A probe that flips across trials is
  classified FLAKY and *investigated, never averaged away*. The F86
  load-flakes are the reason this rule exists: averaging a 24/25 pass
  into "green" would launder exactly the timing sensitivity we need
  to see.

## Verdict classes

| Class | Meaning | Action |
|---|---|---|
| DETERMINISTIC-HOLD | all N trials pass the oracle | control holds within budget |
| DETERMINISTIC-RESID | all N trials agree on a residual-accepted probe's documented "break" | boundary stable; kept visible |
| DETERMINISTIC-FAIL | all N trials fail the oracle | stable failure — investigate the *control*, not the trial |
| FLAKY | mixed outcomes | SIGNAL — investigate nondeterminism (timing, ordering, shared state); do not ship on the average |

## Trial hygiene (what makes a trial a trial)

1. **Fixed seeds.** `random.seed(seed_base + target_idx*100003 + trial)`
   per trial. The matrix is a rule engine and mostly seed-indifferent;
   the discipline exists so that when a probe *does* consume randomness
   (future fuzz lanes, jittered playbooks), trials are reproducible.
2. **Isolated TMPDIR per trial**, with the `tempfile.tempdir` cache
   reset (the registry gate's wave-24 hygiene) — plus each cell's own
   F65 tmpdir sweep. No cross-trial filesystem coupling.
3. **Never concurrent with the canonical suite or the full matrix
   gate** (standing rule: TMPDIR/load phantom flakes). Trials run
   sequentially on a quiet tree — which is also why a FLAKY verdict
   under these conditions is meaningful: nothing external was
   perturbing it.

## Pilot design (2026-09-22)

10 matrix cells × 25 trials + 7 registry probes × 25 trials,
seed_base=20260922. Cell selection was adversarial on purpose:
verdict-diverse (blocked ×3, allowed-with-audit ×3), both harnesses
(provisional/real), four adapters, both privilege-relevant roles —
and it *included the historically load-sensitive sits* (sit64 run-dir
TOCTOU, sit105 chain-verification cost) plus sit10 approval-binding
(F124-adjacent surface) and the 7 brand-new RT21 sterile-cockpit pins.

## Pilot results

- **15 DETERMINISTIC-HOLD** (all 10 matrix cells 25/25, all 5 green
  RT21 pins 25/25). ASR 0.00, 95% CI [0.00, 0.13] per target.
- **2 DETERMINISTIC-RESID** (the two RT21 asymmetry pins: 25/25
  "break", the documented steady state — stable, kept visible).
- **0 FLAKY.** Even sit64/sit105 held 25/25 on a quiet tree,
  consistent with the F86 characterization (their flakes appeared
  under concurrent-lane load, not here).

Measured cost: 425 trials in ~10s in-process (~24ms/trial mean;
standalone `run_cell` is ~0.65s due to import overhead). A full
3216-cell × 25-trial standing gate would cost on the order of an hour
per run for zero signal on a quiet tree.

## Verdict: validated-not-needed (as a standing gate)

The pilot did exactly what a pilot should: it tested whether the
method adds signal. It does not — for *this* matrix, *today*. The
matrix is a deterministic rule engine; 25 fixed-seed trials per
target confirm what the single gate run already said. Standing up a
per-wave 80k-trial gate would be theater: cost without information.
Recorded here as **validated-not-needed** rather than adopted, per
the wave-54 brief's explicit instruction not to inflate.

## What IS kept

1. **`evals/trial_runner.py`** — the working runner (matrix cells +
   registry probes, Wilson CIs, FLAKY detection, `--pilot` mode).
2. **Targeted use, not standing use:**
   - Break-first lanes on *new* attack surfaces (RT-style): run the
     new pins through 25 trials before registering them, so a
     load-sensitive pin never enters the registry as "green" on a
     single lucky run.
   - Timing-sensitive cells (the F86 family: warm-tip sweep,
     chain-verification, tmpdir-sensitive cells) get trial treatment
     when they are touched, not every wave.
   - Spot-checks when the full matrix shows a moving failure: the
     trial runner is the diagnostic for "is this cell flaky or is
     the tree red".
3. **Revisit trigger.** If the product ever gains nondeterministic
   machinery (model-sampled playbooks, randomized fuzz lanes,
   wall-clock-dependent verdicts), this document's "not needed"
   verdict expires and the trial layer becomes the gate. The runner
   is already written for that day.

## Deliberately not done

- No pytest harness, no PyRIT dependency, no CI job (would violate
  the $0/standalone constraint and the stop-duplicating list).
- No Bayesian sequential testing / early-stopping: N=25 fixed is
  auditable and reproducible; adaptive stopping complicates the
  "FLAKY is signal" rule (a stop-early rule can hide a late flip).
- No cross-trial state sharing to "speed up" trials: shared state is
  how flakes hide.
