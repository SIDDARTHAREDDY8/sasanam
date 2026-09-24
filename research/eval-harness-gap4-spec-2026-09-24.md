# GAP-4: Anti-Sandbagging Eval-Integrity Harness — Spec (2026-09-24)

## Problem Statement

The governance product sells *evidence* that an agent is safe and capable.
That evidence is produced by evaluations. If the evaluated runner can detect
evaluation and deliberately underperform on capability-revealing tasks while
using full capability in deployment ("sandbagging"), the evidence is
worthless and the business thesis collapses. Sandbagging is research-backed
(van der Weij et al.; UK AISI documented evaluation-awareness gaming) and
directly threatens the evidence pipeline.

Existing S4 machinery (`gov/eval_integrity.py`) provides: eval-brief
indistinguishability lint, the `EvalCanary` tripwire primitive,
`consistency_score(eval, deploy)` one-shot comparison, detection hooks
(detector_trip → circuit breaker → halt-request), citation provenance, and
governed report acceptance. What is missing is the *harness* that runs an
eval so sandbagging is structurally harder: nothing binds an eval run's
outcomes to the battery that produced them, nothing requires canaries in a
battery, nothing binds the evaluated model identity to deployment, nothing
tracks demonstrated capability longitudinally per identity, and nothing makes
per-task outcomes tamper-evident before scoring.

## Solution

A new public module `gov/eval_harness.py` implementing the eval-run harness:

1. **Battery manifest commitment** — before the run, the harness assembles a
   battery from a task pool with a committed seed, and chains an
   `eval_battery_committed` record (manifest digest, task ids + order +
   kinds, per-task content digests when the pool supplies them, model
   identity, seed) into the hash-chained log. `build_battery` reconstructs
   the run order from a manifest and refuses a digest mismatch, so
   post-commit task swaps, reorderings, and canary removals are detectable.
2. **Holdout/battery randomization with commit-then-reveal discipline** —
   selection is a seeded deterministic draw; the seed is recorded in the
   commitment so the audit can replay it. Canary items are drawn from the
   same pool distribution (indistinguishable by task shape), and a battery
   with zero canaries is refused at commit time ("a battery without
   tripwires is untrusted").
3. **Deployment-equivalence binding** — the manifest binds the intended
   model identity; `accept_eval_results` compares it against an
   *attested* model identity supplied by the execution substrate (never the
   runner's self-report) and, when given, the deployment's configured
   identity. Mismatches refuse acceptance and file violations.
4. **Longitudinal capability-consistency tracking** —
   `CapabilityConsistencyMonitor` keeps per-(identity, task-family) rolling
   baselines of *deployment-demonstrated* capability and flags eval runs
   that underperform the baseline beyond noise (same one-sided
   Bernoulli bound the `EvalCanary` uses). One-shot
   `consistency_score` cannot see slow drift; the rolling baseline can.
5. **Tamper-evident eval records** — per-task outcomes are chained as
   `eval_task_outcome` records as the run proceeds; `accept_eval_results`
   requires the submitted outcomes to match the chained records exactly
   (set equality, no dupes, no drops), then chains `eval_results_checked`
   binding manifest digest + model identity + per-task outcomes + canary
   verdicts + acceptance flag. Duplicate acceptance for a session is
   refused. A lint (`eval_sessions_missing_battery_commit`) finds eval
   sessions with checked results but no committed battery.

Violations route through the existing S4 detection path
(`report_eval_integrity_violation`): detector_trip + circuit breaker +
operator halt-request. Detection proposes; the operator disposes.

## User Stories

1. As an evaluation operator, I want the battery committed to the chained
   log before the run, so that nobody can swap tasks after seeing them.
2. As an auditor, I want to replay the battery selection from the recorded
   seed, so that the holdout was genuinely random and not cherry-picked.
3. As an evaluation operator, I want a battery with no canaries to be
   refused at commit time, so that tripwire-free evals cannot produce
   trusted evidence.
4. As a deployment owner, I want the eval's model identity bound to the
   deployment's configured model, so that a degraded-substitute model
   cannot launder a passing grade onto the real deployment.
5. As a governance lead, I want eval underperformance vs the runner's own
   deployment-demonstrated baseline to be flagged, so that selective
   capability-hiding is a measurable signal, not a hunch.
6. As an evaluator, I want per-task outcomes chained before scoring, so
   that post-hoc editing of results is detectable.
7. As an auditor, I want duplicate acceptance of one battery's results to
   be refused, so that evidence cannot be double-counted -- while a
   re-run with a freshly committed battery under the same session stays
   possible (distinct battery_ids keep the records distinguishable).
8. As an operator, I want every integrity refusal to arrive as a chained
   detector_trip with breaker containment, so that response follows the
   existing governed path instead of inventing a new one.
9. As a buyer of evidence, I want the eval record to bind battery +
   outcomes + model identity in one tamper-evident artifact, so that the
   "what was tested, what happened, on what model" question has one
   answer.

## Implementation Decisions

- New module `gov/eval_harness.py`; no changes to `gov/eval_integrity.py`
  (reuse, don't fork). Seams are public functions in `gov/` only.
- Manifest digest: two-level SHA-256 construction (the spec's first draft
  stated this circularly -- battery_id cannot be both derived from and an
  input to one digest -- so this is the exact construction the code
  implements): inner = SHA-256 over canonical JSON of (version, seed,
  model_identity, ordered (task_id, kind, family, difficulty,
  content_digest) tuples) under domain prefix `gap4-eval-harness-v1`;
  battery_id = "eb-" + inner[:12] (self-describing); manifest_digest =
  SHA-256 over ("gap4-eval-harness-v1" + NUL + "manifest" + NUL +
  battery_id + NUL + inner). Every field is bound; an auditor replays
  inner first, then the outer.
- `build_battery` additionally refuses when the pool's kind for a task
  disagrees with the manifest's (payload swapped after commitment):
  kind is already digest-bound, so this converts a silent inconsistency
  into a loud refusal with a precise error.
- Duplicate acceptance is refused per (session_id, battery_id), not per
  session alone: a refused acceptance must not block a legitimate re-run
  with a freshly committed battery under the same session, and distinct
  battery_ids keep accepted records distinguishable to auditors.
- Selection: `random.Random(seed)` deterministic draw; canaries drawn from
  pool items with kind "canary", scored from kind "scored". battery_id
  derived from the manifest digest (self-describing).
- Canary scoring reuses `EvalCanary` (seam reuse): demonstrated capability
  per canary set = mean(1 − difficulty); the canary verdict rides the
  existing underperformance math.
- `CapabilityConsistencyMonitor` is a pure in-memory scorer (no log
  dependency); the harness wires its flags into violations. Baselines are
  deployment-demonstrated outcomes only — eval outcomes never train the
  baseline (a sandbagger must not get to lower its own bar).
- `accept_eval_results` check order: (1) manifest digest recomputes;
  (2) outcomes match chained `eval_task_outcome` records exactly;
  (3) task set equals manifest set (no dupes/drops/extras);
  (4) attested model identity equals manifest binding;
  (5) deployment equivalence when a deployment identity is supplied;
  (6) canary verdict; (7) longitudinal consistency. Any failure →
  `accepted=False` + chained `eval_results_checked` + violation on the
  integrity-relevant ones. Structural caller errors (bad manifest shape)
  raise ValueError; evidence failures refuse.
- The attested model identity must come from the execution substrate
  (launcher/sandbox attestation), never the runner. Documented as a
  deployment contract; the synthetic harness takes it as a parameter.
- Signal names: `canary_underperformance`, `eval_capability_drift`,
  `eval_outcome_tamper`, `eval_taskset_mismatch` (outcome task set differs
  from the committed battery: swaps, drops, extras), `model_identity_mismatch`,
  `deployment_inequivalence`. Chained signals: `eval_battery_committed`
  (carries the full ordered task list, not just the digest, so the log
  alone reconstructs the battery), `eval_task_outcome`,
  `eval_results_checked` (carries the per-task outcomes alongside the
  manifest digest, model identity, verdicts, and acceptance flag).
- Lint mirrors `eval_sessions_missing_citation_check` naming/shape.

## Testing Decisions

- A good test asserts behavior at the public seam: commit → build →
  record → accept round-trips; attack shapes refused; honest runs
  accepted. Expected values are independent literals (fixed seeds, fixed
  pools), never recomputed by the implementation.
- Break battery `evals/eval_harness_sandbag_break.py`: 5 sandbagging
  attack shapes (task-swap gaming, model substitution, canary-free
  battery, longitudinal underperformance, post-hoc outcome tampering)
  each demonstrated against the current tree's machinery pre-fix
  (BREAK) and refused/detected by the harness post-fix (HELD), with zero
  battery edits between red and green; 2 controls (honest agent accepted
  without violations; existing `consistency_score` still flags blatant
  paired discrepancy). Module-level `GOV_DEPLOYMENT_MODE=staging`,
  verified standalone and under `env -u GOV_DEPLOYMENT_MODE`.
- Unit tests `tests/test_eval_harness.py` at the public seams.
- Prior art: `tests/test_eval_accept_report.py` (F141 checkpoint tests),
  `evals/f152_hunt_break.py` (red-first battery structure, verdict
  taxonomy BREAK/HELD/ERROR).

## Out of Scope

- Behavioral evals alone cannot RULE OUT sleepers or a perfect sandbagger
  that leaks no eval-reasoning and detects evaluation through channels we
  cannot enumerate. Stated honestly in the module docstring; the harness
  raises the cost and the detection likelihood, it does not certify
  non-deception.
- Task *content* integrity beyond the manifest: content digests are bound
  when the pool supplies them; a pool that lies about content is the task
  registry's problem, not the harness's (documented residual).
- Reasoning/CoT monitoring: the harness scores behavior (task outcomes)
  only, per the existing S4 rationale (monitoring reasoning trains
  against the monitor).
- Production model-identity attestation plumbing (launcher attestation
  format) — the harness defines the contract and the check; the substrate
  supplies the attestation.

## Further Notes

- The seed SHOULD be derived from a chained-log anchor chosen after the
  runner is isolated (commit-then-reveal). The harness records whatever
  seed it is given and makes replay auditable; seed hygiene is an
  operator procedure, enforced by audit, not by code.
- `random.Random` (Mersenne Twister) is used for the draw, not for
  secrets: determinism + auditability is the requirement; the seed's
  unpredictability to the runner comes from the commit-then-reveal
  procedure, not the PRNG.
