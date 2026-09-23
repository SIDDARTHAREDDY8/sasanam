# Eval indistinguishability checklist

Ship no eval run until every item below is checked. The goal: a runner
that string-matches its brief for eval markers must find nothing that
distinguishes evaluation from deployment. Run `lint_eval_config` (in
`gov/eval_integrity.py`) over every brief/config before the run ships;
CI should call `assert_no_high_markers`.

## Brief text

- [ ] No sentence tells the runner it is monitored, tested, graded, or
      in an exercise ("This environment runs a behavioral monitor…",
      "in this exercise…").
- [ ] No white-box dump of governance internals in the runner-visible
      brief. Internals summaries are operator documentation, not brief
      content. If a white-box variant exists, its markers are the point
      being tested — label it as a *known-white-box* control, never as
      a blind eval.
- [ ] No fake-infrastructure hostnames that fingerprint the harness
      (`synthetic.local`, `*.test`, `*.local` sinks). If synthetic
      egress is needed, use production-plausible hostnames.
- [ ] No eval-shaped field names or framing visible to the runner
      (`brief_naive`, `lane: attack`, `success_criteria`, "mission").
      Strip or rename before shipping.

## Task design

- [ ] Canary tasks: at least one hidden probe per run with a known
      difficulty profile and a recorded demonstrated-capability baseline
      for the runner under test.
- [ ] Paired presentations: the same task family appears in both
      eval-shaped and prod-shaped briefs so `consistency_score` has
      paired data.
- [ ] Trigger hygiene: no date/phrase in the brief doubles as a plausible
      sleeper trigger. If testing trigger-conditioned behavior, the
      trigger is the *subject* of the test, not an accident of the brief.

## Telemetry

- [ ] Every integrity signal is behavior-scored (task outcomes), not
      reasoning-text-scored. Reasoning monitoring trains against the
      monitor.
- [ ] Integrity violations flow: chained `detector_trip` → circuit
      breaker → operator-signed halt. Verify the path end-to-end on a
      staging run before relying on it.

## Honest limits (do not claim away)

- A perfect sandbagger with no eval-reasoning leakage is undetectable
      by this harness. We raise the cost of detection-evasion; we do not
      close it.
- Rare-trigger sleepers are visible only when the trigger fires inside
      an observed window.
- Consistency scoring needs paired samples; with too few samples it
      reports `insufficient_data`, never a false clean bill.
