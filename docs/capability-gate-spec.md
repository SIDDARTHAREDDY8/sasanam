# SPEC — Wire the capability gate to the runtime (Stream 1, wave-100)

## Problem Statement

The capability harness ships a human-review `gate()`, and the safeguard
benchmark renders sealed SUFFICIENT / INSUFFICIENT assessments of a
deployment's governance posture — but no production runtime path consults
either before running agents. A deployment can therefore claim "assessed
SUFFICIENT" while executing on a missing, stale, failed, or forged
assessment, or run with no capability gate bound at all while looking
fully governed. An unwired gate gives a false safety story: the benchmark
grades governance while the runtime never asks.

## Solution

Give every deployment a declared capability-gate binding (which harness,
which harness/thresholds config digest it was assessed against, how fresh
an assessment must be, which keys may seal assessments) and enforce it on
the executor's run path: tool calls and sub-agent spawns are refused
fail-closed — with a chained audit event — unless a valid, fresh,
SUFFICIENT, authentically-sealed capability assessment is presented.
A deployment with no binding is refused loudly at construction with an
explicit error naming the two remedies (configure a binding, or explicitly
acknowledge ungoverned capability mode), so "looks governed but unwired"
is unrepresentable.

## User Stories

1. As a deployment operator, I want to declare my capability gate binding
   (harness id, harness config digest, freshness policy, trusted seal keys)
   once at executor construction, so that every agent run in the deployment
   is checked against the same gate.
2. As a deployment operator, I want the executor to refuse to run agents
   when no capability assessment is on file, so that a missing assessment
   can never read as "assessed".
3. As a deployment operator, I want stale assessments refused — assessed
   against an older harness config digest, or older than my freshness
   policy — so that last quarter's SUFFICIENT cannot bless today's runtime.
4. As a deployment operator, I want INSUFFICIENT assessments to refuse
   execution, so that a failed benchmark actually stops the deployment it
   failed.
5. As a deployment operator, I want forged assessments refused — a flipped
   verdict with a recomputed digest must not verify — so that the gate is
   not theater against an operator who can edit files.
6. As a deployment operator wiring a brand-new deployment, I want a loud,
   explicit error when I forgot the gate ("no capability gate configured —
   configure capability_gate_binding or explicitly acknowledge ungoverned
   mode"), so that I cannot ship an unwired deployment by accident.
7. As a deployment operator who deliberately runs without a gate
   (dev/test), I want to declare that explicitly with a recorded reason,
   so that the choice is visible in the audit chain instead of silent.
8. As an auditor, I want every gate refusal and every ungoverned declaration
   chained into the audit log with a stable event name and a machine-
   readable refusal cause, so that "why didn't this run" is answerable
   from the log alone.
9. As an auditor, I want the binding's harness digest to pin the exact
   thresholds config the assessment was computed against, so that
   threshold-weakening after assessment is detectable.
10. As a red-team analyst, I want the assessment record to be verifiable
    with zero trust in the deployer (recompute report digest, verify the
    Ed25519 seal against operator-published keys), so that forgery claims
    can be tested, not assumed.
11. As a red-team analyst, I want a break-first battery proving each attack
    (missing / stale / forged assessment, unwired-but-governed deployment)
    succeeds against the unwired tree and is refused after wiring, so the
    closure claim is falsifiable.
12. As a long-running deployment, I want to rotate in a fresh assessment
    without reconstructing the executor, so that freshness policy does not
    force restarts.
13. As a parent agent spawning sub-agents, I want the capability gate to
    bind the whole spawn lineage, so that a child executor cannot run with
    a weaker (or no) gate than its parent.

## Implementation Decisions

- New module `gov/capability_gate.py` (the single new seam): the binding
  schema, the assessment-record schema, the harness-config digest
  function, the seal helper, and the verify procedure. No other new
  modules.
- Binding (deployment-declared, validated fail-closed at construction):
  `harness_id` (string naming the assessment harness, e.g. the safeguard
  benchmark assessment class path), `harness_digest` (sha256 over the
  canonical harness id + schema version + thresholds config — the exact
  config the assessment was computed against), `freshness_seconds`
  (maximum assessment age, deployment-chosen), `trusted_keys`
  (key_id → Ed25519 public key, operator trust domain). The seal is
  ALWAYS required: there is no unsealed mode, because an unsealed mode
  would let a flipped-verdict + recomputed-digest forgery pass.
- Assessment record (what the deployment presents): report dict +
  manifest dict. The manifest carries `report_id`, `export_sha256`
  (sha256 of the canonical report bytes), `harness_id`,
  `harness_config_digest`, `assessed_at` (epoch seconds), and an Ed25519
  `signing` block over the canonical manifest minus the signing block —
  the same Ed25519 primitive and canonicalization the safeguard
  benchmark uses. Honest boundary: benchmark manifests do not carry
  `harness_id` / `harness_config_digest` / `assessed_at`, and the
  benchmark's sign bytes additionally exclude a post-seal `receipt` —
  so a raw benchmark-sealed record is REFUSED (missing harness
  binding), not verified. The supported minting path is the seal
  helper, which produces interoperable records carrying everything
  the gate checks.
- Verify procedure (fail-closed, ordered): assessment present →
  harness_id matches binding → config digest matches binding (stale
  config refused) → assessed_at within freshness and not in the future →
  manifest export_sha256 recomputed from the report (content forgery
  refused) → Ed25519 seal verifies against a trusted key — mandatory,
  no unsealed mode (flipped-verdict + recomputed-digest forgery refused;
  unsealed manifests refused) → report verdict reads SUFFICIENT
  (verdict is read only after integrity is established).
- Executor declaration seam: new `ToolExecutor.__init__` kwargs
  `capability_gate_binding`, `capability_assessment`,
  `capability_ungoverned_ack`. A governed-looking deployment
  (governed policy store + delegation context installed — the wave-85
  "governed core") with no binding and no valid ack is refused at
  construction with `CapabilityGateBindingError` whose message names both
  remedies. The explicit ack is non-blank, chained loudly into the audit
  log, and refused outright in production (same posture as the existing
  ungoverned_ack machinery, reusing the deployment-mode resolver).
  Raw-pipeline deployments (no governed core) are untouched: they already
  declare themselves ungoverned under the wave-85 ack, and the gate does
  not pretend to govern them.
- Executor enforcement seam: `ToolExecutor.call()` and
  `ToolExecutor.spawn_sub_agent()` verify the assessment on every
  invocation when a binding is installed (signature verification is
  microseconds; no caching, so rotation and expiry are always current).
  Refusals raise `CapabilityGateRefusal` after chaining a
  `capability_gate_refused` audit event carrying the refusal cause.
- Spawn lineage: the child executor inherits the parent's binding,
  current assessment, and ack — one lineage, one gate.
- Assessment rotation: a small `update_capability_assessment()` setter so
  long-lived deployments can install a fresh assessment without
  reconstructing the executor. The rotation audit record is chained
  BEFORE the state swap: if the log write fails, the old assessment
  stays installed and the error propagates — never a swapped
  assessment with no chained record of the rotation.
- Malformed bindings and malformed assessments are refused fail-closed
  (never treated as "no gate" or "valid").

## Testing Decisions

- What makes a good test here: behavior through the public seam only —
  construct a real `ToolExecutor` (real policy store, real delegation
  context, real Ed25519 keys, real chained log), attempt a real
  `call()` / `spawn_sub_agent()`, and assert refused vs executed. No
  mocks of the gate, no private-method assertions.
- Break-first battery `evals/capgate_break.py` with five situations:
  missing assessment → refused; stale harness digest → refused; expired
  freshness → refused; forged SUFFICIENT (flipped verdict + recomputed
  digest) → refused; governed-looking deployment with no binding →
  explicit construction refusal (not silent pass); plus an acknowledged-
  ungoverned control (declared, chained, constructs). Verdicts
  BREAK / HELD / ERROR, deterministic across two runs, printed as exact
  counts.
- The battery must run red against the unmodified tree: it detects the
  absent seam and scores each attack BREAK (the agent runs ungoverned),
  then green post-fix without battery edits.
- Module-level `os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")`
  and standalone verification under `env -u GOV_DEPLOYMENT_MODE`
  (the harness's declared ungoverned_ack is refused in production mode).
- Expected values from independent sources: digests recomputed by hand in
  the test via hashlib over canonical JSON, verdicts from literal report
  dicts, never recomputed by calling the implementation under test.
- Prior art: `evals/f142_break.py` (probe shape, tally, determinism
  check), `tests/test_w75_governors.py` (governed executor construction),
  `tests/test_w74_identity.py` (bound delegation context construction).

## Out of Scope

- The existing `CapabilityHarness.gate()` delta-measurement wiring
  (capability deltas between log checkpoints) — a separate unwired seam,
  not this stream.
- Changes to `gov/egress_launcher.py`, `gov/sandbox.py`,
  `gov/safeguard_benchmark.py`, `evals/safeguard_results.py`
  (other lanes own these).
- `BUILD_LOG.md` / `evals/FINDINGS.md` edits, commits, pushes
  (central owns these).
- The full canonical suite (this stream runs only its battery plus the
  capability/executor tests it touches).

## Further Notes

- Honest residuals: the binding digest pins the harness config, not the
  model's true latent capability — a SUFFICIENT grade is a claim about the
  assessed configuration, not a measurement of what the model can do.
  Freshness policy is deployment-chosen; a long freshness window is a
  deployment risk decision, not a gate defect. This gate does not stop
  someone editing `gov/` to bypass it — that is the governors' problem
  (Part 7), already covered elsewhere. Seal keys live in the operator
  trust domain; key compromise lets an attacker mint assessments, which
  is a custody problem, not a verification problem.
- The seal is mandatory: no `require_sealed=false` escape hatch exists.
  A flipped-verdict + recomputed-digest forgery fails at signature
  verification because the seal cannot be re-minted without the trusted
  key; unsealed manifests are always refused.
