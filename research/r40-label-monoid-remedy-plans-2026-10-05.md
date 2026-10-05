# R40 spec: trajectory-level label monoid + remedy plans (OpenAPPA ADAPT)

**Date:** 2026-10-05 · **Base:** sasanam `c47ab9e8` (wave-341 merge) · **Spend:** $0
**Source:** Archestra OpenAPPA (https://github.com/archestra-ai/openappa),
LICENSE.md verified genuine MIT 2026-10-05 by wave-341 lane A (Copyright
2026 Archestra Inc., no riders). Pin any reference to their commit hash,
not `main` (repo is "Preview & RFC", no compatibility guarantees).
**What was stolen:** the PATTERNS (checked label monoid + remedy plans),
re-implemented in Python in Sasanam idioms. The 45k-line Rust engine was
NOT ported. Implementation: `gov/trajectory_labels.py` (new module, overlay
only -- no existing enforcement path changed). Battery:
`evals/w342_r40_label_probes.py` (1 expected BREAK / 18 HELD / 0 ERROR).
Red-first: `evals/w342_r40_arb_redfirst.py`.

## 1. Problem

OpenAPPA's guarantees are conditional on truthful deployment declarations.
A tool result's output label comes from the deployer's annotation delta, so
a mis-annotated tool (`Delta::NONE`) lets secrets cross the trajectory
without the label ever descending: the label tracks *which tools were
used*, not *how sensitive the data is*. This is the **annotation-arbitrage**
class (R40), the direct analog of our F426/F427 declared-name class.
Sasanam's adapter seams need the same truth binding: declarations must be
bound to ground truth by deployment-declared mappings (F427's close-when),
and data-flow labels must be bound to content truth, not just annotations.

## 2. Spec

### 2.1 Label monoid

- `Label(audience, trust, blocked)` where `audience` is a frozenset of
  audience atoms or None (universal, top); `trust` is a 4-tier provenance
  tier (UNTRUSTED < LOW < HIGH < SYSTEM); `blocked` is the absolute-deny
  mark (no authority can permit).
- `combine(x, y)`: the restrictive meet -- audience intersection (None =
  identity), trust minimum, blocked absorbing. Proved never-ascending by
  property probes over a deterministic 21-label corpus (441 pairs):
  `combine(x,y) <= x` and `<= y` under the restrictiveness order.
- `TOP` (universal, SYSTEM) is the identity; `BLOCKED` is absorbing.

### 2.2 Trajectory fold (the anti-arbitrage binding)

- `fold(traj, tool, output, declared=..., registry=..., strict=True)`:
  `content = combine(declared_annotation, truth_label(output))`;
  `new_traj = combine(traj, content)`. The meet can only descend, so a
  mislabeled tool can never raise the label above what the content scan
  justifies -- misannotation is fail-closed by construction.
- `truth_label(output)`: DLP credential scan (`gov.dlp.find_credential`)
  over the bytes. Credential found -> `({self}, UNTRUSTED)`; benign ->
  TOP (neutral element). The truth scan can only descend, never raise.
- Strict mode (default): a tool with no deployment-declared annotation
  refuses outright (`label-annotation-unregistered`) -- the F427-style
  declaration->ground-truth binding.
- `fold_declared_only` is the naive baseline, kept ONLY for red-first
  falsifiability. The red-first script demonstrates the annotation-
  arbitrage bypass against it (public egress ALLOWED -> BREAK) and the
  coded refusal against the hardened fold (HELD).

### 2.3 Check-before-dispatch + remedy plans

- `check_dispatch(traj, recipient, action, recipient_trust_floor)`:
  blocked -> `label-remedy-empty-unliftable`; recipient outside the
  trajectory audience -> `label-egress-refused`; trust below the
  recipient floor -> `label-trust-floor-refused`; else allowed.
- `Remedy` vocabulary (v1): AUTHORIZE, ACCEPT, WITHHOLD, SANITIZE,
  DERIVE, REDISPATCH, FORK. Egress refusals enumerate
  {withhold, sanitize, derive, authorize, redispatch}; trust-floor
  refusals {authorize, redispatch}.
- The EMPTY plan is the proof of unliftability, RELATIVE to the
  implemented vocabulary: the plan digest binds
  `(code, trajectory_digest, action, REMEDY_VOCAB_VERSION)`, so a
  verifier sees the exact scope of the claim. It is not a proof against
  unimplemented remedies -- stated honestly, as OpenAPPA's own plan.rs
  bounds it.
- Every refusal carries a deterministic trajectory digest (hash-chained
  fold) and a canonical JSON record + record digest: evidence-grade,
  recomputable offline without the engine (feeds the sell-evidence story:
  evidence of refusal + enumerated lawful alternatives).

## 3. Honest ceiling (what this does NOT claim)

1. The truth scan is only as good as the detectors. **F428 (OPEN) is the
   documented residual**: JSFuck-obfuscated credentials miss
   `find_credential`, so they miss the truth scan and the label does not
   descend. The battery pins the residual (test_a4); when F428 closes,
   the probe flips to assert descent.
2. The empty-plan unliftability proof is relative to
   `REMEDY_VOCAB_VERSION = 1`; the digest binds the version.
3. `Remedy.SANITIZE` binds a deployment-registered sanitizer; whether
   the transform truly sanitizes is a deployment property, unverified.
4. Membership/directory evidence, adapter event-reporting fidelity
   (Row 8), and sanitizer correctness are out of scope -- the same trust
   boundary OpenAPPA's analysis identified.

## 4. Decision codes (pin 2131 -> 2135)

- `label-egress-refused` (high): recipient outside trajectory audience,
  refusal with remedy plan.
- `label-remedy-empty-unliftable` (high): blocked mark; empty plan is
  the unliftability proof.
- `label-annotation-unregistered` (high): strict fold on an undeclared
  tool; fail closed.
- `label-trust-floor-refused` (high): trajectory trust below the
  recipient floor, refusal with remedy plan.

## 5. Findings

None filed. The annotation-arbitrage bypass reproduces only against the
naive declared-only baseline (kept for falsifiability); the hardened fold
refuses coded. The R40 attack class is recorded for future adapter audits,
not as a finding on the current tree. The F428 residual is pinned, not
filed (already OPEN).

## 6. Open questions for later waves

- Wiring the trajectory label into the live egress/consent/delegation
  seams as an overlay decision aid (currently standalone; existing seams
  remain authoritative by design).
- Whether `truth_label` should consult additional ground-truth sources
  (entropy tripwire is already inside `find_credential`; attachment
  carriers / provenance tiers are candidates).
- The `blocked`-mark term for the taxonomy (lane A recommended adopting
  it; the mark exists in the module, the taxonomy term is deferred).
