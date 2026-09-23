# ASRS-Style Near-Miss Reporting for Agent Governance — wave-75

*Status: docs/process only. This is a reporting convention, not a new
mechanism. Nothing here creates a filing channel or changes any verdict.*

## Why aviation's model

NASA's Aviation Safety Reporting System (ASRS, running since 1976,
2M+ reports) is **voluntary, confidential, non-punitive, and
de-identified**. Its genesis is the load-bearing lesson: in December
1974 TWA Flight 514 flew into Mt. Weather and killed 92; six weeks
earlier a United crew had experienced the *identical* misunderstanding
and narrowly missed the same mountain — but reported it only to their
company, because **no channel existed**. The near-miss died in silence;
the accident repeated it.

The parallel for agent governance is exact. This project red-teams
itself every wave; each probe is a near-miss or a held attack. If the
culture around those findings is punitive ("who broke the build"),
disclosure goes quiet and the silence is what kills you. Findings,
residuals, and boundaries are therefore reported as **blameless
near-misses**: what almost happened, what the mechanism did, and what
changed. The person whose probe caught it is the reporter, not the
accused.

## The ASRS filing shape for this project

Every finding, residual, and boundary note gets the same four-line
treatment:

1. **Narrative (de-identified):** what the attack shape was, in plain
   language. No blame, no authors. ("A key holder re-signed the
   policy-chain records with earlier timestamps.")
2. **What the system did:** which control stopped it, which one merely
   detected it, or which one doesn't exist. Graded honestly:
   - **impossible-by-construction** — the path does not exist (no
     reload-from-disk path; verifier holds only roster public keys).
   - **detected-loudly** — the attack lands but leaves a chained,
     unignorable record (expired break-glass use; anchor catching a
     backdated epoch).
   - **residual** — the attack works or the control depends on a human
     doing the right thing (key-holder can reforge in-chain MACs;
     break-glass review is a human review).
3. **What changed:** the hardening in-wave, or the explicit reason it's
   recorded and not fixed (cost, threat model, design boundary).
4. **Cabin bulletin:** who else needs to know. A residual in
   policy-change control becomes a standing check for every later wave
   (e.g. detection waves consume the in-chain-backdate residual as a
   per-identity baseline requirement).

## This wave's filings (wave-75)

### F-75-01 — Silent policy rewrite attempted: impossible-by-construction
*Narrative:* a process with write access to the policy YAML rewrote
the rules on disk mid-run, expecting the enforcement engine to pick
them up.
*What the system did:* nothing changed. `GovernedPolicyStore.apply()`
is the only governed mutation path; the engine never re-reads the
file, so there is no live target for the rewrite to hit.
*What changed:* nothing needed — the construction removes the path
entirely. The `silent_rewrite_impossible` probe pins this permanently.
*Cabin bulletin:* any future reload-from-disk feature is a
re-opening of this filing.

### F-75-02 — Same-key-two-signatures: detected-loudly (refused)
*Narrative:* a production change was approved by one human signing
twice, attempting to satisfy the two-person rule with one person.
*What the system did:* refused at apply — the nuclear rule counts
**distinct roster keys**, not signatures. PAL two-man-rule doctrine is
explicit that the rule counts people; our count of keys is the
implementation.
*What changed:* the probe `same_key_twice_refused` is registered.
*Cabin bulletin:* one person holding two roster keys is the
PAL-equivalent of one person reaching both launch keys — roster
hygiene (one key per human) is now a deployment procedure, not an
assumption.

### F-75-03 — Key-holder backdates the chained log: residual, loud-but-detected
*Narrative:* a rostered key holder rewrote earlier policy-change
records with earlier timestamps and re-signed them, producing a
chain that verifies in-chain.
*What the system did:* the in-chain MACs verify (stated residual —
same threat model as waves 72/73); the already-published anchor
downgraded the epoch to operator-attested-only (`head_match=False`).
Impossible-by-construction is **not** claimed here; detection-by-anchor
is.
*What changed:* `backdated_change_flagged` probe registered; anchor
downgrade path documented in `workstreams/architect/GOVERNORS_DESIGN.md`.
*Cabin bulletin:* this is the standing argument for wave-76
detection: per-identity baselines over wave-74 identities should watch
for anchor downgrades as tripwires, not routine noise.

### F-75-04 — Break-glass without declaration: impossible-by-construction
*Narrative:* a change was attempted under break-glass authority with
no declaration on record.
*What the system did:* refused — the declaration is the root of the
ceremony; unrecorded use is not a downgraded event, it is a non-event
(the executor cannot enter break-glass mode without an active
declaration).
*Cabin bulletin:* break-glass review remains a human review. The
ceremony records everything; the *quality* of review is still
organizational, not mechanical.

### B-75-01 — Boundary (not a finding): comment-only edits are no-ops
*Narrative:* a policy file was re-saved with only comments and
whitespace changed; no change record was created.
*What the system did:* the canonical digest covers parsed/enforced
meaning, so the no-op produced no change event.
*What changed:* recorded as a boundary, not hardened — semantic
digests are the intended behavior. P8 remains UNCOVERED-by-design and
P13 PARTIAL-by-design for the same reason: format-only churn is not
governed, and that is a choice, not a miss.

## Just-culture rules of this document

- The reporter of a near-miss is never the accused. Every finding in
  FINDINGS.md is credit, not blame.
- A residual is not a failure; an *unrecorded* residual is.
- Boundaries are written down, not wished away. "By design" is only
  allowed with the design reasoning attached.
- The anchor is the independent third party in this system: like NASA
  running ASRS instead of the FAA, the anchor must live outside the
  operator's control for its downgrade verdicts to mean anything.
