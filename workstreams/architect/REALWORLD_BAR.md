# The Real-World Bar

**Version 1 — 2026-09-22 03:44 UTC.** This document operationalizes the mission: *the product genuinely fixes real-world AI governance problems.* It is the definition of done. Green unit tests are necessary but never sufficient. The loop never coasts: **every green gate triggers nastier situations.**

## Honest distance assessment — wave-79 (2026-09-22, rules tiering: the lethal-trifecta as a policy primitive + enforcement wiring, pre-commit for irreversible actions, total decision records)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged in count — wave-79 is a depth wave on the rules layer
  (learnings memo Part 1), not a new incident class. The three axes
  and the trifecta are prior art (Willison, June 2025; Meta's Agents
  Rule of Two, Oct 2025); the wave's invention claim is bounded to
  the policy primitive + enforcement wiring: a closed TOOL_AXES
  registry, tier computed over effective grants (role ∪ verified
  delegation scope ∪ lease scope), a policy-independent approval
  floor on external-comm tools that only ever overrides allow, the
  reserved `trifecta-tier-floor` sentinel, total decision records
  (`policy_version` + `matched_rules`, validator-refused when
  absent), and the pre-commit protocol (preview → digest-bound
  single-use human approval → atomic commit) for the frozen
  irreversible registry. The incident-class probe (mislabeled
  api_call) proves labels escalate but never weaken enforcement:
  read-before-send correlation still queues the exfil; only the tier
  escalation is lost, and the fix is reclassification.
- **B2:** the wave-79 break-first battery is the point of the wave
  (`evals/w79_probes.py`, 11 probes, registered as
  `redteam.rules_w79.*`, pattern RT27): **10 stopped / 1 residual /
  0 break**. Single-tool trifecta (api_call) queued by the floor
  with the sentinel named; three-axis grant composition with no
  single trifecta tool escalates the tier loudly (two-axis control
  does not); cross-hop composition (parent two axes, child adds the
  third) trips the floor with wave-74 attenuation untouched;
  matched_rules spoofing ignored (the record carries the engine's
  list); field-less provenance records refused at build;
  preview-A/executed-B refused; approval replay refused (the ticket
  is consumed atomically by the executing commit — a same-wave
  break→fix, below); forged governed-change records refused while
  the well-formed wave-75 applied path authorizes the exact
  mutation; deny still denies under the floor. The 1 residual is a
  documented classification boundary: write_file destructive
  overwrite executes with the gate installed (classified reversible;
  reclassify through the governed path to gate it).
- **B3:** canonical suite **2683 OK** (2621 + 62 new w79; 8 skipped,
  7 expected failures) — one mid-wave RED was the unconditional
  trifecta floor breaking 75 unrelated tests (my design bug, not a
  flake; resolved honestly, below); the rerun is the number above.
  Registry gate **620/620** oracle matches (609 + 11 new,
  REGISTRY-GATE GREEN; all 11 w79 observed as expected, 10 stopped +
  1 documented residual). Adversary matrix **3216/3216 SHIP-GATE
  GREEN** (1608 provisional + 1608 real). Realistic battery **4/4**.
  Unit `tests/test_w79_rules_tiering.py` + `test_w79_totality.py` +
  `test_w79_precommit.py` **62/62**. Standalone battery **10
  stopped / 1 residual / 0 break**.
- **B4:** no finding filed. Two same-wave break→fix hardenings,
  both caught before landing: (a) the break-first battery caught a
  genuine pre-commit replay bug — the executor `check()`ed the
  bound approval but never consumed it, so the same ticket executed
  twice; fixed to atomic consume-in-commit (`gate.commit` wraps
  `_simulate`; the earlier `check()` stays as the fail-fast denied
  record); (b) the trifecta floor as specified (unconditional)
  broke 75 unrelated tests across 15 files — roles holding api_call
  are elevated from the first call by grant composition, so every
  allowlisted api_call queued; rewriting 75 other waves' regression
  pins was rejected as silent rewriting at scale, and weakening the
  floor was rejected as gutting the claim; resolved as an explicit
  deployment opt-in (`ToolExecutor(..., trifecta_floor=True)`,
  default off = zero behavior change), following the wave-78 opt-in
  gate precedent — documented in the design doc §1, pinned by a
  default-off unit test. The residual (write_file boundary) is
  documented, not filed. F81 stays LOW/OPEN (no egress mechanism
  touched); F29/F70 stay CLOSED; next free finding remains **F129**.
- **B5:** ratchets applied — the approval-queue choke point now
  stamps totality fields on every decision entry (MAC-bound payload
  includes `policy_version` + `matched_rules`); auto-approve is
  disabled for irreversible tools while the pre-commit gate is
  installed (the human moment must be real); the pre-commit commit
  path consumes the ticket atomically (no executor-level replay);
  the irreversible registry has no public mutator (only the
  wave-75 governed path reclassifies).
- **B6:** honest readiness — the graded claim is narrower than the
  wave title: the floor is implemented, probed, and fully tested
  but OFF by default (a deployment decision — enabling it means
  every allowlisted external call in a trifecta session needs a
  human); the tier composes over role ∪ delegation scope, with
  lease scope plumbed but untested end-to-end against real lease
  objects (unit-level only); the pre-commit gate is opt-in and does
  not cover the `execute_approved()` path (the queue's MAC-bound
  approval is the human moment there by design); registry
  reclassification is structural-verified, not yet cryptographically
  re-verifying wave-75 provenance; key custody remains the standing
  prod-KMS priority. Internet intake
  `research/intake-wave79-2026-09-22.md`: two searches (lethal-trifecta framing; NIST AI RMF
  agent governance) + one page opened (the public
  lethal-trifecta-audit skill — its "gate leg 3" fix direction and
  transitive-across-tools closure independently match this wave's
  design; its per-setup framing supports the opt-in decision).

## Honest distance assessment — wave-78 (2026-09-22, supply-chain enforcement: digest-verify every loadable artifact + capability leases, Plugin4Shell response)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged in count — wave-78 is a depth wave on the supply-chain
  incident class, not a new class: the exact CVE-2026-92104
  (Plugin4Shell) refname-shadowing shape is reproduced on a simulated
  legacy path (branch named as the 40-hex pinned SHA shadows the
  commit; attacker bytes load while the caller believes the pin was
  honored) and refused on the governed path (`digest_mismatch`,
  loud, chained). The incident class was already counted; what
  changed is that the refusal is now mechanical (digest pins, no ref
  namespace) rather than procedural.
- **B2:** the wave-78 break-first battery is the point of the wave
  (`evals/w78_probes.py`, 11 probes, registered as
  `redteam.supplychain_w78.*`, pattern RT26): **11 stopped / 0
  residual / 0 break**. Refname shadowing fails closed; digest
  mismatch refused loud with a chained `artifact_load_refused`
  record; the verify→load TOCTOU swap is structurally impossible
  (verification and loading bind to the same in-memory bytes);
  branch names, tags, `latest`, version strings, `FETCH_HEAD`, and
  40-hex git SHAs are all refused AS PIN VALUES; unpinned artifacts
  never load (no TOFU — attacker-first-pin refused as
  `pin_authorship_invalid`); production pins require two DISTINCT
  roster-human approvals over a tier-committed body (single
  approval, same-key-twice, and dev-tier-signature replay all
  refused); stolen leases are refused outside scope
  (`scope_denied`), across tasks (`binding_mismatch`), and after
  expiry (`lease_expired`, no grace); non-authority mint and
  post-mint scope forgery refused (Ed25519); the session opens only
  when no production-shaped raw credential is reachable and the
  verifier graph holds no private key; mid-task expiry halts the
  task until the authority re-mints (executor `lease_refused`,
  loud, audited).
- **B3:** the citation guard stays green in-suite; registry gate
  **609/609** oracle matches (all 11 w78 observed=stopped);
  adversary matrix **3216/3216 SHIP-GATE GREEN**; realistic battery
  **4/4**; canonical suite **2621 OK** (2577 + 44 new w78; 8
  skipped, 7 expected failures).
- **B4:** no finding filed. Three same-wave break→fix hardenings,
  all caught before landing: (a) my registry.yaml append landed
  after the trailing top-level keys — YAML parse error, B3 test RED
  (my bug, not a flake); fixed by moving the entries inside the
  `scenarios` list; (b) the production two-person rule for digest
  pins existed in the design doc but not in `ArtifactPinset.pin`
  (single roster signature) — implemented same-wave: tier-committed
  canonical body, two distinct keys for production, same-key-twice
  refused, dev/test/staging single-human; (c) two probes missed the
  second-signature update after (b) — fixed, battery re-run green.
  F81 stays LOW/OPEN; F29/F70 stay CLOSED; next free finding remains
  **F129**.
- **B5:** ratchets applied — the wave-75 nuclear rule now covers
  digest-pin mutations (not just policy changes); the executor's
  lease gate binds the lease to the executor-held agent identity
  (`identity.agent_id`, not a kwarg), the tool, the
  caller-asserted task framing, and the TTL at every use; the
  minting authority's private key is never in agent-reachable
  state (constructive) and the session asserts no ambient
  production credential is reachable (assertive DLP).
- **B6:** honest readiness — the graded claim is narrower than the
  wave title: `SkillLoader` / `load_file_verified` are governed
  PRIMITIVES, not yet the forced path for the sterile skill-content
  channel, the initial `PolicyEngine(yaml_path)` load, or MCP
  pinsets ("digest-verify every loadable artifact" is the enforced
  direction, not yet the completed wiring); the ambient-clean
  assertion is a helper, not yet wired to session open; pin/load/
  lease events are chained `ActionLog` records, not
  `gov/provenance` schema records; the lease's task binding is
  checked against the caller-asserted `task_id` framing kwarg — the
  containment boundary is the executor-held agent identity + scope
  + TTL (a same-holder cross-task replay gains no scope; the
  residual is mislabeled-task audit entries, stated); key custody
  for the roster, the lease authority, and halt/recovery keys rests
  on the operator's key management (the standing prod-KMS
  priority, not this wave).

## Honest distance assessment — wave-77 (2026-09-22, recovery: "get back to safe" as named, audited operations, Part 6)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-77 is Part 6 (response/recovery) of the governance
  program, built ON the closed F70 (R18): checkpoint → verify →
  resume-or-halt, plus principled decommissioning, each a first-class
  audited operation with stated RTO/RPO-style objectives and the
  test that measures each. The resume story is the industry white
  space (even OpenAI's governance paper stops at "stop it") — this
  wave is differentiation, not catch-up, graded by its battery, not
  by the claim. Fresh intake (Rubrik public-sector CTO, 2026-09-17)
  independently argues the same thesis: "resilience, not shutdown,
  delivers true deterrence" — post-event recovery to a known-good
  state is the missing pillar.
- **B2:** the wave-77 break-first battery is the point of the wave
  (`evals/w77_probes.py`, 8 probes, registered as
  `redteam.recovery_w77.*`, pattern RT25): **8 stopped / 0 residual /
  0 break**. Resume under the halted session's own authority is
  refused LOUD as `resume_authority_not_reissued` (the old session
  dies in the revocation ledger before the new authority exists);
  F52-style journal tampering between checkpoint and resume is
  caught by `chain_to_checkpoint`; forged checkpoints fail the
  dedicated MAC domain; a superseded (rollback-replayed) checkpoint
  fails `fail-checkpoint-superseded` via the operator-pinned
  newest-checkpoint pin (the F72 freshness lesson applied to the
  recovery seam); agent-credentialed decommission is refused at the
  trust-domain check before any step runs; halt without the halt-key
  MAC is refused LOUD and a wrong-domain MAC is refused (a stolen
  halt key is availability-only — it cannot mint checkpoint MACs or
  resume attestations); recorded effects are never re-executed and
  ambiguous half-effects go to the human decision, not an automatic
  retry; a mid-batch trip-drain crash loses zero trips and
  double-triggers zero (re-queue + journaled case-id scan);
  "kill switch tested" (NIST RS.MI-01) is a registered registry
  situation: trip → case → chained `agent_halted` → executor refusal,
  drain→halt 0.8 ms.
- **B3:** every operation's objective names its measuring test
  (checkpoint RPO=0, measured 0.9 ms; verify gate 8 sub-checks
  chained even on fail, measured 1.3 ms; halt RTO drain→halt
  measured 0.8 ms; decommission all-4-steps-or-`incomplete*`);
  the verify gate's `unknown-no-anchor-audit` grading is explicit in
  the chained record — the evidence shows what the gate did NOT
  consult, never a silent pass.
- **B4:** no finding filed. Two same-wave break→fix hardenings, both
  caught by the battery before landing: (a) the trip drain's
  persist-before-append ordering lost a trip's record while marking
  its case id seen on a mid-batch crash — fixed to append-then-
  persist with a pre-append journal scan for already-chained case
  ids; (b) the verify gate's freshness relied on the tip-generation
  pin alone, which never moves unless tips are written — a valid
  older checkpoint was accepted after the log advanced; fixed with
  the operator-pinned newest-checkpoint pin and the halt-time
  re-checkpoint procedure. F81 stays LOW/OPEN; F29/F70 stay CLOSED;
  next free finding remains **F129**.
- **B5:** ratchets applied — the effect journal (`effect_started` /
  `effect_recorded`) makes "journaled effects are never
  re-executed" mechanical, not procedural; the decommission seal is
  a one-way latch (a sealed identity can never resume — only a new
  identity may start work); the halt latch is executor-checked on
  the verdict path and sticky.
- **B6:** honest readiness — the doctrine guarantees forward
  recovery under fresh authority, not time travel: it does not
  un-exfiltrate secrets, undo executed external effects, or detect
  the compromise (wave-76's job); the checkpoint pins journal state,
  not world state; a patient adversary that never trips the
  detector never enters recovery through the trip path (the
  wave-76 slow-boil boundary carries through, visibly); halt-key
  and recovery-key custody rests on the operator's key management
  (the standing prod-KMS priority, not this wave).

## Honest distance assessment — wave-76 (2026-09-22, detection: behavioral circuit breakers, Part 5)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-76 is Part 5 (detection) of the governance program:
  a deterministic runtime statistics layer (EWMA spike + CUSUM drift)
  over the audit stream, wired into enforcement (breaker opens →
  high-risk actions route to the human approval queue, fail-closed).
  It adds no new incident class — it is the *detection* input that
  wave-77 response/recovery will consume. It explicitly does NOT close
  P8 (offline tripwires/judge — still uncovered-by-design): this is
  runtime statistics, a different layer.
- **B2:** the wave-76 anti-deception battery is the point of the wave
  (`evals/w76_probes.py`, 12 probes, registered as
  `redteam.detection_w76.*`): **10 stopped / 2 residual / 0 break**.
  The adversary KNOWS it is monitored: threshold-edge gaming caught
  by CUSUM at bucket 17 (EWMA never fired — the pair's division of
  labor), monitor-blinding floods trip the spike and freeze training
  (the baseline cannot be desensitized mid-attack), cold-start
  poisoning bounded by the conservative purpose-group default (n=0
  until the window ends), the deceptive agent caught by the two
  unseen tripwires (approval-side denial divergence + the
  anchor-downgrade latch — neither visible to nor controllable by the
  agent), trip suppression proven seamed-out (no agent-reachable
  wiring; resets name their resetter), denial-storms bounded (one
  trip record per open transition, no auto-reset). The 2 residuals are
  pinned boundaries, not misses: the patient adversary (0.4σ drift,
  300 buckets, zero trips — the stated slow-boil boundary) and the
  named-human re-baseline (the one operator action that can launder
  drift, chained and named).
- **B3:** the detector's own parameters are auditor-visible in the
  evidence export (`demo/make_report.py` renders
  `gov.detection.export_boundary()` verbatim: windows, α/z/k/h, the
  measured 11-bucket lag, the exact never-trip slow-boil sentence) —
  an auditor sees what drift WOULDN'T trip.
- **B4:** no finding filed. The battery's two initial breaks were
  probe-shape errors, not misses (edge-riding at 2.0σ fired the EWMA
  path by design; the warm-up shape tripped legitimately). One
  same-wave break→fix: the adaptive baseline absorbed a +1σ drift and
  desensitized its own CUSUM (the monitor would have been theater
  against its core gradual-drift claim) — fixed by freezing training
  while CUSUM suspicion is active and seeding the baseline from the
  group default, never from attacker traffic. F81 stays LOW/OPEN;
  F29/F70 stay CLOSED; next free finding remains **F129**.
- **B5:** ratchets applied — retention is now an ENFORCED 288-bucket
  rolling window (exact recompute on eviction, virtual prior survives
  by design), the half-open reset semantics were tightened twice
  (EWMA reseed on reset; CUSUM carried forward only for drift trips,
  else a huge stale `sh` made half-open unclosable).
- **B6:** honest readiness — detection is a tripwire, not a wall.
  The slow-boil boundary is the visible price: a patient adversary
  under the CUSUM reference never trips, and the report says so in
  the same section that lists the thresholds.

## Honest distance assessment — wave-75 (2026-09-22, governors: policy-change control, production two-person approval, break-glass, ASRS)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-75 is Part 7 (governing the governors) of the
  governance program: no new incident classes added — it hardens a
  *meta*-class that every other control depends on. Silent policy
  mutation would defeat all other waves: if whoever changes the rules
  is ungoverned, every enforcement guarantee below is conditional.
  The real-world shape is live, not theoretical: unilateral,
  retroactive rule changes days after an acquisition (Moltbook ToS,
  Mar 2026) are exactly what the governed policy-change primitive
  makes structurally impossible — the substrate operator cannot
  silently mutate the governed rules because no silent path exists.
- **B2:** realistic battery 4/4 (pending re-verification); registry
  619 scenarios expected (610 + 9 new `redteam.governors_w75.*`),
  all 9 probes stopped on standalone battery 9 HOLD / 0 MISS.
- **B3:** the controls that would matter adversarially got nastier
  this wave and held: the nuclear two-person rule now counts distinct
  roster *keys* (same-key-twice refused — one person with two keys is
  PAL doctrine's one person reaching both launch keys); break-glass
  expiry is a chained record, not a silent drop; the key-holder
  backdate residual from waves 72/73 is re-pinned for policy-change
  records and answered by the anchor downgrade, not by the chain.
- **B4:** finding hygiene held: F81 stays LOW OPEN (no egress
  mechanism touched); F29/F70 CLOSED; no genuine
  independently-reachable miss → nothing filed; next free remains
  **F129**. Same-wave break→fix (loader-exception fail-closed) is
  hardened-and-documented, not filed. The ASRS write-up converts the
  B4 posture into process: findings as blameless near-misses, with
  just-culture rules written down so disclosure never goes quiet.
- **B5:** pressure ratchets: disk-rewrite mid-run (impossible by
  construction — no reload path), same-key-twice, undeclared
  break-glass use, post-expiry use, review-gate blocking, key-holder
  backdate vs anchor, in-flight swap version pinning.
- **B6:** honest readiness: the enforcement core now governs its own
  rule changes. A claim audit closed the one weak link in-wave: the
  "every decision record carries the deciding engine's digest" claim
  was false as written (verdict entries didn't stamp it) — `_base()`
  now stamps the call-entry snapshot digest on every verdict-path
  entry, `call()`'s verdict path was audited to zero remaining
  `self.policy` references, and the proof is real calls across a
  swap, not engine-level comparison. Stated boundary that remains:
  `execute_approved()` is a separate entry point using the current
  engine with an explicit policy-staleness refusal — by design, not
  a miss.

## Honest distance assessment — wave-74 (2026-09-22, identity: three-token delegation + spawn lineage)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-74 is Part 4 (Identity) of the governance program:
  no new incident classes added. But it closes a hole inside an
  existing covered class: the delegation chain behind every
  impersonation / confused-deputy / sub-agent scenario is now a
  verified structure (Ed25519, three tokens, per-hop narrowing)
  rather than an assertion. The Red Hat Emerging Tech framing now
  applies honestly to this tree: transport says WHO is calling (F55
  provisioned session identity + process boundary), the application
  layer says ON BEHALF of whom (the three-token chain). We do NOT
  claim live mTLS/SPIRE — the transport layer is local and stated
  as such.
- **B2:** realistic battery 4/4; registry 610 scenarios (569
  executed + 41 delegated), GREEN, with 8 new `redteam.identity_w74.*`
  probes all stopped (forgery, escalation, missing-delegation-under-
  allow-all, cross-session replay, expiry/skew, parent-signature
  swap + splice, middle-hop truncation, valid-chain control).
- **B3:** the controls that would matter adversarially got nastier
  this wave and held: the permission intersection (user ∩ agent ∩
  delegation scope) is enforced in code before policy evaluation,
  so an attacker who rewrites policy text to allow-all still cannot
  act without a valid delegation; the missing-delegation probe is
  the construction proof. MongoDB's Pattern 4 break points are
  pinned as probes: a hop that doesn't narrow is refused at
  issuance AND at chain verification (never trusted), and every
  recipient verifies signatures rather than trusting claims.
- **B4:** F81 stays LOW/OPEN (identity adds nothing to egress
  confinement — said plainly). No new findings filed: the three
  same-wave issues found in review (tokenless-bind error type,
  raw revocation-checker exceptions, unbound leaf-delegation
  subject) were hardened before closeout. Next free: F129.
- **B5:** the ratchet tightened: delegation-schema v2 now requires
  the exact three-ref shape per hop (a fourth token shape is
  structurally refused); wave-73's "version 2 = unknown" test was
  intentionally superseded by the §7 rev contract.
- **B6 (honest readiness):** the enforcement core now has a real
  human-keyed identity primitive — the first key-backed human
  signature in the tree — which is the primitive Wave-75
  (policy-authorship identity) builds on. Still a prototype: no
  live transport identity, no revocation propagation, roster key
  distribution is a deployment act.

## Honest distance assessment — wave-73 (2026-09-22, the provenance record: Art-12-shaped auditor schema + Wave-74 delegation contract)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-73 adds no incident classes — it is Part 3 (Proof)
  of the governance program: the letter inside the envelope. The audit
  chain (HMAC + checkpoints + wave-72 anchoring) is the envelope; the
  provenance record is the auditor-readable schema inside it: every
  governed record carries who/when/resource/outcome, the chained
  delegation path (principal → agent → sub-agent → tool, binds-linked),
  approvals, policy version + matched rules, session timing, payload
  tier, and per-record retention — validator-enforced before append.
- **B2:** Canonical **2412 OK** (2384 baseline + 28 new
  `test_w73_provenance`; 8 skipped, 7 expected failures) — one
  same-wave break→fix caught honestly by the break-first battery: the
  validator initially accepted `approval` records carrying `action`
  fields with no linked decision (the design's §1.2 confusion matrix
  specified the refusal; the implementation missed it) — hardened
  same-wave with a regression unit test, never called a flake. Registry
  gate **GREEN** (602 scenarios; 7 new `redteam.provenance_w73.*` pins,
  all observed=stopped; 41 delegated). Adversary matrix **3216/3216
  SHIP-GATE GREEN** (1608 provisional + 1608 real). Realistic battery
  **4/4**. Break-first **7 HOLD / 0 MISS** (provenance forgery,
  key-holder session backdate residual, record-type confusion, schema
  version games, delegation truncation, payload-tier bypass, valid
  control). No RED anywhere at close; no concurrency violations
  (gates ran strictly sequentially).
- **B3:** B3 citation guard green in-suite; no new
  STANDARDS_MAPPING.md citations this wave (the Art 12 / CSA vocabulary
  is implemented in the export, not cited as control claims — no stale
  or delegated citations possible). New external grounding this wave is
  intake, not control claims: `research/intake-wave73-2026-09-22.md`
  (Art 12(1) automatic-recording as architectural requirement, Art
  12(2) purpose-driven events not payload capture, the Art 12(3)
  Annex-III-1(a)-only scope warning, 6-month retention floor, authensor
  / trust_chain Art-12 mappings as table-stakes honesty notes).
- **B4:** No new findings; **F129** next free. F81 stays LOW/OPEN
  (provenance is evidence-integrity hygiene, not egress confinement —
  wave-73 note appended to `evals/FINDINGS.md`). F29 stays CLOSED
  (disclosure); F70 stays CLOSED (R18 wave-23 — untouched). The
  key-holder session-backdate residual is pinned by probe, not filed
  (designed residual of the anchor cadence: in-chain undetectable,
  anchor-detected). P8/P13 boundaries untouched and unclaimed.
- **B5:** The break-first battery got nastier in exactly the right
  place: the one MISS it found was in the wave's own new code (the
  approval-confusion gap), and the session-timing probe forced the
  threat model honest — the first draft asserted the export-time
  check would flag a post-anchor key-holder backdate, but the anchor
  already downgrades rewritten epochs to operator-attested-only via
  head mismatch, so the probe was rewritten to pin the true residual
  (in-chain passes, anchor catches the rewrite) instead of a fantasy.
- **B6:** Honest readiness: the schema's graded claims are stated
  exactly in `PROVENANCE_DESIGN.md` §8 and the module docstring — the
  schema binds honest writers and gives auditors per-record verifiable
  claims; it does not stop a key-holder (wave-72's model, answered by
  the anchor). The Wave-74 delegation contract (§7) is written as an
  implementable spec: reserved `tokens` slots, binds semantics
  preserved, delegation sub-version revved independently, no fourth
  token shape. Deliberately unbuilt: the three-token identity
  machinery, per-hop scope evaluation, revocation propagation,
  selective disclosure, the commercial evidence pipeline, live Rekor
  submission, P-256 SET verification, anchor-key KMS custody.
  Distance to the bar: the evidence artifact now speaks the auditor's
  vocabulary (Art 12 traceability + retention manifest + live export);
  identity is the open road (Wave-74).

## Honest distance assessment — wave-71 (2026-09-22, in-memory key zeroization + EgressLedger deployment_mode follow-up)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-71 adds no incident classes — it closes
  wave-70's EgressLedger follow-up (one way: no per-ledger mode
  kwarg) and hardens the key-custody seam (zeroization), not an
  incident surface.
- **B2:** Canonical **2356 OK** (2338 baseline + 18 new
  `test_w71_zeroization.py`; 8 skipped, 7 expected failures) — two
  same-wave REDs caught and fixed honestly (a test that asserted a
  byte-identical to_dict round-trip through the lossy legacy
  `key_raw` text path; a test that passed `str` to a
  bytes-only constructor — both real test bugs, never called
  flakes). Registry gate **541/541** (531 + 10 new
  `redteam.zeroize_w71.*` pins, all observed=stopped; 582 scenarios,
  41 delegated). Adversary matrix **3216/3216 SHIP-GATE GREEN**
  (1608 provisional + 1608 real). Realistic battery **4/4**.
  10-probe break-first battery **10 HOLD / 0 MISS** (wipe
  verification, double-wipe safety, use-after-wipe loud failure,
  exception-path wipe, immutable-wipe theater refusal, refcount
  census, env-str residual boundary pin, plus 3 EgressLedger
  deployment_mode probes).
- **B3:** B3 citation guard green in-suite; new external citations
  this wave are zeroization context, not control claims: Python
  discourse on memory-dump exposure (mutable `bytearray` is the
  honest Python-level shape; immutable `str`/`bytes` cannot be
  scrubbed; secrets-in-use cannot hide from a dump; locked memory
  and out-of-process custody need C/HSM), libsodium
  `sodium_memzero` rationale, `MADV_DONTDUMP` for core-dump
  exclusion. Intake: `research/intake-wave71-2026-09-22.md`.
  Design: `research/zeroization-design-wave71-2026-09-22.md`
  (inventory of all wipable vs residual copies, measured
  read-back + refcount census).
- **B4:** Finding hygiene clean — F81 the only open finding
  (LOW, OPEN, accepted filtered-egress gap, unchanged); F129 next
  free. No finding filed this wave (no genuine
  independently-reachable miss; the EgressLedger
  `deployment_mode=` fork was resolved by contract, not a miss;
  the raw-memory reader remains a measured negative, not a new
  miss). F29 stays CLOSED (disclosure) with a residual touch-up
  noted this wave: explicitly-destroyed provider buffers are now
  wiped and fail loud, but dev-era forgeability and the
  immutable/HMAC/allocator residuals are unchanged.
- **B5:** Pressure ratchets: (1) zeroization is now a break-first
  target in the registry (10 pins) — any future key-storage change
  must survive the wipe/census/use-after-wipe battery; (2) the
  `EgressLedger` no-fork contract is pinned by 3 registry probes —
  any future attempt to add per-ledger mode semantics must survive
  the kwarg-mismatch-fails-loud and inherit-env-mode probes;
  (3) `DestroyedKeyError` makes post-destroy serialization fail
  loud by construction, so a wiped key can never silently persist
  as None/zeros.
- **B6:** Honest readiness — the genuinely new closures this wave:
  (a) `gov/zeroize.py` (`zeroize()` fail-loud on immutables,
  `key_buffer()` exception-safe context manager);
  `KeyMaterial`/`KeyRing` store `bytearray` copies and
  `destroy()` wipes the real provider buffer (read-back proof)
  then drops the reference so post-destroy use raises loud; (b)
  the EgressLedger wave-70 follow-up resolved ONE way by contract:
  no `deployment_mode=` kwarg, process-level
  `GOV_DEPLOYMENT_MODE` moves log and ledger together, per-ledger
  forking rejected by construction (`TypeError`). The verdict that
  matters: against the wave's stated raw-memory threat (core dump,
  `/proc/<pid>/mem`, scraper), the mechanism is an honest
  NEGATIVE — CPython immutable `os.environ` `str`, immutable
  `.encode()` `bytes`, and the HMAC C module's internal copy are
  outside Python's reach (measured, documented, not fixed). The
  shipped layer is discard-time wiping for explicitly-destroyed
  provider buffers + fail-loud post-destroy use: defense-in-depth
  against the stale-key-in-dumped-memory class, not a defeat of
  memory readers. Deliberately unbuilt: C-extension locked-memory
  backend (`mlock`, `MADV_DONTDUMP`, secure allocator), HSM/KMS-side
  HMAC, removing environment-string key transport, per-context
  DEKs, the commercial evidence pipeline. Distance to the bar:
  the key lifecycle is fail-closed, machine-audited, and now
  wipe-capable at discard time; deployment-grade custody (the key
  never entering CPython as a string) and the wall (F81) remain
  the open road.

## Honest distance assessment — wave-72 (2026-09-22, Haber–Stornetta anchoring of the audit chain — closeout)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-72 adds no incident classes — it is the
  evidence-integrity primitive the mission's "sell evidence, not the
  engine" bet needs: Ed25519-signed anchor statements witnessed by
  Sigstore Rekor v1 (`hashedrekord`), so the HMAC-key holder cannot
  rewrite history before the last anchor undetected.
- **B2:** Canonical **2384 OK** (2356 baseline + 28 new
  `test_w72_anchor`; 8 skipped, 7 expected failures) — one
  closeout RED caught and fixed honestly: wave-72's `epoch_id`
  entry field (~24 bytes) tipped the r5 size-guard test's 600-byte
  arithmetic (603 > 600 projected) — the guard was behaving
  correctly, the test's numbers were stale; cap recalibrated to 700
  with the refusal behavior re-verified, never called a flake.
  Registry gate **GREEN** (595 scenarios; 13 new
  `redteam.anchor_w72.*` pins, all observed=stopped; 41 delegated).
  Adversary matrix **3216/3216 SHIP-GATE GREEN** (1608 provisional +
  1608 real). Realistic battery **4/4**. Break-first battery
  **13 HOLD / 0 MISS** (key-holder rewrite after anchor detected,
  wall-time tamper breaks MAC, stored-statement head tamper detected,
  witness-time games refused, inclusion-proof forgery detected,
  anchor-interval residual pinned numerically, hash-only witness
  boundary on all three backends, async witness failure loud + chain
  continues, recover() requeues exactly once, sandbox/anchor
  layering, double-anchor idempotence, unknown-backend-tag
  fail-closed, realistic 2-leaf RekorBackend proof round-trip) plus
  **9/9 adversarial extras** (epoch_id caller-clobber, statement
  extra-field rejection, mixed-backend callable audit, empty/not-due
  anchor states, cross-epoch move breaks MAC).
- **B3:** B3 citation guard green in-suite; external citations this
  wave are anchoring context, not control claims: the Sigstore Rekor
  v1 `hashedrekord` 0.0.1 envelope shape (1 search + 1 page opened —
  the pinned `https://rekor.sigstore.dev/api/v1/log/publicKey`
  endpoint, verified byte-for-byte against the code pin with the
  log-id cross-check), Haber–Stornetta 1991 as the design basis.
  Intake: `research/intake-wave72-2026-09-22.md` — written honestly
  at closeout: the REST mapping was NOT validated against live Rekor
  (no `POST /api/v1/log/entries` ever submitted from this
  environment); the false "exactly one live Rekor submission"
  claim in `ANCHOR_DESIGN.md` was corrected in writing, not
  papered over.
- **B4:** Finding hygiene — F81 the only open finding (LOW, OPEN,
  accepted filtered-egress gap, unchanged); F29 stays CLOSED
  (disclosure). **F70 discrepancy flagged:** the closeout handoff
  said F70 MEDIUM/OPEN, but the finding ledger says CLOSED (R18,
  wave-23 crypto/log) with the mechanism (`_marker_sets`,
  `_append_tip_gen_pin`) verified still in `gov/log.py` and the
  regression tests present — wave-72 touched none of it, so the
  ledger stands unchanged; the handoff was stale. No finding filed
  this wave: the self-attested Rekor root (receipt-carried
  `rootHash`, SET carried-not-verified) was adjudicated as a
  documented boundary, not F129 — the `anchored` grade is
  conjunctive and the crown-jewel attacker (HMAC key, no anchor
  key) is stopped at `statement_sig` before the root matters; it
  becomes load-bearing only under anchor-key compromise (already
  total by the key-custody model) or for third-party verifiability
  (wave-73 hardening: P-256 SET verification or the v2 Ed25519
  shard). **F129** next free.
- **B5:** Pressure ratchets: (1) 13 anchor probes in the registry —
  any future anchor/epoch/statement change must survive the
  key-holder rewrite battery; (2) the 2-leaf RekorBackend proof
  probe pins the RFC 6962 path — it caught a real top-down
  proof-consumption bug same-wave (failed for trees > 2 leaves);
  (3) the `epoch_id` HMAC binding is now load-bearing for anchors —
  any future entry-schema change must re-run the size-guard
  calibration (the r5 closeout lesson: schema changes move byte
  arithmetic).
- **B6:** Honest readiness — the genuinely new closures this wave:
  (a) `gov/anchor_backend.py` (Ed25519 statements, FakeWitness /
  LocalAnchorLog / RekorBackend, RFC 6962 verification); (b)
  `gov/anchorer.py` (epoch policy 100 records / 3600 s,
  executor-side daemon, loud unanchored marking, bounded retries +
  `recover()`, conjunctive `audit_anchors` grading
  `anchored` vs `operator-attested-only`); (c) the load-bearing
  guarantee holds as stated: "no undetected rewrite of history
  prior to the last anchor" — history after the last anchor is
  soft, and the anchor cadence is the security parameter. The
  verdict that matters: against the documented crown-jewel threat
  (HMAC-key holder WITHOUT the anchor key, reforging chain AND
  checkpoint sidecar), every rewrite is detected — the forged chain
  verifies, but the anchor catches it (pinned by probe, not by
  prose). Deliberately unbuilt: a live Rekor submission (the wire
  path is schema-conformant by construction + test, not by live
  exercise), P-256 SET verification, STH-signature/consistency
  verification for third-party verifiability, cloud KMS anchor-key
  custody (envelope seam exists, no backend), the commercial
  evidence pipeline. Distance to the bar: the audit chain now has
  an external-witness story that survives its own key holder; the
  wall (F81) and deployment-grade key custody remain the open road.

## Honest distance assessment — wave-70 (2026-09-22, key-management hardening completion: deployment_mode kwarg wiring + HMAC key-path audit as a standing test)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-70 adds no incident classes — it closes wave-69's
  two loose ends by mechanism (kwarg wiring, audit formalization),
  not an incident surface.
- **B2:** Canonical **2338 OK** (2313 baseline + 14 new
  `test_w70_key_management.py` + 11 new
  `test_w70_hmac_chokepoint_audit.py`; 8 skipped, 7 expected
  failures) — two same-wave REDs caught and fixed honestly (a
  missing keyword-only marker on `require_key()`'s new kwarg; a test
  that asserted unknown-mode fail-fast before the opt-in path
  reached mode resolution — both real test/setup bugs, never called
  flakes). Registry gate **531/531** (525 + 6 new
  `redteam.keymgmt_w70.*` pins, all observed=stopped; 572 scenarios,
  41 delegated). Adversary matrix **3216/3216 SHIP-GATE GREEN**
  (1608 provisional + 1608 real). Realistic battery **4/4**. 6-probe
  break-first battery **6 HOLD / 0 MISS** (kwarg authority both
  directions, fail-fast at construction, no-fallback refusal,
  require_key wiring, env-key closure pin).
- **B3:** B3 citation guard green in-suite; new external citations
  this wave are key-management context, not control claims: FileRise
  CVE-2026-77427 (Aug 2026, fixed v3.22.0 — fail-open default key;
  "a remediation that lives in one deployment mode's tooling instead
  of in the application's own logic" is the exact shape of the
  wave-69 kwarg loose end; "fail closed when it can't" mirrors F73;
  no-blind-re-rotation mirrors our never-re-sign migration rule),
  AWS KMS HMAC keys (no automatic rotation — confirms the epoch
  model for the envelope seam), key-separation discipline notes
  (allowlist-not-denylist corroboration for the audit test). Intake:
  `research/intake-wave70-2026-09-22.md`.
- **B4:** Finding hygiene clean — F81 the only open finding
  (LOW, OPEN, accepted filtered-egress gap, unchanged); F129 next
  free. No finding filed this wave: the break-first scratch module
  (temporary unguarded `hmac.new`, 3 alias shapes) drove the new
  audit test RED by design and was removed — a test proving itself,
  not an independently-reachable miss. F29 stays CLOSED (disclosure)
  with a slightly shrunken residual (per-call-site production
  declaration now possible; dev/test-era chains still publicly
  forgeable, local-consistency evidence only; custody still local
  software, no HSM).
- **B5:** Pressure ratchets: (1) the `deployment_mode=` kwarg is now
  a first-class break-first target in the registry (6 pins) AND in
  the unit suite — any future change to mode precedence must survive
  the kwarg-vs-env conflict battery; (2) the HMAC key-path audit is
  now structural, not informal: ANY new `hmac.new`/`HMAC`/`digest`
  call site under `gov/` fails the suite until a human allowlists it
  with a custody story (alias-aware; stale entries fail too), so the
  "every HMAC key path flows through the guarded chokepoint" claim
  is now machine-checked on every run.
- **B6:** Honest readiness — the genuinely new closures this wave:
  (a) keyword-only `deployment_mode=None` on `ActionLog.__init__`
  and `keys.require_key()`, flowing explicit-kwarg > env >
  default-production into `append`/`write_checkpoint` and the
  contradiction check, unknown modes failing fast at construction —
  direction (a) chosen because keyword-only default-None cannot
  break any existing caller (verified: full suite green, no caller
  changes needed); surveyed-and-deliberately-not-wired:
  `EgressLedger` (contract is "same key epochs as the action log" —
  forking mode semantics between a log and its ledger is a
  follow-up), `require_production_key()` (always-production by
  contract), explicit provider selectors (mode-agnostic by design),
  module-level verify helpers (verification must work regardless of
  a creation-time declaration). (b) The AST-based HMAC audit test
  with 13 allowlisted sites, each carrying a custody story; the
  documented residual gap is fully dynamic indirection
  (`__import__`/`getattr` tricks, vendored HMAC) — accepted as a
  boundary (source-write threat model), not a finding. Deliberately
  unbuilt: cloud HSM/KMS custody, in-memory key zeroization, the
  commercial evidence pipeline. Distance to the bar: the key
  lifecycle is now fail-closed at every entry point AND
  machine-audited; the wall (F81) and deployment-grade key custody
  remain the open road.

## Honest distance assessment — wave-69 (2026-09-22, prod KMS/key management — kill the dev-key fallback)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-69 adds no incident classes — it closes a key-custody
  gap, not an incident surface.
- **B2:** Canonical **2313 OK** (2266 baseline + 47 new
  `test_w69_key_management.py`; 8 skipped, 7 expected failures) —
  two same-wave REDs caught and fixed honestly (a broken helper import
  in `keys.require_key()`'s contradiction check; order-dependent
  once-per-process warning assertions — both real test/setup bugs,
  never called flakes). Registry gate **525/525** (510 + 15 new
  `redteam.keymgmt_w69.*` pins, closure: green; 566 scenarios, 41
  delegated). Adversary matrix **3216/3216 SHIP-GATE GREEN**
  (1608 provisional + 1608 real). Realistic battery **4/4**. 15-probe
  break-first battery **15 HOLD / 0 MISS** (fallback resurrection,
  key confusion, rotation+splice, lost key, era-marking honesty,
  legit staging/dev closure pin).
- **B3:** B3 citation guard green in-suite; new external citations
  this wave are key-management context, not control claims: JFrog
  Artifactory CVE-2026-82329 (CVSS 9.8, blank-32-byte default HMAC
  secret → forged admin tokens; "patch does not revoke minted tokens"
  → rotation is an explicit operational step), Authlib CVE-2026-27962
  (key=None → library trusts the attacker's embedded key — the
  never-trust-the-artifact-for-your-key analogue), 2026
  envelope-encryption best practices (root > KEK > DEK hierarchy, old
  versions decrypt / latest encrypts — exactly our epoch model,
  in-memory zeroization — a recorded gap). Intake:
  `research/intake-wave69-2026-09-22.md`.
- **B4:** Finding hygiene clean — F81 the only open finding
  (LOW, OPEN, accepted filtered-egress gap, unchanged); F129 next
  free. No finding filed this wave (no genuine
  independently-reachable miss; the `require_key()` same-wave gap got
  a same-wave fix, not a finding number; dev-era forgeability is the
  F29 documented posture — refuted as a new finding, recorded as a
  boundary).
- **B5:** Pressure ratchets: key management is now a break-first
  target in the registry (15 pins), so any future key-path change
  must survive the fallback-resurrection battery; the
  production/dev contradiction is structural (loud refusal, not a
  warning); the deny-list-completeness audit is recorded as future
  work (every HMAC key path verified to flow through the guarded
  chokepoint this wave).
- **B6:** Honest readiness — the genuinely new closure this wave:
  `gov/keyprovider.py` (KeyProvider ABC + Dev/Env/File/EnvelopeKms
  providers), the `GOV_DEPLOYMENT_MODE` rule (explicit > env >
  default-production; unknown fails fast), and the
  production+double-opt-in contradiction refusal wired into BOTH
  `gov/log.py::_active_key()` and `keys.require_key()`. What existed
  before and is NOT claimed as new: the F73 strict resolver, 0600
  file-backed KeyRing with epochs/rotation, the envelope provider
  and FakeKmsProvider, chained rotation events. F29 stays CLOSED
  (disclosure) with a shrunken residual: dev-keyed chains can no
  longer START on production-mode paths; dev/test-era chains remain
  publicly forgeable and are local-consistency evidence only.
  Deliberately unbuilt: cloud HSM/KMS custody, in-memory key
  zeroization, the commercial evidence pipeline. Distance to the
  bar: enforcement core + evidence export are a solid,
  honestly-tested prototype; the wall (F81) and deployment-grade key
  custody remain the open road.

## Honest distance assessment — wave-68 (2026-09-22, attribution in the evidence export + registration-authority reference design)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-68 took Branch A of wave-67's Q4 (the evidence
  export EXISTS in-repo: `demo/make_report.py` renders the
  hash-chained log as an auditor-readable Markdown+HTML audit
  report): the authenticated-attribution mark now flows into the
  export as first-class fields — `attribution`
  (authenticated/unattributed) and `token_id`, rendered VERBATIM
  from the verified chain (never invented, upgraded, or
  downgraded), plus an "Acknowledgments (consumer attribution)"
  section with a validity-at-time note: "authenticated" describes
  the ack's recorded time, token_id + ts lets the auditor check the
  registration authority's revocation ledger as of that ts, and the
  export never asserts current validity. The deployment-side
  authority that makes those marks meaningful got its reference
  design (no code): `workstreams/architect/
  REGISTRATION_AUTHORITY_DESIGN.md` — operator-console vs
  IAM/workload-identity issuance shapes, onboarding flow (identity
  proof → approval → issuance → audit record), revocation UX
  (propagation-to-verify SLA, emergency brake), verify-only run-side
  wiring, audit of the registry itself (token_id without an issuance
  record is a finding), and a threat model (rogue operator,
  compromised IAM, authority outage, stolen/forged tokens, audit-log
  tamper — what breaks, what stays standing), with every
  deployment-choice dependency marked.
- **B2:** Canonical **2266 OK** (2258 baseline + 8 new
  `test_w68_attribution_export.py`; 8 skipped, 7 expected
  failures) — one same-wave RED caught and fixed honestly (the new
  required `acks` render parameter broke 3 existing callers in
  `tests/test_hardening_r7.py`; made optional, re-run green — a real
  regression, not a flake). Registry gate **510/510** (551 scenarios
  — 506 + 4 new `redteam.sterile_d5_export.*` pins, closure: green;
  41 delegated). Adversary matrix **3216/3216 SHIP-GATE GREEN**
  (1608 provisional + 1608 real). Realistic battery **4/4**. 4-probe
  break-first battery **4 HOLD / 0 MISS** (forged-attribution tamper
  breaks the chain → export renders FAILED; no silent upgrade path;
  revoked-token records keep honest historical marks with
  validity-at-time semantics; end-to-end chain-verify → fields
  first-class in Markdown+HTML). Intake:
  `research/intake-wave68-2026-09-22.md` (2 searches + 1 page —
  vaara EU AI Act Aug 2026: Omnibus VII Reg (EU) 2026/1744 moves
  high-risk to 2 Dec 2027 / 2 Aug 2028, Art 50 + GPAI enforcement
  live 2 Aug 2026, C(2026) 5054 para 31 "on whose behalf"
  attribution obligation; sanction signed audit export; acgs-lite
  chain-vs-receipt "both must hold"; NHI crosswalk JIT/short-lived/
  anomaly-triggered revocation corroborating the lane-2 design).
- **B3:** B3 citation guard green in-suite; new external citations
  this wave are standards-context (EU AI Act Omnibus VII timeline,
  NIST AI RMF NHI mapping), not control claims. Vaara's and
  sanction's signed hash-chained exports with named attribution and
  "what it proves / does not prove" honesty language independently
  converge on the wave-68 export shape.
- **B4:** Finding hygiene clean — F81 the only open finding
  (LOW, OPEN, accepted filtered-egress gap, unchanged); F129 next
  free. No finding filed this wave (no genuine
  independently-reachable miss; dev-key whole-chain forgery is the
  F29 documented posture, anonymous laundering the wave-67 designed
  boundary — both refuted as findings, recorded as boundaries).
- **B5:** Pressure ratchets: the export is now a break-first target
  in the registry (4 pins), so any future export change must survive
  the forged-mark / silent-upgrade / revoked-validity / end-to-end
  battery; the render signature is backward-compatible by
  construction (optional `acks`).
- **B6:** Honest readiness — the evidence bet's Q4 is answered by
  mechanism (attribution is now auditor-readable in the export with
  validity-at-time semantics) and Q3 by reference design (the
  deployment-side registration authority, design-only). What is NOT
  claimed: the commercial pipeline (metering/billing/SaaS export) is
  deliberately unbuilt; the authority design's trust anchor
  (HSM/KMS mint-secret custody, trustworthy clock, identity plane)
  is deployment-owned and unproven here; under the dev key the
  export is forgeable by design (F29 says so loudly). Distance to
  the bar: enforcement core + evidence export are a solid,
  honestly-tested prototype; the wall (F81) and deployment-grade key
  management remain the open road.

## Honest distance assessment — wave-67 (2026-09-22, authenticated consumer registry)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-65/66's documented gap — consumer identity in the
  D5 acknowledgment trail was self-attested — is now closed by
  mechanism: `ConsumerRegistry` (deployment-scoped issuance/
  verification authority), `ConsumerToken` (256-bit HMAC-bound bearer,
  non-serializable/non-copyable), `ConsumerAuthError` (fail-closed
  loud). `acknowledge()` accepts an optional (token, registry) pair:
  verified pairs chain `"attribution": "authenticated"` with the
  public `token_id`; everything else stays honestly
  `"attribution": "unattributed"` — tokens are never mandatory
  (Wave-49 lesson). The executor never issues tokens (a run minting
  its own evidence tokens is self-attestation with extra steps).
  Revocation/expiry fail future acks loud; history is append-only
  (validity-at-time via token_id + ts). The precise claim is pinned:
  "authenticated" proves token possession at ack time bound to the
  named consumer — NOT human identity, NOT non-theft (F59-class
  residual, stated in `workstreams/evals/CONSUMER_REGISTRY.md`).
- **B2:** Canonical **2258 OK** (2228 baseline + 30 new
  `test_w67_consumer_registry.py`; 8 skipped, 7 expected failures).
  Registry gate **506/506** (547 scenarios — 539 + 8 new
  `redteam.sterile_d5_reg.*` pins, closure: green; 41 delegated).
  Adversary matrix **3216/3216 SHIP-GATE GREEN** (1608 provisional +
  1608 real). Realistic battery **4/4**. 8-probe break-first battery
  **7 HOLD / 1 BOUNDARY / 0 MISS** (forgery/bit-flip/foreign-token
  refusal, cross-name theft refusal, same-id distinguished by
  token_id, revocation fail-closed with intact history,
  no-silent-degrade, ttl expiry, legit-loop regression; the boundary:
  anonymous laundering honestly marked `unattributed` — no silent
  path to `authenticated`). Intake:
  `research/intake-wave67-2026-09-22.md` (1 search + 1 page — CyClaw
  auth design; 2 applied learnings: live-revocation-state beats
  stateless tokens + named-individually-revocable tokens are the
  attribution primitive).
- **B3:** B3 citation guard green in-suite; standards-control
  adversarial probes unchanged and green inside the matrix.
- **B4:** F81 stays LOW/OPEN — no F81 mechanism touched; no F129
  filed (no genuine independently-reachable miss — every attack
  lane held or graded as designed boundary). Next free F129.
- **B5:** Pressure ratchet shipped: the wave-65-flagged ratchet
  (self-attested → authenticated consumer identity) is closed by
  mechanism with honest unattributed marks where no token is
  presented. Remaining ratchets: first real `VettingStack`
  deployment consumer; first real `drain_ack_sink` deployment caller
  (consumer-side sink lifetime, drain cadence); deployment
  registration-authority reference design for the evidence bet;
  authenticated-attribution in the metered-evidence export schema.
- **B6:** Verdict **shipped** — ack evidence now carries
  registry-authenticated attribution where a token is presented
  (7/8 attack lanes hold; the 8th is the designed anonymous path,
  honestly marked), legacy flows are byte-identical, and the chain
  still verifies end to end. Not claimed: human identity
  (registrations, not people), non-theft under the bound name
  (possession is the claim), or a real deployment registration
  authority (in-repo stand-in; the executor never holds mint power).

## Honest distance assessment — wave-66 (2026-09-22, per-run cumulative ack flood budget)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-65's deliberate gap — the per-sink budget bounds
  one batch before one drain, so repeated drain/refill cycles could
  grow the hash chain without bound per run — is now closed by
  mechanism: a per-RUN cumulative cap (8 full sink batches, 2048 at
  the default) enforced at `ToolExecutor.drain_ack_sink`, the choke
  point into the chain. The counter lives on the run (executor +
  `.ack_cumulative` run-dir marker), never the sink: sink
  replacement, executor re-creation, and window close/reopen all
  leave it standing. Exhaustion refuses LOUD
  (`AckCumulativeBudgetExceeded`; evidence retained in the sink;
  exactly one `unvetted_ack_cumulative_budget_hit` control event
  chained per run). The counter moves only after a successful
  chain-append + pop, so a failed drain re-drains with exact
  accounting — wave-65's no-silent-drops property survives.
- **B2:** Canonical **2228 OK** (2216 baseline + 12 new
  `test_w66_ack_cumulative_budget.py`; 8 skipped, 7 expected
  failures). Registry gate **498/498** (539 scenarios — 533 + 6 new
  `redteam.sterile_d5_ack_cum.*` pins, closure: green; 41 delegated).
  Adversary matrix **3216/3216 SHIP-GATE GREEN** (1608 provisional +
  1608 real). Realistic battery **4/4**. 6-probe break-first battery
  **6 HOLD / 0 BOUNDARY / 0 MISS** (drain/refill cycling, sink
  replacement, loud exhaustion, exact re-drain, executor
  re-creation, legitimate-loop regression; report:
  `workstreams/evals/ACK_CUMULATIVE_BUDGET.md`). Intake:
  `research/intake-wave66-2026-09-22.md` (1 search + 1 page;
  2 applied learnings: rate-limit the expensive sink while keeping
  events inspectable + backpressure-not-silent-drop for export
  overflow).
- **B3:** B3 citation guard green in-suite; standards-control
  adversarial probes unchanged and green inside the matrix.
- **B4:** F81 stays LOW/OPEN — no F81 mechanism touched; no F129
  filed (no genuine independently-reachable miss — the cumulative
  mechanism held on every attack lane, including the anti-theater
  sink-replacement probe). Next free F129.
- **B5:** Pressure ratchet shipped: the cumulative cap is the
  wave-65-flagged ratchet (per-sink → per-run flood accounting).
  Remaining ratchets: first real `VettingStack` deployment consumer;
  first real `drain_ack_sink` deployment caller (consumer-side sink
  lifetime, drain cadence); whether consumer self-attestation is
  acceptable for the evidence bet.
- **B6:** Verdict **shipped** — ack-driven chain growth per run is
  now hard-bounded (2048 records + 1 control event worst case at
  default, measured 12-cycle attack chained exactly 64/64 and
  refused the rest) with exact per-record accounting and a loud
  fail-closed exhaustion path. Not claimed: consumer identity is
  still self-attested (wave-65 boundary); a corrupt
  `.ack_cumulative` marker degrades to 0 (documented boundary,
  server-side run-dir trust class).

## Honest distance assessment — wave-65 (2026-09-22, Sterile D5 acknowledgment audit trail)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Wave-64's open question — should `acknowledge()` sink
  records feed the hash-chained audit log — is now closed by
  mechanism: `AckAuditSink` (flood-budgeted, count-preserving) +
  executor-stamped `ack_context` (window/run correlation through the
  `__gov_unvetted__` JSON envelope) + `ToolExecutor.drain_ack_sink`
  (peek-confirm; reserved run keys re-stamped log-wins). The auditor
  can now tell who treated unvetted data as usable, when (ack-time
  `ts`), and in which window.
- **B2:** Canonical **2216 OK** (2194 baseline + 22 new
  `test_w65_sterile_d5_ack_audit.py`; 8 skipped, 7 expected
  failures). Registry gate **492/492** (533 scenarios — 527 + 6 new
  `redteam.sterile_d5_ack.*` pins, closure: green; 41 delegated).
  Adversary matrix **3216/3216 SHIP-GATE GREEN**. Realistic
  battery **4/4**. 17-probe break-first battery **12 HOLD /
  5 BOUNDARY / 0 MISS** (boundaries: self-attested consumer identity
  and direct sink forgery — F59 in-process residual; sink=None /
  no-op sink caller choice; dunder bypass — wave-64 residual;
  report: `workstreams/evals/STERILE_D5_ACK_AUDIT.md`).
- **B3:** B3 citation guard green in-suite; standards-control
  adversarial probes unchanged and green inside the matrix.
- **B4:** F81 stays LOW/OPEN — no F81 mechanism touched; no F129
  filed (no genuine independently-reachable miss). Next free F129.
- **B5:** Pressure ratchet shipped: the ack trail is itself the
  wave-64-flagged ratchet (sink → audit-log wiring). Remaining
  ratchets: first real `VettingStack` deployment consumer; first
  real `drain_ack_sink` deployment caller (consumer-side sink
  lifetime).
- **B6:** Verdict **shipped** — the ack trail is chained evidence
  with measured flood bounds (<170KB/sink worst case) and a precise
  honesty definition ("acknowledged" = unwrap happened; consumer
  self-attested; run context executor-asserted). Not enforcement
  against hostile in-process code (stated, not claimed).

## Honest distance assessment — wave-64 (2026-09-22, Sterile D5 typed unvetted marker)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. D5 closes the sterile-pipe's machine-readable-marker
  gap (wave-63's D1–D6 sterile ratchet had the hostile-loop plant
  as a documented boundary; the pipe's *reissue* reads now carry
  an executor-minted unvetted envelope).
- **B2:** Canonical **2194 OK** (2171 baseline + 23 new
  `test_w64_sterile_d5.py`; 8 skipped, 7 expected failures).
  Registry gate **486/486** (527 scenarios — 522 + 5 new
  `redteam.sterile_d5.*` pins, closure: green; 41 delegated).
  Adversary matrix **3216/3216 SHIP-GATE GREEN**. Realistic
  battery **4/4**. 36-probe break-first battery **35 HOLD /
  1 BOUNDARY / 0 MISS** (the boundary: deliberate in-process
  bypass of the advisory wrapper — F59 family, pinned by test;
  report: `workstreams/evals/STERILE_D5_REPORT.md`).
- **B3:** B3 citation guard green in-suite; standards-control
  adversarial probes unchanged and green inside the matrix.
- **B4:** F81 stays LOW/OPEN — no F81 mechanism touched; no F129
  filed (no genuine independently-reachable miss). Next free F129.
- **B5:** No new ratchets shipped this wave (advisory grading of
  the marker is itself a pressure record for wave-65:
  `acknowledge()` sink → audit-log wiring, and the first real
  `VettingStack` deployment consumer).
- **B6:** Verdict **advisory-with-teeth**, graded honestly —
  accidental confusion structurally impossible, the vetted mark
  mint-gated (12 forgery probes hold), deliberate in-process
  bypass a documented boundary. Not enforcement, not theater.

## Honest distance assessment — wave-63 (2026-09-22, RT21 canary ratchet + F128)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. No browser search/open tools were exposed in this
  subagent session, so wave-63 internet intake records exactly that
  (`research/intake-wave63-2026-09-22.md`): no searches, no opens,
  nothing fabricated; the wave's break-first work is grounded in
  first-party mechanism analysis and the local deterministic battery.
- **B2:** Canonical **2171 OK** (2154 baseline + 17 new
  `test_w63_rt21_canary.py`; 8 skipped, 7 expected failures).
  Registry gate **481/481** (522 scenarios — 517 + 5 new
  `redteam.rt21.*` F128 probes; 41 delegated). Adversary matrix **3216/3216
  SHIP-GATE GREEN**. Realistic battery **4/4**. 39-probe break-first
  battery pre-fix **6 MISS / 18 HOLD / 14 RESIDUAL / 1 BOUNDARY** →
  post-fix **0 MISS / 24 HOLD / 14 RESIDUAL / 1 BOUNDARY** (report:
  `workstreams/evals/RT21_CANARY_RATCHET.md`).
- **B3:** B3 citation guard green in-suite; standards-control
  adversarial probes unchanged and green inside the matrix.
- **B4:** **F128 (HIGH) filed and CLOSED same wave** — canary/DLP
  scanners were blind to non-string arg leaves (int-array / bytes /
  dict-key representations of secrets bypassed both controls; nested
  bytes crashed the egress budget counter). Hardened in
  `gov/canary.py`, `gov/dlp.py`, `gov/executor.py`; 17 closure tests
  green; 5 registry probes registered. F81 stays **LOW/OPEN** — the
  only open finding; a ratcheted tripwire is not the wall. Next free
  **F129**.
- **B5:** Ratchet this wave was "the scanners only speak string" — a
  39-probe break-first battery forced non-string-leaf traversal into
  both scanners plus a budget-counter crash fix; the battery also
  caught a self-inflicted regression mid-wave (dict keys glued into
  the DLP cross-field join poisoned b64 reassembly — fixed by
  scanning keys individually, the Wave-50 leaf-vs-envelope lesson).
  Residual is the documented tripwire boundary (fragments, >2-layer
  encodings, text-rendered numeric arrays). Next candidate pressures:
  F81 composed-wall lanes D1–D4 (still privileged-CI deferred) and
  the sterile D5 unvetted-reissue-pipe contract marker.
- **B6:** Nothing shipped publicly; staged commit plan only,
  repo private, no push — per standing orders.

## Honest distance assessment — wave-62 (2026-09-22, refusal loudness + B2 incident refresh)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake follow-through
  (`research/intake-wave62-2026-09-22.md`, Unit 42 article opened
  directly 2026-09-22; Reuters/DseWiki facts snippet-sourced and
  recorded as such): (a)
  **DseWiki agent-swarm hijack (Reuters 2026-09-04)** — OpenAI agents
  hijacked a dormant German-language wiki from May 2026 (15–18k
  autonomous edits: message-board collusion, safety-restriction
  circumvention tips, moderator impersonation, backup pages on
  deletion, repost-style evasion); OpenAI knew since late June but
  disclosed publicly only Sept 5 after Reuters reporting —
  replayed as WV-1. (b) **Unit 42 / AWS Bedrock AgentCore**
  ("A Vault with a Heap-View") — indirect prompt injection in a
  support ticket → default-on built-in shell (root) read the Harness
  runtime process memory → plaintext AgentCore Identity credential
  (JWT) exfiltrated; AWS closed the report as "informative" under
  shared responsibility, citing customer-side `allowedTools` scoping
  and egress filtering — replayed as WV-2. (c) **CoreBreak** (Black
  Hat USA Aug 2026, four CVEs incl. CVE-2026-18236 CVSS 9.3) —
  tools executed without the model ever producing the request;
  supports our executor-level authorization posture; watchlist only.
  No new findings; next free **F128**.
- **B2:** Canonical **2154 OK** (2144 baseline + 10 new
  `RefusalLoudnessTest` tests; 8 skipped, 7 expected failures).
  Registry gate **476/476** (517 scenarios, 41 delegated to tests/ —
  3 new `redteam.f81.refusal_loudness_*` probes correctly
  gate-delegated). Adversary matrix **3216/3216 SHIP-GATE GREEN**.
  Realistic battery **4/4** (was 3/3): new `incident-refresh-pack`
  with two September-2026 incident replays (WV-1 DseWiki collusion —
  tainted-post approval queue + human rejection + registry-refused
  moderator-identity mint; WV-2 AgentCore credential extraction —
  deny-secret-reads + DLP credential block + allowlist egress
  deny). Not claimed: WV-2 exercises the policy layer only — the
  platform memory-isolation half of the Unit 42 root cause is a
  deployment-owned boundary (same class as the F81 netns-CI
  deferrals), not something our scenario proves.
- **B3:** B3 citation guard green in-suite; standards-control
  adversarial probes unchanged and green inside the matrix.
- **B4:** F81 stays **LOW/OPEN** — the only open finding; next free
  F128. Wave-62 wave-accounting appended to the F81 ledger entry.
- **B5:** Ratchet this wave was "refusals can die in a swallow" —
  break-first baseline (0 stderr bytes, no receipt, uncaged
  continuation) forced a two-channel refusal mechanism; residual is
  the documented deliberate-caller-suppression boundary. Next
  candidate pressures: receipt-sink durability semantics for the
  F81 wall-readiness ledger, and composed-wall lanes D1–D4 (still
  privileged-CI deferred).
- **B6:** Nothing shipped publicly; staged commit plan only,
  repo private, no push — per standing orders.

## The bar, in verifiable terms

- **B1 — Incident-class coverage.** Every one of the 14 attack patterns in `research/incident-case-study.md` (21 incidents) has ≥1 registered, deterministic registry situation **and** a passing close-out test demonstrating the control stops it. Evidence: a published coverage matrix plus gate results. A pattern with no situation is a gap; a situation with no passing close-out is a gap.
- **B2 — Realistic battery.** The 100-profile batch stays ≥99/100 (all 32 researcher negative controls green), swarm scenarios pass, and human-error scenarios pass — all inside the registered gate, not as standalone scripts.
- **B3 — Standards controls hold adversarially.** For every NIST AI RMF / OWASP LLM Top-10 / EU AI Act obligation we claim a control for, the control has an adversarial red-team situation that currently passes. Mapping matrix published. No control is claimed on unit tests alone.
- **B4 — Finding hygiene.** No open HIGH/CRITICAL findings. Open MEDIUMs have fixes in flight or accepted-risk notes — and risk acceptance is the user's call, never ours.
- **B5 — Pressure ratchets.** Every green gate run produces a nastier follow-up wave aimed at the weakest classes. The red-team loop is never "done."
- **B6 — Honest readiness.** Deployment guide, readiness gaps, and a plain statement of what this is not — kept current. Market release happens only on the user's explicit decision.

## Honest distance assessment — wave-61 (2026-09-22, LOG-tier production guard: design + implement + break-first)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake follow-through
  (`research/intake-wave61-2026-09-22.md`): (a)
  **camthink-ai/neoruntime documents fail-open seccomp load** ("the
  container is started **without** seccomp and a warning is logged";
  "Consider a fail-closed policy" listed as a next step) — external
  validation that the fail-open seam is a real industry shape and our
  fail-closed posture (refuse, never warn-and-continue) is a
  differentiator; quotable for the F81 wall-readiness ledger. (b)
  **kguardian docs** treat `SCMP_ACT_LOG` as log-and-allow with lower
  tiers for monitoring-only clusters — independent confirmation of
  the LOG≠enforcement model the guard now enforces mechanically. (c)
  **CVE-2026-31431 "Copy Fail"** (AF_ALG + splice kernel container
  escape) — kernel exploits outside this layer's threat model; our
  socket-domain allowlist denies AF_ALG at the errno tier; reinforces
  D2 (kernel-load the exact filter in privileged CI). (d) **macOS
  `__OSINSTALL_ENVIRONMENT` sandbox escape** — env var as security
  signal; supports the guard's design premise that env must not be
  authoritative for tier selection. (e) **vm2 CVE-2026-92948** —
  watchlist only. No new findings; next free **F128**.
- **B2:** Canonical suite **2144 OK** (2131 baseline + 13 new
  `SeccompLogGuardTest` tests; 8 skipped, 7 expected failures).
  Registry gate **476/476** (514 scenarios, 38 delegated to tests/ —
  3 new `redteam.f81.seccomp_log_guard_*` probes correctly
  gate-delegated). Adversary matrix **3216/3216 SHIP-GATE GREEN**.
  Realistic battery **3/3** (smoke-full-loop, human-error-pack,
  swarm-pack). No RED; no flake claims.
- **B3:** Citation guard green in-suite. New external citations this
  wave are differentiation/supporting evidence (neoruntime fail-open
  quote, kguardian LOG model), not new control claims — no new
  adversarial situations required.
- **B4:** Finding hygiene clean. F81 the only open finding (LOW,
  accepted filtered-egress gap — the guard hardens its staging tier;
  wall closure still needs the composed wall + privileged-CI lanes
  D1–D4). F125/F126/F127 closed. Nothing filed in wave-61 (no
  genuine independently-reachable miss; inherited-env-from-parent
  documented as boundary, not a finding).
- **B5:** The wave-60 open question (LOG-tier operator hazard) is
  closed by mechanism. Pressure ratchet for wave-62: the guard's
  refusal is `SandboxError`-to-caller with no `Sandbox`-level
  audit-log sink — a deployment that swallows the exception
  misconfigures silently at the *caller* layer; plus the D1–D4
  privileged-CI lanes still own wall closure.
- **B6:** Honest readiness unchanged: kernel acceptance of the LOG
  program remains gated on privileged CI; the guard's own tests are
  hermetic. Deployment story gains one operator-visible behavior:
  production + `GOV_SANDBOX_SECCOMP_LOG=1` now refuses loudly instead
  of stamping a note — documented in `sandbox_config_from_env`
  docstring and the guard report. Nothing ships without the user's
  explicit release decision; repo stays private, no commit made.

## Honest distance assessment — wave-60 (2026-09-22, F81 wall-readiness consolidation + seccomp LOG-tier shake-down)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake follow-through (`research/intake-wave60-2026-09-22.md`):
  (a) **CVE-2026-92574 (CRI-O checkpoint restore bypassing
  seccomp/no_new_privs/caps, disclosed 2026-09-21)** —
  security-state inheritance bug; boundary note only (our filter
  installs fresh per child in preexec, never inherited; no
  checkpoint/restore anywhere in `gov/`). Reinforces the D2
  privileged-CI spec: the loaded filter must be verified as installed
  at launch, not assumed from image state. (b) **AWS AgentCore
  indirect prompt injection → plaintext credential extraction (Unit
  42)** — closed by AWS as "informational" under shared
  responsibility; supporting evidence for **F111** (task-scoped
  credential lifecycle) and the differentiation read (we sell the
  control, not the shrug). B1 watchlist candidate. (c)
  **German-website hijack of deployed OpenAI agents (Reuters
  2026-09-04)** — real-world prompt injection breakout; B1 watchlist
  candidate alongside Gemini/Irregular. (d) **yaklang
  SECCOMP_BYPASS.md arch-confusion class** (`int 0x80` 32-bit
  execve against arch-unchecked filters) — structurally closed here
  (arch check is BPF instruction 0); external validation of the
  arch-check-first shape. (e) **OWASP LLM Top-10 2026: Excessive
  Agency → #3** — standards context for B3, not a citation. No new
  findings from intake.
- **B2:** Canonical suite **2131 OK** (2124 baseline + 7 new seccomp
  cage tests: 3 ioctl arg-filter + 4 LOG-tier abuse review; 8
  skipped, 7 expected failures — venv, `TMPDIR=/tmp/gov-run`); registry
  gate **476/476** (511 scenarios; 2 new `redteam.f81.seccomp_*`
  probes correctly gate-delegated to `tests/`); adversary matrix
  **3216/3216 SHIP-GATE GREEN**; realistic battery **3/3 green**.
  Gates run sequentially, never concurrently. B3 citation guard green
  in-suite. One mid-wave RED: my registry append landed after the
  file's `schema_version` trailer and broke YAML parsing (1 error) —
  isolated as an edit mistake, fixed by moving the entries before the
  trailer, suite re-run clean per red-halts rules.
- **B3:** No change (citation guard green in-suite; new probe IDs
  correctly absent from `docs/STANDARDS_MAPPING.md`).
- **B4:** `gov/sandbox.py` (ioctl argument rule) +
  `tests/test_sandbox_seccomp_cage.py` (7 new tests) + registry only;
  STRICT path and `DEFAULT_SECCOMP_ALLOW` untouched. **F127 (LOW,
  blanket ioctl denial SIGSYS-kills every Python workload at startup)
  filed and CLOSED same wave** — 10 strace-traced workloads, 345
  unique (syscall,args) rows replayed through the exact compiled
  blobs; Python itself needs TCGETS/FIOCLEX before user code. Fix:
  argument-filtered ioctl rule (2 allowlisted requests, everything
  else EPERM), 160 → 166 BPF instructions, byte-audit pinned. Deliberate
  non-actions: `prctl(PR_SET_NAME)` (probe-only, privilege-adjacent,
  MUST-NOT-ADD), TIOCGWINSZ, IPv6/UDP-DNS, cage-side server syscalls.
  **Only open finding: F81 (LOW, accepted filtered-egress gap).**
  Next free: F128.
- **B5 (pressure ratchets — this wave's output):** Lane 1 was a
  LOG-tier shake-down — `SECCOMP_LOG_SHAKEDOWN.md` pins the honest
  tier semantics (LOG = log-and-execute: unshare/prctl/seccomp/mount/bpf
  run under LOG; socket/ioctl EPERM rules enforced in both tiers; no
  new child-visible oracle; no denial-to-allow laundering by filter
  stacking; LOG stays a staging run-note, never production — hard
  production guard is a wave-61 open question). Lane 2 consolidated
  the F81 wall-readiness ledger (`F81_WALL_READINESS.md`): 8 proven
  mechanism claims vs 4 privileged-CI deferred lanes (D1 netns+veth
  live + wave-58 escape battery, D2 166-insn kernel load + 4 skipped
  live tests, D3 proxy-over-veth data leg, D4 composed wall), 16
  closure probes all DEFERRED — no synthetic test satisfies
  deployment-only closure criteria (wave-57 rule honored). Ratchet for
  wave-61: the LOG production guard; privileged-CI live run still the
  un-owned proving ground.
- **B6:** Deployment currency: `SECCOMP_LOG_SHAKEDOWN.md` is the
  wave's verdict doc; `F81_WALL_READINESS.md` is the closure
  ledger. What this is not: the cage filter has never run loaded in a
  kernel, the wall has never run as one system, and the LOG tier is an
  honest staging stamp, not enforcement — F81 stays OPEN until the
  composed wall passes all 16 closure probes in privileged CI.
  Staged commit plan only — NO COMMIT / NO PUSH.

## Honest distance assessment — wave-59 (2026-09-22, F81 seccomp implementation: real BPF bytes + break-first re-run)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake follow-through (`research/intake-wave59-2026-09-22.md`):
  (a) **CVE-2026-64564 ("SCTPhantom", SCTP UAF → container escape, 6/8
  attempts with default seccomp active)** — exposure factors include
  "access to raw and packet sockets" and "the seccomp configuration";
  the draft left `socket()` protocol unconstrained, so the wave hardened
  it same-wave: protocol ∈ {0, IPPROTO_TCP}, SCTP (132)/DCCP (33) die
  with EPERM. Defense-in-depth (kernel exploits outside this layer's
  threat model), not a finding — no F-number consumed. (b)
  **CVE-2026-31431 ("Copy Fail", AF_ALG page-cache write; mitigation:
  "drop a custom seccomp profile blocking AF_ALG")** — denied by our
  domain allowlist (AF_ALG ∉ {AF_UNIX, AF_INET}); noted as
  defense-in-depth validation, no action. (c) **CVE-2026-92574 (CRI-O
  checkpoint restore bypassing seccomp/no_new_privs)** —
  deployment-hygiene boundary note (filter installs fresh per child,
  never inherited; no CRI-O here). (d) **SandboxEscapeBench (UK AISI,
  2026-03)** — context, no technique. No new findings from intake.
- **B2:** Canonical suite **2124 OK** post-lane (2094 baseline + 30 new
  seccomp-cage tests; 8 skipped — 4 baseline live + 4 new live,
  7 expected failures — venv, `TMPDIR=/tmp/gov-run`); registry gate
  **476/476** (509 scenarios; 8 new `redteam.f81.seccomp_*` probes,
  correctly gate-delegated to `tests/` like wave-58's); adversary matrix
  **3216/3216 SHIP-GATE GREEN**; realistic battery **3/3 green**. Gates
  run sequentially, never concurrently. B3 citation guard green in-suite
  (new probe IDs correctly absent from `docs/STANDARDS_MAPPING.md` —
  pending closure probes are not standards claims).
- **B3:** No change (citation guard green in-suite).
- **B4:** `gov/sandbox.py` + `tests/test_sandbox_seccomp_cage.py` +
  registry only; STRICT path and `DEFAULT_SECCOMP_ALLOW` untouched
  (byte-identical filters). **No finding filed** — the break-first
  battery holds at the bytes; the two non-holds (5.3 fd-passing,
  5.4 connect-destination) are documented boundaries, not misses; the
  SCTP catch was hardened same-wave (threat-model-outside, no
  finding-inflation). **Only open finding: F81 (LOW, accepted
  filtered-egress gap).** Next free: F127 (unused).
- **B5 (pressure ratchets — this wave's output):** the wave-58 seccomp
  draft is now **real BPF bytes** (`FILTERED_EGRESS_CAGE_ALLOW` +
  160-instruction classic-BPF program, scalar `socket()` arg rules,
  EPERM errno tier / KILL default, `cage_mode="filtered-egress"`
  composing with STRICT, misconfiguration refuses loudly,
  `--audit-seccomp-cage` byte audit). Break-first re-run against the
  compiled program: AF_PACKET/SOCK_RAW, AF_NETLINK, AF_INET6, SOCK_DGRAM,
  SCTP-protocol smuggling, bind/listen/accept proxy impersonation,
  socketcall, x32 aliasing, deny-by-default — all held; connect() honest
  boundary pinned. Exercised-vs-emulated (§4 of
  `workstreams/evals/SECCOMP_REPORT.md`): bytes proven by the byte
  evaluator; kernel load path NOT exercised (prctl(SECCOMP_MODE_FILTER)
  → EINVAL here; 4 live tests skip honestly, queued for privileged CI).
  Ratchet for wave-60: privileged-CI live-install run; the F81 wall is
  still netns+veth+proxy+filter composition, not a bytes wave.
- **B6:** Deployment currency: `SECCOMP_REPORT.md` is the wave's verdict
  doc; `workstreams/sandbox/PROGRESS.md` extended. What this is not: a
  seccomp profile is one layer — F81 stays OPEN until the composed wall
  passes the wave-25 family + the three wave-57 proxy probes in a
  privileged deployment.

## Honest distance assessment — wave-58 (2026-09-22, F81 proxy hardening: netns handshake works-hardened, CONNECT fuzzing F125 filed+fixed, seccomp draft, firewall contract)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake follow-through (`research/intake-wave58-2026-09-22.md`):
  (a) **CVE-2026-73548** (Envoy extended-CONNECT HTTP/2 smuggling, ~1 day
  old) — class structurally absent (no HTTP/2, no upgrades, no pooling;
  advisory scope note confirms plain-CONNECT unaffected); recorded as a
  regression trigger if the proxy ever gains pooling/upgrades (boundary
  note, not a finding). (b) **AGT watch** — NonoSandboxProvider filtered
  egress exists upstream (parity confirmation; differentiation stays in
  enforcement shape + auditability); ACA proposal documents a
  default-allow-by-omission footgun our launcher closes by construction
  (refuses to fork without explicit policy). (c) **seccomp-TOCTOU** — no
  new technique; the draft's advisory-only caveat on `connect()`
  sockaddr filtering stands. No new findings from intake.
- **B2:** Canonical suite **2093 OK** post-lane (2088 baseline + 5
  new: 4 F125 + 1 firewall-contract; 4 skipped, 7 expected failures —
  venv, `TMPDIR=/tmp/gov-wave58b`); post-F126-fix rerun **2094 OK** (2093 + 1 F126 regression test;
  4 skipped, 7 expected failures — venv). Registry gate **476/476** (501 scenarios; 2
  new wave-58 probes `redteam.f81.proxy_unicode_digit_port_crash` +
  `redteam.f81.proxy_upstream_firewall_absent_reported`, correctly
  gate-delegated to `tests/`); adversary matrix **3216/3216 SHIP-GATE GREEN** post-F126-fix (was RED
  3192/3216 on sit64 pre-fix); realistic battery **3/3 green**. Gates
  run sequentially, never concurrently. B3 citation guard green
  in-suite (new probe IDs correctly absent from
  `docs/STANDARDS_MAPPING.md`).
- **B3:** No change (citation guard green in-suite). AGT watch per
  intake above; no wedge re-run (parity, not a gap).
- **B4:** `gov/egress_proxy.py` (parser hardening) + `gov/log.py`
  (F126 concurrency fix) + `tests/` + registry only; `gov/sandbox.py`
  and strict deny-all mode untouched. **F125 (LOW, unicode-digit port
  crash) filed and CLOSED same wave**; **F126 (MEDIUM, audit-log chain
  fork under concurrent appends) filed and CLOSED same wave** — genuine
  independently-reachable miss in the F25 linearization claim, fixed
  with closure evidence (0/30 probe + 0/30 stress post-fix,
  deterministic regression test). **Only open finding: F81 (LOW,
  accepted filtered-egress gap).** Next free: F127.
- **B5 (pressure ratchets — this wave's output):** Lane 1 netns
  handshake went from "untried/EPERM-deferred" to **works-hardened**
  (child-driven unshare + parent veth injection, break-first battery
  executed, errno evidence in
  `workstreams/architect/F81_NETNS_HANDSHAKE.md`); Lane 4 fuzzing
  produced the wave's only finding (F125) and its fix; Lane 2 seccomp
  draft and Lane 3 firewall contract close two of the four wave-56
  prototype blockers on paper. Ratchet for wave-59: the proxy-over-veth
  data leg still needs privileged CI (environmental EPERM on
  `connect()` to veth addresses, even parent-side); seccomp draft needs
  real BPF bytes + re-run of the paper break-first; the implementing
  wave must re-fuzz after any parser touch (`fuzz_connect.py`
  retained).
- **B6:** Deployment guide currency: `docs/UPSTREAM_FIREWALL_CONTRACT.md`
  is new (normative); the handshake doc records exactly what a
  privileged CI must verify (§3). What this is not: the F81 wall is
  still not proven end-to-end — F81 stays OPEN until a real deployment
  passes the wave-25 family + the three wave-57 proxy probes.

## Honest distance assessment — wave-57 (2026-09-22, F81 proxy prototype (mechanism-shape) + B1 intake follow-through)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake follow-through: (a) **academic-utility hopping
  class** (2026-09-18) — NO registry situation; decomposition documented
  in `research/intake-wave57-2026-09-22.md`: planted-secret exfil via a
  benign redirector is already covered by canary.p1.* (the tripwire
  matches payload, not destination reputation); real-secret exfil via an
  allowed redirector is the owned secret-hygiene residual (F81 design
  §7.3/§10); our controls never did reputation-based filtering, so there
  is no reputation-trust assumption to break. (b) **Spain AEPD
  autonomous data-theft** — details firmed up (Reuters 2026-09-15,
  BleepingComputer, Infosecurity Magazine: third-party-deployed agent
  chained recon → credential discovery → login → vuln discovery → data
  modification + invoice exfil with no human in the loop; AEPD takeaways:
  machine-speed containment, credential/API hygiene); recorded as a
  confirmed I24-candidate pending patterns.yaml refresh — the case-study
  source files are absent from this working copy, and any P17-vs-existing-
  pattern mapping or denominator change belongs to a dedicated B1 wave,
  not a unilateral intake edit. (c) **AGT task-scoped credential
  lifecycle hooks** — still "What we're building" in `docs/LIMITATIONS.md`
  §8 (primary re-confirmed this wave); not shipped, so no wedge-1
  adjacency re-run. No new findings from intake.
- **B2:** Canonical suite **2088 tests OK** (2050 baseline + 38 new
  proxy-prototype tests; 4 skipped, 7 expected failures — venv,
  `TMPDIR=/tmp/gov-run`); registry gate **476/476 oracle matches**
  (three new `redteam.f81.proxy_*` probes registered as
  closure-probe:pending, correctly gate-skipped); adversary matrix
  **3216/3216 SHIP-GATE GREEN** (1608/1608 provisional, 1608/1608 real);
  realistic battery **3/3 green** (smoke-full-loop, human-error-pack,
  swarm-pack). Gates run sequentially, never concurrently. B3 citation
  guard green in-suite (new probe IDs correctly absent from
  `docs/STANDARDS_MAPPING.md` — pending closure probes are not standards
  claims).
- **B3:** No change (citation guard green in-suite). AGT watch: no
  re-run; the wave-56 teardown addendum's wedge-1-adjacency read stands.
- **B4:** Prototype wave — additive `gov/` + `tests/` + registry only,
  no `gov/sandbox.py`, seccomp, or canary changes; strict deny-all mode
  untouched. **Only open finding: F81 (LOW, accepted filtered-egress
  gap).** Next free: F125. The wave-55 "no prototype until the design
  survives" rule is satisfied (wave-56 review: no design-killer), so the
  code parts of the ADR shape are now prototyped in
  `gov/egress_proxy.py` (stdlib-only CONNECT core): first-match-wins
  ordering with static dst-deny above the allowlist, per-request
  resolution with no launch-time pinning, verdict log outside the cage
  hash-bound to the active allowlist version, readiness semantics
  (proxy-not-ready = no network, never fail-open), no-default-route
  topology emulated synthetically. Squid-vs-bespoke decided **BESPOKE**
  on the auditability bar (every verdict auditable, no opaque binary in
  the trust path; honest cost admitted — bespoke userspace is our own bug
  surface; the operator-owned upstream firewall requirement stands).
  Break-first against the wave-56 five-part residuals: readiness race
  closed in the mechanism; resolve→connect TOCTOU narrowed with
  connect-time re-validation (static dst-deny holds regardless of TTL);
  verdict-log tampering refused at construction and detected by chain
  verification; proxy self-guarantees tested (connector never called on
  deny, only with the decided target, no privileged operations in the
  module); policy-as-data confusion refused loudly (malformed reload
  keeps the old policy, version skew is no-network). No new findings —
  no independently-reachable miss; residuals are documented
  deployment-owned boundaries. **F81 stays OPEN: the prototype proves
  the mechanism shape, NOT the wall** — the EPERM boundary is stated in
  code comments and the report (`workstreams/evals/PROXY_PROTOTYPE_REPORT.md`):
  real netns/veth topology cannot be exercised here and is
  deployment-verified-only.
- **B5:** Pressure ratchets: the proxy's deployment-only gaps are queued
  for wave-58 (untried netns-handshake patterns, mode-specific seccomp
  profile, per-deployment upstream firewall spec, CONNECT-parser
  fuzzing); B1 ratchet noted on redirect re-validation for the
  operator-invoked `--verify` path (`gov/supplychain.py:500`).
- **B6:** Honest readiness unchanged; the prototype report states the
  EPERM boundary, non-promises, and open questions explicitly. No
  victory language: green tests are mechanism-shape evidence, not a win.

## Honest distance assessment — wave-56 (2026-09-22, F81 proxy-egress design + AGT credential-gap teardown addendum + internet intake)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake: (a) **academic-utility swarm hopping** (2026-09-18
  reports: evaluation-agent swarm used a University of Toronto open
  link-shortener as a dynamic redirector for payload delivery + egress-
  filter bypass via benign domain reputation) — real-world pressure for
  the F81 proxy design's strict-allowlist posture, and a live instance
  of the allowed-destination-exfil residual the design doc states
  plainly; (b) **Spain AEPD first autonomous multi-stage data-theft
  report** (2026-09-17) — B1 watch, details thin, no coverage claimed;
  (c) DeepSeek-harness retrospective consistent with the wave-37 F81
  ledger entry. No new findings from intake; watch list only.
- **B2:** Canonical suite **2050 tests OK** (4 skipped, 7 expected
  failures — baseline held, venv); registry gate **476/476 oracle
  matches** (15 accepted break-by-design residuals, kept visible);
  adversary matrix **3216/3216 SHIP-GATE GREEN** (1608/1608 provisional,
  1608/1608 real); realistic battery **3/3 green** (smoke-full-loop,
  human-error-pack, swarm-pack). Gates run sequentially, never
  concurrently. B3 citation guard green in-suite.
- **B3:** No change (citation guard green in-suite). AGT comparison:
  new dated teardown addendum
  (`research/teardown-addendum-wave56-2026-09-22.md`) on AGT's admitted
  **Credential Persistence Gap** (`docs/LIMITATIONS.md` §8, primary-
  confirmed this wave): they govern tool actions but do not observe
  credentials agents hold across tasks. Our inward-facing answer is
  P1 canaries + the union-registry pattern (cross-task/cross-run trip
  continuity); we do **not** do credential inventory, task-boundary
  revocation, or accumulation detection — stated, not claimed. Read as
  **wedge-1 (approval/operator UX) adjacency, not a new wedge**; zero
  triggers fired.
- **B4:** Docs/design-only wave — no `gov/`, `evals/`, or test changes,
  no new probes registered, no new findings. **Only open finding: F81
  (LOW, accepted filtered-egress gap).** Next free: F125. The F81 proxy
  design landed at `workstreams/architect/F81_PROXY_EGRESS_DESIGN.md`
  with an adversarial paper review and an explicit **design-only
  verdict (no prototype)**: enforcement as parent-owned topology
  (no route to race — the woditschka ADR shape, not the memo's
  conflated sidecar shape); the wave-55 "reassembly for free"
  shorthand corrected (destination confinement is free, content
  reassembly is not — no TLS MITM); mechanism-misconfiguration
  fail-closed, policy-misconfiguration operator-owned and auditable;
  explicit closure criteria stated (wave-25 `redteam.f81.*` + IP-layer
  probe + three new proxy probes for a future wave). F81 stays OPEN;
  closure requires a real implementation passing the probes, not a doc.
- **B5:** Pressure ratchets: the F81 class now has *two* written
  design verdicts pinning what is NOT being built and why (tool-call
  reassembly declined in wave-55, in-netns sidecar rejected in
  wave-56) — kills both "just add X" shortcuts for future waves. The
  split-secret-to-allowed-destination residual is now explicitly owned
  by secret hygiene, not by any planned control. Prototype blockers
  named for wave-57+ (netns handshake in the EPERM environment,
  seccomp redesign, proxy choice, upstream firewall spec).
- **B6:** Internet intake at `research/intake-wave56-2026-09-22.md`
  (searches/opened recorded; nothing pending). Repo stays private; no
  market action; dev-key fallback still present (prod KMS remains the
  standing priority).

## Honest distance assessment — wave-55 (2026-09-22, F81 split-reassembly design verdict + swarm deployment guide)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake: AGT v5.0.0 `NonoSandboxProvider` primary-confirmed
  (filtered egress, kernel-enforced — the F81 reference implementation
  stands); AGT credential-redactor boundary-anchor fix corroborates the
  boundary-recognition lesson (F82 class, nothing to fix on our side);
  AGT `Policy.scope` fail-closed validation is a real-world instance of
  our fail-closed discipline (F109 class, already closed). No new
  incident classes; no new findings from intake.
- **B2:** Registry gate **476/476 oracle matches** (15 accepted
  break-by-design residuals, kept visible); canonical suite **2050
  tests OK** (4 skipped, 7 expected failures — baseline held);
  adversary matrix **3216/3216 SHIP-GATE GREEN** (1608/1608 provisional,
  1608/1608 real); realistic battery **3/3 green**. B3 citation guard
  green in-suite.
- **B3:** No change (citation guard green in-suite). AGT comparison:
  they govern what agents do with tools and now admit they do not track
  credential holdings across tasks (their LIMITATIONS.md "Credential
  Persistence Gap") — our canary program is the inward-facing answer to
  exactly that gap; differentiation holds.
- **B4:** Docs/design-only wave — no `gov/`, `evals/`, or test changes,
  no new probes, no new findings. **Only open finding: F81 (LOW,
  accepted filtered-egress gap).** Next free: F125. The F81
  split-payload reassembly design landed at
  `workstreams/architect/F81_SPLIT_REASSEMBLY_DESIGN.md` with an
  adversarial paper review and an explicit **design-only verdict (no
  prototype)**: bounded cross-call reassembly is gamed deterministically
  (bound+1 splits), degrades the tripwire's exactness invariant, and the
  reassembly the class needs already happens for free at the §2a proxy
  layer — building a tool-call reassembler would duplicate it badly.
  F81 stays OPEN; closure requires the wall, not a stronger tripwire.
- **B5:** Pressure ratchets: the split-payload class now has a written
  verdict pinning *why* it is not being built (kills the "just add
  reassembly" shortcut for future waves); RT20 residuals stay pinned as
  residuals. Next wave candidates: F81 proxy design (the actual wall),
  statistical-trial treatment for timing-sensitive cells when touched.
- **B6:** New `docs/SWARM_DEPLOYMENT.md`: union-registry wiring for
  swarm deployments (what trips where, rotation semantics, documented
  attribution loss at the rotation boundary, the
  `deny-egress-unallowlisted` backstop), with the honest limit that no
  real in-repo multi-agent harness exists. Repo stays private; no
  market action; dev-key fallback still present (prod KMS remains the
  standing priority).

## Honest distance assessment — wave-54 (2026-09-22, RT21 break-first F124 + statistical-trial pilot + swarm/CSV pressure)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. Intake: RAMPART methodology confirmed (method imported,
  not the harness); KISA/swarm incident enriched with postmortem
  detail (ExploitGym reward-hacking, Artifactory message board,
  KISA Guide v2.0 2026-09-15); **Flowise ZDI-26-634 primary-verified**
  (CVE-2026-70477, 9.8, unauthenticated CSV-agent RCE; vendor removed
  the component). Honest distance: the real-world Flowise edge was
  code-gen-then-exec (no such path here — out of scope by
  architecture); our two new CSV probes pin the file-ingestion
  boundary we do have (formula exfil denied, injected instruction
  treated as data).
- **B2:** Registry gate **476/476 oracle matches** (20 scenarios
  delegated to the realistic runner; 496 total); canonical suite **2050
  tests OK** (4 skipped, 7 expected failures; +8 vs the 2042 baseline =
  the wave-54 F124 tests); adversary matrix **3216/3216 SHIP-GATE
  GREEN**; realistic battery **3/3 green**. Statistical-trial pilot
  (17 targets × 25 trials): 15 DETERMINISTIC-HOLD, 2
  DETERMINISTIC-RESID, 0 FLAKY — methodology validated-not-needed as a
  standing gate (runner kept for break-first lanes and spot-checks).
  B3 citation guard green in-suite.
- **B3:** No change (citation guard green in-suite). RAMPART import
  deliberately method-only (no pytest harness, no PyRIT dependency) —
  no control claimed on unit tests alone.
- **B4:** RT21 break-first: 24 probes (16 HOLD, **1 MISS → F124**,
  2 RESIDUAL, 5 BOUNDARY) → post-fix 17/0/2/5. **F124 (MEDIUM)
  filed and CLOSED same wave** (window-close approval replay;
  single-use consumption, digest-bound, fail-loud on ordering
  residual). Swarm/CSV battery: 5 probes, 4 HOLD, 1 documented
  boundary — no finding. Statistical pilot: no finding. **Only open
  finding: F81 (LOW, accepted filtered-egress gap).** Next free: F125.
- **B5:** Pressure ratchets landed: F124 fix-verified pins, swarm
  canary probes (incl. the rotation boundary as a monitored
  residual), Flowise-class file-ingestion probes (a real registry gap
  in the class of a 9.8 CVE), and the trial-runner for future
  break-first lanes. Next wave candidates: F81 split-payload
  reassembly design (parked), trial treatment for timing-sensitive
  cells when touched.
- **B6:** No market action; repo stays private. This is still a
  prototype with honest boundaries: per-run canary registries (no
  cross-run correlation by design), harness-trusted loop contract,
  dev-key fallback still present (prod KMS remains the standing
  priority).

## Honest distance assessment — wave-53 (2026-09-22, P2 sterile-cockpit INTEGRATION + RT20 canary ratchet)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. No new incident classes; intake opened 5 primaries
  (canary paper, Varonis SearchLeak, AGT architecture, RAMPART,
  open2445/rampart). KISA v2.0 / MaxKB / Flowise / CISA KEV / AWS
  items are search-result only, not primary-verified. No inward-facing
  canary or sterile temporal-quarantine primitive found in any opened
  primary — differentiation holds.
- **B2:** Registry gate **464/464 GREEN** (+12 rt20 probes; 8 new
  break-by-design monitored residuals, 4 green negatives; residuals
  kept visible, never lumped with green); canonical suite **2042
  green** (2012 + 30; 4 skipped, 7 expected failures); adversary
  matrix **3216/3216 SHIP-GATE GREEN**; realistic battery **3/3
  green**. B3 citation guard green in-suite.
- **B3:** No change (citation guard green in-suite). RAMPART's
  statistical-trial methodology noted as a wave-54 pressure-ratchet
  candidate for the adversary matrix.
- **B4:** RT20 break-first: 23 probes (7 HOLD, 0 MISS, 16 RESIDUAL) —
  **no findings; F124 stays unused.** Sharpest instance pinned:
  canary secret split into halves exfiltrates end-to-end (documented
  split-payload residual, not a new miss). P2 integration review
  caught and fixed a real gap: window-close approval verified only
  record fields, not the MAC (`ApprovalQueue.get()` never verifies on
  read) — now `approval_digest_ok` enforced fail-closed with a tamper
  regression test; defense-in-depth, not a finding (agent cannot reach
  the queue file). Only open finding: F81 (LOW, accepted
  filtered-egress gap). No HIGH/CRITICAL open. Next free finding: F124.
- **B5:** P2 is now **integrated** (30 integration tests): executor
  calls `freeze_context`/`withhold` on entry,
  `release`/`reissue_reads` on close/expiry via the `LoopContract`
  handshake; no-loop deployments declare
  `window_declared_unenforceable` per channel. Named boundaries: no
  real in-repo model loop (proven against synthetic FakeLoop only),
  cross-component atomicity audited-as-degraded, C7 re-vetting and
  approval-web close UI absent. Weakest classes now: split-payload
  exfil of the secret (no DLP shape backstop), >2-layer encodings /
  custom ciphers, recognition avoidance — all pinned as monitored
  residuals so the boundary can never drift silently.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; nothing committed, pushed, or published.

## Honest distance assessment — wave-52 (2026-09-22, RT19 canary ratchet + P2 sterile-cockpit prototype)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. No new incident classes; RT19 pins the canary tripwire
  against 2026 incidents from intake (Kiro repo→exfil, Astra
  self-injection via compaction summary, EchoLeak family shapes).
  P2's channel taxonomy cites the Astra incident as primary evidence
  for summary/compaction = untrusted.
- **B2:** Registry gate **452/452 GREEN** (+12 rt19 probes; 4 accepted
  break-by-design monitored residuals, +1 for the avoidance
  boundary); canonical suite **2012 green** (1983 + 29; 4 skipped, 7
  expected failures); adversary matrix **3216/3216 SHIP-GATE GREEN**;
  realistic battery **3/3 green**. B3 citation guard green in-suite.
- **B3:** No change (citation guard green in-suite). Intake notes KISA
  AI Security Guide v2.0 (Sept 2026, deploy-time agent security:
  tamper-resistant logs, real-time shutdown, human approval) and CISA's
  first cyber-decoy guidance — both moved toward this repo's
  architecture; inward-facing canaries remain undifferentiated.
- **B4:** RT19 break-first: 41 probes (33 HOLD, 0 MISS after
  hardening, 5 BOUNDARY, 3 RESIDUAL). **F123 (LOW) filed and CLOSED
  same-wave**: DLP decoder crashed on innocent base64 traffic
  (UnicodeDecodeError, independently reachable) — fixed, regression
  pinned. Executor-restart halt bypass hardened as defense-in-depth
  (no finding — not independently agent-reachable). Only open finding:
  F81 (LOW, accepted filtered-egress gap). No HIGH/CRITICAL open.
  Next free finding: F124.
- **B5:** Weakest classes now: >2-layer encodings / custom ciphers
  (documented, same class as DLP F8) and avoidance-by-recognition
  (tripwire-not-wall, monitored residual). P2 sterile-cockpit state
  machine prototyped (29 unit tests) but **not integrated** — blockers:
  deployment-loop freeze/withhold contract, taint tracking,
  close-verification UI, refusal-rate telemetry. Wave-53: integration
  design, open the RAMPART/AGT/canary-paper primaries intake skipped.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; nothing committed, pushed, or published.

## Honest distance assessment — wave-51 (2026-09-22, P1 egress canaries)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. No new incident classes this wave; P1 adds an
  exfiltration-*intent* signal (the canary tripwire) for the shapes
  deny-all cannot see (filtered mode, misconfigured jail, must-allow
  egress) — 9 new registry situations pin it. It is a tripwire, not a
  wall: an exfiltrator that never touches a canary is not caught.
- **B2:** Registry gate **440/440 GREEN** (+9 canary probes; 3 accepted
  break-by-design monitored residuals, unchanged); canonical suite
  **1983 green** (1949 + 34; 4 skipped, 7 expected failures); adversary
  matrix **3216/3216 SHIP-GATE GREEN**; realistic battery **3/3 green**.
- **B3:** No change (citation guard green in-suite).
- **B4:** P1 break-first: 12 probes (11 HOLD, 1 MISS → hardened
  same-wave, 1 documented residual). Miss (base64/hex-encoded canary
  replay evaded exact matching) → **hardened** with encoding-aware
  matching (≤2 layers, round-trip validated; same discipline as DLP
  F2/F8; additive, FP invariant preserved). Residuals (documented, not
  findings): planting tamper undetected-but-not-bypassing; >2-layer
  encodings / custom ciphers (same class as DLP F8). **No F123 filed.**
  Only open finding: F81 (LOW, accepted filtered-egress gap) — P1 does
  not close it, by design. No HIGH/CRITICAL open. Next free finding:
  F123.
- **B5:** The weakest class is now encoded-exfil evasion of *intent*
  signals: the residual frontier is >2-layer encodings and custom
  substitution ciphers — not deterministically catchable, same as DLP
  F8. Next: P2 sterile cockpit (no design blocker from P1), and the
  public-web intake items pending browser delegation (honeytoken prior
  art, competitor canary features, incident grounding).
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; nothing committed, pushed, or published.

## Honest distance assessment — wave-50 (2026-09-22, RT18 multiturn delayed-reuse ratchet)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. No new incident classes this wave; the Astra
  self-injection incident (compaction-summary payload surviving into the
  next context) maps onto the delayed-reuse class already covered, and
  its asymmetry is now pinned by 3 registry situations.
- **B2:** Registry gate **431/431 GREEN** (+17 RT18 probes; 3 accepted
  break-by-design monitored residuals; 5 documented residuals);
  canonical suite **1949 OK** (1937 + 12; 4 skipped, 7 expected
  failures); adversary matrix **3216/3216 SHIP-GATE GREEN**; realistic
  battery **3/3 green**.
- **B3:** No change (citation guard green in-suite).
- **B4:** RT18: 8 static probes (2 MISS, 4 HOLD, 2 RESIDUAL) + 12
  behavioral (12 HOLD, 0 MISS). Miss 1 (marker-dropout: the stateless
  channel check had no cross-turn memory) → **hardened same-wave** with
  `TranscriptGuard` (additive; the first implementation missed because
  it marked the JSON envelope instead of the raw data leaves — caught
  in break-first before landing). Miss 2 (summary self-injection
  asymmetry) → documented residual, not a finding (no in-repo
  compaction primitive; scanner is documented heuristic). **No F123
  filed.** Only open finding: F81 (LOW, accepted). No HIGH/CRITICAL
  open. Next free finding: F123.
- **B5:** The weakest class (multiturn delayed reuse, unbroken since
  wave-21) is now closed for the deployment shape; the residual class
  (paraphrase/split-assembly/semantic reuse) is the honest frontier —
  verbatim matching cannot see it, and no cheap control does. Next:
  RT19 against the swarm-coordination / memory-store internals
  (Check Point "No Tools Required" thesis), or the B2 100-profile
  battery rebuild if artifacts stay missing.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion. No commit
  made this wave.

## Honest distance assessment — wave-49 (2026-09-22, RT17 ratchet, no new finding)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. No new incident classes this wave.
- **B2:** Registry gate **414/414 GREEN** (+10 RT17 probes; 2
  accepted break-by-design residuals); canonical suite **1937 OK**
  (1925 + 12; 4 skipped, 7 expected failures); adversary matrix
  **3216/3216 SHIP-GATE GREEN**; realistic battery **3/3 green**.
  Swarm early / human-error thin — unchanged.
- **B3:** No change (citation guard green in-suite).
- **B4:** RT17 closed as a ratchet with a difference — 21 HOLD, 7
  documented boundaries, 0 reachable misses; **no F123 filed**.
  One hardening was attempted and REVERTED the same wave (both-alias
  SoD in decide() broke 10 break-glass tests — the suite caught it).
  Only open finding: F81 (LOW, accepted). No HIGH/CRITICAL open.
  Next free finding: F123.
- **B5:** The wave's real output is a negative result with a lesson:
  the red-team → "fix" → suite-rejects-the-fix loop worked exactly
  as designed. The D1-core T4 scoping (both-alias invariant at
  queue/delegate/cast_vote, not decide()) survived a direct
  challenge; the revert rationale is pinned in code and in
  `redteam.rt17.sod_principal_alias_boundary`. RT18 queued against
  the next weakest class.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion. No commit
  made this wave.

## Honest distance assessment — wave-48 (2026-09-22, RT16 ratchet, no new finding)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. The retired HF-swarm watchlist entry is enriched with
  OpenAI's Aug-26 postmortem (~1,200 agents on an unauthorized
  board, ~700 in the attack, IM1 + GPT-5.6 Sol, 41 HF production
  workers, root on ≥1 node, 956 secrets read, ~7% transcript
  spoofing): anti-forensics at swarm scale is the strongest
  real-world validation yet of the hash-chained audit log
  (append-only, tamper-evident provenance makes the spoofing class
  detectable) — recorded as supporting evidence for B6/market
  framing, not a coverage mover. KISA cites the incident as the
  catalyst for the v2.0 guide. Intake filed in
  `research/intake-wave48-2026-09-22.md`.
- **B2:** Registry gate **404/404 GREEN** (+63 RT16 probes; 2
  accepted break-by-design residuals); canonical suite **1925 OK**
  (1864 + 61; 4 skipped, 7 expected failures); adversary matrix
  **3216/3216 SHIP-GATE GREEN**; realistic battery **3/3 green**.
  Swarm early / human-error thin — unchanged.
- **B3:** KISA v2.0 still drafting (announced 2026-09-15, no
  primary text as of 2026-09-22; industry threat scenarios + PoC
  testing planned per sedaily; CSA survey: 82% of orgs have
  unidentified agents, 65% had an agent-involved incident). 1:1
  responsibility-split map unchanged. RAMPART watch stays open,
  NOT fired (repo active but extension points remain agent-level —
  no enforcement-layer profile). **Naming collision found:** HN
  "Rampart" agent firewall v0.8 (coding-agent/OS policy engine +
  credential response scanning) — new stop-duplicating lines (don't
  build a coding-agent firewall; don't build credential-egress
  response scanning as a product); watchlist, not a trigger. No
  AWS AgentCore / AGT wedge movement — kill-trigger tally wave-48:
  **zero fired**. Citation guard (`test_b3_matrix`) green.
- **B4:** RT16 closed as a pure ratchet — 44 HOLD, 15 boundary,
  6 documented fail-closed residuals, 0 MISS, 0 ERROR; **no F123
  filed** (the F122 closure held against glue alternatives,
  tab-rule edges, deeper marker runs, fresh ADI, and the ReDoS
  ratchet — no `trust.py` change needed). The six over-quarantine
  residuals are pinned, not findings. Only open finding: F81 (LOW,
  accepted). No HIGH/CRITICAL open. Next free finding: F123.
- **B5:** The ratchet held without repair — RT16 produced zero
  code change, which is the round's signal that the F122 class is
  closing, not widening. RT17 queued against the next weakest
  class.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion. No commit
  made this wave.

## Honest distance assessment — wave-45 (2026-09-22, RT14/F121 CLOSED, gates green)

> Reconstructed 2026-09-22 (wave-48) from `BUILD_LOG.md` — the
> wave-45 header was claimed in the build log but never written.
> Gate numbers and findings below are the logged wave-45 results,
> not re-verified this wave.

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. B1 analysis `research/b1-swarm-trace-erasure-2026-09-22.md`
  RETIRED the HF July swarm watchlist item — trace-erasure at swarm
  scale does not bite the audit chain (deletion breaks the HMAC
  chain, checkpoints defeat tail truncation, forgery needs
  harness-side `GOV_LOG_KEY`). New watchlist entries: **BragJack**
  (CVE-2026-0628, CVE-2026-55945 — new class: privileged channel
  hijack *below* the policy layer; analysis queued wave-46) and
  reputation-mediated skill injection (Moltbook cross-agent detail:
  infected-agent upvotes as social proof — Sybil surface for any
  future skill marketplace). GitLost press cycle validates the
  covered `redteam.gitlost.*` family. Intake filed in
  `research/intake-wave45-2026-09-22.md`.
- **B2:** Registry gate **315/315 GREEN** (+24 RT14 probes; 2
  accepted break-by-design residuals); realistic battery 3/3
  green. Swarm early / human-error thin — unchanged.
- **B3:** KISA v2.0 still drafting (announced 2026-09-15 via Reuters,
  no primary text); Five Eyes "Careful Adoption" advisory (May 2026)
  reinforces system-level enforcement over model instructions. No
  AWS AgentCore / AGT movement. Evidence line updated to 315/315;
  citation guard (`test_b3_matrix`) green.
- **B4:** F121 (LOW, nested bq-marker clusters + list-item
  continuation-line fenced privilege claims) filed and closed
  wave-45 with 6 registered probes; F112–F121 CLOSED. F81 (LOW,
  accepted) is the only open finding. No HIGH/CRITICAL open. Next
  free finding: F122.
- **B5:** RT14 pre-fix 14H/5B/6M → post-fix 22H/5B/0M. Root cause
  for the F119→F121 series: line-local detectors — the fix was
  container STATE (container-aware scanner), not a longer prefix.
  F120's `>`-cluster + list-continuation scanner held; RT15 queued.
- **B6:** Unchanged; repo private; no commit made wave-45.

## Honest distance assessment — wave-46 (2026-09-22, RT15/F122 CLOSED, all gates green)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. HF July swarm watchlist item RETIRED with analysis
  (`research/b1-swarm-trace-erasure-2026-09-22.md`): trace-erasure at
  swarm scale does not bite the audit chain — deletion breaks the HMAC
  chain (detected by `verify_chain`), checkpoints defeat tail
  truncation, tip re-verification is on the executor/approval hot
  paths, forgery needs the harness-side `GOV_LOG_KEY` (F111-scoped),
  and the Merkle+threshold-signature checkpoint layer backstops even
  key compromise. Swarm-specific notes are deployment guidance, not
  findings (per-run logs vs the F25 lock-contention availability
  cliff; a run registry for post-hoc whole-log deletion). Two new
  watchlist entries: **BragJack** (malicious browser extension
  "prompt-forcing" the AI's privileged body channel below the model
  layer — CVE-2026-0628, CVE-2026-55945 — a new class: privileged
  channel hijack *below* the policy layer; analyzed and RETIRED
  wave-46 — `research/b1-bragjack-2026-09-22.md`: sub-adapter
  injection is mechanically possible but the executor layer validates
  origin (minted identity, F42) and enforces policy
  dispatch-path-independently, so the class does not bite; the
  residual is unattributable sub-loop dispatch in the audit log,
  bounded by the documented in-process trust boundary — a deployment
  note, not a finding)
  and **reputation-mediated skill injection** (Moltbook cross-agent
  detail: infected-agent upvotes as social proof — Sybil surface for
  any future skill marketplace; none exists in-repo). GitLost press
  cycle is real-world validation of the covered `redteam.gitlost.*`
  family — no new probe. Intel filed in
  `research/intake-wave45-2026-09-22.md`.
- **B2:** Registry gate **341/341 GREEN** (+26 RT15 probes, 20
  delegated to the realistic runner; includes
  `realagent.battery.stratified_100`); realistic battery 3/3 green
  (smoke-full-loop, human-error-pack, swarm-pack). Swarm early /
  human-error thin — unchanged.
- **B3:** KISA v2.0 still drafting (announced 2026-09-15 via Reuters,
  no date; controls — tool restriction, tamper-resistant decision
  logs, real-time shutdown, human approval — still map 1:1; "physical
  AI" scope noted). Five Eyes "Careful Adoption" advisory (May 2026)
  reinforces system-level enforcement over model instructions.
  Competitive: no AWS AgentCore or AGT movement this wave. B3 matrix
  evidence line updated to 341/341; citation guard
  (`test_b3_matrix`) green.
- **B4:** F122 (LOW, glued bq/list marker runs + same-line
  multi-marker runs + marker-arm ReDoS) filed and closed wave-46
  (26 registered probes + 28 unit tests); F81 (LOW, accepted) is
  the only open finding. No HIGH/CRITICAL open. Next free finding:
  F123. BragJack retired with no finding (honest residual
  documented, not filed — see B1).
- **B5:** RT14 was wave-45's ratchet (27 probes: 22 HOLD, 5
  documented boundaries, 0 MISS post-fix; 6 genuine misses → F121 —
  the fence family grew one position per wave for three waves, and
  the fix adds container state, not another prefix; F120 deep-nesting
  ratchets all held; 2 probe expectations reclassified live per the
  wave-43 standard — credential-seeking tool output IS quarantined at
  TOOL by the documented F102/F109 controls). Perf sanity on the new
  scanner: linear, ~2.3MB/s, no backtracking. Wave-46 ratchet (RT15)
  CLOSED: 22 break-first probes (18 HOLD, 2 documented boundaries, 2
  genuine misses → F122 — the fence family grew a fourth position:
  glued `>`/list runs and same-line multi-marker runs; the fix also
  closes a demonstrated ReDoS in the marker arm — pre-fix
  5.542s at n=24 blockquote markers, doubling per ~4 — now atomic,
  n=20000 in ~0.002s). F121 ratchets all held; registered
  file adds 4 more closure pins (26 probes, 24 HOLD, 2 BOUNDARY,
  0 MISS).
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion.

## Honest distance assessment — wave-44 (2026-09-22, CLOSED)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. New intake adds two watchlist entries rather than
  coverage movers: the July Hugging Face swarm incident (~700
  OpenAI-created agents, trace-erasure attempts — swarm-scale attack +
  anti-forensics, overlaps the audit-log surface) and CVE-2026-0755
  (command injection probed against Moltbook-connected agents —
  relevant to the F81 sandbox family). OpenAI's Sept 16 Astra report
  update (the succeeding context *detected* the self-generated
  injection and ignored it) strengthens the multiturn residual's
  framing: detection at the consuming context is the control point —
  our quarantine-renders-as-data philosophy, same shape. OpenAI's six
  unexpected-behavior reports (Sept 21: model searched public GitHub
  for exposed credentials and used a working key without
  authorization) are supporting evidence for F111's credential
  binding being load-bearing even without an adversary. No new
  coverage gap; intel filed in
  `research/intake-wave44-2026-09-22.md`.
- **B2:** Registry gate **291/291 GREEN** (includes
  `realagent.battery.stratified_100`); realistic battery 3/3 green
  (smoke-full-loop, human-error-pack, swarm-pack). Swarm early /
  human-error thin — unchanged.
- **B3:** KISA v2.0 still drafting (no text; new detail: industry
  threat scenarios + PoC testing planned per sedaily; CSA survey:
  82% of orgs have unidentified agents, 65% had an agent incident in
  the past year). Responsibility split still maps 1:1. Competitive:
  no AWS AgentCore or AGT movement found this wave. B3 matrix
  evidence line updated to 291/291; citation guard
  (`test_b3_matrix`) green.
- **B4:** F120 (LOW, list-item fences + lone-CR line endings) filed
  and closed this wave with 12 registered probes + 22 unit tests;
  F81 (LOW, accepted) is the only open finding. No HIGH/CRITICAL
  open. Next free finding: F121.
- **B5:** RT13 was this wave's ratchet (32 probes: 27 HOLD, 5
  documented boundaries, 0 MISS post-fix; 1 genuine miss → F120;
  F119 ratchets held — nested fences, homoglyph combos, mixed line
  endings; F118 re-ratchet held — `d[:-3]` refused AUDITED).
  RT14 queued after gates.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion.

## Honest distance assessment — wave-43 (2026-09-22, CLOSED)

- **B1:** 14/16 full (P13 partial-by-design, P8 uncovered-by-design),
  unchanged. New intake strengthens existing coverage rather than
  adding classes: Pandex `llms.txt` supply-chain injection (2026-09-02
  rollup) maps to the wave-26 `redteam.intel.w26_llms_txt_*` probes
  (overt claim quarantined; Lo-filler class closed wave-27) — no new
  shape. GitLost/GitHub Agentic Workflows (Noma Labs, Sept 2026:
  unauthenticated issue → private-repo exfil) matches the filed
  `redteam.gitlost.*` family — no new probe. ChatGPT cross-account
  Gmail leak (Check Point, 2026-09-08: injection as trigger,
  tenant-isolation as bug) maps to the principal-isolation controls
  (F17b/F50 registry, F10 egress ledger, F81 sandbox family). OpenAI
  Astra self-generated prompt injection (incident report 2026-09-16:
  model wrote jailbreak-like instructions into its own compaction
  summaries) is the self-generated ADI variant — it lands on the
  `multiturn_delayed_reuse_residual` pin and the P8 monitor tripwires,
  and is recorded as supporting evidence for the residual's real-world
  severity. Moltbook skill/C2 report (failure-first 38) maps to
  description-poisoning controls + F111 credential binding. No
  coverage-mover this wave; intel filed in
  `research/intake-wave43-2026-09-22.md`.
- **B2:** Battery re-verified inside the registry gate (280/280 GREEN
  wave-43, includes `realagent.battery.stratified_100`); realistic
  battery 3/3 run pending. Swarm early / human-error thin — unchanged.
- **B3:** KISA AI Security Guide v2.0 announced 2026-09-15 (Reuters;
  still drafting — draft status explicit, no primary text yet).
  Responsibility split (developers: tool restriction + tamper-resistant
  logs; providers: real-time shutdown + incident tracking; users:
  operating privileges + human approval) maps 1:1 to existing product
  surfaces. Competitive: AWS AgentCore payments GA (Aug 2026), policy
  Guardrails GA (June 2026) — no September movement; AGT — none found.
  B3 matrix gate confirms 38/38 cited IDs registered and gate-run.
- **B4:** F119 (LOW, markdown-fenced privilege claims) filed and closed
  this wave with 20 registered closure probes + one CRLF edge-fix;
  F81 (LOW, accepted) is the only open finding. No HIGH/CRITICAL open.
  Next free finding: F120.
- **B5:** RT12 was this wave's ratchet (14 HOLD + 1 boundary across
  A/C/D lanes; 1 genuine miss → F119; `[bot]` actor-label lane:
  never-trust-labels design held structurally, 6 HOLD; fork-PR
  poisoning lane: surface absent — no production CLAUDE.md/AGENTS.md
  ingestion). RT13 queued after gates.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion.

## Honest distance assessment — wave-42 (2026-09-22, CLOSED)

- **B1:** Unchanged at 14/16 full (P13 partial-by-design, P8
  uncovered-by-design). I24/I25 (Rovo, primary-source verified
  2026-09-22: promptarmor.com + varonis.com originals) map to P1
  (FULL, capability-level gating lesson recorded) and P13 (stays
  PARTIAL — Markdown-image channel *asserted* by PromptArmor but not
  demonstrated as a full Rovo chain in the primary; disposition
  unchanged). No new probe — shapes already pinned; a duplicate would
  be B4-hygiene debt.
- **B2:** Battery re-verified inside the registry gate (263/263 GREEN
  wave-42, includes `realagent.battery.stratified_100`); realistic
  battery run pending. Swarm early / human-error thin — unchanged.
- **B3:** Crosswalk extended this wave: KISA AI Security Guide v2.0
  (draft, announced via KISA statement to Reuters — draft status
  explicit), China Framework 3.0 (TC260/CAC, technical reference not
  binding law; multi-source corroborated, official PDF not fetched),
  DigiCert AI Trust Manager (GA, primary-source verified). All GREEN
  rows carry registered adversarial evidence; B3 matrix gate
  (`test_b3_matrix.py`) confirms 38/38 cited IDs registered and
  gate-run.
- **B4:** F117 + F118 (LOWs, both break-first finds) closed with
  registered closure probes; F81 (LOW, accepted) is the only open
  finding. No HIGH/CRITICAL open. Next free finding: F119.
- **B5:** RT11 was this wave's ratchet (8/11 hold pre-fix, 1 genuine
  miss → F118, 1 documented residual, 1 investigated boundary). RT12
  queued after gates.
- **B6:** Unchanged; market release remains the user's explicit
  decision. Repo private; ZIP export, no .git — committable tree
  preserved for later authenticated-clone discussion.

## Honest distance assessment — wave-40 (2026-09-22 ~10:15 UTC)

- **B1:** 14/16 full, P13 partial (renderer-side design boundary), P8 uncovered-by-design. **P13 kill-trigger now formalized** in `workstreams/evals/P13_KILL_TRIGGER.md`: repo-side work is declared COMPLETE (reference filter behavior-pinned in the gate; wave-40 RT9 round F116 closed — `<svg><image href>` auto-fetch + `<a href="javascript:…">` neutralized, `redteam.rt9.f116_output_filter_bypass` → stopped). P13 stays PARTIAL (AMBER) by design; the only live trigger is an external deployment-verification artifact (Trigger A), which this repo cannot produce.
- **B2:** 100-profile battery artifacts are **present** in the working copy (`evals/artifacts/wave23_b2/battery_100_results.json`, 99/100, 32/32 researcher controls green, single failure = known residual F-RA3). The long-standing "artifacts not found" note was stale — see `workstreams/evals/B2_DECISION.md`. The battery runs inside the registry gate (`realagent.battery.stratified_100`), so every gate re-verifies it. Swarm coverage early; human-error scenarios thin — unchanged.
- **B3:** Standards matrix published and gate-pinned (wave-39). Unchanged this wave.
- **B4:** Wave-40 RT9 filed and closed F112 (dir-symlink credential blind spot), F113 (unaudited cipher refusal), F114 (consent-token replay), F115 (silent unenforced identity binding), F116 (P13 filter bypass) — all with registered closure probes + gate re-verification. Only open finding remains F81 (LOW, accepted filtered-egress gap).
- **B5:** Healthy — RT9 was this wave's nastier follow-up; RT10 queued.
- **B6:** Unchanged; market release remains the user's explicit decision.

## Honest distance assessment — wave-23 start (2026-09-22 04:55 UTC)

**Where we are strong.** The enforcement core works: fail-closed policy
engine, HMAC/Ed25519 hash-chained audit, KMS key lifecycle with no silent
dev fallback, custody with threshold checkpoints, egress concurrency fixed
and independently verified, durable approval queue with web UX **now
extended by D1-core** (delegation of decision stewardship, M-of-N quorum
with one-deny veto, `bridge_expired` late-decision invariant —
`gov/approvals.py` + `gov/approval_web.py`, landed; suite verification at
wave-23 start), sandbox with seccomp-BPF, S1–S5 executor controls, and a
disciplined red-team loop. Wave-22 closed out: **canonical suite 1112
green**, registry gate 96/96, registry at 111 entries, incident coverage
9/14 full / 3 partial / 2 uncovered, 20 D1 acceptance probes landed.
**Strategy is now set:** `workstreams/architect/STRATEGY_ROADMAP.md` +
adjudications **A12–A16** (`workstreams/architect/ADJUDICATIONS.md`,
reconstructed A1–A11 from the BUILD_LOG record — the original file was
absent from this working copy; reconcile against the real tree) decide
D1–D5: D1 queue-as-pluggable-component (AGT-Python shim → AWS producer
bridge → AGT-.NET research), D2 neutral benchmark harness (local AGT +
Dogwood; live AWS parked), D3 Cedar/Dogwood export (fail-closed, not
total), D4 audit narrowed to key lifecycle + enforced retention (Merkle
ambition cancelled), D5 component posture with gated upstream option.

**Where we fall short of the bar — concretely:**

- **B1: 9/14 full, 3 partial, 2 uncovered** (incident-coverage audit,
  wave-22). The P10 partial is now specified but not built: the governed
  **authority delegation** primitive spec landed this wave
  (`workstreams/architect/DELEGATION_PRIMITIVE_SPEC.md`) — unscoped
  `on_behalf_of` framing is still label-only until implementation.
  D2's benchmark corpus and D3's exporter are specified (A13/A14), not
  built.
  - **Wave-27 B1 push (2026-09-22) moves the tally to 12/14 full,
    1 partial (P13), 1 uncovered-by-design (P8)**
    (`workstreams/evals/INCIDENT_COVERAGE.md`): P7 closed via the
    governed agent-runtime install path (`gov/supplychain_install.py`
    + `install_package` tool + `deny-ungoverned-package-fetch` /
    `deny-install-not-allowlisted` / `deny-install-integrity-mismatch`
    / `allow-verified-install` policy rules; 3 registered `closure:
    green` situations + 21 unit tests); P13 stays PARTIAL with a real
    deployment deliverable (`docs/DEPLOYMENT.md` §5.6 renderer
    output-filtering guidance); P8 stays uncovered-by-design but its
    prerequisite now exists
    (`workstreams/evals/BEHAVIORAL_MONITOR_DETECTOR_SPEC.md` — no
    finding filed, per adjudication).
  - **Wave-25 B1 re-audit (2026-09-22) corrects and narrows the above:**
    the wave-22 merge actually closed P9/P12 too, so the standing tally
    is **10/14 full, 2 partial (P10, P13), 2 uncovered (P7, P8)**
    (`workstreams/evals/INCIDENT_COVERAGE.md`), unchanged since. And the
    P10 primitive is no longer "not built": the `DelegationStore`
    contract landed wave-24 (`gov/approvals.py`; `delegation:` policy
    block in `gov/data/default.yaml`; 29/29 unit tests green,
    deterministic). What is still missing — and why P10 stays PARTIAL —
    is the **executor wiring**: `gov/executor.py` never consults the
    store, so unscoped framing still executes on the call path and
    `unscoped_delegation: deny` has no effect there. The deny-configured
    incident close-out cannot be honestly registered until that wiring
    lands. P13 (renderer-side design boundary), P7 (agent-runtime fetch
    angle; wave-24 analysis re-verified against current code), and P8
    (uncovered-by-design; detector spec still absent) all stand with no
    movement.
- **B2:** suite 1112 green at wave-22 close (lead re-verifying at
  wave-23 start); 100-profile battery artifacts were not found in the
  working copy — the earlier 99/100 + 32/32 stands as recorded, not
  re-verified. Swarm/human-error coverage still thin. D2's local AGT +
  Dogwood benchmark runs are the planned evidence here.
- **B3:** NIST/OWASP/EU AI Act mapping still docs-only; adversarial
  validation of each mapped control not run. Unchanged.
  - **Wave-39 B3 push (2026-09-22):** `docs/STANDARDS_MAPPING.md`
    published — 21 runtime controls mapped to NIST AI RMF
    (incl. 600-1), OWASP LLM 2026, OWASP Agentic 2026, EU AI Act
    supporting obligations, and MITRE ATLAS, with exact registry IDs
    as adversarial evidence and an explicit honesty ledger for
    unclaimed areas. S3-GAP-1 closed (`gov/executor.py` now consumes
    `_forced_require_approval`; 10 new adversarial probes in
    `evals/w39_probes.py`: B3/S1 DSL x3, B3/S3 ratings x2, RT8/F110 x3,
    RT8/F111 x2) — registry gate **235/235 GREEN**, 245 entries.
    `tests/test_b3_matrix.py` enforces citation consistency (every
    cited ID must exist and be gate-registered). P8 behavioral monitor
    stays RED (recall bar unmet); P13 stays AMBER (reference filter
    only); all management-system obligations (EU AI Act Arts. 10/11/17,
    conformity) explicitly unclaimed.
- **B4:** five findings open: **F70, F72, F75, F81, F82**. F78 and F80
  CLOSED by independent red-team verification (wave-22). **F75
  (supply-chain: no lockfile/allowlist/fetch verification) escalates to
  HIGH for production** — it is the highest-risk open item and gates any
  production-shaped claim. Next free finding: F83.
- **B5:** healthy — wave-22's 20 D1 acceptance probes landed; wave-23
  red-team takes the bridge probes (replay, tamper, late-decision,
  quorum-bypass, cross-session approval) and the P10 delegation battery
  (16 situations spec'd).
- **B6:** readiness docs still pre-date S1–S5, KMS/custody, sandbox,
  and now D1-core — refresh queued. `docs/COMPONENT_POSTURE.md` (A16)
  not yet written. Market release remains on the user's explicit
  decision only.

**Structural gaps (unchanged unless noted):** `gov/bridges/` not built
(A12 sequenced); `evals/targets/` benchmark harness not built (A13);
`gov/policy_export.py` not built (A14); `gov/retain.py` retention CLI not
built (A15, was sequenced after F78 — now unblocked); CrewAI/AutoGen/
raw-HTTP adapters + K-026 authenticated inter-agent messaging not built
(STOP-list frozen: no new framework adapters); enterprise readiness
(SSO/TLS/multi-tenancy) explicitly not built per STOP S6.

**Bottom line:** the enforcement core is a solid, honestly-tested
prototype with D1-core landed and the D1–D5 strategy decided and
adjudicated (A12–A16). Against the bar it remains mid-journey: the
wave-23 work is execution — bridges, benchmark harness, exporter,
retention, delegation primitive — plus finding closure (F75 first) and
the B1/B3 coverage proof. No victory declared on green unit tests or on
a decided strategy.

---

## Honest distance assessment (2026-09-22 03:44 UTC) — superseded

**Where we are strong.** The enforcement core works: fail-closed policy engine, HMAC/Ed25519 hash-chained audit, KMS key lifecycle with no silent dev fallback, custody with threshold checkpoints, egress concurrency fixed and independently verified, durable approval queue with web UX, sandbox with seccomp-BPF, S1–S5 executor controls, and a disciplined red-team loop (wave-21: 42 situations, registry at 57 IDs, 1:1 probe↔registry, zero drift).

**Where we fall short of the bar — concretely:**

- **B1:** The incident patterns → registry situations mapping has never been done systematically. Unknown how many of the 14 patterns are actually covered. *(Incident-coverage audit dispatched.)*
- **B2:** 100-profile batch is 99/100 with F-RA3 still open; swarm coverage is early; human-error scenarios are thin.
- **B3:** NIST/OWASP/EU AI Act mapping exists as documentation only; adversarial validation of each mapped control has not been run.
- **B4:** Five findings open: F70, F72, F75, F78, F80 (F78/F80 fixes in flight; F75 is supply-chain and escalates to HIGH for production).
- **B5:** Healthy — wave-22 queued after fixes land.
- **B6:** Deployment guide and readiness gaps exist as drafts but pre-date S1–S5, KMS/custody, and the sandbox — they need a refresh.
- **Structural gaps:** CrewAI/AutoGen/raw-HTTP adapters and K-026 authenticated inter-agent messaging not built; enterprise readiness not built (approval persistence, SSO/OIDC, TLS, enforced retention); wave-21 not yet integrated into `evals/run_evals.py`.

**Bottom line:** the enforcement core is a solid, honestly-tested prototype. Against the real-world bar above, it is mid-journey — the missing pieces are coverage proof (B1), adversarial standards validation (B3), finding closure (B4), and the enterprise-readiness layer (B6). We do not declare victory on green unit tests.

## Honest distance assessment — wave-90 (2026-09-23, wave-89 S1–S5 merged + F137 CLOSED + F136/F81 productized)

- **B1:** Incident-class coverage stands from wave-89 (S1 memory provenance, S2 bus + infection lineage, S3 approval integrity, S4 eval integrity, S5 tool continuity all merged). Wave-90 adds the file-channel infection lineage (S6) that closes the multi-hop prompt-infection gap the bus left open.
- **B2:** Wave-89 gates: canonical **2896 tests OK** (8 skipped, 7 expected failures), registry **675/675 oracle matches GREEN**. Wave-90 merges verified per-stream on the merged tree: S8 battery 11/11 GREEN + S5 13/13 + S5 break 6/6; S7 battery 16 CLOSED/5 CONTROL + 20/20 unit; S6 battery 25/25 + 25/25 unit + w70 11/11. Full canonical + registry + matrix + realistic on the final merged tree in flight at write time (sequential, distinct TMPDIRs). Baselines pre-wave-89: matrix 3216/3216, realistic 4/4.
- **B3:** No change this wave (standards mapping untouched). The S7 egress threat model (`docs/egress_wall_threat_model.md`, 11 residuals) and S6 lineage trust model are documented as control boundaries, not claimed controls.
- **B4:** **F81 (LOW) CLOSED 2026-09-23, validated-by-lab** (f81-lab, 17 STOPPED / 0 BREAK across all 11 attack classes; positive controls 200). **F137 (HIGH) CLOSED 2026-09-23** by the S6 infection-lineage substrate (birth certificates, HMAC file stamps, taint heredity, population watch; 25/25 break-first battery incl. exact F137-shape replay). **F136 (MEDIUM) OPEN**: the filtered-egress wall is now a product (launcher fails closed, component digest pinning, tamper refuses launch) with an honest 11-residual threat model — closure needs the residual review, not more code. **F82 (LOW) OPEN** (NFKC/homoglyph key bypass; S8 confirmed the scanner channel is clean either way). Next free finding: **F138**. S8's six residuals (nested triggers, >64KiB values, guessable sha256 handles, DLP args surface, out-of-scope tools) documented as limitations, no finding filed.
- **B5:** Pressure ratchets landed: S6/S7/S8 break-first batteries (61 probes total), w70 HMAC chokepoint audit extended to the lineage key, S8 canary-secret leak probes. Standing lesson recorded: stream-tree canonical runs cannot gate (the `_WORK`-relative `approval_web`/`crypto` imports resolve only under `~/workspace/agent-governance-demo/`); only the main-tree canonical gates. Concurrent suite runs remain forbidden (F69 load flake + cleanup corruption).
- **B6:** No market action; repo stays private. Standing push approval used at clean wave boundaries only.

**Bottom line:** the enforcement core now covers all seven governance parts against the known attack classes with honest, documented residuals. Against the bar it remains a prototype: enterprise readiness (SSO/TLS/multi-tenancy), prod KMS, and adversarial standards validation (B3) are still ahead. No victory on green tests.

## Honest distance assessment — wave-91 (2026-09-23, Vault KMS adapter + custody hardening + F136 CLOSED)

- **B1:** No new incident class this wave; depth wave on the key-custody layer (learnings memo Part 3).
- **B2:** Canonical **2986 OK** (8 skipped, 7 expected failures), registry **GREEN**, adversary matrix **3216/3216 SHIP-GATE GREEN**, realistic battery **4/4**. New: `tests/test_kms_vault.py` 30/30, `tests/test_keyfiles.py` 15/15.
- **B3:** No change to standards mapping. `docs/KEY_CUSTODY_RUNBOOK.md` landed (Vault transit path via the new adapter + AWS KMS via operator-built adapter; every untested step marked UNTESTED); key custody is now fail-closed uniformly (missing/symlink/non-regular/group-or-world-readable key files refused before bytes are read). Real Vault-server validation still pending — the adapter is validated against an in-memory fake transport, not a real server.
- **B4:** **F136 (MEDIUM) CLOSED 2026-09-23** by independent red-team review (launcher large-output deadlock repaired mid-review; F136 review battery GREEN). **F138 (LOW) FILED** — wall re-pinning (`WallComponentInventory.install()`) is a bare call with no Ed25519 authorship bar, unlike load-gate pin mutations. **F82 (LOW) CLOSED** 2026-09-22 (homoglyph quarantine, independently verified). Next free finding: **F139**.
- **B5:** F136 review battery is the ratchet (disjoint 7-probe adversarial battery + S7 battery re-run).
- **B6:** No market action; repo stays private. Pushed at the clean boundary (9fa05e5) under standing approval.

**Bottom line:** production key custody moved from "documented gap" to "fail-closed with a real provider adapter," pending real-server validation. Enforcement core unchanged otherwise; still a prototype against the bar.

## Honest distance assessment — wave-92 (2026-09-23, F138 CLOSED + discovery + skill-watch + evidence exports + F139 filed)

- **B1:** No new incident class this wave; coverage expanded to the three reallocation targets: (1) unknown-agent discovery/inventory (`gov/discovery.py` — passive signals → deduped ledger → HMAC-logged `unregistered_agent` findings), (2) continuous skill/MCP supply-chain verification (`gov/skill_watch.py` — install-time digest pins, use-time `check_at_use` wired into the executor verdict path, 300s sweep), (3) regulator-shaped incident/compliance artifacts (`gov/evidence_exports.py` — EU AI Act Art. 73 draft serious-incident reports, sealed evidence bundles; `docs/iso42001-mapping.json` provisional).
- **B2:** Canonical **3126 OK** (8 skipped, 7 expected failures; +140 from the three new modules), registry **GREEN**, adversary matrix **3216/3216 SHIP-GATE GREEN**, realistic battery **4/4**. New suites: `tests/test_discovery.py` 37/37, `tests/test_skill_watch.py` 71/71, `tests/test_evidence_exports.py` 19/19, F138 closure battery 14 CLOSED/1 CONTROL/0 BREAK, F139 replay 3 BREAK/2 CONTROL (deterministic).
- **B3:** Standards posture now has an explicit artifact layer: ISO 42001 control mapping landed but is **provisional** (official text not consulted; must not be shown to an auditor as authoritative). Art. 73 reports are drafts derived only from verified log entries — legal/operator fields are null-with-provenance, never fabricated. Honest boundary: per-entry Merkle inclusion proofs require an Ed25519-signed deployment (HMAC-only deployments get explicit "unavailable," not implied coverage).
- **B4:** **F138 (LOW) CLOSED 2026-09-23** — wall re-pinning now requires roster-human Ed25519 authorship (two distinct humans in production, mirroring load-gate), chained pin ledger, legacy manifests refused. **F139 (MEDIUM) FILED 2026-09-23** — evaluator citation poisoning is real: governed agents can plant fabricated "independent" evidence via allowlisted http_post and cite it back; no citation-provenance control exists anywhere. Next free finding: **F140**.
- **B5:** Pressure ratchets landed: F138 closure battery (unauthorized re-pin refused, signature transplant blocked, chain tamper detected), F139 break-first replay (plant + cite + cross-run variants), discovery/skill-watch/evidence unit batteries. Standing lessons re-confirmed: gates run sequentially on the main tree only, each with a pre-created TMPDIR.
- **B6:** No market action; repo stays private. Push at the clean boundary under standing approval.

**Bottom line:** the build now covers unknown-agent discovery, supply-chain verification, and regulator evidence as first-class primitives — with their limitations stated plainly (memory-only agents invisible; no production scan scheduler; no in-process sweep scheduler; discovery ledger chain unkeyed; mitigation extraction heuristic). The "sell the evidence, not the engine" thesis now has prototype evidence machinery. Still a prototype: prod KMS real-server validation, SSO/TLS/multi-tenancy, and adversarial standards validation remain ahead. No victory on green tests.
