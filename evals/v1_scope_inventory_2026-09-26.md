# v1 Scope Inventory — every unfinished / partial / deferred thread in one place

**Lane:** Wave-116 Lane 1 (inventory only; no product code changed).
**Date:** 2026-09-26. Feature freeze: 2026-10-21. Private v1.0 ship: 2026-10-31.
**Sources read in full:** `evals/attack_program_status_2026-09-26.md` (18-row program),
`docs/READINESS_GAPS.md` (wave-113 refresh), `workstreams/architect/REALWORLD_BAR.md`
(through wave-112/113), `evals/FINDINGS.md` (174 findings, tail = F173/F174 closed,
next free **F175**, **open findings: none**), `docs/evidence-bundle-spec.md` §7,
`evals/f81_privilege_carry_decision.md`, `BUILD_LOG.md` (top = Wave-115 entry).

**Method:** every thread below names what it is, where it is recorded, its current
state, and one recommendation: **CLOSE** (finish before freeze), **HARDEN** (tighten,
do not expand), or **DEFER** (explicitly out of v1, with rationale). For every
"by design" boundary the decision is re-examined and the verdict is stated in words.
Nothing is hand-waved; the §0 register also lists status lines found stale during
this read so the coordinator can correct them.

---

## §0 — Stale lines found (correct these, no product work)

- **S1.** `docs/READINESS_GAPS.md` §1 says "Open findings: F173, F174 (wave-114 lane 1;
  next free finding F175)". Both were CLOSED 2026-09-26 by Wave-115
  (`evals/FINDINGS.md` tail; `BUILD_LOG.md` Wave-115 entry). Correct to: open
  findings: **none**; next free: **F175**.
- **S2.** `docs/READINESS_GAPS.md` header: "waves 80–112 filed and closed findings
  F138–F172". Now: waves 80–115 filed and closed **F138–F174**.
- **S3.** `docs/READINESS_GAPS.md` §2: "Stratified-100 artifact pinning: ... A wave-113
  sibling lane is building the honest pinned claim; until it lands, '99/100' stands
  as recorded, not re-verified." It landed in wave-113 (`evals/stratified_100_claim.json`
  + `evals/verify_stratified_100_claim.py`, fail-closed verifier, re-verified
  2026-09-26: 99/100 with exactly the pinned `careless-typo-014`/F-RA3 miss).
- **S4.** `evals/attack_program_status_2026-09-26.md` tail (F69 maintenance note):
  "Next free finding remains F173" → **F175**.
- **S5.** Same file's same-day addendum: F173/F174 described as "both LOW, OPEN" —
  true at Lane 3's writing time, superseded by the Wave-115 closure. The row
  statuses are unaffected (neither finding contradicts a COVERED row).
- **S6.** `workstreams/architect/REALWORLD_BAR.md` has no wave-114/115 B1–B6
  assessment (last: wave-112/113). The standing sync rule
  (BUILD_LOG + FINDINGS + READINESS_GAPS + REALWORLD_BAR) is violated; B6 was not
  re-assessed after the evidence-bundle adversarial rerun and F173/F174 closure.
- **S7.** `evals/FINDINGS.md` still carries duplicate F81 headings (cosmetic; the
  wave-112 audit already noted it). Merge while doing C1.
- **S8 (process, not a typo).** The Wave-115 `BUILD_LOG.md` entry records only
  targeted gates (51/51 unit, adversarial 9/9, normative 14/15) — no canonical
  suite, registry gate, matrix, or realistic battery on the pushed tree. The wave-114
  integration note explicitly says the four-gate boundary was "deliberately not run
  by this wave; it is the parent's." Since F173/F174 touched `gov/evidence_bundle.py`,
  `gov/evidence_verify.py`, `tools/evidence-verify` and eval batteries, a full-gate
  run on the final tree is the standing "quiet-box after each landing" rule. See C11.

---

## §1 — CLOSE (finish before freeze 2026-10-21)

**C1. Record synchronization (the four standing files).**
What: the §0 items S1–S7, plus a wave-114/115 B6 assessment in REALWORLD_BAR.md.
Where: `docs/READINESS_GAPS.md`, `workstreams/architect/REALWORLD_BAR.md`,
`evals/attack_program_status_2026-09-26.md` tail, `evals/FINDINGS.md` F81 headings.
State: the tree is 2 waves ahead of its own paperwork; every past wave shows that
stale docs become stale claims (wave-112's F81 restatement error, wave-113's
correction). Recommendation: CLOSE — one documentation wave before freeze; no
wave ships after it without the sync check.

**C2. F81 privileged re-verification with a durable artifact.**
What: the filtered-egress wall's privileged battery (`evals/f81launcher_privileged.py`,
10 close-when probes + control) ran under genuine privilege in wave-98
(root, `GOV_F81_PRIVILEGED=1`, netns `f81test0`, 11/11 CLOSED ×2, defect F148 found
by that run) — but **no run artifact exists in the tree** (prose only), waves 99–115
changed the seams, and the wave-113 re-verification attempt was genuinely blocked
(f81-lab stopped, ephemeral IP released; `evals/f81_privilege_carry_decision.md`).
Where: FINDINGS.md F81 entry; attack-program row 13 "stale-evidence note".
State: closure stands on the tree record (adjudicated wave-113); not re-verifiable
from today's tree. Recommendation: CLOSE — the carry decision names the concrete
re-run conditions; re-run on f81-lab (standing $0 order: start, run, stop) before
freeze and commit the per-probe output as a durable artifact. This is the single
most load-bearing security claim in the tree; it must not ship v1.0 on prose.

**C3. Attack-program Row 9 — tool-result caution erosion / many-shot: the only genuine GAP.**
What: no trajectory-level erosion signal exists; per-action checks are
trajectory-blind (memo: GAP → still GAP, 2026-09-26). This is the class behind
many-shot jailbreaks — the most prolific real-world jailbreak technique — and it
is explicitly NOT on the D4 deliberately-not-proposed list.
Where: `evals/attack_program_status_2026-09-26.md` Row 9.
State: no dedicated build ever landed (wave-96 was once scheduled; numbering
diverged; work never landed). Recommendation: CLOSE with bounded scope — a
trajectory-review control at the high-risk seam: on capture-tier / high-risk
actions, the executor passes a trajectory summary (tool-result sequence, drift
signals) through the existing citation-provenance / shield brief path so the
human (or the shield) sees erosion before approving. If even that cannot land by
freeze, the fallback is an explicit v1 boundary in the spec, not silence.

**C4. Row 13 authorized-channel exfil battery (the ShareLeak/CamoLeak shape).**
What: mechanism class (canaries + DLP + sterile windows + egress ledger + F81 wall)
is covered, but **authorized-channel exfil** — exfil riding a legitimate,
classifier-approved action — has no dedicated battery; the memo's wave-100 ask
never landed as distinct work.
Where: attack-program Row 13 residual; READINESS_GAPS §1 (F81 residuals).
State: PARTIAL, stronger within PARTIAL, but the specific shape is unprobed.
Recommendation: CLOSE — a dedicated break-first battery (exfil inside an
approved, legitimate action's content channel) before freeze. A buyer who knows
the ShareLeak paper will ask exactly this question.

**C5. Legacy ungoverned construction is the repo default.**
What: the governed policy-change path (wave-75/w84) is opt-in; wave-84 measured
42 of 44 `ToolExecutor` construction sites as legacy, and "direct
`PolicyEngine(path) → ToolExecutor` makes attacker-selected policy effective with
zero ceremony, zero records: a complete bypass of the governed path by default."
The honest auditor one-liner in the tree: "the default deployment posture in this
repo is ungoverned."
Where: REALWORLD_BAR.md wave-84 entry, 4 registered `residual:documented` probes
(`legacy_executor_ignores_governed_change`, `legacy_construction_zero_ceremony`,
`legacy_blast_radius_counted`).
State: `is_governed` exists for deployments to assert; nothing asserts it on the
documented ship/demo path. Recommendation: CLOSE, bounded — wire `policy_store=`
through the documented deployment entry points (demo/ship paths) or make them
fail closed / refuse loudly when ungoverned. A buyer who runs the hero demo is
currently ungoverned; that must not be the v1.0 first impression.

**C6. Row 12 — model-artifact inventory (weights/scaffolding checksums).**
What: no weight/scaffolding inventory with checksums; no exfil-shaped outbound
detection tuned to model artifacts. Likelihood low today, impact catastrophic —
the assessment is unchanged since the memo.
Where: attack-program Row 12.
State: PARTIAL, roughly unchanged. Recommendation: CLOSE, bounded — the inventory
half is cheap and buyer-visible: a session-open inventory record (artifact path,
sha256, size, mtime) chained into the log, so "which model bytes ran" is
answerable. The outbound-detection tuning is research; keep it DEFERRED.

**C7. Approval web UI does not render the shield brief; quorum `cast_vote` untouched.**
What: GAP-3's approver shield (`gov/approver_shield.py`, F156 CLOSED) is CLI +
programmatic only; the web UI — the surface a human approver actually uses —
does not render the independent brief; `cast_vote` has no per-voter handshake.
Where: attack-program Row 3 residuals; wave-105 BUILD_LOG entry.
State: documented residuals. Recommendation: CLOSE, bounded — render the brief
in `gov/approval_web.py` for capture-tier items before freeze; for `cast_vote`,
either add the handshake or write the explicit boundary (quorum voters bypass
the shield). Shipping a shield the approver never sees on the primary UI is a
half-built control.

**C8. Row 7 — delayed execution / logic bombs: the correlation record.**
What: no intent ledger tracking planted preconditions, no temporal blast-radius
analysis, no revocation timing for non-proximate harm. Effect journals and the
hash-chained audit exist; correlation of action-now with harm-later does not.
Where: attack-program Row 7 (PARTIAL, unchanged since the memo).
State: unbuilt; the memo's specific asks are unbuilt. Recommendation: CLOSE,
bounded — a minimum viable temporal-correlation record: high-risk actions carry
a chained "precondition/intent" annotation and the executor re-surfaces linked
preconditions at later high-risk actions (the B5 multiturn-delayed-reuse ratchet
is the pattern to follow). Full temporal blast-radius analysis is v2.

**C9. Row 11 — agentic misalignment without attacker: standing-goal registration.**
What: behavioral circuit breakers + policy engine constrain actions regardless of
motive (the well-shaped half), but there is no standing-goal registration, no
goal-conflict detection, no anomaly on "agent pursuing unassigned goals."
Where: attack-program Row 11 (PARTIAL, roughly unchanged; once scheduled as
wave-98, never landed).
State: unbuilt. Recommendation: CLOSE, bounded — a goal-registration primitive
(agent declares standing goals at session open; chained; goal-conflict trip on
tools whose declared purpose diverges from registered goals). This is the
misalignment class a safety-conscious buyer names first.

**C10. Eval integration hygiene: wave-21+ situations into `run_evals.py`.**
What: noted as not-yet-integrated in REALWORLD_BAR.md (v1 note) — situations
living outside the registry gate.
Where: REALWORLD_BAR.md B3 notes; `evals/run_evals.py`.
State: noted, not blocking, still open. Recommendation: CLOSE — cheap,
mechanical, and it removes a standing "noted but never done" line from the bar.

**C11. Full four-gate boundary on the final pre-freeze tree.**
What: per S8, wave-115's push record lacks the canonical / registry / matrix /
realistic boundary on the final tree.
State: wave-114/115 gates were targeted-only by design; the parent owns the
boundary. Recommendation: CLOSE — run canonical + registry + matrix + realistic
on the exact pre-freeze tree with pre-created TMPDIRs under `~/workspace/.gov-venv`
before 2026-10-21. The standing red-first post-wave audit rides on this run.

---

## §2 — HARDEN (tighten, do not expand)

**H1. F75 residual — supply-chain audit is name/version-level, not byte-level.**
Where: `docs/READINESS_GAPS.md` §1; FINDINGS.md F75 (CLOSED 2026-09-22; HIGH
escalation retired). State: `requirements.lock` (exact pins + sha256) and the
fail-closed `gov/supplychain.py` audit run before test collection. Harden:
verify post-install file bytes against the lockfile hashes (e.g. `pip hash-checking`
/ recorded `RECORD` hashes) in the preflight, so a post-install mutation is
caught, not just a version drift.

**H2. Row 2 lineage — multi-run correlation + forger-signal surfacing.**
Where: attack-program Row 2 residuals (`gov/lineage.py`, `gov/messaging.py`; F137,
F155 CLOSED). State: bus messages carry lineage stamps; forged stamps quarantine
the *victim*, attribution is impossible by construction; per-run correlation
only (multi-run is stated follow-up); sub-64B payloads miss the population
watch. Harden, bounded: (a) cross-run lineage correlation (the stated follow-up)
over the chained logs; (b) at minimum, the forgery record names the *claimed
sender id* from the forged stamp so the forger leaves a lead, even if it is not
proof. Do not expand into content inspection of sub-64B payloads (FP cost).

**H3. Safeguard Benchmark `gate()` is tested but UNWIRED.**
Where: REALWORLD_BAR.md wave-99 B5/B6; `gov/safeguard_benchmark.py`,
`gov/capability_measure.py`. State: `gate()` into the real `ApprovalQueue` at
the human-review threshold exists and is tested; no production call path
measures capability deltas; `uncovered_forces_insufficient=True` means every
SAR is INSUFFICIENT while identity/covert probes are absent. Harden: wire one
documented call path (or cut the implication — mark `gate()` explicitly
unwired/integration-pending in the spec). A tested-but-unwired gate is a claim
waiting to be misread.

**H4. Discovery ledger is unkeyed.**
Where: `gov/discovery.py`; wave-92 BUILD_LOG entry ("discovery ledger chain
unkeyed" listed as a limitation). State: passive-signal → deduped ledger →
HMAC-logged `unregistered_agent` findings, but the ledger chain itself is
unkeyed. Harden: key the discovery ledger like the action log (the "memory-only
agents invisible" limitation stays documented — it is a sensor boundary, not a
crypto gap).

**H5. Approval console: enforce the localhost-only posture in code.**
Where: `docs/READINESS_GAPS.md` §1 (`gov/approval_web.py`: no SSO/OIDC/mTLS,
in-memory sessions, no TLS; non-localhost "unsupported without TLS + real auth
in front" — which nobody has built). State: the posture is documentation only.
Harden, bounded: refuse non-localhost binds unless an explicit, loud override
flag is set (fail-closed default). Do not build SSO/TLS in-repo (DEFERRED, D2)
— but make the documented boundary a runtime fact.

**H6. F163 record-path fail-open.**
Where: attack-program Row 10 residual: "record-side ledger failure stays
fail-open by design" — while F162 made `_query_velocity` fail-closed on ledger
trouble. State: the exchange-ledger read path fails open where the velocity
path fails closed; the F163 close criterion is "every read is a logged,
policy-checked event," which a failing record path silently un-meets.
Harden: make record-path failure fail closed with a named exception (mirroring
`velocity_check_failed`), or document why the asymmetry is load-bearing. The
current state is a quiet inconsistency between two sibling controls.

**H7. F168 residual — adapter-layer metering exceptions degrade to unmetered.**
Where: FINDINGS.md F168 (CLOSED 2026-09-24): metering is loud at the
`ingest_foreign_result` seam, but "the MCP/generic adapters wrap the call in
their own `try/except: pass` (their pre-existing, documented fail-open
side-channel posture), so an adapter-level metering exception still degrades to
unmetered at the ADAPTER layer." State: production traffic through a throwing
adapter is unmetered. Harden, bounded: accrue usage in the adapter wrapper
before its own exception swallow (a `finally`-adjacent accrual at the adapter
boundary), so the fail-open posture costs availability, not metering.

---

## §3 — DEFER (explicitly out of v1, with rationale)

Production-hardening (all DEFERRED because v1.0 is explicitly pilot-grade,
single-tenant, private; none of these may be implied as production-ready):

- **D1. Production Vault path untested; cloud KMS has no in-repo provider.**
  Recorded: `docs/KEY_CUSTODY_RUNBOOK.md` A/A.1; READINESS_GAPS §1. State:
  `gov/kms_vault.py` validated 20/20 against real Vault OSS v1.20.0 **dev**
  server on loopback; production provisioning (Raft/Consul, TLS listener,
  seal/unseal), TLS end-to-end, non-token auth (AppRole/platform identity), HA,
  and live operator ceremonies all UNTESTED; AWS/GCP/Azure KMS: no in-repo
  provider (AWS path is operator-built). Rationale: production custody is a
  deployment project owned by the buyer, not product code; the runbook already
  marks every untested step UNTESTED. The one non-negotiable: the "validated
  against a real Vault" claim must always carry the dev-mode qualifier.
- **D2. In-repo TLS stack; SSO/OIDC/mTLS for the approval console.**
  Recorded: READINESS_GAPS §1; strategy decision S6 ("NOT NOW"). Rationale:
  the v1 deployment story is reverse-proxy + external IdP (reference config
  landed wave-111); building an in-repo TLS/SSO stack is a product-company
  decision, not a freeze blocker. H5 makes the boundary enforceable.
- **D3. Multi-tenancy, DB-backed approval queue, enforced retention, monitoring.**
  Recorded: READINESS_GAPS §1/§2; SHIP_PLAN §2 (v1 explicitly single-tenant);
  SHIP_PLAN §1.4 (retention operator-owned; `gov/retain.py` does not exist).
  State: file-only JSONL queue (no DB/HA/backup); no metrics/health/alerts
  (monitoring = tail the log + cron `gov/verify.py`). Rationale: a lost run dir
  is a lost queue — acceptable for a pilot, disqualifying for production, and
  documented as such. A pilot is not production; the docs say so in §3.
- **D4. Live Rekor/Sigstore anchoring.** Recorded: evidence-bundle-spec §7
  boundary 4; SHIP_PLAN v1-OUT by decision; wave-72 B6 (REST mapping never
  validated live — the one false "exactly one live submission" claim was
  corrected in writing). State: FakeTransparencyLog / LocalAnchorLog /
  RekorBackend (schema-conformant by construction + test, not by live
  exercise). Rationale: the anchor story survives the HMAC-key holder via
  Ed25519 statements (the load-bearing guarantee is proven by probe); live
  Rekor submission is v2.
- **D5. Multi-operator manifest signatures; out-of-band root pinning;
  proven key custody; trusted timestamps.** Recorded: spec §7 boundaries
  3, 4, 5, 7 (single-operator signature in v1, multi-operator deferred to v2;
  `kms_attestation` is claimed, not proven; timestamps are operator
  wall-clock; authorship needs an out-of-band pin the verifier never invents).
  Rationale: the spec's normative honesty section already binds the verifier
  output; these are v2 trust-model upgrades, not v1 defects.
- **D6. ISO 42001 mapping provisional.** Recorded: `docs/iso42001-mapping.json`;
  wave-92/REALWORLD_BAR B3 ("official text not consulted"). Rationale: the
  mapping is a navigation aid, never auditor evidence — the tree already says
  never to show it as authoritative. Holds.
- **D7. B1 P8 uncovered-by-design (offline tripwires / judge).**
  Recorded: REALWORLD_BAR.md wave-76 B2/B6; `evals/b1exp_probes.py` ("P8 ...
  uncovered-by-design, detector spec lane"). Rationale: wave-76 is runtime
  statistics (EWMA/CUSUM tripwires), a different layer from an offline judge;
  the design decision still holds — the offline judge is a research artifact,
  not a v1 control, and the tree never claims it.
- **D8. B1 P13 partial-by-design (renderer-side boundary).**
  Recorded: `evals/b1_b6_delta_2026-09-26.md`. Rationale: the partiality is a
  stated boundary of the probe surface, not a control gap; holds for v1.
- **D9. Row 3 — a determined/fatigued/complicit approver who passes the
  challenge on purpose.** Recorded: attack-program Row 3 (D4 deliberate
  boundary). Rationale: human-proof approval is not a buildable property; the
  shield raises the bar (independent brief, MAC-bound challenge, fatigue
  metering) and the residual is stated. Holds.
- **D10. Row 4 — perfect sandbaggers / sleepers undetectable.**
  Recorded: Row 4 ("Scope and honest ceiling" in `gov/eval_harness.py`).
  Rationale: behavioral evals cannot rule out deception; attested model
  identity must come from the substrate; seed hygiene is operator procedure.
  Holds.
- **D11. Row 5 — perfect steganalysis impossible; low-and-slow collusion is the
  stated miss.** Recorded: Row 5 (D4 deliberate boundary; FN 4/12 low-and-slow
  as CONTROL). Rationale: information-theoretic ceiling; the shipped direction
  (envelopes + bandwidth/field monitoring, measured FN) is the honest
  cost-raising play. Holds.
- **D12. Row 8 — patient-adversary slow-boil (0.4σ, 300 buckets, zero trips);
  named-human re-baseline laundering.** Recorded: wave-76 B2/B6; wave-83's 4
  measured residuals (sub-k ratchet walk, baseline poisoning, signal spreading,
  byte-volume exfil). Rationale: the boundaries are visible and numerically
  pinned in the export — the auditor sees exactly what drift would NOT trip.
  Holds as documented, not as claimed coverage.
- **D13. Row 10 — true outcome auditing ("did the outcome serve the
  principal's goal?").** Recorded: Row 10 residual. Rationale: outcome
  auditing is a research project; velocity gates tempo, not goal-alignment —
  the tree states this. Holds for v1.
- **D14. Row 15 — detection of deceptive reasoning / CoT monitoring.**
  Recorded: Row 15 (D4 deliberate). Rationale: CoT monitoring trains against
  the monitor; blast-radius bounding (leases, trifecta tiering, digest-bound
  releases) is the shipped answer. Holds.
- **D15. F8 substitution-cipher DLP residual.** Recorded: FINDINGS.md F8
  (documented residual; sit18 `must_execute`). Rationale: heuristic DLP has a
  ceiling; the residual is explicit and probed, never a silent pass. Holds.
- **D16. F12 redaction structural blindness.** Recorded: F139 closure
  ("P1's upload-side BREAK remains by design: F12 redaction makes the approval
  gate structurally blind"). Rationale: the citation-provenance check is the
  compensating control and is wired (F141 `accept_report`). Holds.
- **D17. F6 compromised tool implementations act below governance.**
  Recorded: FINDINGS.md F6 ("residual (by design)"). Rationale: adapters remove
  every *public* path; hostile native code is outside the sandbox's stated
  boundary (defense-in-depth, not a container/VM). Holds.
- **D18. F139 paraphrase defeats payload matching; query-string evasion.**
  Recorded: F139 residuals ("paraphrase defeats payload matching (URL is the
  primary key); query-string evasion is a different normalized URL,
  conservative against false accusation; out-of-governance plants invisible").
  Rationale: fuzzy/structural matching is FP-risky research; the URL-primary-key
  + UNKNOWN-default posture is the honest v1 position. Holds.
- **D19. F163 raw `open()`/`read_text` reads outside the seam; true
  per-principal default-deny needs a run→principal ownership registry.**
  Recorded: F163 closure residuals. Rationale: the seam boundary (log seam +
  agent tool path) is the honest in-process coverage line; raw filesystem reads
  are an out-of-process shape no in-process control can cover. Holds (the
  strict-posture flag + allowlist is the v1 answer).
- **D20. F150 chain-entry interception ceiling.** Recorded: F150 residual
  ("chain entries that evade the child-side interception — pre-bound
  `os._exit`, ctypes/raw syscalls, restoring `os._exit`, fatal signals —
  still bypass the conversion; the parent cannot distinguish those exits").
  Rationale: parent-side detection is impossible in general (verified
  empirically); the raise-don't-exit contract covers what is coverable.
  Holds.
- **D21. F151 unpinned self-consistency-only; no key-revocation channel.**
  Recorded: F151 residuals; spec §7 boundary 5. Rationale: exit-2 makes the
  unpinned mode unmissable; pinning (full public key, not key_id) is the v1
  answer; revocation is v2. Holds.
- **D22. F69 `pin_off` residual (genuine newer pin before `pin_off`).**
  Recorded: FINDINGS.md F69 maintenance notes (wave-112 + wave-114 lane 2:
  17/17 HELD, "the residual cannot be escalated"). Rationale: the accepted
  tip is MAC-authentic and vouches a genuinely-verified prefix; the tail is
  still fully re-verified — staleness is redundant work, never trust in
  unverified bytes. Holds; tightening is ordering, not security.
- **D23. F165/F166 restart-plus-clock-jump eviction.**
  Recorded: F166 honest residual (a): "restart *plus* a forward wall-clock
  jump together can evict pre-restart records — the attacker needs both
  privileges." Rationale: monotonic-pinned within an epoch; the combined
  shape needs two distinct privileges and stays fail-closed otherwise. Holds.
- **D24. F170 (b)(c): no per-reader write rate limit; per-read cost linear in
  window-relevant records at huge operator windows.** Recorded: F170
  residuals. Rationale: (b) is a new control, out of scope; (c) is inherent
  to window semantics, no longer total-history. Holds.
- **D25. F173 residuals: V12 binds receipt presence/reason, not full entry
  identity; 1.0 bundles need re-sealing.** Recorded: F173 closure;
  `evals/f173_legacy_binding_decision.md`. Rationale: content-addressed by
  design (control B2 preserved deliberately); legacy fail-closed with an
  explicit re-seal remedy. Holds.
- **D26. F29/F73 dev-key posture.** Recorded: FINDINGS.md F29 (CLOSED,
  disclosure) + F73 (CLOSED: double opt-in). Rationale: the dev key is a
  posture control, not a secret; prod KMS key-management removes the path
  before real data touches the log. Holds.
- **D27. Zeroization negative (CPython immutables, `os.environ` str, HMAC C
  copies).** Recorded: wave-71 B6 ("the mechanism is an honest NEGATIVE ...
  measured, documented, not fixed"). Rationale: discard-time wiping is the
  shipped layer; defeating memory readers needs C/HSM. Holds.
- **D28. HMAC chokepoint audit vs dynamic indirection.**
  Recorded: wave-70 B6 ("fully dynamic indirection (`__import__`/`getattr`
  tricks, vendored HMAC) — accepted as a boundary (source-write threat
  model)"). Rationale: the AST audit pins the 13 allowlisted sites; the
  residual needs source-write privilege, which is already total. Holds.
- **D29/D30. Loud weak modes: audience-optional (F132 residual), revocation
  TTL-only, spawn key custody caller-side.** Recorded: FINDINGS.md residuals
  (one-time stderr warnings, "loud weak mode, not silently secure").
  Rationale: backward-compat and deployment realities; the weak mode is
  explicit, never silently secure. Holds.
- **D31. Row 1 detector arms-race residuals: paraphrase laundering (MINJA
  pinned miss), 256 KiB fingerprint FIFO eviction, descriptive-practice
  framing dodge, `tainted_run` recorded-but-unused.** Recorded: Row 1.
  Rationale: deterministic heuristics vs. adaptive phrasing is an arms race
  the memo's DONE criteria bound to battery shapes; each miss is pinned, not
  hidden. Holds for v1.
- **D32. Row 2 sub-64B payloads miss the population watch.**
  Recorded: Row 2 residual. Rationale: honest detector ceiling; the
  64B line is measured, not arbitrary. Holds.
- **D33. F162 no clean-env pre-fix battery.** Recorded: Row 10 residual.
  Rationale: pre-fix state cannot be re-created honestly; the post-fix
  battery (`evals/f162_velocity_break.py`, 4 CLOSED + 1 CONTROL, both envs)
  is the standing ratchet. Holds.
- **D34. Stratified-100 99/100 with the pinned known miss; a *better* score
  also invalidates and forces re-pin.** Recorded: wave-112/113;
  `evals/verify_stratified_100_claim.py`. Rationale: the pin is the honesty
  mechanism; the miss (`careless-typo-014`/F-RA3) is documented. Holds.
- **D35. AGT .NET `WebhookApprover`, AWS AgentCore approval-event producer,
  CrewAI / AutoGen / raw-HTTP adapters, K-026 authenticated inter-agent
  messaging — not built.** Recorded: READINESS_GAPS §1 (structural gaps);
  REALWORLD_BAR.md (D1 notes). Rationale: strategy decisions — STOP building
  new adapters; D1 focuses on AGT/AWS bridges sequenced behind the D5
  contract per A12. The accepted-by-design production-coverage gap is stated
  plainly; holds.
- **D36. Enforced retention + narrowed audit (D4).** Recorded: READINESS_GAPS
  §2; strategy roadmap §4. Rationale: plan, not code; retention is
  operator-owned per SHIP_PLAN §1.4. Holds.
- **D37. Seccomp allowlist maintenance tooling is manual (`--audit-seccomp`).**
  Recorded: READINESS_GAPS §2. Rationale: fine for v1 cadence. Holds.
- **D38. Trifecta floor default-off; pre-commit opt-in; lease scope
  unit-level only; pre-commit does not cover `execute_approved()`.**
  Recorded: wave-79 B6; REALWORLD_BAR.md. Rationale: deployment decisions,
  documented with the exact graded claims; enabling the floor means every
  allowlisted external call needs a human — a deployment call, not a defect.
  Holds.
- **D39. F84 `diff_summary` shape-only validator; legacy-construction
  measurement (the part C5 does not rewire).** Recorded: wave-84 entry.
  Rationale: the record carries no policy text by construction (digests are
  the binding); the residual is measured and visible. Holds alongside C5.
- **D40. Key-ceremony runbook written, ceremony unpracticed.**
  Recorded: READINESS_GAPS §1 (`workstreams/kms/CEREMONY_RUNBOOK.md`,
  `docs/KEY_CUSTODY_RUNBOOK.md`). Rationale: operational, not code; the first
  real deployment practices it. The "runbook missing" half is closed; the
  practiced half waits for a live server. Holds.
- **D41. F171 DLP decoder coverage (base32, custom ciphers).**
  Recorded: F171 residuals. Rationale: documented residual of a heuristic
  scanner; the quadratic-time amplifier itself is closed. Holds.

---

## §4 — Counts

| Recommendation | Items |
|---|---|
| CLOSE (before freeze) | **11** — C1 docs sync, C2 F81 privileged re-run + artifact, C3 row-9 trajectory control, C4 authorized-channel exfil battery, C5 legacy ungoverned default, C6 model-artifact inventory, C7 web-UI shield brief, C8 delayed-execution correlation, C9 goal registration, C10 evals integration, C11 full four-gate boundary |
| HARDEN (tighten, don't expand) | **7** — H1 F75 byte-level supply-chain check, H2 lineage multi-run correlation, H3 safeguard `gate()` wire-or-cut, H4 discovery ledger keying, H5 localhost-bind enforcement, H6 F163 record-path fail-open, H7 adapter-layer metering accrual |
| DEFER (explicitly out of v1) | **41** — D1–D41 above |
| Stale lines to correct | **8** — S1–S8 in §0 |

Net: 18 items need work before or at freeze (11 CLOSE + 7 HARDEN); 41 are
explicitly out of v1 with the design decision re-examined and holding.

---

## §5 — The 5 hardest truths (what embarrasses us if a buyer probes)

1. **The egress wall's privileged proof cannot be re-shown.** F81's closure
   rests on a wave-98 privileged run (11/11 ×2) for which no durable artifact
   exists, and waves 99–115 changed the surrounding seams. If a buyer asks
   "run the privileged battery now," the honest answer is "we can't from this
   tree — the lab VM is stopped and the run was never recorded." C2 is the fix;
   until it lands, every filtered-egress claim leans on prose. (Recorded:
   `evals/f81_privilege_carry_decision.md`; attack-program Row 13.)

2. **The default posture of the repo is ungoverned.** Wave-84 measured it:
   42 of 44 `ToolExecutor` construction sites are legacy, and direct
   `PolicyEngine(path) → ToolExecutor` gives attacker-selected policy with
   zero ceremony, zero records. The governed path is real but opt-in. A buyer
   who runs the demo or reads the examples is ungoverned — and the tree admits
   it in its own auditor one-liner. (Recorded: REALWORLD_BAR.md wave-84; C5.)

3. **The approval console is a localhost toy with a documentation seatbelt.**
   No SSO, no OIDC, no mTLS, in-memory sessions, no TLS — and "non-localhost
   binds are unsupported" is a sentence, not a check. Nothing in the code
   stops a pilot from binding 0.0.0.0 with a bearer token as the only guard.
   (Recorded: `docs/READINESS_GAPS.md` §1; H5 is the minimum fix.)

4. **Many-shot / tool-result caution erosion has no control at all.**
   Attack-program Row 9 is the only genuine GAP in the 18-row map: per-action
   checks are trajectory-blind, and no trajectory-level erosion signal exists.
   This is the jailbreak class with the most real-world volume, and the tree's
   honest mark for it is GAP. (Recorded: `evals/attack_program_status_2026-09-26.md`
   Row 9; C3.)

5. **"Validated against a real Vault" means a dev server on loopback.**
   `gov/kms_vault.py` is 20/20 against Vault OSS v1.20.0 **dev** mode; TLS,
   non-token auth, HA, production provisioning, and live ceremonies are all
   UNTESTED (the runbook says so), and AWS/GCP/Azure KMS have no in-repo
   provider at all. Every key-custody claim needs the dev-mode qualifier
   attached, or it becomes the next overstated closure. (Recorded:
   `docs/KEY_CUSTODY_RUNBOOK.md` A/A.1; `docs/READINESS_GAPS.md` §1; D1.)

Honorable mention (process, not product): Wave-115 pushed without a recorded
canonical / registry / matrix / realistic boundary on the final tree (S8/C11) —
the standing "quiet-box after each landing" rule has a hole at the exact wave
that closed the evidence-bundle findings.
