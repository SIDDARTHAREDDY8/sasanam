# The Real-World Bar

**Version 1 — 2026-09-22 03:44 UTC.** This document operationalizes the mission: *the product genuinely fixes real-world AI governance problems.* It is the definition of done. Green unit tests are necessary but never sufficient. The loop never coasts: **every green gate triggers nastier situations.**

## The bar, in verifiable terms

- **B1 — Incident-class coverage.** Every one of the 14 attack patterns in `research/incident-case-study.md` (21 incidents) has ≥1 registered, deterministic registry situation **and** a passing close-out test demonstrating the control stops it. Evidence: a published coverage matrix plus gate results. A pattern with no situation is a gap; a situation with no passing close-out is a gap.
- **B2 — Realistic battery.** The 100-profile batch stays ≥99/100 (all 32 researcher negative controls green), swarm scenarios pass, and human-error scenarios pass — all inside the registered gate, not as standalone scripts.
- **B3 — Standards controls hold adversarially.** For every NIST AI RMF / OWASP LLM Top-10 / EU AI Act obligation we claim a control for, the control has an adversarial red-team situation that currently passes. Mapping matrix published. No control is claimed on unit tests alone.
- **B4 — Finding hygiene.** No open HIGH/CRITICAL findings. Open MEDIUMs have fixes in flight or accepted-risk notes — and risk acceptance is the user's call, never ours.
- **B5 — Pressure ratchets.** Every green gate run produces a nastier follow-up wave aimed at the weakest classes. The red-team loop is never "done."
- **B6 — Honest readiness.** Deployment guide, readiness gaps, and a plain statement of what this is not — kept current. Market release happens only on the user's explicit decision.

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
