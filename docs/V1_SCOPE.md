# v1.0 Scope — agent-governance-layer

**Date:** 2026-09-26 (Wave-116, Lane 2 — scoping only, no product changes)
**Target:** private v1.0 tag on 2026-10-31; feature freeze 2026-10-21
**Strategy:** "sell evidence, not the engine" (founder-strategy memo 2026-09-22;
`workstreams/architect/STRATEGY_ROADMAP.md`). The repo stays **private**; nothing
ships publicly without the user's explicit say-so (standing order).
**Release shape:** SHIP_PLAN §4 Option A (private v1.0) stands unless the user decides otherwise.

This document defines the v1 boundary in three parts: what is IN (the seven
governance parts, mapped to the tree as it exists), what is explicitly OUT
(deferred with rationale, substitute, and trigger — never silently dropped),
and the freeze criteria that must hold on 2026-10-21 for the freeze to be real.
It complements, not replaces, `workstreams/architect/SHIP_PLAN.md` §2 (v1 IN/OUT)
and `docs/READINESS_GAPS.md` (honest distance). Where this document and the tree
disagree, the tree wins and this document gets corrected.

Open findings at scope time: **none** (`evals/FINDINGS.md` tail). Next free: **F175**.
F81 has been CLOSED since wave-98 (2026-09-24) via genuine privileged validation;
it is not re-litigated here — its *residual* (no re-verifiable artifact on today's
tree) is carried as an accepted residual per `evals/f81_privilege_carry_decision.md`.

---

## 1. v1 feature set — IN: the seven governance parts

Each part names the concrete modules that ship in v1 and an honest maturity note.
Maturity legend: **proven** = battery-tested against adversarial batteries and
re-verified by the registry/matrix gates; **mechanically sound** = implemented,
tested, but never adversarially battery-tested; **documented boundary** = the
limitation is written down in code/spec, not hidden.

### Part 1 — Rules (policy engine)

- `gov/policy.py` (fail-closed YAML policy engine), `policies/default.yaml`,
  `gov/dsl.py`, `gov/policy_lint.py`, `gov/rules_tiering.py` (lethal-trifecta
  tiering, opt-in by deployment decision), `gov/precommit.py` (preview →
  digest-bound single-use human approval → atomic commit for the irreversible
  registry), `gov/policy_export.py` (Cedar export, fail-closed on lossy
  mappings — F88).
- **Maturity: proven.** Total decision records (`policy_version` + `matched_rules`,
  validator-refused when absent) landed wave-79; the adversarial matrix
  (3216/3216 SHIP-GATE GREEN) exercises policy semantics continuously.
- Honest note: `rules_tiering`'s trifecta floor is off by default (opt-in);
  Cedar export is portability story, not the engine.

### Part 2 — Enforcement

- `gov/executor.py` (the governed execution choke point; budgets/metering via
  `gov/velocity.py`, `gov/exchange_ledger.py`), `gov/sandbox.py` (contained
  subprocess backend — **defense-in-depth, not a VM boundary**),
  `gov/egress_launcher.py` (NetnsWallProvider + pinned seccomp; filtered-egress
  cage mode), `gov/egress_proxy.py`, `gov/capability_gate.py`,
  `gov/capability_leases.py`, `gov/output_filter.py`, `gov/dlp.py`
  (linear-time PII scrub — F171), `gov/sterile.py` (temporal input quarantine),
  `gov/citation_provenance.py` (evaluator citation poisoning control — F139–F142),
  `gov/eval_integrity.py`.
- **Maturity: proven on the choke point; bounded on the wall.** The executor
  and queue semantics are battery-tested (rows 16–18 of the attack program:
  COVERED, re-verified 2026-09-26). The filtered-egress wall was lab-validated
  (wave-23, 17 STOPPED / 0 BREAK across 11 classes) and privileged-battery
  validated (wave-98, 11/11 ×2) — but the wave-98 run has **no durable artifact
  in the tree**; carried as accepted residual, not as a re-verifiable claim.
- Honest note: the MCP/generic adapters' fail-open side-channel posture is
  documented and deliberate (see F168 residual); foreign metering covers the
  result blob only.

### Part 3 — Proof (audit log + evidence)

- `gov/log.py` (HMAC hash-chained audit log), `gov/ed25519.py`,
  `gov/merkle.py`, `gov/anchor.py` + `gov/anchorer.py` (anchoring substrate;
  **FakeTransparencyLog in v1** — live Rekor deferred), `gov/verify.py`,
  `gov/evidence_bundle.py` (bundle format **1.1**), `gov/evidence_verify.py` +
  `tools/evidence-verify` (byte-identical, drift-guarded by test),
  `docs/evidence-bundle-spec.md` (normative §4.3 V1–V13 + V14; §7 honest
  boundaries), `gov/evidence_exports.py` (auditor-readable exports; the
  ISO 42001 mapping is **provisional — never to be shown to an auditor as
  authoritative**), `evals/verify_stratified_100_claim.py` +
  `evals/stratified_100_claim.json` (pinned 99/100 claim, fail-closed re-pin).
- **Maturity: proven.** Normative tamper battery T1–T10: 14 CAUGHT / 15
  controls / **MISS=0** (re-verified 2026-09-26); adversarial battery 9 CAUGHT /
  0 BREAK (wave-114/115; found and closed F173/F174 — the batteries are doing
  their job). Signature domain `evidence-bundle/v2`; bundle proves authenticity
  of *included* entries (K-060 honest scope — **not completeness** against a
  misbehaving exporter).
- Honest note: key custody is *claimed* via `kms_attestation`, not
  cryptographically proven; timestamps are operator wall-clock (no TSA, no
  external anchor); **threshold root trust is single-operator manifest**
  (multi-operator deferred to v2); authorship requires an out-of-band key pin
  the verifier never invents.

### Part 4 — Identity

- `gov/identity.py` (every action attributed), `gov/agent_identity.py`,
  `gov/delegation_tokens.py` (three-token delegation + spawn lineage, audience
  binding, revocation-at-the-gate — F132/F133/F135 CLOSED),
  `gov/adapters/trust.py`, `gov/credential_manifest.py`.
- **Maturity: proven.** Delegation-abuse row of the attack program: COVERED,
  re-verified 2026-09-26 by the registry gate.
- Honest note: no authenticated inter-agent (peer-to-peer) messaging primitive
  (K-026, structural gap); queue-mediated delegation is the covered shape.

### Part 5 — Detection

- `gov/detection.py` (EWMA + CUSUM behavioral circuit breakers, read-only over
  the chained audit stream; trips wire into enforcement fail-closed),
  `gov/monitor/` (tripwires, infection watch, judge), `gov/canary.py` (egress
  canaries — deception as exfiltration control), `gov/memory_provenance.py`
  (per-entry source-trust ledger; GAP-1), `gov/lineage.py` + `gov/messaging.py`
  (infection-lineage; GAP-2), `gov/covert_channel.py`, `gov/discovery.py`
  (passive unknown-agent discovery — STREAM-A), `gov/skill_watch.py`
  (continuous skill/MCP supply-chain verification).
- **Maturity: mechanically sound on the circuits; PARTIAL on the adversaries.**
  Attack-program rows 1–8, 10–15 are PARTIAL: detectors are deterministic
  heuristics that hold for the battery's shapes, not for arbitrary adversaries
  (e.g. memory poisoning vs paraphrase laundering; infection watch vs
  sub-64B payloads). **Row 9 (tool-result caution erosion / many-shot) is an
  unchanged genuine GAP — no control built** (see §2).
- Honest note: the B1 count stands at 14/16 (P13 partial-by-design, P8
  uncovered-by-design); detection is an arms race, not a wall — stated in the
  module docstring, not marketed away.

### Part 6 — Response / recovery

- `gov/recovery.py` (checkpoint → verify → resume-or-halt, plus decommission;
  doctrine: resume NEVER reuses the halted session's authority; halt key in a
  separate MAC domain from the journal key), `gov/approvals.py` (human approval
  queue — the response choke point), `gov/approval_web.py` (console;
  **localhost-grade**: no SSO/OIDC/mTLS, in-memory sessions, no TLS — non-localhost
  binds explicitly unsupported without TLS + real auth in front),
  `gov/approver_shield.py` (independent brief, persuasion scoring, capture-tier
  challenge handshake, fatigue metering — GAP-3), `gov/zeroize.py` (key
  zeroization).
- **Maturity: mechanically sound.** Recovery builds on the F70 closure (R18,
  wave-23); approval replay/deception is COVERED (row 16, re-verified).
- Honest note: the approval console's transport/auth posture is the weakest
  v1 seam — mitigated by the localhost-grade scoping decision and the documented
  reverse-proxy + external-IdP pattern (see §2 OUT), but the operator must own it.

### Part 7 — Governing the governors (meta-governance)

- `gov/policy_change.py` (wave-75: policy changes as chained governed events;
  author identity via Ed25519 roster keys; **the nuclear rule** — `production`
  changes require two *distinct* roster human keys, enforced in code, never in
  policy text), `gov/release_approval.py` (quorum-gated release ceremony on the
  existing approval queue; digest binding release bits → evidence → human
  decision — F153), `gov/precommit.py`, and the standing **red-first post-wave
  closure audit** (2026-09-25 user order: every claimed closure re-verified
  break-first at the public seams before any push; overstatements re-filed as
  findings, never quietly patched).
- **Maturity: proven.** The policy-change seam (through which every other part
  could be silently defeated) is mechanically closed and registry-gated.
- Honest note: the nuclear rule's enforcement assumes key custody it does not
  itself provide — which is exactly why key custody is the standing #1
  production priority (see §2 OUT).

---

## 2. Explicitly OUT for v1 (deferred with rationale, substitute, trigger)

Each item states: why deferred, the v1 substitute, and what would trigger
building it. All are v2 candidates; "new nastier situations" that would expand
scope are recorded as v2 candidates in `evals/FINDINGS.md`, not built (B5 cap,
SHIP_PLAN §2).

| # | OUT item | Why deferred | v1 substitute | Trigger to build |
|---|----------|--------------|---------------|------------------|
| O1 | Cloud KMS providers (AWS/GCP/Azure) — no in-repo implementations | Standing priority order: Vault adapter first, then cloud only if Vault insufficient; no cloud-KMS spike done | `gov/kms_vault.py` validated vs real Vault OSS v1.20.0 dev server (20/20 live checks) + key-provider interface so the source swaps without touching the rest; AWS path documented as operator-built in `docs/KEY_CUSTODY_RUNBOOK.md` | First pilot/production deployment that requires cloud-managed custody; or Vault spike formally judged insufficient |
| O2 | Vault production hardening: TLS end-to-end, non-token auth (AppRole/platform identity), HA, practiced live key ceremonies | All marked UNTESTED (`docs/KEY_CUSTODY_RUNBOOK.md` A.1); ceremony work is deployment-project, not product-code | Written ceremony runbook (wave-26) + KEY_CUSTODY_RUNBOOK; dev-mode validation | Production deployment with real secrets |
| O3 | In-repo end-to-end TLS | TLS stack is a product in itself; the honest story is the proxy pattern | Reverse-proxy reference config (`docs/DEPLOYMENT_TLS_REFERENCE.md`); explicit "no in-repo TLS" statement | Pilot requiring direct in-repo TLS |
| O4 | Live Rekor/Sigstore anchoring | Production dependency does not exist locally; claiming it would be theater (SHIP_PLAN §2) | `FakeTransparencyLog` seam documented; evidence-bundle spec §7 boundary 4; hash-chained + checkpointed logs | Auditor or deployment requiring an external transparency anchor |
| O5 | Multi-operator manifest signing / out-of-band threshold-root pinning | Design exists (spec §4.2); single-operator is the smallest honest v1 root | Single-operator manifest signature; authorship requires an out-of-band key pin the verifier never invents (spec §7 boundary 5) | Governance requiring multi-signer root trust |
| O6 | SSO/OIDC for the approval console; multi-tenancy | 37-day build budget; tenancy isolation is a second product (SHIP_PLAN §2) | Reverse-proxy + external-IdP pattern documented; written single-tenant scoping decision (`docs/SINGLE_TENANT_SCOPE.md`); approval console explicitly localhost-grade | Enterprise pilot with IdP / multi-tenant requirements |
| O7 | Row-9 tool-result caution erosion control (trajectory-level many-shot erosion signal) | Genuinely unbuilt GAP (not on the D4 deliberately-not-proposed list); Lane 1 to confirm whether buildable in the window | Nothing — per-action checks remain trajectory-blind; the gap is stated in `evals/attack_program_status_2026-09-26.md`, not hidden | Explicit user order + a funded, spec-first lane; do NOT build quietly |
| O8 | D1 bridges beyond Python: AGT .NET `WebhookApprover`, AWS AgentCore approval-event producer; CrewAI/AutoGen/raw-HTTP adapters | Strategy decision: STOP building new adapters (REALWORLD_BAR.md structural gaps — accepted by design) | Python AGT shim (`gov/bridges/agt.py`) only; D1–D5 strategy positions the product as the approval queue + enforcement-testing layer that *plugs into* AGT/AgentCore | Concrete demand from .NET/CrewAI/AutoGen shops, sequenced behind the D5 contract per A12 |
| O9 | Metered commercial pipeline | Founder strategy: year-two business; "metered nothing, sell nothing" for now | v1 meters nothing (spend/token metering exists in-engine for budgets — `gov/velocity.py` — but no commercial pipeline) | Year-two revenue motion |
| O10 | Enforced retention (`gov/retain.py` does not exist) | Strategy D4 is a plan, not code; Microsoft's AGT `retention_days` is declaration-only too (not a differentiator) | Retention is the operator's backup script; documented honestly | Pilot with retention/compliance obligations |
| O11 | Monitoring/alerting pipeline | Operator-owned; not a product seam | Operator tails the action log; cron-runs `gov/verify.py` | First pilot needing alerting |
| O12 | Open-core release | Costs: license scrub, secrets audit, public README, community surface — pushes the date or shrinks scope (SHIP_PLAN §4) | Option A: private v1.0 tag, wheel distributed to design partners directly | User decision, revisited at v2 with a real funnel to measure |
| O13 | Authenticated peer-to-peer inter-agent messaging (K-026) | D1-core delegation invariants assume queue-mediated delegation | `gov/adapters/trust.py` inter-agent trust sans message authentication | A deployment whose agent topology requires peer messaging |

Non-negotiable: repo stays private until the user declares market readiness
(standing order); no certifications (SOC 2 / ISO 42001 / EU AI Act pack /
pen test / SLA) are claimed or implied — anyone evaluating v1 for production
starts from `docs/READINESS_GAPS.md` §1, not from the test count.

---

## 3. Freeze criteria — must ALL be true on 2026-10-21

The freeze is a state, not a date. If any item fails, the freeze slips (and the
10-29 → 10-31 buffer absorbs it); the quality bar is the law, the date is the target.

1. **Four gates green on a clean push clone** (workstream symlinks per
   `~/AGENTS.md` lessons; gate TMPDIRs `mkdir -p`'d — Python 3.12 silently
   falls back to `/tmp` otherwise): canonical suite OK, registry gate
   **GREEN** (all 15 break-by-design residuals still breaking where expected),
   adversary matrix **3216/3216 SHIP-GATE GREEN**, realistic battery **4/4**.
   All gates run under `~/workspace/.gov-venv` (the F75 supply-chain preflight
   fails closed on the system python).
2. **Zero open findings** — or, for any finding still open, an explicit
   accepted-with-residual note in `evals/FINDINGS.md` with a carry-decision
   file (the F81 pattern: `evals/f81_privilege_carry_decision.md`), stating
   the exact residual risk and the re-run conditions. "Open with a plan to
   fix" does not satisfy this item; only closed or accepted-residual.
3. **Four documents synchronized** — `BUILD_LOG.md`, `evals/FINDINGS.md`,
   `docs/READINESS_GAPS.md`, `workstreams/architect/REALWORLD_BAR.md` — no
   document more than one wave stale on facts (the wave-112 B6 doc gap taught
   this: the bar cannot see the product if the paperwork is 30+ waves behind).
4. **Evidence artifacts current:** `evals/stratified_100_claim.json` pin +
   `evals/verify_stratified_100_claim.py` fail-closed verifier green (re-pin on
   any battery drift — a *better* score also invalidates); evidence-bundle
   spec current with the tree (bundle 1.1 / signature domain
   `evidence-bundle/v2`); normative tamper battery (spec §5 T1–T10) and the
   adversarial evidence battery green with MISS=0 / BREAK=0.
5. **No new features after 10-21 — break-fix only.** The B5 cap holds through
   v1.0 tagging: new "nastier situations" are recorded as v2 candidates in
   `evals/FINDINGS.md`, not built. Finding closures, regressions, and
   hardening of shipped surfaces only.
6. **No unresolved red-first post-wave audit items.** Every wave between now
   and 10-21 gets its standing red-first post-wave closure audit (break-first
   re-verification at the public seams; overstatements re-filed as findings);
   the last audit before 10-21 must be GO.
7. **Risk acceptance is explicit.** Any MEDIUM+ finding closed by
   accepted-residual (not by fix) is accepted-risk-noted by the user per
   SHIP_PLAN §3 W4; no finding is quietly carried.

Freeze-day verification procedure: run the four gates from a fresh clone in
this order (canonical → registry → matrix → realistic), then read the
`evals/FINDINGS.md` tail, then diff the four synchronized documents against the
tree. Red halts the freeze.

---

## 4. The wedge vs the infrastructure ("sell evidence, not the engine")

The strategy memo's bet: open-source the enforcement core as the funnel, charge
for the metered evidence pipeline (auditor-readable exports, retention,
attestation reports). v1 ships the wedge's first artifact, not the revenue:

**The wedge (product):**
- `gov/evidence_bundle.py` + `gov/evidence_verify.py` + `tools/evidence-verify`
  — one signed, timestamped, auditor-readable export bundle per run (decisions +
  approvals + retention manifest); third-party-verifiable with zero product
  code (the standalone verifier).
- `gov/evidence_exports.py` — export formats incl. the *provisional* ISO 42001
  mapping (honest scope: the mapping is not authoritative auditor material).
- `docs/evidence-bundle-spec.md` — the normative spec; V1–V14 and the §7
  boundaries are the wedge's contract with its first auditor conversation.
- `evals/verify_stratified_100_claim.py` + `evals/stratified_100_claim.json` —
  pinned, re-verifiable claims (a claim that can't be re-verified isn't evidence).
- Export only in v1: **no managed service, no auditor blessing claimed** (SHIP_PLAN §2).

**Sustaining infrastructure (the engine):**
- Parts 1, 2, 4, 5, 6, 7 as mapped in §1 — policy engine, executor, sandbox,
  identity, detection, recovery, meta-governance. They run the B5-capped
  sustaining loop (regressions, finding closures, hardening of shipped surfaces)
  and, critically, they *generate the exhaust* the wedge sells: every
  enforcement decision, approval, and trip is a chained record the bundle
  packages.
- The funnel/open-core decision is O12 (OUT for v1): the engine stays private
  until v2's funnel is real.

**v1 honesty boundary for the wedge:** the bundle proves authenticity of
*included* entries, not completeness against a misbehaving exporter (K-060);
single-operator manifest root; key custody claimed not proven; wall-clock
timestamps; test-double anchor. These are spec §7 normative boundaries, and any
pitch of the wedge that omits them is a misrepresentation of this product.

---

## 5. Freeze calendar

| Window | Dates | Mode |
|---|---|---|
| Hardening weeks | 2026-09-26 → 10-21 | Finish SHIP_PLAN §3 W2 (installable: wheel/sdist + 15-min quickstart + deployment-hardening minimum), hold W3's evidence surface (shipped waves 112–115; keep spec/tree/batteries in lockstep), W4 full adversarial re-run over the v1 boundary; any HIGH/CRITICAL blocks; MEDIUMs fixed or accepted-risk-noted. B5 cap: sustaining only. |
| **Feature freeze** | **2026-10-21** | Freeze criteria (§3) all true, verified by the freeze-day procedure. |
| Release candidate | 10-21 → 10-29 | **Break-fix only.** v1.0.0 tagged privately; install → quickstart → evidence bundle verified end-to-end from the tag; release notes + changelog written. |
| Slip buffer | 10-29 → 10-31 | Absorbs exactly one bad week. Unused if green. |

After v1.0 tags: the B5 cap lifts; v2 candidates recorded in `evals/FINDINGS.md`
become the planning input; Lane 1's scope inventory
(`evals/v1_scope_inventory_2026-09-26.md`) is the ledger of unfinished/partial/
deferred threads that v2 starts from.

---

*Wave-116 Lane 2 (scoping). No product code was changed for this document.
Standing rules observed: BUILD_LOG.md, evals/FINDINGS.md,
docs/READINESS_GAPS.md, workstreams/architect/REALWORLD_BAR.md unchanged by
this lane (document-only); $0 spend; synthetic/local only.*
