# Ship Plan — v1.0 by 2026-10-31

**Issued:** 2026-09-24. **Deadline:** 2026-10-31 (37 days). **Repo:** private,
`github.com/SIDDARTHAREDDY8/agent-governance-demo`, remote HEAD `49eea44`.
**Standing state:** zero open findings, next free F159, all gates green
(canonical 3470 OK, registry GREEN, matrix 3216/3216 SHIP-GATE GREEN,
realistic 4/4).

This plan converts the open-ended build–test–break loop into a bounded
release program. The loop does not stop — it gets a **cap**.

---

## 1. Honest gap analysis vs the real-world bar (B1–B6)

### What is genuinely shippable today

- **Enforcement core.** Policy engine, capability gate, approval queue
  (durable, restart-surviving), delegation/identity primitives, hash-chained
  audit log with checkpoints. Adversarially tested: 682/682 registry,
  3216/3216 matrix, 3470-test canonical suite, every finding closed with a
  break-first battery. This is the strongest part of the product and it is
  real.
- **Detection / response / recovery.** Circuit breakers, halt/resume under
  fresh authority, decommissioning — tested, documented, honest about the
  slow-boil boundary.
- **Supply-chain controls.** Digest-pinned artifacts, capability leases,
  skill watch with at-use re-verification, pinned dependency graph with
  hashes (`requirements.lock` + F75 preflight).
- **Evidence primitives.** `gov/safeguard_bundle.py` (deterministic bundle,
  authorship pinning), `gov/evidence_exports.py` (provisional ISO 42001
  mapping), provenance records, `demo/make_report.py`. The raw material for
  the "sell evidence" surface exists; the product surface does not.

### What is prototype-only (carried forward honestly)

1. **Production key custody.** `gov/kms_vault.py` (Vault transit adapter)
   validated against a fake transport only — real-server validation is
   Spike A, running now. No cloud-KMS provider (AWS/GCP/Azure) is built.
   The key ceremony runbook exists but the ceremony has never been run.
   Until Spike A lands, production custody = operator wiring, not a
   product claim.
2. **Deployment identity of the approval surface.** `gov/approval_web.py`
   is localhost-grade: no SSO/OIDC, no mTLS, in-memory sessions, no TLS.
   Non-localhost binds are "unsupported without TLS + real auth in front" —
   which nobody has built. Anyone holding the bearer token can approve.
3. **Queue/audit durability.** File-only JSONL in the run dir. Durable
   across restarts of one host; no database, no replication, no HA, no
   backup/restore story. A lost run dir is a lost queue and a lost log.
4. **Retention.** `gov/retain.py` does not exist. Retention is the
   operator's backup script. (Industry note: this is table stakes, not a
   differentiator — but a v1 without an enforced retention story cannot
   sell "evidence".)
5. **External anchoring.** Rekor/Sigstore anchoring is design-only;
   `gov/anchor.py` uses `FakeTransparencyLog`. Claims are tamper-evidence
   *within the tested architecture*, not externally anchored proof.
6. **Packaging.** `pyproject.toml` exists (0.2.0, entry points) but has
   never been installed from a built wheel. Spike B is validating this now.
   Known landmine: code assumes a sibling `workstreams/` layout.
7. **Operator docs.** `DEPLOYMENT.md`, `KEY_CUSTODY_RUNBOOK.md`,
   `SWARM_DEPLOYMENT.md` exist but are thin relative to a v1 install;
   no 15-minute quickstart exists. Spike B is writing one.
8. **Stale honesty docs.** `REALWORLD_BAR.md` has no wave assessment newer
   than wave-79 (2026-09-22); `docs/READINESS_GAPS.md` is wave-27.
   The B6 bar itself is behind the product. Refresh is W1 work.
9. **F69 timing flake.** `test_warm_tip_refused_sweep_bounded_at_20k`
   (150ms bound) flaked once under concurrent-suite load; green
   standalone. A ship gate cannot have a known-flaky test.
10. **B2 evidence gap.** The 100-profile battery artifacts are not in the
    working copy; "99/100 + 32/32" stands as recorded, not re-verified.
    Re-verify or re-record before v1 claims it.

### B1–B6 verdict for v1

- **B1** 14/16 (P13 partial-by-design, P8 uncovered-by-design): HOLD.
  No new incident classes for v1; coverage is a sustaining activity.
- **B2**: re-verify the 100-profile battery and record artifacts (W2).
- **B3**: STANDARDS_MAPPING.md exists; keep claims adversarially backed;
  no new standards work for v1.
- **B4**: zero open findings today; any HIGH/CRITICAL found in the ship
  window blocks the release. New MEDIUMs get fixed or accepted-risk notes
  (acceptance is the user's call).
- **B5**: **CAPPED for v1** (see §3). The "nastier situations" doctrine
  continues as sustaining break-fix, not as scope expansion.
- **B6**: refresh the bar + readiness docs (W1), then keep current.

---

## 2. v1 scope — IN / OUT

### IN

- **Packaged installable v1.0.** `pip install` from a built wheel/sdist;
  version pinned from `requirements.lock`; entry points smoke-tested
  outside the source tree. *Reason: nothing ships until it installs.*
- **15-minute quickstart + operator docs.** Install → governed run →
  evidence bundle, copy-pasteable; deployment guide covering the
  single-host reference deployment. *Reason: adoption starts at the
  quickstart; auditors start at the docs.*
- **Real KMS validation.** Spike A: Vault transit adapter against a real
  server + runbook; one cloud-KMS adapter only if Spike A reveals Vault
  is insufficient for the story. *Reason: key custody is the standing
  #1 production priority; a v1 that can't name its key custody is not
  shippable.*
- **Deployment hardening minimum.** A documented TLS story (reverse-proxy
  reference config, not a built TLS stack), an auth story for the
  approval surface (token hygiene minimum + explicit SSO-deferred note),
  and a written **single-tenant scoping decision**. *Reason: the smallest
  hardening that makes the deployment story honest.*
- **Evidence product surface (v1).** One signed, timestamped,
  auditor-readable export bundle (decisions + approvals + retention
  manifest) per the founder-strategy "sell evidence, not the engine"
  bet. Export only — no managed service, no auditor blessing claimed.
  *Reason: this is the only scope item that opens a budget line.*
- **F69 timing-flake hardening.** Bound the test or bound the load;
  the gate must be deterministic. *Reason: a flaky gate is a lying gate.*

### OUT (explicitly deferred to v2)

- **Multi-tenancy.** v1 is single-tenant by written decision. *Reason:
  tenancy isolation is a second product.*
- **Live Rekor/Sigstore anchoring.** v1 ships hash-chained + checkpointed
  logs with the FakeTransparencyLog seam documented; external anchoring
  is a v2 milestone. *Reason: design exists, production dependency does
  not; claiming it would be theater.*
- **Full SSO/OIDC for the approval console.** v1 documents the
  reverse-proxy + external-IdP pattern. *Reason: building an IdP
  integration in 37 days risks the whole date.*
- **Metered commercial pipeline.** Per the strategy memo, this is the
  year-two business. v1 meters nothing. *Reason: monetization infra is
  scope, not ship.*
- **New enforcement primitives / new incident classes.** The core is in
  sustaining/break-fix. *Reason: the date.*

### The B5 cap (doctrine change for the ship window)

Until v1.0 ships: the red-team loop runs **sustaining only** — regressions,
finding closures, and hardening of shipped surfaces. New "nastier
situations" that would expand scope are recorded as **v2 candidates in
FINDINGS.md**, not built. The cap lifts the day after v1.0 tags. This is
the single most important scope decision in this plan: an uncapped B5
makes 2026-10-31 unhittable by construction.

---

## 3. 37-day schedule

Staffing: subagent lanes under a ship coordinator (Krishna). Gate
protocol per milestone: canonical + registry + matrix + realistic all
green on a clean push clone; **red halts the milestone**. Push only
reviewed green boundaries, private repo, SSH, sign-off trailer.

| Week | Dates | Milestone | Lanes |
|---|---|---|---|
| W1 | 09-24 → 09-30 | **Foundations.** Spikes A+B land; B6 docs refreshed (bar + readiness gaps current through wave-107); F69 flake hardened; B2 100-profile battery re-verified with artifacts recorded. | KMS validation; packaging+quickstart; docs refresh; flake fix |
| W2 | 10-01 → 10-07 | **Installable.** Wheel/sdist installs clean in a fresh venv; quickstart verified by a cold reader (agent with no repo context); deployment-hardening minimum merged (TLS reference, auth story, single-tenant decision doc). | packaging close-out; deployment docs; first install test |
| W3 | 10-08 → 10-14 | **Evidence surface.** v1 export bundle specified (to-spec), built (tdd), break-tested (diagnosing-bugs), reviewed (code-review); retention story enforced or explicitly documented as operator-owned with a shipped verifier. | evidence spec; evidence build; retention decision |
| W4 | 10-15 → 10-21 | **Hardening + freeze.** Full adversarial re-run over the v1 boundary (all break batteries, both envs); any HIGH/CRITICAL blocks; MEDIUMs fixed or accepted-risk-noted by the user. **Feature freeze 10-21.** | red-team sweep; finding triage |
| W5 | 10-22 → 10-28 | **Release candidate.** v1.0.0 tagged privately; install → quickstart → evidence bundle verified end-to-end from the tag; release notes + changelog written. | RC build; release notes |
| Buffer | 10-29 → 10-31 | **Slip buffer.** Unused if green; absorbs exactly one bad week. | — |

Critical path: **Spike A → KMS runbook → deployment docs → RC**.
Second path: **Spike B → packaging → quickstart → RC**. The evidence
surface is the largest scope risk and starts W3 regardless of W1/W2
slip — it parallelizes cleanly.

---

## 4. Release-shape decision (user's call)

Two shapes are on the table. Standing orders say the repo stays private
until the user declares market readiness — so the default is private.

**Option A — private v1.0 (recommended).** Tag `v1.0.0` on the private
repo; distribute the wheel to design partners directly. Matches every
standing order, keeps the evidence-surface pricing power, loses nothing.
The open-core decision can be revisited for v2 with a real funnel to
measure.

**Option B — open-core v1.0.** Open-source the enforcement core
(`gov/` minus key-custody and evidence-export internals) as the funnel;
keep the evidence pipeline private. Follows the founder-strategy memo
and the LangChain/Langfuse pattern. Costs: license scrub of the whole
tree, secrets/keys audit, a public README that doesn't oversell, and
community surface area (issues, PRs) we have no one staffed to tend
before the date. Realistically pushes the date or shrinks the scope.

**Recommendation: ship A.** The strategy memo's own verdict is
"metered nothing, sell nothing" for now, and the evidence artifact —
the thing that would justify open-core — needs its first auditor
conversation before openness buys us anything. Revisit at v2.

**Decision needed from the user:** A or B. Everything in §3 proceeds
under A until told otherwise.

---

## 5. Top risks

1. **B5 scope creep by habit.** The loop has run uncapped for weeks;
   capping it is a discipline change, not a technical one. Mitigation:
   the v2-candidates log + the 10-21 freeze.
2. **KMS validation reveals real adapter defects.** Spike A could find
   the Vault adapter needs rework (auth, rotation semantics). Mitigation:
   it runs first; the cloud-KMS fallback is explicitly descoped.
3. **Evidence artifact without auditor validation.** We can ship the
   bundle; we cannot buy an auditor's blessing in 37 days. Mitigation:
   ship the artifact, claim only what it is (signed, timestamped,
   complete) — the blessing is a v2 sales motion.
4. **Approval-web auth story.** The honest minimum (token hygiene +
   reverse-proxy pattern) may read as thin to a security reviewer.
   Mitigation: write it plainly; do not build half-SSO.
5. **Packaging entanglement.** The `workstreams/` sibling-layout
   assumption may run deeper than the entry points. Mitigation: Spike B
   maps it fully in W1; if deep, the v1 install ships a documented
   layout shim rather than a refactor.

---

## 6. What "shipped" means (acceptance)

- `pip install` from the v1.0.0 wheel in a fresh venv; quickstart
  completes in ≤15 minutes to an evidence bundle.
- All four gates green on the tagged tree.
- Zero open HIGH/CRITICAL; zero open MEDIUMs without a user-signed
  accepted-risk note.
- B6 docs current: bar, readiness gaps, deployment guide, changelog.
- The user declares it market-ready. Nothing before that counts.
