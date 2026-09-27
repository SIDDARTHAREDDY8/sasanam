# Readiness Gaps — agent-governance-layer

**Status:** Wave-127 refresh, 2026-09-26. Companion to `docs/DEPLOYMENT.md` and the
B6 honesty bar in `workstreams/architect/REALWORLD_BAR.md`.

Organization: **§1 blocks production** (deploying without these is negligent);
**§2 is nice-to-have** (deferrable without lying). Every gap is grounded in the
code or the dated record — nothing is aspirational marketing.

**Since wave-27:** waves 80–127 filed and closed findings F138–F175 plus F-RA3
(next free: F176; open findings: none): citation-provenance controls (F139–F142),
skill-watch fail-closed (F143), memory-poisoning ingestion (F144), MCP server
instructions (F145), path-symlink TOCTOU (F146/F147), launcher audit-witness
(F148/F149), the Anthropic Sept-2026-report velocity/economic battery
(F162–F170, incl. the F163/F164 re-open→re-close), DLP quadratic scrub (F171),
evidence-bundle V11 (F172). F163's stale "RE-OPENED" heading fixed (wave-112).
Shipped: W3 evidence bundle (`gov/evidence_bundle.py` + `gov/evidence_verify.py` +
`tools/evidence-verify`, spec `docs/evidence-bundle-spec.md` §4.3 V1–V13, 44/44
tests, normative tamper battery 14 caught / 15 controls / MISS=0); the Vault
transit adapter validated against a real Vault OSS v1.20.0 dev server (20/20
live checks); F69 timing-flake hardened (deterministic gate); a MaxKB-shaped
sandbox sustaining probe landed; the Safeguard Benchmark primitive shipped
(wave-99, UNSC/RSI response). The F81 privileged battery ran under genuine
privilege in wave-98 (2026-09-24, 11/11 CLOSED ×2 on f81-lab; F81 CLOSED) and
was **re-verified on the current tree in wave-127 (2026-09-26, 11/11 CLOSED ×2,
durable artifact `evals/f81_privileged_run_2026-09-26.json` — see §1**).

Waves 116–127 (2026-09-26) addressed the full v1 hardening backlog (H1–H26):
row-9 caution-erosion monitor (row 9 GAP → PARTIAL; no full-row GAP remains),
`send_email` fingerprinting (F175 CLOSED), F-RA3 fail-closed read quarantine
(CLOSED), row-13 authorized-channel exfil pins (4 BREAK pinned residual),
rows 7/11/12 probe pins, H17/H18/H26 tightens (F143 p2/p6 → HELD),
approver-shield web brief (H19), skill pin-file authentication (H22),
exporter-narrowing + ISO 42001 conformance + outcome-auditing pins
(H20/H21/H25), F170 measured-absent + anchor-ready transparency seam
(H23/H24), and the F81 re-verification. The 2026-09-26 industry sweep's
Darktrace history-poisoning class was probed and maps to the F143 p3
factual-poison residual — not a new finding.

---

## 1. Blocks production

### Enterprise hardening (all verified in code)
- **Approval console: localhost-grade.** `gov/approval_web.py`: no SSO, no
  OIDC, no mTLS, in-memory sessions only, no session persistence, no
  cross-process session sharing, no TLS. Non-localhost binds are explicitly
  "unsupported without TLS + real auth in front" — which **nobody has built**.
  Anyone with the bearer token can approve. (Strategy decision S6:
  explicitly "NOT NOW".)
- **End-to-end TLS is a reverse-proxy reference, not an in-repo TLS stack.**
  Wave-111 landed the reference config and the documented auth story (token
  hygiene minimum + explicit SSO-deferred note) — the deployment story is
  honest, but no TLS is built in-repo and no SSO exists.
- **Approval queue persistence is file-only.** Records are JSONL in the run
  dir (`gov/approvals.py`) — durable across restarts of one host, but there is
  no database, no replication, no HA, no backup/restore story. A lost run dir
  is a lost queue and a lost audit log.
- **No enforced retention.** `gov/retain.py` does not exist — strategy D4
  (`workstreams/architect/STRATEGY_ROADMAP.md` §4) remains a plan, not code.
  Today retention is the operator's backup script. (For reference: Microsoft
  AGT's `retention_days` is declaration-only too — `research/competitive-deep-dive.md`
  §1.4 — so this is table-stakes work, not a differentiator.)
- **No monitoring/alerting pipeline.** No metrics, no health checks, no alerts.
  Monitoring = operator tails the action log and cron-runs `gov/verify.py`.
- **Key-ceremony runbook written, ceremony unpracticed.**
  `workstreams/kms/CEREMONY_RUNBOOK.md` (wave-26) and `docs/KEY_CUSTODY_RUNBOOK.md`
  (wave-91) exist — the "runbook missing" gap is closed. The other half stands:
  **no genesis/rotation ceremony has been practiced on a live server** (the
  runbook marks production provisioning, TLS end-to-end, non-token auth, HA,
  and live ceremonies all UNTESTED), so threshold signing is procedure-written
  but not operationally real.
- **Vault custody validated in dev mode only.** `gov/kms_vault.py` (wave-91) is
  validated against a real Vault OSS **v1.20.0** dev server on loopback: 20/20
  live checks green (`tests/test_kms_vault_live.py`; `docs/KEY_CUSTODY_RUNBOOK.md`
  A). Still **UNTESTED** (same file, A.1): production Vault provisioning (Raft
  integrated storage or Consul backend, TLS on the API listener, seal/unseal),
  TLS end-to-end, non-token auth (AppRole/platform identity), HA, operator
  ceremonies against a live server. **AWS/GCP/Azure KMS: no in-repo provider
  implementations** — the runbook documents the AWS path as operator-built.
  So: custody against a real server is proven in dev mode only; production-grade
  custody remains a deployment project, not a done deal.
- **F75 CLOSED 2026-09-22** (`evals/FINDINGS.md`): pinned dependency graph —
  `requirements.lock` (exact `==` pins + sha256 hashes for all artifacts),
  `gov/supplychain.py` package allowlist enforced by a fail-closed audit that
  `tests/run_tests.py` runs before test collection, and artifact
  verification. The HIGH-for-production escalation is retired; residual:
  audit checks installed names/versions, not post-install file bytes.
- **Open findings: none** (next free finding **F176**). F175 (MEDIUM), filed by
  the wave-117 H11 probe, was **CLOSED 2026-09-26** (Wave-118, red-first):
  `send_email` result content is now fingerprinted through the identical
  machinery (`read_file`, `api_call`, `http_post`, `send_email` — same 64-char
  verbatim-overlap fingerprints, same 256 KiB FIFO store, same 64 KiB
  per-result cap). F-RA3 (LOW, workstream), re-opened as partial in wave-117
  when its same-day CLOSED label overstated the close-when, was **CLOSED
  2026-09-26** (Wave-120): escaping `read_file` now returns fail-closed
  quarantine with no synthetic content (mirroring the write side). F173
  (LOW) and F174 (LOW), filed by the wave-114 adversarial rerun, were
  **CLOSED 2026-09-26** (Wave-115, red-first): F173 — bundle format
  `evidence-bundle/1.1`, signature domain `evidence-bundle/v2`, the
  operator-signed claim now binds inclusion presence/coverage + receipt
  bundle-presence/reason (unsigned stripping fails V7/V12; legacy 1.0
  bundles fail V1 closed); F174 — verifier renders `operator_id` in text
  and JSON labeled as operator-supplied/unverified. Adversarial battery
  post-fix: CAUGHT=9 MISS=0 BREAK=0. Every finding ≤ F175 is recorded
  CLOSED (F163 re-closed 2026-09-24 after the Wave-109 quality audit; the
  standing post-wave red-first audit ran GO on every wave since; the
  wave-120 and wave-124 boundaries each caught genuine lane-missed
  regressions — the rule works). The **accepted residual is F81 (LOW, CLOSED
  2026-09-24)**: the filtered-egress wall was lab-validated on f81-lab
  2026-09-23 (17 STOPPED / 0 BREAK across all 11 attack classes), the
  governed launcher exists (`gov/egress_launcher.py`, F136/F138 CLOSED
  2026-09-23), and the privileged battery (`evals/f81launcher_privileged.py`)
  **ran under genuine privilege in wave-98** — root, `GOV_F81_PRIVILEGED=1`,
  11/11 CLOSED, exit 0, deterministic ×2 (pushed `4000791`; the run's one
  break was filed and closed as F148 the same wave). Correction, wave-113:
  the wave-112 B1–B6 delta report's "never ran under real privilege" line was
  an error (it restated the wave-96 state and missed the wave-98 closure).
  **Residual RETIRED, wave-127 (2026-09-26):** the "not re-verifiable from
  today's tree" gap is closed — the privileged battery re-ran under genuine
  privilege on f81-lab (root, CAP_SYS_ADMIN, kernel 7.0.0-1011-gcp) against
  the wave-126 tree (`eb28f7f`): **11/11 CLOSED ×2, zero BREAK/SKIP/ERROR**,
  and the durable artifact `evals/f81_privileged_run_2026-09-26.json`
  (probe-by-probe ×2 runs, environment, tree pin) makes the closure
  re-verifiable going forward. VM stopped after the run ($0). The duplicate
  F81 headings in FINDINGS.md are cosmetic (wave-112 audit note), and the
  main F81 entry's top status line (still "OPEN 2026-09-22") was stale —
  corrected wave-113.

### Structural gaps (also blocking, longer lead)
- **D1 bridges incomplete.** The AGT-Python in-process shim is built
  (`gov/bridges/agt.py`, `DurableQueueApprovalHandler`, bounded wait
  under AGT's 5-min default, `bridge_expired` MAC-bound); the AGT .NET
  `WebhookApprover` ingress and the AWS AgentCore approval-event
  *producer* bridge are **not built** (protocol risk; sequenced behind
  the D5 contract per A12 — do not claim they exist).
- **No CrewAI / AutoGen / raw-HTTP adapters.** Adapters exist for LangChain,
  OpenAI loop, MCP, generic channels (`gov/adapters/`); CrewAI, AutoGen, and
  raw-HTTP governance are not built (`workstreams/architect/REALWORLD_BAR.md`
  structural gaps). Strategy decision: STOP building new adapters (D1 focuses
  on AGT/AWS bridges instead) — so this gap is **accepted by design**, but it
  remains a production-coverage gap for teams on those frameworks.
- **K-026 authenticated inter-agent messaging not built.** Inter-agent trust
  (`gov/adapters/trust.py` exists) has no authenticated message-passing
  primitive; the D1-core delegation invariants (S1–S7) assume queue-mediated
  delegation, not peer-to-peer agent messaging.

### Pinned enforcement residuals (capability boundaries, adversarially measured)

Every residual below is pinned by a battery that fires RED — none is a
closure claim. Full detail in `workstreams/architect/REALWORLD_BAR.md` B6(7)
(waves-116–127 addendum).

- **Row 13 — semantic exfil over authorized channels** (wave-121, 4 BREAK /
  3 HELD): paraphrased/summary/fragmented exfil over allowlisted,
  human-approved channels is not stopped; content-based paraphrase
  detection is not viable pre-freeze (benign paraphrases share more
  lexical overlap than malicious ones). Research-grade problem.
- **F143 p3/p5 — factual poison + heuristic dodge** (wave-123; the
  2026-09-26 Darktrace history-poisoning class maps to p3): factual
  claims delivered with zero warning are allowed by design; the
  quarantine conjunction requires instruction-shaped content.
- **Row 7 — no intent/temporal correlation, no revoke-after-approve**
  (wave-122, 2 BREAK / 1 HELD): staged plant→post exfil across steps
  has no linking signal; revocation is not an operation.
- **Row 11 — no goal registration/conflict detection** (wave-122, 1 BREAK /
  2 HELD): in-budget, policy-clean trajectories with no registered goal
  produce no conflict signal.
- **Row 12 — no artifact inventory / artifact-tuned egress detection**
  (wave-122, 1 BREAK / 2 HELD): hex-encoded weight-shard-shaped payloads
  bypass credential-tuned detection; no clean content-shape seam exists.
- **Row 10 — no outcome auditing** (wave-125, 1 BREAK / 2 HELD): velocity
  gates tempo, not goal-alignment; a goal-divergent trajectory fires zero
  outcome signal. Goal ontology + outcome judge are v2 research.
- **Row 9 — many-shot residual + cross-run erosion** (wave-119): the
  trajectory-erosion monitor is opt-in; e4 many-shot framing drift and
  cross-run erosion remain.
- **K-060 — bundle proves authenticity of included entries, not
  completeness against a misbehaving exporter** (wave-125, 2 BREAK / 2
  HELD; spec §7 honest scope). External anchor is the v2 fix; the H24
  seam makes a v2 adapter cheap.
- **Repo-default posture:** the "42/44 legacy `ToolExecutor` sites
  ungoverned" line described the **pre-wave-85** state (wave-84
  text-search census). Wave-85's fail-closed constructor gate closed the
  construction seam. Fresh AST census 2026-09-26 (wave-127 tree):
  119 sites — 81 deliberately acked (LOUD `ungoverned_bypass`
  declarations), 20 full-core (19 test fixtures + 1 product site,
  `gov/executor.py:1680` child spawn), 6 store-only+ack test fixtures,
  12 bare/`**kw` confined to refusal batteries and test helpers;
  **0 silent ungoverned sites in product code**. Evidence:
  `evals/tool_executor_inventory_2026-09-26.md`. The demos/examples
  (7 acked sites) stay acked by design — teaching scaffolds, not
  deployed paths.

### Reality checks (non-technical, still blocking)
- **Private repo, no certifications, no managed offering.** There is no SOC 2,
  no ISO 42001, no EU AI Act evidence pack, no pen-test report, no SLA, no
  support channel, no managed/hosted deployment. Market release happens only on
  the user's explicit decision (standing order). Do not describe this to third
  parties as production software.

---

## 2. Nice to have (deferrable)

- **D1 bridges:** AGT Python `CallbackApproval` shim — BUILT
  (`gov/bridges/agt.py`); AGT .NET `WebhookApprover` interop, AWS
  AgentCore approval-event producer (`workstreams/architect/STRATEGY_ROADMAP.md`
  §1) — the D1–D5 strategy positions this project as *the approval queue +
  enforcement-testing layer that plugs into AGT and AgentCore, not a
  replacement* (`research/competitive-deep-dive.md` §0). Feasibility and
  sequencing are in the roadmap; only the Python shim is built.
- **Cedar-compatible policy export** (D3): portability story against AWS
  Cedar lock-in; engine stays YAML. `gov/policy_export.py` is built and
  fail-closed (F88 — lossy mappings like `require_approval` refuse rather
  than silently permit).
- **Evidence bundle (W3):** BUILT wave-112 — spec `docs/evidence-bundle-spec.md`
  §4.3 (V1–V13, +V14 as a documented v1 extension): bundle/verify/CLI triple
  (`gov/evidence_bundle.py`, `gov/evidence_verify.py`, `tools/evidence-verify`)
  byte-identical and drift-guarded, 44/44 tests, normative tamper battery
  **14 caught / 15 controls / MISS=0**. Residuals are the spec's own normative
  §7: no external anchor (FakeTransparencyLog — live Rekor deferred to v2 by
  decision), threshold root trust via the operator manifest (single-operator
  signature in v1; multi-operator deferred to v2), authorship requires an
  out-of-band key pin the verifier never invents, key custody claimed via
  `kms_attestation` not cryptographically proven, timestamps operator
  wall-clock. The bundle proves authenticity of *included* entries, not
  completeness against a misbehaving exporter (K-060 honest scope).
- **Enforced retention + narrowed audit** (D4): key-lifecycle-focused audit
  with `min/max_retention_days` enforced by the engine — retention
  enforcement is still not implemented; the ceremony runbooks are written.
- **Battery as neutral benchmark vs AGT** (D2): evidence LANDED —
  `workstreams/evals/D2_BENCHMARK.md`, ours 14/18 vs AGT 3/18
  (2026-09-22 re-run; StruQ privilege-claim + approval-bypass
  families; two-sided limitations documented). Runs stay local;
  publication separately user-gated.
- **Seccomp allowlist maintenance tooling** exists (`--audit-seccomp`) but is
  manual; fine for now.
- **Evals integration:** wave-21+ situations should live in `evals/run_evals.py`
  (noted as not-yet-integrated in REALWORLD_BAR.md v1) — still noted, not
  blocking.
- **Stratified-100 artifact pinning:** landed wave-113 — the in-gate battery's
  99/100 (single miss `careless-typo-014` / F-RA3) is pinned by
  `evals/stratified_100_claim.json` with a fail-closed verifier
  (`evals/verify_stratified_100_claim.py`, 5/5 unit tests). The generated
  result artifact is still regenerated every gate run and reverted
  pre-commit; the pushed tree carries the pinned claim + verifier, not the
  raw artifact.
- **Multi-tenancy, policy hot-reload/versioning-rollback, approval fatigue
  auto-deny** (AGT has the latter): all legitimate roadmap items, none blocking
  a first honest pilot — but a pilot is not production. **v1 is explicitly
  single-tenant** (SHIP_PLAN §2) — do not claim otherwise.

---

## 3. What this is not (plain language)

- **Not a production governance platform.** It is a research prototype with a
  solid, adversarially-tested enforcement core and a built evidence surface
  (signed, third-party-verifiable bundles — unanchored, operator-manifest root
  trust). The distance to production is the list in §1, not a marketing
  paragraph.
- **Not a replacement for Microsoft AGT or AWS AgentCore.** We cannot and do
  not differentiate on policy engines, audit crypto, sandboxing, framework
  adapters, or compliance mappings — those are table stakes they occupy. The
  viable shape is a component that plugs into them (durable approval queue +
  enforcement-layer testing), per `research/competitive-deep-dive.md` §0 and
  the D1–D5 strategy.
- **Not a security boundary against arbitrary hostile native code.** The
  sandbox (`gov/sandbox.py`) is documented defense-in-depth: crash/hang/
  resource-abuse containment for the tool scripts we generate, with honest
  per-call isolation reporting. It is not a container or VM boundary. The
  filtered-egress wall is lab-validated plus launcher-governed; its privileged
  battery ran under genuine privilege in wave-98 (11/11 ×2) and was
  re-verified on the current tree in wave-127 (11/11 ×2, durable artifact
  `evals/f81_privileged_run_2026-09-26.json`).
- **Not certified, audited, or supported.** No SOC 2, no pen test, no SLA, no
  managed offering, private repo. Anyone evaluating it for production use
  should start from §1, not from the test count.
- **Not finished.** The mission is open-ended: the B1–B6 bar in
  `workstreams/architect/REALWORLD_BAR.md` is the definition of done, and this
  project is mid-journey against it. Green unit tests are necessary but never
  sufficient — we do not declare victory on them.
