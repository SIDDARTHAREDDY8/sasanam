# Readiness Gaps — agent-governance-layer

**Status:** Wave-27 refresh, 2026-09-22. Companion to `docs/DEPLOYMENT.md` and the
B6 honesty bar in `workstreams/architect/REALWORLD_BAR.md`.

Organization: **§1 blocks production** (deploying without these is negligent);
**§2 is nice-to-have** (deferrable without lying). Every gap is grounded in the
code or the dated record — nothing is aspirational marketing.

**Since wave-23:** closed F82, F83 (fix + independent verification; closure
unrecorded), F86, F87, F88, F90, F91, F92, F93, F94; F101 closed
(provisional); F70/F72 verifier-chain fixes landed (F70 recorded CLOSED,
F72 closure unrecorded); ceremony runbook written (ceremony unpracticed);
D1 AGT-Python bridge built (.NET + AWS producer still sequenced);
D2 benchmark evidence landed (ours 14/18 vs AGT 3/18, StruQ +
approval-bypass families, `workstreams/evals/D2_BENCHMARK.md`).

---

## 1. Blocks production

### Enterprise hardening (all verified in code)
- **Approval console: localhost-grade.** `gov/approval_web.py`: no SSO, no
  OIDC, no mTLS, in-memory sessions only, no session persistence, no
  cross-process session sharing, no TLS. Non-localhost binds are explicitly
  "unsupported without TLS + real auth in front" — which **nobody has built**.
  Anyone with the bearer token can approve. (Strategy decision S6:
  explicitly "NOT NOW".)
- **Approval queue persistence is file-only.** Records are JSONL in the run
  dir (`gov/approvals.py`) — durable across restarts of one host, but there is
  no database, no replication, no HA, no backup/restore story. A lost run dir
  is a lost queue and a lost audit log.
- **No enforced retention.** Strategy D4 (`workstreams/architect/STRATEGY_ROADMAP.md`
  §4) plans a `retention:` policy section (`min/max_retention_days`); it is
  **not implemented**. Today retention is the operator's backup script. (For
  reference: Microsoft AGT's `retention_days` is declaration-only too —
  `research/competitive-deep-dive.md` §1.4 — so this is table-stakes work, not
  a differentiator.)
- **No monitoring/alerting pipeline.** No metrics, no health checks, no alerts.
  Monitoring = operator tails the action log and cron-runs `gov/verify.py`.
- **Key-ceremony runbook written, ceremony unpracticed.**
  `workstreams/kms/CEREMONY_RUNBOOK.md` now exists (wave-26) — the
  wave-23 "runbook missing" gap is half-closed. The other half stands:
  **no genesis/rotation ceremony has been run** on an offline machine,
  so threshold signing is procedure-written but not operationally real.
- **No real KMS wired.** `gov/kms.py` is provider-neutral with a correct
  envelope contract (key-id binding, fail-closed `KmsError`) and a
  test-double `FakeKmsProvider` that is refused unconditionally from
  operator config (wave-81 deleted the old `GOV_DEV_KEYS` opt-in) — but
  AWS/GCP/Azure provider implementations are "operator provider-config":
  **not built**. A HashiCorp Vault transit adapter now exists
  (`gov/kms_vault.py`, wave-91) but is validated against a fake transport
  only — **real-server validation is required before any production
  claim**. Until one is proven, production custody means either the
  weaker v1 plaintext `KeyRing` or hand-rolled wiring.
- **F75 CLOSED 2026-09-22** (`evals/FINDINGS.md`): pinned dependency graph —
  `requirements.lock` (exact `==` pins + sha256 hashes for all artifacts),
  `gov/supplychain.py` package allowlist enforced by a fail-closed audit
  that `tests/run_tests.py` runs before test collection, and artifact
  verification. The HIGH-for-production escalation is retired; residual:
  audit checks installed names/versions, not post-install file bytes.
- **Other open findings that must close first** (`evals/FINDINGS.md`,
  wave-27): explicitly OPEN — F95, F96, F97, F98 (StruQ residual
  sweep), F99 (`api_call` approval asymmetry; wave-27 closure lane
  dispatched), F100 (GitLost framing; wave-27 closure lane
  dispatched). **Fixes landed but closure unrecorded** (treat as open
  until the owning lane records closure) — F72 (verifier-chain
  replay freshness fix + regression tests landed), F83 (non-atomic
  `_rewrite` fix + independent red-team verification landed). F81
  stays OPEN as the **accepted gap** (no filtered-egress /
  destination-allowlist mode in the sandbox; AGT v5.0.0's
  `NonoSandboxProvider` is the reference implementation for what we
  lack). F101 is CLOSED provisional. Everything ≤ F94 not named here
  is recorded CLOSED.

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
- **Enforced retention + narrowed audit** (D4): key-lifecycle-focused audit
  with `min/max_retention_days` enforced by the engine — retention
  enforcement is still not implemented; the ceremony runbook is written.
- **Battery as neutral benchmark vs AGT** (D2): evidence LANDED —
  `workstreams/evals/D2_BENCHMARK.md`, ours 14/18 vs AGT 3/18
  (2026-09-22 re-run; StruQ privilege-claim + approval-bypass
  families; two-sided limitations documented). Runs stay local;
  publication separately user-gated.
- **Seccomp allowlist maintenance tooling** exists (`--audit-seccomp`) but is
  manual; fine for now.
- **Evals integration:** wave-21+ situations should live in `evals/run_evals.py`
  (noted as not-yet-integrated in REALWORLD_BAR.md v1).
- **Multi-tenancy, policy hot-reload/versioning-rollback, approval fatigue
  auto-deny** (AGT has the latter): all legitimate roadmap items, none blocking
  a first honest pilot — but a pilot is not production.

---

## 3. What this is not (plain language)

- **Not a production governance platform.** It is a research prototype with a
  solid, adversarially-tested enforcement core. The distance to production is
  the list in §1, not a marketing paragraph.
- **Not a replacement for Microsoft AGT or AWS AgentCore.** We cannot and do
  not differentiate on policy engines, audit crypto, sandboxing, framework
  adapters, or compliance mappings — those are table stakes they occupy. The
  viable shape is a component that plugs into them (durable approval queue +
  enforcement-layer testing), per `research/competitive-deep-dive.md` §0 and
  the D1–D5 strategy.
- **Not a security boundary against arbitrary hostile native code.** The
  sandbox (`gov/sandbox.py`) is documented defense-in-depth: crash/hang/
  resource-abuse containment for the tool scripts we generate, with honest
  per-call isolation reporting. It is not a container or VM boundary.
- **Not certified, audited, or supported.** No SOC 2, no pen test, no SLA, no
  managed offering, private repo. Anyone evaluating it for production use
  should start from §1, not from the test count.
- **Not finished.** The mission is open-ended: the B1–B6 bar in
  `workstreams/architect/REALWORLD_BAR.md` is the definition of done, and this
  project is mid-journey against it. Green unit tests are necessary but never
  sufficient — we do not declare victory on them.
