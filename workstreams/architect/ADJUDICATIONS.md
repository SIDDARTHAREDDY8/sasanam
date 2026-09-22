# Architect Adjudications

**Role:** Principal Architect · **Scope:** binding design decisions for the
agent-governance-layer project. Decisions here resolve conflicts, set
non-goals, and gate workstreams. Overrides need a written lead decision
citing new evidence.

> **PROVENANCE NOTE (2026-09-22, wave-23):** This file was created during
> wave-23 because `workstreams/architect/ADJUDICATIONS.md` did not exist in
> the working copy (ZIP export, no `.git`; `workstreams/` contained only
> `market/` and `sandbox/`). Entries **A1–A11** are reconstructed from the
> authoritative record in `BUILD_LOG.md` (entries of 2026-09-22 02:41 UTC
> and 03:01 UTC) — they are marked `[reconstructed]`. If the original
> ADJUDICATIONS.md exists in the real tree, reconcile this file against it
> before relying on A1–A11 wording here. Entries **A12+** are new,
> written fresh.

---

## A1 — CaMeL planner/quarantine split vs taint-and-gate executor `[reconstructed]`

**Verdict: KEEP** the current taint-and-gate executor; incremental
per-value provenance. The full planner/quarantine split is deferred.
Rationale: the split is a research-grade refactor; per-value provenance
gets most of the containment value at a fraction of the risk. The StruQ
and instruction-hierarchy controls stay the prevention layer.

## A2 — Rule-of-Two session invariant `[reconstructed]`

**Verdict: CHANGE.** A fail-closed Rule-of-Two session invariant was added
to the executor (a session that has touched untrusted input cannot take
untrusted-influenced privileged actions without a fresh human/operator
step). Rationale: the sharpest of the literature items; directly closes
indirect-prompt-injection → privilege-escalation chains.

## A3 — Steganography as a hard ceiling on plaintext audit observability `[reconstructed]`

**Verdict: KEEP** the log, **narrow the claims**, add behavioral collusion
probes. Rationale (Motwani et al. + Rippin et al.): plaintext logs cannot
observably rule out covert channels; claiming otherwise is dishonest.
Mitigation is behavioral (collusion probes, egress accounting), not
observational.

## A4 — Sandlock vs Firecracker sandbox upgrade path `[reconstructed]`

**Verdict:** Sandlock is the direction for P3; Firecracker is the
documented ops answer. Rationale: no container/VM ambition in-repo (STOP
list); the honest prototype stays honest.

## A5 — TUF threshold/offline keys vs one active symmetric log key `[reconstructed]`

**Verdict:** k-of-n Ed25519 threshold checkpoint signatures + offline root.
The HMAC hot path stays. Rationale: threshold custody for ceremonies and
external verification; HMAC remains the per-entry workhorse. Superseded
in part by A15 (Merkle-proof ambition cancelled).

## A6 — DIDs vs registry identity `[reconstructed]`

**Verdict: KEEP** the centralized registry; no DIDs. Rationale:
`PrincipalRegistry` is minimal harness infrastructure; decentralized
identity is an identity-racing project we explicitly decline (STOP S8).

## A7 — Formal-shield scope (Alshiekh et al.) `[reconstructed]`

**Verdict:** verify the guardrail lattice as an executable spec; model
behavior is out of scope. Rationale: we govern the enforcement layer,
not the model.

## A8 — Agent Smith contagion model `[reconstructed]`

**Verdict: ADD** contagion evals + a P5 multi-agent extension gate.
Rationale: propagation paths between agents are a real incident class
(B1) and cheap to probe; wave-19 found no propagation path, which is a
result, not an absence of effort.

## A9 — Session identity standard `[reconstructed]`

**Verdict: STANDARDIZE ON** the F55 provisioned-session identity.
Rationale: tuple-equality impersonation (a mid-run mint matching the
operator's tuple) is closed only by provenance; the provisioned session
identity is the deployment's trust root.

## A10 — Two-tier log boundary `[reconstructed]`

**Verdict:** redacted hot log + access-controlled forensic tier.
Rationale (K-063 GDPR minimization vs full-trace capture): the default
trail minimizes; the forensic tier exists behind access control. Both
tiers are hash-chained; the boundary is documented, not implied.

## A11 — F-RA2: policy vs synthetic fixtures `[reconstructed]`

**Verdict: policy is the spec.** The 32 benign-researcher profiles were
regenerated as *negative controls* (deny + never-executed assertions);
`researcher` stays write-denied in `policies/default.yaml`. Rationale:
the policy file is versioned, lint-checked, and hash-pinned (F48); the
fixtures are synthetic and disposable. Weakening the policy to fit the
fixtures would also trip the A2 invariant for the highest-risk archetype.

---

## A12 — D1: durable approval queue as a pluggable piece for AGT and AWS AgentCore

**Date:** 2026-09-22 (wave-23) · **Status: DECIDED — BUILD, corrected direction**

**Verdict.** Build the queue as a component that plugs *into* AGT and
AgentCore — not a replacement for either. D1-core (delegation + quorum +
`bridge_expired` in `gov/approvals.py`, web UI routes) has landed and is
the pluggable core. Bridges are thin adapters under a new `gov/bridges/`
package. The AWS direction is corrected per STRATEGY_ROADMAP §1c: **we are
an approval-event producer into the trajectory, not a consumer of AWS
approval webhooks** (AWS emits none). Any work item phrased "receive AWS
approval events" is to be rejected at dispatch.

**Rationale.** The deep-dive verified the wedge: neither competitor has a
durable queue (AGT: synchronous pause/resume; AWS: no human-approval
primitive at all, explicitly DIY/HumanLayer). Our queue already has
file-backed restart-surviving records, HMAC-bound integrity, TTL, SoD,
risk scoring, flood defense, break-glass, and a 26/26 adversarial web
battery — plus D1-core's delegation/quorum. The defensible move is to
make that core *addressable from their runtimes*, which is weeks of
adapter work, not a platform rebuild.

**What `gov/approvals.py` + the web UI must expose (adapter contract):**

`gov/approvals.py` gains a small, stable bridge surface — nothing in the
existing decision paths changes shape:

```python
# New on ApprovalQueue (sketch; names binding for implementation)
queue_external(tool, args, policy_id, agent_identity, preview,
               bridge_id, external_request_id=None,
               bridge_request_digest=None) -> approval_id
# - external_request_id: idempotency key for ingress replays (.NET webhook).
#   Second queue_external with the same key returns the existing record's
#   id (or its recorded decision), never a second record.
# - bridge_request_digest (+ action/policy/chain versions for .NET) enters
#   the MACed security payload via _SECURITY_PAYLOAD_FIELDS extension.
# - All new fields MAC-bound before any wait begins.

wait_for_decision(approval_id, timeout_s) -> "approved" | "rejected" | "timeout"
# - Bounded wait (per-record threading.Event or poll under the queue lock),
#   strictly shorter than the foreign runtime's own timeout (e.g. 4 min vs
#   AGT's 5-min CallbackApproval default).
# - On timeout: calls mark_bridge_expired(approval_id, bridge_id, ...) and
#   returns "timeout". The caller (bridge) returns deny to its runtime.
#   The record stays pending; a later human decision is audit-only
#   (late_decision=true) and NEVER executable — enforced by the D1-core
#   T12 sweep check, which bridges must not bypass or reimplement.

get_record(approval_id) -> dict | None   # read-only status for bridges
mark_bridge_expired(...)                 # already exists (D1-core §6)
```

`gov/bridges/` package (new), each module with a README contract:

- `gov/bridges/core.py` — `BridgeAdapter` ABC
  (`request_approval(ctx) -> handle`, `wait_for_decision(handle, timeout)`,
  `abort(handle, reason)`), plus the shared timeout/deny + audit helpers
  so every bridge gets identical fail-safe semantics.
- `gov/bridges/agt.py` — `DurableQueueApprovalHandler` implementing AGT
  Python's `ApprovalHandler` interface (`request_approval(context) ->
  ApprovalDecision`). In-process only. Identity mapping: AGT's
  `did:agentmesh:…` recorded verbatim as untrusted framing; the human sees
  only our executor-generated preview.
- `gov/bridges/aws.py` — the corrected **producer** bridge: (1)
  `register_denial(...)` — the customer-documented integration function
  the agent calls on temporal-permit denial (no AWS read API needed);
  (2) `emit_approval_event(gateway, approval_action, session_id,
  principal, match_fields, decision_id)` — invokes the customer-named
  approval action through *their* Gateway with `output.approved: true`,
  same session + principal, exact match fields. Refuses to run unless
  action name, gateway endpoint, and match fields are explicitly
  configured. Ships with `FakeGateway` (same honesty pattern as
  `FakeKmsProvider`); live validation is an operator-side checklist, not
  a CI gate.
- `gov/bridges/agt_webhook.py` — AGT .NET `WebhookApprover` HTTPS ingress:
  authenticated inbound (mTLS or HMAC with out-of-band key), idempotency
  on their `ApprovalRequestId`, strict versioned-schema validation
  (unknown versions refused), expiry honored, request/action digests
  MAC-bound. **Not started until the JSON schema is pinned from their
  .NET source** — protocol research first.

**Web UI exposure:** bridge-queued records render with a `bridge:<id>`
badge and read-only foreign digests/versions; decision/delegate/vote
actions use the identical session/CSRF discipline as native records. No
bridge-specific auth bypass in the console.

**Sequencing (binding):** D1-core → AGT-Python shim → AWS bridge reference
→ AGT-.NET protocol research (highest uncertainty last). The .NET ingress
and any AWS-facing network endpoint stay behind the D5 deployment
contract (real auth, TLS, KMS-backed keys) — until then, in-process shim
only.

**Explicit non-goals:** no "receive AWS approval events" work; no live
AgentCore integration testing ($0/no-credentials standing order — the
reference must never be presented as validated against AgentCore until an
operator runs the checklist); no vendored AWS SDK; no credential custody
in-repo or in logs; the shim is never marketed as "our SaaS governing AGT
Cloud"; no SSO/TLS/multi-tenancy for the console (STOP S6 stands).

**Terminology guard (binding):** "approval delegation" (D1-core: human
reassignment of decision stewardship) vs "authority delegation" (P10:
agent-to-agent grant of tool-call authority) are distinct primitives.
Docs, code comments, and audit event names must not blur them.

## A13 — D2: the adversarial battery as a neutral benchmark vs their governors

**Date:** 2026-09-22 (wave-23) · **Status: DECIDED — BUILD harness; RUN locally vs AGT + Dogwood; PARK live AWS**

**Verdict.** The battery's second life is as a neutral benchmark: the
same adversarial method run against AGT's engine and (local) Dogwood
policies, with our own engine as one target among others. Credibility is
the product; neutrality (including publishing our own failures) is the
mechanism.

**Rationale.** The deep-dive verified nobody attacks the enforcement
layer itself — AGT's red-team is a static prompt-text audit; promptfoo /
Mindgard attack the model. A benchmark only we could be accused of
gaming is worthless, so the harness must be built to embarrass us too.
Local runs are $0 (AGT's Python SDK from PyPI; Dogwood is Apache-2.0 open
source). Live AgentCore runs need an account, creds, and metering — parked.

**What `run_evals.py` needs (binding):**

- `evals/targets/engine_abc.py` (new): `TargetEngine` ABC —
  `name`, `translator_version`, `provision()` / `teardown()` (local-only
  lifecycle), `evaluate(scenario) -> EngineVerdict` where verdict ∈
  `{allow, deny, require_approval, error}` plus free-text notes. No target
  may mutate our engine's semantics; translations live in additive files.
- `evals/targets/agt_engine.py` (new): installs AGT Python SDK locally,
  translates a *subset* of situations (policy-evasion, approval-ceremony,
  DLP-bypass classes) into AGT YAML policies + contexts, records
  allow/deny/require_approval vs the scenario's security expectation.
- `evals/targets/dogwood_local.py` (new): evaluates the D3-exported
  policies under the open-source Dogwood interpreter. **Single-translator
  rule (binding):** this target consumes `gov/policy_export.py`'s
  translator (`translate_for_dogwood()`); it must not re-implement one.
  Two divergent translators would let translation bugs masquerade as
  engine results in either direction.
- `evals/benchmark_corpus.yaml` (new): pinned scenario ids + each
  scenario's security expectation + per-engine translation notes. Only
  pinned scenarios count as benchmark results.
- `run_evals.py --benchmark`: runs N scenarios × {ours, AGT, Dogwood};
  writes `evals/benchmark_results/<translator-version>/results.json`
  with the translator version pinned. **Invalidation rule:** results are
  void if the translator version changed since the run — re-run, don't
  reinterpret.
- `evals/BENCHMARK_METHOD.md` (new): scenario selection, translation
  rules, what "stopped" means per engine, residuals policy.

**Comparison doctrine (binding):** compare each engine's outcome against
the scenario's *security expectation*, never engine-vs-engine parity.
Engines may differ where both are safe. Record disagreements as
`divergent_safe` / `divergent_unsafe`; the latter is a finding candidate,
not a verdict. Document the known semantic mismatch (AGT MostSpecificWins
vs our deny-first) in the method doc — don't hide it.

**Neutrality guardrails (binding):** our engine runs as just another
target; the harness never weakens our gate to flatter a foreign engine;
foreign-engine results are published only with per-scenario
translation-review notes (human-reviewed), never raw harness output; our
own failures publish alongside.

**Explicit non-goals:** no live AgentCore runs (design-only under current
standing orders); no simulated-AgentCore results presented as benchmarks
(that would be exactly the dishonest claim the strategy warns against);
no benchmark SKU or paid packaging (STOP S9 stands); publication and any
contact with Microsoft/AWS are separately gated on explicit user say-so
(standing order — D2's momentum does not carry it past the gate).

## A14 — D3: freeze the engine; Cedar export for portability

**Date:** 2026-09-22 (wave-23) · **Status: DECIDED — BUILD, fail-closed, bounded scope**

**Verdict.** Freeze `gov/policy.py` at v2 semantics (security fixes +
lints only). Build `gov/policy_export.py`: YAML v2 → Cedar for stateless
policies, → Dogwood for stateful ones. This is the anti-lock-in story
against the exact plane AWS monetizes (Gateway + Guardrails functions +
CloudWatch audit), not an engine race.

**Rationale.** AWS's lock-in is the enforcement plane, not the language —
Cedar is open source and policy-as-code ports. Our engine stays the
harness's system-under-test, never a product. The mapping `deny→forbid`
is genuinely aligned (forbid-wins ≡ deny-first; default-deny ≡
default-deny), which makes the export honest rather than aspirational.

**Scope (binding):**

- `gov/policy_export.py` (new) CLI + `translate_for_dogwood()` (consumed
  by A13's Dogwood target — single-translator rule).
- Total mappings: `deny`→`forbid`, `allow`→`permit`, `role` allowlists →
  Cedar principal scoping, `tool` → `AgentCore::Action`, match keys
  (`path_outside_sandbox`, `domain_allowlisted`, `carries_read_content`,
  `source_untrusted`, `read_sensitive`, `path_contains_any`, `when`
  comparisons) → typed `context` attributes under a documented context
  schema (`docs/cedar-context-schema.md`, new) that the operator's
  gateway mapper must populate. Stateful keys (`min_external_calls`,
  `min_sends/min_writes/min_deletes`, `cross_run_campaign`,
  `velocity_exceeded`) → Dogwood `count_within`/temporal blocks.
- **The mapping is not total (binding):** the exporter targets Cedar for
  stateless policies and Dogwood for stateful ones, and **refuses**
  plain-Cedar output for policies containing stateful keys. `require_approval`
  has no Cedar equivalent — the exporter **errors** on `require_approval`
  rules *unless* a `bridge:` binding names the D1-AWS approval action,
  in which case it emits a Dogwood temporal permit gated on the
  bridge-produced approval event (`formerly within <ttl>
  AgentCore::Action::"<ApprovalAction>"::response{… output.approved: true }`,
  single-use per A12). **Never silently permit, never silently drop.**
- Every export carries a header pinning the source policy hash (drift
  detectable); `gov/policy_lint.py` gains an `--export-check` mode.
- Validation: verdict-parity suite — our engine vs Dogwood-local on ≥50
  corpus scenarios, green; run on every D2 benchmark invocation (A13 is
  the validation loop).

**Sequencing (binding):** deny/allow export proceeds in parallel with the
D1-AWS bridge contract; the `require_approval` mapping is gated on A12's
`emit_approval_event` signature being defined.

**Explicit non-goals:** no `gov/policy.py` semantic changes or perf chase
(AGT's 0.037 ms p99 is not our race; STOP S1 stands); no hot-reload; no
compliance-mapping effort (STOP S5); no claim beyond verdict parity on
the corpus — context attributes are a deployment contract the operator's
mapper must honor, not a semantic guarantee we can test.

## A15 — D4: audit differentiation narrowed to key lifecycle + enforced retention

**Date:** 2026-09-22 (wave-23) · **Status: DECIDED — CONFIRM the narrowing; BUILD retention**

**Verdict.** The audit story is two things and only two things: (1) keys
you can actually operate, (2) retention that is enforced, not declared.
Both are genuine gaps: AGT's `retention_days` is declaration-only and its
signing-key rotation story is undocumented; AWS's rotation story is
unverified.

**Rationale.** The signature race is lost — AGT shipped Ed25519 + Merkle
+ 157 conformance tests (verified). Racing it further is STOP S2. The
operational side is unoccupied and auditor-visible: rotation-safe verify
(F19), no silent dev-key fallback (F73/F77), KMS envelope keyring, and
— the actual build — retention the engine enforces.

**Scope (binding):**

- **Key lifecycle — finish, don't expand:** land the in-flight
  Ed25519-threshold work as the *verifier* side (external auditors verify
  without holding the HMAC key), then freeze. The pre-deep-dive "Ed25519
  + Merkle proofs" priority item is **superseded and cancelled** — no
  Merkle-proof ambition. `gov/kms.py` stays provider-neutral; real cloud
  wiring remains operator config (documented, not built);
  `FakeKmsProvider` stays dev-only behind `GOV_DEV_KEYS=1`.
- **Enforced retention — the build:** `policies/default.yaml` (+
  `gov/data` twin) gains a `retention:` section (`min_retention_days`,
  `max_retention_days`); a new `gov/retain.py` CLI implements `seal`
  (verify chain → write manifest → archive), `verify-archive`, and
  `expire` (deletes archives past `max_retention_days` **only** with dual
  human approval recorded in the action log; deleting the *live* log is
  always refused). F78's root-signed tip manifest is the primitive `seal`
  builds on — sequence retention after F78 (now landed/verified).
  Missing retention config fails closed to a documented safe default —
  never unbounded growth, never silent deletion.
- **Docs:** `docs/key-lifecycle.md` (new) — the honest operator story:
  rotation ceremony, dev-key rejection, what HMAC can't do
  (non-repudiation limits), KMS envelope, retention enforcement. This doc
  is the D4 "product."

**Explicit non-goals:** no Merkle race; no cloud-KMS wiring; no TEE
keystore response to AGT's narrowing (noted, no action); no retention
theater — if the engine can't enforce it, it isn't claimed.

## A16 — D5: stay a component; upstream contribution as a live option

**Date:** 2026-09-22 (wave-23) · **Status: DECIDED — posture + docs; contribution gated**

**Verdict.** No managed cloud, no SSO promises, no compliance-paper chase.
The honest-limits discipline (FINDINGS.md residuals, module docstrings
that say what isn't claimed) continues as a *practice*. Upstream
contribution to AGT stays a live, explicitly-gated option.

**Rationale.** D1–D4 only make sense as a component: a reference
implementation + eval harness + pluggable approval queue. Anything
platform-shaped would compete with Microsoft and AWS on their home turf
with $0 and no ops team. The stated strategy if Microsoft ever ships a
durable queue — our queue becomes a PR candidate and the battery is the
reason they take it — is recorded plainly here, not as a euphemism.

**Scope (binding):**

- `docs/COMPONENT_POSTURE.md` (new): what we are (reference
  implementation + eval harness + approval queue that plugs into
  AGT/AgentCore), what we are not (not a platform, not a cloud, not a
  compliance vendor), and the bridge deployment contract (real auth +
  TLS + KMS-backed keys required before any network ingress — until
  then, in-process shim only).
- Keep `gov/approvals.py` stdlib-only and bridge modules
  dependency-light so the queue *could* be contributed upstream.
- **Two gates (binding):** (1) contributing upstream = publishing code =
  explicit user say-so (standing order); (2) the repo has **no LICENSE
  file** — any contribution or publication needs a license decision by
  the user first. Both gates are recorded so nobody starts the process
  "helpfully" overnight.

**Explicit non-goals:** no license defaulting (the decision is parked,
not made); no product launch activity; no compliance mappings (STOP S5
stands).

---

## Disagreements / amendments recorded by the Architect

1. **D2↔D3 translator circularity (amendment to A13/A14).** The roadmap
   sequences D3's exporter as validated by D2's Dogwood target while D2
   needs D3's translator — dispatched as two workstreams, that yields two
   translators and a blame-shifting seam. Resolved above: the
   single-translator rule is binding. One module owns translation;
   benchmark consumes it.
2. **D1-AWS reference can never be validated in-repo (risk accepted, not
   a veto).** `FakeGateway` keeps us honest, but a wrong protocol guess
   (match fields, event shape) means the privileged action stays denied
   forever — safe, but useless. The bridge README must carry an
   operator-side validation checklist, and the reference must never be
   described as working against AgentCore until an operator runs it.
3. **D2 publication neutrality needs a human in the loop (amendment to
   A13).** Translator versioning is necessary but not sufficient:
   foreign-engine results publish only with human-reviewed per-scenario
   translation notes. Raw harness output is not a benchmark result.
4. **D5's upstream option has a quiet precondition.** A PR-shaped queue
   also needs the D1-core web-identity open question (D1_CORE_SPEC §11
   Q1: anonymous-session votes) resolved before any network deployment —
   the component posture doc must say so, or the contribution story
   overclaims.
5. **No decision the Architect was asked for is being declined.** D1–D5
   are all decidable on current evidence; the five verdicts above stand.
   The D1-core spec's five open questions (§11) remain the lead's queue —
   the Architect's recommended dispositions are: Q1 bind a self-asserted
   principal name at login with honest-limits labeling (don't block
   D1-core); Q2 default `max_hops: 1`; Q3 veto is terminal, no override;
   Q4 yes, require registry-known delegatees when a registry is
   configured; Q5 core owns the marker, bridges only call it.

*End of ADJUDICATIONS.md — wave-23 entries A12–A16 decided. Awaiting lead
review; implementation dispatch follows lead sign-off.*
