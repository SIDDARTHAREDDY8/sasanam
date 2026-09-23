# Registration Authority — Reference Design (Wave-68, Q3)

**Status: design-doc only (2026-09-22). No code — this is the
deployment-side companion to the in-repo `ConsumerRegistry`
(wave-67, `workstreams/evals/CONSUMER_REGISTRY.md`).**

The wave-67 mechanism answers *how* a token is issued and verified.
It does not answer *who may register whom*: in-repo,
`ConsumerRegistry.register_consumer()` is callable by any in-process
code, which is correct for a test stand-in and wrong for a deployment.
The registration authority is the deployment-side service that binds
consumer registrations to real identities. This document is the
reference design for it — shapes a deployment can adopt, with every
deployment-choice dependency marked **[DEPLOYMENT CHOICE]**.

Non-goal: this is not the commercial pipeline (metering, billing, SaaS
export service — out of build order per the founder's evidence bet
sequencing). It hardens the evidence the enforcement core already
produces.

---

## 1. Authority placement and integration shapes

The registration authority is deployment-scoped infrastructure, owned
by the deployment operator, *outside* any evidenced run. The executor
never issues tokens (wave-67 §a: a run minting its own evidence tokens
is self-attestation with extra steps).

Two reference shapes; a deployment picks one (or a hybrid), marked
**[DEPLOYMENT CHOICE]**:

### Shape A — Operator console (human-in-the-loop issuance)

- A small admin surface (web console or CLI) where a named operator
  approves each registration request. The console calls the
  authority's issuance API; the console itself authenticates operators
  via the deployment's existing SSO/MFA.
- Fit: small deployments, regulated environments, or any deployment
  where "who acknowledged" must trace to a human-approved onboarding.
- Cost: issuance latency is human-scale (minutes–hours); not suitable
  for ephemeral per-task consumers.

### Shape B — IAM / workload-identity integration (machine issuance)

- The authority trusts an existing identity plane (cloud IAM,
  Kubernetes service accounts, SPIFFE/SPIRE, corporate directory) and
  issues consumer tokens to workloads that present a valid identity
  token from that plane. The mapping "identity → consumer_id" is a
  deployment-owned allowlist, not self-asserted.
- Fit: large fleets of agents/services where human approval per
  consumer is infeasible.
- Cost: the authority's trust root is only as strong as the IAM
  plane (see §6, compromised IAM).

Both shapes sit behind the same interface the in-repo
`ConsumerRegistry` models: `register_consumer(consumer_id, ttl_s)`,
`verify(token, consumer_id)`, `revoke(public_id)`,
`is_revoked(public_id)`. **[DEPLOYMENT CHOICE]**: which shape, what
identity plane, and the exact issuance API surface are deployment
decisions this repo cannot make.

## 2. Onboarding flow

```
request → identity proof → approval → issuance → audit record
```

1. **Request.** A requester (human operator or workload) asks for a
   registration naming a `consumer_id`. `consumer_id` MUST be
   authority-assigned or allowlist-checked, never free-form
   self-asserted at this layer — self-assertion is the gap wave-67
   closed.
2. **Identity proof.** **[DEPLOYMENT CHOICE]** What counts as proof is
   deployment policy. The reference minimum:
   - Shape A: the requester's SSO identity + MFA at approval time, and
     a recorded business justification (ticket, change record).
   - Shape B: a valid identity token from the trusted plane
     (e.g. signed service-account token) whose subject maps to the
     requested `consumer_id` via the deployment allowlist.
   - Either shape: proof of *control* of the consumer (not just of the
     requester) where the consumer is a distinct workload.
3. **Approval.** **[DEPLOYMENT CHOICE]** Who approves:
   - Shape A: a named human operator with the `registrar` role;
     four-eyes (two operators) for `consumer_id`s that touch
     sensitive flows **[DEPLOYMENT CHOICE: threshold policy]**.
   - Shape B: policy-as-code — approval is automatic iff the identity
     proof validates against the allowlist; the allowlist itself is
     changed only via the Shape-A human path (the allowlist is the
     trust root; changing it is a privileged act).
4. **Issuance.** The authority mints the token (in-repo: HMAC-bound
   `ConsumerToken`; a real deployment may use its own token format
   behind the same verify semantics **[DEPLOYMENT CHOICE]**),
   optionally with `ttl_s`. Default TTL: short for workloads
   (hours), longer for human-operated dashboards **[DEPLOYMENT
   CHOICE]**.
5. **Audit record.** Issuance writes to the authority's own audit log
   (see §5) BEFORE the token is usable — a token with no issuance
   record is a finding, not an edge case.

## 3. Revocation UX

- **Who can revoke** **[DEPLOYMENT CHOICE]**: the registrar role
  (Shape A), the owning workload's identity via a self-revoke API
  (Shape B), and an automated path — the deployment's incident
  response runbook revokes tokens when a consumer is suspected
  compromised. Revocation of *another* consumer's token is always a
  privileged act, never self-service.
- **How fast revocation propagates to `verify()`:** `verify()` checks
  the revoked set on every call — there is no cache in the in-repo
  reference, so propagation is immediate *within one authority
  instance*. **[DEPLOYMENT CHOICE]**: a real deployment with
  replicated verifiers must define the revocation-propagation SLA
  (push vs. poll, max staleness). The reference requirement: the SLA
  is documented, monitored, and the staleness window is part of the
  auditor's validity-at-time story (§5, wave-68 lane 1).
- **UX shape:** revoke is one action (console button / API call /
  runbook step) naming the public `token_id`; unknown ids are a
  silent no-op (idempotent, wave-67). Revocation NEVER rewrites
  history: already-chained ack records keep their
  `attribution: "authenticated"` mark with `token_id` + `ts`
  (validity-at-time, pinned by wave-68 lane 1).
- **Emergency brake** **[DEPLOYMENT CHOICE]**: a "revoke all tokens
  for consumer X" and a "suspend the authority's issuance" control
  for incident response. Suspending issuance must not break
  verification of already-issued tokens (reads keep working; only
  new registrations stop).

## 4. Verification-side wiring (what the run sees)

- The run-side executor receives a *verify-only* handle: it can call
  `verify()` and `is_revoked()` but never `register_consumer()`
  (no mint power in the evidenced run — wave-67 §a).
- The registry's mint secret lives in the authority's custody, never
  in run dirs, logs, or the executor's reachable scope.
  **[DEPLOYMENT CHOICE]**: HSM/KMS-backed custody is the reference;
  the in-repo 256-bit in-process secret is the test stand-in.
  (Standing priority from MEMORY: prod KMS key management, remove
  dev-key fallback.)
- Clock: the registry's `now` is injectable in-repo; a deployment
  binds it to a trustworthy clock **[DEPLOYMENT CHOICE]** — TTL and
  validity-at-time are only as honest as the clock.

## 5. Audit of the registry itself

The registry's own actions need evidence too — an authority that
issues tokens off the books is a laundering machine. Reference
requirements:

- **Every** `register_consumer`, `revoke`, allowlist change, and
  role grant/revoke appends to the authority's own append-only,
  hash-chained audit log: `{ts, actor, action, consumer_id,
  token_id, justification_ref}`. The actor is the authenticated
  operator/workload identity from §2 — self-asserted actor names are
  not accepted here.
- The authority's log is chained independently of any single run's
  action log (it outlives runs), and its verification key/epoch is
  operator-managed (same F29/F32 honesty rules as run logs: the
  export states its key status loudly).
- Cross-check for auditors: every `token_id` appearing as
  `attribution: "authenticated"` in a run's evidence export MUST
  have a matching issuance record in the authority log; a token_id
  with chained acks but no issuance record is evidence of forgery
  or of an authority bypass — a finding. (Wave-68 lane 1 gives the
  auditor `token_id` + `ts`; this is what the `ts` is *for*.)
- Retention **[DEPLOYMENT CHOICE]**: the authority log outlives the
  longest token TTL plus the auditor's lookback window.

## 6. Threat model

| Threat | What breaks | What stays standing |
|---|---|---|
| **Rogue operator** (registrar issues a token to an attacker's consumer) | Future acks from that consumer verify as `authenticated` — the evidence lies about *who*, while staying internally consistent. | The issuance is IN the authority audit log (§5) naming the rogue operator and the justification ref — detectable by audit, not preventable by mechanism. Four-eyes on sensitive registrations (§2) raises the bar to collusion. Already-chained records are untouched (append-only). |
| **Compromised IAM** (Shape B: attacker mints identity tokens from the trusted plane) | Attacker self-issues consumer tokens; same evidence-integrity loss as rogue operator, at machine speed. | The authority audit log still records each issuance (detectable); the allowlist-change path (Shape-A human) is NOT compromisable via the IAM plane alone — the trust root for *who may be a consumer* stays standing. Emergency brake (§3) revokes by consumer. |
| **Registration-authority outage** (issuance/verify endpoint down) | New registrations stop; `verify()` fails closed if verifiers cannot reach revocation state — acks during the outage cannot be authenticated (they stay honestly `unattributed`; tokens are never mandatory — Wave-49 lesson). | Already-chained evidence stays verifiable (hash chain + key epoch are self-contained in the run dir). No silent degradation: `verify()` raising loud is the designed behavior, not a bypass. Reads of the authority audit log keep working if it is replicated **[DEPLOYMENT CHOICE]**. |
| **Stolen consumer token** (Bearer <redacted> exfiltrated, used under the bound name) | Attacker's acks verify as `authenticated` for the bound consumer — the F59-class in-process-theft residual, documented in wave-67 §d. | Cross-name use fails (bound-id check); revocation kills future use immediately (§3); the theft is bounded by TTL; the authority audit log shows issuance, the run log shows the acks — the blast radius is enumerable. |
| **Forged token / bit-flip** | Nothing: constant-time MAC verification refuses loud (pinned by wave-67 probes). | — |
| **Authority audit log tampered** | The cross-check (§5) degrades — issuance records can be hidden. | The authority log is hash-chained under an operator-managed key with F29-loud key status; tampering is detectable by chain verification, same as run logs. Key custody is the residual **[DEPLOYMENT CHOICE: HSM/KMS]**. |

## 7. Deployment choices this repo cannot make (consolidated)

- Shape A vs. B vs. hybrid; the trusted identity plane (SSO, IAM,
  SPIFFE, directory).
- What counts as identity proof; who holds the `registrar` role;
  four-eyes thresholds.
- Token format beyond the in-repo HMAC reference; TTL defaults;
  revocation-propagation SLA for replicated verifiers.
- Mint-secret custody (reference: HSM/KMS — a standing repo
  priority); the trustworthy clock source.
- Authority audit-log retention, replication, and verification-key
  management.
- The emergency-brake policy and who may pull it.

Everything else in this document is mechanism the repo already pins
(wave-67) or exports (wave-68 lane 1). The authority is the trust
anchor the evidence bet stands on: the export proves *what happened*;
the authority's audit log proves *who was allowed to claim it*.
