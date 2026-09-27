# Prospectus Lane: CLOUD VENDORS (AWS · Azure · GCP)

**Lane owner:** Krishna (subagent d9de52fa) · **Date:** 2026-09-26
**Scope:** public repos from AWS (`aws`, `awslabs`, `cedar-policy`), Azure (`Azure` — policy enforcement, confidential-computing attestation, workload/agent identity; framework/orchestration excluded — `microsoft/agent-governance-toolkit` and AutoGen already covered by sibling lanes), GCP (`GoogleCloudPlatform`, `googleapis`, `google`).
**Method:** GitHub REST API maturity stats + shallow `--filter=blob:none` clones to `/tmp/cloud-*` (one repo inspected via recursive tree API after a clone hit /tmp capacity). $0 spend. Primary sources only — all file pointers are repo-relative paths verified in-clone unless noted.

## Org inventory (repos touching agent control, identity, policy, or evidence)

| Repo | What it is | Stars | License | Last push | Notes |
|---|---|---|---|---|---|
| `cedar-policy/cedar` | AWS's authorization policy language + embeddable engine (Rust) | 1,748 | Apache-2.0 | 2026-09-25 | **Top find.** Powers Amazon Verified Permissions |
| `spiffe/spire` | Workload-identity control plane: attests workloads, mints X.509/JWT SVIDs | 2,558 | Apache-2.0 | 2026-09-26 | **Top find.** CNCF graduated; node attestors for AWS/Azure/GCP |
| `GoogleCloudPlatform/stet` | Encrypt/decrypt helper gating Cloud KMS key use on Confidential Space attestation | 40 | Apache-2.0 | 2026-09-11 | **Top find.** Attestation-gated key release pattern |
| `Azure/azure-workload-identity` | K8s→Entra federation: mutating webhook + IMDS-intercepting token proxy | 338 | MIT | 2026-09-23 | Credential-brokering pattern for sandboxes |
| `Azure/confidential-computing-cvm-guest-attestation` | C++ client lib + samples: fetch/parse SEV-SNP/TDX attestation reports on Azure CVMs | 83 | MIT | 2026-09-11 | Attestation-gated secret release sample |
| `google/go-tpm` | Go TPM 1.2/2.0 client: command marshalling, sessions, quoting | 673 | Apache-2.0 | 2026-06-02 | PCR-quote building block for external anchoring |
| `Azure/azure-policy` | Compliance-as-code definitions for Azure resources | 1,696 | MIT | 2026-09-20 | Deploy-time governance, not runtime agent enforcement — SKIP |

Notable non-fits (skipped): `2fastlabs/agent-squad` (ex-`awslabs/agent-squad` — left AWS org, pure orchestration framework, AutoGen-lane territory); `awslabs/*` agent samples generally (demos, no governance primitives); `aws/aws-iam-authenticator` (moved to kubernetes-sigs, K8s-only auth).

## Deep dives

### 1. `cedar-policy/cedar` — VERDICT: STEAL

**One line:** AWS's open-source authorization policy language and engine — separates policy-as-code from application code, evaluates `principal × action × resource × context → Allow/Deny` with deny-overrides semantics, and ships formal-verification tooling.

**Maturity:** 1,748 stars, pushed 2026-09-25 (actively maintained), Apache-2.0. Production-hardened: it's the engine behind Amazon Verified Permissions / Verified Access. Embeddable via Rust crate, WASM (`cedar-wasm/`), FFI, protobuf (`cedar-policy/proto/`), CLI (`cedar-policy-cli/`), and a language server (`cedar-language-server/`).

**Steal-worthy ideas:**

1. **The Request/Decision/Diagnostics API shape as our policy-engine contract.** `cedar-policy/src/api.rs:1116` — `Authorizer::is_authorized(&Request, &PolicySet, &Entities) -> Response`, where `Request` is exactly `{principal, action, resource, context}` (`api.rs:5100`) and `Response` is `Decision + Diagnostics` (`api.rs:1141`). Map directly onto our tool-call seam: principal = agent identity (SVID), action = tool name, resource = target artifact, context = `{amount, risk_tier, time_window, egress_bytes}`. `Diagnostics` carries the `PolicyId`s that contributed to the decision (`api.rs:1283`) — that is our auditor-readable "why": every allow/deny in the audit log cites the exact policy ids that fired, not just a boolean. Plugs into: fail-closed policy engine + evidence pipeline (decision receipts).
2. **`forbid` overriding `permit` as the fail-closed idiom.** Cedar's three evaluation rules — forbid wins, else permit wins, else implicit deny — are the cleanest expression of fail-closed we've seen in the wild, and `forbid` gives us a first-class "never, regardless of context" rule (destructive tools, exfil channels) that outranks any contextual permit. Our engine should adopt deny-overrides explicitly rather than ad-hoc ordering. Plugs into: policy engine semantics + break-first red-team policy tests.
3. **Policy templates + slots for per-agent goal scoping.** `PolicySet::add_template` / `template()` (`cedar-policy/src/api.rs:3047–3115`); template AST in `cedar-policy-core/src/ast/`. Parameterized policies instantiated per agent/tenant at registration time. This is the mechanism for goal registration → policy: when an agent registers a goal, mint a linked policy instance with bounded scope (allowed tools, max spend, data classes) rather than hand-writing YAML per agent. Plugs into: goal registration/conflict detection.
4. **Offline policy test harness as a break-first pattern.** The CLI ships `authorize`, `evaluate`, `validate`, `partial_eval`, `run_test` commands (`cedar-policy-cli/src/command/`) and symbolic analysis (`cedar-policy-symcc/`). Steal the workflow, not the code: policies are data that get unit-tested, property-tested, and formally checked *before* deployment — exactly our standing rule applied to the policy layer. Plugs into: pre-push gates for policy changes.

### 2. `spiffe/spire` — VERDICT: STEAL

**One line:** The workload-identity standard's reference control plane — attests nodes and workloads on any platform, then mints short-lived X.509 and JWT SVIDs (SPIFFE Verifiable Identity Documents) bound to a `spiffe://trust-domain/...` ID.

**Maturity:** 2,558 stars, pushed 2026-09-26 (very active), Apache-2.0, CNCF graduated, adopted widely. Cloud-native attestation out of the box.

**Steal-worthy ideas:**

1. **JWT-SVID as the agent identity document.** `pkg/server/api/svid/v1/service.go:157` (`MintJWTSVID`) — mints short-lived, audience-bound JWTs with `sub: spiffe://<trust-domain>/agent/<name>`. This is precisely the shape our agent identity layer needs: an auditor-verifiable, expiring identity doc, not a bearer API key. Adopt the claim shape (SPIFFE ID in `sub`, short TTL, `aud` scoping) and the mint-on-attestation flow; our approval queue and audit log then verify SVIDs instead of trusting self-asserted agent names. Plugs into: agent identity + human approvals + audit log.
2. **Cloud node attestors as the platform-trust root.** `doc/plugin_agent_nodeattestor_aws_iid.md`, `plugin_agent_nodeattestor_azure_msi.md`, `plugin_agent_nodeattestor_gcp_iit.md` — the agent host proves itself via cloud instance identity (AWS IID, Azure MSI/IMDS, GCP IIT) *before* it receives any identity. We should not invent our own host-attestation; the pattern is: platform attests host → workload attestor selects agent → SVID issued. Plugs into: sandbox/agent registration, artifact inventory (bind artifacts to attested agent IDs).
3. **Precedent for identity × policy-engine composition.** SPIRE's own API authorization is driven by an embedded OPA/Rego policy engine (`doc/authorization_policy_engine.md` — rego policy + JSON databindings, `result = {allow, allow_if_admin, …}`). The architecture we want — SPIFFE identity in, policy engine decision out — is already proven in their codebase. We mirror it with Cedar instead of Rego. Plugs into: overall architecture (identity layer → policy layer seam).

### 3. `GoogleCloudPlatform/stet` — VERDICT: STEAL

**One line:** Small Go tool that encrypts/decrypts with Cloud KMS *only after* presenting a Confidential Space attestation token through Workload Identity Federation — i.e., keys are released exclusively to workloads whose attestation claims match policy.

**Maturity:** 40 stars, pushed 2026-09-11 (active), Apache-2.0. Small and readable — a pattern reference, not a dependency.

**Steal-worthy ideas:**

1. **Attestation-gated key release as our key-custody endgame.** `docs/confidential_space.md` — STET swaps in WIP credentials (`confidential_space_configs` → `kek_credentials` → `wip_name`) so the KEK is usable only when the attestation token's claims satisfy the provider's attribute condition, e.g. `assertion.submods.container.image_digest == '<digest>' && assertion.swname == 'CONFIDENTIAL_SPACE' && '<sa>' in assertion.google_service_accounts`. This is the honest production answer for our KMS adapter (`gov/kms_vault.py`): archive the attestation token alongside every key use, and the evidence artifact becomes "this key was releasable *only* to this measured workload." Steal the claim vocabulary verbatim — it's the auditor's language for external anchoring. Plugs into: key custody + evidence pipeline (attestation token per key-use receipt).
2. **Claim-vocabulary for workload identity.** The attestation JWT's `submods.container.image_digest`, `swname`, `hwmodel`, `dbgstat` fields are a ready-made schema for binding an agent sandbox's measured boot to its identity. Plugs into: artifact inventory / sandbox attestation.

### 4. `Azure/azure-workload-identity` — VERDICT: STUDY

**One line:** Kubernetes-to-Entra workload identity federation: a mutating webhook injects projected OIDC tokens, and a proxy transparently swaps them for Azure tokens at the IMDS endpoint.

**Maturity:** 338 stars, pushed 2026-09-23 (active), MIT.

**Steal-worthy ideas:**

1. **The IMDS-intercepting credential broker.** `pkg/proxy/proxy.go` — intercepts `169.254.169.254/metadata/identity/oauth2/token` and exchanges the projected token server-side (`golang.org/x/sync/singleflight` for token caching in the same file). The pattern: agents never hold credentials; they call a brokered endpoint and get short-lived scoped tokens. Our sandbox executor should look like this — the agent's "credential request" is intercepted/brokered by the governance layer, which mints narrowly-scoped creds per tool call and logs the grant. Study the proxy, reimplement the pattern in our executor. Plugs into: sandboxing + authorized-channel exfil defense (creds can't be exfiltrated if the agent never sees them).
2. **Federated-token projection via webhook** (`pkg/webhook/`) — identity injection at admission time. Relevant when our agents run on K8s; for now, pattern only.

### 5. `Azure/confidential-computing-cvm-guest-attestation` — VERDICT: STUDY

**One line:** C++ client library and samples for fetching and parsing hardware attestation reports (SEV-SNP/TDX) inside Azure confidential VMs, plus a secrets-provisioning sample.

**Maturity:** 83 stars, pushed 2026-09-11, MIT. File pointers verified via GitHub recursive-tree API (clone to /tmp failed on space; tree listing retrieved instead).

**Steal-worthy ideas:**

1. **Attestation report field vocabulary.** `client-library/src/Attestation/AttestationClient/lib/HclReportParser.cpp` (+ `AttestationClient.cpp`) — parses the HCL report: chip ID, measurement registers, VMPL. Take the field list as the schema for our own attestation evidence records; don't port the C++.
2. **Attestation-gated secret release, Azure flavor.** `azure-protected-vm-secrets/SecretsProvisioningLibrary.cpp` — releases secrets to the guest only after validating the attestation report. Same pattern as STET; useful as a second primary source that the pattern is cloud-vendor-blessed on both GCP and Azure. Plugs into: evidence pipeline design docs.

### 6. `google/go-tpm` — VERDICT: STUDY

**One line:** Go client for TPM 1.2/2.0 — command marshalling, sessions, key management, quoting.

**Maturity:** 673 stars, pushed 2026-06-02, Apache-2.0.

**Steal-worthy ideas:**

1. **TPM quotes as the external-anchoring primitive.** `tpm2/tpm2.go` — `Quote`/`QuoteResponse` implement `TPM2_Quote` (line ~869): a TPM-signed statement over PCR values, i.e., a hardware-signed measurement of what booted. `tpm2/pcrs.go` covers PCR selection/reading. If we ever anchor agent-sandbox integrity to hardware, this is the produce side; the verify side needs a counterpart (e.g. `google/go-attestation` event-log verification). For now: record the entry points; our near-term external anchoring is attestation tokens (STET/Azure pattern), TPM quotes are the deeper hardware root. Plugs into: external anchoring (roadmap), sandbox boot evidence.

## Verdict summary

| Repo | Verdict | The one thing to take |
|---|---|---|
| `cedar-policy/cedar` | **STEAL** | Request/Decision+Diagnostics contract; `forbid`-overrides-`permit`; policy templates per registered goal |
| `spiffe/spire` | **STEAL** | JWT-SVID claim shape (`sub: spiffe://…/agent/…`, short TTL, aud-bound) + cloud node-attestor pattern |
| `GoogleCloudPlatform/stet` | **STEAL** | Attestation-gated key release; claim vocabulary (`image_digest`, `swname`) for key-custody evidence |
| `Azure/azure-workload-identity` | STUDY | IMDS-intercepting credential broker — agents never hold creds |
| `Azure/confidential-computing-cvm-guest-attestation` | STUDY | HCL report field vocabulary; second source for attestation-gated secret release |
| `google/go-tpm` | STUDY | `TPM2_Quote`/`QuoteResponse` entry points for hardware-rooted sandbox evidence |
| `Azure/azure-policy` | SKIP | Deploy-time compliance-as-code; not runtime agent enforcement |

## Cross-cutting note

The cloud vendors have converged on one architecture, three times independently: **platform attests the workload → identity is minted on attestation → a policy engine decides → the decision and the attestation are the evidence.** (SPIRE: node attestor → SVID → OPA engine. STET: Confidential Space token → WIP attribute condition → KMS release. Azure: CVM report → validated attestation → secret release.) Our build should name and copy that pipeline explicitly: attested identity in, Cedar decision out, attestation + policy IDs archived per decision. That is the evidence product.
