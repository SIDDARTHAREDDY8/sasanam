# Agent identity and discovery — prospectus

**Wave-318 lane 5 · research only · $0 spend · public sources only · 2026-10-04**
**Base:** `c5c95ae3` (wave-317 merge). Mission: prospect the agent-identity/discovery frontier for the
next build direction — (1) how top-company agent frameworks do agent identity and discovery
(SPIFFE/SPIRE revisited; Microsoft agent-governance-toolkit; OpenAI guardrails; the MCP authorization
profile; Google A2A), (2) capability discovery and least-privilege grant negotiation, (3) revocation
and rotation of agent credentials at fleet scale.

Method: three parallel research agents against **primary sources** (specs, RFCs, official changelogs,
LICENSE files read verbatim, vendor docs, postmortems), cited claims, STEAL/ADAPT/WATCH/SKIP verdicts
per source, license checks (Apache-2.0/MIT preferred; traps flagged). Raw inputs preserved in
`~/workspace/teams/wave318-prospect/inputs/`.

Headline: **no single framework delivers attested agent identity plus discovery.** The evidence
supports a composition: **SPIFFE SVIDs (attested identity, short-lived, federated) + A2A Agent Cards
(discovery, signed) + MCP's OAuth 2.1 authorization profile (audience-bound, no token passthrough) +
RAR's `authorization_details` grammar (least-privilege negotiation) + capability-token semantics
(delegation/attenuation) + expiry-as-revocation with short TTLs (fleet rotation).**

---

## 1. Agent identity frameworks

### 1a. SPIFFE / SPIRE — STEAL

SPIFFE is the identity *model*; SPIRE is the reference implementation (Go). A SPIFFE ID is a URI —
`spiffe://<trust-domain>/<path>` — naming a workload. The credential proving it is an **SVID**
(SPIFFE Verifiable Identity Document): **X.509-SVID** (short-lived cert with the SPIFFE ID in the URI
SAN, default ~1h TTL, auto-rotated, for mTLS) and **JWT-SVID** (short-lived signed JWT for
app-level auth/OIDC federation). Workloads fetch SVIDs from the local SPIRE Agent over a
unix-domain-socket Workload API, bootstrapping with **no secret** — the agent attests the calling
process first. Attestation is two-level (node: cloud instance docs, K8s projected SA token, TPM,
join token; workload: PID→uid, K8s service account/pod labels/container image digest, docker
labels); registration entries map selector sets to SPIFFE IDs. Federation: nested SPIRE (root→
region→cluster CA chains) and cross-trust-domain federation via trust-bundle exchange; an OIDC
discovery endpoint lets cloud IAM accept JWT-SVIDs as federated tokens.
([spiffe.io concepts](https://spiffe.io); [Unit42](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/))

**Current version.** v1.15.3 (1.15.0 May 2026; 1.15.2 2026-07-09; 1.15.3 ~Aug 2026). Notable 2025–26
additions: **SPIFFE Broker endpoint/API** (1.15.2), **HashiCorp Vault Key Manager plugin** (1.15.0),
per-caller rate limiting on the Workload API, `azure_imds` node attestor (1.14.0), docker
`image_config_digest` selector, WIT-SVID work in progress, PQC curves, cgroup-attestation hardening
(1.14.0). Security fix in 1.15.1 corrected `azure_imds` PKCS7 signer validation (forged attested
documents could impersonate an arbitrary VM).
([spiffe/spire CHANGELOG](https://github.com/spiffe/spire/blob/HEAD/CHANGELOG.md); [v1.15.3 release](https://github.com/spiffe/spire/releases/tag/v1.15.3))

**Unit42 2026-09 selector-spoofing — VERIFIED, and it is the load-bearing caution.** Unit42's "The
Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE" (2026-09-10,
[unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/))
demonstrated that **root on a Kubernetes node is enough to impersonate every workload the node's
SPIRE agent may attest**: the attacker spoofs cgroup metadata the agent reads during workload
attestation, so their process looks like a co-located container, then the agent issues the victim's
SVID over the Workload API. Key qualifiers straight from Unit42: **post-exploitation analysis, not
a vulnerability disclosure — no CVE**; **not observed in the wild**; it rests on the universal
design assumption that the node is trusted ("once an attacker gets root on that node… any workload
identity scoped to a node should be considered compromised"). Unit42 released **Spooffe**, an
open-source tool to test whether cgroup metadata on a node can be manipulated to retrieve co-located
workload identities. Mitigations: harden nodes, restrict root, prohibit privileged containers,
minimize reliance on weak selectors.

**License.** Apache-2.0 — verified verbatim from [github.com/spiffe/spire/blob/main/LICENSE](https://github.com/spiffe/spire/blob/main/LICENSE).

**What this answers for Sasanam.** The closest production-grade answer to attested agent identity
anywhere: secretless bootstrap, attested process identity, short-lived rotating credentials, and a
cross-org federation story (trust domains) mapping directly onto "discover + verify agents outside
my org." **SVID ≠ authorization**: a valid SVID answers "who," policy answers "what it may do."
→ **STEAL the SPIFFE identity model** (SPIFFE IDs, SVID issuance/rotation semantics, trust-domain
federation) as the attested-identity layer; integrate with SPIRE where deployed. Carry the
Unit42 caveat into the design: the governance layer must **never treat a presented SVID as proof of
node integrity**, and must pin identity grants to strong selectors (image digest, TPM-anchored node
attestation) with short TTLs.

### 1b. Microsoft agent-governance-toolkit — STEAL

`github.com/microsoft/agent-governance-toolkit` exists (public preview, ~6.3k stars,
Python/.NET/TypeScript/Rust/Go SDKs; launched 2026-04-02 via Microsoft Open Source blog).
**LICENSE is MIT** — verified verbatim from
[github.com/microsoft/agent-governance-toolkit/blob/main/LICENSE](https://github.com/microsoft/agent-governance-toolkit/blob/main/LICENSE).

Identity story: "Secure an agent fleet" tutorial path includes **Tutorial 02 — Trust & Identity:
agent identity with SPIFFE**; identity layer `agent-mesh` with DID-based identity plus an **Entra
Agent ID bridge** (Tutorial 31: bridges DID identity with Entra Agent ID, Conditional Access,
sponsor accountability), an **identity attestation evidence model** (v3.5.0, 2026-05-06), and
Entra-signed JWT mesh verification. Cautionary detail: the DID method is **split** — Python+.NET
use `did:mesh:*` while TS+Rust+Go use `did:agentmesh:*`; `docs/LIMITATIONS.md` §9 flags an
initialization-bypass/default-allow risk.

**Advisory layer that can only tighten — CONFIRMED from primary sources.** PR #1390
([commit b50b1b7](https://github.com/microsoft/agent-governance-toolkit/commit/b50b1b7df6ffe70708b4920d0463451b11a68618),
2026-04-23): "Add non-deterministic advisory checks that run AFTER deterministic policy rules pass.
**Can only tighten (block/flag) — never loosen.** Failures default to allow (deterministic layer is
canonical)." Classifiers: CallbackAdvisory, HttpAdvisory, PatternAdvisory (regex:
jailbreak/PII/injection), CompositeAdvisory; runs only after deterministic rules return allow;
cannot override a deterministic deny; all advisory decisions logged with `deterministic=false`.
([issue #1377](https://github.com/microsoft/agent-governance-toolkit/issues/1377))

**Decision BOM — CONFIRMED.** Tutorial 50, `DecisionBOMReconstructor`
([PR #1783](https://github.com/microsoft/agent-governance-toolkit/pull/1783)): reconstructs full
decision context from observability signals, with 4 signal-source protocols (AuditSource,
TrustSource, PolicySource, TraceSource), progressive completeness scoring (60%→100%), field
categories **identity, trust, policy, action, context, outcome, lineage**, batch reconstruction,
JSON export. ADR-0018 deliberately chose "Reconstructible Decision BOM over pre-built."
([PR #2377](https://github.com/microsoft/agent-governance-toolkit/pull/2377))

→ **STEAL** both: (1) the advisory-only-tightens-after-deterministic-allow layering (cheap,
directly hardens the enforcement core's classifier seams); (2) the reconstructible Decision BOM
(field categories + completeness scoring liftable into the decision-packet/evidence work). Do NOT
steal their DID identity scheme — the `did:mesh:*`/`did:agentmesh:*` split and Public Preview churn
make it a cautionary tale.

### 1c. OpenAI Agents SDK / guardrails — SKIP

What exists: "guardrails" are input/output/tool validation functions with tripwires
(`InputGuardrailTripwireTriggered` halts the run). Identity is **API keys / project-scoped service
accounts, full stop** — application API keys with scopes, per-project keys with spend limits and
(since Sept 2026) expiration dates; "the project is the only isolation primitive."
What is **genuinely absent**: no attested agent identity, no agent-to-agent authentication, no
delegation primitive; sessions are conversation-memory backends, not identities. Third parties fill
the gap (e.g. Portkey's per-agent virtual keys); the security community's critique — scoping
limits what a stolen key can do but "says nothing about why an AI agent is holding a durable
enterprise credential" — is the argument for Sasanam's sentinel-credential-substitution direction.

→ **SKIP.** Nothing to steal; the SDK's tripwires are a less expressive version of Sasanam's
existing enforcement core. **The strategic note:** OpenAI's own stack has no attested agent
identity, so a governance layer that provides it is filling a real, vendor-neutral gap.

### 1d. MCP (Model Context Protocol) authorization — ADAPT

Spec status: current revision **2026-07-28**; governance moved to the **Agentic AI Foundation
(Linux Foundation)** in December 2025. The authorization spec is an **OAuth 2.1 profile for HTTP
transports**: the MCP server is an OAuth 2.1 Resource Server, the client an OAuth 2.1 client, a
separate Authorization Server issues tokens (may be co-hosted; roles distinct). Normative points:
servers MUST publish **RFC 9728 Protected Resource Metadata**; clients MUST use it for AS discovery;
clients MUST send **RFC 8707 `resource`** indicators; servers MUST validate tokens on every request
and verify audience/resource; **token passthrough is explicitly forbidden** — "MCP servers MUST NOT
accept or transit any other tokens" (the confused-deputy fix); Dynamic Client Registration
deprecated in favor of Client ID Metadata Documents; step-up authorization via `WWW-Authenticate`
scope challenges; PKCE for interactive clients; opt-in OAuth Client Credentials extension
(`io.modelcontextprotocol/oauth-client-credentials`) with `private_key_jwt` for machine clients.
**Agent→agent authentication: absent.** MCP is strictly one hop, client→server — "there is no notion
of a server acting for an upstream principal, no signed results."
([modelcontextprotocol.io/specification/2026-07-28/basic/authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization))

Adoption caveat: Astrix Security survey of ~5,200 servers found only **8.5%** use OAuth while 53%
still use static API keys; Trend Micro found 492 internet-exposed MCP servers with zero
authentication; 30+ CVEs filed against MCP components in Jan–Feb 2026.

**License — correction to the prior record.** MCP is **NOT plain MIT anymore**: the LICENSE file
states the project "is undergoing a licensing transition from the MIT License to **Apache
License, Version 2.0**." New contributions are Apache-2.0; contributions whose authors haven't
granted relicensing consent remain MIT; docs (excl. specs) are CC-BY-4.0. Copyright: "Model
Context Protocol a Series of LF Projects, LLC." Apache-2.0-compatible either way, but the patent
grant only attaches to the Apache-2.0 portions.

→ **ADAPT.** Don't lift code (mixed license, low real-world compliance). Adopt the *pattern*:
resource-server/audience-bound bearer tokens (RFC 8707), mandatory protected-resource metadata
discovery, and the explicit "never pass through a token; obtain a separate upstream token" rule —
the confused-deputy doctrine Sasanam's tool-proxy and delegation seams should encode. MCP answers
"how does a client authenticate to a tool server"; it does not answer agent identity.

### 1e. Google A2A (Agent2Agent) — ADAPT (discovery) / WATCH (auth)

v1.0 shipped (1.0.0 2026-03-12; 1.0.1 2026-05-28); donated by Google to the **Linux Foundation**
(June 2025); `a2aproject` on GitHub; 150+ supporting orgs. **Agent Cards** (discovery): canonical at
`GET https://<base>/.well-known/agent-card.json` — declares identity (`name`, `description`,
`version`, `provider`), `supportedInterfaces`, `capabilities`, `defaultInputModes/OutputModes`,
`skills[]` (id, name, description, tags, examples), auth fields; cards **can be signed (JWS)**;
verification recommended when signatures present. **Auth fields**: `securitySchemes` (OpenAPI-style:
`apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTLS`) + `securityRequirements`. Credential
acquisition is **explicitly out of band** — the protocol declares pointers, not a handshake.
**The identity gap (honest negative):** "An Agent Card cannot serve as a credential. A card is
public; presenting one proves nothing about who is presenting it." A2A gives agents a *business
card* (discovery) but not a *passport* (attested identity).

→ **ADAPT the Agent Card schema and well-known-path convention** as the agent-discovery format
(with card signatures as the integrity story); **WATCH the auth half**, which is declaration-only.
The coherent synthesis: **A2A card for discovery + SPIFFE SVID for authentication** — and
Microsoft's toolkit already bridges both worlds (A2A/MCP bridges + SPIFFE identity tutorials).

| Framework | Identity story | Discovery story | License | Verdict |
|---|---|---|---|---|
| SPIFFE/SPIRE (v1.15.3) | Attested workload identity: SVIDs, attestation, trust-domain federation | Trust bundles / federation (no card-style directory) | Apache-2.0 ✓ | **STEAL** (attested-identity model; carry Unit42 caveat) |
| Microsoft agent-governance-toolkit | SPIFFE + DID + Entra Agent ID bridge; attestation evidence model | A2A/MCP bridges; Decision BOM for audit | MIT ✓ | **STEAL** (only-tighten layering; reconstructible Decision BOM; skip their DID scheme) |
| OpenAI Agents SDK / guardrails | None — API keys / project service accounts | None | n/a | **SKIP** (the gap itself is the opportunity) |
| MCP auth (spec 2026-07-28) | None — OAuth 2.1 RS/AS profile, one hop only | None | **MIT→Apache-2.0 mixed** (verify per-file) | **ADAPT** (audience-bound tokens, metadata discovery, no-token-passthrough) |
| Google A2A (v1.0.1) | None — declares `securitySchemes`, credentials out-of-band | Agent Cards at `/.well-known/agent-card.json`, JWS-signable | n/a (spec) | **ADAPT** card schema; **WATCH** auth half |

---

## 2. Capability discovery and least-privilege grant negotiation

No single protocol does both discovery and negotiation. The reusable **discovery** patterns:
AS/RFC-8414-style metadata advertising supported types (RAR, UMA `/.well-known/uma2-configuration`,
GNAP metadata), and resource-set registration (UMA RSR). The reusable **negotiation** patterns:
typed access-request arrays (GNAP `access`, RAR `authorization_details`), self-attenuation
(UCAN/Biscuit), and verifier-driven minimal disclosure (OpenID4VP/DCQL).

### 2a. UCAN — ADAPT

Self-contained public-key-signed delegation tokens: `iss`, `aud`, `att` (capabilities as
`{with: <resource URI>, can: <ability>, nb: <caveats>}`), `prf` (parent proofs), `exp`/`nbf`.
Delegation = audience signs a new UCAN referencing the parent in `prf`; every hop must be
equal-or-narrower (attenuation); chain root must be the resource owner; `aud` must match the
presenting caller — verification entirely local, no authorization server call. 1.0 spec split into
Main/Delegation/Invocation/Container; **Revocation and Promise are not yet implemented** in the
reference Go library. Limitations: no built-in discovery protocol; caveat/verb vocabulary is
per-application (no shared capability vocabulary across vendors); chain bloat; ecosystem is
web3-storage/Storacha-centric. License: **dual Apache-2.0 OR MIT** ✓.

→ **ADAPT**: steal the capability object shape (`with`/`can`/`nb`) and the chain-of-proofs
verification discipline (root-owner anchor, equal-or-narrower hop rule, audience binding) as the
pattern for Sasanam's delegation-of-grant. Don't adopt the wire format — no shared capability
vocabulary exists for our tools.

### 2b. zcap-ld / Authorization Capabilities — WATCH

W3C Credentials **Community Group draft v0.3** (not a Recommendation): JSON-LD capability objects
with `controller`, `invoker`, `parentCapability`, `allowedAction`, caveats, `capabilityChain`;
next version intends to drop JSON-LD for JCS signatures. Semantically the closest to Sasanam's
existing capability thinking (delegation chains + caveats + invocation binding), but
implementations are immature (zcap-py, pyzcap "not suitable for production"). No discovery
standard; revocation is client-managed lists.

→ **WATCH** for the JSON-LD-free v1 and a production implementation.

### 2c. Macaroons — SKIP

Google's nested chained-HMAC construction: each caveat computes `HMAC(previous_sig, caveat)`; caveats
can only ever reduce authority; third-party caveats add discharges from other principals.
Attenuation is cheap (microseconds). **Disqualifier**: the verifier must know the root key (HMAC is
symmetric) — every independent tool server needs the shared secret; the exact key-management
burden UCAN/Biscuit avoid. Also: "there are no standard caveats"; no live agent-tooling ecosystem.

→ **SKIP.** Sasanam's own HMAC-chained audit already captures the chained-attenuation idea. Note
only the salvageable pattern: third-party caveats as "bring a discharge from another authority."

### 2d. Biscuit tokens (Eclipse Biscuit) — ADAPT

Bearer tokens on **public-key crypto (Ed25519/P-256)** + a **Datalog authorization language**:
authority block (signed by root key — base rights), then attenuation blocks anyone holding the
token can append that can *only restrict* via Datalog `check` queries; the verifier's own
`allow`/`deny` policies are evaluated by the Datalog engine — **every check in token and authorizer
must pass**. Protobuf-serialized. Implementations in Rust, Go, Java, Python, JS.
Limitations: no built-in revocation (deployments layer their own); the authorizer executes
attacker-supplied Datalog — needs evaluation budgets. License: **Apache-2.0** ✓ (Eclipse
Foundation project, but NOT EPL).

→ **ADAPT**: steal the authority-block + attenuation-block structure and the *verifier-side policy
+ token-side checks both must pass* semantics as the shape for Sasanam's grant envelopes. Don't
adopt the token format/dependency yet — keep Sasanam's native fail-closed policy engine as the
authorizer and express the same semantics in it; revisit direct adoption only if cross-org interop
demands the wire format.

### 2e. GNAP (RFC 9635) — WATCH

IETF Standards Track, October 2024. Client *instances* (no pre-registration; the client presents
a key in the first request that anchors later stages). Grant requests carry structured `access`
descriptors (typed objects with actions/locations/datatypes), `subject` info, declared interaction
modes; AS can return **pending** grants with a key-bound `continue` object; the client may later
**modify grants up or down or cancel them**. All AS-bound requests are key-signed
(proof-of-possession throughout). This is the only protocol here that is *negotiation-native*.
Limitations: still needs a shared Authorization Server (cross-org agent→tool has none); production
implementations thin (reference libs ~4 years stale); grants describe access rights, not intent —
no cryptographic binding to the specific approved action, no post-transaction evidence.

→ **WATCH.** Steal the `access`-array grammar (typed `{type, actions, locations, datatypes}`) and
the continue/modify-grant pattern for approval-queue UX; don't implement the wire protocol until
counterparties exist. Adopt the *moment* a second implementation speaks it.

### 2f. UMA 2.0 — SKIP (protocol) / note the pattern

Kantara Recommendation (2018): five roles, resource servers register resource sets at the AS,
permission tickets make the grant exactly as narrow as the attempted action, async policy-based
consent. Built for *human* owners and *human* requesting parties via a central AS — the
ticket round-trip (RS→AS→client→AS→RS) is too heavy for machine-speed agent→tool calls; no
shared AS in cross-org agent settings; agent-to-agent delegation not modeled.

→ **SKIP the protocol.** Keep the one contribution: **asynchronous policy-based consent** —
owner sets policy once, AS enforces without the owner online — which validates Sasanam's existing
human-approval-queue design as the right shape.

### 2g. OAuth 2.1 + RAR (RFC 9396) — ADAPT

OAuth 2.1 is still an Internet-Draft (draft-ietf-oauth-v2-1-16, Sept 2026; IESG milestone Dec 2026);
its security baseline is final: **RFC 9700, OAuth 2.0 Security BCP (Jan 2025)**. **RAR (RFC 9396)**
adds `authorization_details`: typed objects (`type` + `locations`, `actions`, `datatypes`,
`identifier`, `privileges` + API extensions); the AS returns the *granted* subset and advertises
supported types in AS metadata (`authorization_details_types_supported`). Keycloak 26+ ships RAR
support; a concrete `mcp_tool` type has already been sketched in the wild (`{type, tool, actions,
constraints, expires_in}`).
**Critical over-grant trap** (RFC 9396 §2.2): *"When different common data fields are used in
combination, the permissions the client requests are the product of all the values"* —
`actions:[read,write] × datatypes:[contacts,photos]` = 4 permissions, not 2. Fix is structural:
one object per (tool, resource) pair.
Limitations: still AS-centric; token opaque to client; RAR types need per-API agreement; adoption
early (banking/FDX-driven).

→ **ADAPT.** Adopt `authorization_details` as the *grammar* for Sasanam's grant requests and
approval-queue consent screens — including the AS-metadata advertisement pattern for tool
capability discovery and the **product-of-fields check as a mandatory validator**. This is the
pragmatic interop story for any OAuth-speaking tool a Sasanam agent touches.

### 2h. OpenID4VP / Verifiable Credentials — ADAPT

OpenID for Verifiable Presentations 1.0 (**Final**); the verifier requests a `vp_token`; the wallet
presents credentials matching a query expressed in **DCQL** (Digital Credentials Query Language)
or DIF Presentation Exchange. Primary format in the EU ecosystem: **SD-JWT VC** (selective
disclosure + holder key binding); W3C VCDM 2.0 became a Recommendation May 15, 2025. OpenID
Foundation opened conformance self-certification for OpenID4VP 1.0, OpenID4VCI 1.0, HAIP in **Feb
2026**. The verifier states exactly which claims it needs — **least-privilege disclosure is the
protocol's default**. Limitations: human-wallet-shaped today (QR flows); trust frameworks
(who is an acceptable issuer) are governance work the protocol doesn't solve; issuance side heavy
(Keycloak OID4VCI still experimental/preview in 26.x).

→ **ADAPT the verifier-driven DCQL query + selective-disclosure pattern** for any "agent proves
capability/identity claims to a tool" flow. Don't build a credential *issuance* program yet.

| Source | License | Verdict |
|---|---|---|
| UCAN | Apache-2.0 / MIT ✓ | **ADAPT** (capability object shape + chain-of-proofs discipline) |
| zcap-ld | CCG terms ✓ | **WATCH** (JSON-LD-free v1) |
| Macaroons | paper ✓ | **SKIP** (symmetric-verifier disqualifier) |
| Biscuit | Apache-2.0 ✓ (not EPL) | **ADAPT** (authority/attenuation block structure; verifier+token checks both pass) |
| GNAP (RFC 9635) | IETF terms ✓ | **WATCH** (adopt the moment a second implementation speaks it) |
| UMA 2.0 | Kantara royalty-free ✓ | **SKIP** protocol (note async policy-based consent) |
| OAuth 2.1 + RAR (RFC 9396) | IETF terms ✓ | **ADAPT** (`authorization_details` grammar; one-object-per-pair validator) |
| OpenID4VP / VC | OIDF IPR terms ✓ | **ADAPT** (verifier-driven selective disclosure) |

---

## 3. Revocation and rotation at fleet scale

The industry's converged answer is **not better revocation infrastructure — it is making revocation
mostly unnecessary**:

1. **Expiry-as-revocation**: credentials live minutes-to-hours (SPIRE 1h SVIDs, K8s 1h bound tokens,
   step-ca 24h certs), never years. The revocation window is bounded by TTL by construction.
2. **Rotation must be automatic and invisible**: SPIRE's streaming Workload API renews at ~50% TTL;
   the kubelet refreshes projected tokens at 80% of TTL; cert-manager renews at 2/3 of duration.
3. **Keep a kill-switch for the residual window**: SPIRE registration-entry deletion, `vault lease
   revoke -prefix`, overlapping CA rotation ceremonies.
4. **Trust-root rotation uses a TUF-style ceremony** (version-walk, threshold signatures, rollback
   rejection) — the only safe way to rotate a pinned anchor fleet-wide.
5. **Grant/authorization revocation (Zanzibar/OpenFGA/OPA) is a separate plane** with bounded,
   explicit propagation latency — defense in depth, never the credential-layer story.

Active revocation lost the web-PKI war: Let's Encrypt shut its OCSP responders on Aug 6, 2025;
Chrome dropped online OCSP checks in 2012; the CA/B Forum made OCSP optional. **The lesson for
agent fleets: don't build OCSP/CRL for task credentials — build short lifetimes plus automated
rotation.**

### 3a. SPIFFE/SPIRE SVID rotation — STEAL

SPIRE signs short-lived X.509-SVIDs (commonly 1h, configurable `default_x509_svid_ttl`; JWT-SVIDs
shorter, e.g. 5 min). The agent renews each SVID proactively at ~50% TTL and pushes it down the
streaming Workload API; client libs swap the new cert in-memory — no workload restart.
**Revocation is deliberately absent**: deleting a registration entry stops renewal, and an already-
issued SVID stays valid until it expires — **containment is only as fast as the TTL**. Kill-switches:
entry deletion (residual window = TTL); zero-downtime CA rotation (new CA added to bundle,
old+new both valid, reissue under new, drop old after old SVIDs expire); compromised-node handling
(ban the workload or rotate the CA — "extreme measure," invalidates all SVIDs). Federation:
trust domains exchange trust bundles over the SPIFFE Bundle Endpoint (`https_spiffe` profile pins
the peer server's SPIFFE ID); verification is "add their root CA to your trust list." Unverified
claim found in one third-party guide: a `revocation_enabled` CRL option in `spire-server.conf`
— **could NOT be confirmed in official SPIRE docs; treat as unverified** (open question §7.1).

→ **STEAL**: expiry-as-revocation with sub-hour TTLs, streaming rotation at 50% TTL,
entry-deletion kill-switch, overlap-style CA rotation. Federation's bundle-exchange model is the
template for cross-domain agent trust.

### 3b. step-ca / cert-manager — ADAPT

step-ca: certs 24h by default (host/service ≤1 month). **Passive revocation**: `step ca revoke`
blocks *future renewal* at the CA; the revoked cert stays valid until expiry — the explicit
tradeoff of avoiding centralized revocation checks. Active revocation: minimal OSS CRL server
(operators point relying services at it); advanced tiers use pull-model CRLs + on-demand OCSP.
cert-manager: renews at **2/3 of duration** by default; private-key rotation policy-driven; the
classic outage mode is "renewed but not reloaded" — pod serves the old cert because it read the
file at startup. CA rotation is a manual three-phase ceremony (bundle old+new, reissue, drop old).
Both Apache-2.0 ✓.

→ **ADAPT the patterns**: passive-revocation semantics (revoke = block re-issuance, residual
validity bounded by short TTL) map onto agent credential suspension; the 2/3-duration renewal
timing and overlap CA ceremonies are the rotation playbook. Don't adopt the tools as the agent
credential substrate (X.509/K8s-specific).

### 3c. OCSP stapling vs CRL — SKIP (as a mechanism)

The timeline: OCSP failed on three costs (extra round trip, CA-side privacy leak, soft-fail that
an attacker can block — "a seat belt that snaps when you crash"). CA/B Forum made OCSP optional
(Aug 2023); Let's Encrypt dropped OCSP URLs from certs (May 2025) and turned responders off
(**Aug 6, 2025**). Chrome uses CRLSets (since 2012); Firefox uses CRLite (default since 137,
April 2025) — revocation checked *locally* via distributed filters. The industry moved to 90-day,
then 6-day certs (Jan 2026), heading to a 47-day max by March 2029 — **revocation "wasn't fixed,
it was made to matter less."**

→ **SKIP** as a product mechanism for agent credentials. The consensus finding — *expiry-as-
revocation won* — is already captured in §3a.

### 3d. TUF root rotation — STEAL (confirms the existing verdict)

From the TUF spec: rotating any role key = publishing `root.json` **version N+1**, signed by a
threshold of the keys named in the *currently trusted* root (version N); clients walk versions one
at a time and **reject** a new root whose version isn't exactly N+1 (rollback protection); they
abort if the trusted root has expired (freeze protection); timestamp/snapshot keys are rotated in
the same metadata update. Convention: root expiry ≥1 year (reference 10 years) — root is re-signed
only by an offline threshold ceremony, so expiry bounds anchor lifetime rather than driving
cadence. Revocation semantics: "revoke *and* reissue in the same update," signed by old/remaining
keys. Spec text CC-BY-4.0; python-tuf Apache-2.0 ✓ (re-verify at adoption).

→ **STEAL** (already adopted by this project; this confirms the rotation-ceremony mechanics to
reuse: version-walk + threshold + N+1 rollback rejection + expiry-as-backstop) — the pattern for
rotating Sasanam's pinned trust roots without bricking the fleet. Directly relevant to the
wave-317 direction brief's planned `gov/trust_root_refresh.py`.

### 3e. HashiCorp Vault dynamic secrets / PKI — STEAL pattern, LICENSE CAVEAT

Every read mints a unique, short-lived credential bound to a **lease** with a TTL (e.g. a 1-hour
lease = Vault drops the DB role *at the database* after an hour). Clients renew at ~70% TTL.
Emergency response: `vault lease revoke -prefix/...` — the fleet kill-switch, invalidating at the
source. PKI engine: `/pki/revoke` by serial rotates the CRL; CRL config supports `auto_rebuild`,
delta CRLs, `cross_cluster_revocation`; OCSP responder built in; CRL *distribution* remains
out-of-band. Caveat: a 2026 OpenBao issue documents revoke *not* triggering CRL rebuild in some
configurations — test the propagation path, don't assume it.
**LICENSE CHECK (material, new):** HashiCorp Vault ≥1.14 is **BSL 1.1** — source-available, *not*
OSI open source, with competing-use restrictions. Not an acceptable dependency for an OSS product.
**OpenBao** is the Linux-Foundation-governed, API-compatible fork (Apache-2.0/MPL-2.0 per
community sources), drop-in for the Vault API including the PKI engine.

→ **STEAL the pattern** (already in project history): lease-bound dynamic credentials with enforced
TTLs + prefix-revocation kill-switch; PKI engine for internal issuance. **Adopt via OpenBao, not
HashiCorp Vault, for anything shipped in the product.**

### 3f. K8s bound service-account token projection — STEAL

TokenRequest API mints short-lived, audience-bound JWTs (default **1h**; range 10 min–1 year),
**bound to the pod's lifetime** — the token dies with the pod. Kubelet refreshes at **80% of TTL**
(or 24h, whichever first). Stable since K8s 1.20 (KEP-2799), replacing non-expiring Secret tokens.
**Audience scoping**: a token with `aud: kubernetes` must not be accepted by AWS STS and vice
versa; **empty/missing audience = "please accept this everywhere"** — forbid it; mount separate
tokens per audience. OIDC federation: cluster publishes an OIDC discovery document + JWKS; external
IdPs validate with no shared secret. **Directly agent-relevant:** Anthropic documents K8s workload
identity federation for agents — project a service-account token (`audience:
https://api.anthropic.com`, `expirationSeconds: 3600`) into the inference-worker's pod and use it
with a federation rule to authenticate to Anthropic's API. License: Apache-2.0 ✓.

→ **STEAL.** The closest existing analog to a fleet agent-task credential: bound, audience-scoped,
short-lived, automatically rotated, federable to external APIs — already the documented pattern for
production AI agent workers. The audience-binding discipline (one token per audience, never empty
`aud`) should be a hard rule in our own design.

### 3g. Fleet credential revocation incidents, 2024–2026 — STEAL the response pattern

Evidence for *why* expiry-by-design matters:

- **Drift / Salesforce (UNC6395), Aug 2025 — the canonical agent-credential incident.** A threat
  actor stole OAuth tokens belonging to **Drift, an AI chat agent** connected to 700+ organizations'
  Salesforce instances. The tokens were valid; sessions "looked exactly like the integration doing
  its job." Targeted queries hit Accounts, Users, Cases, then combed results for AWS keys, Snowflake
  tokens, and passwords pasted into tickets. Salesloft and Salesforce **revoked all Drift access and
  refresh tokens on Aug 20, 2025**; Google later warned any token touching the Drift platform should
  be treated as burned. The failure was an identity-lifecycle failure, not a model failure:
  long-lived agent-held credentials + implicit trust of legitimate-looking traffic.
- **Moltbook / OpenClaw, Jan–Feb 2026.** CVE-2026-25253 (CVSS 8.8): 1-click RCE in a viral
  self-hosted agent framework (180k stars in weeks) stealing the agent's auth token → full agent
  control. Moltbook leaked ~35k emails and **1.5M agent tokens** via an open Supabase backend. Agent
  tokens are now a mass-compromise target.
- **Anthropic threat-intel, Sept 10, 2026.** Attackers compromised an AI evaluation sandbox and
  stole API keys from 30+ AI companies; GTG-50021 ran fraudulent Claude resellers; GTG-20006
  harvested tokens from camera-streaming services. Even sandbox tiers need credential lifecycle.
- **Truffle Security, July 2026.** 543,699 **valid** credentials in public GitHub repos; median
  publicly exposed for **784 days** before revocation; oldest live 16+ years. GitGuardian: 29M new
  hardcoded secrets in 2025 (+34% YoY); AI-service credentials leaked at +81%. Without
  expiry-by-design, exposure windows are measured in years.
- **GitHub App keys, Sept 2026.** 474 of 4,802 exposed GitHub App private keys still authenticated;
  44 Apps had org-admin; **GitHub App private keys never expire** (only installation tokens do)
  and rotation is a manual decision nobody is prompted to make — one CDC key leaked Apr 2025 kept
  write access until Sept 2026 (17 months).
- **CISA postmortem, 2026.** A contractor leaked a build repo with admin credentials; CISA reset
  all exposed credentials **and** all credentials across every environment where the repo owner had
  been an administrator. Revocation scope must cover the blast radius, not just the leaked string.
- **TanStack supply chain, May 2026.** 84 malicious package versions in six minutes via a GitHub
  Actions token extracted from a runner; CrowdSec traced a breach to a **former employee's stolen
  OAuth token** kept active after departure. CI/CD tokens need least-privilege + short life;
  deprovisioning must be complete.
- **Amazon Q Developer extension, 2025.** An over-scoped GitHub token in CodeBuild config let an
  attacker ship malicious code in v1.84.0; AWS revoked the credential (bulletin AWS-2025-015).

(No notable Slack/Discord-specific fleet revocation postmortem surfaced for 2024–2026; Drift is
the closest analog.)

→ **STEAL the incident-response pattern** — assume theft, revoke immediately, rotate across the
full blast radius, and above all make credentials short-lived *by default* so the exposure window
is measured in minutes whether or not anyone runs the incident playbook.

### 3h. Zanzibar / OpenFGA / OPA — ADAPT

The fundamental distinction: **grant** revocation, not *credential* revocation. Deleting a
relationship tuple or shipping a new policy bundle removes the grant — but a stolen bearer token
keeps working until it expires. "Whether revocation has propagated to all enforcement points" is
its own unsolved-by-default problem (SPIFFE answers *which workload*, OpenFGA answers *does a
relationship authorize*, OAuth/GNAP answers *what was granted* — none answers whether revocation
propagated). Google Zanzibar: trillions of ACLs, millions of checks/sec, p95 <10ms, **zookies**
(opaque consistency tokens) give causal consistency — for revocation, check at
FullyConsistent or pass the mutation's token; don't cache negative authorizations long. OpenFGA:
tuple delete (transactional); consistency per-request (`MINIMIZE_LATENCY` vs `HIGHER_CONSISTENCY`);
recent read-replica routing makes replica lag literally the revocation propagation bound. OPA:
bundles polled on a configurable interval, ETag/304 caching, **atomic activation** on hash change,
signed bundles, persist-to-disk; propagation bound ≈ the poll interval; evaluation sub-millisecond
as a sidecar. Licenses: OpenFGA and OPA **Apache-2.0** ✓.

→ **ADAPT.** Use the grant plane for fast grant withdrawal with *explicit* consistency choices
(higher-consistency checks on the revocation path; short bundle poll intervals; no long caching of
negative decisions) — but never depend on it for credential-layer revocation. The credential layer
must expire on its own (§3a, §3f); the grant plane is defense in depth.

| # | Topic | Verdict | One-line rationale |
|---|-------|---------|-------------------|
| 1 | SPIFFE/SPIRE SVID rotation | **STEAL** | Expiry-as-revocation + 50%-TTL streaming rotation + entry-deletion kill-switch + bundle-exchange federation |
| 2 | step-ca / cert-manager | **ADAPT** | Passive-revocation semantics; 2/3-duration renewal; overlap CA ceremonies |
| 3 | OCSP stapling vs CRL | **SKIP** | Expiry-as-revocation won (LE killed OCSP Aug 2025); lesson captured in §1 |
| 4 | TUF root rotation | **STEAL** | Confirms existing verdict; version-walk + threshold + N+1 rollback rejection for rotating pinned trust roots |
| 5 | Vault dynamic secrets / PKI | **STEAL** | Lease TTLs + `revoke -prefix` kill-switch confirmed current. **New: Vault is BSL 1.1 — ship via OpenBao** |
| 6 | K8s bound SA token projection | **STEAL** | Bound, audience-scoped, 1h, 80%-TTL refresh, OIDC-federable — closest analog to fleet agent-task credentials |
| 7 | 2024–2026 revocation incidents | **STEAL** (response pattern) | Drift/UNC6395 (700+ orgs), 1.5M agent tokens (Moltbook), 543k live creds in GitHub — expire by default |
| 8 | Zanzibar / OpenFGA / OPA | **ADAPT** | Grant-plane revocation with explicit consistency bounds; never the credential-layer story |

---

## 4. License checks

All Apache-2.0/MIT except where flagged. Verified against the actual LICENSE files where marked ✓.

| Source | License | Trap? |
|---|---|---|
| SPIFFE/SPIRE | Apache-2.0 ✓ | No |
| Microsoft agent-governance-toolkit | MIT ✓ | No |
| MCP (modelcontextprotocol) | **MIT→Apache-2.0 mixed** ✓ | New: patent grant attaches only to Apache-2.0 portions; verify per-file before code reuse |
| UCAN | Apache-2.0 / MIT dual ✓ | No |
| Biscuit | Apache-2.0 ✓ (not EPL despite Eclipse) | No |
| GNAP / OAuth 2.1 / RAR / OpenID4VP | IETF Trust / OIDF IPR terms ✓ | No (spec-pattern reuse is clean) |
| zcap-ld | W3C CCG document terms ✓ | No (spec-pattern reuse clean; re-verify if adopting a library) |
| TUF | Spec CC-BY-4.0; python-tuf Apache-2.0 ✓ | No |
| step-ca / cert-manager / Kubernetes / OpenFGA / OPA | Apache-2.0 ✓ | No |
| **HashiCorp Vault** | **BSL 1.1 (not OSI open source)** ✓ | **YES — competing-use restriction. Ship the dynamic-secrets/lease/PKI pattern via OpenBao (LF fork, API-compatible, Apache-2.0/MPL-2.0), not Vault.** |
| Macaroons | Protocol paper (no encumbrance) | No |

**Project impact:** the project already uses HashiCorp Vault as a key-custody pattern (2026-09-23
streams; `gov/kms_vault.py` `provider: vault`; live-OpenBao spike in wave-310). The
`gov/kms_vault.py` provider speaks the Vault *API*; an OpenBao endpoint is API-compatible, so the
standing plan to keep the provider interface swappable already absorbs this caveat — but any
*future shipped documentation or deployment artifacts* that name "HashiCorp Vault" as the
production answer should gain the OpenBao carve-out. No product code was touched by this lane.

---

## 5. Direction brief — candidate build lanes for the agent identity/discovery frontier

Steals are ordered by evidence strength and engineering cost. Each is framed as a future build lane
(spec-first, TDD at public seams, fail-closed); no build work was done here.

### 5a. STEAL — attested agent identity model (SPIFFE semantics)

Build `gov/agent_identity.py`: an internal agent-identity model with SPIFFE semantics —
`spiffe://<trust-domain>/<agent-path>` identity URIs, SVID-shaped short-lived credentials (sub-hour
TTL), secretless bootstrap via attestation hooks, and trust-domain federation semantics for
cross-org verification. First target: bind agent identities to Sasanam's existing approval tokens
and decision packets (the `identity` field category from Microsoft's reconstructible Decision BOM
§1b slots directly in). Honest scope: integrate with a real SPIRE deployment where available, but
the internal model must work standalone for agents running outside SPIRE clusters.
**Negative rule (Unit42):** the governance layer must never treat a presented SVID as proof of
node integrity; pin identity grants to strong selectors (image digest / TPM-anchored attestation)
and short TTLs; record "node compromise = all node-scoped identities compromised" in the threat
model. The identity model should also emit A2A-style Agent Cards (§5b) so discovery and
authentication travel together.

### 5b. STEAL — agent discovery cards (A2A Agent Card schema, adapted)

Build `gov/agent_card.py`: a signed, well-known-path agent-discovery card modeled on A2A's Agent
Card (`/.well-known/agent-card.json` convention) — `name`, `description`, `version`, `provider`,
`capabilities`, `skills[]`, supported interfaces — but replacing A2A's declaration-only auth
fields with a pointer to the attested identity from §5a (SPIFFE ID + JWS card signature). This is
the answer to "how does an agent discover what another agent or tool can do without over-granting":
the card advertises *capabilities*, and the actual grant is negotiated separately (§5c).

### 5c. STEAL — least-privilege grant negotiation surface (RAR grammar + capability semantics)

Build `gov/grant_negotiation.py`: a grant-request/response grammar based on RAR's
`authorization_details` — typed objects with `type`, `actions`, `locations`, `datatypes`,
`identifier`, `privileges` — surfaced in the human approval queue and the agent↔agent grant API.
Include **as mandatory validators**: (1) the RFC 9396 §2.2 product-of-fields check (one
object per (tool, resource) pair — fail closed on multiplicative privilege); (2) AS-metadata-style
capability advertisement for tool discovery; (3) capability-token semantics from UCAN/Biscuit —
delegation chains anchored at the resource owner, equal-or-narrower hops, audience binding,
authority-block + attenuation-block structure expressed in Sasanam's native policy engine (not a
new wire format). Verifier-side policy + token-side checks must both pass.

### 5d. STEAL — expiry-as-revocation credential lifecycle

Build `gov/agent_credential_lifecycle.py` (or extend the existing KMS/approval plumbing): agent
task credentials are short-lived **by default** (sub-hour TTL, K8s-token style), auto-rotated by
the issuer with no agent-visible action (SPIRE's 50%-TTL streaming model; kubelet's 80%-TTL
refresh), audience-bound (one credential per audience; empty `aud` forbidden), and issued with a
passive-revocation kill-switch (revoke = block re-issuance; residual validity bounded by TTL).
Explicit separation: **credential expiry is the revocation mechanism; the grant plane (OpenFGA/
OPA-style) is defense in depth with explicit consistency bounds**, never the revocation story.
This lane also owns the license carve-out: the deployment story must name **OpenBao**, not
HashiCorp Vault, as the shipped secrets backend (API-compatible; the existing `gov/kms_vault.py`
provider interface already absorbs the swap).

### 5e. STEAL — only-tighten advisory layering + reconstructible Decision BOM

Lift from Microsoft's toolkit (confirmed primary sources): (1) an advisory layer that runs
**after** deterministic policy rules pass and **can only tighten (block/flag), never loosen** —
with failures defaulting to allow (deterministic layer is canonical) and all advisory decisions
logged with `deterministic=false`; (2) a reconstructible Decision BOM with field categories
**identity, trust, policy, action, context, outcome, lineage** and progressive completeness scoring,
feeding the existing decision-packet/evidence-bundle work (wave-176 direction; wave-317 evidence
schema). Do NOT lift their DID identity scheme (`did:mesh:*`/`did:agentmesh:*` split).

### 5f. ADAPT — no-token-passthrough doctrine (MCP authorization profile)

Encode at Sasanam's tool-proxy and delegation seams: a proxy **MUST NOT accept or transit** an
upstream principal's token; every hop obtains its own audience-bound token (RFC 8707 resource
indicators), and servers publish protected-resource metadata (RFC 9728) for AS discovery. This is
the confused-deputy doctrine that the wave-316 producer-wiring lane's live provenance sink already
embodies at execution; §5f extends it to authentication. Pair with GNAP-style continue/modify
semantics (WATCH) when a second implementation exists to negotiate with.

### 5g. WATCH — GNAP wire protocol; zcap-ld v1; A2A auth half; OpenID4VP issuance

Triggers: GNAP — the moment a second implementation speaks it (steal the `access`-array grammar
now, §5c); zcap-ld — JSON-LD-free v1 with a production implementation (semantically closest to
Sasanam's delegation thinking); A2A auth half — only if the spec grows past declaration-only;
OpenID4VP — watch EUDI/HAIP profiles for the hardened verifier-driven variant; don't build
credential issuance.

### 5h. SKIP — Macaroons (symmetric-verifier disqualifier); UMA 2.0 protocol (too heavy for
machine-speed calls); OCSP/CRL for task credentials (expiry won); OpenAI's guardrail identity
(nothing to steal — the gap is the opportunity); SPIRE's unverified `revocation_enabled` CRL
claim (don't cite until confirmed).

## 6. The composable stack (what the evidence supports)

No single framework delivers attested agent identity *plus* discovery *plus* revocation. The
composable answer:

1. **SPIFFE SVIDs** — attested identity, short-lived, federated (STEAL; §1a, §3a)
2. **A2A Agent Cards** — signed discovery at a well-known path (ADAPT; §1e, §5b)
3. **MCP's OAuth 2.1 authorization profile** — audience-bound tokens, protected-resource
   discovery, no token passthrough (ADAPT; §1d, §5f)
4. **RAR `authorization_details`** — the least-privilege negotiation grammar + product-of-fields
   validator (ADAPT; §2g, §5c)
5. **UCAN/Biscuit capability semantics** — delegation chains, equal-or-narrower attenuation,
   authority+attenuation structure (ADAPT; §2a, §2d, §5c)
6. **Expiry-as-revocation + automatic rotation** — sub-hour TTLs, 50–80% renewal, audience
   binding, entry-deletion kill-switch (STEAL; §3a, §3f, §5d)
7. **TUF-style trust-root rotation** — version-walk + threshold + rollback rejection for pinned
   anchors (STEAL, already adopted; §3d; feeds the planned `gov/trust_root_refresh.py`)
8. **Only-tighten advisory layering + reconstructible Decision BOM** (STEAL; §1b, §5e)
9. **OpenBao, not HashiCorp Vault** — for any shipped secrets backend (license carve-out; §3e)

## 7. Open questions and honest limits

1. One third-party guide claims a `revocation_enabled` CRL option in `spire-server.conf` —
   **not confirmed** in official SPIRE docs. Don't cite it until verified against the SPIRE server
   config reference.
2. No Slack/Discord-specific fleet revocation postmortem surfaced for 2024–2026; Drift/UNC6395 is
   the closest analog.
3. The OpenBao CRL-rebuild issue (openbao/openbao#3051, 2026) should be re-checked before relying
   on CRL propagation in the OpenBao path — prefer lease/TTL-based invalidation there.
4. The Unit42 finding is post-exploitation analysis, **not a vulnerability disclosure (no CVE)**,
   and has **not been observed in the wild**. The caveat is real but must not be overstated —
   especially not in external narratives.
5. Every AS-centric protocol (GNAP, UMA, OAuth/RAR) fails the cross-org agent test on the same
   point: no shared authorization server exists between arbitrary agents and tools. The
   capability-token family works without one — at the cost of needing a shared capability
   vocabulary that doesn't exist yet. This is the actual open problem.
6. Research-only lane: no product code was written or modified; no batteries, no gates, no F-
   filings. All factual claims trace to the three input reports in
   `~/workspace/teams/wave318-prospect/inputs/` (identity frameworks, capability
   discovery/least-privilege, revocation/rotation).
