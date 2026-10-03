# Prospectus — Wave-303 Lane 5: Heartbeat Leases & Fail-Closed Refresh

**Date:** 2026-10-03 · **Theme:** how production systems implement continuous
re-proof *in practice* — renewal/rotation timing rules, what a refresh is
authenticated by, what happens when the heartbeat is missed, and what evidence
is emitted for auditors. This is **part 2** of the wave-302 continuous-authorization
theme; part 1 is filed alongside this document as
`research/prospecting/w302_continuous_authorization_part1.md`.

**Standing design rule under test:** *"Authority is a lease with a heartbeat —
issuance is a moment; validity is a stream of re-proofs, and silence revokes."*

**Coverage audit:** ripgrep over all `wave2*-prospect/PROSPECTUS.md` +
`wave300-prospect/PROSPECTUS.md`. Every pick below has **zero prior rendered
verdicts on the angle researched**. Adjacent-but-distinct prior work (not
re-litigated): `smallstep/step-ca` ADAPT (online CA *issuance*, wave-302) —
here we research its *renewal/refresh* discipline; `kubernetes/enhancements
KEP-1205` ADAPT (TokenRequest API *shape*, wave-258) — here we research the
*kubelet rotation loop*; `cedar-policy/cedar` STEAL/ADAPT (policy *language*,
wave-205–215 lineage) — here we research Cedar *in practice* via Verified
Permissions; `permitio/opal` ADAPT (policy *distribution*, wave-302) — here we
research OPA's *decision-log/status* evidence seam; `teleport` SKIP
(dual-layer, wave-302) — **SKIP stands, not re-litigated**, one exhibit note
only; Vault/Boundary BSL pattern-only (wave-252) — Boundary session lifecycle
is a pattern exhibit here, nothing vendored.

**Licenses:** verified 2026-10-03 from public metadata (GitHub license
detection, CNCF project pages, vendor docs). NOT raw LICENSE bytes; reverify
at vendoring time per standing rule.

---

## The four questions, answered across systems first

Before the per-system verdicts, the answers the build lane needs:

### (1) How do systems decide heartbeat interval vs lease duration?

The industry answer is a **fixed fraction of lifetime, never a fixed offset
from expiry** — because the retry budget must scale with how long the authority
lives:

| System | Rule | Source |
|---|---|---|
| smallstep `step ca renew --daemon` | renew when **> 2/3 of lifetime elapsed** | smallstep docs, `certificate-manager/how-it-works.mdx` |
| SPIRE agent X.509-SVIDs | rotate at **50% of TTL** (hardcoded in `pkg/common/rotationutil/rotationutil.go`) | spiffe/spire issue #1754; geico/spire agent docs |
| Kubernetes kubelet projected tokens | start rotating when token older than **80% of TTL** or **24h** | KEP-1205; Red Hat bound-tokens docs |
| oauth2-proxy | `cookie_refresh = AccessToken − 1m` (fixed *skew*, not fraction — the exception that proves the rule: the skew is the downstream-expiry race window) | oauth2-proxy `sessions.md` (wave-302) |

Why fractions, not absolutes: a 1-hour SVID rotated at 50% gets a 30-minute
retry budget; a 7-day SVID gets 3.5 days. SPIRE's `availability_target` knob is
the explicit generalization: rotate when remaining lifetime hits the target
(default 50%, grace `lifetime − target` must be ≥ 12h or the agent falls back
to the 50% default). The pattern: **heartbeat interval = f(lifetime); the
constant is chosen so the *remaining* window always covers worst-case
remediation time.**

For Sasanam: our heartbeat rule should be `reverify_at = expires_at −
max(fraction × lifetime, remediation_bound)` — fraction for scale, absolute
floor for short leases.

### (2) What happens on missed heartbeats — grace vs immediate revoke?

The split is architectural, not philosophical:

- **Renewal-loop systems (grace-by-design):** step-ca's daemon retries with
  *exponential backoff and jitter* to avoid thundering herds; the old cert stays
  valid until expiry. SPIRE keeps serving the old SVID until its TTL. K8s
  kubelet retries; the previously-issued token stays valid until its own `exp`
  (a cached copy is *not* invalidated by rotation — this was the correction in
  the actor-ts #760 triage). Grace is not generosity — it is the retry budget
  from (1).
- **Fail-closed-on-miss (no grace):** oauth2-proxy's accepted fix direction —
  *invalidate the session immediately on failed refresh* (clear cookie, delete
  Redis key), never serve stale. step-ca's hard rule: **once a certificate
  expires, the CA will not renew it** — the refresh path dies permanently at
  expiry; there is no late renewal. Boundary sessions are *force-terminated* on
  expiry, on manual cancel, or when *any associated resource* (host, target,
  credential, project, user, account, auth method) is deleted — the termination
  is pushed by the worker (`terminated connection due to cancelation or
  expiration`).
- **Teleport's strict mode:** `record_session: strict` — if session recording
  fails, *the session terminates immediately*; `best_effort` lets it continue
  unrecorded. (Exhibit only — SKIP stands.)

The honest synthesis: **grace before expiry, death at expiry, immediate death
on explicit revoke.** Systems that blur this (serve-stale-on-failed-refresh)
are the ones that ship CVEs.

### (3) How is the refresh authenticated — is the refresh itself re-proofed?

Yes — every production refresh re-proves *something*, and the *what* is the
design:

- **step-ca:** renewal is authenticated by **mutual TLS with the existing
  private key** — the holder re-proves key possession at every renewal. (Only
  client-authentication certs can be renewed; everything else must be replaced.)
- **SPIRE:** the *agent* re-attests to the server on each SVID request
  (node attestor: cloud identity doc, PSAT, TPM, or join token); workloads
  fetch from the local Workload API socket, which the agent binds to the
  attested process identity. A workload can *never* mint its own replacement —
  the server API requires an admin caller and the Workload API is only reachable
  from the attested workload's own machine.
- **Kubernetes:** the kubelet — a trusted node component — uses its node
  credentials against the TokenRequest API; the workload never talks to the
  API server for rotation.
- **AWS Roles Anywhere:** every `CreateSession` re-signs with the private key
  (via `aws_signing_helper` / PKCS#11 / TPM); the CRL is checked *on every
  call* — freshness is re-proved, not cached.
- **Boundary:** sessions are **not refreshable at all** — you authorize a new
  session, which re-evaluates permissions at establishment. This is the
  strongest refresh discipline: refresh == re-authorization.
- **RFC 8693 in practice:** **no refresh token is issued for an exchanged
  token** (axiam design doc; Keycloak practice) — a refresh token would let the
  holder outlive the subject token, defeating the lifetime cap. **Re-run the
  exchange.** The refresh *is* the re-proof.

For Sasanam: our fail-closed refresh should follow the Boundary/RFC-8693
pole — a re-verification that fails must produce a *new* authority decision,
not extend the old one; and the re-proof must bind a fresh possession proof
(key, cert, PSAT-equivalent), never replay the last verdict.

### (4) What evidence is emitted for auditors?

| System | Evidence |
|---|---|
| Boundary | A **snapshot of the data relevant to authorizing the session** is stored in the data warehouse **at session creation**; historical data is **never deleted**; SSH/RDP session recordings (time, user, target, duration, bytes up/down) viewable in the admin console |
| OPA | **Decision logs**: every decision (input, policy version, result) buffered and uploaded (min_delay 300s / max 600s, 32KB chunks); **status API**: runtime telemetry including active bundle versions — the freshness proof |
| step-ca | Issuance/renewal recorded in the CA audit log (each renewal mints a new serial — rotation is visible as a serial sequence) |
| AWS Roles Anywhere | CloudTrail on every `CreateSession`; the cert CN is stamped into `sourceIdentity` |
| Cedar / Verified Permissions | CloudTrail on every `IsAuthorized`/`IsAuthorizedWithToken` decision (principal, action, resource, verdict) |
| SPIRE | Server/agent logs of attestation, issuance, ban, bundle rotation |

The pattern: **the renewal event itself is the audit event** (new serial, new
`jti`, new session id) — systems that re-verify silently and emit nothing are
the ones auditors reject. Our heartbeat lease must log every re-proof with the
lease id + the factor re-proved (authentik's per-factor freshness from wave-302
applies: log *which* factor was refreshed).

---

## 1. smallstep/step-ca — ADAPT (renewal discipline, distinct from the wave-302 issuance ADAPT)

**Mechanism.** The wave-302 verdict covered step-ca as an online CA (*issuance*).
The *renewal* half is the relevant mechanism here. `step ca renew` authenticates
by mTLS using the existing private key — key-possession re-proof at every
renewal — and produces an identical certificate with a **new serial number**
and extended lifetime. The automation discipline: the `--daemon` flag (or
systemd timer running `step certificate needs-renewal` as `ExecCondition`)
renews **after 2/3 of the certificate's lifetime has elapsed**; renewal
failures retry with **exponential backoff and jitter** (explicitly to mitigate
DoS and thundering herds). The hard rules: **once a certificate expires, the
CA will not renew it** — no late renewal, fail closed; only
client-authentication certs can be renewed (mTLS limitation), everything else
is replaced. Default validity 24h is documented as arbitrary — threat model
chooses the lifetime.

**Sasanam seam.** This is the reference implementation of our heartbeat rule:
2/3-lifetime renewal trigger, mTLS-reauthenticated refresh, backoff-with-jitter
retry, and a hard death at expiry with no resurrection path. The new-serial-per-
renewal is the evidence discipline our heartbeat log should copy. The "2/3,
not 1/2" choice is instructive: it leaves a full third of the lifetime as the
retry budget — more conservative than SPIRE's half, appropriate for certs whose
rotation requires a service reload (`--exec "nginx -s reload"`).

**Falsifiable probe.** (a) A lease renewed at 66% of lifetime with the CA
unreachable MUST keep serving the old authority and retry with growing
intervals — no thundering herd. (b) A lease presented for re-verification
*after* expiry MUST refuse with no renewal path (the refresh handle dies at
expiry). (c) Every renewal emits a new evidence id (serial analog); a heartbeat
log with two identical ids is a defect.

**License / fetch gaps.** Apache-2.0 (smallstep/certificates; also the `step`
CLI). Fetch gap: none — docs are primary.

**Verdict: ADAPT.** The 2/3 renewal trigger, mTLS-reauthenticated refresh,
backoff+jitter retry, and no-late-renewal hard rule. Port the *rules* (Go code
is not stdlib-vendorable, but the rules are arithmetic + retry policy).

---

## 2. SPIFFE/SPIRE — STEAL (pattern: 50%-TTL rotation + availability_target + ban semantics)

**Mechanism.** SPIRE server issues SVIDs (X.509 default, 1h TTL); the agent
rotates them **at 50% of TTL**, hardcoded in
`pkg/common/rotationutil/rotationutil.go` (spiffe/spire#1754 documents the
function and the open request to make it configurable). The
`availability_target` agent knob generalizes it: rotate when remaining lifetime
hits the target; the grace (`lifetime − availability_target`) must be ≥ 12h or
the agent falls back to the 50% default. Workloads read the current SVID from
the local Workload API (streaming push available). Revocation is TTL-bound:
**SPIRE implements no CRLs** — deleting the registration entry stops renewal;
outstanding SVIDs stay valid until their (short) TTL. Node-level kill is
`spire-server agent ban` — the banned agent's SVID requests fail. Emergency
revocation of still-trusted workloads is CA rotation (nuclear: invalidates
everything). The SPIRE server API itself requires admin callers; workloads can
never mint their own replacements.

**Sasanam seam.** This is the production answer to "how does silence revoke":
*banning stops the heartbeat, and the TTL bounds the blast radius.* It is also
the honest exhibit for our own residual — our revocation freshness is
deployment-owned (F378/F379) — because SPIRE's answer to that same problem is
"make the TTL short enough that the residual doesn't matter." The
`availability_target` grace rule is the knob our heartbeat lease needs: the
retry budget must be *asserted* ≥ a remediation bound, not hoped for.

**Falsifiable probe.** (a) Ban a workload's registration; outstanding authority
MUST die within the TTL bound, never sooner by magic — pin the bound. (b) Set
an availability target; assert rotation fires at the target, and that a target
violating the grace floor falls back to 50% (documented, not silent).
(c) Workload attempting self-mint MUST be refused by construction (server-side
admin requirement).

**License / fetch gaps.** Apache-2.0 — CNCF-hosted project (spiffe.io docs
carry the Apache-2.0 license note). Fetch gap: none.

**Verdict: STEAL (pattern).** The 50%-TTL rotation rule, the
`availability_target` grace-floor discipline, and ban-stops-renewal + TTL-
bounds-exposure as the revocation model. No code to vendor (Go); steal the
shapes.

---

## 3. Kubernetes projected service-account tokens — STEAL (80% rotation + audience-bound issuance)

**Mechanism.** KEP-1205 introduced the TokenRequest API and the projected
`serviceAccountToken` volume. The kubelet — a trusted node component, not the
workload — **proactively rotates the token when it is older than 80% of its
TTL or older than 24h** (KEP-1205 API comment; Red Hat bound-tokens docs).
Audience is **bound at issuance**: the token is valid only for the declared
audience, enforced by the issuer, not delegated to consumers
(`aud` mismatch → reject). NodeRestriction admission requires pod-bound
tokens. The subtle, documented behavior: **rotation does not invalidate the
cached copy** — the kubelet rewriting the file leaves the previously-issued
token valid until its own `exp`; clients that memoize the credential and never
re-read (actor-ts #760) break only at expiry, not at rotation — the missing
invalidation (no re-read, no 401-triggered reload) was the genuine defect.

**Sasanam seam.** Three steals: (1) the 80% rotation trigger — more aggressive
than SPIRE's 50%, appropriate for JWT-style bearer tokens where rotation is
cheap; (2) **audience bound at issuance, enforced by the issuer** — this is the
shape our per-step single-use authorizations (wave-302's CAS ST analog) need;
(3) the actor-ts lesson as a negative exhibit: *rotation without consumer
invalidation is half a mechanism* — our heartbeat lease must define what the
*consumer* does at rotation (re-read + 401-triggered reload), not just what the
issuer does.

**Falsifiable probe.** (a) A step authorization minted for audience X presented
to consumer Y MUST refuse (issuer-bound aud). (b) After authority rotation, a
consumer holding the old credential MUST either re-read or receive a
re-prove signal on next use — silent indefinite use of the pre-rotation
credential is a defect. (c) Rotation fires at ≤80% of TTL.

**License / fetch gaps.** Apache-2.0 (kubernetes). Fetch gap: none — KEP-1205
is the primary source.

**Verdict: STEAL.** 80%-TTL rotation trigger, issuer-bound audience, and the
consumer-invalidation half of rotation (the actor-ts negative exhibit).

---

## 4. RFC 8693 in practice — ADAPT (no refresh token on exchange; re-run the exchange)

**Mechanism.** RFC 8693 defines token exchange (delegation via `act`, impersonation).
In practice (Keycloak ≥26.2 standard token exchange; documented designs):
- Exchanged-token lifetime = `min(subject_token_remaining, configured_max)` —
  **an exchanged token never outlives its subject token** (axiam design doc).
  Without this, exchange is privilege-*lifetime* laundering.
- **No refresh token is issued with an exchanged token.** A refresh token would
  let the holder outlive the subject token indefinitely — defeating the cap.
  The discipline is explicit: **re-run the exchange** (ilpanich/axiam
  token-exchange-design.md). Keycloak practice concurs: "Refresh tokens not
  issued during exchange."
- Revoking the subject's session does **not** retroactively revoke exchanged
  tokens — they are separate tokens; the lifetime cap is the containment.
- `act` chains are depth-capped (3 in the documented design) — a wire-level
  analog of our multi-hop delegation bound.

**Sasanam seam.** This is the fail-closed refresh rule made concrete: **the
refresh of a derived authority is a re-proof of the *root*, not an extension of
the leaf.** Our resumed workflow step (F380's replay variant) must re-present
the *original* authority evidence, not the cached step verdict. The depth cap
on `act` chains also informs F379's multi-hop semantics: bound the chain at
issuance, cap the derived lifetime by the root's remaining life.

**Falsifiable probe.** (a) Exchange a 30s-remaining subject token; the derived
token MUST expire ≤30s out, regardless of the configured max. (b) A refresh
attempt against an exchanged token MUST refuse — the only path is a new
exchange against a live subject token. (c) `act` chain at depth 3+ MUST refuse.

**License / fetch gaps.** RFC (IETF, freely implementable); Keycloak Apache-2.0.
Fetch gap: none.

**Verdict: ADAPT.** Lifetime-capped-by-subject + no-refresh-on-exchange +
re-run-the-exchange as the refresh discipline. Direct input to our
fail-closed-refresh close-when.

---

## 5. OPA — ADAPT (per-request evaluation + decision-log/status evidence seam)

**Mechanism.** OPA is the *whether*, not the *who* (it issues nothing). Its
continuous-authorization shape: **every request is evaluated against the live
policy** — there is no session, no TTL, no refresh; freshness is a property of
the *policy/data plane*, not the credential. The management APIs are the
heartbeat of that plane: **bundles** poll a remote HTTP server
(`min_delay_seconds` 60 / `max_delay_seconds` 120 defaults) and reload
atomically on hash change; **decision logs** buffer every decision (input,
policy version, result) and upload in 32KB chunks every 300–600s; the
**status API** reports runtime telemetry including active bundle versions —
the freshness proof an auditor asks for. The discovery bundle can reconfigure
all three at runtime. permitio/opal (wave-302 ADAPT) layers *push* on top for
the policy-data half where polling latency matters.

**Sasanam seam.** OPA inverts our current model in a useful way: instead of
"lease + heartbeat," it is "stateless decision + policy-plane heartbeat." Our
workflow step re-verification (F380) should look like this at the policy layer:
the *decision* is recomputed per use against the current policy bundle, and the
*evidence* of freshness is the bundle version + decision log, not a lease
timestamp. The status API is the shape our authority-health endpoint should
copy: "these are the policy/revocation versions this decision was evaluated
against."

**Falsifiable probe.** (a) Change a policy mid-workflow; the next step
decision MUST reflect the new policy without any session restart (evaluation
is per-request). (b) Decision logs MUST contain the policy version that
produced each verdict — a log without it is a defect. (c) A bundle poll
failure MUST surface on the status API; silent staleness is a defect.

**License / fetch gaps.** Apache-2.0 (open-policy-agent/opa — Dockerfile
license header). Fetch gap: none.

**Verdict: ADAPT.** Per-request evaluation as the continuous-auth pattern +
decision-log/status-API as the evidence seam. (OPA itself is Go; the pattern
is the steal.)

---

## 6. Cedar in practice (Verified Permissions) — ADAPT (per-request eval, immediate policy effect, documented revocation residual)

**Mechanism.** Prior verdicts covered Cedar as a *language*
(forbid-overrides-permit, formally verifiable). In practice via Amazon Verified
Permissions: applications call `IsAuthorized`/`IsAuthorizedWithToken` **at
runtime per request**; **policy changes take effect immediately** (no
redeploy, no session restart); identity tokens (Cognito) are validated per
call (signature + expiry); **every decision is logged to CloudTrail**
(principal, action, resource, verdict). The aws-samples agentic-AI reference
uses Cedar's three-layer model (agent→tool, agent→agent delegation with a
hard hop limit of 5, originating-user) with RFC 8693 token exchange for the
delegation hops — the exact composition our workflow stack is building.
The honest residual, documented in the API reference: **"Tokens from an
identity source continue to be usable until they expire. Token revocation and
resource deletion have no effect on the validity of a token in your policy
store."** Continuous authorization here is only as fresh as the token claims
plus the policy — the IdP half is out of scope.

**Sasanam seam.** This validates our lane-2/lane-6 composition direction
(workflow × delegation × approval evaluated together per step) and gives the
build lane two things: (1) the hop-limit-5 + per-layer-eval composition as a
proven shape for our delegation-chain depth bound; (2) the documented
revocation residual as the *honest boundary* we must also document — our
claims-challenge (wave-302 sequencing item 3) is precisely the mechanism that
closes the residual Verified Permissions leaves open.

**Falsifiable probe.** (a) Policy change mid-run MUST affect the next
authorization without restart. (b) A revoked IdP token presented inside its
`exp` MUST be answered with a re-proof demand (claims-challenge), not a silent
allow — this is where we must beat Verified Permissions. (c) Hop count > 5 in
a delegation chain MUST refuse.

**License / fetch gaps.** cedar-policy/cedar Apache-2.0; Verified Permissions
is a service (pattern only); the cedar-agent reference is Apache-2.0. Python
bindings (`cedarpy`) exist under Apache-2.0 — the one real vendoring
candidate in this wave (policy *evaluation*, not heartbeat). Fetch gap: none.

**Verdict: ADAPT.** Per-request evaluation + immediate policy effect +
CloudTrail decision evidence; carry the documented revocation residual as our
own honest boundary. Evaluate `cedarpy` for vendoring at build time.

---

## 7. HashiCorp Boundary — WATCH (session lifecycle; BSL trap stands)

**Mechanism.** Recorded here as a pattern exhibit only — the BSL-1.1 license
(wave-252) means pattern-steal, never vendor. The session model is the
instructive contrast to everything above: a session is **one-shot and
non-refreshable** — expiration and connection limits are set from target
attributes at creation; **permissions are evaluated only at session
establishment**; changes to a user's permissions do not affect existing
sessions. Termination is **forceful and pushed**: expiry, manual cancel
(`boundary sessions cancel` → `canceling` → `terminated`), or deletion of *any*
associated resource — host, host set, credential, target, project, user,
account, auth method — and the worker kills the connection
(`terminated connection due to cancelation or expiration`). Session credentials
are revoked at termination. Evidence: a **snapshot of the authorization data**
is stored in the **data warehouse at session creation** and historical data is
**never deleted**; SSH/RDP sessions can be recorded and played back with
per-channel byte counts.

**Sasanam seam.** Boundary is the "no heartbeat" pole: instead of continuous
re-proof, it makes sessions short, non-renewable, and *killable from many
directions*. Our suspended-state/kill-switch sequencing item (wave-302 #7)
should copy the termination-cascade shape: revoking any upstream association
kills the session, loudly, with the evidence snapshot already stored. The
"permissions only at establishment" is also the documented anti-pattern our
claims-challenge must avoid — we re-evaluate per use, Boundary doesn't.

**Falsifiable probe.** (a) Deleting any association of a live session MUST
terminate it (cascade), not leave it running. (b) A terminated session's
credentials MUST be revoked — reuse of a post-termination credential refuses.
(c) The authorization snapshot MUST exist in the warehouse before the session
is usable.

**License / fetch gaps.** **BSL-1.1** — pattern only per standing rule
(recorded wave-252). Fetch gap: none.

**Verdict: WATCH.** Termination-cascade + non-refreshable sessions +
never-deleted evidence snapshots. Pattern only.

---

## 8. AWS IAM Roles Anywhere — ADAPT (key-possession re-proof per session; CRL checked every call)

**Mechanism.** On-prem workloads with an X.509 PKI get AWS temporary
credentials: each `CreateSession` is **signed with the workload's private key**
(via `aws_signing_helper`, PKCS#11, or TPM) — the refresh *is* a fresh
possession proof. Session duration 900s–43200s (15min–12h), requested per
call. Revocation: a CRL imported per trust anchor is **checked on every
`CreateSession`** — revoked certificates are rejected at mint time. The PCA
auto-integration publishes the CRL to S3 **within ~30 minutes** of
`revoke-certificate` (the documented propagation-latency bound). CloudTrail
logs every call with the cert CN in `sourceIdentity`.

**Sasanam seam.** This is the cleanest production instance of (3): no
long-lived session handle exists to steal — every credential acquisition
re-proves key possession *and* re-checks revocation state. Our ephemeral tool
credentials (wave-302 sequencing #6, BLESS discipline) should follow this
shape: mint-per-use with possession proof, CRL-equivalent checked at mint,
bounded session duration, and the 30-minute PCA bound as the template for
documenting our own revocation-propagation latency honestly.

**Falsifiable probe.** (a) A `CreateSession`-analog with a revoked cert MUST
refuse at mint (revocation checked per acquisition, never cached). (b) The
revocation-propagation bound MUST be documented and tested (the 30-minute
analog). (c) No standing session handle may outlive its `durationSeconds`.

**License / fetch gaps.** AWS service documentation — pattern only, nothing to
vendor. Fetch gap: none.

**Verdict: ADAPT.** Possession-re-proof per acquisition + per-call revocation
check + documented propagation bound. Pattern steal.

---

## 9. Teleport — SKIP stands (one exhibit note, not re-litigated)

Prior wave-302 verdict **SKIP** (dual-layer: AGPL source + eligibility-gated
CE binaries) stands — not re-litigated. One exhibit note for the build lane's
reading list only: Teleport's `record_session: strict` mode **terminates the
session immediately if recording fails** (`best_effort` lets it continue
unrecorded) — the same fail-closed shape as oauth2-proxy's failed-refresh
rule, and its `pin_source_ip` (enterprise-only) embeds the login source IP in
user certificates so a compromised cert can't move networks — authentik-style
session binding at the cert layer.

---

## Runner-ups (genuinely new, not rendered — WATCH)

- **permitio/opal + cedar-agent** (Apache-2.0): realtime *push* of policy/data
  changes to Cedar agents — the answer to OPA's poll-latency residual. Covered
  opal-as-distribution in wave-302; the cedar-agent binding is new. Revisit
  when the policy-plane heartbeat is built.
- **cert-manager** (Apache-2.0): Kubernetes-native cert renewal controller —
  the `renewBefore` field (default 2/3 of duration) is the same 2/3 rule as
  step-ca, declaratively. Adjacent to KEP-1205; skip unless the CA work needs
  a k8s-native controller shape.
- **SPIFFE federation** (Apache-2.0): cross-trust-domain bundle exchange —
  the post-v1 shape for our multi-principal delegation. Out of scope for the
  heartbeat lane.

## License-trap table (this wave)

| Repo / product | Trap | Posture |
|---|---|---|
| Teleport | AGPL source + eligibility-gated CE binaries (recorded wave-302) | SKIP stands — not re-litigated |
| HashiCorp Boundary/Vault | BSL-1.1 (recorded wave-252) | Pattern only |
| Everything else in this wave | step-ca Apache-2.0, SPIRE Apache-2.0 (CNCF), kubernetes Apache-2.0, OPA Apache-2.0, cedar-policy Apache-2.0 | Clear for pattern/vendor evaluation |

## Reuse / vendoring candidates (stdlib-compatible)

Honest assessment: every core in this wave is Go (step-ca, SPIRE, OPA, K8s)
or a service (Boundary, Roles Anywhere, Verified Permissions) — **nothing is
directly vendoring into our stdlib-only Python tree.** What ports cleanly:

1. **`cedarpy`** (cedar-policy Python bindings, Apache-2.0) — the one real
   vendoring candidate: Cedar policy evaluation in Python for our per-step
   authorization checks. Evaluate at build time (native extension caveat:
   check the wheel/ABI story before committing).
2. **The scheduling rules** — 2/3 (step-ca), 1/2 (SPIRE), 80% (K8s),
   lifetime−skew (oauth2-proxy) — are pure arithmetic; they vendor as ~30
   lines of Python, no dependency.
3. **Backoff-with-jitter retry** (step-ca daemon) — we already carry this
   pattern; the steal is the *placement* (retry the heartbeat, never extend
   the lease while retrying).

## Refined heartbeat-lease spec (for the build lane)

From the four questions, the concrete shape for `gov/authority_lifecycle.py`:

```
lease = {
  "ttl": absolute death,                     # Boundary: non-negotiable
  "idle_bound": death by disuse,             # Janssen, wave-302
  "reverify_at": expires_at
      - max(fraction * lifetime,             # 1/2 SPIRE | 2/3 step-ca | 80% k8s
            remediation_floor),              # SPIRE availability_target grace
  "refresh_auth": fresh possession proof,    # mTLS/cert/PSAT — never replay
  "no_late_renewal": True,                   # step-ca hard rule
  "on_refresh_failure": "invalidate_now",    # oauth2-proxy, never serve stale
  "evidence": heartbeat log with lease id +  # new serial/jti per re-proof
              factor refreshed + policy version,  # OPA status shape
  "revocation": event subscription            # CAE/SSF, wave-302
}
```

And the sequencing correction from this wave: **refresh is re-proof, not
extension** — a successful heartbeat mints a *new* evidence id and re-verifies
the factors; it never mutates the old lease's expiry. (RFC 8693: re-run the
exchange. Boundary: new session. step-ca: new serial.)

## Spec primary sources (cited, not ranked)

- step-ca renewal docs: https://smallstep.com/docs/step-ca/renewal/ ;
  https://github.com/smallstep/docs/blob/HEAD/step-ca/basic-certificate-authority-operations.mdx
  (2/3 lifetime, mTLS renewal auth, no renewal after expiry, backoff+jitter)
- spiffe/spire#1754 (rotationutil 50% TTL);
  https://github.com/geico/spire/blob/HEAD/doc/spire_agent.md (`availability_target`)
- KEP-1205: https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/1205-bound-service-account-tokens/README.md
  (80% TTL / 24h rotation trigger, audience binding)
- RFC 8693 (IETF) + Keycloak practice: exchanged token never outlives subject;
  no refresh token on exchange — re-run the exchange
  (https://github.com/ilpanich/axiam/blob/HEAD/claude_dev/token-exchange-design.md)
- OPA management APIs: bundles (60/120s poll), decision logs (300/600s),
  status API — https://www.openpolicyagent.org/docs/latest/management/ ;
  https://openpolicyagent.org/ecosystem
- Verified Permissions IsAuthorizedWithToken: per-request evaluation, immediate
  policy effect, CloudTrail decisions; documented residual: revocation has no
  effect on in-flight tokens
  (https://docs.aws.amazon.com/verifiedpermissions/ ; AWS Security Blog
  agentic-AI Cedar reference)
- Boundary sessions: https://developer.hashicorp.com/boundary/docs/domain-model/sessions
  (non-refreshable, permissions at establishment only, force-termination
  cascade, data-warehouse snapshot, recordings)
- IAM Roles Anywhere: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html
  (900s–43200s, per-call signing, CRL checked every CreateSession, CloudTrail)
- Teleport role spec (exhibit): strict record_session terminates on recording
  failure (https://github.com/cezary13k/teleport/blob/HEAD/docs/pages/includes/role-spec.mdx)

## New design refinement (extracted)

Wave-302's rule stands; this wave sharpens it:

**"A heartbeat is a re-proof, not a renewal — silence revokes, and a missed
proof never extends the lease."**

Every heartbeat must (a) re-prove possession with a fresh proof, (b) mint a
new evidence id, (c) name the factor refreshed and the policy version
evaluated against, and (d) die loudly on failure — never serve the
last-known-good verdict.
