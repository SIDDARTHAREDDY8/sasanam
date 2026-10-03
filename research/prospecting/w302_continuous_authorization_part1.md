# Prospectus — Wave-302 Lane 4: Continuous Authorization & Session Authority Lifecycle

**Date:** 2026-10-03 · **Theme:** how production systems govern authority *after* issuance —
continuous authorization, re-authentication, step-up auth, session binding, token
refresh/rotation, authority decay and expiry, revocation propagation latency, and what
happens when a long-running workflow outlives its original grant.

**Standing design rule under test:** *"A workflow outlives its runner — every step is
checkpointed, and every resume re-proves its authority."*

**Coverage audit:** ripgrep over all `wave2*-prospect/PROSPECTUS.md` + `wave300-prospect/PROSPECTUS.md`
(40+ patterns). Every pick below has **zero prior rendered verdicts**. Adjacent-but-distinct
prior work (not re-litigated): `dex` (identity issuance, integration being built),
`supertokens/supertokens-core` STEAL (rotating refresh + theft lineage), `ory/hydra` WATCH,
`authelia/authelia` ADAPT (regulation-rule step-up), `smallstep/step-ca` ADAPT (online CA),
`authzed/spicedb` STEAL / `openfga/openfga` ADAPT (Zanzibar zedtoken/consistency discipline),
`permitio/opal` ADAPT (policy distribution plane).

**Licenses:** verified 2026-10-03 from public metadata — GitHub license detection badges,
project READMEs, Linux Foundation project pages, vendor docs. NOT raw LICENSE bytes;
reverify at vendoring time per standing rule.

---

## 1. apereo/cas — STEAL (ticket-typed authority lifecycle)

**Mechanism.** CAS is a ticket-protocol SSO server (Java/Spring Boot). Authority is not one
token type but a *typed ticket lifecycle*: the Ticket-Granting Ticket (TGT) is the
long-lived SSO session; Service Tickets (ST) are short-lived, **single-use**,
service-bound tokens minted from the TGT; Proxy-Granting Tickets (PGT) and Proxy Tickets
(PT) are the delegation chain — a service holding a PGT can mint PTs to act *on behalf
of* the user at a downstream service. Validation endpoints (`/validate`, `/serviceValidate`,
`/proxyValidate`) are the per-use re-verification seam: a PT presented to `/validate`
(non-proxy endpoint) MUST fail validation. Revocation is **Single Logout (SLO)**: when
the TGT is explicitly expired, the server MUST POST a logout XML document to *every
service URL seen during the session*; SLO MAY also fire on TGT idle timeout. Server
behavior is explicitly fire-and-forget — the server SHALL ignore POST errors so
revocation delivery never degrades availability; clients are RECOMMENDED to kill the
application session identified by the service ticket id. The REST protocol variant
deliberately does *not* create SSO sessions (stateless): the caller manages the
session, CAS acts as a pure authentication engine.

**Sasanam seam.** Our delegation stack (F377/F378/F379 closures) has receipts, tickets,
and leases but no *typed* ticket lifecycle: a delegation ticket today is one shape with
one TTL. CAS's TGT/ST/PT split maps directly: session-scoped grant (TGT) → per-step
single-use authorization (ST) → downstream proxy authority (PT). F379 (multi-hop lease
revocation honors only the root's list) is exactly the problem CAS's SLO answers:
revocation must propagate to *every visited grantee*, not just be checkable at the
root. The fire-and-forget SLO discipline is the honest answer to revocation-delivery
latency: best-effort push + client-side session mapping, never blocking the revoker.

**Falsifiable probe.** (a) Mint a PT chain two hops deep; revoke the middle hop's PGT;
present the leaf PT — today this is F379's shape (check what refuses). (b) Single-use:
present the same ST-equivalent twice; the second MUST refuse. (c) SLO fan-out: revoke
a session grant and assert a revocation event is emitted for every downstream grantee
that consumed a ticket in that session (not just the root).

**License / fetch gaps.** Apache-2.0 — README states "licensed under Apache v2"
(verified from fork README mirrors of the canonical text, 2026-10-03). Fetch gap: none
material; the protocol spec is the primary source.
Sources: CAS protocol spec (SLO §2.3.3, server/client behavior)
https://github.com/apereo/cas/blob/HEAD/docs/cas-server-documentation/protocol/CAS-Protocol-Specification.md ;
REST protocol https://apereo.github.io/cas/development/protocol/REST-Protocol-Request-TicketGrantingTicket.html

**Verdict: STEAL.** Ticket-typed lifecycle + SLO fan-out as the revocation-propagation
pattern. Steal the *shapes* (typed tickets, single-use ST, fire-and-forget SLO with
client-side mapping), not the Java.

---

## 2. Microsoft Entra — Continuous Access Evaluation (CAE) — STEAL (pattern)

**Mechanism.** CAE replaces static token lifetimes with *critical-event-driven*
revocation (docs: learn.microsoft.com, primary source). The resource provider evaluates
every presented token against revocation events synced from Entra ID; when a critical
event fires (user deleted/disabled, password changed, MFA registration changed,
token-protection policy changed, high risk detected), the provider rejects even a
*non-expired* token with a **claims challenge** (401 + `insufficient_claims` /
`acrs` payload). The CAE-capable client bypasses its cache and re-requests; Entra ID
re-evaluates all Conditional Access policy before re-issuing — this is continuous
authorization, not expiry. Consequence: token lifetime policy is *not honored* for
CAE sessions; tokens become long-lived (up to 28h, 24h for workload identities) because
**critical events and policy evaluation drive revocation, not an arbitrary time
period**. CAE extends to workload identities (service principals): declare the `cp1`
client capability, get LLTs, and the resource provider (Graph) enforces revocation
events + policy changes per call.

**Sasanam seam.** This is the production proof of our standing rule. Our leases and
delegation bindings today are expiry-driven with revocation checked at presentation
*if* state is presented (F378/F379 residuals: revocation freshness is deployment-owned).
CAE's answer: make revocation *event-driven and push-synced* to the enforcement point,
and make the client capable of a claims challenge — "your token is technically valid
but revoked; come back with fresh proof." The 401+claims-challenge shape is exactly
what a resumed workflow step should receive when its authority died mid-run, instead
of our current binary refuse.

**Falsifiable probe.** (a) Disable a principal mid-workflow; the next step presentation
MUST fail even though its lease/grant is unexpired (event-driven, not TTL-driven).
(b) Claims-challenge shape: a refused presentation returns a machine-readable
"re-prove" payload naming the stale condition, not just a code. (c) Policy-change
propagation: change the policy governing a grant class; outstanding grants under the
old policy MUST re-evaluate at next use.

**License / fetch gaps.** Service documentation, not OSS — pattern steal only, nothing
to vendor. Fetch gap: fine-grained critical-event catalog lives in Entra docs; the
flow above is from the primary concept pages.
Sources:
https://learn.microsoft.com/he-il/entra/identity/conditional-access/concept-continuous-access-evaluation ;
https://learn.microsoft.com/nb-no/entra/identity/conditional-access/concept-continuous-access-evaluation-workload ;
https://learn.microsoft.com/en-gb/training/modules/plan-implement-administer-conditional-access/9-implement-session-management

**Verdict: STEAL (pattern).** Critical-event-driven invalidation + claims-challenge
re-proof is the target architecture for our authority-lifecycle work. No code to take.

---

## 3. Netflix/bless — ADAPT (ephemeral credentials; expiry IS revocation)

**Mechanism.** BLESS (Bastion's Lambda Ephemeral SSH Service) is an SSH CA that runs
as an AWS Lambda function. The design inverts the revocation problem: SSH certificates
are issued **short-lived** (minutes), scoped to a single use case, and hosts trust the
CA — there is no CRL, no OCSP, no revocation list at all. Invocation is IAM-gated
(only the bastion's IAM role may call the Lambda), and the CA key lives in an isolated
AWS account with the passphrase KMS-encrypted. Revocation = "stop issuing + wait
minutes." The user flow: generate a keypair locally, send the public key to the Lambda,
receive a signed short-lived cert.

**Sasanam seam.** Our revocation machinery (F378/F379) is list-based and heavy; BLESS
is the counter-design: for *tool-execution credentials* (the hottest, shortest-lived
authority in the system), expiry-as-revocation eliminates the propagation-latency
problem entirely. Where a lease lives minutes, a revocation list is pure cost. This
also answers the F379 residual cleanly for the short-lived class: no multi-hop
revoker sets needed if the chain can't outlive its TTL.

**Falsifiable probe.** (a) Issue a tool-execution credential with a 5-minute TTL;
revoke the parent grant at minute 1; the credential MUST still verify until minute 5
(documented: expiry-is-revocation is only sound below a TTL bound) — pin the bound.
(b) IAM-gate analog: only the designated issuer role may mint; a mint from any other
role refuses.

**License / fetch gaps.** Apache-2.0 — Netflix OSS convention (all Netflix org repos
listed Apache-2.0 in public metadata, 2026-10-03). **Upstream is archived** ("no longer
plan to maintain") — mechanism steal only, no dependency. Fetch gap: the canonical
repo (Netflix/bless) 404s in search mirrors; forks carry the README verbatim.
Sources: https://github.com/fork-the-planet/netflix___bless (README mirror of
Netflix/bless)

**Verdict: ADAPT.** Ephemeral-credential discipline for tool execution: TTL-bound
authority with no revocation list, plus the explicit TTL bound at which the discipline
stops being sound.

---

## 4. oauth2-proxy/oauth2-proxy — ADAPT (refresh/expire discipline + fail-closed refresh)

**Mechanism.** Per-request authentication proxy. Two knobs govern the whole lifecycle,
documented with unusual honesty in `sessions.md`: `--cookie-refresh` (re-validate /
refresh the access token after this duration — even if still valid) and
`--cookie-expire` (hard session death). The documented discipline:
`cookie_refresh := AccessToken lifespan − 1m` (the −1m covers the race where a token
valid at the proxy is expired at the backend), `cookie_expire := Refresh-Token
lifespan`. Sessions live server-side in Redis (`SETEX`, per-session encrypted), so the
browser holds only a short cookie. The failure mode is instructive: when a refresh
request fails (4xx/5xx/timeout), the proxy historically kept serving the stale session
→ auth loop flooding the IdP; the accepted fix direction is **invalidate the session
immediately on failed refresh** (clear cookie, delete Redis key, redirect to login /
401 for APIs), never serve stale.

**Sasanam seam.** Our leases have TTL but no *refresh discipline*: no documented
`refresh_after = lifetime − skew` rule, and no fail-closed rule for "re-verification
failed." The `-1m` skew rule is a stealable constant-shape: every authority with a
downstream consumer needs `reverify_at = expires_at − downstream_skew`, not
`reverify_at = expires_at`. And the failed-refresh lesson maps directly to our resume
path: if authority re-verification fails (IdP down, revoker unreachable), the session
must die loudly — never limp on with the last-known-good verdict.

**Falsifiable probe.** (a) Set a lease TTL of 60s and a downstream skew of 5s; the
re-verification MUST trigger at ≤55s, never at 60s. (b) Make the revoker unreachable
at resume; the workflow MUST refuse (session invalidated), not proceed on cached
authority. (c) Failed-refresh loop: N consecutive failed re-verifications MUST NOT
produce N upstream retry storms (backoff + dead session).

**License / fetch gaps.** MIT — GitHub org repo listing shows "MIT License"
(2026-10-03). Fetch gap: none.
Source: https://github.com/oauth2-proxy/oauth2-proxy/blob/HEAD/docs/versioned_docs/version-7.6.x/configuration/sessions.md

**Verdict: ADAPT.** The refresh/expire two-knob discipline + fail-closed-on-failed-refresh.

---

## 5. goauthentik/authentik — ADAPT (per-factor freshness, session binding)

**Mechanism.** Self-hosted IdP (Python/Django). Three lifecycle mechanisms worth
stealing: (1) **Per-factor authentication freshness** (tracked in issue #24270): a
password, a WebAuthn assertion, and a TOTP code have *different sensible lifetimes*;
the proposal is a unified per-factor freshness record so a stale factor triggers
re-validation of *only that factor* instead of the full flow. (Prior art inside the
repo: `AuthenticatorValidateStage.last_auth_threshold` MFA-skip windows, `max_age`
honored by full re-run.) (2) **Session binding** (hardening docs): bind a session to
the network/ASN/IP and GeoIP at creation; when the client moves beyond configured
strictness, the session is *terminated* and a logout event records what changed —
explicitly framed as relocation detection, not replay protection. (3) **Key-bound ID
tokens** and on-behalf-of (OBO) flows in recent releases; "terminate other sessions"
on new sign-in as an explicit revocation affordance.

**Sasanam seam.** Our authority is monolithic per grant: one expiry, one
re-verification. authentik's per-factor freshness is the finer instrument — a
delegation chain has multiple "factors" (issuer key health, revoker freshness,
policy version), each with its own sensible lifetime; re-proving should refresh only
the stale factor. Session binding maps to our workflow resume: bind a run's authority
to the runner identity + network context it was issued in; a resume from a *different*
context re-proves from scratch. The "terminate other sessions" affordance is the
operator UX for F379-class revocation: one action, all downstream sessions die.

**Falsifiable probe.** (a) Age out one factor of a compound authority (e.g. policy
version bumped, key still fresh); re-verification MUST demand only the stale factor's
re-proof, not full re-issuance. (b) Resume a workflow from a different runner identity;
it MUST re-prove authority rather than inherit the checkpoint's. (c) Operator
"terminate all sessions for principal P" MUST invalidate every outstanding grant
within one propagation bound.

**License / fetch gaps.** MIT (repo README badge + LICENSE, 2026-10-03); the
`authentik/enterprise/` directory carries a separate EE license — stay on OSS core.
One libhunt mirror lists GPL-3.0 (stale/third-party); the repo's own badge is MIT —
reverify raw LICENSE bytes at vendoring time per standing rule.
Sources: https://github.com/goauthentik/authentik/issues/24270 (per-factor freshness);
https://github.com/goauthentik/authentik/blob/HEAD/website/docs/security/security-hardening.mdx (session binding);
https://github.com/goauthentik/authentik/blob/HEAD/website/docs/releases/2026/v2026.8.mdx (key-bound tokens, OBO)

**Verdict: ADAPT.** Per-factor freshness records + session binding as relocation
detection + terminate-other-sessions as the operator revocation affordance.

---

## 6. JanssenProject/jans — ADAPT (session states, idle lifetimes, global revocation, UMA tickets)

**Mechanism.** Linux Foundation IAM suite; the Auth Server is a certified OIDC
provider. Session model: a session is a *reference identifier* with two states —
`unauthenticated` / `authenticated` — cached server-side, with a `lastUsedAt` updated
on every authentication attempt. Timeout discipline is explicit and multi-knob
(`sessionIdLifetime`, `sessionIdUnusedLifetime`,
`sessionIdUnauthenticatedUnusedLifetime`, `refreshTokenExtendLifetimeOnRotation`,
plus per-flow timeouts for CIBA/UMA/Device) — the docs' "Timeout Management" page is
honest that "the holy grail of timeouts is when everything times out at the same
time... this is rarely attainable," and puts the burden on the RP to handle IDP-first
expiry gracefully. Two more mechanisms: a **Global Token Revocation endpoint** (kill
another principal's session — the operator affordance), and **UMA 2.0** — the
permission ticket (short-lived, single-use correlation handle: RS registers intent,
client trades ticket for RPT at the AS) with the RPT carrying the actual granted
permissions for the session.

**Sasanam seam.** Three steals: (1) the session *state machine* (`unauthenticated` →
`authenticated`, never a bare boolean) — our grants lack an explicit
"issued-but-not-yet-activated" state, which is where TOCTOU lives; (2) the idle-timeout
knob distinct from absolute lifetime (`sessionIdUnusedLifetime`) — our leases have
TTL but no idle death, so a compromised-but-unused grant lives its full TTL;
(3) UMA's permission ticket as the shape for our approval-gated steps: a short-lived,
single-use ticket minted at the enforcement point, traded for the real token at the
authority — this is a cleaner primitive than our current bearer-grant recall for
cross-namespace work.

**Falsifiable probe.** (a) Idle timeout: a grant unused for > idle bound MUST die
even with absolute TTL remaining. (b) Global revocation: operator revocation of
principal P MUST kill P's sessions without P's cooperation. (c) UMA-ticket shape: a
permission ticket presented twice MUST refuse (single-use); a ticket minted for
resource X presented for resource Y MUST refuse.

**License / fetch gaps.** Apache-2.0 — GitHub repo metadata "License: Apache License
2.0 (Apache-2.0)", Linux Foundation project (2026-10-03). Fetch gap: none.
Sources: https://docs.jans.io/v1.4.0/janssen-server/auth-server/session-management/ ;
https://docs.jans.io/v1.1.4/admin/planning/timeout-management/ ;
https://github.com/erickirt/jans/blob/HEAD/docs/janssen-server/auth-server/session-management/README.md (global token revocation, session events)

**Verdict: ADAPT.** Session state machine + idle-timeout knob + global revocation
endpoint + UMA permission-ticket shape for approval-gated steps.

---

## 7. Keyfactor/ejbca-ce — WATCH (revocation machinery; LGPL trap)

**Mechanism.** Longest-running open-source CA. The authority-lifecycle machinery:
certificate states (not-yet-valid / valid / expired / **revoked** / **suspended**),
a dedicated **Validation Authority** role answering "is this still valid?" via OCSP
(per-cert online query) and CRL (periodic list, default cadence ~24h, manually
publishable on demand — `ejbca.sh ca createcrl`), delta CRLs, CRL invalidity dates,
and the OCSP responder's archived-vs-revoked status logic. The CA/RA/VA separation is
the architectural point: issuance, registration, and *validation* are distinct
roles — validation is a service, not a library call.

**Sasanam seam.** Pattern only (license trap). Two ideas worth carrying: (1) the
**suspended** state between valid and revoked — our revocation is binary; a
"suspended pending investigation" state for grants would let an operator freeze
authority without destroying the audit trail; (2) the VA as a *role*: our revocation
checks are library calls inside the enforcement path; a dedicated validation service
with its own key and audit log is the post-v1 shape for "who vouches that this grant
is still good."

**Falsifiable probe.** (a) Suspend a grant; presentations MUST refuse with a
suspended-specific code (distinct from revoked/expired), and unsuspend MUST restore
without re-issuance. (b) Validation-service shape: a revocation check answered by a
signed VA response MUST verify the VA's signature, not just trust the answer.

**License / fetch gaps.** **LGPL-2.1** — GitHub repo metadata "GNU Lesser General
Public License v2.1 (LGPL-2.1)" (2026-10-03). Weak copyleft: pattern-steal posture
only, never vendor (standing rule: Apache-2.0/MIT for reuse). Fetch gap: none.
Sources: https://docs.keyfactor.com/ejbca/latest/using-ejbca-as-a-certificate-management-system-cms ;
https://docs.keyfactor.com/ejbca/latest/crl-generation

**Verdict: WATCH.** Suspended-state + VA-as-a-role are post-v1 patterns; LGPL keeps
it at pattern-only.

---

## Runner-ups (genuinely new, not rendered — WATCH)

- **cloudflare/cfssl** (BSD-2-Clause, 2 prior mentions, no verdict): OCSP/CRL
  responder + short-lived cert profiles; the `ocspsign` flow is the minimal VA.
- **casdoor/casdoor** (Apache-2.0, 1 mention): session/token management in a
  lighter IdP; revisit if authentik's shape proves too heavy.
- **logto/logto** (MPL-2.0 per public metadata — weak copyleft, pattern only):
  session management; kept out for the license.
- **shibboleth** (Apache-2.0, 0 mentions): SAML session + SLO semantics older than
  CAS; CAS covers the ticket shapes better.
- **FreeIPA** (GPL — trap exhibit): HBAC + session; pattern only.
- **lldap** (GPL — trap exhibit): lightweight directory sessions; pattern only.

## License-trap table (this wave)

| Repo / product | Trap | Posture |
|---|---|---|
| HashiCorp Vault / Boundary | BSL-1.1 (already recorded, wave-252) | Pattern only — the *lease* model (TTL, renewal, revocation cascade) is the exhibit for authority lifecycle; never vendor |
| goauthentik/authentik `enterprise/` | Proprietary EE license dir alongside MIT core | Stay on OSS core; verify file-level at vendoring |
| Keyfactor/ejbca-ce | LGPL-2.1 (weak copyleft) | Pattern only (WATCH) |
| lldap | GPL | Exhibit only |
| privacyIDEA | AGPL | Exhibit only |
| Teleport (prior wave, recorded) | Dual-layer: AGPL source + eligibility-gated CE binaries | SKIP stands — do not re-litigate |
| Zitadel (prior wave, recorded) | AGPL-3.0-only since v3 | SKIP stands |

## Spec primary sources (cited, not ranked)

- **RFC 8693 — OAuth 2.0 Token Exchange:** delegation (`act` claim) and impersonation
  tokens; the exchanged token's lifetime MUST NOT exceed the original's — the
  standards-body version of "delegation narrows, never widens," now with a lifetime
  bound. Direct input to our delegation-receipt lifetime rules.
- **RFC 9449 — DPoP:** sender-constrained access tokens; the DPoP proof binds the
  token to a key the client holds, with server-provided nonces against replay. The
  standard shape for "resume re-proves authority": the presenter proves key
  possession at *every* use, not just at issuance.
- **RFC 9470 — OAuth Step-up Authentication:** `authn` challenge protocol for
  demanding a fresher/higher-assurance authentication mid-session. The wire shape for
  our claims-challenge analog.
- **OpenID CAEP / Shared Signals Framework:** security event streams
  (`session-revoked`, `credential-change-required`, `device-compliance-change`) from
  transmitter to receiver — the open-standards sibling of Entra CAE's critical
  events. The event vocabulary for our SLO fan-out.
- **NIST SP 800-63B §7:** reauthentication intervals (12h AAL1 / 15min inactivity
  at AAL2+), session binding, SHALL terminate sessions on logout. The compliance
  anchor for our timeout knobs.

## New standing design rule (extracted)

**"Authority is a lease with a heartbeat — issuance is a moment; validity is a stream
of re-proofs, and silence revokes."**

Every long-lived grant in Sasanam should carry: a TTL (absolute death), an idle
bound (death by disuse), a refresh discipline (re-verify at `lifetime − skew`, never
at expiry), and a critical-event subscription (death by news). A grant that cannot
produce a fresh heartbeat is not "expired soon" — it is already dead.
