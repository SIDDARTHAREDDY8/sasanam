# Wave-67 D5 — Authenticated Consumer Registry for Acknowledgment Evidence

**Status: designed + implemented + break-first tested (2026-09-22).**
$0, stdlib only (hmac, secrets, time). Deterministic (injectable clock).

## The gap this closes

Waves 64–66 built the D5 acknowledgment audit trail: `Unvetted.acknowledge()`
records who unwrapped never-vetted data into a hash-chained log via
`AckAuditSink` and `ToolExecutor.drain_ack_sink`. One field was
SELF-ATTESTED by design: `consumer`. The wave-65 honesty definition said so
plainly — "NOT that consumer_id is authenticated". For the founder's
evidence bet (sell evidence, not the engine), unattributable evidence is
weak evidence: an auditor cannot distinguish "the loop acknowledged" from
"anyone typed a consumer name".

This wave adds an *authenticated* consumer registry. It does not make
authentication mandatory — that would break existing callers (Wave-49
lesson) and exceed what in-process code can enforce against hostile
actors (F59 residual). It makes authentication *available*, machine-
verifiable, and honestly labeled in the chained record.

## Design answers

### (a) Where the registry lives; who issues tokens

**Deployment-scoped, never run-scoped.** The registry is owned by the
deployment's consumer-registration authority — the same standing
convention as `VettingStack` standing in for the deployment's
content-defense stack: in-repo tests construct a `ConsumerRegistry`
directly; a real deployment wires its own registration service
(operator console, deployment IAM, onboarding flow) behind it.

**The executor never issues consumer tokens.** Issuance and verification
are split deliberately: the executor is log-owned infrastructure inside
the run being evidenced. A run minting its own evidence tokens is
self-attestation with extra steps. Issuance belongs to the deployment
operator *outside* the evidenced run; the run-side code (sterile.py,
the executor) only *verifies* tokens against the registry.

In-repo the registry object is the stand-in for the deployment's
registration authority — exactly as `VettingStack` stands in for the
content-defense stack.

### (b) Token lifecycle

- **Issue:** `registry.register_consumer(consumer_id, ttl_s=None)` returns
  a `ConsumerToken`. The token is a 256-bit bearer bound by an HMAC
  (registry's 256-bit mint secret) over `(public_token_id, consumer_id,
  issued_at, ttl_s, bearer)`. Non-serializable, non-copyable —
  `VettingCapability` precedent: possession is by reference, the secret
  never serializes, `copy`/`deepcopy`/`pickle` all raise.
- **Use:** the consumer presents `(consumer_id, token)` at
  `Unvetted.acknowledge(..., consumer_token=tok, registry=reg)`.
  Verification is constant-time (`hmac.compare_digest`) and checks, in
  order: token type, MAC validity, bound consumer_id matches the claimed
  consumer_id (token theft across names fails LOUD), TTL not expired,
  public token id not revoked.
- **Expiry:** optional `ttl_s` at registration; the registry's injectable
  clock decides. Expired tokens verify-fail (loud), never degrade to
  "unattributed".
- **Revocation:** `registry.revoke(public_token_id)` adds the id to a
  revoked set; `register_consumer` mints `cap-<64 hex>` public ids, so
  two registrations of the same consumer_id get distinct ids.
- **History is append-only:** revocation and expiry change what future
  acks may claim — they NEVER rewrite already-chained records. A revoked
  token's past acks keep their `attribution: "authenticated"` mark with
  the public `token_id` and `ts` in the record, so an auditor verifies
  validity-at-time. No retroactive laundering of the chain, ever.

### (c) The anonymous path — tokens are NOT mandatory

`acknowledge(consumer_id)` with no registry/token behaves exactly as
wave-66: the record is stamped `"attribution": "unattributed"`.
Existing battery scenarios, executor paths, and any third-party callers
keep working byte-identically (Wave-49 lesson: a registry that breaks
legitimate acknowledgment is a regression, not a feature).

Can an attacker "launder" a sensitive acknowledgment as unattributed?
Yes — and that is the **designed behavior, graded honestly, not filed**:
the record marks it `unattributed` explicitly. Laundering requires no
more privilege than acknowledging at all (the anonymous path was always
open). A deployment that needs attribution for sensitive flows enforces
it at ITS policy layer ("this window/flow refuses unattributed acks") —
that is a deployment decision the mechanism supports, not a mechanism
miss. The mechanism's guarantee is narrower and exact: nothing reaches
the chain marked `authenticated` without a live, valid, registry-issued
token bound to the named consumer.

### (d) What "authenticated" actually proves — the precise claim

`"attribution": "authenticated"` means exactly:

> At ack time, the caller presented a bearer token issued by this
> registry, HMAC-bound to the named `consumer_id`, whose registry entry
> was neither expired nor revoked at ack time. Verified in-process by
> constant-time MAC comparison against the registry's secret.

It does NOT prove:

- **Human identity.** The registry authenticates a *registration*, not a
  person. What identity a registration maps to (operator console
  account, deployment IAM principal, onboarding token) is the
  deployment's registration-authority design — outside this layer.
- **Non-theft.** A stolen token used by another in-process holder,
  naming the token's bound consumer, verifies fine: **possession is the
  claim**. Token theft *across names* fails loud (bound id ≠ claimed
  id); theft *within* the bound name is an in-process residual, same
  class as F59. The record names the registration, never the holder.
- **Reading, understanding, or use.** Wave-65's honesty definition
  stands: "acknowledged" = the marker was unwrapped by the named
  consumer.
- **Payload safety.** The mark says nothing about the payload.

The evidence buyer's summary: this layer proves *which registration's
token was presented at ack time*, with honest unattributed marks where
no token was presented. It does not prove who pressed the key.

## Record shape (additive, wave-66 compatible)

The `unvetted_acknowledged` record gains:

- `"attribution"`: `"authenticated"` or `"unattributed"` (always present).
- `"token_id"`: the token's public id (present only when authenticated;
  non-secret, safe to chain).

All wave-66 fields (`event/consumer/origin/ack_context/count/ts`)
unchanged. `drain_ack_sink` needs no change — records flow through
`entry.update(rec)`; the executor's reserved-key re-stamp
(run_id/agent_id/role log-wins) is untouched. `consumer`/`token_id`
stay caller-asserted, exactly as `consumer` was in wave-65.

## Failure ordering (fail-closed, loud)

`acknowledge()` with a registry:

1. `registry.verify(token, consumer_id)` — raises `ConsumerAuthError`
   (a `VettingError` subclass) on ANY failure: wrong type, MAC mismatch
   (forgery, bit-flip, foreign-registry token), consumer_id mismatch,
   expiry, revocation. No record is appended; the payload is never
   returned.
2. Record (with `attribution`/`token_id`) appended to the sink — a
   raising sink still withholds the payload (wave-65 ordering).
3. Payload returned.

A token presented with no registry to verify against raises loud
(fail-closed: never "trust me, it's fine"). A registry given with no
token → honest `unattributed`. There is deliberately no
invalid-token→unattributed degradation path: silent downgrade would be
a laundering primitive.

## Boundaries (documented, not filed)

1. **In-process token theft within the bound name** (holder B uses A's
   token naming "A"): verifies as A. Possession is the claim; the
   evidence buyer is told this in (d). F59-class residual.
2. **Registry secret custody**: whoever holds the `ConsumerRegistry`
   object can mint. In-repo it is a test object; the deployment's
   registration authority owns real custody (operator KMS territory —
   same posture as the standing dev-key notes).
3. **Replay across runs**: the registry is deployment-scoped, so a
   token is valid across runs until it expires or is revoked — by
   design. Cross-run replay is not an attack against this design;
   ttl/revocation are the lifecycle tools.
4. **Token theft across names**: fails loud by construction (bound-id
   check). Pinned by probe, not a boundary — it holds.
5. **Deployment-scoped issuance**: in-repo the registry stands in for
   the registration authority (VettingStack precedent). A deployment
   that lets the run mint its own consumer tokens re-opens
   self-attestation; the design doc says so explicitly.

## Break-first battery (`evals/w67_probes.py`, 8 SITUATIONS)

All `stopped` standalone and in-registry (`redteam.sterile_d5_reg.*`):

| probe | attack lane | verdict |
|---|---|---|
| `token_forgery_refused` | mint without the registry; flip bits in bearer and MAC; foreign-registry token | HOLD (ConsumerAuthError, no record, no payload) |
| `cross_name_theft_refused` | A's token presented naming "B" | HOLD (loud refusal, no record) |
| `same_id_two_consumers_distinguished` | two registrations, same consumer_id | HOLD (distinct token_ids; chained records distinguishable; both valid) |
| `revocation_fail_closed_history_append_only` | revoke mid-stream; then re-present | HOLD (future acks refuse loud; past chained records keep attribution+token_id+ts — history not rewritten) |
| `anonymous_laundering_honest` | ack with no token → launder as unattributed | BOUNDARY (designed behavior: honestly marked `unattributed`; deployment policy decides refusal) |
| `invalid_token_never_degrades` | garbage token + registry; token without registry | HOLD (loud, never silent unattributed) |
| `expiry_enforced` | ttl_s elapsed on registry clock | HOLD (expired verifies fail; pre-expiry acks keep their mark) |
| `legit_loop_regression` | executor close→acknowledge→drain, with and without registry; sink=None path | HOLD (byte-identical legacy behavior; authenticated path drains end to end) |

## What was deliberately not built

- **Mandatory tokens** (Wave-49 lesson: would break existing callers).
- **Human-identity binding** (outside the layer; the registry binds
  registrations, the deployment binds registrations to people).
- **Revocation-history rewriting** (append-only chain is the whole
  point; validity-at-time via token_id + ts).
- **Token-use audit at the registry** (the registry verifies, the
  chained record is the audit — single evidence trail, no second book).
- **Cross-registry federation** (one deployment, one registry; foreign
  tokens fail closed).
