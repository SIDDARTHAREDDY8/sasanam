# K-026 — Authenticated Inter-Agent Messaging: Design Scope (Wave 23)

**Status:** DESIGN ONLY — no implementation without architect review.
**Gap:** structural gap per `workstreams/architect/REALWORLD_BAR.md`
("CrewAI/AutoGen/raw-HTTP adapters + K-026 authenticated inter-agent
messaging not built").
**Depends on / unblocks:** `DELEGATION_PRIMITIVE_SPEC.md` §7 names K-026
as the transport for inter-deployment delegation (currently a non-goal:
"single deployment trust domain"). D1-core's delegation/quorum assume a
single deployment; K-026 is what lets the same guarantees cross
deployment boundaries.

## 1. Problem statement

Today, agents inside one deployment are identified by caller-identity
stamping (F42: `agent_id`/`role`/`run_id`/`principal`/`provenance`,
minted at approval-queue time). The moment a message leaves the
deployment — agent A in deployment 1 delegating to agent B in deployment
2 — that identity is *asserted by the sender*, not *verified by the
receiver*. There is no signed envelope, no key directory, no freshness
check. Consequences:

- **Spoofing:** any process that can reach the transport can claim to be
  `agent_id=support-1, principal=customer-org`.
- **Replay:** a captured delegation instruction can be re-sent.
- **Tamper:** payload can be altered in flight with no detection.
- **Confused deputy across deployments:** the receiving deployment's
  `delegatee_mismatch` refusal (load-bearing in the delegation spec)
  has nothing trustworthy to check against.

K-026 does not invent a new identity: it *transports* the existing
`AgentIdentity` with cryptographic authentication.

## 2. Design: reuse, don't rebuild

The building blocks already exist in `gov/`; K-026 is a composition:

| Need | Existing primitive |
|---|---|
| Sign/verify | `gov/signing.py` `Signer`/`Verifier`, `Ed25519Signer`/`Ed25519Verifier` over pure-Python `gov/ed25519.py` (RFC 8032 self-tested) |
| Envelope shape | `gov/identity.py::build_attestation` — signed dict with `attestation_version`, `identity` (agent_id/role/run_id/principal/provenance), flat `str->str` `claims` (constrained disclosure), `nonce`, `issued_at`, `attester_key_id`, `sig` over `_canonical_json` |
| Verification | `gov/identity.py::verify_attestation(att, trusted_keys, expected_nonce, max_age_s)` — already checks version, identity fields, flat claims, key membership, Ed25519 signature, and freshness via nonce or max-age |
| Key lifecycle | `gov/keys.py` `KeyRing` + `gov/kms.py` (no silent dev fallback) |
| Audit | `gov/log.py` hash-chained audit log (HMAC/Ed25519) — sent/received messages become log entries |

**Message envelope (v1):** an attestation-shaped envelope where
`claims` carries the message (payload digest + routing), not the raw
payload — constrained disclosure by default. Full proposal:

```json
{
  "k026_version": 1,
  "envelope_id": "<uuid hex>",
  "sender": {"agent_id": "...", "role": "...", "run_id": "...",
             "principal": "...", "provenance": "..."},
  "recipient": {"deployment": "...", "agent_id": "..."},
  "payload_digest": "<sha256 hex of canonical payload>",
  "claims": {"intent": "delegate|notify|...", "scope_ref": "<grant-id>"},
  "nonce": "<random hex>",
  "issued_at": "<UTC ISO>",
  "sender_key_id": "<ed25519_key_id>",
  "sig": "<ed25519 hex over canonical body>"
}
```

Receiving side: (1) `sender_key_id` ∈ enrolled `trusted_keys` for the
claimed sender deployment; (2) Ed25519 verify; (3) freshness —
`issued_at` within `max_age_s` AND `nonce`/`envelope_id` not seen before
(replay ledger, bounded); (4) `payload_digest` matches the delivered
payload; (5) map sender identity into a **TOOL-level, untrusted**
`tag_privilege` item — received content is data, never
auto-promoted (StruQ quarantine still applies at the receiving
adapter); (6) delegation checks (`delegatee_mismatch`, grant-id lookup)
run against the *verified* sender, not the asserted one.

## 3. Trust model (explicit)

- **Trust domain = deployment.** Keys are per-deployment (one
  deployment attestation key, held in that deployment's KMS/KeyRing),
  not per-agent: agents are identified *inside* the signed envelope.
  This matches F42 (deployment mints caller identities) and keeps key
  management tractable.
- **Out-of-band enrollment.** Deployment B learns deployment A's public
  key via an enrollment step (operator-approved, audit-logged), not via
  the message channel. No TOFU.
- **Signing ≠ confidentiality.** v1 provides authenticity/integrity/
  freshness only. Payload confidentiality (sealed transport) is a
  separate decision — stdlib has no X25519; adding one is new crypto
  surface and is explicitly deferred to the architect's call.
- **Fail-closed receive:** any verification failure → message dropped,
  `k026_verify_failed` audit event, never delivered to the agent.

## 4. Phased plan (for architect sequencing)

- **P0 — envelope + verification (stdlib only):** `gov/messaging.py`
  (envelope build/verify on top of `signing`/`identity` primitives),
  in-process sender/receiver, key-directory file format, replay ledger.
- **P1 — transport binding:** ride on `gov/bridges/` (A12, sequenced)
  as the cross-deployment transport; do NOT build a new raw-HTTP
  adapter (STOP list frozen).
- **P2 — enrollment UX + rotation:** operator enrollment ceremony,
  key rotation via `kms.py` lifecycle, revocation list.
- **P3 — red-team acceptance battery** (registered before any "done"
  claim): replay within/after max_age, tamper payload, key-swap
  (attacker key not enrolled), stale message, cross-principal
  confusion (`principal` mismatch vs. local registry), envelope
  downgrade (k026_version tamper).

## 5. Non-goals

- New framework adapters (CrewAI/AutoGen/raw-HTTP — STOP frozen).
- TLS/SSO/OIDC/multi-tenancy (enterprise readiness explicitly not
  built per STOP S6).
- Bearer-token grants or capability URLs in args (rejected by the
  delegation spec's decision 1: server-side grant records only).
- Confidential payload transport in v1 (authenticity first; see §3).
- Changes to single-deployment behavior when K-026 is disabled.

## 6. Open questions for the architect (max 5)

1. **Confidentiality in v1?** Recommendation: no — authenticity/
   integrity/freshness first; sealed transport as a separate K-item so
   the crypto review stays small.
2. **Per-deployment vs per-agent keys?** Recommendation: per-deployment
   (matches F42 minting; agent identity rides inside the envelope).
3. **Replay ledger backend?** Recommendation: bounded in-memory +
   audit-log spillover, same pattern as the approval queue.
4. **max_age_s default?** Recommendation: 300s, deployment-configurable;
   challenge-response nonce for interactive handshakes.
5. **Enrollment ceremony shape?** Recommendation: operator CLI reusing
   `PrincipalRegistry` semantics (principals already have
   allowed-roles/agent-ids); audit-logged, no TOFU.

## 7. Acceptance criteria (before implementation waves start)

Architect sign-off on §2–§6; P3 battery registered in
`evals/scenarios/registry.yaml` with expected verdicts; and a
red-team review of the envelope spec (signature malleability,
canonicalization edge cases — e.g. non-`str` claim values rejected as
in `build_attestation`) before P0 code lands.
