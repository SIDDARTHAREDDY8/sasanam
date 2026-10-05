# "Borrowed-Crown": Agents Acting Under Someone Else's Identity

**INTERNAL RESEARCH ASSET — NOT A PUBLICATION.** Sasanam internal use only.
Do not reproduce, distribute, disclose, or publish outside the project without
explicit authorization. Patent decision pending (deferred) — treat as
confidential company research.

**Date:** 2026-10-05 · **Base:** sasanam `ad6a79db` (wave-345 merge) · **Spend:** $0
**Lane:** wave-346 lane 5 (research-lab-as-GTM playbook, adapted from the AIR
Security deep-dive: named attack classes with red-first evidence and honest
boundaries, internal-only per the deferred patent decision).

This is the second entry in the research-lab series. The first entry named
four DLP-obfuscation classes
(`research/w344-dlp-obfuscation-classes-2026-10-05.md`: JSFuck / Escape-Ladder /
Concat-Smuggle / Direction-Ghost + Homoglyph-Twin).

## Thesis

Every governance verdict is a statement about *who did it* — but in agent
deployments the acting identity is usually the weakest link in the chain. An
agent runs under a human's API key, a shared service account, or a
self-declared name in a prompt; when that agent takes a consequential action,
the audit trail says "the human did it" or "an agent did it" with no
verifiable binding between the two. Rig Security's whole product is built on
this observation: they **detect and attribute borrowed identities** at runtime
("block the agent, not the employee" — from our Rig deep-dive STEAL-BRIEF).
Detection, however, is ML-inference; it answers *probably*. The class below is
a vocabulary for the attack and for the cryptographic answer: the identity the
agent acts under must be *issued*, not *borrowed*.

## Class — "Borrowed-Crown"

**Name origin:** a crown confers authority on whoever wears it; the question
is whether the wearer was crowned or just found the crown lying around.

**Mechanism.** An agent acts under an identity it was never verifiably issued:
a shared API key, a human's session token, a self-declared `principal` in a
deployment config, or a forwarded OIDC token that nobody re-validated at
mint time. The tool-call packet records the claimed principal; nothing in the
chain ties the claim to an issuer. The damage is not a confused deputy — it is
a *confused owner*: when the action is disputed, the attribution says the
crown's name, and the real owner has no way to prove it wasn't them (or no
way to prove it was).

**Red-first evidence.** The ownership-inference seam (`gov/ownership_inference.py`,
wave-343 lane 4) and the verified-claim threading seam (wave-345 lane 6) are
the two halves of the answer, each pinned by deterministic batteries:

- `evals/w343_ownership_probes.py` — 0 BREAK / 9 HELD: the inference rules
  (verified email > directory subject > directory principal-known;
  a self-declared principal is only ever weakest-tier evidence and is
  honestly labeled as such; conflicts fail closed as
  `ownership-inference-ambiguous`; missing evidence fails closed as
  `ownership-inference-unresolved`; PII as digests).
- `evals/w345_ownthread_probes.py` — 0 BREAK / 12 HELD / 0 ERROR: verified
  `mint_identity` claims are threaded into every per-call decision packet as
  a signature-covered `identity_claims` section
  (`{verification_status, subject_digest, email_digest, email_verified,
  groups_count}`); stale claims cannot be inherited across re-mint; a
  mutated section breaks the packet signature; a forged value refuses at
  construction.
- `evals/w346_identity_surface_probes.py` (this lane) — the measurement
  battery for the claim surface: claim presence across packet types, tamper
  under wrong-key re-sign, self-declared-principal rejection,
  conflicting-evidence ambiguity, PII hygiene. 0 BREAK / 8 HELD / 0 ERROR,
  $0 spend by construction.

**Closure discipline.** The borrowed-crown is closed by making the binding
deterministic and evidence-backed, at issuance time — never inferred
heuristically at audit time:

1. **Issuance is the only trust boundary.** `mint_identity` captures the
   claim record with a `verification_status` naming *how* the claims were
   verified: `identity-token-verified` (federated, pinned JWKS), 
   `token-claims-validated` (validated token), `principal-registry`
   (tokenless, registry-checked), `self-asserted` (dev mode — loud,
   honest, unauthenticated).
2. **Self-declared principals are the weakest evidence, honestly labeled.**
   A `declared_principal` that names a known deployment principal resolves
   only at the weakest tier (`directory-principal-known`) with the source
   honestly recorded as `declared-principal` — it answers "is this
   principal known to the deployment", never "is this principal verified".
   A declared principal nobody registered resolves
   `ownership-inference-unresolved`; a declared principal that *disagrees*
   with verified evidence refuses `ownership-inference-ambiguous` (no
   laundering a borrowed crown through the declaration field).
3. **Conflicts fail closed.** Two or more strong sources naming different
   principals raise `ownership-inference-ambiguous` — never a vote, never a
   guess. The packet carries the code, not a guess.
4. **The packet carries the binding, not the promise.** The
   `identity_claims` section is signature-covered; a swapped digest breaks
   the packet signature, and builder and verifier share the same checker —
   they can never disagree.
5. **Unverifiable is explicit, never silent.** Session/provisioned identities
   that bypass `mint_identity` carry no claim record: their packets honestly
   omit the section (no claim of verification that never happened).

**Honest boundaries.** The closure does not cover everything, and what it does
not cover is documented, not hand-waved:

- **Session/provisioned identities bypass minting.** `_provision_session_identity`
  and `spawn_sub_agent` paths produce identities without verified claims —
  their packets honestly omit the section, but an auditor sees
  declared-only attribution for them. Fail-closed by construction, not a
  finding; but it is the next crown to mint, not the last.
- **Directory poisoning.** The ordering (verified email > directory subject >
  directory principal-known) assumes the directory is a trust anchor. If an
  attacker writes the directory, inference trusts the poison — same as any
  PKI trusts its CA list. The directory's own integrity is out of this
  class's scope.
- **Self-asserted mode is unauthenticated.** In dev mode minting warns loudly
  (one-time stderr) and marks `self-asserted`. The status exists so a
  borrowed crown cannot launder itself as a verified one.
- **Groups are corroboration only.** Group membership never decides an
  owner — it decorates the evidence, never votes.
- **Email without verification is not evidence.** An `email` claim with
  `email_verified != True` is ignored entirely (fail-closed; P3).

## The Rig contrast (from our deep-dive, internal read)

Rig's RICE engine infers ownership with ML (fuzzy matching → graph
clustering → XGBoost → behavioral fingerprints) and claims 96.8% internal
accuracy; Gatewatch blocks locally on inferred identity. Our answer is the
precision opposite: **issued cryptographic identity with deterministic
attribution**. Their worldview is brownfield — agents keep borrowing human
creds, so detect the borrowing. Ours is greenfield — agents get their own
issued identities, so there is nothing to borrow. Both are true in different
segments; the stolen framing ("block the agent, not the employee") applies to
both. We do not copy their worldview (borrowing forever) or their
unverifiable accuracy marketing — our evidence is deterministic, pinned, and
offline re-verifiable.

## Report card (as of base `ad6a79db`)

| Surface | Artifact | Status | Evidence |
|---|---|---|---|
| Ownership inference rules | `gov/ownership_inference.py` | LANDED | w343_ownership_probes: 0/9/0 |
| Verified-claim threading | `gov/executor.py` + `gov/decision_packet.py` | LANDED | w345_ownthread_probes: 0/12/0 |
| Claim-surface measurement | `evals/w346_identity_surface_probes.py` | NEW (this lane) | 0/8/0 |
| Session-identity claims | — | OPEN residual (documented boundary) | honest omission, not a finding |

The next entries in this series belong to the remaining DLP residuals (F436:
base64-run poisoning) and to the session-identity claim path when it lands.
