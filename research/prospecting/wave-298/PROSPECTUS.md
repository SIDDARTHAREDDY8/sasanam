# Wave-298 Prospectus — Agent Delegation & Authority-Transfer Governance

**Lane:** 6 (standing prospecting — research only). **No code, no commits, no clones. $0 spend.**
**Theme:** how authority legitimately MOVES between agents — delegation chains, sub-agent spawning authority, attenuation (least privilege down a chain), revocation propagation, confused-deputy resistance, and what evidence a downstream agent holds that its authority is real.
**Method:** 7 teardowns below (mechanism / Sasanam seam / falsifiable probe / license / fetch gaps / verdict), runner-ups, license-trap table, one standing design rule, build sequencing.

## Coverage audit

All `wave2*-prospect/PROSPECTUS.md` files swept with ripgrep, including substring sweeps. Every pick below has **zero prior teardowns** (0 hits for: `agoric`, `capnproto`, `krb5`, `fuchsia`, `spruceid`, `go-attestation`/`go-tpm-tools`, `tahoe`).

Excluded as already rendered (replaced, per the no-repick rule):
- `go-macaroon-bakery/macaroon-bakery` — ADAPT (pattern), wave-264 §2 (LGPL-3.0 trap)
- `biscuitsec/biscuit` — covered wave-228 P10 + waves 223–237
- `ucan-wg/ucanto` — covered wave-264 §1
- `w3c-ccg/zcap-ld` — covered wave-290 (zcap-py reference)
- `spiffe/spire` — covered (30+ corpus files; ADAPT principle-only wave-178)
- `square/ghostunnel` — ADAPT wave-188
- `letsencrypt/boulder` — SKIP wave-258 (MPL-2.0 trap)
- GNAP (RFC 9632) — WATCH wave-290
- `smallstep/certificates`, `zitadel`, `keycloak`, `ory/hydra`, `casbin`, `authzed/spicedb`, `tailscale`, `temporalio/temporal` — all previously rendered or heavily mentioned

---

## 1. capnproto/capnproto — **STEAL** (MIT)

**What it is.** Cap'n Proto's RPC layer is a distributed object-capability system: an interface reference *is* a capability — it both designates the object and confers permission to call it. "It is impossible for others to access the capability without consent of either the host or the receiver because the host only assigns it an ID specific to the connection over which it was sent." Least privilege falls out naturally; confused-deputy attacks are structurally avoided, not policy-checked.

**Mechanism to steal.** *Delegation = passing a reference; the reference is unforgeable by construction.* There is no separate authorization table to keep in sync, no bearer string that can be guessed or replayed from a log. Attenuation is done by interposition: wrap the capability in a narrower facet before handing it down — the downstream agent literally cannot name the wider authority because it was never given the reference.

**Sasanam seam.** `gov/delegation.py` (new): delegation receipts as unforgeable, connection-scoped references. Plugs into `approval_request` (the request digest becomes the designated object) and `coordination_lease` (a lease grant is a capability; fencing tokens are the "connection-specific ID" analogue). Also the confused-deputy answer for the wave-293 tool-sequence rules: a tool callable handed to a sub-agent is a capability, not a name to be resolved.

**Falsifiable probe.** (a) Serialize a delegation receipt to JSON, hand the bytes to an untrusted test agent — it must NOT be able to reconstitute a live capability from the bytes alone (no ambient rehydration). (b) Attenuate: delegate a write-capability wrapped to read-only; attempt write through the wrapped ref — must refuse, and the *unwrapped* original must be unreachable from the delegate's namespace. (c) Confused deputy: agent A holds cap(tool-X); agent B tricks A into invoking tool-X with B's arguments — the invocation must be attributed to A's authority, logged against A's identity, never B's.

**License.** MIT (permissive). Raw LICENSE bytes to be reverified at vendoring time.

**Fetch gaps.** The RPC security model is documented prose, not a separable library — we steal the *semantics* (unforgeable refs, interposition-as-attenuation), not code.

---

## 2. Agoric/agoric-sdk — **STEAL** (Apache-2.0)

**What it is.** A JavaScript smart-contract platform built on object-capability (ocap) discipline end to end: SES/Hardened JS compartments, ERTP (Electronic Rights Transfer Protocol: purses hold rights, payments transfer them — the *transfer itself* is the delegation), and the Zoe contract framework ("offer safety": users get what they were offered or a full refund, even if the contract fails). The OCap Discipline wiki states the rule that matters for us: *"modules should not export powerful objects… program scripts are free to import all the authority they need and then delegate it."*

**Mechanism to steal.** Two things: (1) **No ambient authority** — anything globally accessible is immutable data; every authority-bearing power arrives as an explicit argument (endowment). (2) **Attenuation by construction**: ERTP payments are attenuated rights — a payment for 5 tokens out of a purse of 100 is a *new object* conferring only 5, not a view with a policy check. Zoe's offer safety is the escrow pattern: the intermediary holds, reallocates, and refunds — the delegate never touches the principal's full balance.

**Sasanam seam.** This is the engineering discipline for `gov/delegation.py` and the wave-297 `supervision.py` child inventory: a spawned sub-agent receives *only* the attenuated capability objects it is declared to need (cf. Fuchsia pick #4 for the declaration syntax). Also the answer to "what evidence a downstream agent holds": it holds the payment-like attenuated object plus the signed chain back to the mint — verifiable without the engine, like an offline evidence bundle.

**Falsifiable probe.** (a) Spawn a test sub-agent with an attenuated payment object; attempt to exercise the un-attenuated parent right through prototype/constructor reachability (`__proto__`, constructor, global lookup) — must fail (no ambient authority). (b) Zoe-pattern: run a delegated multi-step task through an escrow intermediary; kill the intermediary mid-task — the principal's unconsumed authority must be refundable/recoverable, never stranded or double-spendable.

**License.** Apache-2.0 (footer "Apache-2.0 Licensed"; agoric-sdk LICENSE). Reverify raw bytes before vendoring.

**Fetch gaps.** JavaScript compartments don't map 1:1 to Python; we reimplement the discipline (frozen objects, explicit endowments, no module-level powerful singletons) in stdlib Python rather than porting SES.

---

## 3. krb5/krb5 (MIT Kerberos) — **ADAPT** (MIT-style permissive license)

**What it is.** The oldest production delegation system on earth: ticket-granting tickets (TGTs) and the TGS exchange. The delegation-relevant machinery: **forwardable tickets** (a TGT copy minted with a *new session key* for the target service — delegation that is traceable and auditable), the `ok-as-delegate` / `ok-to-auth-as-delegate` principal flags (the *service*, not the client, declares whether delegation to it is acceptable), and **constrained delegation** (S4U2Self/S4U2Proxy: a service obtains tickets *to itself* on behalf of a user, then exchanges them only for named downstream services — no user password, no open-ended impersonation).

**Mechanism to adapt.** Three stealable distinctions: (1) **Delegation is a first-class ticket type**, not a flag on the original credential — the delegate gets a *different* ticket with its own session key, so misuse is attributable. (2) **The recipient opts into being a delegate** (`ok-as-delegate`) — delegation requires the downstream's declared consent, which kills confused-deputy-by-default. (3) **Constrained delegation names the downstream set** — `msDS-AllowedToDelegateTo` is an explicit allowlist; anything not named refuses.

**Sasanam seam.** `gov/delegation.py` ticket model: a delegation receipt names the delegate *and* the downstream scope; a `to_self`-style exchange lets a supervisor agent act on behalf of a principal only toward declared services. The `ok-as-delegate` flag becomes a per-agent declaration in the supervision child inventory (wave-297): a child that never declared itself delegable cannot receive delegated authority, even from its own parent.

**Falsifiable probe.** (a) Delegate with a constrained downstream set {tool-A}; attempt tool-B through the delegation — must refuse with a delegation-scope code. (b) Delegate to a child that did NOT declare `ok-as-delegate` — issuance itself must refuse (not just use). (c) Replay a delegation ticket after the upstream grant was revoked — must refuse via epoch/revocation check (the Kerberos analogue of renewable-ticket expiry).

**License.** MIT Kerberos License (permissive, BSD-style). Reverify raw bytes before vendoring.

**Fetch gaps.** Kerberos assumes a trusted KDC; our KDC-analogue is the coordinator plane, which is *not* assumed incorruptible — every ticket must be verifiable offline by the auditor (evidence-bundle discipline), unlike a KDC-issued ticket.

---

## 4. fuchsia/fuchsia (component framework) — **ADAPT** (BSD-3-Clause / MIT / Apache-2.0 mix, permissive)

**What it is.** Fuchsia's component framework routes capabilities through a declared tree with three keywords: a child **`use`**s a capability, a parent **`offer`**s it (optionally with *narrowed rights* — the docs' own example shows an offer of `r*` failing a child's request for `rw*`), and a child **`expose`**s capabilities upward. Routing is static, declared, and fails closed: "the parent offers the directory `data` to component A with only read-only rights. In this case the routing fails and `data` wouldn't be present in A's namespace." Parents cannot `use` what they merely route (no dependency cycles, no silent privilege retention).

**Mechanism to adapt.** **Declared capability manifests with rights-attenuation at offer time.** The manifest *is* the delegation policy, checked before the component ever runs — not an audit-time reconstruction. The `expose`/`offer`/`use` trichotomy maps exactly onto supervisor/child delegation: a child exposes what it can do, the supervisor offers it to siblings only as declared, and `use` is the only verb that confers exercise authority.

**Sasanam seam.** Wave-297 `supervision.py` child inventory: extend `ChildSpec` with a capability manifest (`use`/`offer`/`expose` + rights). The supervisor becomes a Fuchsia-style component manager: spawning a child without a manifest refuses; a child requesting an un-offered capability refuses at spawn, not at first use. This closes the "undeclared child" finding class at the declaration layer.

**Falsifiable probe.** (a) Declare child manifest requesting `write` on a tool the parent offers as `read` — spawn must refuse (rights mismatch, Fuchsia's `rw*` vs `r*` case). (b) Supervisor attempts to `use` a capability it only routes between children — must refuse (no silent retention). (c) Child exposes a capability, parent offers it to a sibling NOT named in the manifest — must refuse.

**License.** Permissive mix (BSD-3-Clause / MIT / Apache-2.0 per the Fuchsia source tree). Reverify raw bytes before vendoring; do not vendor kernel code, only the manifest-routing semantics.

**Fetch gaps.** Fuchsia's enforcement lives in the kernel/component manager; ours lives in the supervisor's spawn path — same semantics, different trust anchor (documented).

---

## 5. spruceid/didkit — **ADAPT** (Apache-2.0)

**What it is.** A cross-platform toolkit for decentralized identity: DIDs (Decentralized Identifiers) and Verifiable Credentials, Trail-of-Bits audited (2022). The delegation-relevant piece is the VC data model's **`capabilityDelegation` proof purpose**: a DID controller can delegate control authority to another DID *in the DID document itself*, producing a verifiable, offline-checkable chain of "who may act for whom" with no central registry.

**Mechanism to adapt.** **Delegation chains as signed, resolvable, offline-verifiable documents.** Each link names controller → delegate + scope; the whole chain resolves without calling home. This is the portable form of "what evidence a downstream agent holds that its authority is real": the downstream agent holds the chain, and any verifier (including our offline evidence-bundle verifier) can walk it.

**Sasanam seam.** `decision_trace`: delegation links become trace edges (signed, ordered, reason-tagged — the wave-296 trace contract already supports edges; delegation adds a `delegated-authority` edge kind). Also agent identity: bind our agent key ceremony to DIDs so delegation chains are portable across coordinator planes.

**Falsifiable probe.** (a) Present a delegation chain with a link signed by a key NOT named as controller in the previous link — chain verification must refuse. (b) Present a chain where an intermediate link's scope is wider than its predecessor's — must refuse (attenuation enforced at verify time, not just issuance). (c) Verify a chain fully offline (no network, no coordinator) — must succeed with the same verdict as online.

**License.** Apache-2.0 (ecosyste.ms + repo badges agree; Trail of Bits audit 2022-03-14). Reverify raw bytes before vendoring.

**Fetch gaps.** DIDKit is Rust; we reimplement the *chain semantics* (controller → delegate, proof purposes, scope narrowing) in stdlib Python. JSON-LD canonicalization is out of scope — our chain uses canonical JSON like the rest of the tree.

---

## 6. google/go-tpm-tools — **ADAPT** (Apache-2.0)

**What it is.** Google's TPM 2.0 support library with a deliberate **client/server split**: the `client` package proves (signing, attestation, PCR reads, event log, sealing), the `server` package *verifies* (event-log parsing, attestation verification) without ever touching a TPM. Remote attestation: hardware-rooted evidence that a key was generated in, and a statement signed by, a genuine trusted platform.

**Mechanism to adapt.** **The prover/verifier split as an architectural pattern.** "What evidence a downstream agent holds that its authority is real" gets a hardware-rooted answer where TPMs exist and a ceremony-rooted answer elsewhere — but in both cases the *verifier side* is dependency-free and offline-capable. The TCG event log is the precedent for our delegation log: an ordered, replayable record of "what happened on this platform" that a remote party replays to reach the same trust conclusion.

**Sasanam seam.** Key ceremony + `decision_trace`: bind agent identity keys to attestation evidence at issuance; the delegation receipt carries an attestation digest, and the offline verifier replays the "event log" (our append-only delegation log, cf. pick 7's transparency idea) to confirm the platform that minted the authority. Where no TPM exists, the ceremony transcript plays the event-log role.

**Falsifiable probe.** (a) Mint a delegation receipt with attestation evidence from platform X; present it to a verifier with platform X's expected measurements altered by one PCR — must refuse. (b) Replay the delegation event log to a fresh verifier — it must reach the identical accept/refuse verdict (deterministic replay). (c) Strip the attestation block from a receipt — must refuse (evidence-required), never downgrade to unattested.

**License.** Apache-2.0 (badge + Legal section). Reverify raw bytes before vendoring.

**Fetch gaps.** No TPM in this VM and none assumed in deployment; the attestation *format* is adapted, with the ceremony transcript as the software fallback. Never claim hardware root where none exists (honest-boundary rule).

---

## 7. tahoe-lafs/tahoe-lafs — **WATCH** (GPL-2.0-or-later — license trap; pattern only, never vendor)

**What it is.** The least-authority filesystem: read-caps, write-caps, and verify-caps as short cryptographic strings. **Attenuation by derivation**: from a write-cap you hash down to a read-cap; from a read-cap you derive a verify-cap (integrity-check without plaintext). Delegation is literally *handing over the derived string* — the recipient's authority is bounded by cryptography, not by a policy engine that must be consulted.

**Mechanism to watch.** Attenuation-as-one-way-derivation is the cleanest mental model for our delegation receipts: each delegation step hashes the parent's secret with the narrowed scope, so (a) the child cannot recover the parent's authority, (b) anyone can verify the derivation chain given the roots, and (c) there is no revocation list to consult for the *attenuation* property itself (revocation is a separate, explicit mechanism — cf. Kerberos expiry).

**Sasanam seam.** Evidence-bundle access tiers (wave-292's offline bundle): read-cap vs verify-cap vs write-cap for evidence artifacts. A regulator gets a verify-cap (check integrity/availability, never read plaintext); an auditor gets a read-cap; only the owning pipeline holds the write-cap. Derivation by hashing, refusal by cryptography.

**Falsifiable probe.** (a) Given only a verify-cap, attempt to derive the read-cap — must be computationally infeasible (hash preimage). (b) Hand a read-cap to an untrusted party; attempt a write through it — must refuse at the storage layer without consulting any ACL.

**License.** **GPL-2.0-or-later (or TGPPL-1.0, at the user's option)** — copyleft; pattern only, NEVER vendor. Recorded here as a license-trap exhibit.

**Fetch gaps.** None needed — we are not vendoring; the derivation pattern is reimplemented from the documented semantics.

---

## Runner-ups (not teardown'd — one line each)

- **seL4/seL4** — capability minting with badges, diminished-rights derivation, revocation-by-destruction; **WATCH, pattern only** — GPL-2.0-only is a hard trap, and its kernel-enforced model doesn't transfer to our userspace coordinator.
- **Microsoft Midori** — the original distributed object-capability OS (Dean Tribble co-designed); no public repo — historical note only, its lessons live on in Agoric (#1).
- **matrix-org/synapse** — macaroon-based federation auth; SKIP — already a license-trap exhibit (wave-264), and federation delegation is off-theme.
- **w3c/webauthn** — 2 passing mentions, no verdict; attestation-adjacent but device-bound, weaker fit than go-tpm-tools (#6).

## License-trap table (pattern-only sources — never vendor)

| Source | License | Why it's a trap |
|---|---|---|
| tahoe-lafs/tahoe-lafs | GPL-2.0-or-later (or TGPPL-1.0) | Copyleft; derivation pattern only |
| seL4/seL4 | GPL-2.0-only | Copyleft; mint/badge/revoke pattern only |
| go-macaroon-bakery/macaroon-bakery | LGPL-3.0 + linking exception | Already ADAPT'd (wave-264); clean-room only |
| matrix-org/synapse | AGPL-3.0-or-commercial | License-trap exhibit (wave-264) |
| neo4j community (prior waves) | GPL-3.0 | Graph-delegation patterns only |
| artefactual/atom (prior waves) | AGPL-3.0 | Archives-delegation UI patterns only |

All "steal" verdicts above are Apache-2.0/MIT/BSD-class; raw LICENSE bytes must still be reverified at vendoring time per standing rule.

## Standing design rule

**"Delegation narrows, never widens — every handoff is a signed, attenuated receipt on the chain."**

Authority moves only by handing down a *narrower* reference than the one held; each handoff is a signed receipt chained to its parent; the downstream agent's evidence is the chain itself, verifiable without the engine. This composes with wave-293 ("Authority is leased, never held") and wave-296 ("An approval is a signed, time-boxed, quorum-counted vote on a digest"): a delegation is a leased, attenuated, chained approval to act.

## Human-world analogues (non-repo, for the design record)

- **Power of attorney:** scope-limited, revocable by the principal at will, terminates on the principal's death/incapacity (revocation propagation), and a PoA that purports to grant more than the principal holds is void (attenuation). Our revocation lane should copy the "principal can always revoke; revocation binds all downstream copies" rule.
- **Military mission command (Auftragstaktik):** delegation with commander's intent as the boundary — the subordinate may choose means but never ends. Our delegation receipts should carry an *intent digest* (the "what") while leaving the *plan* (the "how") to the delegate — matching the wave-297 approval-request's action-digest binding.
- **Nuclear two-person rule / aviation CRM:** no single agent may exercise critical authority alone; the junior crew member is *required* to challenge. This is the human precedent for combining quorum vetoes (wave-297) with delegation: a delegated critical action still needs the second pair of eyes named in the receipt.
