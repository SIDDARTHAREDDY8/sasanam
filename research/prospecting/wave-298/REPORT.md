# Wave-298 Lane 6 REPORT — Agent Delegation & Authority-Transfer Governance

**Status:** DONE. **REPORT AND STOP** — no follow-on work dispatched.
**Lane:** standing prospecting (research only). No code, no commits, no clones, no repo writes outside this team directory. $0 spend, no paid APIs, no external LLM keys.

## Ranked verdicts

1. **capnproto/capnproto — STEAL** (MIT): unforgeable capability references as the delegation primitive; delegation = passing a reference; attenuation = interposition (wrapping narrower). Confused-deputy resistance by construction, no authz table to desync.
2. **Agoric/agoric-sdk — STEAL** (Apache-2.0): OCap discipline (no ambient authority; authority arrives as explicit endowments), ERTP payments as attenuated rights-objects, Zoe escrow/offer-safety for delegated multi-step work.
3. **krb5/krb5 (MIT Kerberos) — ADAPT** (MIT-style permissive): delegation as a first-class ticket type with its own session key (attributable); `ok-as-delegate` recipient opt-in; constrained delegation naming the downstream set (S4U2Self/S4U2Proxy).
4. **fuchsia/fuchsia component framework — ADAPT** (BSD/MIT/Apache mix): declared capability manifests (`use`/`offer`/`expose`) with rights-attenuation checked at offer time, failing closed before the child ever runs; parents cannot silently retain routed capabilities.
5. **spruceid/didkit — ADAPT** (Apache-2.0, Trail-of-Bits audited 2022): `capabilityDelegation` proof purpose — delegation chains as signed, resolvable, offline-verifiable documents; the downstream agent's evidence is the chain itself.
6. **google/go-tpm-tools — ADAPT** (Apache-2.0): client/server attestation split — the verifier side never touches a TPM; event-log replay as the pattern for our delegation log; hardware-rooted identity where TPMs exist, ceremony transcript as the honest software fallback.
7. **tahoe-lafs/tahoe-lafs — WATCH** (GPL-2.0-or-later — trap; pattern only): attenuation by one-way derivation (write-cap → read-cap → verify-cap); evidence-bundle access tiers.

Full teardowns (mechanism / Sasanam seam / falsifiable probe / license / fetch gaps): [PROSPECTUS.md](sandbox://workspace/teams/wave298-prospect/PROSPECTUS.md).

## Coverage audit

- All `wave2*-prospect/PROSPECTUS.md` files swept with ripgrep (substring sweeps included). Every pick: **zero prior teardowns**.
- Excluded as already rendered: macaroon-bakery (ADAPT wave-264), biscuit (wave-228), ucanto (wave-264), zcap-ld (wave-290), spiffe/spire (wave-178 + 30 corpus files), ghostunnel (ADAPT wave-188), boulder (SKIP wave-258), GNAP (WATCH wave-290), plus smallstep/zitadel/keycloak/ory-hydra/casbin/spicedb/tailscale/temporal (all previously rendered or heavily mentioned).
- Waves 291–297 picks untouched. Reserved waves (287) untouched.

## Deltas vs prior waves

- This is the **first prospecting wave themed on delegation/authority-transfer**. Prior adjacent coverage: wave-264 (macaroon-bakery discharge-as-HITL, ucanto), wave-290 (zcap chains, GNAP negotiation gap), wave-178 (SPIFFE attested identity, in-toto artifact rules). None rendered the capability-OS lineage (seL4/Fuchsia/Midori/Agoric/Cap'n Proto) or the Kerberos delegation model — both are first-rendered here.
- New license trap recorded: **tahoe-lafs GPL-2.0-or-later/TGPPL-1.0** (pattern only). seL4 GPL-2.0-only re-affirmed as pattern-only WATCH.
- New standing design rule: **"Delegation narrows, never widens — every handoff is a signed, attenuated receipt on the chain."** Composes with wave-293 ("Authority is leased, never held") and wave-296 ("An approval is a signed, time-boxed, quorum-counted vote on a digest").
- Human-world analogues added to the design record: power of attorney (revocation binds downstream copies; void-if-wider-than-principal), mission command/Auftragstaktik (intent digest as the delegation boundary — means delegated, ends fixed), two-person rule / aviation CRM (delegated critical actions still need the named second pair of eyes).

## Proposed build sequencing (6 lanes)

1. **`gov/delegation.py` — delegation receipts.** Signed, chained, attenuated receipts (capnproto STEAL: unforgeable refs, interposition-as-attenuation; Agoric STEAL: no ambient authority, ERTP-style attenuated rights-objects, Zoe escrow for multi-step delegated work). Plugs into `approval_request` (request digest = designated object), `coordination_lease` (lease grant = capability; fencing = connection-scoped IDs), and wave-293 tool-sequence rules (a tool handed to a sub-agent is a capability, not a resolvable name).
2. **Kerberos-style ticket model.** Delegation as a first-class ticket type with its own key material (attributable); `ok-as-delegate` recipient opt-in declared in the supervision child inventory; constrained delegation naming the downstream set; forwardable-vs-constrained flags on every receipt.
3. **Fuchsia-style capability manifests for supervision.** Extend wave-297 `ChildSpec` with `use`/`offer`/`expose` + rights; the supervisor routes only declared capabilities and fails closed on rights mismatch at spawn (the `rw*` vs `r*` case); parents cannot `use` what they merely route.
4. **Revocation propagation.** Delegation epochs + revocation list wired into `coordination_lease` fencing: revoking the upstream grant kills every downstream receipt (power-of-attorney rule — revocation binds all downstream copies); receipts carry expiry and epoch, verified offline.
5. **Attested identity binding.** Delegation receipts carry identity evidence (didkit ADAPT: DID chains with `capabilityDelegation`; go-tpm-tools ADAPT: attestation digest with ceremony transcript as software fallback); delegation links become `delegated-authority` edges in `decision_trace`, verifiable by the offline evidence-bundle verifier.
6. **Red-team battery.** Confused-deputy probes, attenuation-escape probes (scope wider than parent), chain-forgery probes (wrong controller key), revocation-race probes (use after upstream revoke), delegation-loop probes (A→B→A), ambient-authority probes (reach the parent right through globals/prototypes).

## Honest limits

- Licenses verified from public metadata (repo badges, README license sections, ecosyste.ms), **not** raw LICENSE bytes — reverify at vendoring time per standing rule before any code is taken.
- Fuchsia's enforcement is kernel-side; our adaptation is supervisor-spawn-path enforcement — same semantics, weaker trust anchor (documented in the prospectus).
- Kerberos assumes a trusted KDC; our coordinator plane is not assumed incorruptible — every ticket must verify offline (evidence-bundle discipline).
- No TPM exists in this environment; attestation is format-adapted with the ceremony transcript as fallback — never claim hardware root where none exists.

**Deliverables:** [PROSPECTUS.md](sandbox://workspace/teams/wave298-prospect/PROSPECTUS.md) (this report's companion). No findings filed (research lane). REPORT AND STOP.
