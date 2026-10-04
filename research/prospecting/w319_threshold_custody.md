# Threshold Custody — Research Prospectus (Wave-319 Lane 5)

**Lane:** wave319-prospect (threshold-custody prospecting) · **Base:** `5ada81d9` (wave-317 merge, verified via `git ls-remote` HEAD before clone) · **Date:** 2026-10-04
**Skill:** research (mattpocock; primary sources, cited claims). **Type:** research only — no product code written or modified.
**Mission:** the wave-317 prospectus's direction item 4 — threshold custody ceremony ("adopt FROST only after an audited implementation exists"). Four parallel depth-2 research agents produced raw reports preserved at `inputs/` (frost_implementations.md, shamir_ceremonies.md, key_ceremonies.md, ed25519_threshold_fit.md); this prospectus synthesizes them with citations.

## Headline answers

1. **Does an audited FROST implementation exist yet? YES** — Zcash Foundation's Rust `frost` crates: NCC Group audit Summer 2023 (3 consultants, 25 person-days) covering `frost-core`, `frost-ed25519`, `frost-ed448`, `frost-p256`, `frost-secp256k1`, `frost-ristretto255` v0.6.0, trusted-dealer *and* DKG keygen and signing, all findings fixed and retest-confirmed; plus Least Authority's Q1 2025 audit of the `frostd`/`frost-client` demo tooling (no high-severity findings). RFC 9591 published June 2024 (Informational, IRTF stream). Caveats that matter: the audit **excludes `frost-secp256k1-tr` (Taproot/BIP340) and `frost-rerandomized`**; it was on v0.6.0 while crates are now ~v2.x (delta review required before depending on the audit); DKG follows the FROST20 paper, not a standard.
2. **Can the project's Ed25519 key material be threshold-split without changing the signature interface? YES.** `KmsProvider.sign(key_id, digest)` is a synchronous single call (32-byte digest in, 64-byte signature out, `KmsError` fail-closed) — the provider *plays the FROST coordinator* internally (the `frostd` pattern), with nonce preprocessing hiding the second round. FROST-Ed25519 output is a standard Ed25519 signature, so verifiers, `provider_can_sign`, and the fail-closed contract are untouched.
3. **What is the cheapest credible custody step?** Vault's own Shamir seal under the existing `VaultKmsProvider` — m-of-n operator unseal, zero `gov/` changes, honestly labeled as unseal-quorum rather than threshold signing. The custody work is a runbook + config, not code.
4. **What is ceremony vs theater?** The CVA's four-property test is the load-bearing practitioner statement: a process counts as a ceremony only if it demonstrates security, segregation of duties, restorability, and auditability — a "ceremony" is a label for four properties, not magic. It's real when it buys no-single-person birth/copy/use, third-party-verifiable evidence, and non-exportability; it's theater when witnesses lack independence, artifacts go unchecked, or the hardware supply chain is trusted blindly.

## §1. FROST implementations and audit status (from `inputs/frost_implementations.md`)

- Spec: `draft-irtf-cfrg-frost` was published as **RFC 9591, June 2024, Informational, IRTF stream**, from `draft-irtf-cfrg-frost-15.txt`; not an Internet Standards Track specification. Source: https://www.rfc-editor.org/info/rfc9591/.
- Key generation is *not* part of the standardized signing protocol: trusted-dealer keygen is in the RFC's appendix; DKG follows the original FROST20 paper. Source: https://github.com/ZcashFoundation/frost (README). ZF flags "the lack of a standardized key generation specification for FROST" as an interoperability limit. Source: https://zfnd.org/the-state-of-frost-for-zcash/.
- ZF `frost` crates (frost-core, -ristretto255, -ed25519, -ed448, -p256, -secp256k1, -secp256k1-tr, -rerandomized): **MIT + Apache-2.0 dual** (no license trap). Considered stable, SemVer-guaranteed. Source: https://github.com/ZcashFoundation/frost.
- **NCC Group audit (Summer 2023):** scoped to v0.6.0 (commit 5fa17ed) of frost-core, frost-ed25519, frost-ed448, frost-p256, frost-secp256k1, frost-ristretto255 — key generation (trusted dealer AND DKG) plus signing, including the Ed448-Goldilocks dependency's used curve operations; 3 consultants, 25 person-days; retest confirmed all findings fixed. Source: https://github.com/ZcashFoundation/frost (README "NCC Audit"); https://www.nccgroup.com/research-blog/public-report-zcash-frost-security-assessment/.
- **Scope exclusions:** the NCC audit explicitly excludes `frost-secp256k1-tr` and `frost-rerandomized` — the ciphersuite a Bitcoin/Taproot-adjacent product would want is *not* the audited one. Source: same README.
- **Least Authority audit (Q1 2025):** the `frostd` server + `frost-client` CLI demo tooling; no high-severity findings; findings addressed. Source: https://zfnd.org/frost-demo-audit-frost-client-and-frostd/.
- Earlier (2021, RedJubJub era): Aumasson/Hamelink/Shlomovits reviewed the 2-round trusted-dealer implementation (404 lines); 2 medium + 3 low, all addressed. Source: zcash-frost-audit-report-20210323.pdf.
- Post-audit security fix: frost-core v2.2.0 added min_signers validation in share-refresh functions (BlockSec-reported; possible share security loss otherwise). No RustSec/CVE entries against the frost crates found. (v2.2.0 release-notes claim quoted from a mirror — re-verify against https://github.com/ZcashFoundation/frost/releases/tag/frostcore/v2.2.0 before depending on it.)
- Other implementations: bytemare/frost (Go, MIT, RFC 9591, DKG-first README — but no audit, no releases) = WATCH; mwaddip/frots (TypeScript port of the *unaudited* -tr crate, test-parity only — and its README's "audited" claim is inaccurate) = SKIP; FrosTON (Python research demo) = SKIP; Chainflip 2022 / Coinbase kryptology audits = SKIP (other parties' implementations; kryptology archived); "sifr" = unverifiable, open question.
- **Verdict refinement of the wave-317 line:** "adopt FROST only after an audited implementation exists" is now ANSWERED AFFIRMATIVELY — adopt, but pin only to audited crates (`frost-ed25519`, `frost-secp256k1`, `frost-ristretto255`, `frost-p256`, `frost-ed448`) and delta-review from audited v0.6.0 to the pinned release; treat `-tr`/rerandomized as unaudited components.

## §2. Shamir theory and operational ceremonies (from `inputs/shamir_ceremonies.md`)

- Theory (Shamir 1979, via MIT DSpace): divide D into n pieces; any k reconstruct, and "even complete knowledge of k−1 pieces reveals absolutely no information about D" — information-theoretic. Intended purpose is explicitly *key management*.
- Honest limits (Yale lecture notes; Casa/Lopp 2020): the base scheme trusts the dealer and shares are unverifiable; splitting *and* reconstruction are single points of failure on one device; it splits a *secret*, not a *capability* — whoever combines shares learns the secret, so it is not threshold signing; no share revocation without full reconstruct + re-split.
- Vault's ceremony (developer.hashicorp.com seal docs): three-layer hierarchy (encryption key → root key → unseal key); the Shamir seal splits the **unseal key**, default 5 shares / 3 threshold. `vault operator init` prints shares once in plaintext; Vault keeps nothing. Documented distribution recommendation: encrypt each share to the holder's PGP key via `-pgp-keys`. Ceremony is manual by design; per-node unseal; unseal shares double as quorum for privileged ops (root-token generation, rekey). Sealing needs one operator; unsealing always costs the quorum.
- Recovery story: below-threshold loss is fatal by design ("will remain permanently sealed!"). Rekey rotates the share set but **requires the old quorum** — compromise response degrades exactly when needed most. Seal migration needs downtime, backups, and both seals. Auto-unseal delegates unsealing to a KMS/HSM; recovery keys (still Shamir-split) remain purely an authorization quorum.
- OpenBao: Shamir path textually identical; adds static-key auto-unseal and **explicitly names scripted manual unseal a discouraged pattern**; delayed recovery-key generation (`recovery_shares=0`, generate later); CLI renamed `rotate-keys`. Source: https://openbao.org/docs/concepts/seal/.
- **Licenses (verified in the repos' own LICENSE files):** Vault = **BSL 1.1** (IBM licensor, 4-year MPL conversion, no competing hosted offering) — confirms the wave-318 finding. OpenBao = **MPL-2.0** (not Apache-2.0 — third-party ADRs claiming Apache-2.0 are wrong). Vault's own `shamir/shamir.go` carries an MPL-2.0 SPDX header even inside the BSL repo (narrow reuse path; doesn't relicense the repo).
- Alternatives: Control Groups (Vault Enterprise-only) — m-of-n human *approvals per operation* ("gate the operation" vs "split the key"); Vault composes both: Shamir for the barrier, quorum for privileged ops. For Sasanam's governance use case, "gate the operation" is the closer shape (approving root-key ceremonies, evidence-anchor signing, policy overrides).
- Honest gotchas: the ceremony is the product, the math is 50 lines; "split the key" and "gate the operation" compose — copy the composition; say below-threshold loss is unrecoverable out loud at init; design the rotation path before the first ceremony; don't automate Shamir's manual unseal.

## §3. Key ceremonies at real companies (from `inputs/key_ceremonies.md`)

- DNSSEC root KSK (ICANN/IANA): 21-volunteer TCR pool (unpaid, to preserve independence), min 3 per ceremony; 3-of-7 smartcard quorum to activate FIPS 140-2 L4 / 140-3 L3 HSMs; 4 ceremonies/year, ~4h each; ceremony computer has no hard drive/battery, never networked; every step scripted, initialed, filmed (3 cameras), webcast, published. Stated goal: KSK used only for its proper purpose with "no ability for its contents to be disclosed for other purposes."
- CA/Browser Forum Baseline Requirements §6.1.1.1: root CA key generation SHALL have a written Key Generation Script + Qualified Auditor witness (or full video) + the auditor's written opinion; in all cases SHALL use multiple-person control + split knowledge in a physically secured environment.
- Let's Encrypt: keys born in HSMs during a ceremony meeting the CP/CPS; practice = develop ceremony tooling openly as a demo repo, mechanically transform into real scripts, reviewed/approved/locked by the policy management authority, documented, recorded, auditor-observed.
- Standards: FIPS 140-2 §4.7.4 split-knowledge procedures with per-component operator authentication and no intervening systems that could combine components; PCI HSM v4 dual-control/split-knowledge definitions.
- Practitioner equivalence (Crypto Valley Association 2020 Guidelines): "As long as the key requirements of security, segregation of duties, ability to restore the keys, and auditability are given, we speak of a key ceremony" — a ceremony is a label for four properties. Its three goals: generate secrets so nobody can determine them before/after; perform restorable, restricted, logged backups; demonstrate to third parties that 1–2 were done per the documented procedure. Goal (3) is the one KMS+IAM does not give by itself.
- Theater criteria (practitioner-grounded): fake independence (witnesses employed by the operator; quorum members sharing one boss); artifacts produced but never checked; hardware/software supply chain trusted blindly (CVA; Ellison's "Reflections" ceremony paper, IACR ePrint 2007/399; IANA 2026 audit's "inherent limitations… human error and the circumvention of controls").
- Cloud alternative that narrows the gap: Google Cloud HSM attestation statements proving non-extractability, genuine-HSM key birth, and key-version binding — third-party cryptographic proof *without* a physical ceremony.
- Minimum credible ceremony for a small team (synthesis): written script + HSM key birth + 2+ person rule + split knowledge + tamper-evident custody + recorded, signed, retained evidence. Overkill: the 21-person TCR pool with quarterly webcasts, FIPS L4 HSMs, retained audit firms — without a global-trust-anchor threat model, that's ritual, not control.

## §4. Ed25519 threshold fit — the interface absorbs the swap (from `inputs/ed25519_threshold_fit.md`)

- Interface (repo as primary source: `gov/kms.py`, `gov/kms_vault.py`, `gov/evidence_certs.py`): `KmsProvider.sign(key_id, digest)` — synchronous single call, 32-byte digest in (prehashed Ed25519), 64-byte signature out, `KmsError` fail-closed. `provider_can_sign` lets consumers refuse rather than degrade. Verifiers see ordinary Ed25519 (`gov/ed25519.py verify` → exact bool).
- Two families: (a) Shamir-split seed = reconstruct-then-sign — interface-invisible, but the key EXISTS at signing time; honestly an operator-quorum claim, not threshold signing. (b) True threshold signing = FROST-Ed25519 (RFC 9591): key never exists; output is a standard 64-byte Ed25519 signature verifiable with the existing verifier (RFC: FROST(Ed25519) signatures "can be verified with a verifier that is compliant with [RFC8032]").
- Critical constraint: FROST signatures must NOT be deterministic — "deriving nonces deterministically allows for a complete key-recovery attack" (RFC 9591). Nonces must be fresh and never reused (§5.1).
- Two rounds hide behind the single call because the provider plays the coordinator: round 1 (nonce commitments) is message-independent and can be preprocessed asynchronously, so each `sign()` can be a single online round. Real deployments do exactly this: ZF's `frostd` is a coordinator JSON-HTTP server fronting share-holders.
- Prehash fit: the interface signs a 32-byte digest; treating the digest as the FROST message yields signatures verifying as Ed25519ph(digest) under the group key — compatible with today's Vault `prehashed: True` semantics.
- Honest recommendation: (1) ship first = Vault Shamir seal behind the existing `VaultKmsProvider` (runbook + config, zero code); (2) full direction = spec a `ThresholdFrostKmsProvider` running the RFC 9591 coordinator inside the provider against t-of-n share-holder backends with a nonce-preprocessing pool, stealing ZF's `frost-ed25519` crate — but this needs a non-stdlib build decision first; do NOT hand-roll FROST in stdlib Python (the nonce-reuse footgun makes from-scratch implementation the highest-risk option, and $0/stdlib-only is incompatible with an audited build).

## §5. Consolidated verdicts

**STEAL:**
- Vault's init-ceremony shape (PGP-encrypted shares, printed-once, "permanently sealed" honesty, rekey-as-recovery, recovery keys as a separate Shamir quorum for authorization) — the ceremony contract, under the existing `VaultKmsProvider`; zero `gov/` changes.
- The three-layer split (what is split ≠ the capability): split the *custody root*, keep day-to-day authority in short-lived revocable tokens.
- m-of-n smartcard quorum + per-component operator authentication (IANA 3-of-7; FIPS 140-2 §4.7.4) for the project's own root/evidence-signing keys.
- ISRG's script discipline: ceremony tooling developed openly, mechanically transformed into real scripts, reviewed/approved/locked, documented, recorded, auditor-observed.
- CVA's four-property test as the anti-theater gate: security, segregation of duties, restorability, auditability.

**ADAPT:**
- ZF `frost` crates (Rust) for threshold signing — conditional: pin only audited crates, delta-review v0.6.0→pinned release, exclude `-tr`/rerandomized. Licenses clean (MIT/Apache-2.0).
- FROST-Ed25519 coordinator-inside-provider pattern (the `frostd` deployment shape) as the future `ThresholdFrostKmsProvider` spec.
- "Gate the operation" (Control-Groups shape) as an open reimplementation for sensitive governance ops — m-of-n human approvals with request paused until quorum, fully audited.
- IANA's publish-everything model scaled down: ceremony artifacts (storybook + attestation statements) shipped with evidence bundles for trust-anchor keys.
- Cloud HSM attestation statements as the witness-substitute for cloud-managed keys.
- FIPS 140-2 split-knowledge ceremony requirements as the hardening checklist for any share-entry UX.

**WATCH:**
- `frost-secp256k1-tr` / `frost-rerandomized` (unaudited; third-party "audited" claims inaccurate).
- bytemare/frost (Go, MIT, RFC 9591) — reassess if audited or the Rust dependency is unacceptable.
- OpenBao static-key auto-unseal (MPL-2.0-clean self-hosted auto-unseal; production guidance unverified).
- Audited Python FROST bindings / second audit coverage of newer frost crate versions (NCC delta unverified; no audited Python FROST exists today).
- Verifiable secret sharing (Feldman/Pedersen), SLIP-0039 (SSS implementation standard), Cloudflare glass-box CA (secondary reporting only, not issuing yet).

**SKIP:**
- Hand-rolling FROST in stdlib Python (nonce-reuse → key-recovery footgun; incompatible with $0/stdlib-only; unaudited = unacceptable for custody).
- Community FROST ports in the signing path (snek-frost, frosTS, FrosTON — explicitly unaudited/educational; the TS port's own README redirects production to the audited Rust implementation).
- Reimplementing Shamir's math (Vault's `shamir/shamir.go` is a correct minimal GF(2⁸) implementation; spend the budget on the ceremony).
- Shamir as a substitute for threshold signing / per-operation authorization (theory gives secret *recovery*, not distributed *authority*).
- The full IANA production (21-person TCR pool, quarterly webcasts, L4 HSMs) for internal keys — overkill without a global-trust-anchor threat model.
- Chainflip 2022 / Coinbase kryptology audits (other implementations, historical; kryptology archived); "sifr" (unverifiable).

## §6. Direction brief for a future threshold-custody build lane

Ordered by evidence strength and cost:

1. **Vault Shamir-seal runbook lane (zero code).** Config + runbook for `-key-shares=N -key-threshold=M` init, PGP-encrypted share distribution, per-node unseal, rekey procedure, "permanently sealed" honesty. Honest label: unseal-quorum, not threshold signing. Ships on the existing provider.
2. **m-of-n operation-approval spec.** To-spec a Control-Groups-shaped discipline for sensitive governance operations (root-key ceremony, evidence-anchor signing, policy override): named approver groups, per-factor approval counts, request paused until quorum, full audit. Open reimplementation (Vault's is Enterprise-gated; OpenBao control-groups status unverified).
3. **Split-the-custody-root design.** Split the custody root (KMS-wrapping / evidence-signing root); keep day-to-day authority in short-lived revocable tokens. Never split the thing that signs every decision.
4. **`ThresholdFrostKmsProvider` build lane (after the build-system decision).** Spec: RFC 9591 FROST(Ed25519, SHA-512), digest-as-message, DKG ceremony (preferred over trusted dealer where the threat model includes the ceremony operator), coordinator inside the provider, nonce-preprocessing pool with consume-once discipline, identifiable-abort handling. Hard gate: delta-review NCC v0.6.0 → pinned release before depending on the audit.
5. **Ceremony artifact publishing.** Publish ceremony storybooks + attestation statements alongside evidence bundles for trust-anchor keys (scaled IANA model).
6. **FIPS 140-2 §4.7.4 checklist** for any share-entry UX: per-operator authentication, trusted-path entry, no combining intermediaries, n−1 documentation.
7. **Vault BSL 1.1 → OpenBao carve-out.** Any deployment artifact naming HashiCorp Vault as the production answer must carry the OpenBao carve-out (wave-318 finding, confirmed in primary LICENSE files this pass).

## §7. Open questions (not findings)

- NCC's per-finding severity breakdown (not located in a primary source this pass).
- frost-core v2.2.0 BlockSec-fix claim quoted from a release-notes mirror — re-verify against the primary GitHub page.
- "sifr" — no project located; unverifiable.
- Casa article + Vault control-groups page full text (browser fetch failures; claims rest on official-source excerpts — re-verify before external quoting).
- Whether HashiCorp documents operator-collusion analysis or a share-compromise runbook beyond rekey mechanics.
- `threshold_crypto` (Rust) — surfaced as BLS-only; whether any maintained Ed25519-threshold crate beyond ZF's exists is unverified.
- No audited Python FROST / audited bindings of `frost-ed25519` found.

## §8. Citation index

- FROST spec: https://www.rfc-editor.org/info/rfc9591/; https://www.rfc-editor.org/rfc/rfc9591.html
- ZF frost crates + NCC audit scope: https://github.com/ZcashFoundation/frost; https://www.nccgroup.com/research-blog/public-report-zcash-frost-security-assessment/
- ZF state-of-FROST FAQ (standardized-keygen gap): https://zfnd.org/the-state-of-frost-for-zcash/
- Least Authority demo-tooling audit: https://zfnd.org/frost-demo-audit-frost-client-and-frostd/
- `frostd` deployment pattern: https://github.com/zcashfoundation/frost/blob/HEAD/book/src/zcash/server.md
- bytemare/frost: https://github.com/bytemare/frost
- mwaddip/frots: https://github.com/mwaddip/frots
- Shamir 1979 (MIT DSpace): https://dspace.mit.edu/entities/publication/91c51bfc-5678-409c-80c5-44ce8fcdbadf; lecture notes: https://65610.csail.mit.edu/2026/lec/l12-ss.pdf; Yale notes: https://zoo.cs.yale.edu/classes/cs467/2014f/lectures/ln21.pdf
- Vault seal docs: https://developer.hashicorp.com/vault/docs/v1.16.x/concepts/seal; operator init: https://developer.hashicorp.com/vault/docs/commands/operator/init; PGP shares tutorial: https://docs.hashicorp.com/vault/tutorials/archive/pgp-encrypted-key-shares
- Vault shamir.go: https://github.com/hashicorp/vault (shamir/shamir.go, MPL-2.0 SPDX header)
- OpenBao seal docs: https://openbao.org/docs/concepts/seal/; repos: https://github.com/hashicorp/vault (BSL 1.1), https://github.com/openbao/openbao (MPL-2.0)
- DNSSEC root KSK: https://www.icann.org/en/system/files/files/tcr-dnssec-key-signing-21jan14-en.pdf; ceremony scripts: https://data.iana.org/ksk-ceremony/39/KC39_Script.pdf, https://data.iana.org/ksk-ceremony/58/KC58_Script.pdf; 2026 audit: http://www.iana.org:443/reports/2026/root-ksk-audit-202511.pdf
- BRs: https://cabforum.org/uploads/Baseline_Requirements_V1_1_4.pdf; ISRG CP-CPS: https://github.com/letsencrypt/cp-cps/blob/HEAD/CP-CPS.md; ISRG ceremony practice: https://community.letsencrypt.org/t/preview-of-our-upcoming-root-ceremony/239494/30
- Ellison ceremony paper: https://eprint.iacr.org/2007/399
- Casa SSS critique: https://blog.casa.io/shamirs-secret-sharing-security-shortcomings/ (excerpt; fetch failed)
- FROST non-determinism requirement: RFC 9591 (rfc-editor.org); preprocessing: https://csrc.nist.rip/csrc/media/Projects/threshold-cryptography/documents/TCall-1/FROST-PW01.pdf
- FROST-PW / security bounds: https://lantr.io/blog/frost-schnorr-threshold-signatures-bitcoin/
- Project interface: lane tree `gov/kms.py`, `gov/kms_vault.py`, `gov/evidence_certs.py`, `gov/ed25519.py` (repo = primary source)

## Standing-rule notes

- Research only: no product code written or modified; no batteries, no gates, no F-filings. `gov/`, `tests/`, `evals/` untouched in the lane tree.
- Every factual claim cites the primary source it was verified against; unverifiable claims are recorded as open questions, not findings.
- Quality > date. $0 spend.

**REPORT AND STOP** — no follow-on work dispatched.
