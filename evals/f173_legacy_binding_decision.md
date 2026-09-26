# F173 legacy-bundle decision (to-spec record, wave-115)

**Question.** Bundles sealed before the F173 fix (`bundle_version`
`evidence-bundle/1.0`) lack the cryptographic binding of the
per-entry inclusion-bundle presence vector, the `inclusion_coverage`
counts, and the receipt's bundle-presence/reason — the binding does
not exist anywhere in their signed bytes. How must the post-fix
verifier treat them?

**Options.**
- (a) Fail closed with an explicit error: "legacy bundle (1.0):
  inclusion coverage and receipt binding are not cryptographically
  bound (F173) — refusing to verify; re-seal with the current
  builder".
- (b) Accept with an explicit legacy label: exit 0 `VERIFIED` plus a
  "legacy: coverage not cryptographically bound" note.

**Decision: (a) fail closed.**

**Rationale.**
1. The F173 close-when requires that any unsigned alteration of
   coverage/receipt state *fails* rather than verifying. For 1.0
   bundles that property is unachievable — there is nothing to check
   the alteration against. Under (b), a no-key attacker could strip
   bundles from any 1.0 bundle in transit and still receive an exit-0
   `VERIFIED` verdict; the legacy label cannot distinguish
   attacker-stripped from operator-degraded, so the exact downgrade
   F173 kills would survive for the whole installed base of 1.0
   bundles. A label on a `VERIFIED` verdict preserves the hole.
2. Fail-closed is the repo's standing idiom (seal refuses unsigned
   bundles; V1 gates versions; F75 fails closed on supply-chain
   drift).
3. The cost is low and honest: re-sealing under the current builder
   re-binds coverage from the source log (the operator retains it in
   the normal deployment; where the source log is gone the bundle
   cannot be re-sealed and stays unverifiable — that is the honest
   outcome, not a migration to paper over). The error message names
   the remedy.
4. Migration burden is a deployment-local question, not a repo-wide
   claim: this repo is private pre-release, so no installed base is
   known here; any deployment holding 1.0 bundles re-seals from its
   source log.

**Mechanics.**
- V1 version gate: `VERSION[0] == "evidence-bundle/1.0"` fails closed
  with the explicit F173 message (not the generic version-mismatch
  text). Unknown future versions keep the generic mismatch failure.
- `EvidenceBundle.assemble` already refuses
  `bundle_version != BUNDLE_VERSION`, so the new builder cannot emit
  1.0 bundles. `BUNDLE_VERSION` is now `evidence-bundle/1.1` and the
  signature domain is `evidence-bundle/v2` (the claim triple changed
  shape: it now also binds `inclusion` and `receipt`).
- The receipt did not exist at seal time, so the receipt binding is
  signed at receipt-attachment time:
  `log_evidence_bundle_receipt(..., signer=...)` re-signs the
  extended claim after attaching the receipt and replaces
  `manifest["signing"]`. V12 additionally requires the transported
  `receipt.json`'s bundle-presence/`unavailable_reason` to equal the
  signed `manifest["receipt"]` binding (content-addressed: tip +
  digest + seq are chain-checked; entry identity is deliberately not
  pinned — see the V12 code comment).

**Residual (documented, not hidden).** An operator who deleted their
source log cannot re-seal a 1.0 bundle — that bundle is unverifiable
by design post-F173. This is a deliberate security tradeoff, not an
oversight.
