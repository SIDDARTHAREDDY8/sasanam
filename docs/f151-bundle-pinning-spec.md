# F151 — Bundle trust-anchor pinning spec

**Finding:** F151 (MEDIUM), filed 2026-09-24. `gov/safeguard_bundle.py::bundle_verify(bundle_dir)`
takes the bundle directory as its sole input and verifies the Ed25519 manifest seal and checkpoint
signatures against the operator/checkpoint keys shipped in `keys/*.json` **inside the bundle**.
A forger's self-sealed bundle (her own log, checkpoint keys, operator key, forged SUFFICIENT
verdict) verifies indistinguishably from the operator's genuine bundle. Battery:
`evals/f151bundlekeysub_break.py`, 1 BREAK / 2 HELD / 0 ERROR (+1 INFO).

## Problem

The bundle's advertised trust model — "zero out-of-band inputs", "the bundle directory is the
entire trust input" — authenticates **internal consistency**, never **authorship**. Victor, following
the documented procedure, cannot distinguish Mallory's SUFFICIENT from the operator's INSUFFICIENT.
`SafeguardAssessment.verify_report` takes `public_key`/`trusted_keys` as explicit out-of-band
inputs; `bundle_verify` silently substitutes bundle-contained keys with no pinning option.

## Seams (existing, public — no new seams)

- `gov.safeguard_bundle.bundle_verify(bundle_dir)` — the verify seam (add optional pin kwargs).
- `gov.safeguard_bundle.bundle_assemble(report, manifest, *, operator_key, checkpoint_keys, out_dir)`
  — the assemble seam (refuse mismatched operator key).

## Design

### `bundle_verify(bundle_dir, *, expected_operator_key_id=None, expected_operator_public_key_hex=None, expected_checkpoint_key_ids=None)`

New check **B6 `authorship_pinning`**, run after B4 (key envelope) and before B5:

1. **Pins supplied.** Validate pin inputs fail-closed (malformed hex / empty key_id / non-list
   expected_checkpoint_key_ids raise `SafeguardBundleError` before any check runs — a typo'd pin
   must never silently pass). Compare against the bundled keys:
   - `expected_operator_key_id` must equal `keys/operator_ed25519.json`'s `key_id`.
   - `expected_operator_public_key_hex` must equal the bundled operator key's `public_key_hex`.
   - `expected_checkpoint_key_ids` (list) must equal the SET of bundled checkpoint key_ids.
   - All supplied pins must match (AND). Any mismatch → check `fail`, loud detail naming the
     expected vs. bundled values, and `fatal` — §4 is not run against the wrong operator's keys.
2. **No pins supplied.** Check status `not_applicable` (not `pass`, not `fail`) with an explicit
   detail: B1–B5 + §4 prove **self-consistency only**; the key envelope is self-asserted by whoever
   assembled the bundle. The verifier's summary explicitly names the required out-of-band key
   binding (published key directory, transparency log, or authenticated delivery channel) and tells
   Victor to re-run with the pins before accepting a passing bundle as *that operator's* evidence.

### `bundle_assemble` — bind at assemble time

After key-envelope validation: if the manifest's `signing.scheme == "ed25519"` and
`signing.key_id` is present, refuse (`SafeguardBundleError`) when
`operator_key["key_id"] != signing["key_id"]`. Loud refusal, no silent shipping of a bundle that
can never pass §4 step 5. (Closes the p4 INFO footgun as HELD.) Skipped when the seal is
`scheme: "none"` or carries no key_id — those already fail closed at verify.

### Honest claim corrections (no silent "zero out-of-band inputs")

- `gov/safeguard_bundle.py` module docstring: replace "verifies with zero out-of-band inputs —
  the bundle directory is the entire trust input" with the two-mode truth: *unpinned = self-
  consistency only; authorship requires pinning the operator's key, bound out-of-band*.
- `VERIFY.txt` `_VERIFY_TEXT`: add a **KEY BINDING (AUTHORSHIP)** section ahead of the procedure;
  replace "with zero out-of-band inputs".
- `docs/safeguard-benchmark-spec.md` §5 bullet: replace "(the key envelope — no out-of-band key
  distribution)" with the honest transport claim (keys travel for integrity/checkpoint binding;
  authorship still requires an out-of-band binding).
- Add the self-asserted-anchor residual to the module's HONEST RESIDUALS list.

### Close-when (from FINDINGS.md)

1. Battery p1 flips to HELD: forger's bundle **rejected** under pinned operator key
   (`expected_operator_key_id=<operator's>`), operator's bundle passes; 0 BREAK / 3 HELD.
2. p2 (tampered genuine bundle rejected) and p3 (honest bundle verifies) stay HELD.
3. The three claim sites corrected to name the required out-of-band key binding.
4. Red-first regression tests at the verify seam: pinning-on + correct key → pass; pinning-on +
   wrong key_id → fail closed; pinning-on + wrong public key → fail closed; pinning-off →
   passes with explicit `not_applicable` B6 residual (not a silent claim); checkpoint pinning
   mismatch → fail closed.
5. p4: assembler refuses mismatched operator key — no silent mismatches.

## Residuals (documented, not filed)

- Unpinned verification remains a **self-consistency check** by design: it proves the bundle is
  internally intact, never who wrote it. This is the honest remaining boundary.
- Set-equality on checkpoint key pins: bundles carrying extra checkpoint keys beyond the pinned
  set fail closed — a stricter posture than subset semantics, documented as a choice.
- No key revocation channel: a compromised operator key is retired by shipping new bundles under a
  new key_id (operator determination) — unchanged from the existing residual list.
