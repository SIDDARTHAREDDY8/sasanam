## 2026-09-29 — Wave-198 lane A: F203 closure (RekorBackend Ed25519ph/SHA-512, live-tested)

**Scope.** Close F203 (MEDIUM, filed 2026-09-29 wave-194 lane D): `gov.anchor_backend.RekorBackend.submit` emitted raw-Ed25519/SHA-256 hashedrekord envelopes, rejected by real Rekor v1.5.4 with HTTP 400 `unsupported hash algorithm: "SHA-256" not in [SHA-512]`. Repaired at the same public seam per the close-when's first option: Ed25519ph/SHA-512 throughout.

**The shape (measured live, not assumed).** Against the local Rekor v1.5.4 + Trillian v1.8.0 + MySQL + Redis stack: declaring `data.hash.algorithm="sha256"` while signing Ed25519ph still 400s; declaring `sha512` with `value=hex(sha512(anchor_hash))` and `sign_ph(seed, anchor_hash)` accepts; signing `sign_ph(seed, sha512(anchor_hash))` is rejected server-side as `ed25519: invalid signature` (double hash). So the verifier (sigstore `WithED25519ph()`) treats the declared digest as the already-computed PH(M) — no double hash. Code: `gov/ed25519.py` gains RFC 8032 Ed25519ph (`sign_ph`/`verify_ph`, correct `"SigEd25519 no Ed25519 collisions"\x01` domain, §7.3 vector byte-exact); `gov/anchor_backend.py::RekorBackend.submit` signs the 32-byte anchor hash with `sign_ph` and declares sha512-of-anchor-hash; receipts carry `anchor_algorithm="ed25519ph-sha512"`; `verify_receipt` refuses explicitly unknown algorithm labels (legacy unlabeled receipts still verify), requires sha512 declaration + matching value in the entry body, and keeps RFC 6962 inclusion-proof verification + pinned log-ID check.

**Red-first.** Pristine d933dd1, live stack: submit -> `WitnessDownError: rekor HTTP 400 ... not in [SHA-512]` (recorded). Fixed, live stack (log id `a65b7454...9eae340`): submit -> real entries (indexes 24-27 observed) -> `verify_receipt` `True, None`; wrong anchor -> `(False, "receipt is for a different anchor")`. Batteries: new `evals/rekor_f203_probes.py` 9/9 HELD (incl. live round-trip, fake-transport tamper/wrong-key/stale-proof probes, deterministic x2, identical under `env -u GOV_DEPLOYMENT_MODE`); `evals/rekor_anchor_probes.py` 11/11 HELD with `p_f203_live_pin` now pinning the FIXED live behavior; `evals/w72_probes.py` 13/13 HOLD; unit suite `tests/test_rekor_f203.py` 10/10 new; adjacent units `test_w72_anchor`+`test_anchoring`+`test_rekor_anchor`+`test_crypto_gov` 160 OK. `evals/FINDINGS.md`: F203 CLOSED 2026-09-29; open findings: none; next free F204. `docs/REKOR_RUNBOOK.md` stale F203-OPEN notes updated.

**Two-axis review (post-fix).** Standards: CLEAN, no hard violations
(setenv, depth-1/GOV_SKIP_GREEN green check, TMPDIR run instructions,
verdict vocabulary all held); two non-blocking smells noted
(duplicated fake-transport helpers between battery and unit file —
accepted as deliberate hermeticity; bare `"ed25519ph-sha512"` label —
fixed by extracting `ANCHOR_ALGORITHM_ED25519PH_SHA512` in
`gov.anchor_backend`). Spec: (a) one REAL catch — the closure
residual overstated legacy compatibility: genuine pre-F203
(sha256-declared) receipts are REFUSED by the shape check, not
grandfathered; residual + code comment corrected to the honest
posture ("repaired throughout"). (b) Added envelope-signature
re-verification to `verify_receipt` (Ed25519ph over the anchor hash,
fail-closed "anchor signature does not verify") so receipts are
self-contained rather than relying transitively on the server's past
verification; unit-tested with a forged-signature case. (c)
Stale-proof guard was task-required, not creep. Live evidence is a
recorded one-time operator run (log id + indexes above);
live-conditional probes pin the shape deterministically in gates —
documented as the evidence basis.

**Residuals (honest).** (1) Rekor receipts remain digest-existence evidence only — never authority; equivocation enforcement stays in the witness layer. (2) The stale-proof guard for THIS seam is proof/claimed-tree-size consistency (root recomputation); the fresh-checkpoint STALE race documented in the runbook for `gov/rekor_anchor.py` is unchanged. (3) No consistency-proof path; checkpoint operator ECDSA signature carried, not verified.
## 2026-09-29 — Wave-198 lane B: attestation-conditioned credential release (Trustee KBS mechanism steal)

**Scope.** Trustee-steal build lane on base `d933dd1`: new product module `gov/attestation_release.py` (attestation token mint/verify, the `evaluate_release` release predicate, `AttestationReleaseConfig` trust anchor, operator-signed policy override), sentinel integration at both seams in `gov/sentinel_substitution.py` + `gov/executor.py`, red-first battery `evals/attestation_release_probes.py` (R1–R9), unit suite `tests/test_attestation_release.py` (82 tests), legacy-migration of the existing sentinel battery's registrations. Steals the mechanism only (stdlib Python, no Rust/TEE, no OPA). `evals/FINDINGS.md`: F203 stays OPEN (next free F204).

**What it is.** Sentinel credential substitution upgrades from host-binding-only release to attestation-conditioned release. The release predicate is evaluated per release at the execution boundary (`substitute_for_execution`), with a fail-closed non-consuming pre-check on the attempt path (`validate_sentinel_binding`). Conjuncts: status affirming, unexpired + TTL ≤ 300s, jti unused, sub == requesting agent, issuer trusted, credential class ⊆ `agent_scope` (non-empty), session (agent_id, run_id) bound, host binding still holds. `SentinelVault.register` takes `release_policy` (`attested` default for new credentials — attestation-mandatory from day one; `legacy-host-only` per-credential migration with LOUD audit + sunset `2026-12-31`; `deny_all` incident hold). `Trustee-style counters (evaluations/approvals/violations/errors) on the config, snapshotted into the audit path (spike §7). Audit events carry ids/verdicts/reasons only — never real values or token material. Honest residual (documented in the module): no general agent-revocation list yet; short TTL + keyset revocation are the controls.

**Red-first.** Pristine (module removed): 9 BREAK / 0 HELD / 0 ERROR (genuine red — bearer-sentinel release on host binding alone). Fixed: **9 HELD / 0 BREAK / 0 ERROR**, deterministic ×3, also under `env -u GOV_DEPLOYMENT_MODE`; green check runs the 82-test unit suite depth-1 (honors `GOV_SKIP_GREEN`).

**Two-axis review (done, findings addressed).** Standards: no hard violations; addressed the cheap judgement calls (magic reason string → `REASON_OPERATOR_OVERRIDE` constant; fail-closed `.get` default documented). Spec vs the wave-196 spike: (1) FIXED the headline — both seams defaulted a policy-less record to `legacy-host-only`, a silent downgrade contradicting R6 and the module's own docstring; now `"attested"` (new `TestNoSilentDowngrade` pins it). (2) FIXED the vocabulary deviation — token claim renamed `credential_classes` → `agent_scope` per spike §4.1/§4.2. (3) ADDED Trustee counters (spike §7). (4) `forensics=True` in `verify_attestation` kept deliberately: authorized by the lane brief ("verify-with-revoked only in forensics mode"), no caller, defaults off — not a bypass. (5) `submods` mapping decided and documented: per spike §6 ("do NOT take the TEE-specific submods hardware shape") the per-submodule structure maps onto the flat claim-set — one top-level `status` + non-empty `agent_scope` (the `count(submods) > 0` anti-vacuous guard); any non-affirming status refuses the whole release. Post-fix re-verification: battery 9/9 ×2 + unset-mode, existing sentinel battery 9/9 HELD, 312 adjacent+new unit tests OK.

**Suites (fresh unique /var/tmp TMPDIRs).** test_attestation_release 82/82, test_keyset + test_mcp_annotations + test_identity_token + test_approvals_d1 all OK (312 total); `evals/adversarial_sentinel_substitution.py` 9/9 HELD after migrating its registrations to explicit `release_policy="legacy-host-only"`; `git diff --check` + `py_compile` clean.

- Signed-off-by: SIDDARTHA REDDY <75976672+SIDDARTHAREDDY8@users.noreply.github.com>
