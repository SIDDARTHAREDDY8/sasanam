# Two-axis review — Wave-115 F173/F174 closure lane (2026-09-26)

**Scope:** `gov/evidence_bundle.py`, `gov/evidence_verify.py`,
`tools/evidence-verify`, `tests/test_evidence_bundle.py`,
`tests/test_evidence_verify.py`,
`evals/evidence_bundle_adversarial.py`, `evals/evidence_bundle_tamper.py`,
`docs/evidence-bundle-spec.md`, `evals/f173_legacy_binding_decision.md`.
Byte-identity: `tools/evidence-verify` == `gov/evidence_verify.py`
(verified by `cmp` and by adversarial-battery control C1, post-edit).

## Axis 1 — Standards (repo conventions)

1. **No new dependencies; stdlib-only verifier preserved.** The
   extended claim uses only `hashlib`/`json`/existing canonicalization.
   The single-file auditor verifier remains runnable with the repo not
   installed.
2. **Fail-closed throughout.** Legacy `evidence-bundle/1.0` fails V1
   with an explicit F173 message (never a silent accept); unknown
   domains fail V7; missing/invalid signatures fail V7; receipt
   presence/reason mismatch fails V12. No new `try/except-pass` or
   warning-instead-of-failure paths.
3. **Red-first, no probe weakening.** F1a/F1b/D1 were `[BREAK]` pins of
   the vulnerable behavior; the fix lane flipped their *assertions* to
   the fixed behavior (exit 1 / `[FAIL] V7|V12`; D1 exit 0 with
   disclaimer visible in both formats) while preserving the exact
   attacker mutations. This is assertion-strengthening toward the
   close-when criteria, not weakening to pass.
4. **Deterministic, synthetic, $0.** All new tests use hermetic
   `Ed25519Signer` keys and `tempfile` dirs; batteries run under
   `env -u GOV_DEPLOYMENT_MODE` / module-level staging; TMPDIRs are
   `mkdir -p`'d before every run (wave-112 lesson).
5. **No debug leftovers, no network, no new files outside the lane.**
   `grep` for `[DEBUG`, `TODO(F17`, and `input(` in touched files is
   clean. No egress, no subprocess, no git invocation added.
6. **Drift guards green.** `test_verifier_copy_drift_guard`
   (byte-identity) and `test_ed25519_vendoring_drift_guard` pass.
7. **Docs synchronized.** Spec §4.1.2/§4.2/§4.3(V1,V7,V12)/§5/§7/P5
   updated to bundle 1.1 / domain v2 / extended claim / receipt
   re-signing / `claimed_operator` disclosure; the stale
   "transitively covers inclusion-coverage accounting" sentence in
   §4.2 was corrected. The decision record's unsupported "No
   production bundles exist" sentence was replaced with a qualified
   migration note.

**Standards verdict: PASS.**

## Axis 2 — Spec (FINDINGS.md close-when criteria, quoted verbatim)

### F173

> **Close-when.** (1) The operator-signed claim triple binds the
> per-entry inclusion-bundle presence vector, the
> `inclusion_coverage` counts, and the receipt's
> bundle-presence/reason, so any unsigned alteration fails V7
> (signature) rather than sailing through to a VERIFIED verdict;
> (2) operator-signed honestly-degraded bundles (inclusion service
> genuinely unavailable at seal time; stale-head reduced coverage as
> in probe `E2`) still verify with explicitly labeled reduced
> coverage; (3) probes `F1a`/`F1b` flip to `[CAUGHT]` (exit 1,
> `[FAIL]` V7 or V9/V12) while `E2` stays `[CONTROL]` (exit 0,
> `2 reduced-coverage entries`).

- (1) **Met.** The signed claim is now
  `{window, chain_verified, checkpoints_digest, inclusion{coverage,
  presence[]}, receipt{bundle_present, unavailable_reason}}` under
  domain `evidence-bundle/v2`; builder (`signed_body`) and verifier
  (`_signed_claim`) construct byte-identical bodies (locked by a new
  equivalence test). Because the receipt is created after `seal()`,
  `log_evidence_bundle_receipt` re-signs the extended claim on
  attach — the shipped signature always covers the receipt binding.
  The old v1 triple cannot be re-presented: V7 requires
  `domain == "evidence-bundle/v2"`.
- (2) **Met.** New unit test
  `test_f173_honest_degraded_bundle_verifies_labeled`: an HMAC-only
  log sealed with `bundle_present=False` + explicit reasons verifies
  exit 0 with `0 inclusion bundles verified` / `4 reduced-coverage
  entries`. The signature binds the *declared-degraded* state, so
  attacker-stripped vs operator-declared-degraded are distinguished
  by the signature, not by reason text.
- (3) **Met (observed).** Adversarial battery:
  `CAUGHT=9 MISS=0 BREAK=0 CONTROL=5 BROKEN=0 AGREE=2 DIVERGE=0
  ERROR=0`. F1a `[CAUGHT]` — exit 1 `[FAIL] V7`; F1b `[CAUGHT]` —
  exit 1 `[FAIL] V12` (the close-when permits V7 *or* V9/V12; the
  receipt strip is caught by V12's presence/reason-vs-signed-binding
  check); E2 `[CONTROL]` — exit 0, `3 inclusion bundles verified`,
  `2 reduced-coverage entries`.
- **Residuals, stated honestly.** (a) V12 binds receipt
  *presence/reason*, not full receipt-entry identity: the binding is
  content-addressed (tip + digest + seq, still chain-checked), so a
  genuine receipt entry for the same export replays harmlessly
  (control B2, preserved deliberately — the close-when requires only
  presence/reason binding). (b) Legacy 1.0 bundles fail closed at V1
  with an explicit F173 message and re-seal remedy
  (`evals/f173_legacy_binding_decision.md`); they are not silently
  accepted.

### F174

> **Close-when.** (1) Both the text and JSON verifier summaries render
> `bundle_meta.operator_id` labeled as an operator-supplied,
> unverified assertion (e.g. `claimed operator: <id>
> (operator-supplied, not independently verified)`); (2) probe `D1`
> flips to `[CAUGHT]` (the misleading name is visible with its
> disclaimer in both formats) while the bundle still verifies exit 0
> — the fix is disclosure, not rejection.

- (1) **Met, with the exact suggested wording.** Text:
  `claimed operator: <id> (operator-supplied, not independently
  verified)` on every verdict path (exit 0/1/2). JSON:
  `claimed_operator: {value, disclaimer: "operator-supplied, not
  independently verified"}`. The field is sourced from
  `bundle_meta.operator_id`, whose payload provenance remains
  `operator_supplied`.
- (2) **Met (observed).** D1 `[CAUGHT]` — the
  `"Acme Corp — Independent Audit Division"` name is visible WITH
  its disclaimer in both formats; the bundle still verifies exit 0.
  New unit tests lock both formats plus the unpinned path.

**Spec verdict: PASS** — every close-when clause is met by the
implementation and observed at the public seams; residuals are
documented, not hidden.

## Evidence

- Unit: `tests.test_evidence_bundle` + `tests.test_evidence_verify` —
  51/51 green (44 pre-existing + 7 new), `TMPDIR=/tmp/gw115u2`,
  `~/workspace/.gov-venv`.
- Normative §5 battery: `CAUGHT=14 MISS=0 CONTROL=15` (unchanged).
- Adversarial battery: `CAUGHT=9 MISS=0 BREAK=0 CONTROL=5 BROKEN=0
  AGREE=2 DIVERGE=0 ERROR=0` (target shape; was `6/0/3/5` at intake).
- `cmp gov/evidence_verify.py tools/evidence-verify` → identical.

**Overall: PASS on both axes. F173 and F174 meet their close-when
criteria; closure recommended.**

## Post-wave break-first closure audit (2026-09-26, standing rule)

Independent fresh-process audit
`~/workspace/audits/wave115/w115_f173_f174_audit.py` (separate
TMPDIR, real `tools/evidence-verify` subprocess at the public seams,
attack shapes re-crafted break-first rather than reusing battery
helpers): 7/7 PASS —

- F1a strip → exit 1 `[FAIL] V7`, never VERIFIED;
- F1b receipt strip → exit 1 `[FAIL] V12`, never VERIFIED;
- honestly-degraded (HMAC-only) seal → exit 0 with labeled reduced
  coverage;
- legacy 1.0 bundle → exit 1 `[FAIL] V1` with the explicit F173
  message;
- F174 text → exit 0, name + disclaimer rendered;
- F174 JSON → exit 0, `claimed_operator.value` + disclaimer;
- F174 unpinned → exit 2 with the disclosure present.

No overstatement found; nothing re-filed. **Audit verdict: GO.**
