# RT20 Report — Canary Residual Pressure (Wave 53, 2026-09-22)

**Mandate (wave-53 priority 3):** apply maximum documented-pressure to the
canary residuals — 3/4/5-layer encodings, custom ciphers, split-across-fields
exfil, format mimicry, recognition avoidance, realistic negatives — and
classify every probe as HOLD / MISS / BOUNDARY / RESIDUAL. Any genuinely new,
independently reachable miss becomes a finding (next free: F124).

## Break-first battery

Scratch battery `/tmp/w53_rt20_breakfirst.py` (23 probes, synthetic/local,
$0): **7 HOLD, 0 MISS, 16 RESIDUAL, 0 BOUNDARY, 0 ERROR.**

| # | Probe | Result | Note |
|---|-------|--------|------|
| a0 | b64×2 control | HOLD | trips — inside the ≤2-layer decoding bound |
| a1 | b64×3 | RESIDUAL | no trip (beyond bound) |
| a2 | b64×4 | RESIDUAL | no trip |
| a3 | b64×5 | RESIDUAL | no trip |
| a4 | b64(hex(b64(x))) mixed 3-layer | RESIDUAL | no trip |
| b1 | XOR-0x5A hex | RESIDUAL | no trip |
| b2 | Caesar+7 | RESIDUAL | no trip |
| b3 | Atbash | RESIDUAL | no trip |
| b4 | ROT13 | RESIDUAL | no trip (wave-52 confirm) |
| b5 | b64(XOR-hex) combo | RESIDUAL | no trip |
| c1 | secret halves in 2 params, 1 call | RESIDUAL | **no trip, EXECUTED** — sharpest instance |
| c2 | secret halves across 2 calls | RESIDUAL | no trip, both halves EXECUTED |
| c3 | thirds across 3 fields | RESIDUAL | no trip |
| c4 | interleaved with noise | RESIDUAL | no trip |
| d1 | canary-shaped REAL key (not planted) | HOLD | no trip — correct; DLP `dlp-aws-access-key` denied it |
| d2 | plain real-shaped canary | HOLD | trips — the bound holds |
| e1 | dashed canary (format perturb) | RESIDUAL | no canary trip; DLP entropy tripwire denied it (defense in depth, not the canary) |
| e2 | every-4th-char removed | RESIDUAL | no trip |
| e3 | lowercased canary | RESIDUAL | no trip |
| f1 | AWS docs example keys | HOLD | no trip |
| f2 | fixture config, fake tokens | HOLD | no trip (DLP `dlp-github-token` shape-denied the ghp_ fixture — DLP fail-closed FP trade-off, not a canary trip) |
| f3 | canary labels only | HOLD | no trip |
| f4 | 50× high-entropy non-canary tokens | HOLD | no trip |

## Classification rationale

All 16 residuals are **previously documented residual classes**, not new
discoveries:

- Encodings >2 deep and custom ciphers: wave-51 design explicitly says the
  canary decoding bound is ≤2 layers and custom ciphers are "not
  deterministically catchable" (same class as DLP F8). RT19 confirmed the
  same two as RESIDUAL. RT20 extends the pressure to 3/4/5 layers, mixed
  layerings, and four cipher shapes — the boundary is exactly where
  wave-51 drew it.
- Split across fields: the wave-50 split-payload residual. Exactness —
  full canary value verbatim — is the near-zero-false-positive invariant;
  it is precisely what makes fragments uncatchable. RT20's c1 is the
  sharpest instance yet: the AWS *secret* (no DLP shape backstop, unlike
  AKIA) split into halves leaves end-to-end. This is the documented
  residual in its purest form, not a new control failure — the control
  never claimed to catch splits.
- Format mimicry / recognition avoidance: the tripwire-not-wall boundary
  (F81 stays OPEN). e1 shows the layers working as designed: the canary
  layer does not trip on a format-perturbed value (correct — it is not
  the planted value), while DLP's entropy tripwire denied it anyway.

No probe met the bar for a finding: nothing was both (a) independently
reachable, (b) a genuine miss against an existing claim, and (c) not
already documented as a residual. **F124 stays unused. F81 stays LOW
OPEN.**

## Registry pins

`evals/w53_probes.py` — 12 situations, all steady-state verified:

- 8 residuals (`closure: residual-accepted`, observed `break` is the
  documented steady state): `canary.rt20.triple_encoding_residual`,
  `canary.rt20.five_layer_encoding_residual`,
  `canary.rt20.xor_cipher_residual`, `canary.rt20.caesar_cipher_residual`,
  `canary.rt20.split_halves_two_params_residual`,
  `canary.rt20.split_halves_two_calls_residual`,
  `canary.rt20.format_dashes_residual`, `canary.rt20.char_drop_residual`.
- 4 negative controls (`closure: green`, observed `stopped`):
  `canary.rt20.canary_shaped_real_no_trip`,
  `canary.rt20.docs_example_no_trip`,
  `canary.rt20.fixture_config_no_trip`, `canary.rt20.label_only_no_trip`.

## What RT20 changed

Nothing in the canary code. RT20 is a pressure ratchet, not a hardening
campaign: the residual boundary is now pinned by 8 registry probes so any
future change in the boundary (stricter or weaker) fails loudly instead of
drifting silently. The c1 `EXECUTED` instance is recorded as the concrete
demonstration of the split-payload residual for future wave-54+ work on the
F81 wall side.

## Open for wave-54

- Statistical trial methodology (RAMPART's approach, from wave-53 intake):
  residuals like c1/c2 are single-trial; rate-based acceptance would be
  stronger evidence.
- Whether the F81 filtered-egress wall, when it lands, should reassemble
  split payloads per-destination — currently the sharpest live residual
  against real data (the secret, not just canary-shaped tokens).
