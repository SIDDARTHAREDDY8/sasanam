# RT11 — F117 closure ratchet + fresh ADI variants (Wave 42, 2026-09-22)

## Objective

Break-first re-attack of the F117 closure (wave-41) from adjacent
angles — truncating-but-nonempty variants, key-dependent behavior,
nonce handling, fresh ADI shapes — and convert every held shape into a
durable ratchet so the closure cannot silently regress.

## Break-first battery (scratch: `~/workspace/agent-governance-demo/scratch/rt11_breakfirst.py`)

Pre-fix result: **8/11 HOLD, 1 genuine MISS, 1 documented residual, 1
investigated boundary**.

### Genuine miss → F118 (LOW, CLOSED wave-42)

- `lambda k,n,d: d[:-1]` (and `d[:len(d)//2]`) **UPLOADED** 45 bytes
  (`nonce + d[:-1]` — 29 of 30 plaintext bytes on the wire) while the
  audit claimed `encrypted: True`.
- Root cause: the F117 guard ran on the NONCE-PREFIXED blob
  (`archive = nonce + cipher(...)`). A truncating cipher that drops
  fewer than the 16 nonce bytes still yields a blob LONGER than the
  plaintext (length check sailed through), and the truncated plaintext
  is no longer a contiguous substring (verbatim check sailed through).
- The wave-41 closure probe tested `d[:4]` — an aggressive truncation
  (4+16=20 ≤ 30, caught by the length check) — and missed the
  sub-nonce hole. **Test-design lesson: probe truncations smaller than
  the nonce, not just large ones.**
- Fix (`gov/platform_egress.py`): the shape check runs on the raw
  cipher OUTPUT before the nonce is prepended; refuse AUDITED
  (`archive_cipher_ineffective`) when the plaintext is verbatim in the
  output or the output is STRICTLY SHORTER than the plaintext
  (truncation is data loss, not encryption). Non-bytes cipher returns
  coerce via `bytes()` inside the audited-failure path (F113 property
  preserved: no raw exception escapes unaudited).
- Boundary correction during the fix: same-length non-verbatim output
  (stream-cipher shape, including the sanctioned TEST-ONLY
  `demonstration_cipher`, HMAC-keystream XOR) PASSES by design — it is
  a functional cipher, not a degenerate one; cipher quality beyond
  degenerate-output detection is the deployer's choice. The first
  version of the fix (`<=`) refused `demonstration_cipher`; the
  vacuity probe caught it before registration.

### Held shapes (ratcheted)

- Truncating variants `d[:-1]` / `d[:len//2]` / `d[:1]` → refused +
  audited post-fix.
- Key-dependent identity (reads the key, returns plaintext) → refused
  (verbatim sub-check).
- Key-dependent truncation → refused.
- Verbatim plaintext inside longer output (`d + 64 zero bytes`) →
  refused (verbatim sub-check; padding does not launder).
- Nonce-echo (`n + d`) → refused (verbatim sub-check).
- Tool-result privilege claim → never parsed: `_ingest_result` (the
  result-ingestion choke point) produces no `privilege_claim` event,
  no DLP taint, no identity change; `_claims_higher_privilege` only
  runs inside `resolve_hierarchy` on tagged content items, never on
  results.
- `sender` / `author` / `from_principal` metadata kwargs → no
  privilege effect; audit attribution stays with the minted identity.
- Cross-run delegation grant replay → refused (grants are MAC-bound
  to their run; `cross_run=False` default).

### Documented residual (pinned, not closed)

- **R7**: a base64 "cipher" (non-trivial transform, no encryption)
  still passes — the deployer chose the cipher; a malicious deployer
  is outside the threat model. Pinned by
  `redteam.rt11.r7_base64_residual_documented` (same pattern as the D3
  bearer-reuse pin): verdict "stopped" while the boundary is
  unchanged, "break" if it ever moves, forcing re-review.

### Investigated boundary (not a probe, not a finding)

- **R10**: `ApprovalQueue.decide()` accepts a caller-asserted
  `decided_by` label in-process. This is the operator's API (web
  bridge: session → origin → CSRF gates; CLI: the human's terminal),
  and the label's trustworthiness comes from the caller — exactly the
  documented process-boundary trust of `mint_identity`'s GOVERNANCE
  WARNING ("audit attribution is only as strong as the process
  boundary"). Reaching `decide()` requires breaking the agent API
  boundary (agent code importing `gov` internals), which is outside
  the threat model the same way editing the binary would be. No
  finding; no probe (the verdict taxonomy has no "API behaves as
  documented" — forcing it in would mislead).

## Probe-hygiene corrections found during RT11 (wave-42)

RT11's break-first discipline caught two weaknesses in the wave-42
RT10 ratchet probes (`evals/w42_probes.py`), both fixed before the
registry gate:

1. **Vacuous tool (`echo_text`)**: three probes (A1, B1, B3) called a
   nonexistent tool, which the policy denies before execution — the
   probes passed without exercising the shape. Rewired to real tools:
   A1 now queues a real `send_email` and asserts `_bridge_state` still
   classifies the record `("none", None)` (the kwarg lands in `args`,
   never record-level provenance); B1 executes a real `read_file`
   with framing kwargs; B3 executes a real `read_file` with a forged
   grant id.
2. **B3's docstring was wrong about the mechanism**: a forged
   `delegation_grant_id` is not "popped and never verified" — it is
   popped from tool kwargs AND fail-closed through the delegation
   gate: the call is DENIED (`unknown_grant`). Stronger than
   documented; probe and registry text corrected.

## Durable artifacts

- Fix: `gov/platform_egress.py` (F118)
- Tests: `tests/test_w42_rt11_f118.py` (12 tests)
- Probes: `evals/w42rt_probes.py` (11 probes:
  `redteam.rt11.f118_*` ×7, `redteam.rt11.r7_base64_residual_documented`,
  `redteam.rt11.held.r8/r9/r11`)
- Registry: `evals/scenarios/registry.yaml` (+11 entries, wave-42,
  closure green)
- Finding: `evals/FINDINGS.md` F118 CLOSED 2026-09-22 (LOW)

## Severity note

F117 severity normalized to **LOW** across all records
(`evals/FINDINGS.md`, `BUILD_LOG.md`, RT10 report, registry text).
The Wave-42 handoff summary called it MEDIUM in error; the finding's
own "Why it matters" (deployer-supplied cipher, audit-claim integrity
issue, no remote exploit) is LOW, and F118 inherits the same
rationale.

## Gates (wave-42 RT11 lane)

- RT11 break-first: 8/11 HOLD pre-fix shapes, F118 filed + fixed,
  all 11 registered probes stopped post-fix
- Registry gate: 263/263 oracle matches, GREEN
- Canonical suite (venv): 1768 ran — 1767 OK, 1 failure = FK-3
  timing flake (166.2 ms vs 150 ms bound; suite ran under load;
  green in isolation on quiet tree). Effective GREEN.
- Ship-gate matrix: **3216/3216 GREEN** (sequential, quiet tree)
- Realistic battery: **3/3 GREEN** (smoke-full-loop, human-error-pack,
  swarm-pack)
- Wave-42 gates: **CLOSED 2026-09-22.** Open findings: F81 LOW only.
  Next free finding: F119.
