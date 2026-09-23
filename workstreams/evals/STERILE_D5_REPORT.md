# Sterile D5 — typed unvetted marker (design + implement + break-first)

**Wave-64, 2026-09-22.** Answers the wave-63 open question: the
sterile-cockpit unvetted-reissue pipe (`LoopContract.reissue_reads`,
`gov/sterile.py`) was documented contract ("never marked vetted",
design §8 R4) but loop consumers got no machine-readable "never
vetted" marker — a consumer doing
`for r in delta: ctx.append(r["result_summary"])` silently treated
unvetted summaries as trusted context (demonstrated as the L0
baseline in the break-first battery).

## 1. Design (Lane 1)

### (a) What the marker is and where it attaches

`Unvetted` — a generic value wrapper in `gov/sterile.py`
(exported in `__all__`). It attaches as a **read-result envelope**:
the **executor** wraps the *entire return value* of
`loop.reissue_reads(...)` at the producer boundary (both sites:
`request_window_close` and `_sterile_expire`), before audit
stashing or any other consumer touches it. The loop's contract
signature is unchanged — it still returns plain data. Wrapping at
the producer boundary (not inside the loop) means a loop cannot
strip a marker applied after it returns, and a loop that "forgets"
to mark cannot downgrade: the executor marks unconditionally.

The stored form is the JSON envelope (`to_envelope()`), never the
live object — the audit log's `json.dumps(..., default=str)` would
erase a live wrapper into an opaque string.

### (b) The unwrap contract

`Unvetted.acknowledge(consumer_id, sink=None)` is the **only
documented read path**. It returns the raw payload; when `sink`
(a list) is given, it appends
`{"event": "unvetted_acknowledged", "consumer": consumer_id,
"origin": ...}` — auditable evidence of who accepted never-vetted
data. `consumer_id` must be a non-empty string (TypeError
otherwise — anonymous acceptance is not acceptance).

If a consumer does not acknowledge: iteration, indexing, `len`,
`in`, `bool`, and `list()` all raise `TypeError` naming the
acknowledge path; `==` against the payload is fail-closed `False`
(identity equality — a marker that compared equal to its payload
would dissolve silently). Accidental silent treatment as vetted is
structurally impossible for *mistakes*. Deliberate bypass
(`_payload` attribute / dunder access) remains possible in
CPython — graded honestly as **advisory** against hostile
in-process consumers (F59 family), a real gate against confused
ones (the human-error shape).

`repr()` shows origin + shape only, never payload contents —
unvetted summaries must not leak into logs through a stray repr.

### (c) The serialization boundary

JSON round-trips erase Python types, so the marker survives via
the envelope: `{"__gov_unvetted__": true, "origin": ...,
"payload": ...}`. `Unvetted.from_envelope` is **total and
fail-closed**: there is no input that yields a bare,
potentially-trusted-looking value —

- envelope with the key → `Unvetted` (origin restored);
- any other JSON value (key stripped, pre-D5 plain list/string,
  anything) → `Unvetted` with `origin="unmarked-erased"`;
- non-JSON types → `TypeError` (programmer error, loud).

The deeper invariant making erasure safe: **nothing is vetted
unless it carries a minted `Vetted` mark** (ground truth of the
scheme; Unvetted is the default state made explicit). Erasure can
only under-inform, never over-trust. Stripping the key from the
*stored audit copy* is detectable via the log's hash chain
(existing F34/F43 machinery); hostile in-process editing of a
live envelope is the F59 accepted residual. Marker keys are
meaningful only at the envelope top level — a `__gov_vetted__`-
looking key nested inside payload is inert data, and
`Vetted.from_envelope` requires a live `(stack, capability)`
regardless.

### (d) Who can mint the "vetted" marker

`Vetted` cannot be constructed directly (`TypeError` — the
constructor requires the module-private `_VETTED_SEAL`, held only
by `VettingStack.vet()`). Mint authority is the **content-defense
stack**, modeled by `VettingStack`:

- each stack holds a per-instance 256-bit secret mint token;
- `issue_capability(purpose)` returns a `VettingCapability` bound
  to that token (unguessable; the loop is never issued one);
- `vet(payload, capability)` mints only if the capability is a
  `VettingCapability` whose token matches this stack's
  (`hmac.compare_digest`) — otherwise `VettingError`;
- capabilities block `copy`/`deepcopy`/`pickle` (possession is by
  reference, never by value);
- the vetted JSON envelope carries only the non-secret `mint_id`;
  `Vetted.from_envelope` re-verifies `mint_id` against the
  capability and re-mints through `stack.vet()`. With no live
  capability, a vetted envelope decodes as `Unvetted`
  (fail-closed).

Honesty note: in a single Python process the gate is
possession-based — it stops confused-deputy/accidental minting
and any code without a reference to the stack, which is the real
threat (a loop "remembering" to mark its own output vetted can no
longer do so by calling a constructor). A fully hostile
in-process importer is outside the model (F59). The
enforcement-grade story is the deployment's process boundary
(the vetting stack lives outside the agent's code path) — named,
not claimed. External validation: the neural-taint-tracking
project's declassification rule ("an agent cannot make a document
trusted by asking to authorize it") and the "labels are not the
enforcement layer" principle (research/intake-wave64-2026-09-22.md).

## 2. Implementation (Lane 2)

- `gov/sterile.py`: `Unvetted`, `Vetted`, `VettingStack`,
  `VettingCapability`, `VettingError` (+ `__all__`,
  `LoopContract.reissue_reads` docstring updated to name the
  executor-side wrap and the loop author's residual obligation).
- `gov/executor.py`: both reissue sites
  (`request_window_close`, `_sterile_expire`) wrap the loop's
  return in `Unvetted(...).to_envelope()` for the
  `post_window_delta` audit field. `reconciled_vetted: False`
  unchanged (R4). `request_window_close`'s return shape unchanged
  (Wave-49 lesson: `reconcile` still the raw `[(tool, channel)]`
  list). One mid-wave bug caught by the battery: the first cut
  referenced `Unvetted` imported `__init__`-locally (NameError
  swallowed as `reissue_error`) — fixed with the file's
  method-local no-cycle import idiom, and the close-path wrap
  moved into the try/else so a wrap failure could never be
  misattributed as a `loop_contract_error`.

## 3. Break-first evidence

Battery `/tmp/w64_breakfirst.py` (36 probes, 7 lanes):

| Lane | Probes | Result |
|---|---|---|
| L0 baseline gap (pre-D5 bare list silently trusted) | 1 | HOLD (gap confirmed, then closed) |
| L1 type-erasure (JSON round-trip, stripped key, pre-D5 plain, forged inner key, vetted-claim-without-capability, non-JSON input) | 7 | HOLD |
| L2 consumer confusion (iter/list/getitem/len/contains/bool, equality, acknowledge contract + sink, consumer_id validation) | 10 | HOLD |
| L3 marker forgery (direct construct, seal forge, fresh/foreign/non capability, copy/deepcopy/pickle, mint_id mismatch, no-capability decode, unvetted-as-vetted, legit mint, token-not-serialized) | 12 | HOLD |
| L4 deliberate bypass reachable | 1 | **BOUNDARY** — dunder/attribute access reaches `_payload`; advisory grading pinned, F59 family, not a miss |
| L5 legitimate-loop regression (close/expiry enveloped, JSON-safe without `default=str`, return shape unchanged, no-loop path unchanged) | 4 | HOLD |
| L6 repr hygiene | 1 | HOLD |

**36 probes → 35 HOLD / 1 BOUNDARY / 0 MISS.** No genuine
independently-reachable miss → no F129 filed (next free stays
F129). Two battery bugs (not code bugs) were fixed mid-wave: an
expiry timestamp in the past, and a test asserting on a random
mint_id hex.

Durable pins: `tests/test_w64_sterile_d5.py` (23 tests),
`evals/w64_probes.py` (5 probes) + 5 `redteam.sterile_d5.*`
registry entries (closure: green).

## 4. Verdict

**Shipped as advisory-with-teeth** — not enforcement, not
theater, not a documented-only boundary:

- *With teeth*: accidental confusion is structurally impossible
  (confusion paths raise; equality fail-closed; the audit record
  is self-describing JSON); the vetted mark is genuinely
  mint-gated (untrusted code cannot manufacture trust — 12
  forgery probes hold).
- *Advisory*: deliberate in-process bypass of the `Unvetted`
  wrapper is reachable (L4 BOUNDARY, pinned by test); the
  enforcement half remains the pre-existing R4 invariant (the
  executor never marks reconciled reads vetted) plus the
  deployment's process boundary for the vetting stack.

What was deliberately not done: per-read (vs per-return) markers
(one envelope per `reissue_reads` call matches the pipe's
contract surface; per-read adds API without new security);
wrapping `request_window_close`'s return value (would change a
public return shape — Wave-49); HMAC-signed vetted envelopes
(entangles with the open prod-KMS priority; the capability token
is the mint gate, the mint_id is correlation-only); any change
to the loop's contract signature.

Open questions for Wave-65: (1) should `acknowledge()` sink
records feed the hash-chained audit log directly (currently a
caller-provided list)? (2) the `VettingStack` has no in-repo
deployment consumer yet — the first real content-defense stack
integration should define who calls `issue_capability()` and for
what purposes; (3) F81's D1–D4 privileged-CI lanes remain the
standing deferred pressure.
