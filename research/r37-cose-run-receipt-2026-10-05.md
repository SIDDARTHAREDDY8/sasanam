# R37 — COSE_Sign1 Run Receipt (spec)

**Date:** 2026-10-05 · **Pattern lineage:** sipyourdrink-ltd/bernstein PR #6392
("feat(replay): project the run receipt into COSE_Sign1 beside the JSON",
merged 2026-10-04, Apache-2.0, ARAVIND281) — **ADAPT only.**
No Bernstein code is vendored, imported, or translated line-by-line; the
three design decisions below are reimplemented clean-room in our idioms.
Bernstein repo re-verify note: the wave-341 research lane read the PR
description and public semantics only.

## 1. Problem

Our evidence-envelope track emits auditor-facing artifacts (evidence
bundles, witness checkpoints, VSA packets), but none is natively
ingestible by an operator whose pipeline takes **COSE_Sign1**: a
transparency service registering signed statements, a generic COSE
verifier, or an HSM that only signs COSE. The run receipt — the artifact
that binds a whole governed run — is the one that must speak that wire
format. An off-the-shelf verifier should validate it with no Sasanam
code in the loop.

## 2. The three stolen decisions

1. **Embedded binding BYTES, not a digest.** The COSE_Sign1 payload is
   the binding block itself (journal head + spine head), so a
   third-party statement about the envelope is a statement about the
   journal head and the spine head rather than about a filename. Edit
   one journal event afterwards and the registered statement no longer
   matches what the artifacts recompute to — with no Sasanam code in
   the verifying loop.
2. **Two copies of the binding are compared, never trusted.** The
   envelope carries one copy (the payload); the verifier recomputes the
   subject binding from the artifacts it was given and compares the two
   byte-for-byte (constant-time). A correctly-signed envelope over the
   wrong binding is `tampered`, not `verified`.
3. **`verify_run_receipt` returns a `tampered` status** (not an
   exception) when: the payload differs from the recomputed subject
   binding, the content type is not the run-receipt type, or the
   signature does not verify under the pinned key. It takes **bytes,
   not paths**; it never learns where any artifact came from.

### Sasanam analogs (Bernstein → us)

| Bernstein | Sasanam (`gov/run_receipt.py`) |
|---|---|
| journal (tool-event chain) | hash-chained audit log; **journal head** = chain-tip entry digest (32 bytes) |
| spine (run spine) | witness log; **spine head** = witness checkpoint projection `{tree_size, root_hash, timestamp, log_id}` |
| run-receipt.json + `.cose` sidecar | `build_run_receipt(...) -> bytes` (wire bytes); the JSON story is out of scope for this slice |
| receipt's own key | operator Ed25519 key; verifier pins the 32-byte public key explicitly |
| `cose_verified` tri-state | `cose_verified`: True (supplied and agreed), False (supplied, tampered), None (no envelope supplied) |

## 3. Wire format (RFC 8152 COSE_Sign1, wire-compatible)

```
COSE_Sign1 = #6.18([ protected: bstr, unprotected: map, payload: bstr, signature: bstr ])
```

- **Protected header** (bstr-wrapped CBOR map): `{1: -8, 3: "application/vnd.sasanam.run-receipt+cbor"}`.
  Label 1 = alg (EdDSA = -8); label 3 = content type. Both are
  integrity-protected. Any other alg value refuses; any other content
  type is `tampered`. The content type is read from the **protected**
  header only — an unprotected-header copy is ignored (never trusted).
- **Unprotected header**: empty map (reserved; ignored by the verifier).
- **Payload**: bstr of the CBOR-encoded binding block (definite-length,
  canonical map ordering):
  ```
  { 1: "run-receipt/1",
    2: h'<32-byte journal head>',
    3: { 1: <tree_size: uint>, 2: h'<32-byte root hash>', 3: <timestamp: uint>, 4: "<log_id hex>" } }
  ```
- **Signature**: Ed25519 over the COSE `Sig_structure`
  `["Signature1", body_protected, h'', payload]` (empty external AAD),
  CBOR-encoded exactly per RFC 8152 §4.4.
- **Tag**: the envelope MUST be tagged 18 (COSE_Sign1). Tag 98
  (COSE_Sign) or an untagged array is `tampered`.
- **CBOR**: minimal stdlib subset, definite-length only
  (`gov/run_receipt.py::_cbor_*`). Indefinite lengths, trailing bytes,
  and nesting beyond depth 16 refuse.

## 4. API

```python
build_run_receipt(*, journal_head: bytes, spine_head: dict,
                   signer: Ed25519Signer,
                   content_type: str = DEFAULT_CONTENT_TYPE) -> bytes
verify_run_receipt(cose_bytes: bytes | None, *,
                   public_key: bytes,
                   expected: dict | None = None) -> RunReceiptResult
```

`spine_head`: `{"tree_size": int, "root_hash": bytes(32),
"timestamp": int, "log_id": str}`. `expected`: the recomputed subject
binding `{"journal_head": bytes, "spine_head": {...}}`.

`RunReceiptResult.status` ∈ `{"verified", "tampered", "no-envelope"}`;
`tampered_reason` ∈ `{None, "signature", "content-type",
"payload-mismatch", "payload-malformed", "envelope-malformed",
"algorithm"}`; `cose_verified` ∈ `{True, False, None}`;
`binding_compared: bool` — False when `expected` was not supplied, so a
signature-only pass can never be read as "the binding was compared".

Usage errors (not content verdicts) raise `RunReceiptError`:
`public_key` missing/malformed, builder inputs malformed. Content
anomalies never raise — they are `tampered`.

## 5. Threat model (read before trusting a receipt)

- A receipt proves **registration of a statement about a binding
  block**, not truth of the events. The journal-head binding is only as
  honest as the journal writer; the witness checkpoint is only as
  honest as the witness key holder.
- **No-rollback property:** `verify_run_receipt(old_receipt,
  expected=new_binding)` → `tampered` (`payload-mismatch`). An auditor
  pinned to the new head cannot be shown a stale-but-valid receipt.
- **keyid is a hint, never authority** (witness_log.py lesson): the
  verifier uses the caller-pinned `public_key`, never any `kid` in the
  envelope. A spoofed kid changes nothing.
- The comparison is byte-level on canonical CBOR: a digest-instead-of-
  binding payload (the Bernstein mutant) fails `payload-malformed`,
  never "verified with a weaker statement".
- Replay of the *same* receipt against the *same* binding verifies —
  receipts are statements, not nonces. Freshness is the auditor's job
  (pin the head you expect).

## 6. Slice boundary

Slice 1 (this lane): spec + builder + verifier + break-first battery.
Slice 2 (future): CLI verify command accepting a `.cose` on its own;
registering receipts with a transparency service.

## 7. Honesty notes

- This is **genuinely wire-compatible COSE_Sign1** (tag 18, CBOR,
  Sig_structure per RFC 8152), unlike `gov/evidence_receipt.py`'s
  JSON-shaped analog which is deliberately not wire-compatible. The
  claim "an off-the-shelf COSE verifier validates it" is testable:
  any RFC 8152 verifier with EdDSA support parses these bytes.
- The minimal CBOR codec is a prototype subset. It is NOT a general
  CBOR library; structures outside the subset refuse loudly.
- Determinism: the builder is a pure function of
  `(journal_head, spine_head, signer_seed)` — same inputs, same bytes.
  A committed test vector is pinned in the battery.
