# Review artifact — evidence-bundle tamper battery rebuild + F172 fix (2026-09-26)

Two-axis review per the `code-review` skill (no `.git` in this tree; the
"diff" is the changed-file set). Both axes ran as parallel sub-agents;
their reports are reproduced below, followed by dispositions.

Changed files:
- `evals/evidence_bundle_tamper.py` — REWRITTEN: normative §5 battery
  (T1–T10, 14 tamper cases + 15 controls)
- `gov/evidence_verify.py` — V11 `unversioned` rendering fix (F172)
- `tools/evidence-verify` — byte-identical re-sync
- `tests/test_evidence_verify.py` — `TestEvidenceVerifyUnversionedPolicy`
- `evals/FINDINGS.md` — F172 filed + closed

Spec source: `docs/evidence-bundle-spec.md` §5 (T1–T10 + benign controls),
§4.1.1 item 3 (policy section, "unversioned" if absent), §4.3 (V11, exit codes).

---

## Standards axis

**Hard violations of documented standards: none.** Battery sets
`GOV_DEPLOYMENT_MODE=staging` at module level, is deterministic (fixed hex
keys, fixed `GOV_LOG_KEY`, fixed `EXPORTED_AT`, no sleeps/network/RNG),
builds fresh synthetic fixtures per case, runs the real
`tools/evidence-verify` as a subprocess with `cwd="/tmp"` and PYTHONPATH
stripped, asserts exact exit codes + named checks. `tools/evidence-verify`
is byte-identical to `gov/evidence_verify.py` (drift guard green). The V11
fix applies the documented §4.1.1-item-3 rendering rule; the new test class
follows the file's existing convention.

**Baseline smells (judgement calls, all addressed):**
1. *Duplicated Code* — the eleven per-scenario controls were near-identical
   3-line bodies → replaced with a single `_control(tag)` helper; all
   controls now assert through one path.
2. *Message Chains* — one-shot dict drilling in `c4_sar_unsealed` /
   `c5_unversioned_policy` — minor; left as is (one-shot reads in controls).
3. *Duplicated Code (mild)* — `t4b`/`t5` hand-rolled fail-any logic →
   replaced with an `_expect_any_fail(code, out, exit_code, *fail_ids)` helper.

Checked and NOT flagged: unused `import shutil` (tooling-enforced);
`t7`'s use of the verifier's private Merkle helpers via `SourceFileLoader`
(repo battery convention); the `_assemble` fixture-dict bag.

---

## Spec axis

**(a) Missing / partial coverage — both found genuine and both fixed:**
1. *T8's second normative MUST was untested.* §5 T8: "V10 must fail when a
   section references sequences outside `[from_seq, to_seq]`" — no case
   injected an out-of-window seq ref into a payload section.
2. *T8a asserted V9+V10; the spec's T8 names V12+V10.* Cutting the slice
   tail with a stale manifest keeps the receipt chained to the manifest's
   declared tip (V12 compares `receipt.prev_hash` to the manifest's
   `tip_hash`, not the slice's recomputed tip), so V12 never fired on the
   naive tail cut.

   **Fix:** new case `t8c_window_shift_coherent` — the attacker cuts the
   slice tail AND re-declares the window `[1,4]` (white-box re-sign so V7
   passes), presenting the truncation as complete. The receipt still binds
   the old seq-5 tip → V12 fails ("does not chain onto"); the payload
   sections still reference seq 5 and the coverage still claims 5 entries
   → V10 fails. Battery now asserts `[FAIL] V12` + `[FAIL] V10`, exit 1.
   Verified green: CAUGHT=14.

3. *§4.3 exit-code tension in t4c (spec-internal, documented not redefined).*
   §4.3's exit-2 paragraph lists `scheme: "none"` as a SELF_CONSISTENT case
   ("which cannot occur for v1 bundles but is handled explicitly"), while
   §5 T4 says "V5/V7 fail closed". The verifier fails V7 → exit 1; the
   battery follows the normative §5 (fail-closed is the safe direction for
   an alg=none-shaped attack — treating it as "internally intact" would be
   the dangerous reading). Tension recorded in the battery and BUILD_LOG;
   behavior unchanged.

**(b) Scope creep — none requiring removal:**
- T9's extra "V6 fails with genuine pin" probe: beyond §5 T9's letter,
  harmless and consistent (kept).
- t7 pins the exact string "signature does NOT verify": §5 T7 demands only
  "V8's Ed25519 verification must fail" — the string is the implementation's
  own fail-closed message (kept).

**(c) Looked wrong, investigated, NOT a defect:**
- *F172 explicit-null edge.* The reviewer noted `latest.get("policy_version",
  "unversioned")` still yields `None` for an explicit-null field. Checked
  the builder (`gov/evidence_bundle.py::_build_policy` line 327):
  `ev.get("policy_version", "unversioned")` — the IDENTICAL rule. So
  explicit null renders `None` on both sides and V11 compares None == None
  → passes. Absent key renders "unversioned" on both sides → passes. The
  builder and verifier cannot disagree; no false reject in any of the three
  shapes. No change needed.

**White-box re-signs (assessed, kept):** T5's attacker re-sign is exactly
what §5 T5 prescribes ("Replace the envelope operator key with the
attacker's key and re-sign") — faithful. T10's operator re-sign is
instrumentation the spec doesn't mention, but a keyless attacker's T10 dies
at V4, so the normative MUST ("V11 must fail") is unreachable without it;
the battery documents it and pins V4-PASS to keep the instrumentation
honest. T8c's operator re-sign is the same pattern (isolates V10/V12 past
a valid V7).

---

## Verdict

Standards: PASS (no hard violations; smells addressed).
Spec: PASS after the t8c addition — all §5 T1–T10 normative MUSTs now have
dedicated tamper cases plus fresh positive controls; the two genuine
coverage gaps found by the review are closed; the scheme:none tension is
documented; the F172 explicit-null edge is a non-issue by construction.
