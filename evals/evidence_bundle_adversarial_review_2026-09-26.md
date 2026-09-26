# Two-axis review: evidence-bundle adversarial battery (wave-114 lane 1)

Date: 2026-09-26. Battery: `evals/evidence_bundle_adversarial.py`
(16 probes). Result: **CAUGHT=6 MISS=0 BREAK=3 CONTROL=5 BROKEN=0
AGREE=2 DIVERGE=0 ERROR=0**, exit 0; deterministic across 2 runs;
`--weakened` mode exits 1 (A1 miss) — red-capable. Findings filed:
**F173 (LOW, OPEN)**, **F174 (LOW, OPEN)**.

## Axis 1 — Standards

**Repo conventions: PASS.**

- `os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")` sits
  immediately after imports (wave-95 lesson); the battery was verified
  standalone under `env -u GOV_DEPLOYMENT_MODE` (exit 0).
- Runs under `~/workspace/.gov-venv` only; every run used a pre-created
  isolated TMPDIR (wave-112 lesson — Python 3.12 silently ignores a
  nonexistent TMPDIR).
- Deterministic: two full runs produce byte-identical stdout; all
  identities are fixed synthetic Ed25519 keys; wall-clock is pinned
  (`_pinned_time`) wherever two fixtures must be comparable, and
  explicitly unpinned where the probe needs distinct timestamps (B2's
  receipt mints).
- Red-capable: `--weakened` generates a deliberately broken verifier
  copy (threshold branch counts *signatures*, not distinct keys, with
  uniqueness asserts on the weakening anchors so the weakening cannot
  silently not-apply) and the whole battery runs against it — it FAILS
  with exactly the A1 miss. The A1 probe additionally asserts the
  weakened verifier is *fooled* (exit 0) on the normal run, so a vacuous
  probe would be loud, not silent.
- Malformed-input robustness: the C2 differential corpus includes empty
  dirs, truncated JSON, garbage lines, future VERSION, non-dict
  manifests, and a regular-file-not-directory — the harness treats any
  probe exception as `[ERROR]`, never a silent pass.
- Threat-model honesty: no-key probes use raw file surgery + unsigned
  digest recompute only (never the signing keys); white-box probes that
  re-sign say so in their docstrings and isolate exactly one verifier
  check past a valid operator signature.
- No network, $0, synthetic/local only. Nothing committed or pushed;
  no full gates run; `evals/artifacts/wave23_b2/battery_100_results.json`
  untouched.

**Caveats (not failures).** The C3 CLI-parity probe normalizes the
argparse prog name *and* collapses whitespace before comparing stderr,
because usage wrapping depends on the script's filename length — the
parity under test is the failure mode (exit 3, same message), which
holds. B2's second receipt mint uses a hardcoded
`2026-09-26T12:01:00+00:00` timestamp to beat `_utcnow`'s 1-second
resolution; it is deterministic but time-anchored — harmless for a
synthetic probe.

## Axis 2 — Spec / task

**Task coverage: PASS.** All five assigned attack shapes are probed,
with negative results reported as results, not padded:

- (a) **Threshold confusion** — 4 attacks (duplicate-key k-of-n,
  wrong-envelope-key signer, roster key-ID aliasing, roster
  substitution), all CAUGHT at V8, plus a genuine 2-of-3 control.
- (b) **Receipt replay** — cross-content replay CAUGHT at V12;
  byte-identical-content replay VERIFIES including V12b (B2): the
  honest negative result is that the receipt binding is
  content-addressed, so replay across *different* content is impossible
  and across *identical* content is harmless.
- (c) **Verifier differentials** — byte-identity drift guard (C1) plus
  a 16-input hostile/diverse corpus run against both copies with
  exit-code + stdout agreement (C2), plus CLI error parity (C3). No
  divergence found.
- (d) **Auditor-misleading bundles** — D1 reproduces the filed F174
  (misleading operator_id invisible in both output formats); D2
  verifies the §7 honesty footer rides all verdict paths.
- (e) **Checkpoint binding** — stale head without re-sign CAUGHT at V8
  (E1); stale head with re-sign verifies only with explicitly labeled
  reduced coverage (E2): staleness surfaces, never passes silently.

**Findings hygiene: PASS.** Two real breaks found, both filed as new
findings with severity and close-when criteria, both OPEN — nothing
was fixed quietly in this lane:

- **F173 (LOW, OPEN)** — unsigned inclusion-coverage downgrade (probes
  F1a/F1b, `[BREAK]`): the operator signature's claim triple does not
  cover inclusion-bundle presence, coverage counts, or the receipt's
  bundle-presence, so a no-key transport attacker can strip inclusion
  bundles (or the receipt's own bundle), adjust the unsigned counts,
  recompute only the unsigned transport digest, and still get exit 0
  VERIFIED. Bounded impact is stated in the finding: entry forgery is
  still prevented by V9's Merkle-root recomputation against signed
  heads; what breaks is per-entry offline provability, the receipt's
  chaining proof, and the honesty of the coverage accounting.
- **F174 (LOW, OPEN)** — auditor-misleading operator identity (probe
  D1, `[BREAK]`): a VERIFIED bundle can carry an
  authoritative-sounding `operator_id` that appears in neither the text
  nor the JSON verifier summary, inviting auditors to mistake
  key-pinning for identity verification. The finding is explicit that
  this is a display/attribution-clarity gap, not a cryptographic
  bypass (the verifier never claims to verify the name).

**Non-duplication.** The wave-112 normative battery covers §5 T1–T10
(14 caught / 15 controls); this battery does not re-probe those
directions — it attacks *beyond* §5, and its break-demos (F1a/F1b/D1)
are the red-first pins for the fix lane.

## Verdict

Standards **PASS**, Spec **PASS**. The battery is committed as the
standing adversarial suite for the evidence-bundle surface; the fix
lane owns F173/F174 against their close-when criteria (F1a/F1b must
flip to `[CAUGHT]`, D1 to disclosed-and-labeled, E2 must stay green).
