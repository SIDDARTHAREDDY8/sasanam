# Two-axis review: wave-114 lane 2 — adversarial rerun of the F69 `pin_off` change

Date: 2026-09-26. Change under review: **no product change** (adversarial
lane; negative result). Battery `evals/f69_pin_off_adversarial.py` (17
probes) attacks the wave-112 change to `gov/log.py`'s F72 replay-freshness
hot path — the incremental scan from the MAC-covered `pin_off` instead of
JSON-parsing the whole checkpoint sidecar — plus the F69
`time.process_time()` metric change. FINDINGS.md carries a wave-114 lane-2
maintenance note under F69 (precision correction, no new finding).

## Standards axis: PASS

Reviewed against repo eval-battery conventions (drawn from
`evals/f69_timing_flake_two_axis_review.md`, the AGENTS.md standing
lessons, and neighboring batteries like `evals/gap5_reverify_break.py`):

1. **Deployment mode**: `os.environ.setdefault("GOV_DEPLOYMENT_MODE",
   "staging")` at module level immediately after imports. Verified
   standalone under `env -u GOV_DEPLOYMENT_MODE` (first full run) and
   normal env (second run): identical 17/17.
2. **Key hygiene**: fresh random key per process via
   `tests/keyfixture.provision_test_key` (the same env backend
   production uses). No key material in the repo; attacker artifacts
   are raw file surgery with no key use, genuine artifacts go through
   the real code paths (`_append_tip_gen_pin`, `_write_tip_cache`,
   `verify_chain_tip`, `write_chain_tip_from_tail`).
3. **TMPDIR discipline**: every probe builds its own `mkdtemp` run dir
   and `cleanup()`s in `finally`; the runner was executed with
   pre-created `TMPDIR`s (the wave-112 AGENTS.md lesson). Burner
   processes in t2 are killed/waited in `finally`.
4. **Deterministic**: no threads, no sleeps on the measured path, no
   timing races — every interleaving is constructed deterministically
   by file/sidecar surgery. Two full runs: identical verdicts and
   stable margins (t1 367/387ms vs 150ms bound; t2 worst 12/13ms).
   ~10s total: fast and agent-runnable.
5. **Verdict discipline**: `HELD` = attack stopped or residual confirmed
   benign with a demonstrated failed escalation; `BREAK` reserved for an
   achieved attacker goal (none); `ERROR` for setup faults. Exit code is
   nonzero on BREAK/ERROR. During development one genuine probe bug was
   caught and fixed honestly (a3's first draft tampered the tail
   *after* the blinding sweep had already advanced the tip, so the
   tampered entry sat in the MAC-vouched prefix — correct accept,
   mislabeled BREAK; restructured so the tamper precedes the sweep),
   plus two `verify_chain`-returns-a-tuple mistakes. The battery does
   not paper over these: the final run is clean.
6. **Seams**: probes assert at the public seams (`_read_tip_cache`,
   `verify_chain_tip`, `verify_chain`) and additionally pin the
   *layering* (c3b: `_read_tip_cache` alone accepts on an empty scan
   window; `verify_chain_tip`'s shrink check is the boundary) so a
   future refactor cannot silently move the boundary.

Nits (not blocking): a2 and d3 duplicate the racy-tip construction
arithmetic; acceptable — each probe is self-contained by design, and
both document the construction as the faithful emulation of a sweep
that read the tip before a concurrent writer's pins landed (the
function holds the tip in a local after `_read_tip_cache`, so a real
interleaving produces exactly this state).

## Spec axis: PASS

Reviewed against the lane brief's four attack shapes plus the timing
metric. For each: what was attempted, what the battery demonstrates,
and whether the verdict is the security-relevant one.

### (a) Concurrent-writer interleavings — HELD, residual not escalated

- **a1** (attacker mints a pin, tip_gen=99999, no key): the scan skips
  the MAC-invalid line; the tip stays fresh; the sweep fails closed on
  the forged tail line via the newest-line MAC check. Demonstrates the
  MAC boundary honestly: forgery is impossible, and even the *attempt*
  degrades to fail-closed, not to a confused scan.
- **a2** (the documented residual, faithful end-to-end): a genuine
  newer pin (gen 3) positioned before the tip's `pin_off`, tip gen 2 —
  the exact interleaving the wave-112 review accepted as benign (writer
  A reads the tip, writer B's pins land, A measures `pin_off` after
  them and advances gen 1→2). The battery asserts the residual is
  REAL (scan max 2 < full-sidecar max 3, tip accepted) and then tries
  to escalate: tampering a new tail entry. `verify_chain_tip` returns
  None. **Why escalation is impossible here**: the freshness signal
  carries no decision-relevant information — refusals and the F70
  marker manifest fold deterministically over the verified segment,
  and the segment is always fully re-verified per-entry from the
  MAC-anchored tip. A stale-but-genuine tip costs redundant work,
  never trust in unverified bytes. Negative result with a demonstrated
  failed attack, as the brief asked for.
- **a3** (truncate the sidecar to exactly a stale tip's `cp_size` +
  replay that tip): the scan IS blinded (asserted: `_read_tip_cache`
  accepts — this is the strongest attacker primitive in the battery,
  and the probe does not hide that it works), but the verdict stays
  correct (20/20 entries re-verified), and a tail tamper planted
  *before* the sweep fails closed incrementally (None) and loudly on
  full verify (`ok=False`, broken at seq 15). Blinding the freshness
  scan is not a replay hole because freshness gates work, not trust.

### (b) `pin_off` forgery — HELD

- **b1/b2**: bit-flip and cross-tip `pin_off` transplantation both
  break the tip MAC → `_read_tip_cache` returns None → full-verify
  fallback. There is no splice that preserves the MAC without the
  key; `pin_off` is inside the MAC'd `_tip_body`, and the range check
  (`0 <= pin_off <= cp_size`) additionally rejects confused values
  fail-closed.
- **b3**: sidecar prefix bit-flip → the pinned `cp_digest` check in
  `verify_chain_tip` fails closed. The freshness scan itself does not
  check the prefix hash — the battery pins *where* each check lives.

### (c) Sidecar shrink/grow — HELD, layering documented

- **c1/c2**: grown garbage and forged pin-shaped lines are skipped by
  the scan (correct: the scan must not fail closed on attacker
  appendage, else trivial DoS) but fail the sweep closed — `n_bad` for
  garbage, newest-line MAC dispatch (via `_pin_gen_of`) for the
  forged shape. The asymmetry is intentional and safe.
- **c3/c3b**: shrink below `cp_size`, and truncation below `pin_off`
  (where `_read_tip_cache` alone scans `b""` and accepts), both fail
  closed via the shrink check. c3b is the valuable documentation:
  the scan is not the security boundary; `verify_chain_tip`'s
  shrink + prefix-hash checks are.
- **c4**: old-prefix replay (truncate to a genuine older prefix +
  replay the matching tip, log intact) is accepted with a correct
  verdict — redundant work, matching the (corrected) residual.

### (d) Shared `checkpoints.jsonl` — HELD, delta documented

- **d1**: B-longer-than-A fails closed incrementally (None) and
  loudly on full verify (`ok=False`, tail-truncation) — the wave-112
  audit note ("interfere fail-closed") re-confirmed, not weakened.
- **d2**: B advancing the shared gen makes A's tip read stale;
  reseeding heals with gen following the shared max. Fail-closed and
  self-healing.
- **d3**: the wave-112 behavior delta, demonstrated empirically rather
  than argued: with B's newer pin (gen 3) before A's `pin_off`, the
  pre-112 whole-sidecar scan computes max 3 > tip gen 2 (would reject)
  while the post-112 `pin_off` scan computes max 2 (accepts) — and
  A's sweep verdict stays correct (5/5). The delta is benign for the
  same reason as (a): the pin carries no per-log decision content.
  Noted honestly: the fail-closed interference surface for shared
  sidecars is narrower than pre-112. No silence, no hole.

### Timing metric — HELD, with a stated narrowing

- **t1**: the pre-R16 amplifier (full verify per sweep, tip deleted)
  still trips the 150ms `process_time` bound (367/387ms CPU). The
  metric change did not neuter the pin.
- **t1b**: the removed O(sidecar) scan term is visible to
  `process_time` (whole-sidecar 95–96ms vs `pin_off` 16ms, ~6x) — the
  metric captures the amplifier the wave-112 change removed, so the
  pairing of the two changes is coherent.
- **t2**: 6/6 warm sweeps green under 2-CPU saturation, worst 12–13ms
  vs the 150ms bound — the wave-112 "6/6 green" claim re-verified
  independently.
- **Honest caveat** (stated, not hidden): `process_time()` excludes
  I/O wait and descheduling by construction. That is the point of the
  change — the bound pins CPU work (the F69 amplifier) — but it means
  the test no longer trips on I/O-latency regressions (e.g. a
  pathological fsync stall would pass while wall time blows up). This
  is a narrowed pin, not a moved flake: t1 shows the CPU amplifier
  still trips, and the fsync-per-sweep cost is O(1) by design.

## Residuals and boundaries (not findings — F173 stays free)

1. **Full run-dir snapshot rollback** (log + sidecar + tip all restored
   to a genuine past state) is accepted by construction: every MAC
   verifies and the state is self-consistent. Not wave-112-introduced
   (the pre-112 whole-sidecar scan accepted it identically — verified
   by reasoning over the scan semantics, which see no newer pins in a
   rolled-back sidecar), and not fixable in-band: it needs an external
   monotonic anchor or trusted timestamping. The F52/F72 threat model
   targets forgery and partial tampering, against which the MAC +
   prefix-hash + shrink checks hold (demonstrated by b1–b3, c1–c3).
   Consistent with wave-77's "recovery is forward, not time travel".
   Documented as a boundary in the FINDINGS.md maintenance note.
2. **Precision correction** (FINDINGS.md, not a mechanism change): the
   F72 residual as documented — "truncate the sidecar past the newest
   pin AND replay an older tip together forces one redundant full
   re-verification" — is imprecise. a3/c4 show truncate-to-exactly-
   `cp_size` + replay does NOT force full re-verification; the sweep
   proceeds incrementally from the stale tip with a correct verdict
   (redundant segment work). The scan is blinded but the verdict
   stays correct. The note is corrected; nothing in the product
   changed.
3. **d3's delta** (above): shared-sidecar fail-closed interference is
   narrower post-112. Benign, documented.

## Verification summary

- `evals/f69_pin_off_adversarial.py`: 17/17 HELD, 0 BREAK, 0 ERROR,
  twice (second run: `env -u GOV_DEPLOYMENT_MODE` clean env on the
  first pass; normal env on the second — identical).
- Adjacent suites: `tests.test_hardening_r16` +
  `tests.test_log_merkle`: 33/33 green (the battery touches no product
  code, but the seams overlap).
- No product files changed by this lane: `git`-less tree; new files
  are the battery, this review, and the FINDINGS.md/BUILD_LOG.md
  notes.

## Verdict

**GO (negative result).** The wave-112 `pin_off` residual cannot be
escalated into a replay hole: every constructed blinding or stale-accept
shape either fails closed or yields a correct verdict, because the
freshness scan gates work rather than trust, and the MAC'd
`cp_size`/`cp_digest`/shrink checks plus full per-entry tail
re-verification carry the actual security property. The timing metric
change is faithful to the bound's intent with one stated narrowing
(I/O-latency blindness). No finding filed; F173 remains free.
