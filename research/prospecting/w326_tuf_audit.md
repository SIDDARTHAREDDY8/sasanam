# Audit — Wave-326 Lane 4: TUF §5 client-workflow conformance of `gov/bundle_refresh.py`

**Date:** 2026-10-04 · **Lane:** wave-326 lane 4 (audit only — no product code changed) ·
**Base:** `c819b56` (wave-325 merge) · **Oracle:** python-tuf source (MIT + Apache-2.0, read-only; nothing vendored — product is stdlib-only)

**Scope:** the six TUF §5 (client workflow) targets from the wave-325 prospectus §5 ADAPT verdict, audited break-first against `gov/bundle_refresh.py` (1313 lines). Method: for each target, probes in `evals/w326_tufaudit_probes.py` attack the refresh path; conformant code HOLDS with the coded refusal, gaps BREAK and are filed as findings. Unit coverage in `tests/test_bundle_refresh_audit.py` (13 tests).

**Headline:** 16/18 probes HELD, 0 errors. Five targets conformant (one stricter than TUF). One genuine gap filed: **F410 (LOW)** — the post-rotation timestamp bootstrap wedges the client permanently when the repository does not serve a contiguous version history from v1.

---

## Target 1 — Root rotation is exactly N+1: CONFORMANT

`_adopt_root_candidate` enforces the exact chain the prospectus §5(a) calls for:

- **Skip refused.** A v3 document served at the probed N+1 slot (v2 never published) → `RootChainError("root v3 skips versions (trusted v1); refusing")`, client suspends. Probe `T1a` HELD.
- **Rollback refused.** Rewinding the v2 slot to v1 bytes after v2 was adopted → `RollbackError("root v1 is older than trusted v2")`. Probe `T1b` HELD.
- **Single-threshold refused.** A v2 declaring the new root role `(b,rk3)` but carrying only old `(a,b)` signatures → `RootChainError("dual threshold not met (old root: True, new root: False); no best-effort path")`. The dual-threshold check (`old_ok and new_ok`, distinct key IDs, no double-count via the `seen` set in `_threshold_ok`) matches the prospectus §5(a) "each new root verified by the previous" requirement. Probe `T1c` HELD.
- **Valid N+1 adopted.** Dual-signed v2 advances the version. Probe `T1d` HELD (positive control).

No gap. The refusal messages name the exact defect class (skip vs rollback vs threshold), which is good auditability.

## Target 2 — Freeze attacks / fixed update-start time: CONFORMANT

- **Start time pinned.** `refresh()` samples `self._clock()` once into `_ref_time`; every `_is_expired` in the cycle reads that single reference (wave-273 TUF pattern). Probe `T2a`: metadata expiring 30 min after cycle start, clock returning pre-expiry for the first two reads (init + cycle sample) then post-expiry forever after → state stays `trusted`. The clock is called exactly **twice total** — no per-check sampling exists for a mid-cycle advance to corrupt. HELD.
- **Replayed old-but-valid timestamp refused.** Re-serving timestamp v2 (unexpired, validly signed) after the client reached v3 → `RollbackError("timestamp v2 is older than trusted v3")`. The timestamp rollback floor defeats the freeze-by-replay that expiry alone would allow. Probe `T2b` HELD.

No gap. Note the deliberate design: expiry produces `stale` (served loudly), never silent acceptance — freeze degrades to staleness, not to old-data trust.

## Target 3 — Rollback protection on every role: CONFORMANT (stricter than TUF)

- **Timestamp:** serving v2 at slot v4 while trusting v3 → `RollbackError`. Probe `T3a` HELD.
- **Snapshot:** a *valid, newer* timestamp (v5) binding the *older* snapshot (v1) while the client trusts snapshot v2 → `RollbackError("snapshot: parent binds v1, older than trusted v2")`. Probe `T3b` HELD. This is stricter than TUF, which lets a newer timestamp move the snapshot pointer backward; the code treats the cached version as a floor. Deliberate hardening, documented in the audit battery.
- **Targets:** same pattern through snapshot → `RollbackError("targets: parent binds v1, older than trusted v2")`. Probe `T3c` HELD.
- **Root:** covered under Target 1 (`T1b`).

No gap. The bound-role floors (`_refresh_bound`) close the "newer parent, older child" rollback that a timestamp-only floor would miss.

## Target 4 — Fast-forward recovery: GAP (F410, LOW) + conformant halves

**Conformant halves:**
- Contiguous recovery works: after a trust-changing rotation (root key `a→rk3`, timestamp key `ts→tk2`), with old versions retained, the client drops the chain, re-bootstraps timestamp/snapshot/targets under the new root, and lands `trusted` at the new versions with a loud `re-bootstrap` warning. Probe `T4a` HELD.
- The pre-rotation floor is enforced: a new-key-signed timestamp v1 planted below the floor (v3) → `RollbackError("v1 below the pre-rotation v3; refusing")`. Probe `T4b` HELD.

**The gap — F410:** `_bootstrap_timestamp_post_rotation` scans timestamp slots from v1 and `break`s on the first `FetchNotFound`. If the repository does not serve a contiguous history from v1 — it continued versioning under the new key (v4, v5) and pruned the old slots (T4c), or even a single slot is missing (T4d: v1, v2 old-key, v3 gone, v4, v5 new-key) — the scan breaks before reaching any version that verifies under the new root. `best` stays `None` → `_ChainBreak("post-rotation: no timestamp version verifies under the new root")` → `suspended`, on **every** refresh, forever. Both probes BREAK as designed.

This is fail-closed (nothing bad is accepted) but permanent and fleet-wide: every client holding the pre-rotation chain wedges at the same rotation. The TUF model does not require repositories to retain old versions, and pruning after a key compromise — the Mercury scenario this recovery exists for — is plausible. The floor already rejects everything below the pre-rotation version, so requiring slots v1..floor-1 to *exist* is pure liveness cost. Filed as **F410 (LOW)** with reproduction and close-when in `evals/FINDINGS.md`; pinned by `F410KnownIssueTest` (2 tests asserting the current wedged behavior, to be rewritten on closure). Not fixed in-lane: the fix (scan from `max(1, floor)`; bounded continue-past-miss) is a design decision with DoS tradeoffs, documented as follow-on work per the audit-first mandate.

## Target 5 — Mix-and-match (parent bindings): CONFORMANT

`_refresh_bound` checks, in order: parent-declared version equality, parent-declared sha256 digest over the wire bytes, then the signature threshold — digest before signature, so a swapped-but-validly-signed payload is caught by the cheaper check first.

- Forged snapshot digest in a valid timestamp → `BindingError("wire digest does not match the parent's bound sha256")`. Probe `T5a` HELD.
- v3 bytes served at the v2 slot (bound v2) → `"served v3 above the parent-bound v2; refusing"`. Probe `T5b` HELD.
- Forged targets digest in a valid snapshot → refused. Probe `T5c` HELD.
- Attacker-content targets v2 (validly signed, same version) swapped under a snapshot binding the good v2 → digest mismatch refused. Probe `T5d` HELD. This is the mix-and-match core: same version, valid signature, wrong bytes — caught.

No gap.

## Target 6 — Arbitrary-update vs rollback boundary: DOCUMENTED (not a finding)

A compromised timestamp key publishing *newer*, validly signed versions (v4 → evil snapshot → evil targets) is **accepted** — probe `T6a` HELD. This is the TUF trust model, not a defect: rollback protection defends against *older* versions, not against a trusted key signing new ones. Key compromise is contained by rotation (Targets 1/4), not by the refresh path. Recorded as an explicit boundary so a future reader does not re-file it.

---

## Findings filed

- **F410 (LOW, OPEN)** — post-rotation bootstrap wedge (this audit). One finding; no product code changed in-lane.

## Artifacts

- `evals/w326_tufaudit_probes.py` — 18 break-first probes (16 HELD / 2 BREAK / 0 ERROR); green check runs `tests.test_bundle_refresh` depth-1 with `GOV_SKIP_GREEN` honored.
- `tests/test_bundle_refresh_audit.py` — 13 unittest cases (conformance pins + `F410KnownIssueTest`).
- `evals/FINDINGS.md` — F410 entry (severity, reproduction, close-when, rationale); footer re-pointed to next-free F411.

## Verdict

`gov/bundle_refresh.py` is conformant with TUF §5 on five of six targets, stricter than the spec on bound-role rollback, and has one genuine liveness gap (F410) in the fast-forward recovery path. The gap is fail-closed, availability-only, and requires a trust-changing root rotation plus a pruning repository — LOW severity, documented for follow-on work, not boiled in-lane.
