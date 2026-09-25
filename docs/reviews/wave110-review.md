# Wave-110 two-axis code review — review artifact

**Wave:** Wave-110 (Wave-109 quality-audit closure wave).
**Reviewer:** Wave-110 closure coordinator (synthesized from the four lane
two-axis reviews, each executed inline per the code-review skill with axes
kept separate, plus coordinator-level boundary and cross-lane coherence
checks performed 2026-09-25).
**Date:** 2026-09-25.
**Process note:** this artifact exists because the Wave-109 review left no
artifact — the Wave-109 BUILD_LOG entry claimed "Two-axis code-review PASS"
with nothing verifiable in the tree. Per the Wave-110 process correction,
no "review PASS" claim is made without this file.

## Scope under review

Four closure lanes, each red-first (break battery → to-spec → tdd →
implement → two-axis review), verified in normal and
`env -u GOV_DEPLOYMENT_MODE` clean environments:

| Lane | Findings | Product files | Lane review artifact |
|---|---|---|---|
| F164 | F164 (HIGH) CLOSED, F163 RE-CLOSED | `gov/executor.py` | `evals/f164_two_axis_review.md` |
| ledger-robustness | F165, F166 (MED), F170 (LOW) CLOSED | `gov/exchange_ledger.py` | `evals/ledger_robustness_two_axis_review.md` |
| executor-persistence | F167, F168 (MED) CLOSED | `gov/executor.py` | `evals/executor_persistence_two_axis_review.md` |
| battery-integrity + Lane-2 | F169 (MED) CLOSED, F171 (LOW) filed+CLOSED | `evals/adaptive_adversary.py`, `gov/dlp.py` | `evals/battery_integrity_two_axis_review.md` |

Supporting: 5 new red-first test modules, 4 to-spec outputs, FINDINGS.md
closure entries, BUILD_LOG.md lane entries. Open findings after this wave:
none. Next free finding: F172.

## Standards axis — PASS

Per-lane verdicts: all four PASS, no blocking findings. Review-found issues
were fixed in-lane (noted below), not waived:

- F164 lane: one non-blocking gap found and fixed during review —
  the denied-record chained-log mirror was not asserted for denials on
  the tool path; assertion added, re-verified 10/10 both envs, red state
  re-confirmed pre-fix.
- ledger-robustness lane: one real bug found and fixed during review —
  a thread-safety race in the first compaction draft; pinned by a
  concurrency test that fails 5/5 with the lock removed.
- executor-persistence lane: one in-review fix — `UnicodeDecodeError`
  hardening of the rehydration scan (F28 precedent).
- battery-integrity lane: 0 findings (1 nit: unused-but-protocol `kwargs`).

Coordinator-level checks (2026-09-25):
- `gov/executor.py` was edited by TWO lanes (F164 + F167/F168); the merged
  file parses, and all three features coexist (`_exchange_ledger` guard +
  `bind_reader` at both execution boundaries, `_rehydrate_tempo_pause()` in
  `__init__`, `_mint_result_usage` metering in `ingest_foreign_result`).
  No hunk conflicts; each lane's adjacent-suite runs covered the shared
  file (canonical 3572–3575 OK across lanes).
- No `[DEBUG-…]` markers in any touched product file.
- All five new test modules carry module-level
  `GOV_DEPLOYMENT_MODE=staging` (wave-95 lesson) — verified by grep.
- `git diff --check` clean on the push boundary.
- No import cycle introduced: `gov/exchange_ledger.py` still imports zero
  `gov` modules (regression test pins it); the executor uses the same
  `from . import X as _X` alias pattern as the log seam.

## Spec axis — PASS

Each finding's closure direction (from FINDINGS.md) verified against the
shipped code:

- **F164:** "bind the ambient exchange reader … call `check_exchange_read`
  on the executor's file-returning tool path(s); the A1 repro must yield
  `exchange_read` records and trip on bulk through the tool path."
  Shipped: two-phase guard in `_simulate`'s read_file sandbox branch (the
  single choke point for direct-allow, commit-thunk, and sweep paths),
  `bind_reader` at both boundaries, full tool-path audit (read_file is the
  only tool returning real file bytes). A1 repro: BREAK → recorded;
  agent-path bulk battery 50 allowed / 51st denied, both envs.
- **F163 (re-closure):** "every read of another run's traces/exchanges is a
  logged, policy-checked event" on BOTH the log seam and the agent tool
  path. Both legs re-verified end to end, both envs.
- **F165:** fail-closed on `GOV_EXCHANGE_WINDOW_SEC<=0`. Shipped: parsed
  non-positive window denies window-dependent cross-run reads with an
  audited `exchange_read_denied` naming the bad value; own-run reads
  unaffected. Posture choice (deny, not clamp, not ValueError) is
  spec'd and tested.
- **F166:** monotonic window accounting. Shipped: records carry `mono`
  (monotonic) + `boot` (boot-id); same-epoch gates on monotonic only;
  cross-epoch/legacy records keep counting by wall `ts` — the deliberate
  fail-closed direction (restart must not launder the budget), documented
  as a spec'd deviation from the filing's one-liner.
- **F167:** pause/wire survive executor rotation. Shipped:
  `_rehydrate_tempo_pause()` derives pause from the chained log
  (latest `velocity_paused`/`velocity_resumed` wins; only chain-bookkept
  entries honored); wire deliberately NOT rehydrated (F166 cross-boot
  lesson); human-approved resume still clears exactly once.
- **F168:** `ingest_foreign_result` accrues real usage. Shipped: mints via
  `_mint_result_usage` from the normalized blob (adapter-asserted `_usage`
  never read), accrued BEFORE and OUTSIDE the taint `try/except: pass`
  (metering loud, taint posture unchanged).
- **F169:** silent credential win scores BREAK. Shipped: `CredCampaign`
  goal_check fixed red-first; battery re-run both envs —
  exfil HELD (6), cred BREAK round 4 (designed win), persist HELD (6).
  The persist instrument defect (package= vs name=, goal_check on refused
  installs) was also confirmed RED and fixed red-first.
- **F170:** bounded ledger. Shipped: bounded-tail scan
  (`max(2MB, window·512)`), append-time compaction past
  `max(1MB, window·256)` keeping window-relevant records, atomic
  temp+`os.replace`, failures → `ExchangeAccessDenied` (never unbounded).
- **F171:** DLP quadratic scrub. Filed from Lane-2 measurement, fixed
  red-first with trigger-character guards; 263KB now denies in 0.49s;
  139 DLP-adjacent tests green.

No scope creep: each lane's diff serves its finding(s); the only
cross-finding change is F171, which was filed (not smuggled) with its own
red-first battery.

## Blocking findings raised

**None.** Every lane review returned PASS on both axes with zero blocking
findings. The three issues found during review (denied-mirror assertion,
compaction thread race, rehydration Unicode hardening) were fixed and
re-verified in-lane before closure.

## Residuals (carried, not hidden)

- F164: raw `open()`/read_text outside governed seams still uncovered;
  default tool-path ledger placement is `<sandbox>/runs/exchange_access.jsonl`
  when `GOV_EXCHANGE_LEDGER_PATH` is unset — deployments should pin it
  outside the sandbox.
- F166: non-Linux boot-id fallback is per-process; sustained clock-flood
  degrades to fail-closed deny (availability shape).
- F167: cross-boot wire starts cold after rotation + approved resume;
  rehydration scan is O(n) per construction (F22 log-size guard bounds it).
- F168: MCP/generic adapters keep their own `try/except: pass` around the
  call — the seam no longer fails silent, but adapter-level swallowing is
  their documented posture.
- F170: no per-reader rate limit; fail-closed DoS shape under sustained
  flood is the accepted trade-off.
- Lane-2 measured (not findings): low-and-slow max ≈ 2MB/principal/24h
  below every automated deny → human review; ledger slow-drip max
  ≈ 16.67 GiB/900s window bounded by victim availability, every read
  recorded.
- Known flakes (documented, unrelated): w88 cross-process rundir flake,
  F69 warm-sweep timing bound, one `test_2000_appends` timing flake under
  concurrent load — each reproduced on the pristine tree or in isolation.

## Boundary

Push boundary vs `b4f1395` (Wave-109): exactly the Wave-110 set —
`gov/executor.py`, `gov/exchange_ledger.py`, `gov/dlp.py`,
`evals/adaptive_adversary.py`, 5 new test modules, 4 spec docs, 4 lane
review artifacts, this file, `evals/FINDINGS.md`, `BUILD_LOG.md`
(including the ride-along Wave-108 / Wave-109-audit entries per the
Wave-105 convention). W2 packaging files present in the active tree are
EXCLUDED from this boundary — they integrate separately as Wave-111.
