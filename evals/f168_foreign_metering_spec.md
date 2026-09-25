# F168 Closure Spec — Meter the Foreign Result Path
## (filed 2026-09-24, quality-audit of Wave-109; Wave-110 executor-persistence lane)

This spec synthesizes the F168 finding and its closure direction. No
interview was run (per the `to-spec` skill: synthesize what is known).
Seam: `ToolExecutor.ingest_foreign_result` in `gov/executor.py`
(the production/real-adapter metering path). No new seams.

## Problem Statement

`evals/f162_velocity_spec.md` claims "Real adapters (MCP/foreign) must
route real results through `ingest_foreign_result` to accrue" — but
`ingest_foreign_result` builds `{"content": blob}` with no `_usage`,
and `_accrue_result_usage` only reads `result["_usage"]` (minted solely
by `_mint_result_usage` on the governed simulated-result path). Real
adapter results therefore accrue exactly 0 tokens / 0 spend: the
S2-GAP-1 "metered accounting on the chained log" story holds only for
simulated results, and production traffic is unmetered. Deterministic
repro: `~/workspace/audits/wave110/vrfy_foreign_metering.py`
(governed `api_call` accrues 180 tokens; `ingest_foreign_result` with a
40KB blob accrues 0).

## Solution

Wire production metering into `ingest_foreign_result`:

1. **Mint governed-side from the normalized blob**: after
   `_foreign_normalize`, call `_mint_result_usage(tool, {}, ...)` on
   the normalized content — the same pure function the governed path
   uses. `args={}`: the foreign adapter's real call args are not
   visible on this path, and nothing caller-supplied may influence the
   mint (anti-forgery, same as the governed path). A foreign result
   that already carries an adapter-asserted `_usage` is never read —
   the mint ignores/overwrites it, so an adapter cannot forge or
   deflate its meter.
2. **Accrue on the RESULT path**: route the minted usage through
   `_accrue_result_usage`, the same accrual the governed path uses.
3. **Metering is loud; taint stays fail-open**: the mint + accrue
   happen BEFORE and OUTSIDE the taint-ingestion `try/except: pass`.
   The F168 defect was a *silent* 0-accrual, so metering failures must
   propagate loudly by design. Taint ingestion keeps its deliberate
   fail-open posture (the call already executed; the signal is
   heuristic, like the native path's ledger taint-mark) — unchanged.
4. **Exactly-once metering**: the dict handed to `_ingest_result`
   carries no `_usage`, so its internal `_accrue_result_usage` reads 0
   (a true no-op); the loud accrual is the single metering event —
   no double-count.
5. **Opaque-only results** (no text blob, e.g. pure bytes) accrue the
   tool's base rate via `mint_usage(tool, {}, {})`: the execution
   happened, the content is invisible, the base is the honest minimum.
   `result=None` stays a clean no-op (unchanged).

## User Stories

1. As a deployment operator running real (MCP/foreign) adapters, I
   want foreign results metered exactly like governed results, so
   production traffic cannot silently evade token/spend budgets.
2. As a security reviewer, I want the foreign mint to be a pure
   function of the normalized blob — never of adapter-asserted
   fields — so a compromised adapter cannot deflate its meter.
3. As a security reviewer, I want metering failures to be loud while
   taint ingestion stays fail-open, so a metering outage can never
   again degrade silently into 0-accrual.
4. As an auditor, I want foreign-result accrual visible in
   `_tokens_used` / `_spend_used` exactly once per ingestion, so the
   meter stays honest.

## Implementation Decisions

- In `ingest_foreign_result`, after the `_foreign_normalize`
  try/except: `if result is None: return` (preserve the clean no-op);
  then `metered_src = {"content": blob} if blob else {}`;
  `self._accrue_result_usage(self._mint_result_usage(tool, {},
  metered_src))` — loud, outside any try/except.
- Then the existing taint block unchanged: `if blob:` → fail-open
  `self._ingest_result(tool, {"content": blob}, principal)`; `if
  opaque:` → conservative taint bits (unchanged).
- The `_ingest_result` internal accrual is intentionally left reading
  a `_usage`-less dict (0, no-op); a code comment pins the
  exactly-once invariant so a future reader does not "fix" it into a
  double-count by passing the minted dict.
- No signature changes to `_ingest_result`, `_mint_result_usage`, or
  `_accrue_result_usage`; the governed path is untouched.

## Testing Decisions

- A good test drives the public seam (`ingest_foreign_result`) and
  asserts the user-visible meter (`_tokens_used` delta), not private
  mint helpers. Expected values come from the spec's worked example
  (40KB blob → `80 + 40000//4` tokens for `api_call`), not by
  re-running the implementation.
- Prior art: `tests/test_budgets.py`, `tests/test_s5_velocity.py`
  (S2-GAP-1 accrual tests).
- Red-first: new `tests/test_f168_foreign_metering.py` must FAIL
  against the unfixed code (scratch copy) — foreign path accrues 0
  pre-fix.
- Cases: 40KB blob accrues `80 + 10000` tokens (governed-parity shape);
  adapter-asserted `_usage` on the foreign result is ignored (mint
  from blob, never from the input dict); opaque-only (bytes) result
  accrues the tool base rate; `result=None` accrues nothing; taint
  ingestion still fail-open (a throwing `_ingest_result` does not
  break the result path — metering already accrued loudly before it);
  no double-count (accrue delta equals exactly one mint).
- Both deployment modes: normal and `env -u GOV_DEPLOYMENT_MODE`.

## Out of Scope

- Metering the foreign adapter's *call arguments* (not visible on this
  path; the blob is the honest meterable surface).
- Changing the governed simulated path's mint/accrue (untouched).
- Spend pricing changes (`spend_for` from policy `budgets:` — reused
  as-is).

## Further Notes

- Failure-posture decision (required by the finding): metering sits
  OUTSIDE the taint `try/except: pass`. If taint ingestion throws,
  metering has already accrued loudly; if metering itself throws, the
  exception propagates to the adapter (loud) rather than degrading to
  the silent 0 that created this finding. The deliberate asymmetry —
  loud accounting, fail-open heuristics — is the design, not an
  accident.
