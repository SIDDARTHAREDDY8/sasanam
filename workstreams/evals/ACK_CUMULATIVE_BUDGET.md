# Wave-66 design: per-run cumulative ack flood budget

Wave-65 shipped `AckAuditSink` with a per-sink budget (256 individual
records + consecutive-duplicate coalescing + one count-preserving
overflow summary) and `ToolExecutor.drain_ack_sink` (peek-confirm into
the hash-chained ActionLog). The deliberate gap it left: the budget
bounds ONE batch before ONE drain. Repeated drain/refill cycles grow
the chain without bound per run — a buggy loop or an adversary that
controls acknowledgment volume launders unbounded evidence into the
chain one budget at a time. This doc closes the gap by mechanism.

## The four answers

### (a) Where the cumulative budget lives: on the RUN, never the sink

The only path by which ack evidence enters the hash chain is
`ToolExecutor.drain_ack_sink` — that is the choke point, so the
cumulative counter lives there:

- In-memory: `ToolExecutor._ack_cumulative_used` — ack records this
  run has chained via `drain_ack_sink`, keyed to `run_id`
  (`self.run_dir.name`, the existing run identity).
- Durable: run-dir marker file `.ack_cumulative`
  (`{"drained": N, "budget_hit": bool}`), read at executor
  construction, rewritten after every drain that advanced the counter.
  Precedent: wave-52's canary halt marker (`.canary_halted`) —
  server-side run-dir state, never the jail, best-effort I/O.

Survival matrix (the explicit anti-theater requirements):

| Event | Counter survives because |
|---|---|
| Sink replacement mid-run | counter is on the executor, not the sink |
| Executor re-creation over the same run dir | marker file re-read at `__init__` |
| Window close/reopen | counter is per `run_id`; windows are orthogonal |

If replacing the sink reset the counter, the budget would be theater —
the break-first battery probes exactly this (fresh sink mid-run).

A corrupt/unparseable marker degrades to 0 (documented boundary: the
marker is server-side run-dir state, same trust class as the run dir
itself; in-memory counting still bounds the live executor's drains).
Concurrent executors over one run dir are out of scope (single-writer
simulation, same as the rest of the log path).

### (b) What counts against it: chained records, exactly

Accounting unit: **one record appended to the hash-chained ActionLog
by `drain_ack_sink`**. Both `unvetted_acknowledged` records AND
`unvetted_ack_overflow` summaries count — both are chain entries. A
coalesced record with `count=5000` is ONE unit: the unit is chain
growth, which is what the budget bounds, not the number of acks the
world performed. Records never drained (sink=None, undrained sink)
never touch the chain and never count — the budget bounds laundering
INTO the chain, not acknowledgment volume per se.

Cap: `_ACK_CUMULATIVE_BATCHES_DEFAULT = 8` full sink batches, i.e.
`8 * sink.max_records` (2048 at the default 256). Scaling with the
sink's batch budget keeps the budget coherent when a deployment raises
the per-batch bound, and keeps unit tests fast (small sinks, small
caps). Plain-list sinks (no per-sink budget) default to the 256 batch
baseline → cap 2048; the cumulative cap is the ONLY bound on a plain
list, which has no per-sink flood protection at all.

### (c) Exhaustion behavior: refuse LOUD (fail-closed)

Three candidates:

1. **Refuse loudly** (raise; evidence retained in the sink; one
   audited control event in the chain). Matches the codebase idiom:
   F22 drain failure, `PolicyPinMismatchError`, the terminal canary
   halt — the enforcement core fails closed and says so.
2. **Degrade to summary-only**: weaker bound (one summary per drain
   cycle still grows the chain per cycle) and harder exact accounting
   — the chain is append-only, so folding new volume into an
   already-emitted summary means re-emitting.
3. **Silent withhold**: violates wave-65's "no silent drops, exact
   accounting" property outright.

Picked (1). New exception `AckCumulativeBudgetExceeded` (defined in
`gov/sterile.py` next to `AckAuditSink` — ack-domain; `executor.py`
imports it method-locally per the file's no-cycle idiom):

- Budget already exhausted and the sink is non-empty → raise before
  touching anything.
- Budget hit mid-drain → records drained so far stay chained (the
  counter increments only after a successful log-append + pop, so the
  count is exact), the remaining records stay IN the sink
  (peek-confirm preserved), raise.
- Exactly once per run, before the first raise, the executor appends
  one control event `unvetted_ack_cumulative_budget_hit`
  (`budget`, `drained`, `decision: refused`) to the chain — loud in
  the audit trail, not just in the exception. It is a control event,
  not an ack record, so it does not count against the ack budget.
- An empty sink drains to 0 with no raise even when exhausted —
  legitimate no-op drains keep working.

Legitimate-loop cost: the realistic posture drains one batch per
window close; runs have a handful of windows; consecutive-duplicate
coalescing collapses legitimate per-row loops into single records.
2048 chained ack records per run is far beyond any legitimate flow in
the 4/4 battery (pinned by `legit_loop_regression`). A deployment
that genuinely needs more raises `_ACK_CUMULATIVE_BATCHES_DEFAULT`
explicitly — the constant is the knob, documented here.

### (d) Re-drain double-count: impossible by construction

The counter increments only AFTER `self.log.append(entry)` succeeds
AND `pop()` removes the record. A failed append raises before both —
the record stays in the sink, the counter is untouched, the marker is
not rewritten. A later re-drain counts that record exactly once.
Wave-65's "no silent drops, exact accounting" survives: the total
number of ack records chained via `drain_ack_sink` in a run is ≤ cap,
and `_ack_cumulative_used` equals that number exactly.

## What acknowledge() does NOT do

`acknowledge()` has no executor reference — the sink is
consumer-side. The choke point is the drain, so the cumulative budget
is enforced at the drain. A hostile loop can still append millions of
acks into a sink, but the sink itself is already memory-bounded
(256 records + 1 summary); the run-level threat was chain growth via
drain/refill cycles, and that is what this closes.

## Deliberately not built

- Per-ack pre-authorization at `acknowledge()` time (no run context
  there; would entangle the consumer-side sink with the log owner —
  violates the standing "sterile.py never owns the log" convention).
- Cumulative folding summaries instead of refusal (weaker bound,
  §(c)).
- Cross-run / cross-deployment budgets (the threat is per-run chain
  growth; the run dir already scopes everything else).
- Authenticated consumer registry (wave-65 Q3, still open).

## Honesty grading of the residual

Consumer identity stays self-attested (wave-65 boundary, unchanged).
Direct in-process sink forgery stays the F59 accepted residual. A
corrupt `.ack_cumulative` marker degrades to 0 (§(a) boundary). None
of these is a finding: none is a new independently-reachable miss —
the cumulative mechanism itself holds or it gets an F-number.
