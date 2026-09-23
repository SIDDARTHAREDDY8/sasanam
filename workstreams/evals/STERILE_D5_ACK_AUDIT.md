# Sterile D5 — acknowledgment audit trail (design + implement + break-first)

**Wave-65, 2026-09-22.** Answers the wave-64 open question: should
`acknowledge()` sink records feed the hash-chained audit log? An
acknowledgment that left no evidence was a control without a trail —
the auditor couldn't tell who treated unvetted data as usable, when,
or in which window. **Answer: yes — via the standing drain
convention, not by giving sterile.py the log.** `sterile.py` never
owns the audit log (the codebase's `_drain_sterile` pattern: the
component appends to a passive sink; the log owner drains). This wave
adds the structured version of that pattern for acknowledgments.

## 1. Design (Lane 1)

### (a) What is recorded per acknowledgment

`Unvetted.acknowledge(consumer_id, sink)` appends one record:

| Field | Source | Notes |
|---|---|---|
| `event` | fixed | `"unvetted_acknowledged"` |
| `consumer` | caller | **self-attested** string (the honesty gap, §1c) |
| `origin` | marker | `"reissue_reads"` / `"unmarked-erased"` (restored through the envelope) |
| `ack_context` | executor | `{"window": wid, "run_id": rid}`, stamped by the **trusted producer** at the wrap site and carried through the JSON envelope (`to_envelope`/`from_envelope`); `{}` for direct (non-pipe) markers; malformed envelope context degrades to `{}` (under-inform, never over-trust) |
| `ts` | sink clock | **ack time** (injectable clock on `AckAuditSink`; `time.time()` for plain-list sinks) — distinct from the log's drain-time `ts` |
| `count` | sink | 1; >1 only via consecutive-duplicate coalescing |

**Never payload contents** (repr already never leaks; pinned by test:
the secret string appears nowhere in the JSON record). On
"mint_id correlation" from the wave brief: `Unvetted` has no mint —
the analog is the executor-stamped `(window, run_id)` pair, which
lets the auditor join the ack record against the `sterile_window_exit`
event carrying the same window's `post_window_delta` envelope in the
hash chain.

`ack_context` is validated at `Unvetted` construction (dict, string
keys, JSON-scalar values — else `TypeError`, loud programmer error);
a forged envelope's context is only as trustworthy as the envelope
the consumer read, and the auditor cross-checks it against the
chained stored copy.

### (b) Flood resistance

An adversary or a buggy loop could spam acknowledgments to bloat the
hash chain. The rule is **budget + count-preserving dedup + overflow
summary — no sampling, no silent drops**:

- **Budget**: `AckAuditSink(max_records=256)` (default). At most 256
  individual ack records per sink. Measured worst-case chain growth:
  ~630 bytes per chained log entry → **under ~170KB per sink**,
  drained per run. The budget is per sink instance (per consumer
  session), so it bounds ack-driven chain growth per run.
- **Consecutive-duplicate coalescing**: acks agreeing on
  (consumer, origin, ack_context) with the immediately preceding
  record bump its exact `count` instead of appending. A tight loop
  acknowledging 5000 identical rows produces **1 record, count=5000**.
- **Overflow summary**: beyond the budget, further distinct acks are
  counted — exactly, by consumer — in **one** tail summary record
  (`unvetted_ack_overflow`: `dropped`, `by_consumer`, `budget`,
  count-preserving note). The summary is never dropped and always
  drains.

Evidence accounting is exact: `sum(counts) + summary.dropped == N`
for N acks, always (pinned by test and probe). Sampling was
deliberately rejected — sampling loses evidence; the summary loses
only per-ack timestamps of overflowed acks, which is documented on
the summary record itself. The F22 log size guard (`LogFullError`)
remains the backstop at drain time.

### (c) The honesty question

**"Acknowledged" is precisely defined, not hand-waved.** The record
attests exactly this: *consumer_id called `acknowledge()` on this
marker, and the marker was unwrapped (the payload was returned to
that caller).* It does **not** claim:

- the consumer used, read, or understood the payload;
- the payload is safe;
- the consumer identity is authenticated — `consumer_id` is a
  **self-attested string**. The record proves *an* unwrap happened,
  not *who* unwrapped. (External validation: levaj2000/ai-identity's
  trust model — "the chain seals whatever the audit writer is
  handed… authenticity at capture time is the job of the signing
  layers above"; research/intake-wave65-2026-09-22.md.)

Both directions of the honesty gap, proved:

- **Record-without-unwrap is impossible through the public API.**
  `acknowledge()` appends to the sink *before* returning the payload
  (record-then-unwrap). A sink whose `append` raises propagates loud
  and the payload is never returned (pinned by probe). There is no
  unhappy path that unwraps unrecorded through `acknowledge()`
  (the "action and its record are the same transaction" principle).
- **Unwrap-without-record** is possible in exactly two named ways,
  both documented boundaries, neither a bypass: (1) `sink=None` —
  the caller's explicit choice (the trail is opt-in at the call
  site); (2) deliberate dunder/`_payload` access — the wave-64 F59
  advisory residual, unchanged. A caller-supplied no-op sink is the
  same class as (1): visible in the caller's own code.
- **Forged records** (direct `sink.append` without `acknowledge()`)
  are possible for anyone holding the sink reference — the sink is a
  consumer-process-local object; cross-boundary forgery is the F59
  in-process residual. What the drain *does* neutralize: forged
  **run context** — `drain_ack_sink` stamps `run_id`/`agent_id`/`role`
  *after* the record (log-wins, mirroring `ActionLog`'s
  reserved-metadata rule), so a forged `run_id` cannot survive into
  the chain. Forged *consumer* identity survives — it was never
  authenticated to begin with (the table above says so).

`AckAuditSink(expected_consumer=...)` is an optional **confusion
guard** (a dashboard wiring bug fails loud with `ValueError`), not a
security boundary — documented as such.

### (d) Failure mode: sink unavailable at acknowledge time

Two layers, both loud:

1. **At acknowledge time**: `AckAuditSink.append` is **total** with
   respect to the budget — volume never raises (it coalesces or
   overflow-counts). The only raises are programmer error
   (non-dict record, `expected_consumer` mismatch). A
   caller-supplied custom sink whose `append` raises propagates
   **before** the payload return — fail-closed in the evidence
   direction, never silent. (Wave-49 lesson honored: the legitimate
   unwrap is never broken by the trail machinery itself.)
2. **At drain time**: `ActionLog.append` failures (`LogFullError`,
   `AppendLockError`, `NoKeyConfiguredError`) propagate out of
   `drain_ack_sink` with the record **still in the sink**
   (peek-confirm: append-to-log first, pop only on success). The run
   fails closed per the F22 standing rule; the deployment must drain
   before relying on the trail; a retry drains cleanly (pinned).

## 2. Implementation (Lane 2)

- `gov/sterile.py`:
  - `AckAuditSink` (+ `_ACK_BUDGET_DEFAULT = 256`,
    `_valid_ack_context`, `_dup_key` helpers), exported in `__all__`.
    Passive container: `append` (budget/coalesce/overflow/ts-stamp),
    `pending`/`peek_oldest`/`pop_oldest` (peek-confirm drain).
  - `Unvetted.__init__(payload, origin=..., ack_context=None)` —
    validated, stored as a copy; new slot `_ack_context`.
  - `acknowledge()`: builds the enriched record; `AckAuditSink`
    stamps ts from its clock, plain lists get `time.time()`; append
    precedes `return self._payload`. Signature unchanged (wave-64
    contract additive-only — pinned).
  - `to_envelope()`/`from_envelope()` carry `ack_context`
    (malformed → `{}`).
- `gov/executor.py`:
  - `drain_ack_sink(sink, agent_id="system", role="system")` — the
    blessed drain path, mirroring `_drain_sterile` but with
    reserved-keys-win ordering and peek-confirm. Accepts
    `AckAuditSink` or a plain list. Returns the drained count.
  - Both reissue wrap sites (close, expiry) stamp
    `ack_context={"window": wid, "run_id": self.run_id}` at the
    producer boundary (executor = trusted producer).

## 3. Break-first evidence

Battery `/tmp/w65_breakfirst.py` (17 probes, 5 lanes):

| Lane | Probes | Result |
|---|---|---|
| L0 forged acks (direct sink forgery, impersonated consumer_id, expected_consumer guard, forged run context at drain) | 4 | 2 HOLD / 2 BOUNDARY |
| L1 log injection (newline/control-char consumer_id, window-id smuggling, single-writer-choke-point check) | 3 | 3 HOLD |
| L2 flood (5000 distinct → 257 records/162KB/verifies; 5000 identical → 1 record count=5000; overflow drains + verifies) | 3 | 3 HOLD |
| L3 honesty (sink=None, dunder bypass, record-without-unwrap impossible, atomic ordering, no-op sink) | 5 | 2 HOLD / 3 BOUNDARY |
| L4 legit regression (full close→ack→drain flow, wave-64 contract spot-check) | 2 | 2 HOLD |

**17 probes → 12 HOLD / 5 BOUNDARY / 0 MISS.** No genuine
independently-reachable miss → no F129 filed (next free stays F129).
The five boundaries are pinned honestly, not graded as misses:

- B1/B2 (L0): direct sink forgery and consumer_id impersonation —
  anyone holding the sink / calling acknowledge can claim any
  consumer. Consumer identity is self-attested by design; run
  context forgery IS neutralized at drain (HOLD). F59 in-process
  residual family.
- B3 (L3): `sink=None` unwraps with no record — caller choice.
- B4 (L3): dunder/`_payload` bypass — wave-64 residual, unchanged.
- B5 (L3): caller-supplied no-op sink — same class as B3.

Durable pins: `tests/test_w65_sterile_d5_ack_audit.py` (22 tests),
`evals/w65_probes.py` (6 probes) + 6 `redteam.sterile_d5_ack.*`
registry entries (closure: green).

## 4. Verdict

**Shipped: the ack trail feeds the hash-chained log via the drain
convention.** The wave-64 open question is closed by mechanism:
who/what/when/which-window is now chained evidence, with the flood
answer (budget + exact-count dedup + overflow summary, measured
<170KB/sink worst case) and the honesty answer ("acknowledged" =
unwrap happened; consumer self-attested; run context
executor-asserted at drain; record-without-unwrap impossible via the
API). Not enforcement against hostile in-process code (F59 family —
stated, not claimed), not theater (12 attack lanes hold, 5
boundaries documented with exact scope).

What was deliberately not done: sampling or rate-limiting with loss
(rejected — loses evidence); making `acknowledge()` fail closed when
the sink is merely absent (would break legitimate loops — Wave-49);
authenticating consumer identity (no identity infrastructure in the
sterile layer; the executor re-stamps what it can — the run context);
per-ack HMAC signatures (the chain's HMAC already covers the drained
record; a second signature adds no new trust root); any change to
the wave-64 `acknowledge()` signature.

Open questions for Wave-66: (1) the first real deployment consumer
of `drain_ack_sink` — which component owns the consumer-side sink
lifetime (per-run? per-dashboard-session?) and when it drains;
(2) `VettingStack` still needs its first real content-defense-stack
integration (carried from wave-64); (3) F81's filtered-egress work
remains the standing deferred pressure (LOW, OPEN).
